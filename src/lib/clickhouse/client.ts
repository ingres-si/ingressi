import { createClient, type ClickHouseClient } from '@clickhouse/client';

// ── Configuration ───────────────────────────────────────────────────────────

const CH_URL = process.env.CLICKHOUSE_URL ?? 'http://clickhouse:8123';
const CH_USER = process.env.CLICKHOUSE_USER ?? 'ingressi';
const CH_PASS = process.env.CLICKHOUSE_PASSWORD ?? '';
const CH_DB = process.env.CLICKHOUSE_DB ?? 'analytics';

// Validate CH_DB is a safe identifier (alphanumeric + underscore only)
if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(CH_DB)) {
  throw new Error(`CLICKHOUSE_DB contains invalid characters: ${CH_DB}`);
}

const DEFAULT_RETENTION_DAYS = 30;

/** Parse CLICKHOUSE_RETENTION_DAYS into a positive integer number of days. */
function parseRetentionDays(raw: string | undefined): number {
  if (raw == null || raw.trim() === '') return DEFAULT_RETENTION_DAYS;
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`CLICKHOUSE_RETENTION_DAYS must be a positive integer (got: ${raw})`);
  }
  return n;
}

// Number of days analytics events are kept before ClickHouse's TTL deletes them.
const CH_RETENTION_DAYS = parseRetentionDays(process.env.CLICKHOUSE_RETENTION_DAYS);

// ── Analytics state ─────────────────────────────────────────────────────────

const analyticsConfigured = CH_PASS.trim().length > 0;

/** Returns true when ClickHouse analytics is configured for this process. */
export function isAnalyticsEnabled(): boolean {
  return analyticsConfigured;
}

/** Number of days analytics events are retained before TTL deletion. */
export function getRetentionDays(): number {
  return CH_RETENTION_DAYS;
}

// ── Singleton client ────────────────────────────────────────────────────────

let client: ClickHouseClient | null = null;

export function getClient(): ClickHouseClient {
  if (!client) {
    client = createClient({
      url: CH_URL,
      username: CH_USER,
      password: CH_PASS,
      database: CH_DB,
      clickhouse_settings: {
        async_insert: 1,
        wait_for_async_insert: 0,
      },
      log: {
        // 127 is ClickHouseLogLevel.OFF; keep this numeric to avoid widening test mocks.
        level: 127,
      },
    });
  }
  return client;
}

// ── Table creation ──────────────────────────────────────────────────────────

const TRAFFIC_EVENTS_DDL = `
CREATE TABLE IF NOT EXISTS traffic_events (
    ts           DateTime('UTC')   CODEC(Delta, ZSTD),
    client_ip    String            CODEC(ZSTD(3)),
    country_code LowCardinality(Nullable(String)),
    host         LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    method       LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    uri          String            DEFAULT '' CODEC(ZSTD(3)),
    status       UInt16            DEFAULT 0,
    proto        LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    bytes_sent   UInt64            DEFAULT 0 CODEC(Delta, ZSTD),
    user_agent   String            DEFAULT '' CODEC(ZSTD(3)),
    is_blocked   Bool              DEFAULT false,
    is_rate_limited Bool           DEFAULT false,
    asn          UInt32            DEFAULT 0,
    as_org       LowCardinality(String) DEFAULT '',
    outcome      LowCardinality(String) DEFAULT '',
    duration_ms  UInt32            DEFAULT 0,
    ua_family    String            DEFAULT '' CODEC(ZSTD(3)),
    waf_rule_id  UInt32            DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (host, ts)
TTL ts + INTERVAL ${CH_RETENTION_DAYS} DAY DELETE
SETTINGS index_granularity = 8192
`;

/**
 * Coraza's transaction id (the stored audit record's transaction.id): the
 * WAF event's id in the REST API. Rows written before the column existed
 * compute it from raw_data on read.
 */
const WAF_TX_ID_DEFAULT = `JSONExtractString(ifNull(raw_data, ''), 'transaction', 'id')`;

const WAF_EVENTS_DDL = `
CREATE TABLE IF NOT EXISTS waf_events (
    ts           DateTime('UTC')   CODEC(Delta, ZSTD),
    host         LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    client_ip    String            CODEC(ZSTD(3)),
    country_code LowCardinality(Nullable(String)),
    method       LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    uri          String            DEFAULT '' CODEC(ZSTD(3)),
    rule_id      Nullable(Int32),
    rule_message Nullable(String)  CODEC(ZSTD(3)),
    severity     LowCardinality(Nullable(String)),
    raw_data     Nullable(String)  CODEC(ZSTD(3)),
    blocked      Bool              DEFAULT true,
    tx_id        String            DEFAULT ${WAF_TX_ID_DEFAULT} CODEC(ZSTD(3))
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (host, ts)
TTL ts + INTERVAL ${CH_RETENTION_DAYS} DAY DELETE
SETTINGS index_granularity = 8192
`;

// Migrations applied to existing tables on startup (idempotent MODIFY COLUMN).
// Do not change an existing ts column's timezone here. toYYYYMM(ts) is its
// partition key: an in-place UTC cast leaves old local-month partition IDs
// behind and range pruning can hide boundary rows. Numeric epoch inserts are
// safe for legacy DateTime columns too; retain their existing interpretation.
// New tables explicitly use UTC, and migrations must not erase that metadata.
const TRAFFIC_EVENTS_MIGRATIONS = [
  `ALTER TABLE traffic_events MODIFY COLUMN client_ip String CODEC(ZSTD(3))`,
  `ALTER TABLE traffic_events MODIFY COLUMN country_code LowCardinality(Nullable(String))`,
  `ALTER TABLE traffic_events MODIFY COLUMN host LowCardinality(String) DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE traffic_events MODIFY COLUMN method LowCardinality(String) DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE traffic_events MODIFY COLUMN uri String DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE traffic_events MODIFY COLUMN proto LowCardinality(String) DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE traffic_events MODIFY COLUMN bytes_sent UInt64 DEFAULT 0 CODEC(Delta, ZSTD)`,
  `ALTER TABLE traffic_events MODIFY COLUMN user_agent String DEFAULT '' CODEC(ZSTD(3))`,
  // Requests refused by the rate limiter (Caddy's 429, not the upstream's).
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS is_rate_limited Bool DEFAULT false`,
  // Analytics fields (src/lib/analytics). Rows written before these columns
  // existed keep the defaults; the query layer derives their outcome from
  // is_blocked / is_rate_limited (src/lib/analytics/dimensions.ts).
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS asn UInt32 DEFAULT 0`,
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS as_org LowCardinality(String) DEFAULT ''`,
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS outcome LowCardinality(String) DEFAULT ''`,
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS duration_ms UInt32 DEFAULT 0`,
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS ua_family String DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE traffic_events ADD COLUMN IF NOT EXISTS waf_rule_id UInt32 DEFAULT 0`,
];

const WAF_EVENTS_MIGRATIONS = [
  `ALTER TABLE waf_events MODIFY COLUMN host LowCardinality(String) DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE waf_events MODIFY COLUMN client_ip String CODEC(ZSTD(3))`,
  `ALTER TABLE waf_events MODIFY COLUMN country_code LowCardinality(Nullable(String))`,
  `ALTER TABLE waf_events MODIFY COLUMN method LowCardinality(String) DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE waf_events MODIFY COLUMN uri String DEFAULT '' CODEC(ZSTD(3))`,
  `ALTER TABLE waf_events MODIFY COLUMN severity LowCardinality(Nullable(String))`,
  `ALTER TABLE waf_events MODIFY COLUMN rule_message Nullable(String) CODEC(ZSTD(3))`,
  `ALTER TABLE waf_events MODIFY COLUMN raw_data Nullable(String) CODEC(ZSTD(3))`,
  `ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS tx_id String DEFAULT ${WAF_TX_ID_DEFAULT} CODEC(ZSTD(3))`,
];

const RETENTION_TABLES = ['traffic_events', 'waf_events'] as const;

/** Extract the retention (in days) from a table's TTL clause, if present. */
function ttlDaysFromCreateQuery(createQuery: string): number | null {
  // ClickHouse normalizes `INTERVAL N DAY` to `toIntervalDay(N)` in create_table_query,
  // but older servers may report the literal form — match both.
  const match =
    createQuery.match(/TTL\s+ts\s*\+\s*toIntervalDay\((\d+)\)/i) ??
    createQuery.match(/TTL\s+ts\s*\+\s*INTERVAL\s+(\d+)\s+DAY/i);
  return match ? Number(match[1]) : null;
}

/**
 * Bring an existing table's TTL in line with CH_RETENTION_DAYS.
 *
 * `CREATE TABLE IF NOT EXISTS` never alters an existing table, so deployments
 * created under a different retention keep their old TTL forever unless we
 * issue an explicit MODIFY TTL. We only do so when the current TTL differs,
 * since MODIFY TTL materializes a mutation that rewrites parts to drop expired
 * rows — cheap to skip, wasteful to repeat on every restart.
 */
async function ensureRetentionTtl(ch: ClickHouseClient, table: (typeof RETENTION_TABLES)[number]): Promise<void> {
  const result = await ch.query({
    query: `SELECT create_table_query FROM system.tables WHERE database = {db:String} AND name = {tbl:String}`,
    query_params: { db: CH_DB, tbl: table },
    format: 'JSONEachRow',
  });
  const rows = await result.json<{ create_table_query: string }>();
  const current = ttlDaysFromCreateQuery(rows[0]?.create_table_query ?? '');
  if (current === CH_RETENTION_DAYS) return;
  await ch.command({
    query: `ALTER TABLE ${table} MODIFY TTL ts + INTERVAL ${CH_RETENTION_DAYS} DAY DELETE`,
  });
}

// Diagnostic system-log tables that docker/clickhouse/config.d/low-disk-write.xml
// turns off. On stock ClickHouse these flush every few seconds regardless of
// traffic, so a deployment that ran before the override accumulated gigabytes we
// can now reclaim. Disabling only stops new writes; the old data lingers until
// the tables are dropped, which is what this list drives.
const DISABLED_SYSTEM_LOGS = [
  'metric_log',
  'asynchronous_metric_log',
  'trace_log',
  'query_log',
  'query_thread_log',
  'query_views_log',
  'part_log',
  'processors_profile_log',
  'text_log',
  'session_log',
  'opentelemetry_span_log',
  'blob_storage_log',
  'backup_log',
  'histogram_metric_log',
] as const;

// Matches a disabled log table and its numbered upgrade leftovers. When a
// ClickHouse upgrade changes a system-log table's schema, the server renames
// the old table to `<name>_<N>` (e.g. trace_log_3) and creates a fresh one;
// those frozen copies are never cleaned up and, on long-lived deployments,
// dwarf the live table. An exact-name drop misses them, so we match the
// `_<N>` suffix too. Anchored to full names built from the trusted constant
// list above — no user input reaches this regex.
const DISABLED_SYSTEM_LOG_PATTERN = `^(${DISABLED_SYSTEM_LOGS.join('|')})(_[0-9]+)?$`;

/**
 * Drop the diagnostic system-log tables we disable via config — including the
 * numbered `_<N>` copies left behind by past version upgrades — so their
 * already-written data is reclaimed. Best-effort: the analytics user often
 * lacks DROP on the `system` database, so a failure is logged once and ignored
 * rather than aborting startup.
 */
async function dropDisabledSystemLogs(ch: ClickHouseClient): Promise<void> {
  let names: string[];
  try {
    const result = await ch.query({
      query: `SELECT name FROM system.tables WHERE database = 'system' AND match(name, {pattern:String})`,
      query_params: { pattern: DISABLED_SYSTEM_LOG_PATTERN },
      format: 'JSONEachRow',
    });
    names = (await result.json<{ name: string }>())
      .map((row) => row.name)
      .filter((name): name is string => typeof name === 'string' && name.length > 0);
  } catch (err) {
    console.warn(`[clickhouse] could not list disabled system log tables to drop: ${(err as Error).message}`);
    return;
  }

  for (const name of names) {
    try {
      await ch.command({ query: `DROP TABLE IF EXISTS system.${name} SYNC` });
    } catch (err) {
      console.warn(
        `[clickhouse] could not drop disabled system log tables (insufficient privileges?); ` +
        `they will stop growing once the config override is applied, but existing data must be ` +
        `cleared manually. Reason: ${(err as Error).message}`,
      );
      return;
    }
  }
}

export async function initClickHouse(): Promise<void> {
  if (!analyticsConfigured) {
    console.log('ClickHouse analytics disabled (CLICKHOUSE_PASSWORD not set)');
    return;
  }
  const ch = getClient();
  await ch.command({ query: `CREATE DATABASE IF NOT EXISTS ${CH_DB}` });
  await ch.command({ query: TRAFFIC_EVENTS_DDL });
  await ch.command({ query: WAF_EVENTS_DDL });
  for (const q of [...TRAFFIC_EVENTS_MIGRATIONS, ...WAF_EVENTS_MIGRATIONS]) {
    await ch.command({ query: q });
  }
  for (const table of RETENTION_TABLES) {
    await ensureRetentionTtl(ch, table);
  }
  await dropDisabledSystemLogs(ch);
}

export async function closeClickHouse(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
  }
}

// ── Insert helpers ──────────────────────────────────────────────────────────

export interface TrafficEventRow {
  ts: number;
  client_ip: string;
  country_code: string | null;
  host: string;
  method: string;
  uri: string;
  status: number;
  proto: string;
  bytes_sent: number;
  user_agent: string;
  is_blocked: boolean;
  /** Refused by the rate limiter (log-parser.ts); absent counts as false. */
  is_rate_limited?: boolean;
  /** Autonomous system of client_ip (GeoLite2-ASN); 0 when unknown. */
  asn?: number;
  /** Organisation of that autonomous system; empty when unknown. */
  as_org?: string;
  /** What happened to the request (src/lib/analytics/outcome.ts); empty on rows written before it existed. */
  outcome?: string;
  /** Caddy's `duration`, in whole milliseconds. */
  duration_ms?: number;
  /** User-agent family (src/lib/analytics/user-agent.ts). */
  ua_family?: string;
  /** The WAF rule that made the WAF block the request; 0 when none is known. */
  waf_rule_id?: number;
}

export interface WafEventRow {
  ts: number;
  host: string;
  client_ip: string;
  country_code: string | null;
  rule_id: number | null;
  rule_message: string | null;
  severity: string | null;
  raw_data: string | null;
  blocked: boolean;
  method: string;
  uri: string;
  /** Coraza's transaction id; computed from raw_data when left out. */
  tx_id?: string;
}

/**
 * DateTime stores UInt32 epoch seconds. Rows outside that range are dropped,
 * not wrapped; throwing would fail the whole batch and the parser would re-read
 * the same lines on every pass.
 */
function withEventEpochs<T extends { ts: number }>(rows: T[], table: string): T[] {
  const valid = rows.filter(r => Number.isFinite(r.ts) && r.ts >= 0 && r.ts < 0x1_0000_0000);
  if (valid.length < rows.length) console.warn(`[clickhouse] skipped ${rows.length - valid.length} ${table} rows with an invalid timestamp`);
  return valid.map(r => ({ ...r, ts: Math.floor(r.ts) }));
}

export async function insertTrafficEvents(rows: TrafficEventRow[]): Promise<void> {
  if (!analyticsConfigured || rows.length === 0) return;
  const ch = getClient();
  // Numeric Unix seconds are unambiguous even before an existing table is migrated.
  const values = withEventEpochs(rows, 'traffic_events').map(r => ({
    ...r,
    is_blocked: r.is_blocked ? 1 : 0,
    is_rate_limited: r.is_rate_limited ? 1 : 0,
  }));
  if (values.length === 0) return;
  await ch.insert({ table: 'traffic_events', values, format: 'JSONEachRow' });
}

export async function insertWafEvents(rows: WafEventRow[]): Promise<void> {
  if (!analyticsConfigured || rows.length === 0) return;
  const ch = getClient();
  const values = withEventEpochs(rows, 'waf_events').map(r => ({
    ...r,
    blocked: r.blocked ? 1 : 0,
  }));
  if (values.length === 0) return;
  await ch.insert({ table: 'waf_events', values, format: 'JSONEachRow' });
}

// ── Parameterized query helpers ─────────────────────────────────────────────

type QueryParams = Record<string, unknown>;

/**
 * Build a host filter clause using parameterized query placeholders.
 * Returns the SQL fragment and the params to merge into query_params.
 */
function hostFilter(hosts: string[]): { sql: string; params: QueryParams } {
  if (hosts.length === 0) return { sql: '', params: {} };
  const params: QueryParams = {};
  const placeholders: string[] = [];
  hosts.forEach((h, i) => {
    const key = `host_${i}`;
    params[key] = h;
    placeholders.push(`{${key}:String}`);
  });
  return { sql: ` AND host IN (${placeholders.join(',')})`, params };
}

function timeFilter(): string {
  return `ts >= toDateTime({p_from:UInt32}) AND ts <= toDateTime({p_to:UInt32})`;
}

function timeParams(from: number, to: number): QueryParams {
  return { p_from: safeUint(from), p_to: safeUint(to) };
}

function buildWafFilter(search?: string, from?: number, to?: number): { where: string; params: QueryParams } {
  const clauses: string[] = [];
  let params: QueryParams = {};

  if (Number.isFinite(from) && Number.isFinite(to)) {
    clauses.push(timeFilter());
    params = { ...params, ...timeParams(from as number, to as number) };
  }

  if (search) {
    clauses.push(`(
      host ILIKE {p_search:String}
         OR client_ip ILIKE {p_search:String}
         OR uri ILIKE {p_search:String}
         OR rule_message ILIKE {p_search:String}
    )`);
    params.p_search = `%${search}%`;
  }

  return {
    where: clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  };
}

/** Clamp a number to a safe non-negative integer (guards against NaN/Infinity). */
function safeUint(n: number): number {
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

async function queryRows<T>(query: string, query_params?: QueryParams): Promise<T[]> {
  if (!analyticsConfigured) return [];
  const ch = getClient();
  const result = await ch.query({ query, query_params, format: 'JSONEachRow' });
  return result.json<T>();
}

async function queryRow<T>(query: string, query_params?: QueryParams): Promise<T | null> {
  const rows = await queryRows<T>(query, query_params);
  return rows[0] ?? null;
}

// ── Analytics queries ───────────────────────────────────────────────────────

export interface AnalyticsSummary {
  totalRequests: number;
  uniqueIps: number;
  blockedRequests: number;
  blockedPercent: number;
  /** Requests the rate limiter answered with 429; not part of blockedRequests. */
  rateLimitedRequests: number;
  bytesServed: number;
}

export async function querySummary(from: number, to: number, hosts: string[]): Promise<AnalyticsSummary> {
  const hf = hostFilter(hosts);
  const tp = timeParams(from, to);

  const traffic = await queryRow<{ total: string; unique_ips: string; blocked: string; rate_limited: string; bytes: string }>(`
    SELECT
      count() AS total,
      uniq(client_ip) AS unique_ips,
      countIf(is_blocked) AS blocked,
      countIf(is_rate_limited) AS rate_limited,
      sum(bytes_sent) AS bytes
    FROM traffic_events
    WHERE ${timeFilter()}${hf.sql}
  `, { ...tp, ...hf.params });

  const wafRow = await queryRow<{ waf_blocked: string }>(`
    SELECT count() AS waf_blocked
    FROM waf_events
    WHERE ${timeFilter()} AND blocked = true${hf.sql}
  `, { ...tp, ...hf.params });

  const total = Number(traffic?.total ?? 0);
  const geoBlocked = Number(traffic?.blocked ?? 0);
  const wafBlocked = Number(wafRow?.waf_blocked ?? 0);
  const blocked = geoBlocked + wafBlocked;

  return {
    totalRequests: total,
    uniqueIps: Number(traffic?.unique_ips ?? 0),
    blockedRequests: blocked,
    blockedPercent: total > 0 ? Math.round((blocked / total) * 1000) / 10 : 0,
    rateLimitedRequests: Number(traffic?.rate_limited ?? 0),
    bytesServed: Number(traffic?.bytes ?? 0),
  };
}

/** Every host name seen in traffic or WAF events, as stored. */
export async function queryDistinctHostsAll(): Promise<string[]> {
  const rows = await queryRows<{ host: string }>(`
    SELECT DISTINCT host FROM (
      SELECT host FROM traffic_events
      UNION ALL
      SELECT host FROM waf_events
    ) WHERE host != ''
  `);
  return rows.map(r => r.host);
}

// ── WAF analytics queries ───────────────────────────────────────────────────

export async function queryWafCount(from: number, to: number, hosts: string[] = []): Promise<number> {
  const tp = timeParams(from, to);
  const hf = hostFilter(hosts);
  const row = await queryRow<{ value: string }>(`
    SELECT count() AS value FROM waf_events WHERE ${timeFilter()}${hf.sql}
  `, { ...tp, ...hf.params });
  return Number(row?.value ?? 0);
}

export async function queryWafCountWithSearch(search?: string, from?: number, to?: number): Promise<number> {
  const filter = buildWafFilter(search, from, to);
  const row = await queryRow<{ value: string }>(`
    SELECT count() AS value FROM waf_events
    ${filter.where}
  `, filter.params);
  return Number(row?.value ?? 0);
}

export interface WafEventStats {
  total: number;
  blocked: number;
  critical: number;
  uniqueHosts: number;
  ruleIdsTriggered: number;
}

export async function queryWafEventStatsWithSearch(search?: string, from?: number, to?: number): Promise<WafEventStats> {
  const filter = buildWafFilter(search, from, to);
  const row = await queryRow<{
    total: string;
    blocked: string;
    critical: string;
    unique_hosts: string;
    rule_ids_triggered: string;
  }>(`
    SELECT
      count() AS total,
      countIf(blocked) AS blocked,
      countIf(upperUTF8(ifNull(severity, '')) = 'CRITICAL') AS critical,
      uniqExact(host) AS unique_hosts,
      uniqExactIf(rule_id, rule_id IS NOT NULL) AS rule_ids_triggered
    FROM waf_events
    ${filter.where}
  `, filter.params);

  return {
    total: Number(row?.total ?? 0),
    blocked: Number(row?.blocked ?? 0),
    critical: Number(row?.critical ?? 0),
    uniqueHosts: Number(row?.unique_hosts ?? 0),
    ruleIdsTriggered: Number(row?.rule_ids_triggered ?? 0),
  };
}

export interface TopWafRule {
  ruleId: number;
  count: number;
  message: string | null;
}

export async function queryTopWafRules(from: number, to: number, limit = 10, hosts: string[] = []): Promise<TopWafRule[]> {
  const tp = timeParams(from, to);
  const hf = hostFilter(hosts);
  const rows = await queryRows<{ rule_id: string; count: string; message: string | null }>(`
    SELECT
      rule_id,
      count() AS count,
      any(rule_message) AS message
    FROM waf_events
    WHERE ${timeFilter()} AND rule_id IS NOT NULL${hf.sql}
    GROUP BY rule_id
    ORDER BY count DESC
    LIMIT {p_limit:UInt32}
  `, { ...tp, ...hf.params, p_limit: safeUint(limit) });

  return rows
    .filter(r => r.rule_id != null)
    .map(r => ({ ruleId: Number(r.rule_id), count: Number(r.count), message: r.message ?? null }));
}

export interface TopWafRuleWithHosts {
  ruleId: number;
  count: number;
  message: string | null;
  hosts: { host: string; count: number }[];
}

export async function queryTopWafRulesWithHosts(from: number, to: number, limit = 10, hosts: string[] = []): Promise<TopWafRuleWithHosts[]> {
  const topRules = await queryTopWafRules(from, to, limit, hosts);
  if (topRules.length === 0) return [];

  // Rule IDs come from ClickHouse query results — they are integers, safe for IN clause
  const ruleIds = topRules.map(r => r.ruleId);
  const tp = timeParams(from, to);
  const ruleParams: QueryParams = {};
  const rulePlaceholders: string[] = [];
  ruleIds.forEach((id, i) => {
    const key = `rid_${i}`;
    ruleParams[key] = id;
    rulePlaceholders.push(`{${key}:Int32}`);
  });

  const hf = hostFilter(hosts);
  const hostRows = await queryRows<{ rule_id: string; host: string; count: string }>(`
    SELECT rule_id, host, count() AS count
    FROM waf_events
    WHERE ${timeFilter()} AND rule_id IN (${rulePlaceholders.join(',')})${hf.sql}
    GROUP BY rule_id, host
    ORDER BY count DESC
  `, { ...tp, ...ruleParams, ...hf.params });

  return topRules.map(rule => ({
    ...rule,
    hosts: hostRows
      .filter(r => Number(r.rule_id) === rule.ruleId)
      .map(r => ({ host: r.host, count: Number(r.count) })),
  }));
}

export async function queryWafCountries(from: number, to: number, hosts: string[] = []): Promise<{ countryCode: string; count: number }[]> {
  const tp = timeParams(from, to);
  const hf = hostFilter(hosts);
  const rows = await queryRows<{ country_code: string | null; count: string }>(`
    SELECT country_code, count() AS count
    FROM waf_events
    WHERE ${timeFilter()}${hf.sql}
    GROUP BY country_code
    ORDER BY count DESC
  `, { ...tp, ...hf.params });
  return rows.map(r => ({ countryCode: r.country_code ?? 'XX', count: Number(r.count) }));
}

export async function queryWafRuleMessages(ruleIds: number[]): Promise<Record<number, string | null>> {
  if (ruleIds.length === 0) return {};
  const params: QueryParams = {};
  const placeholders: string[] = [];
  ruleIds.forEach((id, i) => {
    const key = `rid_${i}`;
    params[key] = id;
    placeholders.push(`{${key}:Int32}`);
  });
  const rows = await queryRows<{ rule_id: string; message: string | null }>(`
    SELECT rule_id, any(rule_message) AS message
    FROM waf_events
    WHERE rule_id IN (${placeholders.join(',')})
    GROUP BY rule_id
  `, params);
  return Object.fromEntries(
    rows.filter(r => r.rule_id != null).map(r => [Number(r.rule_id), r.message ?? null])
  );
}

export interface WafEvent {
  id: number;
  /** Coraza's transaction id: the event's id in the REST API (empty when the record has none). */
  eventId: string;
  ts: number;
  host: string;
  clientIp: string;
  countryCode: string | null;
  method: string;
  uri: string;
  ruleId: number | null;
  ruleMessage: string | null;
  severity: string | null;
  rawData: string | null;
  blocked: boolean;
}

export async function queryWafEvents(limit = 50, offset = 0, search?: string, from?: number, to?: number): Promise<WafEvent[]> {
  const safeLimit = safeUint(limit);
  const safeOffset = safeUint(offset);
  const filter = buildWafFilter(search, from, to);
  const query = `
    SELECT toUInt32(ts) AS ts, host, client_ip, country_code, method, uri,
           rule_id, rule_message, severity, raw_data, blocked, tx_id
    FROM waf_events
    ${filter.where}
    ORDER BY ts DESC
    LIMIT {p_limit:UInt32} OFFSET {p_offset:UInt32}
  `;
  const params = { ...filter.params, p_limit: safeLimit, p_offset: safeOffset };

  const rows = await queryRows<WafEventQueryRow>(query, params);
  return rows.map((r, i) => wafEventFromRow(r, safeOffset + i + 1));
}

type WafEventQueryRow = {
  ts: string; host: string; client_ip: string; country_code: string | null;
  method: string; uri: string; rule_id: string | null; rule_message: string | null;
  severity: string | null; raw_data: string | null; blocked: string; tx_id: string | null;
};

function wafEventFromRow(r: WafEventQueryRow, id: number): WafEvent {
  return {
    id,
    eventId: r.tx_id ?? '',
    ts: Number(r.ts),
    host: r.host,
    clientIp: r.client_ip,
    countryCode: r.country_code ?? null,
    method: r.method,
    uri: r.uri,
    ruleId: r.rule_id != null ? Number(r.rule_id) : null,
    ruleMessage: r.rule_message ?? null,
    severity: r.severity ?? null,
    rawData: r.raw_data ?? null,
    blocked: Boolean(Number(r.blocked)),
  };
}

/** The WAF event with Coraza transaction id `eventId`, or null. */
export async function queryWafEventByTxId(eventId: string): Promise<WafEvent | null> {
  const row = await queryRow<WafEventQueryRow>(`
    SELECT toUInt32(ts) AS ts, host, client_ip, country_code, method, uri,
           rule_id, rule_message, severity, raw_data, blocked, tx_id
    FROM waf_events
    WHERE tx_id = {p_tx:String}
    ORDER BY ts DESC
    LIMIT 1
  `, { p_tx: eventId });
  return row ? wafEventFromRow(row, 1) : null;
}

export interface WafPeriodSummary {
  total: number;
  blocked: number;
  uniqueClientIps: number;
  rules: number;
  hosts: number;
}

/** Totals of the WAF events in a period. */
export async function queryWafPeriodSummary(from: number, to: number): Promise<WafPeriodSummary> {
  const row = await queryRow<{ total: string; blocked: string; ips: string; rules: string; hosts: string }>(`
    SELECT count() AS total, countIf(blocked) AS blocked, uniq(client_ip) AS ips,
           uniqExactIf(rule_id, rule_id IS NOT NULL) AS rules, uniqExact(host) AS hosts
    FROM waf_events
    WHERE ${timeFilter()}
  `, timeParams(from, to));
  return {
    total: Number(row?.total ?? 0),
    blocked: Number(row?.blocked ?? 0),
    uniqueClientIps: Number(row?.ips ?? 0),
    rules: Number(row?.rules ?? 0),
    hosts: Number(row?.hosts ?? 0),
  };
}

/** WAF events per UTC day in a period, oldest first; days without events are left out. */
export async function queryWafDailyCounts(from: number, to: number): Promise<{ day: string; count: number; blocked: number }[]> {
  const rows = await queryRows<{ day: string; count: string; blocked: string }>(`
    SELECT toString(toDate(ts, 'UTC')) AS day, count() AS count, countIf(blocked) AS blocked
    FROM waf_events
    WHERE ${timeFilter()}
    GROUP BY day
    ORDER BY day
  `, timeParams(from, to));
  return rows.map((r) => ({ day: r.day, count: Number(r.count), blocked: Number(r.blocked) }));
}

/** WAF events per request host (as stored, port included) in a period. */
export async function queryWafHostCounts(from: number, to: number): Promise<{ host: string; count: number; blocked: number }[]> {
  const rows = await queryRows<{ host: string; count: string; blocked: string }>(`
    SELECT host, count() AS count, countIf(blocked) AS blocked
    FROM waf_events
    WHERE ${timeFilter()}
    GROUP BY host
    ORDER BY count DESC
    LIMIT 10000
  `, timeParams(from, to));
  return rows.map((r) => ({ host: r.host, count: Number(r.count), blocked: Number(r.blocked) }));
}
