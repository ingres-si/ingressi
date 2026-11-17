/**
 * Security events: mitigated requests by source over time (traffic_events
 * outcomes), the WAF rules, source addresses and hosts behind them
 * (waf_events, which also holds detection-only matches), and the event list
 * that merges both.
 */
import { ApiValidationError } from '../api-errors';
import {
  COUNTRY_SQL,
  DIMENSION_SPECS,
  HOST_NAME_SQL,
  MITIGATED_SQL,
  OUTCOME_SQL,
  PATH_SQL,
  WAF_COUNTRY_SQL,
  WAF_PATH_SQL,
  type Dimension,
} from './dimensions';
import { filterCondition, isContainsOp, parseFilters, type AnalyticsFilter, type SqlFragment } from './filters';
import { initGeoIp, lookupIp } from './geoip';
import { MITIGATED_OUTCOMES, isOutcome, type Outcome } from './outcome';
import { OUTCOME_LABELS, type Series } from './query';
import { previousPeriod, sparklineStep, type ResolvedRange } from './range';
import { delta, num, ratio, selectRows, withAnalytics, type AnalyticsStatus, type QueryParams } from './run';
import { hostName, proxyHostForName, type ProxyHostDomains } from './scope';

function timeWhere(): string {
  return 'ts >= toDateTime({p_from:UInt32}) AND ts < toDateTime({p_to:UInt32})';
}

function baseParams(range: ResolvedRange): QueryParams {
  return { p_from: range.start, p_to: range.end };
}

// ── Mitigated requests by source ─────────────────────────────────────────

export type SecuritySeriesResult = {
  status: AnalyticsStatus;
  range: { preset: string; start: number; end: number; step: number; buckets: number };
  /** One series per mitigation source (waf, geo, access, auth, rate_limit), current period. */
  series: Series[];
  totals: {
    mitigated: number;
    requests: number;
    /** Mitigated over all requests, 0 to 1. */
    share: number;
    /** Mitigated in the previous period; null when it is outside the retention window. */
    previousMitigated: number | null;
    delta: number | null;
  };
  peak: SecurityPeak | null;
};

/** What stood out in the busiest bucket: where most of it came from, which host it hit and the WAF rule that matched most. */
export type SecurityPeakTop = {
  /** Distinct source addresses in the bucket. */
  addresses: number;
  source: { ip: string; country: string; count: number } | null;
  host: { name: string; count: number } | null;
  rule: { ruleId: number; message: string | null; count: number } | null;
};

export type SecurityPeak = {
  index: number;
  ts: number;
  value: number;
  bySource: Partial<Record<Outcome, number>>;
  /** Attribution over the same mitigated traffic requests as value; detection-only matches are excluded. */
  top: SecurityPeakTop | null;
};

export async function querySecuritySeries(input: { range: ResolvedRange }, now = Math.floor(Date.now() / 1000)): Promise<SecuritySeriesResult> {
  const { range } = input;
  const prev = previousPeriod(range, now);
  const empty = {
    range: { preset: range.preset, start: range.start, end: range.end, step: range.step, buckets: range.buckets },
    series: [] as Series[],
    totals: { mitigated: 0, requests: 0, share: 0, previousMitigated: prev.available ? 0 : null, delta: null },
    peak: null,
  };
  return withAnalytics('security series', empty, async () => {
    const params = baseParams(range);
    const [rows, totals] = await Promise.all([
      selectRows<{ b: unknown; o: string; c: unknown }>(
        `SELECT intDiv(toUInt32(ts) - {p_from:UInt32}, {p_step:UInt32}) AS b, ${OUTCOME_SQL} AS o, count() AS c
         FROM traffic_events WHERE ${timeWhere()} AND ${MITIGATED_SQL}
         GROUP BY b, o`,
        { ...params, p_step: range.step }
      ),
      selectRows<{ requests: unknown; mitigated: unknown; previous: unknown }>(
        `SELECT countIf(ts >= toDateTime({p_from:UInt32})) AS requests,
                countIf(ts >= toDateTime({p_from:UInt32}) AND ${MITIGATED_SQL}) AS mitigated,
                countIf(ts < toDateTime({p_from:UInt32}) AND ${MITIGATED_SQL}) AS previous
         FROM traffic_events
         WHERE ts >= toDateTime({p_prev:UInt32}) AND ts < toDateTime({p_to:UInt32})`,
        { ...params, p_prev: prev.available ? prev.start : range.start }
      ),
    ]);
    const values = new Map<Outcome, number[]>();
    for (const row of rows) {
      const b = num(row.b);
      if (!isOutcome(row.o) || !Number.isInteger(b) || b < 0 || b >= range.buckets) continue;
      const list = values.get(row.o) ?? new Array<number>(range.buckets).fill(0);
      list[b] += num(row.c);
      values.set(row.o, list);
    }
    const series: Series[] = MITIGATED_OUTCOMES.filter((o) => values.has(o)).map((o) => {
      const list = values.get(o)!;
      return { key: o, label: OUTCOME_LABELS[o], values: list, total: list.reduce((a, v) => a + v, 0) };
    });
    let peakIndex = -1;
    let peakValue = 0;
    for (let i = 0; i < range.buckets; i++) {
      const value = series.reduce((a, s) => a + s.values[i], 0);
      if (value > peakValue) {
        peakValue = value;
        peakIndex = i;
      }
    }
    const mitigated = num(totals[0]?.mitigated);
    const requests = num(totals[0]?.requests);
    const previousMitigated = prev.available ? num(totals[0]?.previous) : null;
    let peak: SecurityPeak | null = null;
    if (peakIndex !== -1) {
      const ts = range.start + peakIndex * range.step;
      peak = {
        index: peakIndex,
        ts,
        value: peakValue,
        bySource: Object.fromEntries(series.map((s) => [s.key, s.values[peakIndex]]).filter(([, v]) => (v as number) > 0)),
        top: await queryPeakTop({ ...params, p_from: ts, p_to: ts + range.step }),
      };
    }
    return {
      ...empty,
      series,
      totals: { mitigated, requests, share: ratio(mitigated, requests), previousMitigated, delta: delta(mitigated, previousMitigated) },
      peak,
    };
  });
}

/** The same stopped-request population as the peak headline, counted once per access event. */
async function queryPeakTop(params: QueryParams): Promise<SecurityPeakTop | null> {
  const stopped = `traffic_events WHERE ${timeWhere()} AND ${MITIGATED_SQL}`;
  const [addresses, sources, hosts, rules] = await Promise.all([
    selectRows<{ n: unknown }>(`SELECT uniq(client_ip) AS n FROM ${stopped}`, params),
    selectRows<{ client_ip: unknown; country: unknown; n: unknown }>(
      `SELECT client_ip, any(${COUNTRY_SQL}) AS country, count() AS n FROM ${stopped} GROUP BY client_ip ORDER BY n DESC, client_ip LIMIT 1`, params
    ),
    selectRows<{ name: unknown; n: unknown }>(
      `SELECT ${HOST_NAME_SQL} AS name, count() AS n FROM ${stopped} GROUP BY name ORDER BY n DESC, name LIMIT 1`, params
    ),
    selectRows<{ rule_id: unknown; n: unknown }>(
      `SELECT waf_rule_id AS rule_id, count() AS n FROM ${stopped}
       AND (${OUTCOME_SQL}) = 'waf' AND waf_rule_id > 0
       GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT 1`, params
    ),
  ]);
  const source = sources[0];
  const host = hosts[0];
  const rule = rules[0];
  if (!source && !host && !rule) return null;
  // Audit events can include multiple rule matches per request. They provide
  // descriptive text only; never use their counts as stopped-request counts.
  const messages = rule ? await selectRows<{ message: unknown }>(
    `SELECT any(rule_message) AS message FROM waf_events WHERE ${timeWhere()}
     AND blocked AND rule_id = {p_peak_rule:Int32}`, { ...params, p_peak_rule: num(rule.rule_id) }
  ) : [];
  return {
    addresses: num(addresses[0]?.n),
    source: source ? { ip: String(source.client_ip ?? ''), country: String(source.country ?? '') || 'XX', count: num(source.n) } : null,
    host: host ? { name: String(host.name ?? ''), count: num(host.n) } : null,
    rule: rule ? { ruleId: num(rule.rule_id), message: messages[0]?.message == null ? null : String(messages[0].message), count: num(rule.n) } : null,
  };
}

// ── Top WAF rules ────────────────────────────────────────────────────────

export type SecurityRule = {
  ruleId: number;
  message: string | null;
  severity: string | null;
  events: number;
  blocked: number;
  /** Distinct source addresses. */
  sources: number;
  hostCount: number;
  pathCount: number;
  hosts: { host: string; count: number }[];
  paths: { path: string; count: number }[];
  /** Events per sparkline bucket over the range. */
  sparkline: number[];
};

export type SecurityRulesResult = {
  status: AnalyticsStatus;
  sparklineStep: number;
  totals: { events: number; rulesMatched: number };
  rules: SecurityRule[];
};

const RULE_DETAIL_LIMIT = 4;

export async function querySecurityRules(input: { range: ResolvedRange; limit: number }): Promise<SecurityRulesResult> {
  const { range } = input;
  const step = sparklineStep(range);
  const points = Math.ceil((range.end - range.start) / step);
  const empty = { sparklineStep: step, totals: { events: 0, rulesMatched: 0 }, rules: [] as SecurityRule[] };
  return withAnalytics('security rules', empty, async () => {
    const params = baseParams(range);
    const where = timeWhere();
    const [totals, top] = await Promise.all([
      selectRows<{ events: unknown; rules: unknown }>(
        `SELECT count() AS events, uniqExactIf(rule_id, rule_id IS NOT NULL) AS rules FROM waf_events WHERE ${where}`,
        params
      ),
      selectRows<Record<string, unknown>>(
        `SELECT rule_id, count() AS events, countIf(blocked) AS blocked_events, any(rule_message) AS message, any(severity) AS sev,
                uniq(client_ip) AS sources, uniq(host) AS host_count, uniq(${WAF_PATH_SQL}) AS path_count
         FROM waf_events WHERE ${where} AND rule_id IS NOT NULL
         GROUP BY rule_id ORDER BY events DESC, rule_id LIMIT {p_limit:UInt32}`,
        { ...params, p_limit: input.limit }
      ),
    ]);
    const ids = top.map((row) => num(row.rule_id)).filter((id) => Number.isInteger(id));
    const rules = new Map<number, SecurityRule>(
      top.map((row) => [
        num(row.rule_id),
        {
          ruleId: num(row.rule_id),
          message: row.message == null ? null : String(row.message),
          severity: row.sev == null ? null : String(row.sev),
          events: num(row.events),
          blocked: num(row.blocked_events),
          sources: num(row.sources),
          hostCount: num(row.host_count),
          pathCount: num(row.path_count),
          hosts: [],
          paths: [],
          sparkline: new Array<number>(points).fill(0),
        },
      ])
    );
    if (ids.length > 0) {
      const ruleParams = { ...params, p_ids: ids, p_detail: RULE_DETAIL_LIMIT, p_step: step };
      const [hosts, paths, trend] = await Promise.all([
        selectRows<{ rule_id: unknown; host: string; c: unknown }>(
          `SELECT rule_id, host, count() AS c FROM waf_events WHERE ${where} AND rule_id IN {p_ids:Array(Int32)}
           GROUP BY rule_id, host ORDER BY c DESC, host LIMIT {p_detail:UInt32} BY rule_id`,
          ruleParams
        ),
        selectRows<{ rule_id: unknown; path: string; c: unknown }>(
          `SELECT rule_id, ${WAF_PATH_SQL} AS path, count() AS c FROM waf_events WHERE ${where} AND rule_id IN {p_ids:Array(Int32)}
           GROUP BY rule_id, path ORDER BY c DESC, path LIMIT {p_detail:UInt32} BY rule_id`,
          ruleParams
        ),
        selectRows<{ rule_id: unknown; b: unknown; c: unknown }>(
          `SELECT rule_id, intDiv(toUInt32(ts) - {p_from:UInt32}, {p_step:UInt32}) AS b, count() AS c
           FROM waf_events WHERE ${where} AND rule_id IN {p_ids:Array(Int32)} GROUP BY rule_id, b`,
          ruleParams
        ),
      ]);
      for (const row of hosts) rules.get(num(row.rule_id))?.hosts.push({ host: String(row.host ?? ''), count: num(row.c) });
      for (const row of paths) rules.get(num(row.rule_id))?.paths.push({ path: String(row.path ?? ''), count: num(row.c) });
      for (const row of trend) {
        const b = num(row.b);
        const rule = rules.get(num(row.rule_id));
        if (rule && Number.isInteger(b) && b >= 0 && b < points) rule.sparkline[b] += num(row.c);
      }
    }
    return {
      ...empty,
      totals: { events: num(totals[0]?.events), rulesMatched: num(totals[0]?.rules) },
      rules: [...rules.values()],
    };
  });
}

// ── Top source addresses ─────────────────────────────────────────────────

export type SecuritySource = {
  ip: string;
  country: string;
  asn: number;
  asOrg: string;
  /** WAF events (detection-only matches included). */
  wafEvents: number;
  wafBlocked: number;
  /** Requests stopped by geo, access, sign-in or rate limit rules. */
  otherMitigated: number;
  /** Up to five WAF rules the address triggered. */
  rules: number[];
  hosts: number;
  lastSeen: number;
};

export type SecuritySourcesResult = { status: AnalyticsStatus; totals: { addresses: number }; sources: SecuritySource[] };

const SOURCES_UNION = `
  SELECT client_ip, host, ts, 1 AS w, toUInt8(blocked) AS wb, 0 AS o, ${WAF_COUNTRY_SQL} AS c, toUInt32(ifNull(rule_id, 0)) AS r
  FROM waf_events WHERE ts >= toDateTime({p_from:UInt32}) AND ts < toDateTime({p_to:UInt32})
  UNION ALL
  SELECT client_ip, host, ts, 0 AS w, 0 AS wb, 1 AS o, ${COUNTRY_SQL} AS c, toUInt32(0) AS r
  FROM traffic_events WHERE ts >= toDateTime({p_from:UInt32}) AND ts < toDateTime({p_to:UInt32})
    AND ${MITIGATED_SQL} AND (${OUTCOME_SQL}) != 'waf'`;

export async function querySecuritySources(input: { range: ResolvedRange; limit: number }): Promise<SecuritySourcesResult> {
  const empty = { totals: { addresses: 0 }, sources: [] as SecuritySource[] };
  return withAnalytics('security sources', empty, async () => {
    const params = baseParams(input.range);
      const [totals, rows] = await Promise.all([
      selectRows<{ n: unknown }>(`SELECT uniq(client_ip) AS n FROM (${SOURCES_UNION})`, params),
      selectRows<Record<string, unknown>>(
        `SELECT client_ip, sum(w) AS waf, sum(wb) AS waf_blocked, sum(o) AS other, any(c) AS country,
                groupUniqArrayIf(5)(r, r != 0) AS rules, uniq(host) AS hosts, toUInt32(max(ts)) AS last_seen
         FROM (${SOURCES_UNION})
         GROUP BY client_ip ORDER BY (waf + other) DESC, client_ip LIMIT {p_limit:UInt32}`,
        { ...params, p_limit: input.limit }
      ),
    ]);
    await initGeoIp();
    return {
      totals: { addresses: num(totals[0]?.n) },
      sources: rows.map((row) => {
        const ip = String(row.client_ip ?? '');
        const info = lookupIp(ip);
        return {
          ip,
          country: String(row.country ?? '') || info.country || 'XX',
          asn: info.asn,
          asOrg: info.asOrg,
          wafEvents: num(row.waf),
          wafBlocked: num(row.waf_blocked),
          otherMitigated: num(row.other),
          rules: Array.isArray(row.rules) ? row.rules.map(num).filter((id) => id > 0).sort((a, b) => a - b) : [],
          hosts: num(row.hosts),
          lastSeen: num(row.last_seen),
        };
      }),
    };
  });
}

// ── Most targeted hosts ──────────────────────────────────────────────────

export type SecurityHost = {
  /** The stored Host as a bare lowercase name (no port). */
  host: string;
  /** WAF events plus requests stopped by the other rules. */
  events: number;
  wafEvents: number;
  otherMitigated: number;
  /** The proxy host serving the name, when one does. */
  proxyHostId: number | null;
};

export type SecurityHostsResult = { status: AnalyticsStatus; totals: { events: number }; hosts: SecurityHost[] };

/** Hosts ranked by WAF events plus requests stopped by geo, access, sign-in and rate limit rules. */
export async function querySecurityHosts(
  input: { range: ResolvedRange; limit: number },
  proxyHosts: readonly ProxyHostDomains[] = []
): Promise<SecurityHostsResult> {
  const empty = { totals: { events: 0 }, hosts: [] as SecurityHost[] };
  return withAnalytics('security hosts', empty, async () => {
    const params = baseParams(input.range);
      const [totals, rows] = await Promise.all([
      selectRows<{ n: unknown }>(`SELECT count() AS n FROM (${SOURCES_UNION})`, params),
      selectRows<{ name: unknown; events: unknown; waf: unknown; other: unknown }>(
        `SELECT ${HOST_NAME_SQL} AS name, count() AS events, sum(w) AS waf, sum(o) AS other
         FROM (${SOURCES_UNION}) GROUP BY name ORDER BY events DESC, name LIMIT {p_limit:UInt32}`,
        { ...params, p_limit: input.limit }
      ),
    ]);
    return {
      totals: { events: num(totals[0]?.n) },
      hosts: rows.map((row) => {
        const name = String(row.name ?? '');
        return {
          host: name,
          events: num(row.events),
          wafEvents: num(row.waf),
          otherMitigated: num(row.other),
          proxyHostId: name ? proxyHostForName(name, proxyHosts) : null,
        };
      }),
    };
  });
}

// ── Event list ───────────────────────────────────────────────────────────

export const SECURITY_EVENT_KINDS = ['waf', 'geo', 'access', 'auth', 'rate_limit'] as const;
export type SecurityEventKind = (typeof SECURITY_EVENT_KINDS)[number];

export type SecurityEvent = {
  ts: number;
  kind: SecurityEventKind;
  /** WAF events: Coraza's transaction id, for GET /api/v1/waf/events/{id}/explain; null for the other kinds. */
  eventId: string | null;
  /** False for a WAF match in detection-only mode (the request was served). */
  blocked: boolean;
  host: string;
  method: string;
  path: string;
  ip: string;
  country: string;
  /** WAF events: the rule, its message and severity. */
  ruleId: number | null;
  message: string | null;
  severity: string | null;
  /** Status Caddy answered with (0 for WAF events, whose status is in the audit record). */
  status: number;
};

export type SecurityEventsResult = { status: AnalyticsStatus; events: SecurityEvent[]; limit: number; offset: number };

export function parseEventKinds(value: unknown): SecurityEventKind[] {
  if (value === undefined || value === null || value === '') return [...SECURITY_EVENT_KINDS];
  const list = String(value).split(',').map((v) => v.trim()).filter(Boolean);
  for (const kind of list) {
    if (!(SECURITY_EVENT_KINDS as readonly string[]).includes(kind)) {
      throw new ApiValidationError(`kind must be one or more of ${SECURITY_EVENT_KINDS.join(', ')}`);
    }
  }
  return [...new Set(list)] as SecurityEventKind[];
}

/** Dimensions the event list can be filtered by (both tables have them). */
export const SECURITY_EVENT_FILTER_DIMENSIONS = ['host', 'path', 'country', 'ip', 'method', 'waf_rule'] as const satisfies readonly Dimension[];

/**
 * Filters of the event list, in the analytics format (filters.ts), limited
 * to SECURITY_EVENT_FILTER_DIMENSIONS. Throws ApiValidationError.
 */
export function parseSecurityEventFilters(input: unknown): AnalyticsFilter[] {
  const filters = parseFilters(input);
  for (const filter of filters) {
    if (!(SECURITY_EVENT_FILTER_DIMENSIONS as readonly string[]).includes(filter.dim)) {
      throw new ApiValidationError(`Security events can be filtered by ${SECURITY_EVENT_FILTER_DIMENSIONS.join(', ')}`);
    }
  }
  return filters;
}

/**
 * WHERE fragment of the event filters for one side of the union. Values are
 * validated by the dimension specs and bound as sf0, sf1...; a host is
 * compared as a bare name (port and case ignored), and a WAF rule filter
 * leaves out the requests the other rules stopped, which have no rule.
 */
function eventFilterSql(filters: readonly AnalyticsFilter[], table: 'waf' | 'traffic'): SqlFragment {
  const params: Record<string, unknown> = {};
  const include = new Map<string, string[]>();
  const exclude: string[] = [];
  filters.forEach((filter, index) => {
    const name = `sf${index}`;
    let condition: string;
    if (isContainsOp(filter.op)) {
      condition = filterCondition(filter, name, params);
    } else if (filter.dim === 'host') {
      params[name] = hostName(filter.value);
      condition = `${HOST_NAME_SQL} = {${name}:String}`;
    } else if (filter.dim === 'waf_rule') {
      params[name] = DIMENSION_SPECS.waf_rule.compare(filter.value).value;
      condition = table === 'waf' ? `toUInt32(ifNull(rule_id, 0)) = {${name}:UInt32}` : '0';
    } else {
      const compared = DIMENSION_SPECS[filter.dim].compare(filter.value);
      params[name] = compared.value;
      condition = `(${compared.sql}) = {${name}:${compared.type}}`;
    }
    if (filter.op === 'is' || filter.op === 'contains') include.set(filter.dim, [...(include.get(filter.dim) ?? []), condition]);
    else exclude.push(`NOT (${condition})`);
  });
  const clauses = [...[...include.values()].map((list) => `(${list.join(' OR ')})`), ...exclude];
  return { sql: clauses.length > 0 ? clauses.join(' AND ') : '1', params };
}

/** Newest first; WAF events and requests stopped by the other rules, merged. */
export async function querySecurityEvents(
  input: { range: ResolvedRange; limit: number; offset: number; kinds: SecurityEventKind[]; filters?: readonly AnalyticsFilter[] }
): Promise<SecurityEventsResult> {
  const empty = { events: [] as SecurityEvent[], limit: input.limit, offset: input.offset };
  return withAnalytics('security events', empty, async () => {
    const params = baseParams(input.range);
    const filters = input.filters ?? [];
    const wafFilter = eventFilterSql(filters, 'waf');
    const trafficFilter = eventFilterSql(filters, 'traffic');
    const others = input.kinds.filter((kind) => kind !== 'waf');
    const parts: string[] = [];
    if (input.kinds.includes('waf')) {
      parts.push(`SELECT toUInt32(ts) AS t, 'waf' AS kind, toUInt8(blocked) AS blk, host, method, ${WAF_PATH_SQL} AS path, client_ip,
                         ${WAF_COUNTRY_SQL} AS country, toInt64(ifNull(rule_id, -1)) AS rid, ifNull(rule_message, '') AS message,
                         ifNull(severity, '') AS sev, toUInt16(0) AS code, tx_id AS eid
                  FROM waf_events WHERE ${timeWhere()} AND ${wafFilter.sql}`);
    }
    if (others.length > 0) {
      parts.push(`SELECT toUInt32(ts) AS t, ${OUTCOME_SQL} AS kind, toUInt8(1) AS blk, host, method, ${PATH_SQL} AS path, client_ip,
                         ${COUNTRY_SQL} AS country, toInt64(-1) AS rid, '' AS message, '' AS sev, toUInt16(status) AS code, '' AS eid
                  FROM traffic_events WHERE ${timeWhere()} AND (${OUTCOME_SQL}) IN {p_kinds:Array(String)} AND ${trafficFilter.sql}`);
    }
    if (parts.length === 0) return empty;
    const rows = await selectRows<Record<string, unknown>>(
      `SELECT * FROM (${parts.join(' UNION ALL ')}) ORDER BY t DESC LIMIT {p_limit:UInt32} OFFSET {p_offset:UInt32}`,
      { ...params, ...wafFilter.params, ...trafficFilter.params, p_kinds: others, p_limit: input.limit, p_offset: input.offset }
    );
    return {
      ...empty,
      events: rows.map((row) => {
        const ruleId = num(row.rid);
        const eventId = row.kind === 'waf' && typeof row.eid === 'string' && row.eid ? row.eid : null;
        return {
          ts: num(row.t),
          kind: String(row.kind) as SecurityEventKind,
          eventId,
          blocked: num(row.blk) === 1,
          host: String(row.host ?? ''),
          method: String(row.method ?? ''),
          path: String(row.path ?? ''),
          ip: String(row.client_ip ?? ''),
          country: String(row.country ?? ''),
          ruleId: ruleId >= 0 && row.kind === 'waf' ? ruleId : null,
          message: row.message ? String(row.message) : null,
          severity: row.sev ? String(row.sev) : null,
          status: num(row.code),
        };
      }),
    };
  });
}

/** A WAF rule that matched a host's requests: how often, how often it blocked, and the path it matched most. */
export type HostWafRule = { ruleId: number; message: string | null; events: number; blocked: number; topPath: string | null };

/**
 * The WAF rules that matched the requests to one host (its domain names)
 * over `range`, most frequent first: what a host's Security tab offers to
 * exclude. Wildcard names are left out (events carry the name requested).
 */
export async function queryHostWafRules(input: { range: ResolvedRange; domains: readonly string[]; limit: number }): Promise<{ status: AnalyticsStatus; rules: HostWafRule[] }> {
  const names = [...new Set(input.domains.filter((domain) => !domain.includes('*')).map((domain) => hostName(domain)).filter(Boolean))];
  const empty = { rules: [] as HostWafRule[] };
  if (names.length === 0) return { ...empty, status: 'ok' };
  return withAnalytics('host waf rules', empty, async () => {
    const rows = await selectRows<Record<string, unknown>>(
      `SELECT rule_id, count() AS events, countIf(blocked) AS blocked_events, any(rule_message) AS message, topK(1)(${WAF_PATH_SQL}) AS top_path
       FROM waf_events WHERE ${timeWhere()} AND rule_id IS NOT NULL AND ${HOST_NAME_SQL} IN {p_hosts:Array(String)}
       GROUP BY rule_id ORDER BY events DESC, rule_id LIMIT {p_limit:UInt32}`,
      { ...baseParams(input.range), p_hosts: names, p_limit: input.limit }
    );
    return {
      rules: rows.map((row) => ({
        ruleId: num(row.rule_id),
        message: row.message == null ? null : String(row.message),
        events: num(row.events),
        blocked: num(row.blocked_events),
        topPath: Array.isArray(row.top_path) && row.top_path.length > 0 ? String(row.top_path[0]) : null,
      })),
    };
  });
}
