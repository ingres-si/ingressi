import { afterEach, describe, expect, it, vi } from 'vitest';

describe('clickhouse client analytics enablement', () => {
  afterEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
    vi.doUnmock('@clickhouse/client');
  });

  it('treats analytics as enabled when CLICKHOUSE_PASSWORD is configured before init runs', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');

    const query = vi
      .fn()
      .mockResolvedValueOnce({ json: async () => [{ total: '12', unique_ips: '4', blocked: '2', rate_limited: '1', bytes: '1024' }] })
      .mockResolvedValueOnce({ json: async () => [{ waf_blocked: '3' }] });

    const createClient = vi.fn(() => ({ query, command: vi.fn(), insert: vi.fn(), close: vi.fn() }));

    vi.doMock('@clickhouse/client', () => ({
      createClient,
    }));

    const { isAnalyticsEnabled, querySummary } = await import('@/src/lib/clickhouse/client');

    expect(isAnalyticsEnabled()).toBe(true);

    await expect(querySummary(0, 60, [])).resolves.toEqual({
      totalRequests: 12,
      uniqueIps: 4,
      blockedRequests: 5,
      blockedPercent: 41.7,
      rateLimitedRequests: 1,
      bytesServed: 1024,
    });

    expect(query).toHaveBeenCalledTimes(2);
    expect(createClient).toHaveBeenCalledWith(expect.objectContaining({
      log: { level: 127 },
      clickhouse_settings: {
        async_insert: 1,
        wait_for_async_insert: 0,
      },
    }));
  });

  it('treats analytics as disabled when CLICKHOUSE_PASSWORD is missing', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', '');

    const createClient = vi.fn();
    vi.doMock('@clickhouse/client', () => ({ createClient }));

    const { isAnalyticsEnabled, querySummary } = await import('@/src/lib/clickhouse/client');

    expect(isAnalyticsEnabled()).toBe(false);

    await expect(querySummary(0, 60, [])).resolves.toEqual({
      totalRequests: 0,
      uniqueIps: 0,
      blockedRequests: 0,
      blockedPercent: 0,
      rateLimitedRequests: 0,
      bytesServed: 0,
    });

    expect(createClient).not.toHaveBeenCalled();
  });

  it('defaults retention to 30 days and creates tables with a 30-day TTL', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    vi.stubEnv('CLICKHOUSE_RETENTION_DAYS', '');

    const commands: string[] = [];
    const command = vi.fn(async ({ query }: { query: string }) => { commands.push(query); });
    // ensureRetentionTtl reads the live TTL; report it already matches 30 days.
    const query = vi.fn(async () => ({ json: async () => [{ create_table_query: 'TTL ts + toIntervalDay(30)' }] }));

    vi.doMock('@clickhouse/client', () => ({
      createClient: vi.fn(() => ({ query, command, insert: vi.fn(), close: vi.fn() })),
    }));

    const { getRetentionDays, initClickHouse } = await import('@/src/lib/clickhouse/client');
    expect(getRetentionDays()).toBe(30);

    await initClickHouse();

    const trafficDdl = commands.find(q => q.includes('CREATE TABLE IF NOT EXISTS traffic_events'));
    const wafDdl = commands.find(q => q.includes('CREATE TABLE IF NOT EXISTS waf_events'));
    expect(trafficDdl).toContain('TTL ts + INTERVAL 30 DAY DELETE');
    expect(wafDdl).toContain('TTL ts + INTERVAL 30 DAY DELETE');
    // TTL already matches → no MODIFY TTL migration issued.
    expect(commands.some(q => q.includes('MODIFY TTL'))).toBe(false);
  });

  it('honors a custom retention value and migrates an existing table whose TTL differs', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    vi.stubEnv('CLICKHOUSE_RETENTION_DAYS', '7');

    const commands: string[] = [];
    const command = vi.fn(async ({ query }: { query: string }) => { commands.push(query); });
    // Existing tables were created under the old 90-day TTL.
    const query = vi.fn(async () => ({ json: async () => [{ create_table_query: 'TTL ts + toIntervalDay(90)' }] }));

    vi.doMock('@clickhouse/client', () => ({
      createClient: vi.fn(() => ({ query, command, insert: vi.fn(), close: vi.fn() })),
    }));

    const { getRetentionDays, initClickHouse } = await import('@/src/lib/clickhouse/client');
    expect(getRetentionDays()).toBe(7);

    await initClickHouse();

    expect(commands.find(q => q.includes('CREATE TABLE IF NOT EXISTS traffic_events')))
      .toContain('TTL ts + INTERVAL 7 DAY DELETE');
    const modifies = commands.filter(q => /ALTER TABLE \w+ MODIFY TTL ts \+ INTERVAL 7 DAY DELETE/.test(q));
    expect(modifies).toHaveLength(2);
  });

  it('throws when CLICKHOUSE_RETENTION_DAYS is not a positive integer', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    vi.stubEnv('CLICKHOUSE_RETENTION_DAYS', 'not-a-number');
    vi.doMock('@clickhouse/client', () => ({ createClient: vi.fn() }));

    await expect(import('@/src/lib/clickhouse/client')).rejects.toThrow(/CLICKHOUSE_RETENTION_DAYS/);
  });

  // The drop step first enumerates matching tables from system.tables, then drops
  // each. This mock answers the enumeration query with `liveTables` and every
  // other query (the retention create_table_query read) with a matching 30-day TTL.
  function mockClient(liveTables: string[], commandImpl?: (q: string) => void) {
    const calls: { command: string[]; queries: { query: string; params?: Record<string, unknown> }[] } = {
      command: [],
      queries: [],
    };
    const command = vi.fn(async ({ query }: { query: string }) => {
      calls.command.push(query);
      commandImpl?.(query);
    });
    const query = vi.fn(async ({ query, query_params }: { query: string; query_params?: Record<string, unknown> }) => {
      calls.queries.push({ query, params: query_params });
      if (query.includes('FROM system.tables') && query.includes('match(name')) {
        return { json: async () => liveTables.map((name) => ({ name })) };
      }
      return { json: async () => [{ create_table_query: 'TTL ts + toIntervalDay(30)' }] };
    });
    vi.doMock('@clickhouse/client', () => ({
      createClient: vi.fn(() => ({ query, command, insert: vi.fn(), close: vi.fn() })),
    }));
    return calls;
  }

  it('drops every disabled system-log table that exists, including numbered upgrade leftovers', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');

    // What system.tables would return: live tables, numbered _N copies from past
    // upgrades, and the newly-disabled histogram_metric_log.
    const liveTables = ['trace_log', 'trace_log_3', 'trace_log_5', 'metric_log', 'metric_log_0', 'histogram_metric_log'];
    const calls = mockClient(liveTables);

    const { initClickHouse } = await import('@/src/lib/clickhouse/client');
    await initClickHouse();

    // The enumeration matches the disabled families plus an optional _<N> suffix,
    // and now includes histogram_metric_log.
    const enumeration = calls.queries.find((q) => q.query.includes('match(name'));
    expect(enumeration?.params?.pattern).toBe(
      '^(metric_log|asynchronous_metric_log|trace_log|query_log|query_thread_log|query_views_log|' +
      'part_log|processors_profile_log|text_log|session_log|opentelemetry_span_log|blob_storage_log|' +
      'backup_log|histogram_metric_log)(_[0-9]+)?$',
    );

    // Exactly the tables that exist are dropped — the _N leftovers included.
    for (const name of liveTables) {
      expect(calls.command).toContain(`DROP TABLE IF EXISTS system.${name} SYNC`);
    }
    const drops = calls.command.filter((q) => q.startsWith('DROP TABLE IF EXISTS system.'));
    expect(drops).toHaveLength(liveTables.length);
  });

  it('does not abort init when dropping system-log tables fails (insufficient privileges)', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');

    const dropAttempts: string[] = [];
    const calls = mockClient(['trace_log', 'metric_log', 'part_log'], (q) => {
      if (q.startsWith('DROP TABLE IF EXISTS system.')) {
        dropAttempts.push(q);
        throw new Error('Not enough privileges. To execute this query, it is necessary to have the grant DROP TABLE');
      }
    });

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const { initClickHouse } = await import('@/src/lib/clickhouse/client');
    // Best-effort: a privilege error must not reject and abort startup.
    await expect(initClickHouse()).resolves.toBeUndefined();

    // Bails out after the first failure rather than spamming a warning per table.
    expect(dropAttempts).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('could not drop disabled system log tables');
    void calls;

    warn.mockRestore();
  });

  it('returns full WAF stats for the filtered result set', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');

    const query = vi.fn().mockResolvedValueOnce({
      json: async () => [{ total: '5400', blocked: '5400', critical: '5400', unique_hosts: '1', rule_ids_triggered: '3' }],
    });

    vi.doMock('@clickhouse/client', () => ({
      createClient: vi.fn(() => ({ query, command: vi.fn(), insert: vi.fn(), close: vi.fn() })),
    }));

    const { queryWafEventStatsWithSearch } = await import('@/src/lib/clickhouse/client');

    await expect(queryWafEventStatsWithSearch('example.com')).resolves.toEqual({
      total: 5400,
      blocked: 5400,
      critical: 5400,
      uniqueHosts: 1,
      ruleIdsTriggered: 3,
    });

    expect(query).toHaveBeenCalledTimes(1);
  });

  it('adds the WAF event id column to new and existing tables, computed from the audit record', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    const commands: string[] = [];
    const command = vi.fn(async ({ query }: { query: string }) => { commands.push(query); });
    const query = vi.fn(async () => ({ json: async () => [{ create_table_query: 'TTL ts + toIntervalDay(30)' }] }));
    vi.doMock('@clickhouse/client', () => ({
      createClient: vi.fn(() => ({ query, command, insert: vi.fn(), close: vi.fn() })),
    }));
    const { initClickHouse } = await import('@/src/lib/clickhouse/client');
    await initClickHouse();
    const expression = "JSONExtractString(ifNull(raw_data, ''), 'transaction', 'id')";
    expect(commands.find((q) => q.includes('CREATE TABLE IF NOT EXISTS waf_events'))).toContain(`tx_id        String            DEFAULT ${expression}`);
    expect(commands).toContain(`ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS tx_id String DEFAULT ${expression} CODEC(ZSTD(3))`);
  });

  it('finds a WAF event by its id with a bound parameter', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    const query = vi.fn().mockResolvedValueOnce({
      json: async () => [{
        ts: '1790938961', host: 'app.example.com', client_ip: '203.0.113.66', country_code: null, method: 'GET', uri: '/',
        rule_id: '942100', rule_message: 'SQL Injection', severity: 'critical', raw_data: '{}', blocked: '1', tx_id: "x' OR 1=1 --",
      }],
    });
    vi.doMock('@clickhouse/client', () => ({
      createClient: vi.fn(() => ({ query, command: vi.fn(), insert: vi.fn(), close: vi.fn() })),
    }));
    const { queryWafEventByTxId } = await import('@/src/lib/clickhouse/client');
    await expect(queryWafEventByTxId("x' OR 1=1 --")).resolves.toMatchObject({ eventId: "x' OR 1=1 --", ruleId: 942100, blocked: true });
    const call = query.mock.calls[0][0] as { query: string; query_params: Record<string, unknown> };
    expect(call.query).toContain('WHERE tx_id = {p_tx:String}');
    expect(call.query).not.toContain('OR 1=1');
    expect(call.query_params).toEqual({ p_tx: "x' OR 1=1 --" });
  });
});


describe('ClickHouse UTC timestamp contract (issue 400)', () => {
  afterEach(() => { vi.resetModules(); vi.unstubAllEnvs(); vi.doUnmock('@clickhouse/client'); });
  it('uses explicit UTC for fresh tables and existing-table migrations, with numeric epochs for both inserts', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'isolated-test');
    const command = vi.fn(); const insert = vi.fn();
    vi.doMock('@clickhouse/client', () => ({ createClient: () => ({ command, insert, query: async () => ({ json: async () => [] }) }) }));
    const client = await import('@/src/lib/clickhouse/client');
    await client.initClickHouse();
    const commands = command.mock.calls.map(([x]) => x.query as string);
    for (const table of ['traffic_events', 'waf_events']) {
      expect(commands.find((q) => q.includes('CREATE TABLE IF NOT EXISTS ' + table))).toContain("DateTime('UTC')");
      expect(commands.some((q) => q.startsWith(`ALTER TABLE ${table} MODIFY COLUMN ts `))).toBe(false);
    }
    for (const epoch of [0, 1793511000.9, 1793514600, 4294967295]) {
      await client.insertTrafficEvents([{ ts: epoch, is_blocked: false, is_rate_limited: false } as never]);
      await client.insertWafEvents([{ ts: epoch, blocked: true } as never]);
    }
    expect(insert.mock.calls.map(([x]) => x.values[0].ts)).toEqual([0, 0, 1793511000, 1793511000, 1793514600, 1793514600, 4294967295, 4294967295]);
    // Out-of-range rows are dropped so one bad line cannot stall ingestion.
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    insert.mockClear();
    for (const ts of [NaN, Infinity, -1, 4294967296]) {
      await client.insertTrafficEvents([{ ts } as never]);
      await client.insertWafEvents([{ ts } as never]);
    }
    expect(insert).not.toHaveBeenCalled();
    await client.insertTrafficEvents([{ ts: -1 } as never, { ts: 1793514600, is_blocked: false, is_rate_limited: false } as never]);
    expect(insert.mock.calls.map(([x]) => x.values.map((v: { ts: number }) => v.ts))).toEqual([[1793514600]]);
  });
});
