/**
 * One pass of the access log parser: it reads the access log first and
 * waf-rules.log right after (so every WAF-interrupted request it reads has
 * its violation in hand), starts waf-rules.log near its end the first time,
 * carries violations whose access log line is not written yet to the next
 * pass, and stores the outcome of each request.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({
  values: new Map<string, string>(),
  files: new Map<string, { size: number; lines: string[] }>(),
  reads: [] as { file: string; start: number }[],
  inserted: [] as Record<string, unknown>[],
}));

vi.mock('@/src/lib/db', async () => {
  // The parse state lives in state.values; `eq` (mocked below) reduces a
  // condition to its key. Queries are awaited: the chain ends in promises.
  let lastKey = '';
  const fake = {
    select: () => ({
      from: () => ({
        where: (cond: { key?: string }) => {
          lastKey = cond?.key ?? lastKey;
          const key = lastKey;
          return { limit: async () => (state.values.has(key) ? [{ value: state.values.get(key) }] : []) };
        },
        then: (resolve: (rows: unknown[]) => unknown) => resolve([]),
      }),
    }),
    insert: () => ({
      values: (row: { key: string; value: string }) => ({
        onConflictDoUpdate: async () => {
          state.values.set(row.key, row.value);
        },
      }),
    }),
  };
  return (await import('../helpers/db-module')).mockDbModule(() => fake);
});
vi.mock('drizzle-orm', async (importOriginal) => ({
  ...(await importOriginal<typeof import('drizzle-orm')>()),
  eq: (_column: unknown, key: string) => ({ key }),
}));
vi.mock('maxmind', () => ({ default: { open: vi.fn().mockResolvedValue(null) } }));
vi.mock('node:fs', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:fs')>()),
  existsSync: (path: string) => state.files.has(path),
  statSync: (path: string) => ({ size: state.files.get(path)?.size ?? 0 }),
}));
vi.mock('@/src/lib/log-read', () => ({
  readLines: async (start: number, file: string) => {
    state.reads.push({ file, start });
    const entry = state.files.get(file);
    return { lines: entry ? entry.lines : [], newOffset: entry?.size ?? start };
  },
}));
vi.mock('@/src/lib/clickhouse/client', () => ({
  insertTrafficEvents: async (rows: Record<string, unknown>[]) => { state.inserted.push(...rows); },
}));
vi.mock('@/src/lib/analytics/address-rules', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/src/lib/analytics/address-rules')>()),
  getAddressRuleList: async () => null,
}));

import { parseNewLogEntries } from '@/src/lib/log-parser';

const ACCESS = '/logs/access.log';
const RULES = '/logs/waf-rules.log';
// Recent: violations older than the carry-over window (3 minutes) are dropped.
const TS = Math.floor(Date.now() / 1000) - 10;

const handled = (uri: string, status: number, ts = TS) =>
  JSON.stringify({ ts: ts + 0.5, msg: 'handled request', waf_transaction_id: `tx-${uri}`, status, size: 1, duration: 0.01, request: { client_ip: '203.0.113.9', host: 'app.example.com', method: 'GET', uri, proto: 'HTTP/1.1', headers: {} } });
const violation = (uri: string, ts = TS) =>
  JSON.stringify({ level: 'error', ts: ts + 0.2, logger: 'http.handlers.waf', msg: 'WAF rule violation detected', hostname: 'app.example.com', uri, client_ip: '203.0.113.9', unique_id: `tx-${uri}` });
const rule = (uri: string, id: number, ts = TS) =>
  JSON.stringify({ level: 'error', ts: ts + 0.1, logger: 'http.handlers.waf', msg: `[client "203.0.113.9"] Coraza: Warning. x [id "${id}"] [unique_id "tx-${uri}"]` });

beforeEach(() => {
  state.values.clear();
  state.files.clear();
  state.reads = [];
  state.inserted = [];
});

describe('parseNewLogEntries', () => {
  it('reads waf-rules.log after the access log and stores WAF outcomes with their rule', async () => {
    state.files.set(ACCESS, { size: 100, lines: [handled('/x?q=<script>', 403), handled('/ok', 200)] });
    state.files.set(RULES, { size: 5_000_000, lines: [rule('/x?q=<script>', 941100), violation('/x?q=<script>')] });
    await parseNewLogEntries();
    expect(state.reads.map((read) => read.file)).toEqual([ACCESS, RULES]);
    // First pass: only the last megabyte of waf-rules.log.
    expect(state.reads[1].start).toBe(5_000_000 - 1024 * 1024);
    expect(state.inserted.map((row) => [row.uri, row.outcome, row.waf_rule_id])).toEqual([
      ['/x?q=<script>', 'waf', 941100],
      ['/ok', 'served', 0],
    ]);
    expect(state.values.get('access_waf_rules_offset')).toBe('5000000');
  });

  it('matches a violation read before its access log line on the next pass', async () => {
    state.files.set(ACCESS, { size: 10, lines: [] });
    state.files.set(RULES, { size: 50, lines: [violation('/late')] });
    await parseNewLogEntries();
    expect(state.inserted).toHaveLength(0);

    state.reads = [];
    state.files.set(ACCESS, { size: 20, lines: [handled('/late', 403, TS + 1)] });
    state.files.set(RULES, { size: 50, lines: [] });
    await parseNewLogEntries();
    expect(state.reads.find((read) => read.file === RULES)?.start).toBe(50);
    expect(state.inserted.map((row) => row.outcome)).toEqual(['waf']);
  });

  it('works without waf-rules.log', async () => {
    state.files.set(ACCESS, { size: 10, lines: [handled('/plain', 200)] });
    await parseNewLogEntries();
    expect(state.inserted.map((row) => row.outcome)).toEqual(['served']);
  });
});
