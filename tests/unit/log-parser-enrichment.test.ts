/**
 * What the log parser adds to each request: the network (GeoLite2-ASN,
 * through a mocked reader since the repository ships no fixture database),
 * the outcome correlated with caddy-blocker, the WAF (waf-rules.log) and
 * the response, the duration and the user-agent family.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/src/lib/db', async () => {
  // A real, empty test database: these tests do not look at the parse state.
  const { createTestDb } = await import('../helpers/db');
  const db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => db);
});
vi.mock('maxmind', () => ({ default: { open: vi.fn().mockResolvedValue(null) } }));
vi.mock('node:fs', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:fs')>()),
  existsSync: vi.fn().mockReturnValue(false),
}));
vi.mock('@/src/lib/clickhouse/client', () => ({ insertTrafficEvents: vi.fn().mockResolvedValue(undefined) }));

import { collectBlockedSignatures, durationMs, parseLine } from '@/src/lib/log-parser';
import { lookupIp, setGeoReaders } from '@/src/lib/analytics/geoip';
import { buildAddressRuleList, inAddressRules } from '@/src/lib/analytics/address-rules';
import {
  collectWafLogLines,
  consumeWafViolation,
  createWafCorrelation,
  pruneWafCorrelation,
} from '@/src/lib/analytics/waf-correlation';

const TS = 1_791_000_000;

function handled(overrides: Record<string, unknown> = {}, request: Record<string, unknown> = {}): string {
  return JSON.stringify({
    ts: TS + 0.4,
    msg: 'handled request',
    status: 200,
    size: 512,
    duration: 0.0421,
    request: {
      client_ip: '203.0.113.9',
      host: 'app.example.com',
      method: 'GET',
      uri: '/admin?token=x',
      proto: 'HTTP/2.0',
      headers: { 'User-Agent': ['curl/8.5.0'] },
      ...request,
    },
    ...overrides,
  });
}

function blockerLine(ts: number, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ ts, msg: 'request blocked', plugin: 'caddy-blocker', reason: 'block_rule', client_ip: '203.0.113.9', method: 'GET', uri: '/admin?token=x', ...extra });
}

const violation = (ts: number, uniqueId = 'tx1', extra: Record<string, unknown> = {}) =>
  JSON.stringify({ level: 'error', ts, logger: 'http.handlers.waf', msg: 'WAF rule violation detected', hostname: 'app.example.com', uri: '/admin?token=x', client_ip: '203.0.113.9', unique_id: uniqueId, ...extra });
const ruleMatch = (ts: number, id: number, uniqueId = 'tx1') =>
  JSON.stringify({ level: 'error', ts, logger: 'http.handlers.waf', msg: `[client "203.0.113.9"] Coraza: Warning. Restricted [id "${id}"] [msg "Restricted header"] [severity "critical"] [hostname "10.0.0.2"] [uri "/admin"] [unique_id "${uniqueId}"]` });

beforeEach(() => {
  setGeoReaders({ country: null, asn: null });
});

describe('ASN enrichment', () => {
  it('stores the AS number and organisation of the client address', () => {
    const asnGet = vi.fn((ip: string) => (ip === '203.0.113.9' ? { autonomous_system_number: 64500, autonomous_system_organization: 'Example\u0000 Networks ' } : null));
    setGeoReaders({ country: { get: () => ({ country: { iso_code: 'IT' } }) as never }, asn: { get: asnGet as never } });
    const row = parseLine(handled(), new Set())!;
    expect(row.asn).toBe(64500);
    expect(row.as_org).toBe('Example Networks');
    expect(row.country_code).toBe('IT');
    // Cached per address.
    parseLine(handled(), new Set());
    expect(asnGet).toHaveBeenCalledTimes(1);
  });

  it('leaves the network empty without a database or a record', () => {
    expect(parseLine(handled(), new Set())).toMatchObject({ asn: 0, as_org: '', country_code: null });
    setGeoReaders({ asn: { get: () => null } });
    expect(lookupIp('198.51.100.1')).toEqual({ country: null, asn: 0, asOrg: '' });
  });

  it('ignores malformed records and reader errors', () => {
    setGeoReaders({
      country: { get: () => ({ country: { iso_code: 'not-a-code' } }) as never },
      asn: { get: () => { throw new Error('corrupt'); } },
    });
    expect(lookupIp('198.51.100.2')).toEqual({ country: null, asn: 0, asOrg: '' });
    setGeoReaders({ asn: { get: () => ({ autonomous_system_number: -5, autonomous_system_organization: 'x' }) as never } });
    expect(lookupIp('198.51.100.3').asn).toBe(0);
  });
});

describe('parseLine fields', () => {
  it('records duration, user-agent family and served outcome', () => {
    const row = parseLine(handled(), new Set())!;
    expect(row.duration_ms).toBe(42);
    expect(row.ua_family).toBe('curl 8.5.0');
    expect(row.outcome).toBe('served');
    expect(row.waf_rule_id).toBe(0);
    expect(row.uri).toBe('/admin?token=x');
  });

  it('reads Go duration strings too', () => {
    expect(durationMs(1.5)).toBe(1500);
    expect(durationMs('1.5ms')).toBe(2);
    expect(durationMs('2m3.5s')).toBe(123_500);
    expect(durationMs('850µs')).toBe(1);
    expect(durationMs(-1)).toBe(0);
    expect(durationMs('nonsense')).toBe(0);
    expect(durationMs(1e12)).toBe(0xffffffff);
  });

  it('marks rate-limited, basic-auth and forward-auth requests', () => {
    expect(parseLine(handled({ status: 429, rate_limit_zone: 'login' }), new Set())!.outcome).toBe('rate_limit');
    expect(parseLine(handled({ status: 401, resp_headers: { 'Www-Authenticate': ['Basic realm="restricted"'] } }), new Set())!.outcome).toBe('access');
    const portal = parseLine(
      handled({ status: 302, resp_headers: { Location: ['https://ingressi.example.com/portal?rd=https%3A%2F%2Fapp.example.com%2F'] } }),
      new Set(),
      { portalUrl: 'https://ingressi.example.com/portal' }
    )!;
    expect(portal.outcome).toBe('auth');
  });
});

describe('caddy-blocker correlation', () => {
  it('is geo for a country or ASN rule and access for an address rule', () => {
    const lines = [blockerLine(TS + 0.1), handled({ status: 403 })];
    const geo = parseLine(lines[1], collectBlockedSignatures(lines), { addressRules: buildAddressRuleList([{ block_cidrs: ['198.51.100.0/24'] }]) })!;
    expect(geo).toMatchObject({ is_blocked: true, outcome: 'geo' });
    const access = parseLine(lines[1], collectBlockedSignatures(lines), { addressRules: buildAddressRuleList([{ block_cidrs: ['203.0.113.0/24'] }]) })!;
    expect(access).toMatchObject({ is_blocked: true, outcome: 'access' });
  });

  it('matches a block logged a second before the access log line', () => {
    const lines = [blockerLine(TS - 0.2), handled({ status: 403 })];
    expect(parseLine(lines[1], collectBlockedSignatures(lines))!.outcome).toBe('geo');
  });

  it('matches fail-closed blocks that only log remote_addr', () => {
    const lines = [
      JSON.stringify({ ts: TS + 0.1, msg: 'request blocked', plugin: 'caddy-blocker', reason: 'fail_closed', remote_addr: '203.0.113.9:51234', method: 'GET', uri: '/admin?token=x' }),
      handled({ status: 403 }),
    ];
    expect(parseLine(lines[1], collectBlockedSignatures(lines))!.outcome).toBe('geo');
  });
});

describe('address rules', () => {
  it('collects block_ips and block_cidrs of every geoblocking setting, skipping junk', () => {
    const list = buildAddressRuleList([
      { block_ips: ['192.0.2.7', 'not an ip', ''], block_cidrs: ['2001:db8::/32', '10.0.0.0/99'] },
      null,
      { block_cidrs: ['198.51.100.0/25'] },
    ]);
    expect(inAddressRules(list, '192.0.2.7')).toBe(true);
    expect(inAddressRules(list, '2001:db8::5')).toBe(true);
    expect(inAddressRules(list, '198.51.100.100')).toBe(true);
    expect(inAddressRules(list, '198.51.100.200')).toBe(false);
    expect(inAddressRules(list, '10.0.0.1')).toBe(false);
    expect(inAddressRules(list, 'garbage')).toBe(false);
    expect(inAddressRules(null, '192.0.2.7')).toBe(false);
  });
});

describe('WAF correlation', () => {
  const access = (status: number, id: unknown, extra: Record<string, unknown> = {}, request: Record<string, unknown> = {}) =>
    handled({ status, waf_transaction_id: id, ...extra }, request);

  it('marks the exact interrupted transaction and consumes it once', () => {
    const waf = collectWafLogLines([ruleMatch(TS, 949110), ruleMatch(TS, 920450), violation(TS + 0.2)]);
    expect(parseLine(access(403, 'tx1'), new Set(), { waf })).toMatchObject({ outcome: 'waf', waf_rule_id: 920450 });
    expect(parseLine(access(403, 'tx1'), new Set(), { waf })).toMatchObject({ outcome: 'served', waf_rule_id: 0 });
  });

  it('does not steal an interruption in a same-second burst (issue 397)', () => {
    const waf = collectWafLogLines([ruleMatch(TS + 0.2, 941100, 'blocked'), violation(TS + 0.2, 'blocked')]);
    const rows = [access(200, 'before'), access(403, 'blocked'), access(200, 'after')]
      .map(line => parseLine(line, new Set(), { waf })!);
    expect(rows.map(row => [row.status, row.outcome, row.waf_rule_id])).toEqual([
      [200, 'served', 0], [403, 'waf', 941100], [200, 'served', 0],
    ]);
  });

  it('separates concurrent upstream 403s and different methods with the same path', () => {
    const waf = collectWafLogLines([violation(TS, 'post-blocked')]);
    expect(parseLine(access(403, 'get-upstream'), new Set(), { waf })).toMatchObject({ outcome: 'served' });
    expect(parseLine(access(403, 'post-blocked', {}, { method: 'POST' }), new Set(), { waf })).toMatchObject({ outcome: 'waf' });
  });

  it('uses transaction identity even when the violation has no hostname or delayed access logging', () => {
    const waf = collectWafLogLines([violation(TS, 'tx1', { hostname: '', uri: '/different-log-representation' })]);
    expect(parseLine(access(403, 'tx1', { ts: TS + 90 }), new Set(), { waf })).toMatchObject({ outcome: 'waf' });
  });

  it('does not infer an interruption from a detection-only rule match or HTTP status', () => {
    const waf = collectWafLogLines([ruleMatch(TS, 941100, 'detection-only')]);
    expect(parseLine(access(200, 'detection-only'), new Set(), { waf })).toMatchObject({ outcome: 'served', waf_rule_id: 0 });
    expect(parseLine(access(403, 'detection-only'), new Set(), { waf })).toMatchObject({ outcome: 'served', waf_rule_id: 0 });
  });

  it.each([403, 413, 406, 200])('attributes an actual interruption with status %s, even without a rule ID', status => {
    const waf = collectWafLogLines([violation(TS)]);
    expect(parseLine(access(status, 'tx1'), new Set(), { waf })).toMatchObject({ outcome: 'waf', waf_rule_id: 0 });
  });

  it.each([undefined, null, '', 123, ['tx1'], { id: 'tx1' }, 'x'.repeat(129)])('ignores missing or malformed access IDs: %j', id => {
    const waf = collectWafLogLines([violation(TS)]);
    expect(parseLine(access(403, id), new Set(), { waf })).toMatchObject({ outcome: 'served' });
    expect(waf.violations.size).toBe(1);
  });

  it('does not trust a client-supplied transaction header or legacy tuple matching', () => {
    const waf = collectWafLogLines([violation(TS)]);
    expect(parseLine(handled({ status: 403 }, { headers: { 'Waf-Transaction-Id': ['tx1'] } }), new Set(), { waf })).toMatchObject({ outcome: 'served' });
    expect(waf.violations.size).toBe(1);
  });

  it('carries unmatched IDs across passes and prunes stale state', () => {
    const waf = createWafCorrelation();
    collectWafLogLines([violation(TS), ruleMatch(TS, 930130)], waf);
    pruneWafCorrelation(waf, TS + 60);
    expect(consumeWafViolation(waf, 'tx1')).toEqual({ ruleId: 930130 });
    collectWafLogLines([violation(TS), ruleMatch(TS, 930130)], waf);
    pruneWafCorrelation(waf, TS + 1000);
    expect(waf.violations.size).toBe(0);
    expect(waf.rules.size).toBe(0);
  });

  it('consumes duplicate violation records only once', () => {
    const waf = collectWafLogLines([violation(TS), violation(TS)]);
    expect(consumeWafViolation(waf, 'tx1')).toEqual({ ruleId: 0 });
    expect(consumeWafViolation(waf, 'tx1')).toBeNull();
  });

  it('ignores malformed interruption records', () => {
    const waf = collectWafLogLines(['not json', JSON.stringify({ msg: 42 }), JSON.stringify({ msg: 'WAF rule violation detected' }), violation(TS, ''), '']);
    expect(waf.violations.size).toBe(0);
  });

  it('never consumes an ID when the blocker or limiter refused the request first', () => {
    const waf = collectWafLogLines([violation(TS)]);
    const lines = [blockerLine(TS), access(403, 'tx1')];
    expect(parseLine(lines[1], collectBlockedSignatures(lines), { waf })).toMatchObject({ outcome: 'geo' });
    expect(parseLine(access(429, 'tx1', { rate_limit_zone: 'test' }), new Set(), { waf })).toMatchObject({ outcome: 'rate_limit' });
    expect(waf.violations.size).toBe(1);
  });
});
