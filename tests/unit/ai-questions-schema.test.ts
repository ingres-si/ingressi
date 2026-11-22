/**
 * Plain-language analytics questions (ee/ai/questions): the strict
 * validation of the structured query and of the model's answer, which
 * refuses anything outside the allow-lists (prompt-injection style answers
 * included), the range a question resolves to, the query in words, the link
 * to the Analytics page, the metric expressed as filters and the summary the
 * dashboard writes.
 */
import { describe, expect, it } from 'vitest';
import { ApiValidationError } from '@/src/lib/api-errors';
import { parseModelAnswer, parseQuestionQuery, parseQuestionText, usesRequestDetails } from '@/ee/ai/questions/schema';
import { analyticsHrefFor, computedSummary, describeQuery, describeRange, formatPeriod } from '@/ee/ai/questions/describe';
import { exactRange, metricFilters, resolveQuestionRange } from '@/ee/ai/questions/run';
import { REQUEST_DETAIL_DIMENSIONS, type QuestionResult } from '@/ee/ai/questions/types';

const VALID = {
  metric: 'mitigated',
  breakdown: 'country',
  filters: [{ dim: 'status', op: 'is', value: '5XX' }],
  hostTags: ['Shop'],
  range: { preset: '7d' },
  comparison: 'previous_period',
  limit: 5,
};

function refuses(input: unknown, message?: RegExp) {
  let error: unknown;
  try {
    parseQuestionQuery(input);
  } catch (caught) {
    error = caught;
  }
  expect(error, JSON.stringify(input)).toBeInstanceOf(ApiValidationError);
  if (message) expect((error as Error).message).toMatch(message);
}

describe('parseQuestionQuery', () => {
  it('scopes a WAF rule breakdown to WAF interruptions, including older saved queries', () => {
    for (const metric of ['requests', 'mitigated', 'errors']) {
      const parsed = parseQuestionQuery({ metric, breakdown: 'waf_rule', range: { preset: '7d' } });
      expect(parsed.filters).toEqual([{ dim: 'outcome', op: 'is', value: 'waf' }]);
      expect(parseQuestionQuery(parsed)).toEqual(parsed);
    }
    // A breakdown by country still counts mitigations from every control.
    expect(parseQuestionQuery({ metric: 'mitigated', breakdown: 'country', range: { preset: '7d' } }).filters).toEqual([]);
  });

  it('does not broaden a conflicting outcome into an OR when adding WAF scope', () => {
    for (const filters of [
      [{ dim: 'outcome', op: 'is', value: 'geo' }],
      [{ dim: 'outcome', op: 'is_not', value: 'waf' }],
      [{ dim: 'outcome', op: 'is', value: 'waf' }, { dim: 'outcome', op: 'is', value: 'rate_limit' }],
    ]) refuses({ metric: 'mitigated', breakdown: 'waf_rule', range: { preset: '7d' }, filters }, /WAF rule breakdown/);
    const country = { dim: 'country', op: 'is', value: 'US' };
    const parsed = parseQuestionQuery({ metric: 'mitigated', breakdown: 'waf_rule', range: { preset: '7d' }, filters: [country, { dim: 'outcome', op: 'is_not', value: 'served' }] });
    expect(parsed.filters).toEqual([country, { dim: 'outcome', op: 'is_not', value: 'served' }, { dim: 'outcome', op: 'is', value: 'waf' }]);
  });

  it('retains the filter budget when adding the required WAF scope', () => {
    const filters = Array.from({ length: 10 }, (_, i) => ({ dim: 'host', op: 'is', value: `host${i}.example.com` }));
    refuses({ metric: 'requests', breakdown: 'waf_rule', range: { preset: '7d' }, filters }, /WAF rule breakdown/);
    expect(parseQuestionQuery({ metric: 'requests', breakdown: 'waf_rule', range: { preset: '7d' }, filters: filters.slice(1) }).filters).toHaveLength(10);
  });

  it('accepts a query on the allow-lists and normalises it', () => {
    expect(parseQuestionQuery(VALID)).toEqual({
      metric: 'mitigated',
      breakdown: 'country',
      filters: [{ dim: 'status', op: 'is', value: '5xx' }],
      hostTags: ['shop'],
      range: { preset: '7d' },
      comparison: 'previous_period',
      limit: 5,
    });
    expect(parseQuestionQuery({ metric: 'requests', breakdown: 'none', range: { from: '2026-09-29', to: 'now' } })).toEqual({
      metric: 'requests',
      breakdown: 'none',
      filters: [],
      hostTags: [],
      range: { from: '2026-09-29', to: 'now' },
      comparison: 'none',
      limit: 10,
    });
    expect(parseQuestionQuery({ ...VALID, filters: [{ dim: 'asn', value: 'AS13335' }, { dim: 'country', op: 'is_not', value: 'cn' }, { dim: 'asn', value: '13335' }] }).filters).toEqual([
      { dim: 'asn', op: 'is', value: '13335' },
      { dim: 'country', op: 'is_not', value: 'CN' },
    ]);
  });

  it('refuses unknown fields at every level instead of ignoring them', () => {
    refuses({ ...VALID, sql: 'DROP TABLE traffic_events' }, /Unknown field "sql"/);
    refuses(JSON.parse('{"metric":"requests","breakdown":"none","range":{"preset":"24h"},"__proto__":{"isAdmin":true}}'), /Unknown field "__proto__"/);
    refuses({ ...VALID, filters: [{ dim: 'host', op: 'is', value: 'a.example.com', raw: '1=1' }] }, /Unknown field "raw"/);
    refuses({ ...VALID, range: { preset: '7d', from: '2026-01-01' } }, /Unknown field/);
    refuses({ ...VALID, range: { from: '2026-09-01', to: 'now', tz: 'Europe/Rome' } }, /Unknown field "tz"/);
    refuses({ ...VALID, table: 'users' }, /Unknown field "table"/);
  });

  it('refuses names off the lists, including SQL put in their place', () => {
    refuses({ ...VALID, metric: 'count(*)' }, /metric must be one of/);
    refuses({ ...VALID, metric: 'requests); DROP TABLE traffic_events; --' }, /metric must be one of/);
    refuses({ ...VALID, breakdown: 'client_ip' }, /breakdown must be one of/);
    refuses({ ...VALID, breakdown: 'host UNION SELECT password FROM users' });
    refuses({ ...VALID, filters: [{ dim: 'host) OR 1=1 --', op: 'is', value: 'x' }] }, /dim must be one of/);
    refuses({ ...VALID, filters: [{ dim: 'host', op: 'like', value: '%' }] }, /op must be one of/);
    refuses({ ...VALID, range: { preset: '1y' } }, /range.preset must be one of/);
    refuses({ ...VALID, range: 'all' });
    refuses({ ...VALID, comparison: 'year_over_year' }, /comparison must be one of/);
  });

  it('validates every filter value for its dimension', () => {
    const bad: [string, string][] = [
      ['country', "DE' OR '1'='1"],
      ['status', '5xx OR 1=1'],
      ['asn', '13335 OR 1'],
      ['ip', '203.0.113.7; DROP TABLE x'],
      ['waf_rule', '942100 UNION SELECT 1'],
      ['method', 'GET POST'],
      ['protocol', 'HTTP/1.1 OR 1'],
      ['outcome', 'served OR 1'],
      ['host', 'h'.repeat(256)],
      ['path', `/${'a'.repeat(600)}`],
      ['user_agent', 'u'.repeat(300)],
      ['host', 'a.example.com\u0000'],
      ['path', ''],
    ];
    for (const [dim, value] of bad) refuses({ ...VALID, filters: [{ dim, op: 'is', value }] });
    refuses({ ...VALID, filters: [{ dim: 'host', value: { $ne: null } }] }, /value must be a string/);
    refuses({ ...VALID, filters: Array.from({ length: 11 }, (_, i) => ({ dim: 'status', value: String(400 + i) })) }, /At most 10 filters/);
  });

  it('keeps text values as text: they reach ClickHouse only as bound parameters', () => {
    // A host value is free text up to 255 characters; run.ts binds it, never writes it into SQL.
    expect(parseQuestionQuery({ ...VALID, filters: [{ dim: 'host', value: "x' OR 1=1 --" }] }).filters[0].value).toBe("x' OR 1=1 --");
  });

  it('bounds tags, limit and range, and the combinations the analytics layer supports', () => {
    refuses({ ...VALID, hostTags: ['shop hosts'] }, /not a valid host tag/);
    refuses({ ...VALID, hostTags: ['<script>'] });
    refuses({ ...VALID, hostTags: ['a', 'b', 'c', 'd', 'e', 'f'] }, /At most 5 host tags/);
    refuses({ ...VALID, hostTags: 'shop' });
    for (const limit of [0, 51, 2.5, '10', null]) refuses({ ...VALID, limit });
    refuses({ ...VALID, range: { from: 'yesterday' } }, /date/);
    refuses({ ...VALID, range: { from: '2026-02-31', to: 'now' } }, /not a valid date/);
    refuses({ ...VALID, range: { from: '2026-09-01T10:00:00', to: 'now' } }, /time zone/);
    refuses({ ...VALID, metric: 'bytes', breakdown: 'country' }, /Bytes sent can be shown/);
    refuses({ ...VALID, metric: 'visitors', breakdown: 'host' }, /Unique client addresses/);
    expect(parseQuestionQuery({ ...VALID, metric: 'bytes', breakdown: 'host' }).breakdown).toBe('host');
    refuses({ breakdown: 'none', range: { preset: '24h' } }, /metric is required/);
    refuses({ metric: 'requests', range: { preset: '24h' } }, /breakdown is required/);
    refuses({ metric: 'requests', breakdown: 'none' }, /range is required/);
    refuses(null);
    refuses([VALID]);
    refuses('{"metric":"requests"}');
  });
});

describe('parseModelAnswer', () => {
  it('reads one JSON object, in a code fence or after a reasoning block', () => {
    expect(parseModelAnswer('{"answer":"query","query":{"metric":"requests"}}')).toEqual({ kind: 'query', query: { metric: 'requests' } });
    expect(parseModelAnswer('```json\n{"answer":"clarify","message":"Which hosts?"}\n```')).toEqual({ kind: 'clarify', message: 'Which hosts?' });
    expect(parseModelAnswer('<think>{"answer":"query"}</think>{"answer":"unsupported","message":"Traffic data counts requests."}')).toEqual({
      kind: 'unsupported',
      message: 'Traffic data counts requests.',
    });
  });

  it('refuses anything else', () => {
    expect(parseModelAnswer('SELECT * FROM traffic_events').kind).toBe('invalid');
    expect(parseModelAnswer('{"answer":"sql","sql":"SELECT 1"}').kind).toBe('invalid');
    expect(parseModelAnswer('{"answer":"query","query":{},"sql":"SELECT 1"}').kind).toBe('invalid');
    expect(parseModelAnswer('{"answer":"clarify","message":"x","tool":"run"}').kind).toBe('invalid');
    expect(parseModelAnswer('[{"answer":"query"}]').kind).toBe('invalid');
    expect(parseModelAnswer('{"answer":"query"').kind).toBe('invalid');
    expect(parseModelAnswer('{"answer":"query"}')).toEqual({ kind: 'invalid', reason: 'the answer had no query' });
  });

  it('keeps messages short, single-line and printable', () => {
    const answer = parseModelAnswer(JSON.stringify({ answer: 'clarify', message: `Which\u0007 hosts?\n\n${'x'.repeat(400)}` }));
    expect(answer.kind).toBe('clarify');
    const message = (answer as { message: string }).message;
    expect(message.length).toBeLessThanOrEqual(300);
    expect(message).not.toMatch(/\p{Cc}/u);
    expect(parseModelAnswer('{"answer":"unsupported"}')).toEqual({ kind: 'unsupported', message: 'Traffic data cannot answer that.' });
  });
});

describe('parseQuestionText', () => {
  it('collapses whitespace and bounds the length', () => {
    expect(parseQuestionText('  Which  countries\nwere blocked? ')).toBe('Which countries were blocked?');
    expect(() => parseQuestionText('')).toThrow(/question is required/);
    expect(() => parseQuestionText(42)).toThrow(/question is required/);
    expect(() => parseQuestionText('x'.repeat(501))).toThrow(/at most 500/);
    expect(() => parseQuestionText('bell \u0007 here')).toThrow(/control characters/);
  });
});

describe('ranges', () => {
  const now = Date.parse('2026-10-03T11:36:00Z') / 1000;

  it('resolves presets, inclusive dates and "now", capped at now', () => {
    expect(resolveQuestionRange({ preset: '24h' }, now)).toMatchObject({ preset: '24h', step: 1800, buckets: 48 });
    const week = resolveQuestionRange({ from: '2026-09-26', to: '2026-10-02' }, now);
    expect(week.start).toBe(Date.parse('2026-09-26T00:00:00Z') / 1000);
    expect(week.end).toBe(Date.parse('2026-10-03T00:00:00Z') / 1000);
    const sinceTuesday = resolveQuestionRange({ from: '2026-09-29', to: 'now' }, now);
    expect(sinceTuesday.start).toBe(Date.parse('2026-09-29T00:00:00Z') / 1000);
    expect(sinceTuesday.end).toBeGreaterThanOrEqual(now);
  });

  it('resolves the last N minutes, ending now, and reads them back in words', () => {
    const now = Date.parse('2026-10-09T15:42:30Z') / 1000;
    expect(parseQuestionQuery({ metric: 'errors', breakdown: 'status', range: { minutes: 3 } }).range).toEqual({ minutes: 3 });
    const three = resolveQuestionRange({ minutes: 3 }, now);
    expect(three).toMatchObject({ preset: 'custom', step: 60 });
    expect(three.start).toBe(Date.parse('2026-10-09T15:39:00Z') / 1000);
    expect(three.end).toBeGreaterThanOrEqual(now);
    expect(describeRange({ minutes: 3 })).toBe('the last 3 minutes');
    expect(describeRange({ minutes: 1 })).toBe('the last minute');
    expect(describeRange({ minutes: 360 })).toBe('the last 6 hours');
    for (const minutes of [0, 1441, 2.5, '3']) {
      expect(() => parseQuestionQuery({ metric: 'errors', breakdown: 'none', range: { minutes } }), String(minutes)).toThrow(/range\.minutes/);
    }
    expect(() => parseQuestionQuery({ metric: 'errors', breakdown: 'none', range: { minutes: 3, from: '2026-10-01' } })).toThrow();
  });

  it('refuses periods that have not started, run backwards or are too long', () => {
    expect(() => resolveQuestionRange({ from: '2026-10-05', to: 'now' }, now)).toThrow(/not started/);
    expect(() => resolveQuestionRange({ from: '2026-09-29', to: '2026-09-01' }, now)).toThrow(/ends before it starts/);
    expect(() => resolveQuestionRange({ from: '2026-01-01', to: 'now' }, now)).toThrow(/at most 92 days/);
  });

  it('keeps a report period exact, with buckets that divide it', () => {
    // September in Rome: 31 Aug 22:00 to 30 Sep 22:00 UTC.
    const start = Date.parse('2026-08-31T22:00:00Z') / 1000;
    const end = Date.parse('2026-09-30T22:00:00Z') / 1000;
    expect(exactRange(start, end)).toEqual({ preset: 'custom', start, end, step: 3600, buckets: 720 });
    expect(exactRange(start, start + 5400).step).toBe(1800);
  });
});

describe('the query in words and on the Analytics page', () => {
  const query = parseQuestionQuery(VALID);
  const period = { start: Date.parse('2026-09-26T00:00:00Z') / 1000, end: Date.parse('2026-10-03T00:00:00Z') / 1000 };

  it('describes the query', () => {
    expect(formatPeriod(period.start, period.end)).toBe('26 Sep–2 Oct 2026');
    expect(formatPeriod(period.start, period.start + 3600)).toBe('26 Sep 2026, 00:00–01:00 UTC');
    expect(describeQuery(query, period)).toBe(
      'Mitigated requests by country (top 5), 26 Sep–2 Oct 2026, hosts tagged shop, status code is 5xx, compared with the 7 days before'
    );
    expect(describeRange({ preset: '7d' })).toBe('the last 7 days');
    expect(describeRange({ from: '2026-09-29', to: 'now' })).toBe('29 Sep 2026 to now');
    const withPath = parseQuestionQuery({ ...VALID, filters: [{ dim: 'path', value: '/admin' }, { dim: 'ip', value: '203.0.113.7' }] });
    expect(describeQuery(withPath, period, { redact: true })).not.toMatch(/\/admin|203\.0\.113\.7/);
    expect(describeQuery(withPath, period, { redact: true })).toContain('path is [hidden]');
  });

  it('links the same query, host tags becoming the host names they matched', () => {
    const { href, complete } = analyticsHrefFor(query, { ...period, preset: 'custom' }, ['shop.example.com', 'shop.example.com:443']);
    expect(complete).toBe(true);
    const url = new URL(href, 'https://dash.example.com');
    expect(url.pathname).toBe('/analytics');
    expect(url.searchParams.get('range')).toBe('custom');
    expect(url.searchParams.get('from')).toBe(String(period.start));
    expect(url.searchParams.get('metric')).toBe('mitigated');
    expect(JSON.parse(url.searchParams.get('filters')!)).toEqual([
      { dim: 'host', op: 'is', value: 'shop.example.com' },
      { dim: 'host', op: 'is', value: 'shop.example.com:443' },
      { dim: 'status', op: 'is', value: '5xx' },
    ]);
    const many = analyticsHrefFor(query, { ...period, preset: '7d' }, Array.from({ length: 30 }, (_, i) => `h${i}.example.com`));
    expect(many.complete).toBe(false);
    expect(new URL(many.href, 'https://dash.example.com').searchParams.get('range')).toBe('7d');
  });

  it('knows which questions need request details', () => {
    expect(usesRequestDetails(query, REQUEST_DETAIL_DIMENSIONS)).toBe(false);
    expect(usesRequestDetails({ breakdown: 'ip', filters: [] }, REQUEST_DETAIL_DIMENSIONS)).toBe(true);
    expect(usesRequestDetails({ breakdown: 'none', filters: [{ dim: 'path', op: 'is', value: '/x' }] }, REQUEST_DETAIL_DIMENSIONS)).toBe(true);
  });
});

describe('metric as filters', () => {
  it('counts mitigated requests and error responses with the ranked dimensions', () => {
    expect(metricFilters('mitigated', [])).toEqual({ filters: [{ dim: 'outcome', op: 'is_not', value: 'served' }], impossible: false });
    expect(metricFilters('errors', []).filters).toEqual([
      { dim: 'status', op: 'is', value: '4xx' },
      { dim: 'status', op: 'is', value: '5xx' },
    ]);
    expect(metricFilters('errors', [{ dim: 'status', op: 'is', value: '5xx' }, { dim: 'status', op: 'is', value: '200' }]).filters).toEqual([
      { dim: 'status', op: 'is', value: '5xx' },
    ]);
    expect(metricFilters('errors', [{ dim: 'status', op: 'is', value: '2xx' }]).impossible).toBe(true);
    expect(metricFilters('requests', [{ dim: 'host', op: 'is', value: 'a.example.com' }]).filters).toHaveLength(1);
  });
});

describe('computed summary', () => {
  const base: QuestionResult = {
    status: 'ok',
    kind: 'breakdown',
    metric: 'mitigated',
    breakdown: 'country',
    unit: 'count',
    range: { start: 0, end: 86_400, step: 3600, buckets: 24 },
    previous: { start: -86_400, end: 0, available: true },
    total: 1000,
    previousTotal: 800,
    change: 0.25,
    rows: [
      { value: 'DE', label: null, count: 600, share: 0.6, previous: 400, change: 0.5 },
      { value: 'US', label: null, count: 300, share: 0.3, previous: 300, change: 0 },
    ],
    distinct: 2,
    series: null,
    peak: null,
    scope: null,
    notes: [],
  };

  it('writes sentences from the numbers only', () => {
    expect(computedSummary(base, '1 Jan 1970')).toBe(
      'DE had the most mitigated requests in 1 Jan 1970: 600 of 1,000 (60.0%). Next: US with 300 (30.0%). That is 25.0% more than in the previous period (800).'
    );
    expect(computedSummary({ ...base, kind: 'total', rows: [], previous: null, previousTotal: null }, '1 Jan 1970')).toBe('1,000 mitigated requests in 1 Jan 1970.');
    expect(computedSummary({ ...base, rows: [], total: 0 }, 'the period')).toBe('No mitigated requests in the period.');
    expect(computedSummary({ ...base, status: 'disabled' }, 'x')).toMatch(/not configured/);
  });
});
