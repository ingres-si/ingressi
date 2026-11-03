/**
 * Access list rule validation (src/lib/access-list-rules.ts): addresses and
 * CIDR ranges (IPv4 and IPv6, normalized as Caddy and the blocker accept
 * them), countries, continents, AS numbers, rule and list settings input,
 * and how a list is classified for the list table.
 */
import { describe, expect, it } from 'vitest';
import { ApiValidationError } from '@/src/lib/api-errors';
import {
  MAX_RULES_PER_LIST,
  classifyAccessList,
  ipRangeContains,
  isRuleExpired,
  normalizeListName,
  normalizeListSettings,
  normalizeMemberInput,
  normalizeRuleInput,
  normalizeRuleList,
  normalizeRuleValue,
  normalizeRuleValues,
  parseIpRange,
  ruleKindLabel,
  ruleValuesText,
} from '@/src/lib/access-list-rules';

const NOW = new Date('2026-10-03T12:00:00.000Z');

function value(kind: Parameters<typeof normalizeRuleValue>[0], raw: string): string | null {
  const result = normalizeRuleValue(kind, raw);
  return 'value' in result ? result.value : null;
}

describe('IP addresses and CIDR ranges', () => {
  it.each([
    ['203.0.113.7', '203.0.113.7'],
    ['203.0.113.7/32', '203.0.113.7'],
    ['203.0.113.0/26', '203.0.113.0/26'],
    // Host bits are cleared, as Caddy's matchers and the blocker do.
    ['203.0.113.77/24', '203.0.113.0/24'],
    ['0.0.0.0/0', '0.0.0.0/0'],
    ['2001:DB8::1', '2001:db8::1'],
    ['2001:db8:0:0:0:0:0:1', '2001:db8::1'],
    ['2001:db8::/32', '2001:db8::/32'],
    ['2001:db8:bad::5/48', '2001:db8:bad::/48'],
    ['::/0', '::/0'],
    ['::1/128', '::1'],
    ['::ffff:192.0.2.1', '::ffff:c000:201'],
    ['fe80:0:0:1:0:0:0:1', 'fe80:0:0:1::1'],
    [' 198.51.100.19 ', '198.51.100.19'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(value('ip', input)).toBe(expected);
  });

  it.each([
    '256.0.0.1',
    '1.2.3',
    '1.2.3.4.5',
    // Leading zeros: Go (Caddy) refuses them, some tools read them as octal.
    '010.0.0.1',
    '10.0.0.1/033',
    '10.0.0.1/33',
    '10.0.0.1/-1',
    '2001:db8::1/129',
    'fe80::1%eth0',
    '2001:db8:::1',
    '2001:db8::1::2',
    '1:2:3:4:5:6:7:8:9',
    'example.com',
    '10.0.0.0/8/8',
    '',
    'all',
  ])('refuses %s', (input) => {
    expect(value('ip', input)).toBeNull();
  });

  it('keeps the private_ranges shorthand', () => {
    expect(value('ip', 'Private_Ranges')).toBe('private_ranges');
  });

  it('tells whether a range contains an address', () => {
    const range = parseIpRange('10.1.0.0/16')!;
    expect(ipRangeContains(range, parseIpRange('10.1.2.3')!)).toBe(true);
    expect(ipRangeContains(range, parseIpRange('10.2.0.1')!)).toBe(false);
    expect(ipRangeContains(range, parseIpRange('10.0.0.0/8')!)).toBe(false);
    expect(ipRangeContains(parseIpRange('2001:db8::/32')!, parseIpRange('2001:db8:1::9')!)).toBe(true);
    expect(ipRangeContains(parseIpRange('2001:db8::/32')!, parseIpRange('10.1.2.3')!)).toBe(false);
  });
});

describe('countries, continents and AS numbers', () => {
  it('takes ISO country codes in any case and refuses others', () => {
    expect(value('country', 'it')).toBe('IT');
    expect(value('country', 'XK')).toBe('XK');
    expect(value('country', 'UK')).toBeNull();
    expect(value('country', 'ITA')).toBeNull();
    expect(value('country', 'Italy')).toBeNull();
  });

  it('takes the seven continent codes', () => {
    expect(['AF', 'AN', 'AS', 'EU', 'NA', 'OC', 'SA'].map((code) => value('continent', code.toLowerCase()))).toEqual([
      'AF', 'AN', 'AS', 'EU', 'NA', 'OC', 'SA',
    ]);
    expect(value('continent', 'ME')).toBeNull();
  });

  it('takes AS numbers with or without the prefix and stores the number', () => {
    expect(value('asn', 'AS64500')).toBe('64500');
    expect(value('asn', 'as64500')).toBe('64500');
    expect(value('asn', '64500')).toBe('64500');
    expect(value('asn', '4294967295')).toBe('4294967295');
    expect(value('asn', '0')).toBeNull();
    expect(value('asn', '4294967296')).toBeNull();
    expect(value('asn', '064500')).toBeNull();
    expect(value('asn', 'AS-1')).toBeNull();
    expect(value('asn', '1.5')).toBeNull();
  });

  it('splits a string of values, deduplicates them and names the first bad one', () => {
    expect(normalizeRuleValues('country', 'it, FR fr  de')).toEqual(['IT', 'FR', 'DE']);
    expect(normalizeRuleValues('asn', [64500, 'AS64501', '64500'])).toEqual(['64500', '64501']);
    expect(() => normalizeRuleValues('ip', ['10.0.0.1', 'nope'])).toThrow(/"nope" is not an IP address/);
    expect(() => normalizeRuleValues('ip', [])).toThrow(/at least one value/);
    expect(() => normalizeRuleValues('ip', ' , ')).toThrow(ApiValidationError);
    expect(() => normalizeRuleValues('ip', Array.from({ length: 501 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`)))
      .toThrow(/at most 500/);
    expect(() => normalizeRuleValues('ip', { a: 1 })).toThrow(/must be an array/);
    expect(() => normalizeRuleValues('ip', [null])).toThrow(/must be a string/);
  });
});

describe('rules', () => {
  it('normalizes a rule', () => {
    expect(normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['2001:DB8::/32'], note: '  scanner  ' }, { now: NOW }))
      .toEqual({ action: 'deny', kind: 'ip', values: ['2001:db8::/32'], note: 'scanner', expiresAt: null });
  });

  it('refuses unknown fields, actions and kinds, and ignores the fields of a stored rule', () => {
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], priority: 1 })).toThrow(/unknown field "priority"/);
    expect(() => normalizeRuleInput({ action: 'block', kind: 'ip', values: ['10.0.0.1'] })).toThrow(/action/);
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'city', values: ['Rome'] })).toThrow(/kind/);
    expect(() => normalizeRuleInput(['deny'])).toThrow(/must be an object/);
    expect(
      normalizeRuleInput({ id: 4, position: 2, createdAt: 'x', updatedAt: 'x', expired: false, action: 'allow', kind: 'asn', values: 'AS1' }).values
    ).toEqual(['1']);
  });

  it('takes an expiry in the future, at most ten years ahead', () => {
    expect(normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], expiresAt: '2026-10-04T12:00:00+02:00' }, { now: NOW }).expiresAt)
      .toBe('2026-10-04T10:00:00.000Z');
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], expiresAt: '2026-10-03T11:59:59Z' }, { now: NOW }))
      .toThrow(/in the future/);
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], expiresAt: '2040-01-01T00:00:00Z' }, { now: NOW }))
      .toThrow(/ten years/);
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], expiresAt: 'tomorrow' }, { now: NOW }))
      .toThrow(/ISO 8601/);
  });

  it('keeps a stored expiry sent back unchanged, even once it passed', () => {
    const stored = '2026-10-03T11:00:00.000Z';
    expect(
      normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], expiresAt: stored }, { now: NOW, existingExpiry: stored }).expiresAt
    ).toBe(stored);
    expect(isRuleExpired({ expiresAt: stored }, NOW)).toBe(true);
    expect(isRuleExpired({ expiresAt: null }, NOW)).toBe(false);
  });

  it('validates a whole list, naming the rule at fault, up to the limit', () => {
    expect(() => normalizeRuleList([{ action: 'allow', kind: 'ip', values: ['10.0.0.1'] }, { action: 'deny', kind: 'country', values: ['ZZ'] }]))
      .toThrow(/rules\[1\]\.values: "ZZ"/);
    expect(() => normalizeRuleList('nope')).toThrow(/must be an array/);
    expect(() => normalizeRuleList(Array.from({ length: MAX_RULES_PER_LIST + 1 }, () => ({ action: 'deny', kind: 'ip', values: ['10.0.0.1'] }))))
      .toThrow(/at most/);
  });

  it('refuses notes with control characters or over 500 characters', () => {
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], note: 'a\u0000b' })).toThrow(/control/);
    expect(() => normalizeRuleInput({ action: 'deny', kind: 'ip', values: ['10.0.0.1'], note: 'x'.repeat(501) })).toThrow(/500/);
  });
});

describe('list settings', () => {
  it('takes the fields present', () => {
    expect(normalizeListSettings({ defaultAction: 'deny', denyStatus: 451, denyBody: 'Not here', failClosed: true }))
      .toEqual({ defaultAction: 'deny', denyStatus: 451, denyBody: 'Not here', failClosed: true });
    expect(normalizeListSettings({})).toEqual({});
    expect(normalizeListSettings({ denyBody: '', denyRedirectUrl: '  ' })).toEqual({ denyBody: null, denyRedirectUrl: null });
  });

  it('refuses statuses outside 400-599 and non-HTTP redirects', () => {
    for (const status of [200, 302, 399, 600, 403.5, '403']) {
      expect(() => normalizeListSettings({ denyStatus: status })).toThrow(/400 to 599/);
    }
    for (const url of ['javascript:alert(1)', 'ftp://example.com/x', 'not a url', 'https://example.com/a b']) {
      expect(() => normalizeListSettings({ denyRedirectUrl: url })).toThrow(/HTTP or HTTPS/);
    }
    expect(normalizeListSettings({ denyRedirectUrl: 'https://example.com/not-available' }).denyRedirectUrl).toBe('https://example.com/not-available');
    expect(() => normalizeListSettings({ defaultAction: 'block' })).toThrow(/defaultAction/);
    expect(() => normalizeListSettings({ failClosed: 'yes' })).toThrow(/failClosed/);
    expect(() => normalizeListSettings({ skipAuthForAllowed: 'yes' })).toThrow(/skipAuthForAllowed/);
    expect(() => normalizeListSettings({ denyBody: 'x'.repeat(4097) })).toThrow(/4096/);
    expect(() => normalizeListSettings({ denyBody: 'a\u0007' })).toThrow(/control/);
    expect(normalizeListSettings({ denyBody: '<h1>Gone</h1>\nBye' }).denyBody).toBe('<h1>Gone</h1>\nBye');
  });

  it('checks list names and members', () => {
    expect(normalizeListName('  Office  ')).toBe('Office');
    expect(() => normalizeListName('   ')).toThrow(/name is required/);
    expect(() => normalizeListName('x'.repeat(201))).toThrow(/200/);
    expect(normalizeMemberInput({ username: ' alice ', password: 'pw' })).toEqual({ username: 'alice', password: 'pw' });
    expect(() => normalizeMemberInput({ username: 'a:b', password: 'pw' })).toThrow(/colon/);
    expect(() => normalizeMemberInput({ username: 'alice', password: '' })).toThrow(/password is required/);
  });
});

describe('classifyAccessList', () => {
  const rule = (action: string, kind: string) => ({ action, kind });
  it.each([
    [{ defaultAction: 'allow', rules: [], memberCount: 0 }, 'empty', 'Empty'],
    [{ defaultAction: 'allow', rules: [], memberCount: 2 }, 'basic_auth', 'Basic auth'],
    [{ defaultAction: 'deny', rules: [rule('allow', 'continent'), rule('allow', 'ip')], memberCount: 0 }, 'geo', 'Geo'],
    [{ defaultAction: 'deny', rules: [rule('allow', 'ip')], memberCount: 0 }, 'address_allowlist', 'Address allowlist'],
    [{ defaultAction: 'allow', rules: [rule('deny', 'ip'), rule('deny', 'asn')], memberCount: 0 }, 'address_blocklist', 'Address blocklist'],
    [{ defaultAction: 'allow', rules: [rule('allow', 'ip'), rule('deny', 'ip')], memberCount: 1 }, 'rules', 'Rules and basic auth'],
    [{ systemKey: 'blocked_sources', defaultAction: 'allow', rules: [rule('deny', 'ip')], memberCount: 0 }, 'blocked_sources', 'Global blocklist'],
  ])('%o is %s', (list, type, label) => {
    expect(classifyAccessList(list)).toMatchObject({ type, label });
  });

  it('describes rule values for people', () => {
    expect(ruleKindLabel('ip', ['198.51.100.19'])).toBe('Address');
    expect(ruleKindLabel('ip', ['198.51.100.0/24'])).toBe('Network');
    expect(ruleValuesText('country', ['IT'])).toBe('IT · Italy');
    expect(ruleValuesText('continent', ['EU'])).toBe('EU · Europe');
    expect(ruleValuesText('asn', ['64500', '64501'])).toBe('AS64500, AS64501');
  });
});
