import { describe, expect, it } from 'vitest';
import {
  attentionLabel,
  certificateAttention,
  certificateTone,
  hostState,
  matchesHostSearch,
  matchesProtection,
  matchesStatus,
  matchesTags,
  parseHostListQuery,
  protectionsOf,
  sortAttention,
  sortHostRows,
  hostGroupOf,
  statusText,
  type HostAttention,
  type HostCertificate,
  type HostListRow,
  type ProtectionInput,
} from '@/src/lib/proxy-host-view';

const NONE: ProtectionInput = {
  wafMode: 'off',
  sso: false,
  authentik: false,
  forwardAuth: null,
  rateLimit: { rules: 0, first: null },
  geo: null,
  accessList: null,
  mtls: false,
};

function row(id: number, extra: Partial<HostListRow> = {}): HostListRow {
  return {
    id,
    name: `Host ${id}`,
    domains: [`h${id}.example.com`],
    upstreams: [`http://app${id}:8080`],
    enabled: true,
    tags: [],
    createdAt: `2026-01-0${id}T00:00:00.000Z`,
    state: 'healthy',
    attention: [],
    pendingChangeRequestId: null,
    traffic: { requests: 0, errors5xx: 0, errorRate5xx: 0, mitigated: 0, bytes: 0 },
    wafMode: 'off',
    protections: [],
    certificate: { visible: false, automatic: true },
    ...extra,
  };
}

const cert = (extra: Partial<Extract<HostCertificate, { visible: true }>>): HostCertificate => ({
  visible: true,
  kind: 'acme',
  name: null,
  daysLeft: 60,
  validTo: '2026-12-02T00:00:00.000Z',
  issuer: "Let's Encrypt",
  renewal: 'scheduled',
  certificateId: null,
  ...extra,
});

describe('protectionsOf', () => {
  it('lists nothing for an unprotected host', () => {
    expect(protectionsOf(NONE)).toEqual([]);
  });

  it('names each protection with its filter key and pill colour', () => {
    const pills = protectionsOf({
      ...NONE,
      wafMode: 'block',
      sso: true,
      forwardAuth: 'authelia',
      rateLimit: { rules: 1, first: { events: 100, window: '1m' } },
      geo: { blockCountries: ['CN', 'RU'], allowCountries: [], blockContinents: [], other: 0, fromGlobal: false },
      accessList: { name: 'Office' },
      mtls: true,
    });
    expect(pills.map((pill) => [pill.key, pill.kind, pill.label])).toEqual([
      ['waf_block', 'waf', 'WAF · Block'],
      ['sign_in', 'sso', 'SSO'],
      ['sign_in', 'forward-auth', 'Forward auth · Authelia'],
      ['access_list', 'access-list', 'Access list · Office'],
      ['mtls', 'mtls', 'mTLS'],
      ['rate_limit', 'rate-limit', 'Rate limit · 100/1m'],
      ['geo', 'geo', 'Geo · blocks CN, RU'],
    ]);
  });

  it('summarises long lists and detection-only WAF', () => {
    const pills = protectionsOf({
      ...NONE,
      wafMode: 'detection_only',
      rateLimit: { rules: 3, first: { events: 10, window: '1s' } },
      geo: { blockCountries: ['CN', 'RU', 'KP', 'IR'], allowCountries: [], blockContinents: [], other: 0, fromGlobal: true },
      accessList: { name: null },
    });
    expect(pills.map((pill) => pill.label)).toEqual(['WAF · Detect only', 'Access list', 'Rate limit · 3 rules', 'Geo · blocks 4 countries']);
    expect(pills.find((pill) => pill.key === 'geo')?.title).toMatch(/global rules/);
  });
});

describe('certificates', () => {
  it('colours a certificate by how urgent it is', () => {
    expect(certificateTone({ visible: false, automatic: true })).toBe('off');
    expect(certificateTone(cert({}))).toBe('ok');
    expect(certificateTone(cert({ daysLeft: 25 }))).toBe('warn');
    expect(certificateTone(cert({ renewal: 'due', daysLeft: 20 }))).toBe('warn');
    expect(certificateTone(cert({ renewal: 'overdue', daysLeft: 5 }))).toBe('bad');
    expect(certificateTone(cert({ renewal: 'expired', daysLeft: -1 }))).toBe('bad');
    expect(certificateTone(cert({ renewal: 'inactive', daysLeft: null }))).toBe('off');
  });

  it('needs attention only when someone has to act', () => {
    expect(certificateAttention(cert({}))).toBeNull();
    expect(certificateAttention(cert({ renewal: 'due', daysLeft: 20 }))).toBeNull();
    expect(certificateAttention({ visible: false, automatic: false })).toBeNull();
    expect(certificateAttention(cert({ renewal: 'overdue', daysLeft: 9 }))).toMatchObject({ tone: 'bad', state: 'overdue' });
    expect(certificateAttention(cert({ kind: 'imported', renewal: 'replace_soon', daysLeft: 20 }))).toMatchObject({ tone: 'warn' });
    expect(certificateAttention(cert({ kind: 'imported', renewal: 'replace_soon', daysLeft: 3 }))).toMatchObject({ tone: 'bad' });
  });
});

describe('attention', () => {
  const time = (ms: number) => new Date(ms).toISOString().slice(11, 16);
  const burst: HostAttention = {
    kind: 'error_burst', tone: 'warn', status: 501, count: 143, requests: 267,
    start: Date.UTC(2026, 9, 3, 9, 2) / 1000, end: Date.UTC(2026, 9, 3, 9, 3) / 1000, ongoing: false, method: 'POST', path: '/sync',
  };

  it('reads like the status column', () => {
    expect(attentionLabel(burst, time)).toBe('501 burst at 09:02');
    expect(attentionLabel({ ...burst, ongoing: true, status: 0 }, time)).toBe('5xx burst since 09:02');
    expect(attentionLabel({ kind: 'error_rate', tone: 'warn', rate: 0.052, errors: 52, requests: 1000 }, time)).toBe('5xx at 5.2%');
    expect(attentionLabel({ kind: 'mitigation_spike', tone: 'warn', count: 900, baseline: 100, factor: 9, outcome: 'waf' }, time)).toBe('Blocked traffic 9× usual');
    expect(attentionLabel({ kind: 'certificate', tone: 'bad', state: 'expired', daysLeft: -2 }, time)).toBe('Certificate expired');
    expect(attentionLabel({ kind: 'certificate', tone: 'warn', state: 'replace_soon', daysLeft: 1 }, time)).toBe('Certificate expires in 1 day');
    expect(statusText(502)).toBe('502 Bad Gateway');
    expect(statusText(599)).toBe('599');
  });

  it('puts red before amber and derives the state', () => {
    const red: HostAttention = { kind: 'certificate', tone: 'bad', state: 'expired', daysLeft: -1 };
    expect(sortAttention([burst, red])[0]).toBe(red);
    expect(hostState(false, [red], 4)).toBe('disabled');
    expect(hostState(true, [red], 4)).toBe('attention');
    expect(hostState(true, [], 4)).toBe('pending');
    expect(hostState(true, [], null)).toBe('healthy');
  });
});

describe('list query', () => {
  it('defaults to the busiest hosts first with analytics, by name without', () => {
    expect(parseHostListQuery({}, true)).toMatchObject({ sortBy: 'requests', sortDir: 'desc', status: 'all', page: 1, tags: [], protection: null });
    expect(parseHostListQuery({}, false)).toMatchObject({ sortBy: 'host', sortDir: 'asc' });
    expect(parseHostListQuery({ sortBy: 'errors' }, false)).toMatchObject({ sortBy: 'host' });
  });

  it('uses a saved default sort only when the URL does not specify one', () => {
    expect(parseHostListQuery({}, true, { key: 'host', dir: 'desc' })).toMatchObject({ sortBy: 'host', sortDir: 'desc' });
    expect(parseHostListQuery({ sortBy: 'created' }, true, { key: 'host', dir: 'desc' })).toMatchObject({ sortBy: 'created', sortDir: 'desc' });
    expect(parseHostListQuery({ sortDir: 'asc' }, true, { key: 'host', dir: 'desc' })).toMatchObject({ sortBy: 'requests', sortDir: 'asc' });
    expect(parseHostListQuery({}, false, { key: 'requests', dir: 'desc' })).toMatchObject({ sortBy: 'host', sortDir: 'asc' });
  });

  it('accepts the earlier sort keys and ignores unknown values', () => {
    expect(parseHostListQuery({ sortBy: 'name', sortDir: 'desc' }, true)).toMatchObject({ sortBy: 'name', sortDir: 'desc' });
    expect(parseHostListQuery({ sortBy: 'enabled' }, true)).toMatchObject({ sortBy: 'status', sortDir: 'asc' });
    expect(parseHostListQuery({ sortBy: 'createdAt' }, true)).toMatchObject({ sortBy: 'created', sortDir: 'desc' });
    expect(parseHostListQuery({ sortBy: 'drop table', sortDir: 'sideways', status: 'nope', protection: 'magic', page: '-4' }, true)).toMatchObject({
      sortBy: 'requests',
      sortDir: 'desc',
      status: 'all',
      protection: null,
      page: 1,
    });
  });

  it('reads search, status, protection and repeated tags', () => {
    expect(parseHostListQuery({ search: '  App ', status: 'attention', protection: 'waf_off', tag: ['Prod', 'prod', 'web'], page: '3' }, true)).toMatchObject({
      search: 'App',
      status: 'attention',
      protection: 'waf_off',
      tags: ['prod', 'web'],
      page: 3,
    });
  });
});

describe('filters and sort', () => {
  it('searches names, domains, upstreams and tags', () => {
    const host = row(1, { name: 'Mail', domains: ['mail.example.com'], upstreams: ['https://mailcow:443'], tags: ['mail'] });
    for (const needle of ['MAIL', 'example.com', 'mailcow:443', 'mail']) expect(matchesHostSearch(host, needle)).toBe(true);
    expect(matchesHostSearch(host, 'jellyfin')).toBe(false);
    expect(matchesHostSearch(host, '   ')).toBe(true);
  });

  it('filters by protection, tags and status', () => {
    const waf = row(1, { wafMode: 'block', protections: protectionsOf({ ...NONE, wafMode: 'block' }) });
    const plain = row(2);
    expect(matchesProtection(waf, 'waf_block')).toBe(true);
    expect(matchesProtection(plain, 'waf_block')).toBe(false);
    expect(matchesProtection(plain, 'waf_off')).toBe(true);
    expect(matchesProtection(plain, 'none')).toBe(true);
    expect(matchesProtection(waf, 'none')).toBe(false);
    expect(matchesProtection(waf, null)).toBe(true);
    expect(matchesTags(row(3, { tags: ['a', 'b'] }), ['b', 'c'])).toBe(true);
    expect(matchesTags(row(3, { tags: ['a'] }), ['c'])).toBe(false);
    expect(matchesStatus(row(4, { state: 'disabled' }), 'disabled')).toBe(true);
    expect(matchesStatus(row(4, { state: 'pending' }), 'attention')).toBe(false);
  });

  it('groups the sorted list by tag, untagged hosts last', () => {
    const rows = [
      row(1, { domains: ['a.example.com'], tags: [] }),
      row(2, { domains: ['b.example.com'], tags: ['media', 'prod'] }),
      row(3, { domains: ['c.example.com'], tags: ['cloud'] }),
      row(4, { domains: ['d.example.com'], tags: ['media'] }),
    ];
    expect(sortHostRows(rows, 'host', 'asc', 'tag').map((r) => r.id)).toEqual([3, 2, 4, 1]);
    // The direction orders hosts inside a section; the sections stay alphabetical.
    expect(sortHostRows(rows, 'host', 'desc', 'tag').map((r) => r.id)).toEqual([3, 4, 2, 1]);
    expect(sortHostRows(rows, 'host', 'asc', 'none').map((r) => r.id)).toEqual([1, 2, 3, 4]);
    // With a tag filter a host sits in the section of a tag it was filtered by.
    expect(hostGroupOf(rows[1], ['prod'])).toBe('prod');
    expect(hostGroupOf(rows[1])).toBe('media');
    expect(hostGroupOf(rows[0])).toBeNull();
    expect(parseHostListQuery({ group: 'tag' }, false).groupBy).toBe('tag');
    expect(parseHostListQuery({ group: 'nope' }, false).groupBy).toBe('none');
  });

  it('sorts by the host name apart from its domain', () => {
    const rows = [
      row(1, { name: '📺 Sonarr', domains: ['z.example.com'] }),
      row(2, { name: '☁️ Nextcloud', domains: ['a.example.com'] }),
      row(3, { name: '📺 Radarr', domains: ['m.example.com'] }),
    ];
    const asc = sortHostRows(rows, 'name', 'asc').map((r) => r.id);
    expect(asc.indexOf(3)).toBeLessThan(asc.indexOf(1));
    expect(sortHostRows(rows, 'name', 'desc').map((r) => r.id)).toEqual([...asc].reverse());
    expect(parseHostListQuery({ sortBy: 'name' }, false)).toMatchObject({ sortBy: 'name', sortDir: 'asc' });
  });

  it('sorts by traffic, status and name with a stable tie-break', () => {
    const traffic = (requests: number, rate = 0) => ({ requests, errors5xx: 0, errorRate5xx: rate, mitigated: 0, bytes: 0 });
    const rows = [
      row(1, { domains: ['b.example.com'], traffic: traffic(10, 0.5) }),
      row(2, { domains: ['a.example.com'], traffic: traffic(30), state: 'disabled' }),
      row(3, { domains: ['c.example.com'], traffic: traffic(20), state: 'attention', attention: [{ kind: 'error_rate', tone: 'warn', rate: 0.1, errors: 2, requests: 20 }] }),
      row(4, { domains: ['d.example.com'], traffic: traffic(20), state: 'attention', attention: [{ kind: 'certificate', tone: 'bad', state: 'expired', daysLeft: -1 }] }),
    ];
    expect(sortHostRows(rows, 'requests', 'desc').map((r) => r.id)).toEqual([2, 3, 4, 1]);
    expect(sortHostRows(rows, 'host', 'asc').map((r) => r.id)).toEqual([2, 1, 3, 4]);
    expect(sortHostRows(rows, 'host', 'desc').map((r) => r.id)).toEqual([4, 3, 1, 2]);
    expect(sortHostRows(rows, 'status', 'asc').map((r) => r.id)).toEqual([4, 3, 1, 2]);
    expect(sortHostRows(rows, 'errors', 'desc').map((r) => r.id)).toEqual([1, 2, 3, 4]);
    expect(sortHostRows(rows, 'created', 'desc').map((r) => r.id)).toEqual([4, 3, 2, 1]);
  });
});
