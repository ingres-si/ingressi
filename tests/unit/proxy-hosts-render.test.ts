/**
 * Server-side render of the redesigned proxy hosts list and a host's page:
 * columns, statuses, protection pills, certificates, links to the host page
 * and the host editor, what is hidden without permissions, and the host
 * page's sections.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/proxy-hosts',
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/app/(dashboard)/proxy-hosts/actions', () => ({
  createProxyHostAction: vi.fn(),
  updateProxyHostAction: vi.fn(),
  deleteProxyHostAction: vi.fn(),
  toggleProxyHostAction: vi.fn(),
}));
vi.mock('@/app/(dashboard)/proxy-hosts/bulk-actions', () => ({ bulkProxyHostsAction: vi.fn() }));
vi.mock('@/components/proxy-hosts/HostDialogs', () => ({
  CreateHostDialog: () => null,
  EditHostDialog: () => null,
  DeleteHostDialog: () => null,
}));

import ProxyHostsClient from '@/app/(dashboard)/proxy-hosts/ProxyHostsClient';
import HostDetailClient from '@/app/(dashboard)/proxy-hosts/[id]/HostDetailClient';
import type { HostListRow, HostListQuery } from '@/src/lib/proxy-host-view';
import type { HostDetail } from '@/src/lib/proxy-host-detail';
import type { ProxyHost } from '@/src/lib/models/proxy-hosts';

const BURST_START = Date.UTC(2026, 9, 3, 9, 2) / 1000;

const rows: HostListRow[] = [
  {
    id: 1,
    name: 'Media',
    domains: ['tv.example.com', 'suggest.tv.example.com'],
    upstreams: ['http://jellyfin:8096'],
    enabled: true,
    tags: ['media'],
    createdAt: '2026-01-01T00:00:00.000Z',
    state: 'healthy',
    attention: [],
    pendingChangeRequestId: null,
    traffic: { requests: 12147, errors5xx: 0, errorRate5xx: 0, mitigated: 0, bytes: 0 },
    wafMode: 'block',
    protections: [{ key: 'waf_block', kind: 'waf', label: 'WAF · Block', title: 'The WAF blocks requests' }],
    certificate: { visible: true, kind: 'acme', name: null, daysLeft: 60, validTo: '2026-12-02T00:00:00.000Z', issuer: "Let's Encrypt", renewal: 'scheduled', certificateId: null },
  },
  {
    id: 2,
    name: 'email.example.com',
    domains: ['email.example.com'],
    upstreams: ['https://mailcow-nginx:443'],
    enabled: true,
    tags: ['mail'],
    createdAt: '2026-01-02T00:00:00.000Z',
    state: 'attention',
    attention: [
      { kind: 'error_burst', tone: 'warn', status: 501, count: 143, requests: 267, start: BURST_START, end: BURST_START + 74, ongoing: false, method: 'POST', path: '/Microsoft-Server-ActiveSync' },
    ],
    pendingChangeRequestId: null,
    traffic: { requests: 2729, errors5xx: 143, errorRate5xx: 0.052, mitigated: 0, bytes: 0 },
    wafMode: 'off',
    protections: [],
    certificate: { visible: true, kind: 'acme', name: null, daysLeft: 25, validTo: '2026-10-28T00:00:00.000Z', issuer: "Let's Encrypt", renewal: 'due', certificateId: null },
  },
  {
    id: 3,
    name: 'Old',
    domains: ['old.example.com'],
    upstreams: ['http://old:80'],
    enabled: false,
    tags: [],
    createdAt: '2026-01-03T00:00:00.000Z',
    state: 'disabled',
    attention: [],
    pendingChangeRequestId: null,
    traffic: { requests: 0, errors5xx: 0, errorRate5xx: 0, mitigated: 0, bytes: 0 },
    wafMode: 'off',
    protections: [],
    certificate: { visible: false, automatic: true },
  },
];

const hosts = rows.map((row) => ({ id: row.id, name: row.name, domains: row.domains, upstreams: row.upstreams, enabled: row.enabled, tags: row.tags })) as unknown as ProxyHost[];

const query: HostListQuery = { search: '', status: 'all', protection: null, tags: [], sortBy: 'requests', sortDir: 'desc', groupBy: 'none', page: 1 };

function renderList(overrides: Record<string, unknown> = {}) {
  return renderToStaticMarkup(
    createElement(ProxyHostsClient, {
      hosts,
      rows,
      totalHosts: 3,
      statusCounts: { all: 3, attention: 1, disabled: 1 },
      maxRequests: 12147,
      analyticsStatus: 'ok',
      availableTags: ['mail', 'media'],
      query,
      certificates: [],
      accessLists: [],
      caCertificates: [],
      authentikDefaults: null,
      pagination: { total: 3, page: 1, perPage: 25 },
      ...overrides,
    } as never)
  );
}

describe('proxy hosts list', () => {
  it('renders the header, filters and the table columns', () => {
    const html = renderList();
    expect(html).toContain('Proxy hosts');
    expect(html).toContain('href="/proxy-hosts/new"');
    expect(html).toContain('New proxy host');
    expect(html).toContain('Domain, upstream or tag');
    expect(html).toContain('Needs attention');
    for (const column of ['Host', 'Status', 'Requests, 24h', '5xx', 'Protection', 'Certificate', 'Tags']) expect(html).toContain(`>${column}`);
    // Everything fits on one page: no pager.
    expect(html).not.toContain('Pages of hosts');
  });

  it('offers grouping by tag and renders a heading where the section changes', () => {
    expect(renderList()).toContain('Group by tag');
    expect(renderList()).not.toContain('colgroup');
    const grouped = renderList({ query: { ...query, groupBy: 'tag' } });
    expect(grouped).toContain('Grouped by tag');
    expect(grouped).toContain('scope="colgroup"');
  });

  it('pages a long list with the shared pager, linking each page by ?page=', () => {
    const html = renderList({ totalHosts: 62, statusCounts: { all: 62, attention: 1, disabled: 1 }, pagination: { total: 62, page: 2, perPage: 25 } });
    expect(html).toContain('aria-label="Pages of hosts"');
    expect(html).toMatch(/26<\/span>–<span class="num">50<\/span> of <span class="num">62<\/span> hosts/);
    expect(html).toContain('href="/proxy-hosts?page=3"');
    expect(html).toContain('aria-label="Next page"');
    expect(html).not.toContain('>Previous<');
  });

  it('renders each row with its link, status, traffic, pills and certificate', () => {
    const html = renderList();
    expect(html).toContain('href="/proxy-hosts/1"');
    expect(html).toContain('+ suggest.tv.example.com');
    expect(html).toContain('http://jellyfin:8096');
    expect(html).toContain('No issues');
    expect(html).toContain('501 burst at 09:02');
    expect(html).toContain('Disabled');
    expect(html).toContain('12,147');
    expect(html).toContain('5.2%');
    expect(html).toContain('WAF · Block');
    expect(html).toContain('60 days');
    expect(html).toContain('renewing now');
    expect(html).toContain('Automatic');
    expect(html).toContain('aria-label="More actions for tv.example.com"');
    expect(html).toContain('aria-label="Select tv.example.com"');
  });

  it('hides traffic, selection and the write actions from readers', () => {
    const html = renderList({ analyticsStatus: null, canWrite: false });
    expect(html).not.toContain('Requests, 24h');
    expect(html).not.toContain('12,147');
    expect(html).not.toContain('Select tv.example.com');
    expect(html).not.toContain('New proxy host');
  });

  it('says when ClickHouse did not answer, and offers the first host when there is none', () => {
    expect(renderList({ analyticsStatus: 'unavailable' })).toContain('Traffic could not be read.');
    const empty = renderList({ rows: [], hosts: [], totalHosts: 0, statusCounts: { all: 0, attention: 0, disabled: 0 }, pagination: { total: 0, page: 1, perPage: 25 } });
    expect(empty).toContain('No proxy hosts yet');
    const filtered = renderList({ rows: [], hosts: [], query: { ...query, search: 'nothing' }, pagination: { total: 0, page: 1, perPage: 25 } });
    expect(filtered).toContain('No proxy host matches these filters');
    expect(filtered).toContain('Clear filters');
  });
});

const detail: HostDetail = {
  row: rows[1],
  config: [
    { section: 'routing', title: 'Routing', summary: '1 upstream over HTTPS · no health checks · WebSockets on' },
    { section: 'security', title: 'Security', summary: 'WAF off · no rate limit' },
    { section: 'access', title: 'Access', summary: 'Public: anyone who reaches the domain gets through' },
    { section: 'certificate', title: 'Certificate', summary: "Let's Encrypt · renewing now · expires 28 Oct 2026 · HTTP redirects to HTTPS" },
    { section: 'headers', title: 'Headers', summary: 'HSTS on · Host header passed through' },
  ],
  traffic: {
    status: 'ok',
    range: { start: BURST_START - 9 * 1800, end: BURST_START + 1800, step: 1800, buckets: 10 },
    totals: { requests: 2729, errors5xx: 143, errorRate5xx: 0.052, mitigated: 3, bytes: 60_700_000, clients: 21 },
    series: { requests: [49, 78, 56, 58, 64, 74, 48, 45, 267, 77], errors5xx: [0, 0, 0, 0, 0, 0, 0, 0, 143, 0], mitigated: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    topPaths: [
      { path: '/', count: 1450, mitigated: 0, statuses: [{ status: 200, count: 1450 }] },
      { path: '/Microsoft-Server-ActiveSync', count: 1236, mitigated: 0, statuses: [{ status: 200, count: 766 }, { status: 501, count: 143 }] },
    ],
    statusCodes: [
      { status: 200, count: 2212, share: 0.81 },
      { status: 499, count: 327, share: 0.12 },
      { status: 501, count: 143, share: 0.05 },
    ],
  },
  errorRateAlert: { thresholdPercent: 1, ruleName: 'Errors' },
  health: {
    proxyHostId: 2,
    checkedAt: '2026-10-03T12:00:00.000Z',
    caddyReachable: true,
    status: 'unchecked',
    healthChecks: { active: null, passive: null, loadBalancing: null },
    upstreams: [{ upstream: 'https://mailcow-nginx:443', dial: 'mailcow-nginx:443', tls: true, status: 'unchecked', reported: true, fails: 0, requestsInFlight: 0 }],
  },
  changes: {
    total: 2,
    entries: [
      {
        id: 9, action: 'update', summary: 'Updated proxy host email.example.com', actor: 'admin', createdAt: '2026-09-29T10:00:00.000Z',
        fields: [{ path: 'allowWebsocket', before: false, after: true }], moreFields: 0, rollbackVersionId: 41,
      },
      { id: 8, action: 'create', summary: 'Created proxy host email.example.com', actor: 'admin', createdAt: '2026-06-03T10:00:00.000Z', fields: null, moreFields: 0, rollbackVersionId: null },
    ],
  },
};

const ALL = { write: true, analytics: true, alerts: true, certificates: true, auditLog: true, approvals: true, security: true };

function renderDetail(overrides: Partial<HostDetail> = {}, can = ALL) {
  return renderToStaticMarkup(
    createElement(HostDetailClient, {
      host: { id: 2, name: 'email.example.com', domains: ['email.example.com'], enabled: true, tags: ['mail'] },
      detail: { ...detail, ...overrides },
      can,
    })
  );
}

describe('host page', () => {
  it('renders the header, tabs and actions', () => {
    const html = renderDetail();
    expect(html).toContain('email.example.com');
    expect(html).toContain('href="/proxy-hosts"');
    expect(html).toContain('href="https://email.example.com"');
    expect(html).toContain('Open site');
    // One page: no separate editor to open, the tabs switch in place.
    expect(html).not.toContain('Edit host');
    expect(html).not.toContain('/edit');
    expect(html).toContain('aria-label="Host sections"');
    expect(html).toMatch(/<a href="#overview" role="tab" aria-selected="true"/);
    expect(html).toContain('href="#history"');
  });

  it('explains the incident and links to its requests', () => {
    const html = renderDetail();
    expect(html).toContain('Resolved: 143 responses with 501 Not Implemented at 09:02.');
    expect(html).toContain('POST /Microsoft-Server-ActiveSync');
    expect(html).toContain('Show these requests');
    expect(html).toContain('Alert history');
  });

  it('shows traffic, upstreams, paths, configuration and changes', () => {
    const html = renderDetail();
    for (const text of ['Last 24 hours', '2,729', '60.7 MB', 'Alert at', 'Upstreams', 'https://mailcow-nginx:443', 'TLS to upstream', 'Health checks are off', 'Where requests go', '143 × 501', 'closed by the client', 'Configuration', 'Edit routing']) {
      expect(html, text).toContain(text);
    }
    // Editing a section stays on this page.
    expect(html).toContain('href="#routing"');
    // The changes are on the History tab, not the overview.
    expect(html).not.toContain('Changes to this host');
  });

  it('offers health checks only with more than one upstream, and warns about passive ones on a lone upstream', () => {
    const lone = renderDetail();
    expect(lone).toContain('With one upstream there is no other to send requests to');
    expect(lone).not.toContain('Turn on health checks');

    const second = { upstream: 'https://mailcow-nginx-2:443', dial: 'mailcow-nginx-2:443', tls: true, status: 'unchecked' as const, reported: true, fails: 0, requestsInFlight: 0 };
    const two = renderDetail({ health: { ...detail.health, upstreams: [...detail.health.upstreams, second] } });
    expect(two).toContain('Turn on health checks');
    expect(two).toContain('href="#health-checks"');

    const passive = renderDetail({
      health: { ...detail.health, healthChecks: { active: null, passive: { counting: true, failDuration: '30s', maxFails: null }, loadBalancing: null } } as HostDetail['health'],
    });
    expect(passive).toContain('With one upstream, a single failed request makes Caddy refuse every request for 30s.');
    expect(passive).toContain('href="#load-balancing"');
  });

  it('leaves out what the reader may not use', () => {
    const html = renderDetail({ traffic: null, changes: null }, { ...ALL, write: false, analytics: false, alerts: false, auditLog: false });
    for (const text of ['Edit routing', 'Last 24 hours', 'Where requests go', 'href="#history"', 'Turn on health checks', 'Show these requests', 'Alert history', 'Disable']) {
      expect(html, text).not.toContain(text);
    }
    expect(html).toContain('Upstreams');
    expect(html).toContain('Configuration');
  });
});
