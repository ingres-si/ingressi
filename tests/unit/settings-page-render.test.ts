/**
 * The settings pages: the catalog that tells the command palette and the
 * old Settings links where each section is now (every old id still leads
 * somewhere, every page is in the navigation with settings:read), the save
 * bar's change count, and server-side renders of each page in its main
 * states (replica wording, read-only analytics, restricted sections).
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const searchParams = new URLSearchParams();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings',
  useSearchParams: () => searchParams,
}));
// Server actions are not called by a render; stubs keep the database and Caddy out of it.
vi.mock('../../app/(dashboard)/settings/actions', () => ({
  updateGeneralSettingsAction: vi.fn(),
  updateDefaultResponseSettingsAction: vi.fn(),
  updateAcmeSettingsAction: vi.fn(),
  updateDnsProviderSettingsAction: vi.fn(),
  updateDnsSettingsAction: vi.fn(),
  createSlaveInstanceAction: vi.fn(),
  deleteSlaveInstanceAction: vi.fn(),
  pinSlaveSyncKeyAction: vi.fn(),
  resetSlaveSyncKeyPinAction: vi.fn(),
  syncSlaveInstancesAction: vi.fn(),
  toggleSlaveInstanceAction: vi.fn(),
  updateInstanceModeAction: vi.fn(),
  updateSlaveInstanceAction: vi.fn(),
  updateSlaveMasterTokenAction: vi.fn(),
  updateTrustedProxiesSettingsAction: vi.fn(),
  updateUpstreamDnsResolutionSettingsAction: vi.fn(),
  updateAuthentikSettingsAction: vi.fn(),
  updateErrorPagesSettingsAction: vi.fn(),
  updateResponseHeadersSettingsAction: vi.fn(),
  updateForwardAuthSettingsAction: vi.fn(),
  updateGeoBlockSettingsAction: vi.fn(),
  updateRateLimitSettingsAction: vi.fn(),
  updateLoggingSettingsAction: vi.fn(),
  updateMetricsSettingsAction: vi.fn(),
  createOAuthProviderAction: vi.fn(),
  updateOAuthProviderAction: vi.fn(),
  deleteOAuthProviderAction: vi.fn(),
}));
vi.mock('@/ee/high-availability/ui/certificate-storage-actions', () => ({
  saveCertificateStorageAction: vi.fn(),
  removeCertificateStorageAction: vi.fn(),
  testCertificateStorageAction: vi.fn(),
}));

import SettingsClient, { type SettingsClientProps } from '../../app/(dashboard)/settings/SettingsClient';
import CertificateSettingsClient, { type CertificateSettingsProps } from '../../app/(dashboard)/certificates/settings/CertificateSettingsClient';
import HostDefaultsClient, { type HostDefaultsProps } from '../../app/(dashboard)/proxy-hosts/defaults/HostDefaultsClient';
import GeoBlockingClient from '../../app/(dashboard)/geo-blocking/GeoBlockingClient';
import RateLimitingClient from '../../app/(dashboard)/rate-limiting/RateLimitingClient';
import AnalyticsSettingsClient, { type AnalyticsSettingsProps } from '../../app/(dashboard)/analytics/settings/AnalyticsSettingsClient';
import InstancesClient from '../../app/(dashboard)/instances/InstancesClient';
import type { InstanceSyncProps } from '../../app/(dashboard)/instances/types';
import ClusterSection from '@/ee/high-availability/ui/ClusterSection';
import BackupsTab from '@/ee/backups/ui/BackupsTab';
import { countChanges } from '@/src/components/settings/settings-form';
import { NAV_PAGES } from '../../src/lib/navigation';
import { SETTINGS_PAGES, SETTINGS_SECTIONS, findSettingsSection, settingsSectionHref } from '../../src/lib/settings-sections';
import { GEOIP_ASN_DB, GEOIP_COUNTRY_DB, getGeoIpDatabases, getGeoIpStatus } from '../../src/lib/geoip-status';
import { decodeEntities } from '../helpers/text';

/** Every id `/settings?section=` (or `#`) accepted by the old Settings page. */
const OLD_SECTION_IDS = [
  'general', 'acme', 'sync', 'high-availability', 'backups', 'trusted-proxies', 'upstream-dns',
  'geoblock', 'rate-limit', 'error-pages', 'forward-auth', 'oauth', 'analytics', 'branding',
  'default-response', 'dns-providers', 'dns-resolvers', 'certificate-storage', 'shared-state', 'authentik', 'metrics', 'logging',
  'instance-sync',
];

function decode(html: string): string {
  return decodeEntities(html);
}

describe('where each setting is', () => {
  it('sends every old Settings link to the page that holds the section now', () => {
    for (const id of OLD_SECTION_IDS) {
      expect(settingsSectionHref(id), id).not.toBeNull();
    }
    expect(settingsSectionHref('dns-providers')).toBe('/certificates/settings#dns-providers');
    expect(settingsSectionHref('acme')).toBe('/certificates/settings');
    expect(settingsSectionHref('default-response')).toBe('/proxy-hosts/defaults#default-response');
    expect(settingsSectionHref('authentik')).toBe('/proxy-hosts/defaults#authentik');
    expect(settingsSectionHref('geoblock')).toBe('/geo-blocking');
    expect(settingsSectionHref('rate-limit')).toBe('/rate-limiting');
    expect(settingsSectionHref('oauth')).toBe('/oauth-providers');
    expect(settingsSectionHref('logging')).toBe('/analytics/settings#logging');
    expect(settingsSectionHref('sync')).toBe('/instances');
    expect(settingsSectionHref('instance-sync')).toBe('/instances');
    expect(settingsSectionHref('shared-state')).toBe('/high-availability#shared-state');
    expect(settingsSectionHref('backups')).toBe('/backups');
    expect(settingsSectionHref('branding')).toBe('/branding');
    expect(settingsSectionHref('general')).toBe('/settings');
    // The groups of the old page, as ?group=.
    expect(settingsSectionHref('networking')).toBe('/proxy-hosts/defaults#trusted-proxies');
    expect(settingsSectionHref('nope')).toBeNull();
    expect(settingsSectionHref('')).toBeNull();
  });

  it('keeps ids unique and puts every section on a page of the navigation that needs settings:read', () => {
    const ids = SETTINGS_SECTIONS.map((section) => section.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const section of SETTINGS_SECTIONS) {
      const path = section.href.split('#')[0];
      const page = NAV_PAGES.find((candidate) => candidate.href === path);
      expect(page, section.id).toBeDefined();
      // Backups is its own permission area, as on the REST API.
      expect(page?.permission, section.id).toBe(section.id === 'backups' ? 'backups:read' : 'settings:read');
      expect(page?.label, section.id).toBe(section.page);
    }
    expect([...SETTINGS_PAGES].sort()).toEqual([
      '/analytics/settings', '/backups', '/certificates/settings', '/geo-blocking', '/high-availability', '/instances',
      '/oauth-providers', '/proxy-hosts/defaults', '/rate-limiting', '/settings',
    ]);
  });

  it('keeps the permission each section needs on top of settings:read', () => {
    expect(findSettingsSection('sync')?.permission).toBe('instances:read');
    expect(findSettingsSection('oauth')?.permission).toBe('sso:read');
    expect(findSettingsSection('backups')?.permission).toBe('backups:read');
    expect(findSettingsSection('certificate-storage')?.permission).toBe('high_availability:read');
    expect(findSettingsSection('high-availability')?.permission).toBe('high_availability:read');
    expect(findSettingsSection('shared-state')?.permission).toBe('high_availability:read');
    expect(findSettingsSection('geoblock')?.permission).toBeUndefined();
  });
});

describe('save bar change count', () => {
  it('counts each field name whose values differ', () => {
    const initial = new Map([['primaryDomain', ['a.example.com']], ['enabled', []], ['mode', ['caddy']]]);
    expect(countChanges(initial, new Map(initial))).toBe(0);
    expect(countChanges(initial, new Map([...initial, ['primaryDomain', ['b.example.com']]]))).toBe(1);
    // A switch turned on, and a field that appeared.
    expect(countChanges(initial, new Map([...initial, ['enabled', ['on']], ['status', ['404']]]))).toBe(2);
  });
});

describe('GeoIP status helper', () => {
  it('reports both databases with their paths', () => {
    const status = getGeoIpStatus();
    expect(typeof status.country).toBe('boolean');
    expect(typeof status.asn).toBe('boolean');
    expect(getGeoIpDatabases().map((database) => database.path)).toEqual([GEOIP_COUNTRY_DB, GEOIP_ASN_DB]);
  });
});

describe('Settings page', () => {
  function render(overrides: Partial<SettingsClientProps> = {}) {
    const props: SettingsClientProps = {
      general: { primaryDomain: 'example.com', acmeEmail: 'admin@example.com' },
      baseUrl: 'https://dashboard.example.com',
      isSlave: false,
      overrideGeneral: false,
      canWriteSettings: true,
      ...overrides,
    };
    return decode(renderToStaticMarkup(createElement(SettingsClient, props)));
  }

  it('shows the general settings, without the old group list', () => {
    const html = render();
    expect(html).toMatch(/<h1[^>]*>Settings/);
    expect(html).toContain('Primary domain');
    expect(html).toContain('https://dashboard.example.com');
    expect(html.match(/data-testid="settings-save-bar"/g)).toHaveLength(1);
    expect(html).not.toContain('Search settings');
    expect(html).not.toContain('Settings navigation');
    expect(html).not.toContain('Requests for unknown hosts');
    // The contact e-mail is on Certificate settings; General only carries it along.
    expect(html).toContain('<input type="hidden" data-untracked="" name="acmeEmail" value="admin@example.com"/>');
  });

  it('cannot save without settings:write, and asks a replica whether to override its master', () => {
    expect(render({ canWriteSettings: false })).toContain('Your role can read these settings but not change them.');
    expect(render({ isSlave: true })).toContain('Override the master');
  });
});

describe('Certificate settings page', () => {
  function render(overrides: Partial<CertificateSettingsProps> = {}) {
    const props: CertificateSettingsProps = {
      acme: null,
      general: { primaryDomain: 'example.com', acmeEmail: 'admin@example.com' },
      dnsProvider: null,
      dnsProviderDefinitions: [],
      dns: null,
      isSlave: false,
      overrides: { general: false, acme: false, dnsProvider: false, dns: false },
      certificateStorage: null,
      canSave: true,
      canOpenCertificates: true,
      ...overrides,
    };
    return decode(renderToStaticMarkup(createElement(CertificateSettingsClient, props)));
  }

  it('holds the CA, the contact e-mail, DNS-01 providers and resolvers, and certificate storage', () => {
    const html = render();
    expect(html).toMatch(/<h1[^>]*>Certificate settings/);
    expect(html).toContain('href="/certificates"');
    expect(html).toContain('Certificate authority');
    expect(html).toContain('Contact e-mail');
    for (const id of ['acme', 'dns-providers', 'dns-resolvers', 'certificate-storage']) expect(html).toContain(`id="${id}"`);
    expect(html).toContain('No DNS provider yet');
    expect(html).toContain('Use my own resolvers');
    // The primary domain is saved with the e-mail, from Settings.
    expect(html).toContain('<input type="hidden" data-untracked="" name="primaryDomain" value="example.com"/>');
    // Certificate storage needs high_availability:read.
    expect(html).toContain('high_availability:read');
  });

  it('says where a replica takes its contact e-mail from', () => {
    expect(render({ isSlave: true })).toContain('Follows the master unless Settings, General overrides it on this replica.');
  });
});

describe('Host defaults page', () => {
  function render(overrides: Partial<HostDefaultsProps> = {}) {
    const props: HostDefaultsProps = {
      defaultResponse: null,
      errorPages: null,
      responseHeaders: null,
      trustedProxies: null,
      upstreamDnsResolution: null,
      authentik: null,
      forwardAuth: null,
      isSlave: false,
      overrides: { defaultResponse: false, responseHeaders: false, trustedProxies: false, upstreamDnsResolution: false, authentik: false, forwardAuth: false },
      canSave: true,
      canOpenProxyHosts: true,
      ...overrides,
    };
    return decode(renderToStaticMarkup(createElement(HostDefaultsClient, props)));
  }

  it('holds the answer for unknown hosts, error pages, response headers, trusted proxies, upstream DNS and forward auth, with one save bar', () => {
    const html = render();
    expect(html).toMatch(/<h1[^>]*>Host defaults/);
    for (const id of ['default-response', 'error-pages', 'response-headers', 'trusted-proxies', 'upstream-dns', 'forward-auth', 'authentik', 'generic-forward-auth']) {
      expect(html).toContain(`id="${id}"`);
    }
    for (const answer of ['Caddy default', 'Custom response', 'Redirect', 'Close the connection']) expect(html).toContain(answer);
    expect(html).toContain('placeholder="outpost.goauthentik.io"');
    expect(html.match(/data-testid="settings-save-bar"/g)).toHaveLength(1);
    expect(html).toContain('No unsaved changes.');
  });

  it('has the PROXY protocol sources under Trusted proxies, empty by default', () => {
    const html = render();
    const card = html.slice(html.indexOf('id="trusted-proxies"'), html.indexOf('id="upstream-dns"'));
    expect(card).toContain('PROXY protocol from');
    expect(card).toContain('for="settings-proxy-protocol-ranges"');
    expect(card).toMatch(/<textarea[^>]*name="proxyProtocolRanges"[^>]*><\/textarea>/);
    expect(card).toContain('send a PROXY header (v1 or v2) to ports 80 and 443');
  });

  it('shows the stored PROXY protocol sources one per line', () => {
    const html = render({ trustedProxies: { ranges: [], proxy_protocol_ranges: ['192.168.1.1', '10.0.10.0/24'] } });
    expect(html).toMatch(/<textarea[^>]*name="proxyProtocolRanges"[^>]*>\n?192\.168\.1\.1\n10\.0\.10\.0\/24<\/textarea>/);
  });

  it('shows the stored response headers, set as name: value and removed one per line', () => {
    const html = render({ responseHeaders: { set: { Server: 'web', 'X-Frame-Options': 'DENY' }, remove: ['Via', 'X-Powered-By'] } });
    expect(html).toMatch(/<textarea[^>]*name="set"[^>]*>\n?Server: web\nX-Frame-Options: DENY<\/textarea>/);
    expect(html).toMatch(/<textarea[^>]*name="remove"[^>]*>\n?Via\nX-Powered-By<\/textarea>/);
  });

  it('locks the PROXY protocol sources on a replica that follows its master', () => {
    const textarea = (html: string) => html.match(/<textarea[^>]*name="proxyProtocolRanges"[^>]*>/)?.[0] ?? '';
    expect(textarea(render({ isSlave: true }))).toContain('disabled=""');
    const overridden = render({
      isSlave: true,
      overrides: { defaultResponse: false, responseHeaders: false, trustedProxies: true, upstreamDnsResolution: false, authentik: false, forwardAuth: false },
    });
    expect(textarea(overridden)).not.toContain('disabled=""');
  });
});

describe('Geo blocking and Rate limiting pages', () => {
  it('shows the GeoIP databases found and missing', () => {
    const html = decode(
      renderToStaticMarkup(
        createElement(GeoBlockingClient, {
          geoblock: null,
          geoip: [
            { name: 'GeoLite2 Country', path: GEOIP_COUNTRY_DB, found: true, updatedAt: '2026-10-01T03:00:00.000Z' },
            { name: 'GeoLite2 ASN', path: GEOIP_ASN_DB, found: false, updatedAt: null },
          ],
          canSave: true,
          canOpenSecurity: true,
        })
      )
    );
    expect(html).toMatch(/<h1[^>]*>Geo blocking/);
    expect(html).toContain(GEOIP_COUNTRY_DB);
    expect(html).toContain('Missing');
    expect(html).toContain('GeoLite2 ASN is missing');
    expect(html).toContain('Default rules');
    expect(html).toContain('href="/security"');
  });

  it('shows the default rate limits', () => {
    const html = decode(renderToStaticMarkup(createElement(RateLimitingClient, { rateLimit: null, canSave: true, canOpenSecurity: false })));
    expect(html).toMatch(/<h1[^>]*>Rate limiting/);
    expect(html).toContain('data-testid="rate-limit-settings"');
    expect(html).not.toContain('href="/security"');
  });
});

describe('Analytics settings page', () => {
  function render(overrides: Partial<AnalyticsSettingsProps> = {}) {
    const props: AnalyticsSettingsProps = {
      analytics: { enabled: true, retentionDays: 30, retentionFromEnv: false, totals: null, totalsError: null },
      logging: { enabled: true, format: 'json' },
      metrics: null,
      isSlave: false,
      overrides: { logging: false, metrics: false },
      canSave: true,
      canOpenAnalytics: true,
      ...overrides,
    };
    return decode(renderToStaticMarkup(createElement(AnalyticsSettingsClient, props)));
  }

  it('shows ClickHouse and its retention read-only, with totals only when given', () => {
    const without = render();
    expect(without).toContain('Keep events for');
    expect(without).toContain('30 days');
    expect(without).toContain('CLICKHOUSE_RETENTION_DAYS');
    expect(without).not.toContain('Unique addresses');
    expect(without).toContain('http://ingressi-caddy:9090/metrics');
    for (const id of ['analytics', 'logging', 'metrics']) expect(without).toContain(`id="${id}"`);

    const withTotals = render({
      analytics: { enabled: true, retentionDays: 30, retentionFromEnv: true, totals: { requests: 2_980_000, wafEvents: 30_545, bytes: 41.9e9, uniqueAddresses: 10_896 }, totalsError: null },
    });
    expect(withTotals).toContain('Unique addresses');
    expect(withTotals).toContain('30,545');
  });

  it('shows why ClickHouse did not answer and what to check', () => {
    const html = render({
      analytics: { enabled: true, retentionDays: 30, retentionFromEnv: false, totals: null, totalsError: { label: 'Host name not found', note: 'docker compose logs clickhouse says why.' } },
    });
    expect(html).toContain('Host name not found');
    expect(html).toContain('docker compose logs clickhouse says why.');
    expect(html).not.toContain('Connected');
  });

  it('warns that analytics stop while the access log is off', () => {
    expect(render({ logging: { enabled: false, format: 'json' } })).toContain('Traffic analytics get no new requests while access logging is off.');
  });
});

describe('Instance sync page', () => {
  const instanceSync: InstanceSyncProps = {
    mode: 'master',
    modeFromEnv: false,
    tokenFromEnv: false,
    slave: null,
    master: { instances: [], envInstances: [], orphanSyncKeyPins: [] },
  };

  it('says replica, never slave, while keeping the stored mode value', () => {
    const html = decode(renderToStaticMarkup(createElement(InstancesClient, { instanceSync, canWrite: true, canOpenFleet: true })));
    expect(html).toMatch(/<h1[^>]*>Instance sync/);
    expect(html).toContain('>Replica<');
    expect(html).toContain('<input type="hidden" name="mode" value="master"/>');
    expect(html).toContain('No replicas yet');
    expect(html).not.toMatch(/>[^<]*\bslaves?\b[^<]*</i);
  });

  it('shows a notice instead of the settings without instances:read', () => {
    const html = decode(renderToStaticMarkup(createElement(InstancesClient, { instanceSync: null, canWrite: false, canOpenFleet: false })));
    expect(html).toContain('instances:read');
    expect(html).not.toContain('Instance mode');
  });
});

describe('High availability page', () => {
  it('shows the dashboard cluster, or how to set one up', () => {
    const off = renderToStaticMarkup(
      createElement(ClusterSection, {
        view: { enabled: false, error: null, node: null, lease: null, replication: null, lastRestore: null, nodes: [], config: null },
      })
    );
    expect(off).toContain('High availability is off on this node');
    expect(off).toContain('ee/docs/high-availability.md');

    const now = '2026-10-03T10:00:00.000Z';
    const on = decode(
      renderToStaticMarkup(
        createElement(ClusterSection, {
          view: {
            enabled: true,
            error: null,
            node: { id: 'web-1', role: 'leader', startedAt: now, statusUpdatedAt: now },
            lease: { holder: 'web-1', epoch: 7, ttlSeconds: 15, checkedAt: now, error: null },
            replication: { replicaId: 'e7-0a1b2c3d', lastSyncAt: now, lagSeconds: 1, error: null, checkedAt: now },
            lastRestore: { at: now, ok: true, source: 'replica', replicaId: 'e6-99887766', durationMs: 2400, error: null },
            nodes: [
              { id: 'web-1', role: 'leader', epoch: 7, follow: null, lastRestore: null, updatedAt: now },
              { id: 'web-2', role: 'standby', epoch: null, follow: { replicaId: 'e7-0a1b2c3d', ready: true, error: null }, lastRestore: null, updatedAt: now },
            ],
            config: {
              redis: { mode: 'standalone', addresses: ['valkey.example.com:6379'], keyPrefix: 'ingressi-ha', tls: false, hasPassword: true },
              storage: { endpoint: 'https://s3.example.com', region: 'us-east-1', bucket: 'ingressi-ha', path: 'ingressi' },
              leaseTtlSeconds: 15,
              syncIntervalSeconds: 1,
              followIntervalSeconds: 5,
            },
          },
        })
      )
    );
    expect(on).toContain('Dashboard cluster');
    expect(on).toContain('Epoch 7');
    expect(on).toContain('e7-0a1b2c3d');
    expect(on).toContain('Restored from the newest replica');
    expect(on).toContain('web-2');
    expect(on).toContain('Ready');
    expect(on).not.toContain('Replication is behind');
  });
});

describe('Backups page', () => {
  it('pages through the backup runs', () => {
    const stamp = '2026-10-02T03:00:00.000Z';
    const runs = Array.from({ length: 25 }, (_, index) => ({
      id: 100 - index, destinationId: 1, destinationName: 'Offsite', trigger: 'schedule' as const, status: 'success' as const,
      startedAt: stamp, finishedAt: stamp, objectKey: `prod/backup-${index}.json`, sizeBytes: 2048, sha256: null, prunedCount: 0, error: null, warning: null,
    }));
    const html = decode(
      renderToStaticMarkup(
        createElement(BackupsTab, {
          destinations: [],
          runs: { runs, total: 60, page: 1, perPage: 25 },
          isSlave: false,
          minPassphraseLength: 12,
          paginateRuns: true,
        })
      )
    );
    expect(html).toContain('aria-label="Pages of backup runs"');
    expect(html).toContain('of <span class="num">60</span> runs');
    expect(html).toContain('href="/settings?page=2"');
  });
});
