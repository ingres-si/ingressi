import { describe, expect, it } from 'vitest';
import { dayText, hostConfigSummaries } from '@/src/lib/proxy-host-config-summary';
import type { ProxyHost } from '@/src/lib/models/proxy-hosts';
import type { HostCertificate, ProtectionInput } from '@/src/lib/proxy-host-view';

function host(extra: Partial<ProxyHost> = {}): ProxyHost {
  return {
    id: 1,
    name: 'Mail',
    domains: ['mail.example.com'],
    upstreams: ['https://mailcow:443'],
    certificateId: null,
    accessListId: null,
    sslForced: true,
    hstsEnabled: true,
    hstsSubdomains: false,
    allowWebsocket: true,
    preserveHostHeader: true,
    skipHttpsHostnameValidation: false,
    enabled: true,
    createdAt: '2026-06-03T00:00:00.000Z',
    updatedAt: '2026-06-03T00:00:00.000Z',
    customReverseProxyJson: null,
    customPreHandlersJson: null,
    authentik: null,
    loadBalancer: null,
    dnsResolver: null,
    upstreamDnsResolution: null,
    geoblock: null,
    geoblockMode: 'merge',
    waf: null,
    mtls: null,
    ingressiForwardAuth: null,
    forwardAuth: null,
    redirects: [],
    rewrite: null,
    locationRules: [],
    pathAllows: [],
    pathBlocks: [],
    pathAccessLists: [],
    pathRewrites: [],
    errorPages: [],
    rateLimit: null,
    tags: [],
    ...extra,
  };
}

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

const ACME: HostCertificate = {
  visible: true,
  kind: 'acme',
  name: null,
  daysLeft: 86,
  validTo: '2026-12-28T10:00:00.000Z',
  issuer: "Let's Encrypt",
  renewal: 'scheduled',
  certificateId: null,
};

describe('hostConfigSummaries', () => {
  it('summarises each editor section of a plain host', () => {
    const rows = hostConfigSummaries(host(), NONE, ACME);
    expect(rows.map((row) => row.section)).toEqual(['routing', 'security', 'access', 'certificate', 'headers']);
    expect(Object.fromEntries(rows.map((row) => [row.section, row.summary]))).toEqual({
      routing: '1 upstream over HTTPS · no health checks · WebSockets on',
      security: 'WAF off · no rate limit',
      access: 'Public: anyone who reaches the domain gets through',
      certificate: "Let's Encrypt · renews automatically · expires 28 Dec 2026 · HTTP redirects to HTTPS",
      headers: 'HSTS on · Host header passed through',
    });
  });

  it('names what protects the host and what the advanced section holds', () => {
    const rows = hostConfigSummaries(
      host({
        upstreams: ['http://a:80', 'http://b:80'],
        loadBalancer: {
          enabled: true, policy: 'least_conn', policyHeaderField: null, policyCookieName: null, policyCookieSecret: null,
          tryDuration: null, tryInterval: null, retries: null, activeHealthCheck: null,
          passiveHealthCheck: { enabled: true, failDuration: '30s', maxFails: 3, unhealthyStatus: null, unhealthyLatency: null },
        },
        waf: { enabled: true, mode: 'On' },
        pathBlocks: [{ path: '/admin', status: 403 }],
        redirects: [{ from: '/old', to: '/new', status: 301 }],
        customReverseProxyJson: '{}',
        hstsSubdomains: true,
        sslForced: false,
      }),
      { ...NONE, wafMode: 'block', sso: true, accessList: { name: 'Office' }, rateLimit: { rules: 2, first: null } },
      { visible: false, automatic: true }
    );
    const byId = Object.fromEntries(rows.map((row) => [row.section, row.summary]));
    expect(byId.routing).toBe('2 upstreams · least connections load balancing · health checks on · WebSockets on');
    expect(byId.security).toBe('WAF blocks · 2 rate limit rules');
    expect(byId.access).toBe('Sign-in with dashboard accounts · access list "Office" · 1 blocked path');
    expect(byId.certificate).toBe('Obtained automatically · HTTP not redirected');
    expect(byId.headers).toBe('HSTS on, with subdomains · Host header passed through');
    expect(byId.advanced).toBe('1 redirect · custom Caddy JSON');
  });

  it('says when the WAF follows the global settings', () => {
    const [, security] = hostConfigSummaries(host(), { ...NONE, wafMode: 'detection_only' }, ACME);
    expect(security.summary).toBe('WAF detection only (global settings) · no rate limit');
  });

  it('formats days in UTC', () => {
    expect(dayText('2026-12-31T23:30:00.000Z')).toBe('31 Dec 2026');
    expect(dayText('nonsense')).toBe('');
  });
});
