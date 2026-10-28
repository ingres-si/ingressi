/**
 * Server-side render of the host editor: the page frame (breadcrumb, the
 * linkable section list, the bar), each section with its labelled fields, a
 * new host's name field in Routing, and raw Caddy JSON read-only for users
 * who are not administrators.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/proxy-hosts/7/edit',
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/app/(dashboard)/proxy-hosts/editor-actions', () => ({
  saveProxyHostEditorAction: vi.fn(),
  previewProxyHostEditorAction: vi.fn(),
}));
vi.mock('@/app/(dashboard)/certificates/actions', () => ({ saveManagedCertificateAction: vi.fn() }));

import type { ProxyHost } from '@/src/lib/models/proxy-hosts';
import type { HostEditorData } from '@/src/components/proxy-hosts/editor/types';
import { HostEditor } from '@/src/components/proxy-hosts/editor/HostEditor';
import { EditorProvider, type EditorContextValue } from '@/src/components/proxy-hosts/editor/fields';
import { hostToForm, type HostForm } from '@/src/components/proxy-hosts/editor/model';
import { SecuritySection } from '@/src/components/proxy-hosts/editor/SecuritySection';
import { AccessSection } from '@/src/components/proxy-hosts/editor/AccessSection';
import { AdvancedSection, CertificateSection, HeadersSection } from '@/src/components/proxy-hosts/editor/OtherSections';
import { RoutingSection } from '@/src/components/proxy-hosts/editor/RoutingSection';
import { ReviewPanel, type PreviewState } from '@/src/components/proxy-hosts/editor/ReviewPanel';

const host: ProxyHost = {
  id: 7,
  name: 'App',
  domains: ['app.example.com'],
  upstreams: ['http://10.0.0.5:8080'],
  certificateId: null,
  accessListId: null,
  sslForced: true,
  hstsEnabled: true,
  hstsSubdomains: true,
  allowWebsocket: true,
  preserveHostHeader: true,
  skipHttpsHostnameValidation: false,
  enabled: true,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-02T00:00:00.000Z',
  customReverseProxyJson: '{"headers":{}}',
  customPreHandlersJson: null,
  authentik: null,
  loadBalancer: null,
  dnsResolver: null,
  upstreamDnsResolution: null,
  geoblock: null,
  geoblockMode: 'merge',
  waf: { enabled: true, mode: 'On', waf_mode: 'merge', excluded_rule_ids: [942430] },
  mtls: null,
  ingressiForwardAuth: null,
  forwardAuth: null,
  redirects: [],
  rewrite: null,
  locationRules: [],
  pathAllows: [],
  pathBlocks: [],
  pathRewrites: [],
  errorPages: [],
  rateLimit: null,
  tags: ['prod'],
};

function data(overrides: Partial<HostEditorData> = {}): HostEditorData {
  return {
    mode: 'edit',
    host,
    template: null,
    initialDomain: null,
    forwardAuthAccess: { userIds: [], groupIds: [] },
    certificates: [{ id: 2, name: 'Wildcard', type: 'imported', domains: ['*.example.com'], expiresAt: '2027-01-01T00:00:00.000Z', issuer: 'Example CA', provider: null }],
    servedCertificate: null,
    clientAddress: { proxiesTrusted: false, forwardedForForgeable: false },
    accessLists: [{ id: 3, name: 'Office', description: null, rules: 2, members: 0, defaultAction: 'deny', otherHosts: 1 }],
    blockedSourcesActive: true,
    caCertificates: [],
    mtlsRoles: [],
    clientCertificates: [],
    users: [],
    groups: [],
    canChooseTrust: true,
    canChooseUsers: true,
    canChooseGroups: true,
    canChooseAccessLists: true,
    isAdmin: true,
    authentikDefaults: null,
    forwardAuthDefaults: null,
    scopeTags: [],
    approval: { policies: [], canEmergency: false },
    wafGlobal: { appliesToAll: true, mode: 'On', loadOwaspCrs: true, paranoiaLevel: 1, inboundThreshold: 5 },
    wafExclusions: [
      { id: 1, ruleId: 942430, wholeHost: true, path: null, pathMatch: null, variable: null, reason: 'Search box', createdBy: 'admin', createdAt: '2026-09-12T00:00:00.000Z' },
      { id: 2, ruleId: 920420, wholeHost: false, path: '/upload', pathMatch: 'prefix', variable: null, reason: 'Uploads', createdBy: null, createdAt: '2026-07-02T00:00:00.000Z' },
    ],
    wafRuleMessages: { 942430: 'Restricted SQL Character Anomaly Detection (args)' },
    canReadWaf: true,
    rateLimitDefaults: null,
    geoblockGlobal: null,
    dnsProviderConfigured: false,
    dnsChoices: { providers: [], defaultProvider: null },
    canCreateCertificate: true,
    lastSaved: { at: '2026-01-02T00:00:00.000Z', by: 'admin' },
    historyHref: '/audit-log?search=App',
    ...overrides,
  };
}

function inEditor(element: ReactElement, editorData: HostEditorData = data(), formOverrides: Partial<HostForm> = {}): string {
  const form = { ...hostToForm(editorData.host!), ...formOverrides };
  const value: EditorContextValue = {
    form,
    saved: form,
    data: editorData,
    lookup: {
      certificate: String,
      accessList: String,
      user: String,
      group: String,
      role: String,
      clientCertificate: String,
      globalWafMode: 'blocking',
    },
    update: () => {},
    certificateSaved: () => {},
    errors: {},
    touch: () => {},
    wasOf: () => null,
  };
  return renderToStaticMarkup(createElement(EditorProvider, { value, children: element }));
}

describe('host editor page', () => {
  it('on a host\'s page: one tab bar with Overview, the sections and History, opening on the overview without a bar', () => {
    const workspace = {
      header: (tabs: unknown) => createElement('header', { 'data-testid': 'page-header' }, tabs as never),
      overview: createElement('p', null, 'The overview'),
      history: createElement('p', null, 'The history'),
      historyCount: 4,
    };
    const html = renderToStaticMarkup(createElement(HostEditor, { data: data(), workspace }));
    expect(html).toContain('data-testid="page-header"');
    expect(html).toContain('aria-label="Host sections"');
    for (const tab of ['overview', 'routing', 'security', 'access', 'certificate', 'headers', 'advanced', 'history']) {
      expect(html).toContain(`href="#${tab}"`);
    }
    expect(html).toMatch(/<a href="#overview" role="tab" aria-selected="true"/);
    expect(html).toContain('The overview');
    expect(html).not.toContain('The history');
    // Nothing changed: no bar, and no editor-only header (the page has its own).
    expect(html).not.toContain('data-testid="host-editor-bar"');
    expect(html).not.toContain('Edit App');
  });

  it('asks for a new host’s name in Routing and starts from ?domain=', () => {
    const html = renderToStaticMarkup(createElement(HostEditor, { data: data({ mode: 'create', host: null, initialDomain: 'new.example.com', lastSaved: null }) }));
    expect(html).toContain('New proxy host');
    expect(html).toContain('<label for="f-name"');
    expect(html).toContain('new.example.com');
    expect(html).toContain('>Create host<');
    // The same tab bar, without Overview and History, and the bar from the start.
    expect(html).toContain('aria-label="Host settings"');
    expect(html).toMatch(/<a href="#routing" role="tab" aria-selected="true"/);
    expect(html).not.toContain('href="#overview"');
    expect(html).toContain('data-testid="host-editor-bar"');
  });
});

describe('host editor sections', () => {
  it('Routing: domains, upstreams, load balancing and protocols', () => {
    const html = inEditor(createElement(RoutingSection));
    expect(html).toContain('Add domains');
    expect(html).toContain('aria-label="Domains"');
    expect(html).toContain('placeholder="10.0.0.5:8080"');
    expect(html).toContain('aria-label="Upstream 1 scheme"');
    expect(html).toContain('Custom load balancing');
    expect(html).toContain('Path-based routes');
    // Edit mode keeps the name in Advanced.
    expect(html).not.toContain('<label for="f-name"');
  });

  it('Routing: warns that passive health checks on a lone upstream refuse every request after a failure', () => {
    const lb = {
      enabled: true, policy: 'random', policyHeaderField: null, policyCookieName: null, policyCookieSecret: null, tryDuration: null, tryInterval: null, retries: null,
      activeHealthCheck: null, passiveHealthCheck: { enabled: true, failDuration: '30s', maxFails: null, unhealthyStatus: null, unhealthyLatency: null },
    };
    const lone = data({ host: { ...data().host!, loadBalancer: lb as never } });
    const html = inEditor(createElement(RoutingSection), lone);
    expect(html).toContain('One upstream with passive health checks:');
    expect(html).toContain('Caddy refuses every request to this host (503) for 30s');
    const two = data({ host: { ...data().host!, upstreams: ['http://10.0.0.5:8080', 'http://10.0.0.6:8080'], loadBalancer: lb as never } });
    expect(inEditor(createElement(RoutingSection), two)).not.toContain('One upstream with passive health checks');
  });

  it('Security: the WAF mode, the host’s exclusions and rate limiting', () => {
    const html = inEditor(createElement(SecuritySection));
    // The mode is a radio group of cards, like the WAF settings' global mode; the host blocks.
    expect(html).toContain('role="radiogroup" aria-labelledby="f-waf-mode-label"');
    expect(html).toMatch(/role="radio" aria-checked="true"[^>]*>(?:(?!role="radio").)*?Block/s);
    // Geo blocking is part of Security.
    expect(html).toContain('Geo blocking');
    // Global mode names the mode the WAF settings give it today.
    expect(html).toContain('Follows the WAF settings: blocking now.');
    // The rarely changed settings sit under Advanced, closed while they are the defaults.
    expect(html).toMatch(/aria-expanded="false" aria-controls="waf-advanced"/);
    expect(html).toContain('<div id="waf-advanced" hidden=""');
    // Every exclusion with where it applies; changing them needs waf:write.
    expect(html).toContain('Restricted SQL Character Anomaly Detection (args)');
    expect(html).toContain('Every request');
    expect(html).toContain('Paths under /upload');
    expect(html).not.toContain('Edit in WAF settings');
    expect(html).not.toContain('aria-label="Remove the exclusion of rule 942430"');
    expect(html).toContain('Rate limiting');
    expect(html).toContain('No global rules are set, so nothing is limited.');
    expect(inEditor(createElement(SecuritySection), data({ rateLimitDefaults: { enabled: true, rules: 2 } }))).toContain('The 2 global rules apply; this host adds none.');
  });

  it('Security: writers change and remove exclusions in place, and exclude the rules that matched lately', () => {
    const html = inEditor(
      createElement(SecuritySection),
      data({ canWriteWaf: true, wafRecentRules: [{ ruleId: 941100, message: 'XSS Attack Detected via libinjection', events: 12, blocked: 3, topPath: '/search' }, { ruleId: 942430, message: null, events: 4, blocked: 0, topPath: null }] })
    );
    expect(html).toContain('Add exclusion');
    expect(html).toContain('aria-label="Change the exclusion of rule 942430"');
    expect(html).toContain('aria-label="Remove the exclusion of rule 942430"');
    expect(html).toContain('Matched this host in the last 7 days');
    expect(html).toContain('XSS Attack Detected via libinjection');
    expect(html).toContain('12 matches, 3 blocked · mostly /search');
    expect(html).toContain('aria-label="Exclude rule 941100"');
    // Rules already excluded on every request are not offered again.
    expect(html).not.toContain('aria-label="Exclude rule 942430"');
  });

  it('Security: Advanced opens by itself when something in it is not the default', () => {
    const host = data().host!;
    const html = inEditor(createElement(SecuritySection), data({ host: { ...host, waf: { ...host.waf!, waf_mode: 'override' } } as never }));
    expect(html).toMatch(/aria-expanded="true" aria-controls="waf-advanced"/);
    expect(html).toContain('own settings only');
  });

  it('Security: geo blocking says which rules apply, and when allow rules alone block nothing', () => {
    const host = data().host!;
    const render = (geoblock: object | null, geoblockMode: 'merge' | 'override', globalOn = true, globalBlocks = true) =>
      inEditor(createElement(SecuritySection), data({ host: { ...host, geoblock: geoblock as never, geoblockMode }, geoblockGlobal: { enabled: globalOn, blocks: globalBlocks } }));
    expect(render({ enabled: false }, 'merge')).toContain('Off for this host: only the global geo blocking rules apply.');
    expect(render({ enabled: false }, 'override')).toContain('overrides the global geo blocking rules, so none apply');
    expect(render({ enabled: false }, 'override', false)).not.toContain('Off for this host');
    // A mode without settings (the API can store one) leaves the global rules in force, so it reads as merge.
    expect(render(null, 'override')).toContain('Off for this host: only the global geo blocking rules apply.');

    const allowOnly = { enabled: true, allow_countries: ['AT'] };
    expect(render(allowOnly, 'override')).toContain('with no block rules nothing is blocked');
    expect(render(allowOnly, 'merge', false)).toContain('with no block rules nothing is blocked');
    // Merged, the host's allow rules make exceptions to the global block rules, if it has any.
    expect(render(allowOnly, 'merge')).not.toContain('nothing is blocked');
    expect(render(allowOnly, 'merge', true, false)).toContain('with no block rules nothing is blocked');
    expect(render({ ...allowOnly, block_continents: ['EU'] }, 'override')).not.toContain('nothing is blocked');
  });

  it('Access: access list, geo blocking, sign-in, mTLS and blocked paths', () => {
    const html = inEditor(createElement(AccessSection));
    expect(html).toContain('<label for="f-access-list"');
    expect(html).toContain('Blocked sources');
    expect(html).toContain('aria-label="Provider"');
    expect(html).toContain('Require client certificates');
    expect(html).toContain('Blocked paths');
  });

  it('Certificate and Headers', () => {
    const certificate = inEditor(createElement(CertificateSection));
    expect(certificate).toContain('Managed by Caddy (automatic)');
    expect(certificate).toContain('Wildcard · imported');
    expect(certificate).toContain('Redirect HTTP to HTTPS');
    // Only the default provider is set up: nothing else to choose.
    expect(certificate).not.toContain('Use a different DNS provider');
    const headers = inEditor(createElement(HeadersSection));
    expect(headers).toContain('Send the HSTS header');
    expect(headers).toContain('Include subdomains');
  });

  it('Certificate: says how the certificate is obtained and offers another DNS provider', () => {
    const dnsChoices = {
      providers: [{ name: 'cloudflare', label: 'Cloudflare' }, { name: 'godaddy', label: 'GoDaddy' }],
      defaultProvider: 'cloudflare',
    };
    const automatic = inEditor(createElement(CertificateSection), data({ dnsChoices }));
    expect(automatic).toContain('Obtained with');
    expect(automatic).toContain('DNS-01 with Cloudflare (default)');
    expect(automatic).toContain('Use a different DNS provider');
    // Without certificates:write the button is left out, and so is it when only the default provider exists.
    expect(inEditor(createElement(CertificateSection), data({ dnsChoices, canCreateCertificate: false }))).not.toContain('Use a different DNS provider');
    expect(inEditor(createElement(CertificateSection), data({ dnsChoices: { ...dnsChoices, providers: [dnsChoices.providers[0]] } }))).not.toContain('Use a different DNS provider');
    // No DNS provider at all: HTTP-01.
    expect(inEditor(createElement(CertificateSection))).toContain('>HTTP-01<');

    const managed = { id: 5, name: 'Shop', type: 'managed', domains: ['app.example.com'], expiresAt: null, issuer: null, provider: 'godaddy' };
    const chosen = inEditor(createElement(CertificateSection), data({ dnsChoices, host: { ...host, certificateId: 5 }, certificates: [managed] }));
    expect(chosen).toContain('DNS-01 with GoDaddy');
    expect(chosen).not.toContain('(default)');
    expect(chosen).toContain('Edit certificate');
    expect(chosen).not.toContain('Use a different DNS provider');
    // A managed certificate without an override follows the default provider.
    const followsDefault = inEditor(createElement(CertificateSection), data({ dnsChoices, host: { ...host, certificateId: 5 }, certificates: [{ ...managed, provider: null }] }));
    expect(followsDefault).toContain('DNS-01 with Cloudflare (default)');

    // An imported certificate is not obtained from anyone.
    const imported = inEditor(createElement(CertificateSection), data({ dnsChoices, host: { ...host, certificateId: 2 } }));
    expect(imported).not.toContain('Obtained with');
    expect(imported).not.toContain('Edit certificate');
  });

  it('Certificate: shows what Caddy serves for the saved choice, a managed entry included', () => {
    const validTo = new Date(Date.now() + 60 * 86_400_000 + 3_600_000).toISOString();
    const served = { domains: ['app.example.com'], issuer: 'R11', keyType: 'ECDSA P-256', validTo };
    const managed = { id: 5, name: 'Shop', type: 'managed', domains: ['app.example.com'], expiresAt: null, issuer: null, provider: null };
    const onManaged = { host: { ...host, certificateId: 5 }, certificates: [managed] };

    // Saved with the managed entry: the same issuer, key and expiry as the overview.
    const known = inEditor(createElement(CertificateSection), data({ ...onManaged, servedCertificate: served }));
    expect(known).toContain('R11');
    expect(known).toContain('ECDSA P-256');
    expect(known).toContain('60 days');
    expect(known).not.toContain('Not known here');
    expect(known).not.toContain('Obtained by Caddy');
    // Not read yet: the placeholders stay.
    const unread = inEditor(createElement(CertificateSection), data(onManaged));
    expect(unread).toContain('Obtained by Caddy');
    expect(unread).toContain('Not known here');

    // A changed, unsaved selection has no reading yet, in either direction.
    const toAutomatic = inEditor(createElement(CertificateSection), data({ ...onManaged, servedCertificate: served }), { certificateId: null });
    expect(toAutomatic).not.toContain('R11');
    expect(toAutomatic).toContain('Obtained and renewed automatically once the host is saved.');
    const toManaged = inEditor(createElement(CertificateSection), data({ certificates: [managed], servedCertificate: served }), { certificateId: 5 });
    expect(toManaged).not.toContain('R11');
    expect(toManaged).toContain('Not known here');

    // Automatic stays as it was; an imported certificate keeps the expiry of its PEM.
    expect(inEditor(createElement(CertificateSection), data({ servedCertificate: served }))).toContain('R11');
    const imported = inEditor(createElement(CertificateSection), data({ host: { ...host, certificateId: 2 }, servedCertificate: served }));
    expect(imported).toContain('Example CA');
    expect(imported).not.toContain('R11');

    // The tab's summary says the same.
    const tabs = (editorData: HostEditorData) => renderToStaticMarkup(createElement(HostEditor, { data: editorData }));
    expect(tabs(data({ ...onManaged, servedCertificate: served }))).toContain('title="Shop · 60 days left"');
    expect(tabs(data(onManaged))).toContain('title="Shop"');
  });

  it('Advanced: raw Caddy JSON is read-only for users who are not administrators', () => {
    const admin = inEditor(createElement(AdvancedSection));
    expect(admin).toContain('<label for="f-name"');
    expect(admin).not.toMatch(/<textarea[^>]*id="f-reverse-proxy"[^>]*disabled/);
    const user = inEditor(createElement(AdvancedSection), data({ isAdmin: false }));
    expect(user).toContain('Only administrators can change custom Caddy JSON.');
    expect(user).toMatch(/<textarea[^>]*disabled=""[^>]*id="f-reverse-proxy"|<textarea[^>]*id="f-reverse-proxy"[^>]*disabled=""/);
  });
});

describe('host editor review', () => {
  const window = { restricted: false, open: true, nextOpenAt: null, description: null };
  function review(required: boolean, policiesExist: boolean): string {
    const preview = {
      status: 'ready',
      preview: {
        approval: { required, policies: required ? [{ id: 1, name: 'Production' }] : [], requiredApprovals: 1, operations: ['update'], window, emergencyAllowed: false, minEmergencyReasonLength: 10 },
        changes: [],
        impact: { lines: [{ key: 'reload', text: 'Reloads its configuration on this node.' }] },
        warning: null,
      },
    } as unknown as PreviewState;
    const noop = () => {};
    return renderToStaticMarkup(
      createElement(ReviewPanel, {
        title: 'Review 1 change to App', changes: [], creating: false, preview, note: '', onNote: noop, emergency: false, onEmergency: noop,
        emergencyReason: '', onEmergencyReason: noop, submitError: null, submitting: false, submitLabel: required ? 'Submit for approval' : 'Save changes',
        onSubmit: noop, onClose: noop, onShow: noop, onUndo: noop, hostLabel: 'App', policiesExist,
      })
    );
  }

  it('says no approval is needed only where approval policies exist', () => {
    expect(review(false, true)).toContain('No approval needed.');
    expect(review(false, false)).not.toContain('No approval needed.');
    expect(review(false, false)).toContain('Reloads its configuration on this node.');
  });

  it('says which policy covers a change and what it needs', () => {
    const html = review(true, true);
    expect(html).toContain('This change needs approval');
    expect(html).toContain('App is covered by &quot;Production&quot;.');
    expect(html).toContain('needs 1 approval from someone other than you, and is applied as soon as it is approved.');
  });
});
