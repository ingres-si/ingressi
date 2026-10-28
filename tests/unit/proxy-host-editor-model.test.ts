/**
 * The host editor's form model (src/components/proxy-hosts/editor): a stored
 * host round-trips through the form without a change, an update sends only
 * the fields that changed, the WAF keeps every value the user did not touch,
 * forward-auth grants follow the sign-in choice, the change list reads and
 * undoes, and the checks and server-error mapping point at the right field.
 */
import { describe, expect, it } from 'vitest';
import type { ProxyHost } from '@/src/lib/models/proxy-hosts';
import {
  buildPayload,
  copyHostForm,
  formToInput,
  hostToForm,
  newHostForm,
  payloadIsEmpty,
  withHealthChecksOn,
  type HostForm,
} from '@/src/components/proxy-hosts/editor/model';
import { changeGroups, formChanges, type ChangeLookup } from '@/src/components/proxy-hosts/editor/changes';
import { fieldOfServerError, isValidDomain, normalizeDomainInput, validateForm } from '@/src/components/proxy-hosts/editor/validate';

function host(overrides: Partial<ProxyHost> = {}): ProxyHost {
  return {
    id: 7,
    name: 'App',
    domains: ['app.example.com', 'www.example.com'],
    upstreams: ['http://10.0.0.5:8080', 'https://backend.example.com:8443'],
    certificateId: null,
    accessListId: 3,
    sslForced: true,
    hstsEnabled: true,
    hstsSubdomains: false,
    allowWebsocket: true,
    preserveHostHeader: true,
    skipHttpsHostnameValidation: false,
    enabled: true,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-02T00:00:00.000Z',
    customReverseProxyJson: '{"headers":{}}',
    customPreHandlersJson: null,
    authentik: null,
    loadBalancer: {
      enabled: true,
      policy: 'round_robin',
      policyHeaderField: null,
      policyCookieName: null,
      policyCookieSecret: null,
      tryDuration: '5s',
      tryInterval: null,
      retries: 2,
      activeHealthCheck: { enabled: true, uri: '/healthz', port: null, interval: '10s', timeout: '2s', status: 200, body: null },
      passiveHealthCheck: null,
    },
    dnsResolver: null,
    upstreamDnsResolution: null,
    geoblock: null,
    geoblockMode: 'merge',
    waf: { enabled: true, mode: 'On', waf_mode: 'merge', request_body_limit: 13_107_200, excluded_rule_ids: [942430], custom_directives: '' },
    mtls: null,
    ingressiForwardAuth: null,
    forwardAuth: null,
    redirects: [{ from: '/docs', to: 'https://docs.example.com/', status: 302 }],
    rewrite: null,
    locationRules: [{ path: '/api/*', upstreams: ['http://10.0.0.9:9000'], loadBalancer: null }],
    pathAllows: [],
    pathBlocks: [{ path: '/metrics', status: 404 }],
    pathRewrites: [],
    errorPages: [{ statuses: [502, 503], body: '<h1>Down</h1>' }],
    rateLimit: { enabled: true, mode: 'merge', rules: [{ path: '/login', methods: ['POST'], key: 'client_ip', events: 5, window: '30s' }] },
    tags: ['prod'],
    ...overrides,
  };
}

const lookup: ChangeLookup = {
  certificate: (id) => `Certificate ${id}`,
  accessList: (id) => `List ${id}`,
  user: (id) => `user${id}`,
  group: (id) => `group${id}`,
  role: (id) => `role${id}`,
  clientCertificate: (id) => `cert${id}`,
  globalWafMode: 'blocking',
};

function edited(form: HostForm, recipe: (form: HostForm) => HostForm): HostForm {
  return recipe(structuredClone(form));
}

describe('host editor payload', () => {
  it('sends nothing when nothing changed, for a host with many settings', () => {
    const stored = host();
    const saved = hostToForm(stored);
    expect(payloadIsEmpty(buildPayload(saved, saved, stored, false))).toBe(true);
  });

  it('sends only the top-level field that changed', () => {
    const stored = host();
    const saved = hostToForm(stored);
    const form = edited(saved, (f) => ({ ...f, lb: { ...f.lb, policy: 'least_conn' } }));
    const payload = buildPayload(form, saved, stored, false);
    expect(Object.keys(payload.host)).toEqual(['loadBalancer']);
    expect(payload.host.loadBalancer).toMatchObject({ enabled: true, policy: 'least_conn', tryDuration: '5s', retries: 2 });
    expect(payload.forwardAuthAccess).toBeUndefined();
  });

  it('keeps stored WAF values the user did not touch (a 12.5 MiB body limit stays exact)', () => {
    const stored = host();
    const saved = hostToForm(stored);
    expect(saved.waf.bodyLimit).toBe('12.5');
    const form = edited(saved, (f) => ({ ...f, waf: { ...f.waf, mode: 'detection_only' } }));
    const waf = buildPayload(form, saved, stored, false).host.waf;
    expect(waf).toMatchObject({ enabled: true, mode: 'DetectionOnly', request_body_limit: 13_107_200, waf_mode: 'merge' });
    // Unchanged exclusions are left out, so the host's exclusion records stay as they are.
    expect(waf).not.toHaveProperty('excluded_rule_ids');
  });

  it('sends the excluded rule list when it changes', () => {
    const stored = host();
    const saved = hostToForm(stored);
    const form = edited(saved, (f) => ({ ...f, wafExcluded: [920540, 942430] }));
    expect(buildPayload(form, saved, stored, false).host.waf).toMatchObject({ excluded_rule_ids: [920540, 942430] });
  });

  it('does not give a host without WAF settings a WAF section unless the user picks a mode', () => {
    const stored = host({ waf: null });
    const saved = hostToForm(stored);
    expect(saved.waf.mode).toBe('inherit');
    expect(buildPayload(saved, saved, stored, false).host.waf).toBeUndefined();
    const form = edited(saved, (f) => ({ ...f, waf: { ...f.waf, mode: 'block' } }));
    expect(buildPayload(form, saved, stored, false).host.waf).toEqual({ enabled: true, mode: 'On', waf_mode: 'merge' });
  });

  it('turns the other sign-in providers off and keeps their settings', () => {
    const stored = host({
      authentik: {
        enabled: true,
        outpostDomain: 'outpost.example.com',
        outpostUpstream: 'http://outpost:9000',
        authEndpoint: '/outpost.example.com/auth/caddy',
        copyHeaders: ['X-Authentik-Username'],
        trustedProxies: ['private_ranges'],
        setOutpostHostHeader: true,
        protectedPaths: null,
        excludedPaths: ['/public/*'],
        bypassSources: [],
      },
    });
    const saved = hostToForm(stored);
    expect(saved.signIn).toBe('authentik');
    const form = edited(saved, (f) => ({ ...f, signIn: 'none' }));
    const payload = buildPayload(form, saved, stored, false);
    expect(Object.keys(payload.host)).toEqual(['authentik']);
    expect(payload.host.authentik).toMatchObject({ enabled: false, outpostDomain: 'outpost.example.com', excludedPaths: ['/public/*'] });
  });

  it('sends forward-auth grants when they change and clears them when the built-in sign-in is turned off', () => {
    const stored = host({ ingressiForwardAuth: { enabled: true, protected_paths: null, excluded_paths: null } });
    const saved = hostToForm(stored, { forwardAuthAccess: { userIds: [4], groupIds: [] } });
    const added = edited(saved, (f) => ({ ...f, ingressi: { ...f.ingressi, groupIds: [2] } }));
    expect(buildPayload(added, saved, stored, false)).toEqual({ host: {}, forwardAuthAccess: { userIds: [4], groupIds: [2] } });
    const off = edited(saved, (f) => ({ ...f, signIn: 'none' }));
    const payload = buildPayload(off, saved, stored, false);
    expect(payload.forwardAuthAccess).toEqual({ userIds: [], groupIds: [] });
    expect(payload.host.ingressiForwardAuth).toEqual({ enabled: false });
  });

  it('sends every field of a new host with the dashboard defaults', () => {
    const saved = newHostForm({ initialDomain: 'new.example.com', scopeTags: ['team-a'] });
    const form = edited(saved, (f) => ({ ...f, name: 'New', upstreams: [{ ...f.upstreams[0], address: '10.0.0.7:80' }] }));
    const { host: input, forwardAuthAccess } = buildPayload(form, saved, null, true);
    expect(input).toMatchObject({
      name: 'New',
      domains: ['new.example.com'],
      upstreams: ['http://10.0.0.7:80'],
      tags: ['team-a'],
      enabled: true,
      sslForced: true,
      hstsEnabled: true,
      hstsSubdomains: true,
      allowWebsocket: true,
      preserveHostHeader: true,
      certificateId: null,
      accessListId: null,
    });
    for (const key of ['waf', 'geoblock', 'authentik', 'forwardAuth', 'ingressiForwardAuth', 'mtls', 'rateLimit', 'loadBalancer']) {
      expect(input).not.toHaveProperty(key);
    }
    expect(forwardAuthAccess).toBeUndefined();
  });

  it('copies a host without custom Caddy JSON or client-certificate trust the user may not set, but with its exclusions', () => {
    const template = host({ mtls: { enabled: true, trusted_role_ids: [1] } });
    const saved = copyHostForm(template, { canSetCustomJson: false, canChooseTrust: false });
    expect(saved.name).toBe('App (copy)');
    expect(saved.customReverseProxyJson).toBe('');
    expect(saved.mtls.enabled).toBe(false);
    const input = buildPayload(saved, saved, template, true).host;
    expect(input).not.toHaveProperty('customReverseProxyJson', '{"headers":{}}');
    expect(input.waf).toMatchObject({ enabled: true, mode: 'On', excluded_rule_ids: [942430] });
    expect(input.locationRules).toEqual([{ path: '/api/*', upstreams: ['http://10.0.0.9:9000'], loadBalancer: null }]);
  });

  it('keeps geo blocking mode and settings together', () => {
    const stored = host({ geoblock: null });
    const saved = hostToForm(stored);
    const form = edited(saved, (f) => ({ ...f, geoblock: { ...f.geoblock, enabled: true, mode: 'override', blockCountries: ['RU'] } }));
    const input = buildPayload(form, saved, stored, false).host;
    expect(input.geoblockMode).toBe('override');
    expect(input.geoblock).toMatchObject({ enabled: true, block_countries: ['RU'], response_status: 403 });
  });

  it('reads a geo blocking mode stored without settings as merge, which is what Caddy does with it', () => {
    expect(hostToForm(host({ geoblock: null, geoblockMode: 'override' })).geoblock).toMatchObject({ enabled: false, mode: 'merge' });
    const withSettings = host({ geoblock: { enabled: false } as never, geoblockMode: 'override' });
    expect(hostToForm(withSettings).geoblock).toMatchObject({ enabled: false, mode: 'override' });
  });

  it('round-trips location rules, rate limits and error pages unchanged', () => {
    const stored = host();
    const saved = hostToForm(stored);
    const input = formToInput(saved, saved, stored);
    expect(input.rateLimit).toEqual(stored.rateLimit);
    expect(input.errorPages).toEqual([{ statuses: [502, 503], body: '<h1>Down</h1>' }]);
    expect(input.pathBlocks).toEqual([{ path: '/metrics', status: 404 }]);
    expect(input.redirects).toEqual(stored.redirects);
  });
});

describe('host editor change list', () => {
  it('lists each changed group once, in section order, and undoes it', () => {
    const stored = host();
    const saved = hostToForm(stored);
    const groups = changeGroups('edit');
    const form = edited(saved, (f) => ({
      ...f,
      hstsEnabled: false,
      domains: [...f.domains, 'new.example.com'],
      lb: { ...f.lb, policy: 'least_conn' },
    }));
    const changes = formChanges(saved, form, lookup, groups);
    expect(changes.map((change) => change.group.id)).toEqual(['domains', 'lb', 'hstsEnabled']);
    expect(changes[0].diff).toEqual([{ type: 'add', text: 'new.example.com' }]);
    expect(changes[1].diff).toEqual([
      { type: 'remove', text: 'Policy: Round robin' },
      { type: 'add', text: 'Policy: Least connections' },
    ]);
    expect(changes[2].diff).toEqual([
      { type: 'remove', text: 'On' },
      { type: 'add', text: 'Off' },
    ]);
    const undone = changes[1].group.restore(form, saved);
    expect(formChanges(saved, undone, lookup, groups).map((change) => change.group.id)).toEqual(['domains', 'hstsEnabled']);
  });

  it('shows a changed secret without its value', () => {
    const stored = host();
    const saved = hostToForm(stored);
    const withCookie = edited(saved, (f) => ({ ...f, lb: { ...f.lb, policy: 'cookie', cookieName: 'srv', cookieSecret: 'aaaa' } }));
    const changed = edited(withCookie, (f) => ({ ...f, lb: { ...f.lb, cookieSecret: 'bbbb' } }));
    const [change] = formChanges(withCookie, changed, lookup, changeGroups('edit'));
    expect(JSON.stringify(change.diff)).not.toContain('bbbb');
    expect(change.diff).toEqual([{ type: 'add', text: 'Load balancing changed' }]);
  });
});

describe('host editor checks', () => {
  const context = { nameSection: 'advanced' as const, dnsProviderConfigured: false, canChooseTrust: true };

  it('accepts a stored host as it is', () => {
    expect(validateForm(hostToForm(host()), context)).toEqual({});
  });

  it('points each problem at its field and section', () => {
    const form = edited(hostToForm(host()), (f) => ({
      ...f,
      name: '',
      domains: ['bad_domain!'],
      upstreams: [{ key: 'u', scheme: 'http://', address: '' }],
      rateLimit: { ...f.rateLimit, rules: [{ ...f.rateLimit.rules[0], windowValue: '2', windowUnit: 'h' }] },
      mtls: { ...f.mtls, enabled: true },
      customPreHandlersJson: '{"not": "an array"}',
    }));
    const errors = validateForm(form, context);
    expect(errors['f-name']).toMatchObject({ section: 'advanced' });
    expect(errors['f-domains'].message).toContain('bad_domain!');
    expect(errors['f-up-0']).toMatchObject({ section: 'routing' });
    expect(errors['f-rl-0-window']).toMatchObject({ section: 'security' });
    expect(errors['f-mtls']).toMatchObject({ section: 'access' });
    expect(errors['f-pre-handlers'].message).toBe('Enter a JSON array of handlers.');
  });

  it('asks for a DNS provider or a certificate for a wildcard domain', () => {
    const form = edited(hostToForm(host()), (f) => ({ ...f, domains: ['*.example.com'] }));
    expect(validateForm(form, context)['f-domains'].message).toContain('needs a DNS provider');
    expect(validateForm(form, { ...context, dnsProviderConfigured: true })['f-domains']).toBeUndefined();
    expect(validateForm({ ...form, certificateId: 4 }, context)['f-domains']).toBeUndefined();
  });

  it('refuses health checks that Caddy would not run', () => {
    const base = hostToForm(host());
    const noPath = edited(base, (f) => ({ ...f, lb: { ...f.lb, active: { ...f.lb.active, enabled: true, uri: '', port: '' } } }));
    expect(validateForm(noPath, context)['f-lb-active-uri'].message).toContain('without a path or a port');
    const portOnly = edited(noPath, (f) => ({ ...f, lb: { ...f.lb, active: { ...f.lb.active, port: '8081' } } }));
    expect(validateForm(portOnly, context)['f-lb-active-uri']).toBeUndefined();
    const noDuration = edited(base, (f) => ({ ...f, lb: { ...f.lb, passive: { ...f.lb.passive, enabled: true, failDuration: '' } } }));
    expect(validateForm(noDuration, context)['f-lb-passive-duration'].message).toContain('counts none');
    const withDuration = edited(noDuration, (f) => ({ ...f, lb: { ...f.lb, passive: { ...f.lb.passive, failDuration: '30s' } } }));
    expect(validateForm(withDuration, context)['f-lb-passive-duration']).toBeUndefined();
  });

  it('turns on passive health checks that count failures, and leaves checks that are on alone', () => {
    const off = hostToForm(host({ loadBalancer: null }));
    const on = withHealthChecksOn(off);
    expect(on.lb).toMatchObject({ enabled: true, passive: { enabled: true, failDuration: '30s' }, active: { enabled: false } });
    expect(validateForm(on, context)).toEqual({});
    const active = hostToForm(host());
    expect(withHealthChecksOn(active)).toBe(active);
  });

  it('checks domains like the server', () => {
    expect(isValidDomain('*.example.com')).toBe(true);
    expect(isValidDomain('a.*.example.com')).toBe(false);
    expect(isValidDomain('192.0.2.1')).toBe(true);
    expect(isValidDomain('-bad.example.com')).toBe(false);
    expect(normalizeDomainInput(' HTTPS://App.Example.com./path ')).toBe('app.example.com');
  });

  it('maps server messages to fields', () => {
    expect(fieldOfServerError('rateLimit.rules[2].events must be an integer from 1 to 1000', 'advanced')).toEqual({ id: 'f-rl-2-events', section: 'security' });
    expect(fieldOfServerError('forwardAuth.authUpstream must be a valid http(s) URL', 'advanced')).toEqual({ id: 'f-fa-upstream', section: 'access' });
    expect(fieldOfServerError('waf.request_body_in_memory_limit must not exceed waf.request_body_limit', 'advanced')).toEqual({ id: 'f-waf-memory', section: 'security' });
    expect(fieldOfServerError('Invalid domain "x". Wildcards are supported only as the left-most label, for example "*.example.com".', 'routing')).toEqual({ id: 'f-domains', section: 'routing' });
    expect(fieldOfServerError('Only administrators can set custom Caddy JSON on a proxy host', 'advanced')).toEqual({ id: 'f-reverse-proxy', section: 'advanced' });
    expect(fieldOfServerError('Name is required', 'routing')).toEqual({ id: 'f-name', section: 'routing' });
    expect(fieldOfServerError('Something unexpected happened', 'routing')).toBeNull();
  });
});
