/**
 * The host editor and the addresses that skip sign-in: a stored list
 * round-trips through the form without a change, an edit sends exactly the
 * parsed list, the checks point at the field, the change list reads and
 * undoes, and the section shows the field (for the sign-in providers, not
 * for client certificates) with the warning that fits how Caddy reads the
 * client address.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
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
import { AccessSection } from '@/src/components/proxy-hosts/editor/AccessSection';
import { EditorProvider, type EditorContextValue } from '@/src/components/proxy-hosts/editor/fields';
import {
  addressList,
  buildPayload,
  copyHostForm,
  hostToForm,
  newHostForm,
  payloadIsEmpty,
  type HostForm,
} from '@/src/components/proxy-hosts/editor/model';
import { changeGroups, formChanges, type ChangeLookup } from '@/src/components/proxy-hosts/editor/changes';
import { fieldOfServerError, validateForm } from '@/src/components/proxy-hosts/editor/validate';

const base: ProxyHost = {
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
  pathRewrites: [],
  errorPages: [],
  rateLimit: null,
  tags: [],
};

const authentik = (bypassSources: string[]): ProxyHost['authentik'] => ({
  enabled: true,
  outpostDomain: 'outpost.example.com',
  outpostUpstream: 'http://outpost:9000',
  authEndpoint: '/outpost.example.com/auth/caddy',
  copyHeaders: ['X-Authentik-Username'],
  trustedProxies: ['private_ranges'],
  setOutpostHostHeader: true,
  protectedPaths: null,
  excludedPaths: null,
  bypassSources,
});
const generic = (bypassSources: string[]): ProxyHost['forwardAuth'] => ({
  enabled: true,
  provider: 'authelia',
  authUpstream: 'http://authelia:9091',
  authEndpoint: '/api/authz/forward-auth',
  copyHeaders: ['Remote-User'],
  trustedProxies: ['private_ranges'],
  apiSplit: false,
  apiBypassHeaders: [],
  protectedPaths: null,
  excludedPaths: null,
  bypassSources,
});
const ingressi = (bypass_sources: string[]): ProxyHost['ingressiForwardAuth'] => ({ enabled: true, protected_paths: null, excluded_paths: null, bypass_sources });

type Provider = {
  name: string;
  signIn: 'authentik' | 'generic' | 'ingressi';
  host: (sources: string[]) => Partial<ProxyHost>;
  /** The form's field, the payload's key and field, the field's id. */
  form: (f: HostForm) => { bypassSources: string };
  patch: (f: HostForm, bypassSources: string) => HostForm;
  payload: (host: Record<string, any>) => unknown;
  id: string;
  line: string;
};

const PROVIDERS: Provider[] = [
  {
    name: 'Authentik',
    signIn: 'authentik',
    host: (sources) => ({ authentik: authentik(sources) }),
    form: (f) => f.authentik,
    patch: (f, bypassSources) => ({ ...f, authentik: { ...f.authentik, bypassSources } }),
    payload: (host) => host.authentik?.bypassSources,
    id: 'f-ak-sources',
    line: 'Skip sign-in from: ',
  },
  {
    name: 'Generic forward auth',
    signIn: 'generic',
    host: (sources) => ({ forwardAuth: generic(sources) }),
    form: (f) => f.forwardAuth,
    patch: (f, bypassSources) => ({ ...f, forwardAuth: { ...f.forwardAuth, bypassSources } }),
    payload: (host) => host.forwardAuth?.bypassSources,
    id: 'f-fa-sources',
    line: 'Skip sign-in from: ',
  },
  {
    name: 'Built-in sign-in',
    signIn: 'ingressi',
    host: (sources) => ({ ingressiForwardAuth: ingressi(sources) }),
    form: (f) => f.ingressi,
    patch: (f, bypassSources) => ({ ...f, ingressi: { ...f.ingressi, bypassSources } }),
    payload: (host) => host.ingressiForwardAuth?.bypass_sources,
    id: 'f-fi-sources',
    line: 'Skip sign-in from: ',
  },
];

const lookup: ChangeLookup = {
  certificate: String,
  accessList: String,
  user: String,
  group: String,
  role: String,
  clientCertificate: String,
  ca: String,
  globalWafMode: 'blocking',
};
const context = { nameSection: 'advanced' as const, dnsProviderConfigured: false, canChooseTrust: true };

function edited(form: HostForm, recipe: (form: HostForm) => HostForm): HostForm {
  return recipe(structuredClone(form));
}

describe('addressList', () => {
  it('splits on commas, spaces and new lines, without blanks or repeats', () => {
    expect(addressList('10.0.0.5, 192.168.1.0/24\n172.16.0.0/12  10.0.0.5,,')).toEqual(['10.0.0.5', '192.168.1.0/24', '172.16.0.0/12']);
    expect(addressList('')).toEqual([]);
    expect(addressList(' , \n ')).toEqual([]);
  });
});

describe.each(PROVIDERS)('$name: the form', (provider) => {
  it('shows the stored list, comma separated', () => {
    const form = hostToForm({ ...base, ...provider.host(['192.168.1.0/24', 'private_ranges']) });
    expect(provider.form(form).bypassSources).toBe('192.168.1.0/24, private_ranges');
    expect(provider.form(hostToForm({ ...base, ...provider.host([]) })).bypassSources).toBe('');
    expect(provider.form(newHostForm({ initialDomain: 'new.example.com', scopeTags: [] })).bypassSources).toBe('');
  });

  it('sends nothing when nothing changed', () => {
    const stored = { ...base, ...provider.host(['192.168.1.0/24', 'private_ranges']) };
    const saved = hostToForm(stored);
    expect(payloadIsEmpty(buildPayload(saved, saved, stored, false))).toBe(true);
  });

  it('sends the parsed list when it changes, and an empty one when it is cleared', () => {
    const stored = { ...base, ...provider.host(['192.168.1.0/24']) };
    const saved = hostToForm(stored);

    const changed = buildPayload(provider.patch(saved, '10.0.0.0/8 ,203.0.113.9\n192.168.1.0/24'), saved, stored, false);
    expect(provider.payload(changed.host)).toEqual(['10.0.0.0/8', '203.0.113.9', '192.168.1.0/24']);

    const cleared = buildPayload(provider.patch(saved, ''), saved, stored, false);
    expect(provider.payload(cleared.host)).toEqual([]);
  });

  it('sends the list of a new host that has one', () => {
    const saved = newHostForm({ initialDomain: 'new.example.com', scopeTags: [] });
    const form = provider.patch({ ...saved, name: 'New', signIn: provider.signIn }, '192.168.1.0/24');
    expect(provider.payload(buildPayload(form, saved, null, true).host)).toEqual(['192.168.1.0/24']);
  });

  it('is copied with the host', () => {
    const copy = copyHostForm({ ...base, ...provider.host(['192.168.1.0/24']) }, { canSetCustomJson: true, canChooseTrust: true });
    expect(provider.form(copy).bypassSources).toBe('192.168.1.0/24');
  });
});

describe.each(PROVIDERS)('$name: the checks', (provider) => {
  const selected = (sources: string) => provider.patch({ ...hostToForm({ ...base, ...provider.host([]) }), signIn: provider.signIn }, sources);

  it('accept addresses, networks and private_ranges', () => {
    expect(validateForm(selected('192.168.1.0/24, 10.0.0.5, private_ranges, 2001:db8::/32'), context)[provider.id]).toBeUndefined();
    expect(validateForm(selected(''), context)[provider.id]).toBeUndefined();
  });

  it.each([
    ['a name', 'office.example.com', /not an IP address/],
    ['a prefix that is too long', '10.0.0.0/33', /not an IP address/],
    ['a range that matches every address', '0.0.0.0/0', /matches every address/],
    ['a placeholder', '{http.request.host}', /not an IP address/],
  ])('refuse %s, at the field, in the access section', (_label, value, message) => {
    const error = validateForm(selected(`192.168.1.0/24, ${value}`), context)[provider.id];
    expect(error).toBeDefined();
    expect(error.section).toBe('access');
    expect(error.message).toMatch(message);
  });

  it('refuse more than 100 entries', () => {
    const many = Array.from({ length: 101 }, (_, index) => `10.${Math.floor(index / 250)}.${index % 250}.0/24`).join(', ');
    expect(validateForm(selected(many), context)[provider.id]?.message).toMatch(/At most 100/);
  });

  it('look at the provider that is selected only', () => {
    const other = edited(selected('nonsense'), (f) => ({ ...f, signIn: 'none' }));
    expect(validateForm(other, context)[provider.id]).toBeUndefined();
  });

  it('send the server\'s message to the same field', () => {
    const label = provider.signIn === 'authentik' ? 'authentik.bypassSources' : provider.signIn === 'generic' ? 'forwardAuth.bypassSources' : 'ingressiForwardAuth.bypass_sources';
    expect(fieldOfServerError(`${label}: "nope" is not an IP address, a CIDR range or private_ranges`, 'advanced')).toEqual({ id: provider.id, section: 'access' });
    expect(fieldOfServerError(`${label}[3] must be a string`, 'advanced')).toEqual({ id: provider.id, section: 'access' });
  });
});

describe.each(PROVIDERS)('$name: the change list', (provider) => {
  it('reads the new list and undoes it', () => {
    const stored = { ...base, ...provider.host(['192.168.1.0/24']) };
    const saved = hostToForm(stored);
    const form = provider.patch(saved, '192.168.1.0/24, 10.0.0.0/8');
    const groups = changeGroups('edit');
    const changes = formChanges(saved, form, lookup, groups);
    expect(changes.map((change) => change.group.id)).toEqual(['signIn']);
    expect(changes[0].diff).toEqual([
      { type: 'remove', text: `${provider.line}192.168.1.0/24` },
      { type: 'add', text: `${provider.line}192.168.1.0/24, 10.0.0.0/8` },
    ]);
    const undone = changes[0].group.restore(form, saved);
    expect(formChanges(saved, undone, lookup, groups)).toEqual([]);
    expect(provider.form(undone).bypassSources).toBe('192.168.1.0/24');
  });

  it('does not count a change of spelling as a change', () => {
    const stored = { ...base, ...provider.host(['192.168.1.0/24', '10.0.0.0/8']) };
    const saved = hostToForm(stored);
    const respelled = provider.patch(saved, '192.168.1.0/24 10.0.0.0/8,');
    expect(formChanges(saved, respelled, lookup, changeGroups('edit'))).toEqual([]);
  });
});

// ── what the section shows ──────────────────────────────────────────────

function data(host: ProxyHost, clientAddress: HostEditorData['clientAddress']): HostEditorData {
  return {
    mode: 'edit',
    host,
    template: null,
    initialDomain: null,
    forwardAuthAccess: { userIds: [], groupIds: [] },
    certificates: [],
    servedCertificate: null,
    clientAddress,
    accessLists: [],
    blockedSourcesActive: false,
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
    wafExclusions: [],
    wafRuleMessages: {},
    canReadWaf: false,
    rateLimitDefaults: null,
    geoblockGlobal: null,
    dnsProviderConfigured: false,
    dnsChoices: { providers: [], defaultProvider: null },
    canCreateCertificate: false,
    lastSaved: null,
    historyHref: null,
  } as unknown as HostEditorData;
}

function section(host: ProxyHost, clientAddress: HostEditorData['clientAddress'] = { proxiesTrusted: false, forwardedForForgeable: false }): string {
  const editorData = data(host, clientAddress);
  const form = hostToForm(host);
  const value: EditorContextValue = {
    form,
    saved: form,
    data: editorData,
    lookup,
    update: () => {},
    certificateSaved: () => {},
    errors: {},
    touch: () => {},
    wasOf: () => null,
  } as unknown as EditorContextValue;
  return renderToStaticMarkup(createElement(EditorProvider, { value, children: createElement(AccessSection) }));
}

const WARNING_PRIVATE = /Matches the address that connects to Caddy/;
const WARNING_FORGEABLE = /lets a visitor forge the address/;

describe.each(PROVIDERS)('$name: the Access section', (provider) => {
  const host = (sources: string[]) => ({ ...base, ...provider.host(sources) });

  it('has a field for the addresses, filled with the stored list', () => {
    const html = section(host(['192.168.1.0/24', '203.0.113.9']));
    expect(html).toContain(`id="${provider.id}"`);
    expect(html).toContain('Skip sign-in from, optional');
    expect(html).toContain('value="192.168.1.0/24, 203.0.113.9"');
  });

  it('says nothing more while the list is empty', () => {
    const html = section(host([]), { proxiesTrusted: false, forwardedForForgeable: true });
    expect(html).not.toMatch(WARNING_PRIVATE);
    expect(html).not.toMatch(WARNING_FORGEABLE);
  });

  it('warns about private networks when no proxy is trusted', () => {
    for (const sources of [['private_ranges'], ['192.168.1.0/24'], ['203.0.113.9', '10.0.0.5']]) {
      expect(section(host(sources))).toMatch(WARNING_PRIVATE);
    }
  });

  it('does not warn about public addresses alone', () => {
    const html = section(host(['203.0.113.0/24', '2001:db8::/32']));
    expect(html).not.toMatch(WARNING_PRIVATE);
    expect(html).not.toMatch(WARNING_FORGEABLE);
  });

  it('does not warn about private networks once proxies are trusted', () => {
    expect(section(host(['private_ranges']), { proxiesTrusted: true, forwardedForForgeable: false })).not.toMatch(WARNING_PRIVATE);
  });

  it('warns that X-Forwarded-For can be forged when it is read the loose way behind trusted proxies', () => {
    const html = section(host(['203.0.113.9']), { proxiesTrusted: true, forwardedForForgeable: true });
    expect(html).toMatch(WARNING_FORGEABLE);
    expect(html).not.toMatch(WARNING_PRIVATE);
  });
});

describe('client certificates', () => {
  it('have no field for addresses: they are not a sign-in', () => {
    const html = section({
      ...base,
      mtls: { enabled: true, trusted_client_cert_ids: [1], protected_paths: null, excluded_paths: null },
    });
    expect(html).toContain('id="f-mtls-paths-excluded"');
    expect(html).not.toContain('f-mtls-paths-sources');
    expect(html).not.toContain('Skip sign-in from');
  });
});
