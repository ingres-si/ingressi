/**
 * The host editor's form: one plain object holding every setting of a proxy
 * host as the editor shows it (strings for numbers, rows with stable keys),
 * built from a stored host (hostToForm) and turned back into the REST
 * API's host input (formToInput). Pure functions, shared by the editor, the
 * change list and the tests.
 *
 * The saved form is the starting point: what the host is now (edit), or what
 * a new host starts from. An update sends only the top-level fields whose
 * input differs from the saved form's, so untouched settings are never
 * rewritten.
 */
import type {
  ErrorPageRule,
  LoadBalancerConfig,
  LoadBalancerInput,
  LoadBalancingPolicy,
  LocationRuleInput,
  PathBlockRule,
  PathBlockStatusCode,
  ProxyHost,
  ProxyHostInput,
  RedirectRule,
  WafHostConfig,
} from "@/lib/models/proxy-hosts";
import type { AuthentikSettings, ForwardAuthSettings, GeoBlockSettings } from "@/lib/settings";
import type { RateLimitKey } from "@/lib/rate-limit-rules";
import { hostModeOf, withHostMode, type WafHostMode } from "@/lib/waf-host-mode";

// ── Constants ─────────────────────────────────────────────────────────

export const SCHEMES = ["http://", "https://"] as const;
export type Scheme = (typeof SCHEMES)[number];

export const LB_POLICIES: { value: LoadBalancingPolicy; label: string; description: string }[] = [
  { value: "random", label: "Random", description: "Picks any healthy upstream at random." },
  { value: "round_robin", label: "Round robin", description: "Sends each request to the next upstream in turn." },
  {
    value: "least_conn",
    label: "Least connections",
    description: "Sends each request to the upstream with the fewest open requests. Good when some requests take much longer than others.",
  },
  { value: "ip_hash", label: "IP hash", description: "The same client address always reaches the same upstream." },
  { value: "first", label: "First available", description: "Uses the first healthy upstream in the list; the others are standby." },
  { value: "header", label: "Header hash", description: "Hashes a request header, so equal values reach the same upstream." },
  { value: "cookie", label: "Cookie", description: "Sticky sessions: a cookie keeps a browser on one upstream." },
  { value: "uri_hash", label: "URI hash", description: "The same path always reaches the same upstream, which helps caches." },
];

/** Mirrors PATH_BLOCK_STATUS_CODES in src/lib/models/proxy-hosts.ts (a server module). */
export const PATH_BLOCK_STATUSES: readonly PathBlockStatusCode[] = [400, 401, 403, 404, 410, 418, 451, 500, 502, 503];
export const REDIRECT_STATUSES = [301, 302, 307, 308] as const;
export type RedirectStatus = (typeof REDIRECT_STATUSES)[number];

export const AUTHENTIK_DEFAULT_HEADERS = [
  "X-Authentik-Username",
  "X-Authentik-Groups",
  "X-Authentik-Entitlements",
  "X-Authentik-Email",
  "X-Authentik-Name",
  "X-Authentik-Uid",
  "X-Authentik-Jwt",
  "X-Authentik-Meta-Jwks",
  "X-Authentik-Meta-Outpost",
  "X-Authentik-Meta-Provider",
  "X-Authentik-Meta-App",
  "X-Authentik-Meta-Version",
];
export const AUTHELIA_ENDPOINT = "/api/authz/forward-auth";
export const AUTHELIA_HEADERS = ["Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name", "Remote-IP"];
export const DEFAULT_TRUSTED_PROXIES = ["private_ranges"];

const BYTES_PER_MIB = 1_048_576;

// ── Types ─────────────────────────────────────────────────────────────

export type UpstreamRow = { key: string; scheme: Scheme; address: string };

export type LbForm = {
  enabled: boolean;
  policy: LoadBalancingPolicy;
  headerField: string;
  cookieName: string;
  cookieSecret: string;
  tryDuration: string;
  tryInterval: string;
  retries: string;
  active: { enabled: boolean; uri: string; port: string; interval: string; timeout: string; status: string; body: string };
  passive: { enabled: boolean; failDuration: string; maxFails: string; unhealthyStatus: string; unhealthyLatency: string };
};

export type LocationRuleRow = { key: string; path: string; upstreams: UpstreamRow[]; lb: LbForm };

export type WafForm = {
  mode: WafHostMode;
  rules: "merge" | "override";
  loadCrs: boolean;
  bodyLimit: string;
  bodyMemory: string;
  bodyAction: "inherit" | "Reject" | "ProcessPartial";
};

export type RateLimitRuleRow = {
  key: string;
  path: string;
  methods: string[];
  by: RateLimitKey;
  header: string;
  events: string;
  windowValue: string;
  windowUnit: "s" | "m" | "h";
};

export type RateLimitForm = { enabled: boolean; mode: "merge" | "override"; rules: RateLimitRuleRow[] };

export type HeaderRow = { key: string; name: string; value: string };

export type GeoForm = {
  enabled: boolean;
  mode: "merge" | "override";
  blockCountries: string[];
  blockContinents: string[];
  blockAsns: string[];
  blockCidrs: string[];
  blockIps: string[];
  allowCountries: string[];
  allowContinents: string[];
  allowAsns: string[];
  allowCidrs: string[];
  allowIps: string[];
  trustedProxies: string[];
  failClosed: boolean;
  responseStatus: string;
  responseBody: string;
  redirectUrl: string;
  headers: HeaderRow[];
};

export type SignIn = "none" | "ingressi" | "authentik" | "generic";

export type AuthentikForm = {
  outpostDomain: string;
  outpostUpstream: string;
  authEndpoint: string;
  copyHeaders: string;
  trustedProxies: string;
  protectedPaths: string;
  excludedPaths: string;
  /** Client addresses that skip sign-in. */
  bypassSources: string;
  setHostHeader: boolean;
};

export type GenericAuthForm = {
  provider: "authelia" | "custom";
  authUpstream: string;
  authEndpoint: string;
  copyHeaders: string;
  trustedProxies: string;
  apiSplit: boolean;
  apiBypassHeaders: string;
  protectedPaths: string;
  excludedPaths: string;
  bypassSources: string;
};

export type IngressiAuthForm = { protectedPaths: string; excludedPaths: string; bypassSources: string; userIds: number[]; groupIds: number[] };

export type MtlsForm = {
  enabled: boolean;
  certIds: number[];
  roleIds: number[];
  protectedPaths: string;
  excludedPaths: string;
  /** CA certificates trusted by the old model; kept as they are. */
  legacyCaIds: number[];
};

export type PathBlockRow = { key: string; path: string; status: PathBlockStatusCode; body: string };
export type PathAllowRow = { key: string; path: string };
export type RedirectRow = { key: string; from: string; to: string; status: RedirectStatus };
export type PathRewriteRow = { key: string; from: string; to: string };
export type ErrorPageRow = { key: string; statuses: string; body: string; contentType: string };

export type DnsForm = { enabled: boolean; resolvers: string; fallbacks: string; timeout: string };
export type UpstreamDnsForm = { mode: "inherit" | "enabled" | "disabled"; family: "inherit" | "ipv6" | "ipv4" | "both" };

export type HostForm = {
  name: string;
  tags: string[];
  enabled: boolean;
  domains: string[];
  upstreams: UpstreamRow[];
  lb: LbForm;
  allowWebsocket: boolean;
  preserveHostHeader: boolean;
  skipHttpsHostnameValidation: boolean;
  locationRules: LocationRuleRow[];
  waf: WafForm;
  wafDirectives: string;
  wafExcluded: number[];
  rateLimit: RateLimitForm;
  accessListId: number | null;
  geoblock: GeoForm;
  signIn: SignIn;
  authentik: AuthentikForm;
  forwardAuth: GenericAuthForm;
  ingressi: IngressiAuthForm;
  mtls: MtlsForm;
  pathBlocks: PathBlockRow[];
  pathAllows: PathAllowRow[];
  certificateId: number | null;
  sslForced: boolean;
  hstsEnabled: boolean;
  hstsSubdomains: boolean;
  redirects: RedirectRow[];
  rewritePrefix: string;
  pathRewrites: PathRewriteRow[];
  errorPages: ErrorPageRow[];
  dnsResolver: DnsForm;
  upstreamDns: UpstreamDnsForm;
  customPreHandlersJson: string;
  customReverseProxyJson: string;
};

/** What a form is built from besides the host. */
export type FormContext = {
  authentikDefaults?: AuthentikSettings | null;
  forwardAuthDefaults?: ForwardAuthSettings | null;
  forwardAuthAccess?: { userIds: number[]; groupIds: number[] } | null;
  /** The global WAF loads the OWASP Core Rule Set (what a merging host inherits). */
  globalCrs?: boolean;
};

// ── Small helpers ─────────────────────────────────────────────────────

let keySeed = 0;
/** A key for a new list row (stable while the row exists). */
export function rowKey(prefix = "row"): string {
  keySeed += 1;
  return `${prefix}-${keySeed}`;
}

/** Canonical JSON (sorted keys, no undefined), to compare inputs. */
export function canonical(value: unknown): string {
  const sort = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map((entry) => (entry === undefined ? null : sort(entry)));
    if (item && typeof item === "object") {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(item as Record<string, unknown>).sort()) {
        const entry = (item as Record<string, unknown>)[key];
        if (entry !== undefined) out[key] = sort(entry);
      }
      return out;
    }
    return item;
  };
  return JSON.stringify(sort(value ?? null)) ?? "null";
}

/** Comma, newline or space separated values, trimmed, without blanks or repeats. */
export function splitList(text: string, separators: RegExp = /[\n,]/): string[] {
  return [...new Set(text.split(separators).map((part) => part.trim()).filter(Boolean))];
}

const text = (value: string): string | null => (value.trim() ? value.trim() : null);

function integer(value: string): number | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
}

const numText = (value: number | null | undefined): string => (typeof value === "number" ? String(value) : "");

export function parseUpstream(upstream: string): { scheme: Scheme; address: string } {
  if (upstream.startsWith("https://")) return { scheme: "https://", address: upstream.slice(8) };
  if (upstream.startsWith("http://")) return { scheme: "http://", address: upstream.slice(7) };
  return { scheme: "http://", address: upstream };
}

export function upstreamRows(upstreams: readonly string[]): UpstreamRow[] {
  return upstreams.map((upstream) => ({ key: rowKey("up"), ...parseUpstream(upstream) }));
}

export function serializeUpstreams(rows: readonly UpstreamRow[]): string[] {
  return [...new Set(rows.filter((row) => row.address.trim()).map((row) => `${row.scheme}${row.address.trim()}`))];
}

export function statusList(value: string): number[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((part) => parseInt(part.trim(), 10))
        .filter((code) => Number.isInteger(code))
    ),
  ];
}

export function mibText(bytes: number | undefined): string {
  if (typeof bytes !== "number" || bytes <= 0) return "";
  const mib = bytes / BYTES_PER_MIB;
  return Number.isInteger(mib) ? String(mib) : String(Math.round(mib * 10) / 10);
}

// ── Load balancing ────────────────────────────────────────────────────

/**
 * How long passive health checks remember a failure when the field is left
 * empty: Caddy counts no failures without one.
 */
export const DEFAULT_PASSIVE_FAIL_DURATION = "30s";

/**
 * The form with health checks on, for "Turn on health checks" on the host's
 * page: custom load balancing (where they live) and, unless a check is on
 * already, passive checks with a fail duration, so Caddy counts failures.
 */
export function withHealthChecksOn(form: HostForm): HostForm {
  const lb = form.lb;
  const checking = lb.active.enabled || lb.passive.enabled;
  if (lb.enabled && checking) return form;
  return {
    ...form,
    lb: {
      ...lb,
      enabled: true,
      passive: checking ? lb.passive : { ...lb.passive, enabled: true, failDuration: lb.passive.failDuration || DEFAULT_PASSIVE_FAIL_DURATION },
    },
  };
}

export function emptyLb(enabled = false): LbForm {
  return {
    enabled,
    policy: "random",
    headerField: "",
    cookieName: "",
    cookieSecret: "",
    tryDuration: "",
    tryInterval: "",
    retries: "",
    active: { enabled: false, uri: "", port: "", interval: "", timeout: "", status: "", body: "" },
    passive: { enabled: false, failDuration: "", maxFails: "", unhealthyStatus: "", unhealthyLatency: "" },
  };
}

export function lbToForm(config: LoadBalancerConfig | null | undefined): LbForm {
  if (!config) return emptyLb();
  const active = config.activeHealthCheck;
  const passive = config.passiveHealthCheck;
  return {
    enabled: Boolean(config.enabled),
    policy: config.policy ?? "random",
    headerField: config.policyHeaderField ?? "",
    cookieName: config.policyCookieName ?? "",
    cookieSecret: config.policyCookieSecret ?? "",
    tryDuration: config.tryDuration ?? "",
    tryInterval: config.tryInterval ?? "",
    retries: numText(config.retries),
    active: {
      enabled: Boolean(active?.enabled),
      uri: active?.uri ?? "",
      port: numText(active?.port),
      interval: active?.interval ?? "",
      timeout: active?.timeout ?? "",
      status: numText(active?.status),
      body: active?.body ?? "",
    },
    passive: {
      enabled: Boolean(passive?.enabled),
      failDuration: passive?.failDuration ?? "",
      maxFails: numText(passive?.maxFails),
      unhealthyStatus: passive?.unhealthyStatus?.join(", ") ?? "",
      unhealthyLatency: passive?.unhealthyLatency ?? "",
    },
  };
}

function hasActiveFields(active: LbForm["active"]): boolean {
  return Boolean(active.uri || active.port || active.interval || active.timeout || active.status || active.body);
}

function hasPassiveFields(passive: LbForm["passive"]): boolean {
  return Boolean(passive.failDuration || passive.maxFails || passive.unhealthyStatus || passive.unhealthyLatency);
}

export function lbToInput(lb: LbForm): LoadBalancerInput {
  const unhealthy = statusList(lb.passive.unhealthyStatus).filter((code) => code >= 100);
  return {
    enabled: lb.enabled,
    policy: lb.policy,
    policyHeaderField: text(lb.headerField),
    policyCookieName: text(lb.cookieName),
    policyCookieSecret: text(lb.cookieSecret),
    tryDuration: text(lb.tryDuration),
    tryInterval: text(lb.tryInterval),
    retries: integer(lb.retries),
    activeHealthCheck:
      lb.active.enabled || hasActiveFields(lb.active)
        ? {
            enabled: lb.active.enabled,
            uri: text(lb.active.uri),
            port: integer(lb.active.port),
            interval: text(lb.active.interval),
            timeout: text(lb.active.timeout),
            status: integer(lb.active.status),
            body: text(lb.active.body),
          }
        : null,
    passiveHealthCheck:
      lb.passive.enabled || hasPassiveFields(lb.passive)
        ? {
            enabled: lb.passive.enabled,
            failDuration: text(lb.passive.failDuration),
            maxFails: integer(lb.passive.maxFails),
            unhealthyStatus: unhealthy.length > 0 ? unhealthy : null,
            unhealthyLatency: text(lb.passive.unhealthyLatency),
          }
        : null,
  };
}

/** A location rule's load balancer as the stored config shape (LocationRuleInput takes LoadBalancerConfig-like objects). */
function locationLb(lb: LbForm): LoadBalancerInput | null {
  return lb.enabled ? lbToInput(lb) : null;
}

// ── Rate limiting ─────────────────────────────────────────────────────

export function rateLimitRow(rule?: { path: string; methods: string[]; key: RateLimitKey; header?: string; events: number; window: string }): RateLimitRuleRow {
  const match = rule ? /^(\d+)(s|m|h)$/.exec(rule.window) : null;
  return {
    key: rowKey("rl"),
    path: rule && rule.path !== "*" ? rule.path : "",
    methods: rule ? [...rule.methods] : [],
    by: rule?.key ?? "client_ip",
    header: rule?.header ?? "",
    events: rule ? String(rule.events) : "60",
    windowValue: match?.[1] ?? "1",
    windowUnit: (match?.[2] as RateLimitRuleRow["windowUnit"] | undefined) ?? "m",
  };
}

export function rateLimitRules(rows: readonly RateLimitRuleRow[]) {
  return rows.map((row) => ({
    path: row.path.trim() || "*",
    methods: row.methods,
    key: row.by,
    ...(row.by === "header" ? { header: row.header.trim() } : {}),
    events: Number(row.events),
    window: `${row.windowValue.trim()}${row.windowUnit}`,
  }));
}

// ── Geo blocking ──────────────────────────────────────────────────────

export function geoToForm(settings: GeoBlockSettings | null | undefined, mode: "merge" | "override" = "merge"): GeoForm {
  return {
    enabled: Boolean(settings?.enabled),
    mode,
    blockCountries: [...(settings?.block_countries ?? [])],
    blockContinents: [...(settings?.block_continents ?? [])],
    blockAsns: (settings?.block_asns ?? []).map(String),
    blockCidrs: [...(settings?.block_cidrs ?? [])],
    blockIps: [...(settings?.block_ips ?? [])],
    allowCountries: [...(settings?.allow_countries ?? [])],
    allowContinents: [...(settings?.allow_continents ?? [])],
    allowAsns: (settings?.allow_asns ?? []).map(String),
    allowCidrs: [...(settings?.allow_cidrs ?? [])],
    allowIps: [...(settings?.allow_ips ?? [])],
    trustedProxies: [...(settings?.trusted_proxies ?? [])],
    failClosed: Boolean(settings?.fail_closed),
    responseStatus: String(settings?.response_status ?? 403),
    responseBody: settings?.response_body ?? "Forbidden",
    redirectUrl: settings?.redirect_url ?? "",
    headers: Object.entries(settings?.response_headers ?? {}).map(([name, value]) => ({ key: rowKey("gh"), name, value })),
  };
}

function geoHasRules(geo: GeoForm): boolean {
  return [
    geo.blockCountries,
    geo.blockContinents,
    geo.blockAsns,
    geo.blockCidrs,
    geo.blockIps,
    geo.allowCountries,
    geo.allowContinents,
    geo.allowAsns,
    geo.allowCidrs,
    geo.allowIps,
  ].some((list) => list.length > 0);
}

export function geoToSettings(geo: GeoForm): GeoBlockSettings {
  const asns = (list: string[]) => list.map((asn) => parseInt(asn, 10)).filter((asn) => Number.isInteger(asn));
  const status = integer(geo.responseStatus);
  const headers: Record<string, string> = {};
  for (const row of geo.headers) {
    const name = row.name.trim();
    if (name) headers[name] = row.value.trim();
  }
  return {
    enabled: geo.enabled,
    block_countries: geo.blockCountries,
    block_continents: geo.blockContinents,
    block_asns: asns(geo.blockAsns),
    block_cidrs: geo.blockCidrs,
    block_ips: geo.blockIps,
    allow_countries: geo.allowCountries,
    allow_continents: geo.allowContinents,
    allow_asns: asns(geo.allowAsns),
    allow_cidrs: geo.allowCidrs,
    allow_ips: geo.allowIps,
    trusted_proxies: geo.trustedProxies,
    fail_closed: geo.failClosed,
    response_status: status !== null && status >= 100 && status <= 599 ? status : 403,
    response_body: geo.responseBody.trim() || "Forbidden",
    response_headers: headers,
    redirect_url: geo.redirectUrl.trim(),
  };
}

// ── Building a form ───────────────────────────────────────────────────

function authentikForm(host: ProxyHost | null, defaults: AuthentikSettings | null | undefined): AuthentikForm {
  const own = host?.authentik ?? null;
  return {
    outpostDomain: own?.outpostDomain ?? defaults?.outpostDomain ?? "",
    outpostUpstream: own?.outpostUpstream ?? defaults?.outpostUpstream ?? "",
    authEndpoint: own?.authEndpoint ?? defaults?.authEndpoint ?? "",
    copyHeaders: (own && own.copyHeaders.length > 0 ? own.copyHeaders : AUTHENTIK_DEFAULT_HEADERS).join(", "),
    trustedProxies: (own && own.trustedProxies.length > 0 ? own.trustedProxies : DEFAULT_TRUSTED_PROXIES).join(", "),
    protectedPaths: own?.protectedPaths?.join(", ") ?? "",
    excludedPaths: own?.excludedPaths?.join(", ") ?? "",
    bypassSources: own?.bypassSources?.join(", ") ?? "",
    setHostHeader: own?.setOutpostHostHeader ?? true,
  };
}

function genericForm(host: ProxyHost | null, defaults: ForwardAuthSettings | null | undefined): GenericAuthForm {
  const own = host?.forwardAuth ?? null;
  const provider = own?.provider ?? (defaults?.provider === "custom" ? "custom" : "authelia");
  return {
    provider,
    authUpstream: own?.authUpstream ?? defaults?.authUpstream ?? "",
    authEndpoint: own?.authEndpoint ?? defaults?.authEndpoint ?? (provider === "authelia" ? AUTHELIA_ENDPOINT : ""),
    copyHeaders: (own && own.copyHeaders.length > 0 ? own.copyHeaders : provider === "authelia" ? AUTHELIA_HEADERS : []).join(", "),
    trustedProxies: (own && own.trustedProxies.length > 0 ? own.trustedProxies : DEFAULT_TRUSTED_PROXIES).join(", "),
    apiSplit: own?.apiSplit ?? false,
    apiBypassHeaders: own?.apiBypassHeaders?.join(", ") ?? "",
    protectedPaths: own?.protectedPaths?.join(", ") ?? "",
    excludedPaths: own?.excludedPaths?.join(", ") ?? "",
    bypassSources: own?.bypassSources?.join(", ") ?? "",
  };
}

function signInOf(host: ProxyHost | null): SignIn {
  if (host?.authentik?.enabled) return "authentik";
  if (host?.forwardAuth?.enabled) return "generic";
  if (host?.ingressiForwardAuth?.enabled) return "ingressi";
  return "none";
}

function wafForm(waf: WafHostConfig | null | undefined, globalCrs: boolean | undefined): WafForm {
  const rules = waf?.waf_mode === "override" ? "override" : "merge";
  return {
    mode: hostModeOf(waf),
    rules,
    loadCrs: waf?.load_owasp_crs ?? (rules === "override" ? false : globalCrs ?? true),
    bodyLimit: mibText(waf?.request_body_limit),
    bodyMemory: mibText(waf?.request_body_in_memory_limit),
    bodyAction: waf?.request_body_limit_action ?? "inherit",
  };
}

/** The form of a stored host (edit, or a copy's starting point). */
export function hostToForm(host: ProxyHost, context: FormContext = {}): HostForm {
  const grants = context.forwardAuthAccess ?? { userIds: [], groupIds: [] };
  const mtls = host.mtls?.enabled ? host.mtls : null;
  return {
    name: host.name,
    tags: [...host.tags],
    enabled: host.enabled,
    domains: [...host.domains],
    upstreams: host.upstreams.length > 0 ? upstreamRows(host.upstreams) : [{ key: rowKey("up"), scheme: "http://", address: "" }],
    lb: lbToForm(host.loadBalancer),
    allowWebsocket: host.allowWebsocket,
    preserveHostHeader: host.preserveHostHeader,
    skipHttpsHostnameValidation: host.skipHttpsHostnameValidation,
    locationRules: host.locationRules.map((rule) => ({
      key: rowKey("loc"),
      path: rule.path,
      upstreams: rule.upstreams.length > 0 ? upstreamRows(rule.upstreams) : [{ key: rowKey("up"), scheme: "http://", address: "" }],
      lb: rule.loadBalancer?.enabled ? lbToForm(rule.loadBalancer) : emptyLb(),
    })),
    waf: wafForm(host.waf, context.globalCrs),
    wafDirectives: host.waf?.custom_directives ?? "",
    wafExcluded: [...(host.waf?.excluded_rule_ids ?? [])].sort((a, b) => a - b),
    rateLimit: host.rateLimit
      ? { enabled: host.rateLimit.enabled, mode: host.rateLimit.mode, rules: host.rateLimit.rules.map(rateLimitRow) }
      : { enabled: false, mode: "merge", rules: [] },
    accessListId: host.accessListId,
    // Override only means something next to the host's own config; without one
    // (the API can store a mode alone) the global rules apply, as when merging.
    geoblock: geoToForm(host.geoblock, host.geoblock ? host.geoblockMode : "merge"),
    signIn: signInOf(host),
    authentik: authentikForm(host, context.authentikDefaults),
    forwardAuth: genericForm(host, context.forwardAuthDefaults),
    ingressi: {
      protectedPaths: host.ingressiForwardAuth?.protected_paths?.join(", ") ?? "",
      excludedPaths: host.ingressiForwardAuth?.excluded_paths?.join(", ") ?? "",
      bypassSources: host.ingressiForwardAuth?.bypass_sources?.join(", ") ?? "",
      userIds: [...grants.userIds].sort((a, b) => a - b),
      groupIds: [...grants.groupIds].sort((a, b) => a - b),
    },
    mtls: {
      enabled: Boolean(mtls),
      certIds: [...(mtls?.trusted_client_cert_ids ?? [])],
      roleIds: [...(mtls?.trusted_role_ids ?? [])],
      protectedPaths: mtls?.protected_paths?.join(", ") ?? "",
      excludedPaths: mtls?.excluded_paths?.join(", ") ?? "",
      legacyCaIds: [...(mtls?.ca_certificate_ids ?? [])],
    },
    pathBlocks: host.pathBlocks.map((rule) => ({ key: rowKey("pb"), path: rule.path, status: rule.status, body: rule.body ?? "" })),
    pathAllows: host.pathAllows.map((rule) => ({ key: rowKey("pa"), path: rule.path })),
    certificateId: host.certificateId,
    sslForced: host.sslForced,
    hstsEnabled: host.hstsEnabled,
    hstsSubdomains: host.hstsSubdomains,
    redirects: host.redirects.map((rule) => ({ key: rowKey("rd"), from: rule.from, to: rule.to, status: rule.status })),
    rewritePrefix: host.rewrite?.path_prefix ?? "",
    pathRewrites: host.pathRewrites.map((rule) => ({ key: rowKey("rw"), from: rule.from, to: rule.to })),
    errorPages: host.errorPages.map((rule) => ({
      key: rowKey("ep"),
      statuses: rule.statuses.join(", "),
      body: rule.body,
      contentType: rule.contentType ?? "",
    })),
    dnsResolver: {
      enabled: Boolean(host.dnsResolver?.enabled),
      resolvers: host.dnsResolver?.resolvers?.join("\n") ?? "",
      fallbacks: host.dnsResolver?.fallbacks?.join("\n") ?? "",
      timeout: host.dnsResolver?.timeout ?? "",
    },
    upstreamDns: {
      mode: host.upstreamDnsResolution?.enabled === true ? "enabled" : host.upstreamDnsResolution?.enabled === false ? "disabled" : "inherit",
      family: host.upstreamDnsResolution?.family ?? "inherit",
    },
    customPreHandlersJson: host.customPreHandlersJson ?? "",
    customReverseProxyJson: host.customReverseProxyJson ?? "",
  };
}

/** The form of a new host: the defaults the product has always used for hosts made in the dashboard. */
export function newHostForm(
  options: { initialDomain?: string | null; scopeTags?: readonly string[] } = {},
  context: FormContext = {}
): HostForm {
  return {
    name: "",
    tags: options.scopeTags && options.scopeTags.length > 0 ? [options.scopeTags[0]] : [],
    enabled: true,
    domains: options.initialDomain ? [options.initialDomain] : [],
    upstreams: [{ key: rowKey("up"), scheme: "http://", address: "" }],
    lb: emptyLb(),
    allowWebsocket: true,
    preserveHostHeader: true,
    skipHttpsHostnameValidation: false,
    locationRules: [],
    waf: wafForm(null, context.globalCrs),
    wafDirectives: "",
    wafExcluded: [],
    rateLimit: { enabled: false, mode: "merge", rules: [] },
    accessListId: null,
    geoblock: geoToForm(null),
    signIn: "none",
    authentik: authentikForm(null, context.authentikDefaults),
    forwardAuth: genericForm(null, context.forwardAuthDefaults),
    ingressi: { protectedPaths: "", excludedPaths: "", bypassSources: "", userIds: [], groupIds: [] },
    mtls: { enabled: false, certIds: [], roleIds: [], protectedPaths: "", excludedPaths: "", legacyCaIds: [] },
    pathBlocks: [],
    pathAllows: [],
    certificateId: null,
    sslForced: true,
    hstsEnabled: true,
    hstsSubdomains: true,
    redirects: [],
    rewritePrefix: "",
    pathRewrites: [],
    errorPages: [],
    dnsResolver: { enabled: false, resolvers: "", fallbacks: "", timeout: "" },
    upstreamDns: { mode: "inherit", family: "inherit" },
    customPreHandlersJson: "",
    customReverseProxyJson: "",
  };
}

/**
 * The starting form of a copy of `template`: everything but the name (which
 * gets " (copy)"); custom Caddy JSON and client certificate trust only when
 * the user may set them.
 */
export function copyHostForm(
  template: ProxyHost,
  options: { canSetCustomJson: boolean; canChooseTrust: boolean },
  context: FormContext = {}
): HostForm {
  const form = hostToForm(template, { ...context, forwardAuthAccess: null });
  form.name = `${template.name} (copy)`;
  if (!options.canSetCustomJson) {
    form.customPreHandlersJson = "";
    form.customReverseProxyJson = "";
  }
  if (!options.canChooseTrust) {
    form.mtls = { enabled: false, certIds: [], roleIds: [], protectedPaths: "", excludedPaths: "", legacyCaIds: [] };
  }
  return form;
}

// ── Building the input ────────────────────────────────────────────────

const pathList = (value: string): string[] | null => {
  const list = splitList(value);
  return list.length > 0 ? list : null;
};

/** Addresses may be separated by commas, spaces or new lines. */
const ADDRESS_SEPARATORS = /[\s,]+/;
export const addressList = (value: string): string[] => splitList(value, ADDRESS_SEPARATORS);

function authentikInput(form: HostForm, base: ProxyHost | null) {
  const selected = form.signIn === "authentik";
  if (!selected && !base?.authentik) return undefined;
  const a = form.authentik;
  return {
    enabled: selected,
    outpostDomain: text(a.outpostDomain),
    outpostUpstream: text(a.outpostUpstream),
    authEndpoint: text(a.authEndpoint),
    copyHeaders: splitList(a.copyHeaders),
    trustedProxies: splitList(a.trustedProxies),
    setOutpostHostHeader: a.setHostHeader,
    protectedPaths: pathList(a.protectedPaths),
    excludedPaths: pathList(a.excludedPaths),
    bypassSources: addressList(a.bypassSources),
  };
}

function genericInput(form: HostForm, base: ProxyHost | null) {
  const selected = form.signIn === "generic";
  if (!selected && !base?.forwardAuth) return undefined;
  const f = form.forwardAuth;
  return {
    enabled: selected,
    provider: f.provider,
    authUpstream: text(f.authUpstream),
    authEndpoint: text(f.authEndpoint),
    copyHeaders: splitList(f.copyHeaders),
    trustedProxies: splitList(f.trustedProxies),
    apiSplit: f.apiSplit,
    apiBypassHeaders: splitList(f.apiBypassHeaders),
    protectedPaths: pathList(f.protectedPaths),
    excludedPaths: pathList(f.excludedPaths),
    bypassSources: addressList(f.bypassSources),
  };
}

function ingressiInput(form: HostForm, base: ProxyHost | null) {
  const selected = form.signIn === "ingressi";
  if (!selected && !base?.ingressiForwardAuth) return undefined;
  return selected
    ? {
        enabled: true,
        protected_paths: pathList(form.ingressi.protectedPaths),
        excluded_paths: pathList(form.ingressi.excludedPaths),
        bypass_sources: addressList(form.ingressi.bypassSources),
      }
    : { enabled: false };
}

function mibBytes(value: string): number | undefined {
  const mib = Number(value.trim());
  return value.trim() && Number.isFinite(mib) ? Math.round(mib * BYTES_PER_MIB) : undefined;
}

/**
 * The WAF settings: the stored ones with what the user changed applied, so a
 * setting the user did not touch keeps its stored value (an unset value keeps
 * inheriting the global one). Undefined when there is nothing to send.
 */
function wafInput(form: HostForm, saved: HostForm, baseWaf: WafHostConfig | null | undefined, creating: boolean): WafHostConfig | undefined {
  const changed = <K extends keyof WafForm>(key: K) => form.waf[key] !== saved.waf[key];
  const directivesChanged = form.wafDirectives !== saved.wafDirectives;
  const excludedChanged = canonical(form.wafExcluded) !== canonical(saved.wafExcluded);
  const anyChanged =
    (Object.keys(form.waf) as (keyof WafForm)[]).some((key) => changed(key)) || directivesChanged || excludedChanged;
  if (!baseWaf && !anyChanged) return undefined;

  let next: WafHostConfig = { ...(baseWaf ?? {}) };
  if (changed("mode")) next = withHostMode(next, form.waf.mode);
  if (changed("rules")) next.waf_mode = form.waf.rules;
  // A host that overrides the global settings inherits nothing: what the form
  // shows is what it gets. A merging host inherits the global value until changed.
  if (changed("loadCrs") || form.waf.rules === "override") next.load_owasp_crs = form.waf.loadCrs;
  const setBytes = (key: "request_body_limit" | "request_body_in_memory_limit", value: string) => {
    const bytes = mibBytes(value);
    if (bytes === undefined) delete next[key];
    else next[key] = bytes;
  };
  if (changed("bodyLimit")) setBytes("request_body_limit", form.waf.bodyLimit);
  if (changed("bodyMemory")) setBytes("request_body_in_memory_limit", form.waf.bodyMemory);
  if (changed("bodyAction")) {
    if (form.waf.bodyAction === "inherit") delete next.request_body_limit_action;
    else next.request_body_limit_action = form.waf.bodyAction;
  }
  if (directivesChanged) next.custom_directives = form.wafDirectives.trim();
  // The list replaces the host's whole-host exclusions; leaving it out keeps
  // them. A new host gets the list it starts with (a copy's exclusions).
  if (excludedChanged || (creating && form.wafExcluded.length > 0)) next.excluded_rule_ids = [...form.wafExcluded];
  else delete next.excluded_rule_ids;
  if (!next.waf_mode) next.waf_mode = "merge";
  return next;
}

function geoInput(form: HostForm, base: ProxyHost | null): { geoblock: GeoBlockSettings | null | undefined; geoblockMode: "merge" | "override" | undefined } {
  const geo = form.geoblock;
  const meaningful = geo.enabled || geoHasRules(geo) || geo.mode === "override" || Boolean(base?.geoblock);
  if (!meaningful) return { geoblock: base ? null : undefined, geoblockMode: undefined };
  return { geoblock: geoToSettings(geo), geoblockMode: geo.mode };
}

function rateLimitInput(form: HostForm, base: ProxyHost | null) {
  const rate = form.rateLimit;
  if (!rate.enabled && rate.rules.length === 0) return base ? null : undefined;
  return { enabled: rate.enabled, mode: rate.mode, rules: rateLimitRules(rate.rules) };
}

function mtlsInput(form: HostForm, base: ProxyHost | null) {
  const m = form.mtls;
  if (!m.enabled) return base ? null : undefined;
  return {
    enabled: true,
    trusted_client_cert_ids: [...m.certIds],
    trusted_role_ids: [...m.roleIds],
    protected_paths: pathList(m.protectedPaths),
    excluded_paths: pathList(m.excludedPaths),
    ...(m.legacyCaIds.length > 0 ? { ca_certificate_ids: [...m.legacyCaIds] } : {}),
  };
}

function dnsInput(form: HostForm, base: ProxyHost | null) {
  const d = form.dnsResolver;
  if (!d.enabled && !base?.dnsResolver && !d.resolvers.trim() && !d.fallbacks.trim() && !d.timeout.trim()) return base ? null : undefined;
  const fallbacks = splitList(d.fallbacks);
  return { enabled: d.enabled, resolvers: splitList(d.resolvers), fallbacks: fallbacks.length > 0 ? fallbacks : null, timeout: text(d.timeout) };
}

function upstreamDnsInput(form: HostForm, base: ProxyHost | null) {
  const u = form.upstreamDns;
  if (u.mode === "inherit" && u.family === "inherit") return base?.upstreamDnsResolution ? { enabled: null, family: null } : undefined;
  return { enabled: u.mode === "inherit" ? null : u.mode === "enabled", family: u.family === "inherit" ? null : u.family };
}

/**
 * The host input of a form. `saved` is the form the editor started from and
 * `base` the stored host it came from (the edited host, or the template of a
 * copy); both decide which stored values a field keeps. Undefined values mean
 * "not sent".
 */
export function formToInput(form: HostForm, saved: HostForm, base: ProxyHost | null, creating = false): Partial<ProxyHostInput> {
  const geo = geoInput(form, base);
  const locationRules: LocationRuleInput[] = form.locationRules
    .map((rule) => ({ path: rule.path.trim(), upstreams: serializeUpstreams(rule.upstreams), loadBalancer: locationLb(rule.lb) }))
    .filter((rule) => rule.path && rule.upstreams.length > 0);
  const redirects: RedirectRule[] = form.redirects
    .filter((rule) => rule.from.trim() || rule.to.trim())
    .map((rule) => ({ from: rule.from.trim(), to: rule.to.trim(), status: rule.status }));
  const pathBlocks: PathBlockRule[] = form.pathBlocks
    .filter((rule) => rule.path.trim())
    .map((rule) => ({ path: rule.path.trim(), status: rule.status, ...(rule.body.trim() ? { body: rule.body } : {}) }));
  const errorPages: ErrorPageRule[] = form.errorPages
    .filter((rule) => rule.body.trim())
    .map((rule) => ({
      statuses: statusList(rule.statuses).filter((code) => code >= 400 && code <= 599),
      body: rule.body,
      ...(rule.contentType.trim() ? { contentType: rule.contentType.trim() } : {}),
    }));
  return {
    name: form.name.trim(),
    tags: [...form.tags],
    enabled: form.enabled,
    domains: [...form.domains],
    upstreams: serializeUpstreams(form.upstreams),
    loadBalancer: form.lb.enabled || base?.loadBalancer ? lbToInput(form.lb) : base ? null : undefined,
    allowWebsocket: form.allowWebsocket,
    preserveHostHeader: form.preserveHostHeader,
    skipHttpsHostnameValidation: form.skipHttpsHostnameValidation,
    locationRules,
    waf: wafInput(form, saved, base?.waf, creating),
    rateLimit: rateLimitInput(form, base),
    accessListId: form.accessListId,
    geoblock: geo.geoblock,
    geoblockMode: geo.geoblockMode,
    authentik: authentikInput(form, base),
    forwardAuth: genericInput(form, base),
    ingressiForwardAuth: ingressiInput(form, base),
    mtls: mtlsInput(form, base),
    pathBlocks,
    pathAllows: form.pathAllows.filter((rule) => rule.path.trim()).map((rule) => ({ path: rule.path.trim() })),
    certificateId: form.certificateId,
    sslForced: form.sslForced,
    hstsEnabled: form.hstsEnabled,
    hstsSubdomains: form.hstsSubdomains,
    redirects,
    rewrite: form.rewritePrefix.trim() ? { path_prefix: form.rewritePrefix.trim() } : null,
    pathRewrites: form.pathRewrites
      .filter((rule) => rule.from.trim() || rule.to.trim())
      .map((rule) => ({ from: rule.from.trim(), to: rule.to.trim() })),
    errorPages,
    dnsResolver: dnsInput(form, base),
    upstreamDnsResolution: upstreamDnsInput(form, base),
    customPreHandlersJson: text(form.customPreHandlersJson),
    customReverseProxyJson: text(form.customReverseProxyJson),
  };
}

/** The users and groups the built-in forward auth lets in, as saving would set them. */
export function effectiveGrants(form: HostForm): { userIds: number[]; groupIds: number[] } {
  if (form.signIn !== "ingressi") return { userIds: [], groupIds: [] };
  return {
    userIds: [...form.ingressi.userIds].sort((a, b) => a - b),
    groupIds: [...form.ingressi.groupIds].sort((a, b) => a - b),
  };
}

export type EditorPayload = {
  host: Partial<ProxyHostInput>;
  forwardAuthAccess?: { userIds: number[]; groupIds: number[] };
  note?: string;
  emergencyReason?: string;
};

/**
 * What the editor sends: every field of a new host; for an existing host
 * the top-level fields whose input changed. Forward-auth grants are sent
 * when they change (or for a new host that lets users in).
 */
export function buildPayload(form: HostForm, saved: HostForm, base: ProxyHost | null, creating: boolean): EditorPayload {
  const current = formToInput(form, saved, base, creating);
  const grants = effectiveGrants(form);
  if (creating) {
    const host = Object.fromEntries(Object.entries(current).filter(([, value]) => value !== undefined)) as Partial<ProxyHostInput>;
    const sendGrants = grants.userIds.length > 0 || grants.groupIds.length > 0;
    return { host, ...(sendGrants ? { forwardAuthAccess: grants } : {}) };
  }
  const before = formToInput(saved, saved, base) as Record<string, unknown>;
  const host: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(current)) {
    if (value === undefined) continue;
    if (canonical(value) !== canonical(before[key])) host[key] = value;
  }
  // The geo blocking mode goes with the settings it belongs to.
  if (host.geoblock !== undefined && current.geoblockMode !== undefined) host.geoblockMode = current.geoblockMode;
  if (host.geoblockMode !== undefined && host.geoblock === undefined && current.geoblock !== undefined) host.geoblock = current.geoblock;
  const grantsChanged = canonical(grants) !== canonical(effectiveGrants(saved));
  return { host: host as Partial<ProxyHostInput>, ...(grantsChanged ? { forwardAuthAccess: grants } : {}) };
}

/** Whether the payload would change anything. */
export function payloadIsEmpty(payload: EditorPayload): boolean {
  return Object.keys(payload.host).length === 0 && payload.forwardAuthAccess === undefined;
}
