import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { Resolver } from "node:dns/promises";
import { join, dirname } from "node:path";
import { connect as netConnect, isIP } from "node:net";
import crypto from "node:crypto";
import {
  expandPrivateRanges,
  isPlainObject,
  mergeDeep,
  parseJson,
  parseOptionalJson,
  parseCustomHandlers,
  formatDialAddress,
  parseUpstreamTarget,
  toDurationMs,
  escapeHostPlaceholders,
} from "./caddy-utils";
import {
  groupHostPatternsByPriority,
  sortAutomationPoliciesBySubjectPriority,
  sortRoutesByHostPriority,
  sortTlsPoliciesBySniPriority,
} from "./host-pattern-priority";
import http from "node:http";
import https from "node:https";
import { appDb } from "./db";
import { eq, isNull } from "drizzle-orm";
import { config } from "./config";
import { configuredDashboardUpstreams, dashboardProxyFields } from "./dashboard-upstreams";
import {
  getGeneralSettings,
  getAcmeSettings,
  getMetricsSettings,
  getLoggingSettings,
  getDnsSettings,
  getDnsProviderSettings,
  getUpstreamDnsResolutionSettings,
  getGeoBlockSettings,
  getWafSettings,
  getErrorPagesSettings,
  getResponseHeadersSettings,
  getDefaultResponseSettings,
  getTrustedProxiesSettings,
  getRateLimitSettings,
  withSettingsSnapshot,
  type AcmeSettings,
  type DnsSettings,
  type UpstreamDnsAddressFamily,
  type UpstreamDnsResolutionSettings,
  type GeoBlockSettings,
  type WafSettings,
  type TrustedProxiesSettings,
  type RateLimitSettings
} from "./settings";
import { buildDefaultResponseRoute } from "./caddy-default-response";
import { buildResponseHeadersRoute } from "./caddy-response-headers";
import { buildProxyProtocolListenerWrappers } from "./proxy-protocol";
import { isReservedL4Port } from "./l4-reserved-ports";
import { buildDnsChallengeConfig, type DnsProviderCredentials } from "./dns-providers";
import { parseStoredCertificateProviderOptions } from "./certificate-provider-options";
import { syncInstances } from "./instance-sync";
import { deferCaddyApplyToBatch } from "./change-batch";
import { recordConfigSnapshotAfterApply } from "@/ee/config-history/snapshots";
import { loadMonetizationForCaddy, type MonetizationCaddyOptions } from "@/ee/monetization/caddy-config";
import { resolveCaddyStorage } from "@/ee/high-availability/caddy-storage";
import { CERTIFICATE_STORAGE_SETTING_KEY } from "@/ee/high-availability/types";
import {
  CONSUMER_HEADER_PREFIX,
  CHARGE_HEADER,
  CHARGE_LOG_FIELD,
  X402_PAYMENT_REQUEST_HEADERS,
  X402_PAYMENT_RESPONSE_HEADER,
  GATE_HOST_ID_HEADER,
  GATE_IDENTITY_HEADERS,
  GATE_PATH,
  GATE_TOKEN_HEADER,
  GATE_CLIENT_IP_HEADER,
} from "@/ee/monetization/types";
import {
  accessListEntries,
  accessListRules,
  accessLists,
  certificates,
  caCertificates,
  issuedClientCertificates,
  proxyHosts,
  l4ProxyHosts
} from "./db/schema";
import { type GeoBlockMode, type WafHostConfig, type MtlsConfig, type RedirectRule, type RewriteConfig, type LocationRuleMeta, type PathAllowRule, type PathBlockRule, type PathRewriteRule, type ErrorPageRule } from "./models/proxy-hosts";
import { stripPlaceholders } from "./caddy-placeholders";
import { buildClientAuthentication, groupMtlsDomainsByCaSet, buildMtlsRbacSubroutes, buildFingerprintCelExpression, buildValidClientCertCelExpression, resolveAllowedFingerprints, type MtlsAccessRuleLike } from "./caddy-mtls";
import { buildRoleFingerprintMap, buildCertFingerprintMap, buildRoleCertIdMap } from "./models/mtls-roles";
import { getAccessRulesForHosts } from "./models/mtls-access-rules";
import { buildWafHandlerEntry, resolveEffectiveWaf, wafDirectiveSource, wafExclusionsForHost } from "./caddy-waf";
import { listWafExclusionRows, type WafExclusionRow } from "./models/waf-exclusions";
import {
  buildHostRateLimit,
  buildRateLimitLogRoute,
  rateLimitContext,
  readStoredHostRateLimit,
  resolveEffectiveRateLimitRules,
} from "./caddy-rate-limit";
import {
  FORWARD_AUTH_CALLBACK_PATH,
  FORWARD_AUTH_COPY_HEADERS,
  FORWARD_AUTH_PROXY_PROOF_HEADER,
  FORWARD_AUTH_PROXY_HOST_ID_HEADER,
  FORWARD_AUTH_PORTAL_TARGET_HEADER,
  LEGACY_FORWARD_AUTH_CALLBACK_PATH,
  getForwardAuthProxyProof,
} from "./forward-auth-trust";
import { decryptSecret } from "./secret";
import {
  CaddyApplyError,
  describeCaddyRejection,
  logCaddyApplyFailure,
  safeSystemErrorCode,
} from "./caddy-apply-error";
import { readCaddyApplyState, recordCaddyApplyResult, type CaddyApplyFailureCode } from "./caddy-apply-status";
import { TLS_ISSUANCE_LOGGERS } from "./tls-issuance-log";
import { withCoalescedClusterLock } from "./db/locks";
import { readBypassSources } from "./sign-in-bypass";
import {
  accessListRouteName,
  addressMatcherName,
  buildAccessListHandler,
  BLOCKED_SOURCES_LOG_VALUE,
  type AccessListCaddyContext,
  type CompiledAccessList,
} from "./caddy-access-lists";
import {
  BLOCKED_SOURCES_KEY,
  DEFAULT_DENY_STATUS,
  isRuleAction,
  isRuleExpired,
  isRuleKind,
  normalizeListSettings,
  normalizeRuleValue,
} from "./access-list-rules";

/**
 * Headers removed from every forward-auth subrequest. The verify call is a
 * plain GET to the auth service; if the client's WebSocket handshake headers
 * went with it, Caddy would treat the subrequest as an upgrade, the auth
 * service (CPM's Next.js server, Authentik, …) would drop or refuse it, and
 * every WebSocket on a protected host would end in 502 Bad Gateway. The
 * request to the upstream app is a separate handler and keeps them.
 */
export const FORWARD_AUTH_SUBREQUEST_STRIP_HEADERS = [
  "Connection",
  "Upgrade",
  "Sec-WebSocket-Key",
  "Sec-WebSocket-Version",
  "Sec-WebSocket-Extensions",
  "Sec-WebSocket-Protocol"
];

const CERTS_DIR = process.env.CERTS_DIRECTORY || join(process.cwd(), "data", "certs");
mkdirSync(CERTS_DIR, { recursive: true, mode: 0o700 });

// Directory shared (via a Docker volume) with the Caddy container, so a
// custom ACME CA root PEM written here by the web container is readable by
// Caddy at the same path for `trusted_roots_pem_files`. Read lazily so tests
// (and non-Docker deployments) can override ACME_CA_ROOT_DIR at runtime.
function acmeCaRootFile(): string {
  return join(process.env.ACME_CA_ROOT_DIR || "/acme-ca", "custom-ca-root.pem");
}

/**
 * Persist (or clear) the custom ACME CA root PEM to the shared volume and
 * return the file path Caddy should reference, or null if no root is
 * configured or the file could not be written (in which case the issuer is
 * left without `trusted_roots_pem_files` rather than pointing at a missing file).
 */
function syncAcmeCaRootFile(caRootPem: string | undefined): string | null {
  const file = acmeCaRootFile();
  const pem = caRootPem?.trim();
  if (!pem) {
    try {
      rmSync(file, { force: true });
    } catch {
      // best-effort cleanup
    }
    return null;
  }
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, pem.endsWith("\n") ? pem : `${pem}\n`, { mode: 0o644 });
    return file;
  } catch (error) {
    console.error(`Failed to write ACME CA root PEM to ${file}`, error);
    return null;
  }
}

const DEFAULT_AUTHENTIK_HEADERS = [
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
  "X-Authentik-Meta-Version"
];

const DEFAULT_AUTHENTIK_TRUSTED_PROXIES = ["private_ranges"];


type ProxyHostRow = {
  id: number;
  name: string;
  domains: string;
  upstreams: string;
  certificateId: number | null;
  accessListId: number | null;
  sslForced: number;
  hstsEnabled: number;
  hstsSubdomains: number;
  allowWebsocket: number;
  preserveHostHeader: number;
  skipHttpsHostnameValidation: number;
  meta: string | null;
  enabled: number;
};

type DnsResolverMeta = {
  enabled?: boolean;
  resolvers?: string[];
  fallbacks?: string[];
  timeout?: string;
};

type UpstreamDnsResolutionMeta = {
  enabled?: boolean;
  family?: UpstreamDnsAddressFamily;
};

type IngressiForwardAuthMeta = {
  enabled?: boolean;
  protected_paths?: string[];
  excluded_paths?: string[];
  /** Client addresses that skip sign-in. Read through readBypassSources. */
  bypass_sources?: string[];
};

type ForwardAuthMeta = {
  enabled?: boolean;
  provider?: string;
  auth_upstream?: string;
  auth_endpoint?: string;
  copy_headers?: string[];
  trusted_proxies?: string[];
  api_split?: boolean;
  api_bypass_headers?: string[];
  protected_paths?: string[];
  excluded_paths?: string[];
  bypass_sources?: string[];
};

const DEFAULT_AUTHELIA_FORWARD_AUTH_ENDPOINT = "/api/authz/forward-auth";
const DEFAULT_AUTHELIA_FORWARD_AUTH_HEADERS = [
  "Remote-User",
  "Remote-Groups",
  "Remote-Email",
  "Remote-Name",
  "Remote-IP"
];

/** RFC 7230 token — copy/bypass header names are interpolated into Caddy
 * placeholders and matcher keys, so free-form text must never reach them. */
const FA_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z-]+$/;

/**
 * Placeholder for a header of the forward-auth subrequest's response.  Caddy
 * registers these under Go's canonical header name ("X-Ingressi-User") and the
 * lookup is case-sensitive, so any other spelling would never resolve.
 */
function authResponseHeaderPlaceholder(headerName: string): string {
  const canonical = headerName
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join("-");
  return `{http.reverse_proxy.header.${canonical}}`;
}

/**
 * Standard request-credential headers.  They carry the client's own
 * credentials, not an identity assertion, and excluded paths, access-list
 * basic auth and the auth server itself may need them, so the identity-header
 * strip leaves them alone.  On protected routes, one listed as a copy header
 * is replaced by the auth server's value, or removed when it returns none
 * (see buildAuthResponseCopyRoutes).
 */
const CLIENT_CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization", "cookie"]);

/** Beyond this many separators only the uniform spellings are enumerated. */
const MAX_ENUMERATED_HEADER_SEPARATORS = 6;

/**
 * Every spelling of `name` that mixes "-" and "_" at its separators, starting
 * with `name` itself (X-Ingressi-User, X_Ingressi-User, X-Ingressi_User,
 * X_Ingressi_User).
 */
function headerSeparatorSpellings(name: string): string[] {
  const parts = name.split(/[-_]/);
  const separators = parts.length - 1;
  if (separators > MAX_ENUMERATED_HEADER_SEPARATORS) {
    return [name, parts.join("-"), parts.join("_")];
  }
  const spellings = [name];
  for (let mask = 0; mask < 1 << separators; mask++) {
    let spelling = parts[0];
    for (let i = 1; i < parts.length; i++) {
      spelling += (mask & (1 << (i - 1)) ? "_" : "-") + parts[i];
    }
    spellings.push(spelling);
  }
  return spellings;
}

/**
 * A `headers` handler deleting client-supplied copies of the identity headers
 * that the auth server vouches for.  Caddy deletes by Go's canonical header
 * name, which covers letter case but treats "-" and "_" as different
 * characters, while CGI/WSGI-style upstreams fold both into one variable
 * (HTTP_X_INGRESSI_USER).  So each name is deleted in every mix of the two
 * separators.
 */
function buildIdentityHeaderStripHandler(headerNames: readonly string[]): Record<string, unknown> | null {
  const names = new Map<string, string>();
  for (const name of headerNames) {
    if (CLIENT_CREDENTIAL_HEADERS.has(name.toLowerCase().replace(/_/g, "-"))) continue;
    for (const spelling of headerSeparatorSpellings(name)) {
      const key = spelling.toLowerCase();
      if (!names.has(key)) names.set(key, spelling);
    }
  }
  return names.size > 0 ? { handler: "headers", request: { delete: [...names.values()] } } : null;
}

/**
 * The handle_response routes run on the original request after a 2xx auth
 * response: each copy header is set from the auth response when that has a
 * non-empty value. The client credential headers are exempt from the
 * identity-header strip so the auth server receives them; one listed as a
 * copy header is removed here when the auth server returns none, so an
 * upstream relying on the header listed only ever gets the auth server's
 * value, never one the client sent.
 */
function buildAuthResponseCopyRoutes(headerNames: readonly string[]): Record<string, unknown>[] {
  const routes: Record<string, unknown>[] = [{ handle: [{ handler: "vars" }] }];
  for (const headerName of headerNames) {
    const placeholder = authResponseHeaderPlaceholder(headerName);
    routes.push({
      handle: [{ handler: "headers", request: { set: { [headerName]: [placeholder] } } }],
      match: [{ not: [{ vars: { [placeholder]: [""] } }] }]
    });
    if (CLIENT_CREDENTIAL_HEADERS.has(headerName.toLowerCase().replace(/_/g, "-"))) {
      routes.push({
        handle: [{ handler: "headers", request: { delete: [...new Set(headerSeparatorSpellings(headerName))] } }],
        match: [{ vars: { [placeholder]: [""] } }]
      });
    }
  }
  return routes;
}

/**
 * API monetization (ee/monetization): a `headers` handler that removes every
 * client-supplied copy of the headers the gate vouches for, in each mix of
 * "-" and "_", plus the whole X-Ingressi-Consumer-* family (Caddy deletes
 * names ending in "*" by prefix) and X-Ingressi-Client-Ip.
 */
function buildMonetizationStripHandler(): Record<string, unknown> {
  const strip = buildIdentityHeaderStripHandler(GATE_IDENTITY_HEADERS)!;
  const request = strip.request as { delete: string[] };
  // The consumer family, and the client address Caddy sets on the gate subrequest (never a client's copy upstream).
  for (const spelling of new Set([...headerSeparatorSpellings(`${CONSUMER_HEADER_PREFIX}*`), ...headerSeparatorSpellings(GATE_CLIENT_IP_HEADER)])) {
    if (!request.delete.includes(spelling)) request.delete.push(spelling);
  }
  return strip;
}

/**
 * The forward_auth-style subrequest to the gate (GET /api/monetization/gate)
 * with the per-install gate token and the proxy host id. A 2xx answer copies
 * the consumer id and plan to the request and continues to the upstream; any
 * other answer (401, 402, 403, 429) is returned to the client as the gate
 * wrote it. Without an address for the dashboard nobody is let through.
 * With several dashboard replicas a gate request is retried on another one
 * only when it never reached the first: the gate charges when it answers.
 */
function buildMonetizationGateHandler(proxyHostId: number, gateToken: string): Record<string, unknown> {
  const dashboardUpstreams = getDashboardUpstreams();
  if (dashboardUpstreams.length === 0) {
    return { handler: "static_response", status_code: 503, body: "API gate unavailable" };
  }
  return {
    handler: "reverse_proxy",
    ...dashboardProxyFields(dashboardUpstreams, { retryAfterSend: false }),
    rewrite: { method: "GET", uri: GATE_PATH },
    headers: {
      request: {
        set: {
          [GATE_TOKEN_HEADER]: [gateToken],
          [GATE_HOST_ID_HEADER]: [String(proxyHostId)],
          // The request's path for x402's resource (the gate's own request is rewritten).
          "X-Forwarded-Uri": ["{http.request.uri}"],
          // The client's address as Caddy determined it (the connection's, or the one the server's
          // trusted proxies report), replacing any copy the client sent: x402's per-address limit.
          [GATE_CLIENT_IP_HEADER]: ["{http.vars.client_ip}"]
        }
      }
    },
    handle_response: [
      {
        match: { status_code: [2] },
        routes: [
          ...buildAuthResponseCopyRoutes(GATE_IDENTITY_HEADERS),
          buildMonetizationChargeLogRoute(),
          ...buildX402ResponseRoutes()
        ]
      }
    ]
  };
}

/**
 * x402 (ee/monetization/x402): the gate's settlement answer goes to the
 * client on the upstream's response (PAYMENT-RESPONSE, set before the
 * upstream answers, so the upstream's own headers are added to it), and the
 * payment payload never reaches the upstream.
 */
function buildX402ResponseRoutes(): Record<string, unknown>[] {
  const placeholder = authResponseHeaderPlaceholder(X402_PAYMENT_RESPONSE_HEADER);
  return [
    {
      handle: [{ handler: "headers", response: { set: { [X402_PAYMENT_RESPONSE_HEADER]: [placeholder] } } }],
      match: [{ not: [{ vars: { [placeholder]: [""] } }] }]
    },
    { handle: [{ handler: "headers", request: { delete: [...X402_PAYMENT_REQUEST_HEADERS] } }] }
  ];
}

/**
 * Failed-answer credits (ee/monetization/answer-credits.ts): the charge id
 * the gate answers with goes into the request's access log line, next to
 * the status the request is finally answered with. `early`: the gate's
 * header is read before the upstream's answer replaces the reverse_proxy
 * placeholders.
 */
function buildMonetizationChargeLogRoute(): Record<string, unknown> {
  const placeholder = authResponseHeaderPlaceholder(CHARGE_HEADER);
  return {
    handle: [{ handler: "log_append", key: CHARGE_LOG_FIELD, value: placeholder, early: true }],
    match: [{ not: [{ vars: { [placeholder]: [""] } }] }]
  };
}

type MtlsMeta = {
  enabled?: boolean;
  trusted_client_cert_ids?: number[];
  trusted_role_ids?: number[];
  protected_paths?: string[];
  excluded_paths?: string[];
  ca_certificate_ids?: number[];
};

type ProxyHostMeta = {
  custom_reverse_proxy_json?: string;
  custom_pre_handlers_json?: string;
  authentik?: ProxyHostAuthentikMeta;
  // Stored under its pre-rename key, which existing databases, exports and
  // replicas on older versions read.
  cpm_forward_auth?: IngressiForwardAuthMeta;
  forward_auth?: ForwardAuthMeta;
  load_balancer?: LoadBalancerMeta;
  dns_resolver?: DnsResolverMeta;
  upstream_dns_resolution?: UpstreamDnsResolutionMeta;
  geoblock?: GeoBlockSettings;
  geoblock_mode?: GeoBlockMode;
  waf?: WafHostConfig;
  mtls?: MtlsMeta;
  redirects?: RedirectRule[];
  rewrite?: RewriteConfig;
  location_rules?: LocationRuleMeta[];
  path_allows?: PathAllowRule[];
  path_blocks?: PathBlockRule[];
  path_rewrites?: PathRewriteRule[];
  error_pages?: ErrorPageRule[];
  /** Read through readStoredHostRateLimit, which drops anything invalid. */
  rate_limit?: unknown;
};

type L4Meta = {
  load_balancer?: LoadBalancerMeta;
  dns_resolver?: DnsResolverMeta;
  upstream_dns_resolution?: UpstreamDnsResolutionMeta;
  geoblock?: GeoBlockSettings;
  geoblock_mode?: GeoBlockMode;
};

type ProxyHostAuthentikMeta = {
  enabled?: boolean;
  outpost_domain?: string;
  outpost_upstream?: string;
  auth_endpoint?: string;
  copy_headers?: string[];
  trusted_proxies?: string[];
  set_outpost_host_header?: boolean;
  protected_paths?: string[];
  excluded_paths?: string[];
  bypass_sources?: string[];
};

type AuthentikRouteConfig = {
  enabled: boolean;
  outpostDomain: string;
  outpostUpstream: string;
  authEndpoint: string;
  copyHeaders: string[];
  trustedProxies: string[];
  setOutpostHostHeader: boolean;
  protectedPaths: string[] | null;
  excludedPaths: string[] | null;
  /** Client addresses that skip sign-in (valid entries only). */
  bypassSources: string[];
};

type ForwardAuthRouteConfig = {
  enabled: boolean;
  provider: "authelia" | "custom";
  /** host:port dial address extracted from the auth server URL. */
  dialAddress: string;
  /** URI (may include a query string) the auth subrequest is rewritten to. */
  authEndpoint: string;
  copyHeaders: string[];
  trustedProxies: string[];
  /** Non-browser requests get a 401 instead of the auth server's redirect. */
  apiSplit: boolean;
  /** Header names that make a request skip forward auth entirely. */
  apiBypassHeaders: string[];
  protectedPaths: string[] | null;
  excludedPaths: string[] | null;
  /** Client addresses that skip sign-in (valid entries only). */
  bypassSources: string[];
};

type LoadBalancerActiveHealthCheckMeta = {
  enabled?: boolean;
  uri?: string;
  port?: number;
  interval?: string;
  timeout?: string;
  status?: number;
  body?: string;
};

type LoadBalancerPassiveHealthCheckMeta = {
  enabled?: boolean;
  fail_duration?: string;
  max_fails?: number;
  unhealthy_status?: number[];
  unhealthy_latency?: string;
};

type LoadBalancerMeta = {
  enabled?: boolean;
  policy?: string;
  policy_header_field?: string;
  policy_cookie_name?: string;
  policy_cookie_secret?: string;
  try_duration?: string;
  try_interval?: string;
  retries?: number;
  active_health_check?: LoadBalancerActiveHealthCheckMeta;
  passive_health_check?: LoadBalancerPassiveHealthCheckMeta;
};

type LoadBalancerRouteConfig = {
  enabled: boolean;
  policy: string;
  policyHeaderField: string | null;
  policyCookieName: string | null;
  policyCookieSecret: string | null;
  tryDuration: string | null;
  tryInterval: string | null;
  retries: number | null;
  activeHealthCheck: {
    enabled: boolean;
    uri: string | null;
    port: number | null;
    interval: string | null;
    timeout: string | null;
    status: number | null;
    body: string | null;
  } | null;
  passiveHealthCheck: {
    enabled: boolean;
    failDuration: string | null;
    maxFails: number | null;
    unhealthyStatus: number[] | null;
    unhealthyLatency: string | null;
  } | null;
};

type AccessListEntryRow = {
  accessListId: number;
  username: string;
  passwordHash: string;
};

type CertificateRow = {
  id: number;
  name: string;
  type: string;
  domainNames: string;
  certificatePem: string | null;
  privateKeyPem: string | null;
  autoRenew: number;
  providerOptions: string | null;
};

type CaddyHttpRoute = Record<string, unknown>;

type CertificateUsage = {
  certificate: CertificateRow;
  domains: Set<string>;
};

const VALID_UPSTREAM_DNS_FAMILIES: UpstreamDnsAddressFamily[] = ["ipv6", "ipv4", "both"];

type UpstreamDnsResolutionRouteConfig = {
  enabled: boolean | null;
  family: UpstreamDnsAddressFamily | null;
};

type EffectiveUpstreamDnsResolution = {
  enabled: boolean;
  family: UpstreamDnsAddressFamily;
};

function parseUpstreamDnsResolutionConfig(
  meta: UpstreamDnsResolutionMeta | undefined | null
): UpstreamDnsResolutionRouteConfig | null {
  if (!meta) {
    return null;
  }

  const enabled = typeof meta.enabled === "boolean" ? meta.enabled : null;
  const family = meta.family && VALID_UPSTREAM_DNS_FAMILIES.includes(meta.family) ? meta.family : null;

  if (enabled === null && family === null) {
    return null;
  }

  return {
    enabled,
    family
  };
}

function resolveEffectiveUpstreamDnsResolution(
  globalSetting: UpstreamDnsResolutionSettings | null,
  hostSetting: UpstreamDnsResolutionRouteConfig | null
): EffectiveUpstreamDnsResolution {
  const globalFamily = globalSetting?.family && VALID_UPSTREAM_DNS_FAMILIES.includes(globalSetting.family)
    ? globalSetting.family
    : "both";
  const globalEnabled = Boolean(globalSetting?.enabled);

  return {
    enabled: hostSetting?.enabled ?? globalEnabled,
    family: hostSetting?.family ?? globalFamily
  };
}

function getLookupServers(dnsConfig: DnsResolverRouteConfig | null, globalDnsSettings: DnsSettings | null): string[] {
  if (dnsConfig && dnsConfig.enabled && dnsConfig.resolvers.length > 0) {
    const servers = [...dnsConfig.resolvers];
    if (dnsConfig.fallbacks && dnsConfig.fallbacks.length > 0) {
      servers.push(...dnsConfig.fallbacks);
    }
    return servers;
  }

  if (globalDnsSettings?.enabled && Array.isArray(globalDnsSettings.resolvers) && globalDnsSettings.resolvers.length > 0) {
    const servers = [...globalDnsSettings.resolvers];
    if (Array.isArray(globalDnsSettings.fallbacks) && globalDnsSettings.fallbacks.length > 0) {
      servers.push(...globalDnsSettings.fallbacks);
    }
    return servers;
  }

  return [];
}

function getLookupTimeoutMs(dnsConfig: DnsResolverRouteConfig | null, globalDnsSettings: DnsSettings | null): number | null {
  const hostTimeout = toDurationMs(dnsConfig?.timeout ?? null);
  if (hostTimeout !== null) {
    return hostTimeout;
  }

  if (globalDnsSettings?.enabled) {
    const globalTimeout = toDurationMs(globalDnsSettings.timeout ?? null);
    if (globalTimeout !== null) {
      return globalTimeout;
    }
  }

  return null;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number | null, timeoutLabel: string): Promise<T> {
  if (!timeoutMs || timeoutMs <= 0) {
    return promise;
  }

  let timeoutHandle: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          reject(new Error(`${timeoutLabel} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }
  }
}

async function resolveHostnameAddresses(
  resolver: Resolver,
  hostname: string,
  family: UpstreamDnsAddressFamily,
  timeoutMs: number | null
): Promise<string[]> {
  const errors: string[] = [];
  const resolved: string[] = [];
  const seen = new Set<string>();

  const resolve6 = async () => {
    try {
      return await withTimeout(resolver.resolve6(hostname), timeoutMs, `AAAA lookup for ${hostname}`);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
      return [];
    }
  };

  const resolve4 = async () => {
    try {
      return await withTimeout(resolver.resolve4(hostname), timeoutMs, `A lookup for ${hostname}`);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
      return [];
    }
  };

  const pushUnique = (addresses: string[]) => {
    for (const address of addresses) {
      if (!seen.has(address)) {
        seen.add(address);
        resolved.push(address);
      }
    }
  };

  if (family === "ipv6") {
    pushUnique(await resolve6());
  } else if (family === "ipv4") {
    pushUnique(await resolve4());
  } else {
    pushUnique(await resolve6());
    pushUnique(await resolve4());
  }

  if (resolved.length === 0 && errors.length > 0) {
    throw new Error(errors.join("; "));
  }

  return resolved;
}

type ResolveUpstreamsResult = {
  upstreams: Array<{ dial: string }>;
  hasHttpsUpstream: boolean;
  httpsTlsServerName: string | null;
};

async function resolveUpstreamDials(
  row: ProxyHostRow,
  upstreams: string[],
  dnsConfig: DnsResolverRouteConfig | null,
  globalDnsSettings: DnsSettings | null,
  dnsResolution: EffectiveUpstreamDnsResolution
): Promise<ResolveUpstreamsResult> {
  const parsedTargets = upstreams.map(parseUpstreamTarget);
  const hasHttpsUpstream = parsedTargets.some((target) => target.scheme === "https");

  if (!dnsResolution.enabled) {
    return {
      upstreams: parsedTargets.map((target) => ({ dial: target.dial })),
      hasHttpsUpstream,
      httpsTlsServerName: null
    };
  }

  const httpsHostnames = Array.from(
    new Set(
      parsedTargets
        .filter((target) => target.scheme === "https" && target.host && target.port && isIP(target.host) === 0)
        .map((target) => target.host as string)
    )
  );
  const canResolveHttps = httpsHostnames.length <= 1;
  if (!canResolveHttps) {
    console.warn(
      `[caddy] Skipping DNS pinning for HTTPS upstreams on host "${row.name}" because multiple TLS server names are configured.`
    );
  }

  const resolver = new Resolver();
  const lookupServers = getLookupServers(dnsConfig, globalDnsSettings);
  if (lookupServers.length > 0) {
    try {
      resolver.setServers(lookupServers);
    } catch (error) {
      console.warn(`[caddy] Failed to set custom DNS servers for upstream pinning`, error);
    }
  }
  const timeoutMs = getLookupTimeoutMs(dnsConfig, globalDnsSettings);

  const dials: string[] = [];
  for (const target of parsedTargets) {
    if (!target.host || !target.port || isIP(target.host) !== 0) {
      dials.push(target.dial);
      continue;
    }

    if (target.scheme === "https" && !canResolveHttps) {
      dials.push(target.dial);
      continue;
    }

    try {
      const addresses = await resolveHostnameAddresses(resolver, target.host, dnsResolution.family, timeoutMs);
      if (addresses.length === 0) {
        dials.push(target.dial);
        continue;
      }
      for (const address of addresses) {
        dials.push(formatDialAddress(address, target.port));
      }
    } catch (error) {
      console.warn(
        `[caddy] Failed to resolve upstream "${target.original}" for host "${row.name}", falling back to hostname dial.`,
        error
      );
      dials.push(target.dial);
    }
  }

  const dedupedDials: Array<{ dial: string }> = [];
  const seen = new Set<string>();
  for (const dial of dials) {
    if (!seen.has(dial)) {
      seen.add(dial);
      dedupedDials.push({ dial });
    }
  }

  return {
    upstreams: dedupedDials,
    hasHttpsUpstream,
    httpsTlsServerName: canResolveHttps && httpsHostnames.length === 1 ? httpsHostnames[0] : null
  };
}

function collectCertificateUsage(rows: ProxyHostRow[], certificates: Map<number, CertificateRow>) {
  const usage = new Map<number, CertificateUsage>();
  const autoManagedDomains = new Set<string>();

  for (const row of rows) {
    if (!row.enabled) {
      continue;
    }

    const domains = parseJson<string[]>(row.domains, []).map((domain) => domain?.trim().toLowerCase());
    const filteredDomains = domains.filter((domain): domain is string => Boolean(domain));
    if (filteredDomains.length === 0) {
      continue;
    }

    // Handle auto-managed certificates (certificateId is null)
    if (!row.certificateId) {
      for (const domain of filteredDomains) {
        autoManagedDomains.add(domain);
      }
      continue;
    }

    const cert = certificates.get(row.certificateId);
    if (!cert) {
      continue;
    }

    if (!usage.has(cert.id)) {
      usage.set(cert.id, {
        certificate: cert,
        domains: new Set()
      });
    }

    const entry = usage.get(cert.id)!;
    for (const domain of filteredDomains) {
      entry.domains.add(domain);
    }
  }

  return { usage, autoManagedDomains };
}

function mergeGeoBlockSettings(
  global: GeoBlockSettings,
  host: GeoBlockSettings
): GeoBlockSettings {
  return {
    enabled: host.enabled || global.enabled,
    block_countries: [...(global.block_countries ?? []), ...(host.block_countries ?? [])],
    block_continents: [...(global.block_continents ?? []), ...(host.block_continents ?? [])],
    block_asns: [...(global.block_asns ?? []), ...(host.block_asns ?? [])],
    block_cidrs: [...(global.block_cidrs ?? []), ...(host.block_cidrs ?? [])],
    block_ips: [...(global.block_ips ?? []), ...(host.block_ips ?? [])],
    allow_countries: [...(global.allow_countries ?? []), ...(host.allow_countries ?? [])],
    allow_continents: [...(global.allow_continents ?? []), ...(host.allow_continents ?? [])],
    allow_asns: [...(global.allow_asns ?? []), ...(host.allow_asns ?? [])],
    allow_cidrs: [...(global.allow_cidrs ?? []), ...(host.allow_cidrs ?? [])],
    allow_ips: [...(global.allow_ips ?? []), ...(host.allow_ips ?? [])],
    trusted_proxies: [...(global.trusted_proxies ?? []), ...(host.trusted_proxies ?? [])],
    // Host config wins for scalar fields
    fail_closed: host.fail_closed || global.fail_closed || false,
    response_status: host.response_status ?? global.response_status ?? 403,
    response_body: host.response_body ?? global.response_body ?? "Forbidden",
    response_headers: { ...(global.response_headers ?? {}), ...(host.response_headers ?? {}) },
    redirect_url: host.redirect_url ?? global.redirect_url ?? "",
  };
}

export function resolveEffectiveGeoBlock(
  global: GeoBlockSettings | null,
  host: { geoblock: GeoBlockSettings | null; geoblock_mode: GeoBlockMode }
): GeoBlockSettings | null {
  const hostConfig = host.geoblock;
  const globalConfig = global;

  // Neither configured or enabled
  if (!hostConfig?.enabled && !globalConfig?.enabled) return null;

  // Host override mode: use host config only
  if (hostConfig && host.geoblock_mode === "override") {
    return hostConfig.enabled ? hostConfig : null;
  }

  // Host merge mode: only enabled host config should alter global behavior.
  // A disabled host geoblock means "no per-host geoblock" in merge mode.
  if (hostConfig?.enabled && globalConfig) {
    return mergeGeoBlockSettings(globalConfig, hostConfig);
  }

  // Only one configured
  if (hostConfig?.enabled) return hostConfig;
  if (globalConfig?.enabled) return globalConfig;

  return null;
}

export function buildBlockerHandler(config: GeoBlockSettings): Record<string, unknown> {
  const handler: Record<string, unknown> = {
    handler: "blocker",
    geoip_db: "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    asn_db: "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
  };

  if (config.block_countries?.length) handler.block_countries = config.block_countries;
  if (config.block_continents?.length) handler.block_continents = config.block_continents;
  if (config.block_asns?.length) handler.block_asns = config.block_asns;
  if (config.block_cidrs?.length) handler.block_cidrs = config.block_cidrs;
  if (config.block_ips?.length) handler.block_ips = config.block_ips;

  if (config.allow_countries?.length) handler.allow_countries = config.allow_countries;
  if (config.allow_continents?.length) handler.allow_continents = config.allow_continents;
  if (config.allow_asns?.length) handler.allow_asns = config.allow_asns;
  if (config.allow_cidrs?.length) handler.allow_cidrs = config.allow_cidrs;
  if (config.allow_ips?.length) handler.allow_ips = config.allow_ips;

  if (config.trusted_proxies?.length) handler.trusted_proxies = expandPrivateRanges(config.trusted_proxies);
  if (config.fail_closed) handler.fail_closed = true;

  if (config.redirect_url) {
    handler.redirect_url = config.redirect_url;
  } else {
    if (config.response_status) handler.response_status = config.response_status;
    if (config.response_body) handler.response_body = config.response_body;
    if (config.response_headers && Object.keys(config.response_headers).length) {
      handler.response_headers = config.response_headers;
    }
  }

  return handler;
}

/**
 * Normalize the configured trusted-proxy ranges: trim, drop blanks, and expand
 * the "private_ranges" shorthand into concrete CIDRs (matching how the geoblock
 * and Authentik handlers treat the same shorthand).
 */
export function normalizeTrustedProxyRanges(ranges: string[] | undefined | null): string[] {
  return expandPrivateRanges((ranges ?? []).map((r) => r.trim()).filter(Boolean));
}

/**
 * Build the server-level trusted-proxy fields for the main HTTP server object
 * (`servers.ingressi`). Caddy resolves `{http.vars.client_ip}` in core — before
 * any handler runs — so this is the only place a global trusted-proxy list can
 * fix client-IP attribution for access logs, analytics and downstream handlers.
 *
 * Returns an empty object (nothing emitted, current behaviour preserved) unless
 * at least one range is configured.
 */
export function buildServerTrustedProxies(
  settings: TrustedProxiesSettings | null | undefined
): {
  trusted_proxies?: { source: string; ranges: string[] };
  client_ip_headers?: string[];
  trusted_proxies_strict?: number;
} {
  if (!settings) return {};

  const ranges = normalizeTrustedProxyRanges(settings.ranges);
  if (ranges.length === 0) return {};

  const out: {
    trusted_proxies: { source: string; ranges: string[] };
    client_ip_headers?: string[];
    trusted_proxies_strict?: number;
  } = {
    trusted_proxies: { source: "static", ranges }
  };

  const headers = (settings.client_ip_headers ?? []).map((h) => h.trim()).filter(Boolean);
  if (headers.length > 0) out.client_ip_headers = headers;

  // Caddy's trusted_proxies_strict is an int flag (1 = strict, 0 = off).
  if (settings.strict) out.trusted_proxies_strict = 1;

  return out;
}

type AccessListRecord = typeof accessLists.$inferSelect;
type AccessListRuleRecord = typeof accessListRules.$inferSelect;

/** A stored rule's values, parsed and checked again; values that do not parse are left out. */
function storedRuleValues(rule: AccessListRuleRecord): string[] {
  const values = parseJson<unknown>(rule.matchValues, []);
  if (!Array.isArray(values) || !isRuleKind(rule.kind)) return [];
  const kind = rule.kind;
  const checked: string[] = [];
  for (const value of values) {
    const result = typeof value === "string" ? normalizeRuleValue(kind, value) : null;
    if (result && "value" in result) checked.push(result.value);
    else console.warn(`Ignoring an invalid value in access list rule ${rule.id}`);
  }
  return checked;
}

/** A list's deny response as stored, checked again (an imported file is not trusted to be valid). */
function storedDenyResponse(list: AccessListRecord): Pick<CompiledAccessList, "denyStatus" | "denyBody" | "denyRedirectUrl"> {
  let response: Pick<CompiledAccessList, "denyStatus" | "denyBody" | "denyRedirectUrl"> = {
    denyStatus: DEFAULT_DENY_STATUS,
    denyBody: null,
    denyRedirectUrl: null,
  };
  try {
    const checked = normalizeListSettings({
      denyStatus: list.denyStatus,
      denyBody: list.denyBody,
      denyRedirectUrl: list.denyRedirectUrl,
    });
    response = {
      denyStatus: checked.denyStatus ?? DEFAULT_DENY_STATUS,
      denyBody: checked.denyBody ?? null,
      denyRedirectUrl: checked.denyRedirectUrl ?? null,
    };
  } catch {
    console.warn(`Access list ${list.id} has an invalid deny response; serving the default`);
  }
  return response;
}

/**
 * The Caddy configuration of access list rules (caddy-access-lists.ts): one
 * named route per list whose rules do something, invoked by the hosts that
 * use the list, and the route of the global Blocked sources list, which runs
 * first on the server, for every host. Expired rules are left out.
 */
export function buildAccessListCaddyConfig(
  lists: readonly AccessListRecord[],
  rules: readonly AccessListRuleRecord[],
  trustedProxiesSettings: TrustedProxiesSettings | null | undefined,
  now: Date = new Date()
): {
  namedRoutes: Record<string, CaddyHttpRoute>;
  invokes: Map<number, Record<string, unknown>>;
  blockedSourcesRoute: CaddyHttpRoute | null;
} {
  const context: AccessListCaddyContext = { trustedProxies: normalizeTrustedProxyRanges(trustedProxiesSettings?.ranges) };
  const rulesByList = new Map<number, AccessListRuleRecord[]>();
  for (const rule of rules) {
    if (isRuleExpired(rule, now)) continue;
    const bucket = rulesByList.get(rule.accessListId) ?? [];
    bucket.push(rule);
    rulesByList.set(rule.accessListId, bucket);
  }

  const namedRoutes: Record<string, CaddyHttpRoute> = {};
  const invokes = new Map<number, Record<string, unknown>>();
  let blockedSourcesRoute: CaddyHttpRoute | null = null;
  for (const list of lists) {
    const systemList = list.systemKey === BLOCKED_SOURCES_KEY;
    if (list.systemKey && !systemList) continue;
    const listRules = (rulesByList.get(list.id) ?? [])
      .slice()
      .sort((a, b) => a.position - b.position || a.id - b.id)
      .flatMap((rule) => {
        if (!isRuleAction(rule.action) || !isRuleKind(rule.kind)) return [];
        // Blocked sources only ever deny.
        if (systemList && rule.action !== "deny") return [];
        const values = storedRuleValues(rule);
        return values.length > 0 ? [{ action: rule.action, kind: rule.kind, values }] : [];
      });
    const compiled: CompiledAccessList = {
      logValue: systemList ? BLOCKED_SOURCES_LOG_VALUE : String(list.id),
      rules: listRules,
      // Blocked sources lets through everything it does not name.
      defaultAction: !systemList && list.defaultAction === "deny" ? "deny" : "allow",
      ...storedDenyResponse(list),
      failClosed: Boolean(list.failClosed),
    };
    const handler = buildAccessListHandler(compiled, context);
    if (!handler) continue;
    if (systemList) {
      blockedSourcesRoute = { handle: [handler] };
      continue;
    }
    const name = accessListRouteName(list.id);
    namedRoutes[name] = { handle: [handler] };
    invokes.set(list.id, { handler: "invoke", name });
  }
  return { namedRoutes, invokes, blockedSourcesRoute };
}

type BuildProxyRoutesOptions = {
  globalDnsSettings: DnsSettings | null;
  globalUpstreamDnsResolutionSettings: UpstreamDnsResolutionSettings | null;
  globalGeoBlock?: GeoBlockSettings | null;
  globalWaf?: WafSettings | null;
  mtlsRbac?: {
    roleFingerprintMap: Map<number, Set<string>>;
    certFingerprintMap: Map<number, string>;
    accessRulesByHost: Map<number, MtlsAccessRuleLike[]>;
  };
  /** Monetized hosts and the gate token (ee/monetization); null when none. */
  monetization?: MonetizationCaddyOptions | null;
  /** Global rate limiting defaults and allowlist (caddy-rate-limit.ts). */
  globalRateLimit?: RateLimitSettings | null;
  /** WAF rule exclusion records (src/lib/models/waf-exclusions.ts); global ones have no proxyHostId. */
  wafExclusions?: readonly WafExclusionRow[];
  /**
   * The `invoke` handler of each access list whose rules do something, by
   * list id (caddy-access-lists.ts); hosts using the list run it after geo
   * blocking.
   */
  accessListInvokes?: ReadonlyMap<number, Record<string, unknown>>;
  /**
   * The server's trusted proxy ranges, normalized (private_ranges expanded):
   * with some, the sign-in bypass matches the client address behind them,
   * without, the address of the connection (as access list rules do).
   */
  trustedProxies?: readonly string[];
};

export function buildLocationReverseProxy(
  rule: LocationRuleMeta,
  skipHttpsValidation: boolean,
  preserveHostHeader: boolean
): { safePath: string; reverseProxyHandler: Record<string, unknown> } {
  const parsedTargets = rule.upstreams.map(parseUpstreamTarget);
  const hasHttps = parsedTargets.some((t) => t.scheme === "https");

  // Sanitize path to prevent Caddy placeholder injection
  const safePath = stripPlaceholders(rule.path);

  const reverseProxyHandler: Record<string, unknown> = {
    handler: "reverse_proxy",
    upstreams: parsedTargets.map((t) => ({ dial: t.dial })),
  };

  if (preserveHostHeader) {
    reverseProxyHandler.headers = {
      request: { set: { Host: ["{http.request.host}"] } },
    };
  }

  if (hasHttps) {
    reverseProxyHandler.transport = {
      protocol: "http",
      tls: skipHttpsValidation ? { insecure_skip_verify: true } : {},
    };
  }

  // Per-rule load balancing / health checks (mirrors the host-level config).
  const lbConfig = parseLoadBalancerConfig(rule.load_balancer);
  if (lbConfig) {
    const loadBalancing = buildLoadBalancingConfig(lbConfig);
    if (loadBalancing) {
      reverseProxyHandler.load_balancing = loadBalancing;
    }
    const healthChecks = buildHealthChecksConfig(lbConfig);
    if (healthChecks) {
      reverseProxyHandler.health_checks = healthChecks;
    }
  }

  return { safePath, reverseProxyHandler };
}

// Builds a Caddy server-level error route (handle_errors equivalent) that serves a
// custom static response while preserving the original error status code. An empty
// `statuses` list matches every error; `hosts`, when set, scopes the route to a host.
export function buildErrorPageRoute(rule: ErrorPageRule, hosts?: string[]): CaddyHttpRoute {
  const matcher: Record<string, unknown> = {};
  if (hosts && hosts.length > 0) {
    matcher.host = hosts;
  }
  if (rule.statuses.length > 0) {
    // Mirrors Caddy's documented handle_errors form, e.g. {http.error.status_code} == 404
    matcher.expression = rule.statuses.map((s) => `{http.error.status_code} == ${s}`).join(" || ");
  }
  const route: CaddyHttpRoute = {
    handle: [
      {
        handler: "static_response",
        status_code: "{http.error.status_code}",
        body: escapeHostPlaceholders(rule.body),
        headers: { "Content-Type": [escapeHostPlaceholders(rule.contentType || "text/html; charset=utf-8")] },
      },
    ],
    terminal: true,
  };
  if (Object.keys(matcher).length > 0) {
    route.match = [matcher];
  }
  return route;
}

/**
 * For every route of `routes` from `start` on whose handlers include one of
 * `checks` (the sign-in check), puts a twin right before it for the clients
 * `source` matches: the same host and path, without the sign-in check and
 * with the route's other handlers. Several routes that differ only in what
 * the twin ignores (browser or API client) share one twin. Routes that ask
 * for no sign-in get none.
 */
function insertSourceBypassRoutes(
  routes: CaddyHttpRoute[],
  start: number,
  checks: ReadonlySet<unknown>,
  source: Record<string, unknown>
): void {
  const out: CaddyHttpRoute[] = [];
  const twins = new Set<string>();
  for (const route of routes.slice(start)) {
    const handle = (route.handle as unknown[] | undefined) ?? [];
    if (!handle.some((handler) => checks.has(handler))) {
      out.push(route);
      continue;
    }
    const twin: CaddyHttpRoute = {
      match: ((route.match as Array<Record<string, unknown>> | undefined) ?? []).map(({ host, path }) => ({
        ...(host !== undefined ? { host } : {}),
        ...(path !== undefined ? { path } : {}),
        ...source
      })),
      handle: JSON.parse(JSON.stringify(handle.filter((handler) => !checks.has(handler)))),
      terminal: true
    };
    const key = JSON.stringify(twin);
    if (!twins.has(key)) {
      twins.add(key);
      out.push(twin);
    }
    out.push(route);
  }
  routes.splice(start, routes.length - start, ...out);
}

async function buildProxyRoutes(
  rows: ProxyHostRow[],
  accessAccounts: Map<number, AccessListEntryRow[]>,
  tlsReadyCertificates: Set<number>,
  options: BuildProxyRoutesOptions
): Promise<{ routes: CaddyHttpRoute[]; errorRoutes: CaddyHttpRoute[]; namedRoutes: Record<string, CaddyHttpRoute> }> {
  const routes: CaddyHttpRoute[] = [];
  const errorRoutes: CaddyHttpRoute[] = [];
  const namedRoutes: Record<string, CaddyHttpRoute> = {};
  const validClientCertExpression = buildValidClientCertCelExpression();
  const rateLimitDefaults = options.globalRateLimit ?? null;
  const rateLimitCtx = rateLimitContext(rateLimitDefaults);

  for (const row of rows) {
    if (!row.enabled) {
      continue;
    }

    // Allow hosts with certificateId = null (Caddy Auto) or with valid certificate IDs
    const isAutoManaged = !row.certificateId;
    const hasValidCertificate = row.certificateId && tlsReadyCertificates.has(row.certificateId);

    if (!isAutoManaged && !hasValidCertificate) {
      continue;
    }

    const domains = parseJson<string[]>(row.domains, []);
    if (domains.length === 0) {
      continue;
    }
    const domainGroups = groupHostPatternsByPriority(domains);

    // Require upstreams
    const upstreams = parseJson<string[]>(row.upstreams, []);
    if (upstreams.length === 0) {
      continue;
    }

    const handlers: Record<string, unknown>[] = [];
    const meta = parseJson<ProxyHostMeta>(row.meta, {});
    const authentik = parseAuthentikConfig(meta.authentik);
    const forwardAuth = parseForwardAuthConfig(meta.forward_auth);
    const ingressiForwardAuth = meta.cpm_forward_auth?.enabled ? meta.cpm_forward_auth : null;
    const hostRoutes: CaddyHttpRoute[] = [];

    const effectiveGeoBlock = resolveEffectiveGeoBlock(
      options.globalGeoBlock ?? null,
      { geoblock: meta.geoblock ?? null, geoblock_mode: meta.geoblock_mode ?? "merge" }
    );
    if (effectiveGeoBlock?.enabled) {
      handlers.unshift(buildBlockerHandler(effectiveGeoBlock));
    }

    // Access list rules (address, country and AS number rules), right after
    // geo blocking and before path blocks, redirects and the list's basic
    // auth below. The WAF and rate limiting are put in front of both.
    const accessListInvoke = row.accessListId ? options.accessListInvokes?.get(row.accessListId) : undefined;
    if (accessListInvoke) {
      handlers.push(accessListInvoke);
    }

    const effectiveWaf = resolveEffectiveWaf(
      options.globalWaf ?? null,
      meta.waf
    );
    if (effectiveWaf?.enabled && effectiveWaf.mode !== 'Off') {
      handlers.unshift(
        buildWafHandlerEntry(
          effectiveWaf,
          Boolean(row.allowWebsocket),
          wafDirectiveSource(options.globalWaf ?? null, meta.waf, `proxy host "${row.name}" (${domains.join(", ")})`),
          wafExclusionsForHost(options.wafExclusions ?? [], row.id, meta.waf)
        )
      );
    }

    // Rate limiting: the client-IP and header limiters run first on every
    // route of the host, before the WAF and geo blocking (so floods do not
    // cost WAF inspection), path blocks, redirects, basic auth, the
    // monetization gate (whose per-consumer limit applies after this one),
    // forward auth and the upstream. Rules keyed by the signed-in user need
    // Ingressi forward auth's user header, so they run right before the
    // upstream instead (rateLimit.beforeUpstream, below). Both are named
    // routes, so each limiter exists once per host. See caddy-rate-limit.ts.
    const usesIngressiForwardAuth = !authentik && !forwardAuth && Boolean(ingressiForwardAuth);
    const rateLimit = buildHostRateLimit(
      row.id,
      resolveEffectiveRateLimitRules(rateLimitDefaults, readStoredHostRateLimit(meta.rate_limit)),
      rateLimitCtx,
      usesIngressiForwardAuth
    );
    Object.assign(namedRoutes, rateLimit.namedRoutes);
    if (rateLimit.early) {
      handlers.unshift(rateLimit.early);
    }
    const earlyRateLimit: Record<string, unknown>[] = rateLimit.early ? [rateLimit.early] : [];

    // API monetization: client copies of the gate's headers are removed
    // first, on every route of the host; the gate itself runs below, where
    // an access list's basic auth would (monetization replaces it).
    const monetized = options.monetization?.hostIds.has(row.id) ? options.monetization : null;
    if (monetized) {
      handlers.unshift(buildMonetizationStripHandler());
    }

    if (row.hstsEnabled) {
      const value = row.hstsSubdomains ? "max-age=63072000; includeSubDomains" : "max-age=63072000";
      handlers.push({
        handler: "headers",
        response: {
          set: {
            "Strict-Transport-Security": [value]
          }
        }
      });
    }

    if (row.sslForced) {
      for (const domainGroup of domainGroups) {
        hostRoutes.push({
          match: [
            {
              host: domainGroup,
              expression: '{http.request.scheme} == "http"'
            }
          ],
          handle: [
            {
              handler: "static_response",
              status_code: 308,
              headers: {
                Location: ["https://{http.request.host}{http.request.uri}"]
              }
            }
          ],
          terminal: true
        });
      }
    }

    // Path blocks (terminal static_response) and path rewrites (URI rewrite).
    //
    // Path Allows are not emitted as standalone routes — a terminal match with
    // an empty handle would stop the subroute without falling through to the
    // reverse_proxy, returning an empty 200. Instead, every allow pattern is
    // folded into each block's matcher as a `not` clause: a block matches when
    // the request path matches the block pattern AND does not match any allow
    // pattern. Allowed requests therefore skip every block and exit the
    // subroute naturally, continuing to the outer reverse_proxy. Allows do not
    // affect rewrites — those keep their original matchers.
    const pathAllows = meta.path_allows ?? [];
    const pathBlocks = meta.path_blocks ?? [];
    const pathRewrites = meta.path_rewrites ?? [];
    if (pathBlocks.length > 0 || pathRewrites.length > 0) {
      const allowPatterns = pathAllows
        .map((a) => stripPlaceholders(a.path))
        .filter((p) => p.length > 0);
      const pathRoutes: CaddyHttpRoute[] = [];
      for (const block of pathBlocks) {
        // Sanitize path to prevent Caddy placeholder injection
        const safePath = stripPlaceholders(block.path);
        if (!safePath) continue;
        const handle: Record<string, unknown> = {
          handler: "static_response",
          status_code: block.status,
        };
        if (block.body) {
          handle.body = escapeHostPlaceholders(block.body);
        }
        const matcher: Record<string, unknown> = { path: [safePath] };
        if (allowPatterns.length > 0) {
          matcher.not = [{ path: allowPatterns }];
        }
        pathRoutes.push({
          match: [matcher],
          handle: [handle],
          terminal: true,
        });
      }
      for (const rw of pathRewrites) {
        const safeFrom = stripPlaceholders(rw.from);
        const safeTo = stripPlaceholders(rw.to);
        if (!safeFrom || !safeTo) continue;
        pathRoutes.push({
          match: [{ path: [safeFrom] }],
          handle: [{
            handler: "rewrite",
            uri: safeTo,
          }],
        });
      }
      if (pathRoutes.length > 0) {
        handlers.push({
          handler: "subroute",
          routes: pathRoutes,
        });
      }
    }

    // Structured redirects — emitted before auth so .well-known paths work without login
    if (meta.redirects && meta.redirects.length > 0) {
      const redirectRoutes = meta.redirects.map((rule) => ({
        match: [{ path: [rule.from] }],
        handle: [{
          handler: "static_response",
          status_code: rule.status,
          headers: { Location: [escapeHostPlaceholders(rule.to)] },
        }],
      }));
      handlers.push({
        handler: "subroute",
        routes: redirectRoutes,
      });
    }

    if (row.accessListId) {
      const accounts = accessAccounts.get(row.accessListId) ?? [];
      if (accounts.length > 0) {
        handlers.push({
          handler: "authentication",
          providers: {
            http_basic: {
              accounts: accounts.map((entry) => ({
                username: entry.username,
                password: entry.passwordHash
              }))
            }
          }
        });
      }
    }

    if (monetized) {
      handlers.push(buildMonetizationGateHandler(row.id, monetized.gateToken));
    }

    const lbConfig = parseLoadBalancerConfig(meta.load_balancer);
    const dnsConfig = parseDnsResolverConfig(meta.dns_resolver);
    const hostDnsResolutionConfig = parseUpstreamDnsResolutionConfig(meta.upstream_dns_resolution);
    const effectiveDnsResolution = resolveEffectiveUpstreamDnsResolution(
      options.globalUpstreamDnsResolutionSettings,
      hostDnsResolutionConfig
    );
    const resolvedUpstreams = await resolveUpstreamDials(
      row,
      upstreams,
      dnsConfig,
      options.globalDnsSettings,
      effectiveDnsResolution
    );

    const reverseProxyHandler: Record<string, unknown> = {
      handler: "reverse_proxy",
      upstreams: resolvedUpstreams.upstreams
    };

    // Authentik outpost handler will be added later after protected paths
    let outpostRoute: CaddyHttpRoute | null = null;
    if (authentik) {
      // Parse the outpost upstream URL to extract host:port for Caddy's dial field
      let outpostDial: string;
      try {
        const url = new URL(authentik.outpostUpstream);
        const port = url.port || (url.protocol === "https:" ? "443" : "80");
        outpostDial = `${url.hostname}:${port}`;
      } catch {
        // If URL parsing fails, try to extract host:port from string
        outpostDial = authentik.outpostUpstream.replace(/^https?:\/\//, "").replace(/\/$/, "");
      }

      const outpostHandler: Record<string, unknown> = {
        handler: "reverse_proxy",
        upstreams: [
          {
            dial: outpostDial
          }
        ]
      };

      if (authentik.setOutpostHostHeader) {
        outpostHandler.headers = {
          request: {
            set: {
              Host: ["{http.reverse_proxy.upstream.host}"]
            }
          }
        };
      }

      outpostRoute = {
        match: [
          {
            // Sanitize outpostDomain to prevent path traversal and placeholder injection
            path: [`/${stripPlaceholders(authentik.outpostDomain.replace(/\.\./g, '')).replace(/\/+/g, '/')}/*`]
          }
        ],
        handle: [...earlyRateLimit, outpostHandler],
        terminal: true
      };
    }

    if (row.preserveHostHeader) {
      reverseProxyHandler.headers = {
        request: {
          set: {
            Host: ["{http.request.host}"]
          }
        }
      };
    }

    // Configure TLS transport for HTTPS upstreams
    if (resolvedUpstreams.hasHttpsUpstream) {
      const tlsTransport: Record<string, unknown> = row.skipHttpsHostnameValidation
        ? {
            insecure_skip_verify: true
          }
        : {};
      if (resolvedUpstreams.httpsTlsServerName) {
        tlsTransport.server_name = resolvedUpstreams.httpsTlsServerName;
      }

      reverseProxyHandler.transport = {
        protocol: "http",
        tls: tlsTransport
      };
    }

    // Configure load balancing and health checks
    if (lbConfig) {
      const loadBalancing = buildLoadBalancingConfig(lbConfig);
      if (loadBalancing) {
        reverseProxyHandler.load_balancing = loadBalancing;
      }
      const healthChecks = buildHealthChecksConfig(lbConfig);
      if (healthChecks) {
        reverseProxyHandler.health_checks = healthChecks;
      }
    }

    // Add transport-level DNS resolver config if enabled
    if (dnsConfig && dnsConfig.enabled && dnsConfig.resolvers.length > 0) {
      const resolverConfig = buildResolverConfig(dnsConfig);
      if (resolverConfig) {
        // Merge resolver into existing transport (preserving TLS settings for HTTPS upstreams)
        if (reverseProxyHandler.transport) {
          (reverseProxyHandler.transport as Record<string, unknown>).resolver = resolverConfig;
          if (dnsConfig.timeout) {
            (reverseProxyHandler.transport as Record<string, unknown>).dial_timeout = dnsConfig.timeout;
          }
        } else {
          // No existing transport, create one with resolver
          reverseProxyHandler.transport = {
            protocol: "http",
            resolver: resolverConfig,
            ...(dnsConfig.timeout ? { dial_timeout: dnsConfig.timeout } : {})
          };
        }
      }
    }

    // Security: This field allows admins to inject arbitrary Caddy reverse_proxy config.
    // This is intentional — admins have full control of the proxy configuration.
    // Prototype pollution is prevented by mergeDeep blocking __proto__/constructor/prototype.
    const customReverseProxy = parseOptionalJson(meta.custom_reverse_proxy_json);
    if (customReverseProxy) {
      if (isPlainObject(customReverseProxy)) {
        mergeDeep(reverseProxyHandler, customReverseProxy as Record<string, unknown>);
      } else {
        console.warn("Ignoring custom reverse proxy JSON because it is not an object", customReverseProxy);
      }
    }

    // Structured path prefix rewrite
    // Sanitize path_prefix to prevent Caddy placeholder injection
    if (meta.rewrite?.path_prefix) {
      const safePrefix = stripPlaceholders(meta.rewrite.path_prefix);
      if (safePrefix) {
        handlers.push({
          handler: "rewrite",
          uri: `${safePrefix}{http.request.uri}`,
        });
      }
    }

    // Security: This field allows admins to inject arbitrary Caddy HTTP handlers.
    // This is intentional — admins can add any handler (file_server, rewrite, etc.)
    // before the reverse_proxy handler in the chain.
    const customHandlers = parseCustomHandlers(meta.custom_pre_handlers_json);
    if (customHandlers.length > 0) {
      handlers.push(...customHandlers);
    }

    // Clients whose address the host lets skip sign-in. For every route that
    // asks for sign-in, a twin goes right before it (insertSourceBypassRoutes):
    // same host and path, matched on the client address, with the same
    // handlers (WAF, rate limits, access list, path rules, identity-header
    // stripping) except the sign-in check. The server's routes are finally
    // ordered by host and path with ties kept in this order, so the twin wins
    // over the route it copies and over no other. The address is matched as
    // access list rules match it. An empty list adds nothing.
    const sourceMatcher = (sources: readonly string[]): Record<string, unknown> | null => {
      const ranges = Array.from(new Set(expandPrivateRanges([...sources])));
      if (ranges.length === 0) return null;
      return { [addressMatcherName({ trustedProxies: options.trustedProxies ?? [] })]: { ranges } };
    };
    // The handlers that check for sign-in, and the match of the clients that skip it.
    const signInChecks = new Set<unknown>();
    let signInBypass: Record<string, unknown> | null = null;
    const providerStart = hostRoutes.length;

    if (authentik) {
      // Build handle_response routes for copying headers on 2xx status
      const handleResponseRoutes = buildAuthResponseCopyRoutes(authentik.copyHeaders);

      // Create the forward auth reverse_proxy handler
      // Convert "private_ranges" to actual CIDR blocks for JSON config
      const trustedProxies = authentik.trustedProxies.includes("private_ranges")
        ? ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fd00::/8", "::1/128"]
        : authentik.trustedProxies;

      // Parse the outpost upstream to extract host:port for dial
      // Remove http://, https://, and any trailing slashes
      let dialAddress = authentik.outpostUpstream.replace(/^https?:\/\//, "").replace(/\/$/, "");
      // Remove any path portion if accidentally included
      dialAddress = dialAddress.split("/")[0];

      const forwardAuthHandler: Record<string, unknown> = {
        handler: "reverse_proxy",
        upstreams: [
          {
            dial: dialAddress
          }
        ],
        rewrite: {
          method: "GET",
          uri: authentik.authEndpoint
        },
        headers: {
          request: {
            set: {
              "X-Forwarded-Method": ["{http.request.method}"],
              "X-Forwarded-Uri": ["{http.request.uri}"]
            },
            delete: [...FORWARD_AUTH_SUBREQUEST_STRIP_HEADERS]
          }
        },
        handle_response: [
          {
            match: {
              status_code: [2]
            },
            routes: handleResponseRoutes
          }
        ]
      };

      if (trustedProxies.length > 0) {
        forwardAuthHandler.trusted_proxies = trustedProxies;
      }

      // Security: client-supplied copies of the identity headers are deleted on
      // every route that reaches the upstream. The copy step above only sets a
      // header when the outpost response carries a non-empty value, and
      // unprotected routes never consult the outpost at all.
      const authentikStripHandler = buildIdentityHeaderStripHandler(authentik.copyHeaders);
      const akHandlers: Record<string, unknown>[] = authentikStripHandler
        ? [authentikStripHandler, ...handlers]
        : handlers;

      signInChecks.add(forwardAuthHandler);
      signInBypass = sourceMatcher(authentik.bypassSources);

      // Path-based authentication support
      if (authentik.protectedPaths && authentik.protectedPaths.length > 0) {
        // Whitelist mode: only specified paths get auth
        for (const domainGroup of domainGroups) {
          // Create separate routes for each protected path
          for (const protectedPath of authentik.protectedPaths) {
            const protectedHandlers: Record<string, unknown>[] = [...akHandlers];
            const protectedReverseProxy = JSON.parse(JSON.stringify(reverseProxyHandler));

            protectedHandlers.push(forwardAuthHandler);
            protectedHandlers.push(protectedReverseProxy);

            hostRoutes.push({
              match: [
                {
                  host: domainGroup,
                  path: [protectedPath]
                }
              ],
              handle: protectedHandlers,
              terminal: true
            });
          }

          if (outpostRoute) {
            const outpostMatches = (outpostRoute.match as Array<Record<string, unknown>> | undefined) ?? [];
            hostRoutes.push({
              ...outpostRoute,
              match: outpostMatches.map((match) => ({
                ...match,
                host: domainGroup
              }))
            });
          }

          // Location rules are unprotected (no forwardAuthHandler), matching the catch-all
          // behavior when protected_paths is configured — only explicitly protected paths get auth.
          const locationRules = meta.location_rules ?? [];
          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath] }],
              handle: [...akHandlers, locationProxy],
              terminal: true,
            });
          }

          const unprotectedHandlers: Record<string, unknown>[] = [...akHandlers, reverseProxyHandler];

          hostRoutes.push({
            match: [{ host: domainGroup }],
            handle: unprotectedHandlers,
            terminal: true
          });
        }
      } else if (authentik.excludedPaths && authentik.excludedPaths.length > 0) {
        // Exclusion mode: protect everything EXCEPT specified paths
        const locationRules = meta.location_rules ?? [];
        for (const domainGroup of domainGroups) {
          if (outpostRoute) {
            const outpostMatches = (outpostRoute.match as Array<Record<string, unknown>> | undefined) ?? [];
            hostRoutes.push({
              ...outpostRoute,
              match: outpostMatches.map((match) => ({
                ...match,
                host: domainGroup
              }))
            });
          }

          // Create unprotected routes for each excluded path (before the catch-all)
          for (const excludedPath of authentik.excludedPaths) {
            hostRoutes.push({
              match: [{ host: domainGroup, path: [excludedPath] }],
              handle: [...akHandlers, JSON.parse(JSON.stringify(reverseProxyHandler))],
              terminal: true
            });
          }

          // Location rules get auth (same as full-site mode)
          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath] }],
              handle: [...akHandlers, forwardAuthHandler, locationProxy],
              terminal: true,
            });
          }

          // Catch-all with auth (everything not excluded)
          hostRoutes.push({
            match: [{ host: domainGroup }],
            handle: [...akHandlers, forwardAuthHandler, reverseProxyHandler],
            terminal: true
          });
        }
      } else {
        // Full-site mode: protect everything
        const locationRules = meta.location_rules ?? [];
        for (const domainGroup of domainGroups) {
          if (outpostRoute) {
            const outpostMatches = (outpostRoute.match as Array<Record<string, unknown>> | undefined) ?? [];
            hostRoutes.push({
              ...outpostRoute,
              match: outpostMatches.map((match) => ({
                ...match,
                host: domainGroup
              }))
            });
          }

          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath] }],
              handle: [...akHandlers, forwardAuthHandler, locationProxy],
              terminal: true,
            });
          }

          const routeHandlers: Record<string, unknown>[] = [...akHandlers, forwardAuthHandler, reverseProxyHandler];
          const route: CaddyHttpRoute = {
            match: [{ host: domainGroup }],
            handle: routeHandlers,
            terminal: true
          };
          hostRoutes.push(route);
        }
      }
    } else if (forwardAuth) {
      // ── Generic Forward Auth (Authelia etc., issue #188) ────────────
      // Split browser vs API authentication:
      //
      //  - Browser requests (Accept: text/html, no X-Requested-With) go
      //    through the plain forward-auth handler: the auth server's 302
      //    "go log in" response passes through untouched so the browser is
      //    redirected to the auth portal.
      //
      //  - Non-browser requests (API clients, WebSocket handshakes) go
      //    through a handler that converts the auth server's 3xx redirect
      //    into a bare 401 (apiSplit), so machine clients get a machine
      //    error instead of an HTML login page.
      //
      //  - Requests carrying any apiBypassHeaders header skip forward auth
      //    entirely and reach the upstream, which performs its own API-key
      //    / Authorization check (e.g. Moonraker's X-Api-Key).
      //
      // Security: the identity headers copied from the auth server's 2xx
      // response (Remote-User, Remote-Groups, ...) are STRIPPED from every
      // inbound request before it reaches the upstream — on protected and
      // unprotected routes alike. Without this a caller could forge their
      // identity directly to the upstream: on unauthenticated routes the
      // forged headers would pass straight through, and on authenticated
      // routes the copy step only overwrites a header when the verify
      // response value is non-empty. Same class of fix as the X-Ingressi-*
      // stripping below (SECURITY-AUDIT H1).
      const faStripHandler = buildIdentityHeaderStripHandler(forwardAuth.copyHeaders);
      const faHandlers = faStripHandler ? [faStripHandler, ...handlers] : handlers;

      const browserMatcher: Record<string, unknown> = {
        header: { Accept: ["*text/html*"] },
        // Caddy's `not` matcher takes an ARRAY of matcher sets.
        not: [{ header: { "X-Requested-With": ["*"] } }]
      };

      const browserFaHandler = buildGenericForwardAuthHandler(forwardAuth, false);
      const apiFaHandler = forwardAuth.apiSplit ? buildGenericForwardAuthHandler(forwardAuth, true) : null;
      signInChecks.add(browserFaHandler);
      if (apiFaHandler) signInChecks.add(apiFaHandler);
      signInBypass = sourceMatcher(forwardAuth.bypassSources);

      const locationRules = meta.location_rules ?? [];

      for (const domainGroup of domainGroups) {
        // API-key bypass routes first — they must win over both auth routes.
        for (const bypassHeader of forwardAuth.apiBypassHeaders) {
          hostRoutes.push({
            match: [{ host: domainGroup, header: { [bypassHeader]: ["*"] } }],
            handle: [...faHandlers, JSON.parse(JSON.stringify(reverseProxyHandler))],
            terminal: true
          });
        }

        if (forwardAuth.protectedPaths && forwardAuth.protectedPaths.length > 0) {
          // Whitelist mode: only the listed paths get auth.
          for (const protectedPath of forwardAuth.protectedPaths) {
            const pathMatch: Record<string, unknown> = { host: domainGroup, path: [protectedPath] };
            const protectedProxy = JSON.parse(JSON.stringify(reverseProxyHandler));
            if (apiFaHandler) {
              hostRoutes.push({
                match: [{ ...pathMatch, ...browserMatcher }],
                handle: [...faHandlers, browserFaHandler, protectedProxy],
                terminal: true
              });
              hostRoutes.push({
                match: [{ ...pathMatch }],
                handle: [...faHandlers, apiFaHandler, JSON.parse(JSON.stringify(reverseProxyHandler))],
                terminal: true
              });
            } else {
              hostRoutes.push({
                match: [{ ...pathMatch }],
                handle: [...faHandlers, browserFaHandler, protectedProxy],
                terminal: true
              });
            }
          }

          // Location rules are unprotected (no forward auth), matching the
          // catch-all behavior in whitelist mode.
          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath] }],
              handle: [...faHandlers, locationProxy],
              terminal: true
            });
          }

          // Unprotected catch-all.
          hostRoutes.push({
            match: [{ host: domainGroup }],
            handle: [...faHandlers, reverseProxyHandler],
            terminal: true
          });
        } else {
          // Exclusion / full-site mode.
          for (const excludedPath of forwardAuth.excludedPaths ?? []) {
            hostRoutes.push({
              match: [{ host: domainGroup, path: [excludedPath] }],
              handle: [...faHandlers, JSON.parse(JSON.stringify(reverseProxyHandler))],
              terminal: true
            });
          }

          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            if (apiFaHandler) {
              hostRoutes.push({
                match: [{ host: domainGroup, path: [safePath], ...browserMatcher }],
                handle: [...faHandlers, browserFaHandler, locationProxy],
                terminal: true
              });
              hostRoutes.push({
                match: [{ host: domainGroup, path: [safePath] }],
                handle: [...faHandlers, apiFaHandler, JSON.parse(JSON.stringify(locationProxy))],
                terminal: true
              });
            } else {
              hostRoutes.push({
                match: [{ host: domainGroup, path: [safePath] }],
                handle: [...faHandlers, browserFaHandler, locationProxy],
                terminal: true
              });
            }
          }

          // Browser catch-all: forward auth with the portal redirect flow.
          // Without apiSplit a single unified catch-all handles everything.
          if (apiFaHandler) {
            hostRoutes.push({
              match: [{ host: domainGroup, ...browserMatcher }],
              handle: [...faHandlers, browserFaHandler, JSON.parse(JSON.stringify(reverseProxyHandler))],
              terminal: true
            });

            // API/WebSocket catch-all: 3xx from the auth server becomes 401.
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [...faHandlers, apiFaHandler, reverseProxyHandler],
              terminal: true
            });
          } else {
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [...faHandlers, browserFaHandler, reverseProxyHandler],
              terminal: true
            });
          }
        }
      }
    } else if (ingressiForwardAuth) {
      // ── Ingressi Forward Auth ───────────────────────────────────────
      // Uses the dashboard itself as the auth provider (replaces Authentik).
      // Verify only reads and a sign-in code is redeemed at most once, so
      // both may be retried on another dashboard replica.
      const dashboardUpstreams = getDashboardUpstreams();
      if (dashboardUpstreams.length > 0) {
        const dashboardProxyProof = getForwardAuthProxyProof();

        // Security: strip any client-supplied identity headers, current and
        // legacy names, from the inbound request before it ever reaches the
        // upstream. These headers are injected solely by the dashboard from
        // the verify response; accepting them
        // from the client would let a caller spoof their identity / group
        // membership to upstream apps. This must run on EVERY route — protected,
        // unprotected catch-all, excluded, and location — because on routes
        // without the auth handler nothing else would remove them, and on
        // authenticated routes the copy step below only overwrites a header
        // when the verify response value is non-empty (e.g. a user in no group
        // returns an empty X-Ingressi-Groups, which would otherwise leave the
        // client's forged value intact).
        const identityStripHandler = buildIdentityHeaderStripHandler(FORWARD_AUTH_COPY_HEADERS)!;
        // Prepend the strip handler to the shared handler chain for all
        // built-in forward-auth routes.
        const ingressiHandlers = [identityStripHandler, ...handlers];
        // The signed-in-user limiter, after the verify handler set the user
        // header and right before the upstream, on every route of the host.
        const toUpstream = (proxy: Record<string, unknown>): Record<string, unknown>[] =>
          rateLimit.beforeUpstream ? [rateLimit.beforeUpstream, proxy] : [proxy];

        // Build handle_response routes for copying user headers on 2xx
        const identityCopyRoutes: Record<string, unknown>[] = [
          { handle: [{ handler: "vars" }] }
        ];
        for (const headerName of FORWARD_AUTH_COPY_HEADERS) {
          const placeholder = authResponseHeaderPlaceholder(headerName);
          identityCopyRoutes.push({
            handle: [
              {
                handler: "headers",
                request: {
                  set: { [headerName]: [placeholder] }
                }
              } as Record<string, unknown>
            ],
            match: [
              {
                not: [{ vars: { [placeholder]: [""] } }]
              }
            ]
          });
        }

        // Redirect to the portal on 401/403.  The verify endpoint supplies the
        // protected URL already encoded for the portal's query string, so "&",
        // "#", "+" and "%" in it survive.  Should the header be missing, the
        // second route escapes the whole request URI itself.
        const portalTargetPlaceholder = authResponseHeaderPlaceholder(FORWARD_AUTH_PORTAL_TARGET_HEADER);
        const portalRedirect = (location: string): Record<string, unknown> => ({
          handler: "static_response",
          status_code: 302,
          headers: { Location: [location] }
        });
        const portalRedirectRoutes: Record<string, unknown>[] = [
          {
            match: [{ not: [{ vars: { [portalTargetPlaceholder]: [""] } }] }],
            handle: [portalRedirect(`${config.baseUrl}/portal?rd=${portalTargetPlaceholder}`)]
          },
          {
            handle: [
              portalRedirect(
                `${config.baseUrl}/portal?rd={http.request.scheme}://{http.request.hostport}{http.request.uri_escaped}`
              )
            ]
          }
        ];

        // Forward auth handler — subrequest to the dashboard's verify endpoint
        const verifyHandler: Record<string, unknown> = {
          handler: "reverse_proxy",
          ...dashboardProxyFields(dashboardUpstreams, { retryAfterSend: true }),
          rewrite: {
            method: "GET",
            uri: "/api/forward-auth/verify"
          },
          headers: {
            request: {
              set: {
                "X-Forwarded-Method": ["{http.request.method}"],
                "X-Forwarded-Uri": ["{http.request.uri}"],
                "X-Forwarded-Host": ["{http.request.hostport}"],
                "X-Forwarded-Proto": ["{http.request.scheme}"],
                [FORWARD_AUTH_PROXY_PROOF_HEADER]: [dashboardProxyProof],
                [FORWARD_AUTH_PROXY_HOST_ID_HEADER]: [String(row.id)]
              },
              delete: [...FORWARD_AUTH_SUBREQUEST_STRIP_HEADERS]
            }
          },
          handle_response: [
            {
              match: { status_code: [2] },
              routes: identityCopyRoutes
            },
            {
              match: { status_code: [401, 403] },
              routes: portalRedirectRoutes
            }
          ],
          trusted_proxies: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fd00::/8", "::1/128"]
        };

        // Callback route — unprotected, so it goes before forward_auth. The
        // legacy path stays routed for sign-ins started before an upgrade.
        const callbackPaths = [FORWARD_AUTH_CALLBACK_PATH, LEGACY_FORWARD_AUTH_CALLBACK_PATH];
        const callbackRoute: CaddyHttpRoute = {
          match: [{ path: callbackPaths }],
          handle: [
            ...earlyRateLimit,
            {
              handler: "reverse_proxy",
              ...dashboardProxyFields(dashboardUpstreams, { retryAfterSend: true }),
              rewrite: {
                uri: "/api/forward-auth/callback?{http.request.uri.query}"
              },
              headers: {
                request: {
                  set: {
                    "X-Forwarded-Host": ["{http.request.hostport}"],
                    "X-Forwarded-Proto": ["{http.request.scheme}"],
                    [FORWARD_AUTH_PROXY_PROOF_HEADER]: [dashboardProxyProof],
                    [FORWARD_AUTH_PROXY_HOST_ID_HEADER]: [String(row.id)]
                  }
                }
              }
            }
          ],
          terminal: true
        };

        const locationRules = meta.location_rules ?? [];

        signInChecks.add(verifyHandler);
        signInBypass = sourceMatcher(readBypassSources(ingressiForwardAuth.bypass_sources));

        if (ingressiForwardAuth.protected_paths && ingressiForwardAuth.protected_paths.length > 0) {
          // Whitelist mode: only specified paths get auth
          for (const domainGroup of domainGroups) {
            // Add callback route (unprotected)
            hostRoutes.push({
              ...callbackRoute,
              match: [{ host: domainGroup, path: callbackPaths }]
            });

            // Protected paths
            for (const protectedPath of ingressiForwardAuth.protected_paths) {
              const protectedHandlers: Record<string, unknown>[] = [...ingressiHandlers];
              const protectedReverseProxy = JSON.parse(JSON.stringify(reverseProxyHandler));
              protectedHandlers.push(verifyHandler);
              protectedHandlers.push(...toUpstream(protectedReverseProxy));

              hostRoutes.push({
                match: [{ host: domainGroup, path: [protectedPath] }],
                handle: protectedHandlers,
                terminal: true
              });
            }

            // Location rules (unprotected)
            for (const rule of locationRules) {
              const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
                rule,
                Boolean(row.skipHttpsHostnameValidation),
                Boolean(row.preserveHostHeader)
              );
              if (!safePath) continue;
              hostRoutes.push({
                match: [{ host: domainGroup, path: [safePath] }],
                handle: [...ingressiHandlers, ...toUpstream(locationProxy)],
                terminal: true
              });
            }

            // Unprotected catch-all
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [...ingressiHandlers, ...toUpstream(reverseProxyHandler)],
              terminal: true
            });
          }
        } else if (ingressiForwardAuth.excluded_paths && ingressiForwardAuth.excluded_paths.length > 0) {
          // Exclusion mode: protect everything EXCEPT specified paths
          for (const domainGroup of domainGroups) {
            // Callback route first (unprotected)
            hostRoutes.push({
              ...callbackRoute,
              match: [{ host: domainGroup, path: callbackPaths }]
            });

            // Excluded paths — unprotected, before the catch-all
            for (const excludedPath of ingressiForwardAuth.excluded_paths) {
              hostRoutes.push({
                match: [{ host: domainGroup, path: [excludedPath] }],
                handle: [...ingressiHandlers, ...toUpstream(JSON.parse(JSON.stringify(reverseProxyHandler)))],
                terminal: true
              });
            }

            // Location rules with forward auth
            for (const rule of locationRules) {
              const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
                rule,
                Boolean(row.skipHttpsHostnameValidation),
                Boolean(row.preserveHostHeader)
              );
              if (!safePath) continue;
              hostRoutes.push({
                match: [{ host: domainGroup, path: [safePath] }],
                handle: [...ingressiHandlers, verifyHandler, ...toUpstream(locationProxy)],
                terminal: true
              });
            }

            // Catch-all with auth (everything not excluded)
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [...ingressiHandlers, verifyHandler, ...toUpstream(reverseProxyHandler)],
              terminal: true
            });
          }
        } else {
          // Full-site mode: protect everything
          for (const domainGroup of domainGroups) {
            // Callback route first (unprotected)
            hostRoutes.push({
              ...callbackRoute,
              match: [{ host: domainGroup, path: callbackPaths }]
            });

            // Location rules with forward auth
            for (const rule of locationRules) {
              const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
                rule,
                Boolean(row.skipHttpsHostnameValidation),
                Boolean(row.preserveHostHeader)
              );
              if (!safePath) continue;
              hostRoutes.push({
                match: [{ host: domainGroup, path: [safePath] }],
                handle: [...ingressiHandlers, verifyHandler, ...toUpstream(locationProxy)],
                terminal: true
              });
            }

            // Main route with forward auth
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [...ingressiHandlers, verifyHandler, ...toUpstream(reverseProxyHandler)],
              terminal: true
            });
          }
        }
      }
    } else {
      const locationRules = meta.location_rules ?? [];
      const mtls = meta.mtls?.enabled ? meta.mtls : null;
      const mtlsProtectedPaths = mtls?.protected_paths?.length ? mtls.protected_paths : null;
      const mtlsExcludedPaths = mtls?.excluded_paths?.length ? mtls.excluded_paths : null;

      // Check for mTLS RBAC access rules for this proxy host
      const hostAccessRules = options.mtlsRbac?.accessRulesByHost.get(row.id);
      const hasMtlsRbac = hostAccessRules && hostAccessRules.length > 0
        && options.mtlsRbac?.roleFingerprintMap && options.mtlsRbac?.certFingerprintMap;
      const hostTrustedFingerprints = mtls
        ? resolveAllowedFingerprints(
            {
              pathPattern: "*",
              allowedRoleIds: mtls.trusted_role_ids ?? [],
              allowedCertIds: mtls.trusted_client_cert_ids ?? [],
              denyAll: false,
            },
            options.mtlsRbac?.roleFingerprintMap ?? new Map(),
            options.mtlsRbac?.certFingerprintMap ?? new Map()
          )
        : new Set<string>();
      const hostTrustedFingerprintExpression = hostTrustedFingerprints.size > 0
        ? buildFingerprintCelExpression(hostTrustedFingerprints)
        : validClientCertExpression;

      for (const domainGroup of domainGroups) {
        const pushProtectedCatchAllRoute = () => {
          if (hasMtlsRbac) {
            const rbacSubroutes = buildMtlsRbacSubroutes(
              hostAccessRules,
              options.mtlsRbac!.roleFingerprintMap,
              options.mtlsRbac!.certFingerprintMap,
              handlers,
              reverseProxyHandler,
              true,
              hostTrustedFingerprints
            );
            if (rbacSubroutes) {
              hostRoutes.push({
                match: [{ host: domainGroup }],
                handle: [{ handler: "subroute", routes: rbacSubroutes }],
                terminal: true,
              });
              return;
            }
          }

          hostRoutes.push({
            match: [{ host: domainGroup, expression: hostTrustedFingerprintExpression }],
            handle: [...handlers, reverseProxyHandler],
            terminal: true,
          });
          hostRoutes.push({
            match: [{ host: domainGroup }],
            handle: [{ handler: "static_response", status_code: "403", body: "mTLS access denied" }],
            terminal: true,
          });
        };

        if (mtlsProtectedPaths) {
          for (const protectedPath of mtlsProtectedPaths) {
            if (hasMtlsRbac) {
              const rbacSubroutes = buildMtlsRbacSubroutes(
                hostAccessRules,
                options.mtlsRbac!.roleFingerprintMap,
                options.mtlsRbac!.certFingerprintMap,
                handlers,
                reverseProxyHandler,
                true,
                hostTrustedFingerprints
              );
              if (rbacSubroutes) {
                hostRoutes.push({
                  match: [{ host: domainGroup, path: [protectedPath] }],
                  handle: [{ handler: "subroute", routes: rbacSubroutes }],
                  terminal: true,
                });
                continue;
              }
            }

            hostRoutes.push({
              match: [{ host: domainGroup, path: [protectedPath], expression: hostTrustedFingerprintExpression }],
              handle: [...handlers, JSON.parse(JSON.stringify(reverseProxyHandler))],
              terminal: true,
            });
            hostRoutes.push({
              match: [{ host: domainGroup, path: [protectedPath] }],
              handle: [{ handler: "static_response", status_code: "403", body: "mTLS access denied" }],
              terminal: true,
            });
          }

          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath] }],
              handle: [...handlers, locationProxy],
              terminal: true,
            });
          }

          hostRoutes.push({
            match: [{ host: domainGroup }],
            handle: [...handlers, reverseProxyHandler],
            terminal: true,
          });
          continue;
        }

        if (mtlsExcludedPaths) {
          for (const excludedPath of mtlsExcludedPaths) {
            hostRoutes.push({
              match: [{ host: domainGroup, path: [excludedPath] }],
              handle: [...handlers, JSON.parse(JSON.stringify(reverseProxyHandler))],
              terminal: true,
            });
          }

          for (const rule of locationRules) {
            const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
              rule,
              Boolean(row.skipHttpsHostnameValidation),
              Boolean(row.preserveHostHeader)
            );
            if (!safePath) continue;
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath], expression: hostTrustedFingerprintExpression }],
              handle: [...handlers, locationProxy],
              terminal: true,
            });
            hostRoutes.push({
              match: [{ host: domainGroup, path: [safePath] }],
              handle: [{ handler: "static_response", status_code: "403", body: "mTLS access denied" }],
              terminal: true,
            });
          }

          pushProtectedCatchAllRoute();
          continue;
        }

        for (const rule of locationRules) {
          const { safePath, reverseProxyHandler: locationProxy } = buildLocationReverseProxy(
            rule,
            Boolean(row.skipHttpsHostnameValidation),
            Boolean(row.preserveHostHeader)
          );
          if (!safePath) continue;
          hostRoutes.push({
            match: [{ host: domainGroup, path: [safePath] }],
            handle: [...handlers, locationProxy],
            terminal: true,
          });
        }

        if (hasMtlsRbac) {
          const rbacSubroutes = buildMtlsRbacSubroutes(
            hostAccessRules,
            options.mtlsRbac!.roleFingerprintMap,
            options.mtlsRbac!.certFingerprintMap,
            handlers,
            reverseProxyHandler
          );
          if (rbacSubroutes) {
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [{
                handler: "subroute",
                routes: rbacSubroutes,
              }],
              terminal: true,
            });
          } else {
            hostRoutes.push({
              match: [{ host: domainGroup }],
              handle: [...handlers, reverseProxyHandler],
              terminal: true,
            });
          }
        } else {
          const route: CaddyHttpRoute = {
            match: [{ host: domainGroup }],
            handle: [...handlers, reverseProxyHandler],
            terminal: true,
          };
          hostRoutes.push(route);
        }
      }
    }

    if (signInBypass) {
      insertSourceBypassRoutes(hostRoutes, providerStart, signInChecks, signInBypass);
    }

    routes.push(...hostRoutes);

    // Per-host error pages, scoped to this host's domains. Collected separately so
    // they can be attached to the server-level `errors` block (handle_errors).
    if (meta.error_pages && meta.error_pages.length > 0) {
      for (const rule of meta.error_pages) {
        errorRoutes.push(buildErrorPageRoute(rule, domains));
      }
    }
  }

  return { routes: sortRoutesByHostPriority(routes), errorRoutes, namedRoutes };
}

function buildTlsConnectionPolicies(
  usage: Map<number, CertificateUsage>,
  managedCertificatesWithAutomation: Set<number>,
  autoManagedDomains: Set<string>,
  mTlsDomainMap: Map<string, number[]>,
  caCertMap: Map<number, { id: number; certificatePem: string }>,
  issuedClientCertMap: Map<number, string[]>,
  cAsWithAnyIssuedCerts: Set<number>,
  mTlsDomainLeafOverride: Map<string, string[]>,
  mTlsOptionalAuthDomains: Set<string>
) {
  const policies: Record<string, unknown>[] = [];
  const readyCertificates = new Set<number>();
  const importedCertPems: { certificate: string; key: string }[] = [];

  const buildAuth = (domains: string[], mode: "require_and_verify" | "verify_if_given" | "request") =>
    buildClientAuthentication(domains, mTlsDomainMap, caCertMap, issuedClientCertMap, cAsWithAnyIssuedCerts, mTlsDomainLeafOverride, mode);

  /**
   * Pushes one TLS policy per unique CA set found in `mTlsDomains`.
   * Domains that share the same CA configuration are grouped into one policy;
   * domains with different CAs get separate policies so a cert from CA_B cannot
   * authenticate against a host that only trusts CA_A.
   */
  const pushMtlsPolicies = (mTlsDomains: string[]) => {
    const scopedDomains = mTlsDomains.filter((domain) => mTlsOptionalAuthDomains.has(domain));
    const requiredDomains = mTlsDomains.filter((domain) => !mTlsOptionalAuthDomains.has(domain));

    for (const [domains, mode] of [
      [requiredDomains, "require_and_verify"],
      [scopedDomains, "request"],
    ] as const) {
      if (domains.length === 0) continue;

      const groups = groupMtlsDomainsByCaSet(domains, mTlsDomainMap, mTlsDomainLeafOverride);
      for (const domainGroup of groups.values()) {
        for (const priorityGroup of groupHostPatternsByPriority(domainGroup)) {
          const mTlsAuth = buildAuth(priorityGroup, mode);
          if (mTlsAuth) {
            policies.push({ match: { sni: priorityGroup }, client_authentication: mTlsAuth });
          } else {
            // All CAs have all certs revoked — drop connections rather than allow through without mTLS
            policies.push({ match: { sni: priorityGroup }, drop: true });
          }
        }
      }
    }
  };

  // Add policy for auto-managed domains (certificateId = null)
  if (autoManagedDomains.size > 0) {
    const domains = Array.from(autoManagedDomains);
    // Split first so mTLS domains always get their own policy, regardless of auth result.
    const mTlsDomains = domains.filter(d => mTlsDomainMap.has(d));
    const nonMTlsDomains = domains.filter(d => !mTlsDomainMap.has(d));

    if (mTlsDomains.length > 0) {
      pushMtlsPolicies(mTlsDomains);
    }
    for (const priorityGroup of groupHostPatternsByPriority(nonMTlsDomains)) {
      policies.push({ match: { sni: priorityGroup } });
    }
  }

  for (const [id, entry] of usage.entries()) {
    const domains = Array.from(entry.domains);
    if (domains.length === 0) {
      continue;
    }

    if (entry.certificate.type === "imported") {
      if (!entry.certificate.certificatePem || !entry.certificate.privateKeyPem) {
        continue;
      }

      // Collect PEMs for tls.certificates.load_pem (inline, no shared filesystem needed)
      importedCertPems.push({
        certificate: entry.certificate.certificatePem.trim(),
        key: entry.certificate.privateKeyPem.trim()
      });

      const mTlsDomains = domains.filter(d => mTlsDomainMap.has(d));
      const nonMTlsDomains = domains.filter(d => !mTlsDomainMap.has(d));

      if (mTlsDomains.length > 0) {
        pushMtlsPolicies(mTlsDomains);
      }
      for (const priorityGroup of groupHostPatternsByPriority(nonMTlsDomains)) {
        policies.push({ match: { sni: priorityGroup } });
      }

      readyCertificates.add(id);
      continue;
    }

    if (entry.certificate.type === "managed") {
      if (!managedCertificatesWithAutomation.has(id)) {
        continue;
      }

      const mTlsDomains = domains.filter(d => mTlsDomainMap.has(d));
      const nonMTlsDomains = domains.filter(d => !mTlsDomainMap.has(d));

      if (mTlsDomains.length > 0) {
        pushMtlsPolicies(mTlsDomains);
      }
      for (const priorityGroup of groupHostPatternsByPriority(nonMTlsDomains)) {
        policies.push({ match: { sni: priorityGroup } });
      }

      readyCertificates.add(id);
    }
  }

  return {
    policies: sortTlsPoliciesBySniPriority(policies),
    readyCertificates,
    importedCertPems
  };
}

export async function buildTlsAutomation(
  usage: Map<number, CertificateUsage>,
  autoManagedDomains: Set<string>,
  options: { acmeEmail?: string; dnsSettings?: DnsSettings | null; acmeSettings?: AcmeSettings | null }
) {
  const managedEntries = Array.from(usage.values()).filter(
    (entry) => entry.certificate.type === "managed" && Boolean(entry.certificate.autoRenew)
  );

  const hasAutoManagedDomains = autoManagedDomains.size > 0;

  if (managedEntries.length === 0 && !hasAutoManagedDomains) {
    return {
      managedCertificateIds: new Set<number>()
    };
  }

  const dnsProviderSettings = await getDnsProviderSettings();
  const globalDnsProvider: DnsProviderCredentials | null =
    dnsProviderSettings?.default && dnsProviderSettings.providers[dnsProviderSettings.default]
      ? { provider: dnsProviderSettings.default, credentials: dnsProviderSettings.providers[dnsProviderSettings.default] }
      : null;

  const dnsSettings = options.dnsSettings ?? await getDnsSettings();
  const hasDnsResolvers = dnsSettings && dnsSettings.enabled && dnsSettings.resolvers && dnsSettings.resolvers.length > 0;

  // Build DNS resolvers list (primary + fallbacks)
  const dnsResolvers: string[] = [];
  if (hasDnsResolvers) {
    dnsResolvers.push(...dnsSettings.resolvers);
    if (dnsSettings.fallbacks && dnsSettings.fallbacks.length > 0) {
      dnsResolvers.push(...dnsSettings.fallbacks);
    }
  }

  const managedCertificateIds = new Set<number>();
  const policies: Record<string, unknown>[] = [];

  // Custom ACME directory URL + trusted root for internal CAs (OpenBao, Step-CA, etc.)
  const acmeSettings = options.acmeSettings ?? await getAcmeSettings();
  const customAcmeUrl = acmeSettings?.caUrl?.trim() || null;
  const acmeRootPath = syncAcmeCaRootFile(acmeSettings?.caRootPem);

  const applyAcmeOverrides = (issuer: Record<string, unknown>) => {
    if (customAcmeUrl) {
      issuer.ca = customAcmeUrl;
    }
    if (acmeRootPath) {
      issuer.trusted_roots_pem_files = [acmeRootPath];
    }
  };

  // Add policy for auto-managed domains (certificateId = null)
  if (hasAutoManagedDomains) {
    for (const subjects of groupHostPatternsByPriority(Array.from(autoManagedDomains))) {
      const issuer: Record<string, unknown> = {
        module: "acme"
      };
      applyAcmeOverrides(issuer);

      if (options.acmeEmail) {
        issuer.email = options.acmeEmail;
      }

      if (globalDnsProvider) {
        const dnsChallenge = buildDnsChallengeConfig(
          globalDnsProvider.provider,
          globalDnsProvider.credentials,
          dnsResolvers
        );
        if (dnsChallenge) {
          issuer.challenges = { dns: dnsChallenge };
        }
      }

      policies.push({
        subjects,
        issuers: [issuer]
      });
    }
  }

  // Add policies for explicitly managed certificates
  for (const entry of managedEntries) {
    const subjects = Array.from(entry.domains);
    if (subjects.length === 0) {
      continue;
    }

    managedCertificateIds.add(entry.certificate.id);

    // Per-certificate provider override, falling back to global default
    let effectiveProvider = globalDnsProvider;
    const certOptions = parseStoredCertificateProviderOptions(entry.certificate.providerOptions);
    if (certOptions?.provider && dnsProviderSettings?.providers[certOptions.provider]) {
      effectiveProvider = {
        provider: certOptions.provider,
        credentials: dnsProviderSettings.providers[certOptions.provider],
      };
    }

    for (const subjectGroup of groupHostPatternsByPriority(subjects)) {
      const issuer: Record<string, unknown> = {
        module: "acme"
      };
      applyAcmeOverrides(issuer);

      if (options.acmeEmail) {
        issuer.email = options.acmeEmail;
      }

      if (effectiveProvider) {
        const dnsChallenge = buildDnsChallengeConfig(
          effectiveProvider.provider,
          effectiveProvider.credentials,
          dnsResolvers
        );
        if (dnsChallenge) {
          issuer.challenges = { dns: dnsChallenge };
        }
      }

      policies.push({
        subjects: subjectGroup,
        issuers: [issuer]
      });
    }
  }

  if (policies.length === 0) {
    return {
      managedCertificateIds
    };
  }

  return {
    tlsApp: {
      automation: {
        policies: sortAutomationPoliciesBySubjectPriority(policies)
      }
    },
    managedCertificateIds
  };
}

const VALID_L4_LB_POLICIES = ["random", "round_robin", "least_conn", "ip_hash", "first"];

function trimmedString(value: unknown): string | null {
  return typeof value === "string" ? value.trim() || null : null;
}

function nonNegativeInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

/**
 * Builds the `load_balancing` / `health_checks` fields of a caddy-l4 proxy
 * handler (layer4.handlers.proxy).
 *
 * caddy-l4 has its own schema, not the one of http.handlers.reverse_proxy:
 * the policy goes under `selection` (not `selection_policy`), there is no
 * `retries`, active checks only take port/interval/timeout and passive checks
 * only fail_duration/max_fails. Caddy decodes module config strictly, so one
 * HTTP-only field makes it reject the whole config (issue #301). Only fields
 * caddy-l4 accepts are emitted; legacy `retries` / `unhealthy_latency` values
 * still stored in older hosts' meta are ignored.
 */
export function buildL4LoadBalancerHandlerConfig(meta: LoadBalancerMeta | undefined | null): Record<string, unknown> {
  if (!meta?.enabled) return {};

  const result: Record<string, unknown> = {};

  const policy = meta.policy && VALID_L4_LB_POLICIES.includes(meta.policy) ? meta.policy : "random";
  const loadBalancing: Record<string, unknown> = { selection: { policy } };
  const tryDuration = trimmedString(meta.try_duration);
  if (tryDuration) loadBalancing.try_duration = tryDuration;
  const tryInterval = trimmedString(meta.try_interval);
  if (tryInterval) loadBalancing.try_interval = tryInterval;
  result.load_balancing = loadBalancing;

  const healthChecks: Record<string, unknown> = {};
  const activeMeta = meta.active_health_check;
  if (activeMeta?.enabled) {
    const active: Record<string, unknown> = {};
    const port = nonNegativeInteger(activeMeta.port);
    if (port !== null && port > 0) active.port = port;
    const interval = trimmedString(activeMeta.interval);
    if (interval) active.interval = interval;
    const timeout = trimmedString(activeMeta.timeout);
    if (timeout) active.timeout = timeout;
    // An empty object still enables active checks with caddy-l4's defaults.
    healthChecks.active = active;
  }
  const passiveMeta = meta.passive_health_check;
  if (passiveMeta?.enabled) {
    const passive: Record<string, unknown> = {};
    const failDuration = trimmedString(passiveMeta.fail_duration);
    if (failDuration) passive.fail_duration = failDuration;
    const maxFails = nonNegativeInteger(passiveMeta.max_fails);
    if (maxFails !== null) passive.max_fails = maxFails;
    if (Object.keys(passive).length > 0) healthChecks.passive = passive;
  }
  if (Object.keys(healthChecks).length > 0) result.health_checks = healthChecks;

  return result;
}

async function buildL4Servers(): Promise<Record<string, unknown> | null> {
  const l4Hosts = await appDb
    .select()
    .from(l4ProxyHosts)
    .where(eq(l4ProxyHosts.enabled, true))
    // In id order: the servers' names (srv0, srv1, ...) follow it.
    .orderBy(l4ProxyHosts.id);

  if (l4Hosts.length === 0) return null;

  // Safety net for rows created before reserved-port validation (issue #295):
  // an L4 host on :80/:443/:2019 would share a listener with the dashboard's own HTTP
  // app or admin API (SO_REUSEPORT makes the bind succeed but silently splits
  // connections). Skip them so one legacy row cannot break every other host.
  const l4HostsFiltered = l4Hosts.filter((host) => {
    if (isReservedL4Port(host.listenAddress)) {
      console.warn(
        `[l4] Skipping L4 proxy host "${host.name}" (id ${host.id}): listen address ${host.listenAddress} uses a reserved port (80/443/2019). Edit the host to use a different port.`
      );
      return false;
    }
    return true;
  });
  if (l4HostsFiltered.length === 0) return null;

  const [globalDnsSettings, globalUpstreamDnsResolutionSettings, globalGeoBlock] = await Promise.all([
    getDnsSettings(),
    getUpstreamDnsResolutionSettings(),
    getGeoBlockSettings(),
  ]);

  // Group hosts by listen address — multiple hosts on the same port share routes in one server
  const serverMap = new Map<string, typeof l4HostsFiltered>();
  for (const host of l4HostsFiltered) {
    const key = host.listenAddress;
    if (!serverMap.has(key)) serverMap.set(key, []);
    serverMap.get(key)!.push(host);
  }

  const servers: Record<string, unknown> = {};
  let serverIdx = 0;
  for (const [listenAddr, hosts] of serverMap) {
    const routes: Record<string, unknown>[] = [];

    for (const host of hosts) {
      const route: Record<string, unknown> = {};

      // Build matchers
      const matcherType = host.matcherType as string;
      const matcherValues = host.matcherValue ? parseJson<string[]>(host.matcherValue, []) : [];

      if (matcherType === "tls_sni" && matcherValues.length > 0) {
        route.match = [{ tls: { sni: matcherValues } }];
      } else if (matcherType === "http_host" && matcherValues.length > 0) {
        route.match = [{ http: [{ host: matcherValues }] }];
      } else if (matcherType === "proxy_protocol") {
        route.match = [{ proxy_protocol: {} }];
      }
      // "none" = no match block (catch-all)

      // Parse per-host meta for load balancing, DNS resolver, and upstream DNS resolution
      const meta = parseJson<L4Meta>(host.meta, {});

      // DNS resolver config
      const dnsConfig = parseDnsResolverConfig(meta.dns_resolver);

      // Upstream DNS resolution (pinning)
      const hostDnsResolution = parseUpstreamDnsResolutionConfig(meta.upstream_dns_resolution);
      const effectiveDnsResolution = resolveEffectiveUpstreamDnsResolution(
        globalUpstreamDnsResolutionSettings,
        hostDnsResolution
      );

      // Build handler chain
      const handlers: Record<string, unknown>[] = [];

      // 1. Receive inbound proxy protocol
      if (host.proxyProtocolReceive) {
        handlers.push({ handler: "proxy_protocol" });
      }

      // 2. TLS termination
      if (host.tlsTermination) {
        handlers.push({ handler: "tls" });
      }

      // 3. Proxy handler
      const upstreams = parseJson<string[]>(host.upstreams, []);

      // Resolve upstream hostnames to IPs if DNS pinning is enabled
      let resolvedDials = upstreams;
      if (effectiveDnsResolution.enabled) {
        const resolver = new Resolver();
        const lookupServers = getLookupServers(dnsConfig, globalDnsSettings);
        if (lookupServers.length > 0) {
          try { resolver.setServers(lookupServers); } catch { /* ignore invalid servers */ }
        }
        const timeoutMs = getLookupTimeoutMs(dnsConfig, globalDnsSettings);

        const pinned: string[] = [];
        for (const upstream of upstreams) {
          const colonIdx = upstream.lastIndexOf(":");
          if (colonIdx <= 0) { pinned.push(upstream); continue; }
          const hostPart = upstream.substring(0, colonIdx);
          const portPart = upstream.substring(colonIdx + 1);
          if (isIP(hostPart) !== 0) { pinned.push(upstream); continue; }
          try {
            const addresses = await resolveHostnameAddresses(resolver, hostPart, effectiveDnsResolution.family, timeoutMs);
            for (const addr of addresses) {
              pinned.push(addr.includes(":") ? `[${addr}]:${portPart}` : `${addr}:${portPart}`);
            }
          } catch {
            pinned.push(upstream);
          }
        }
        resolvedDials = pinned;
      }

      // For UDP hosts, upstream dials must also use the udp/ prefix
      const dialPrefix = (host.protocol as string) === "udp" ? "udp/" : "";
      const proxyHandler: Record<string, unknown> = {
        handler: "proxy",
        upstreams: resolvedDials.map((u) => ({ dial: [`${dialPrefix}${u}`] })),
      };
      if (host.proxyProtocolVersion) {
        proxyHandler.proxy_protocol = host.proxyProtocolVersion;
      }
      Object.assign(proxyHandler, buildL4LoadBalancerHandlerConfig(meta.load_balancer));
      handlers.push(proxyHandler);

      route.handle = handlers;

      // Geo blocking: add a blocking route BEFORE the proxy route.
      // At L4, the blocker is a matcher (layer4.matchers.blocker) — blocked connections
      // match this route and are closed. Non-blocked connections fall through to the proxy route.
      const effectiveGeoBlock = resolveEffectiveGeoBlock(globalGeoBlock, {
        geoblock: meta.geoblock ?? null,
        geoblock_mode: meta.geoblock_mode ?? "merge",
      });
      if (effectiveGeoBlock) {
        const blockerMatcher: Record<string, unknown> = {
          geoip_db: "/usr/share/GeoIP/GeoLite2-Country.mmdb",
          asn_db: "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
        };
        if (effectiveGeoBlock.block_countries?.length) blockerMatcher.block_countries = effectiveGeoBlock.block_countries;
        if (effectiveGeoBlock.block_continents?.length) blockerMatcher.block_continents = effectiveGeoBlock.block_continents;
        if (effectiveGeoBlock.block_asns?.length) blockerMatcher.block_asns = effectiveGeoBlock.block_asns;
        if (effectiveGeoBlock.block_cidrs?.length) blockerMatcher.block_cidrs = effectiveGeoBlock.block_cidrs;
        if (effectiveGeoBlock.block_ips?.length) blockerMatcher.block_ips = effectiveGeoBlock.block_ips;
        if (effectiveGeoBlock.allow_countries?.length) blockerMatcher.allow_countries = effectiveGeoBlock.allow_countries;
        if (effectiveGeoBlock.allow_continents?.length) blockerMatcher.allow_continents = effectiveGeoBlock.allow_continents;
        if (effectiveGeoBlock.allow_asns?.length) blockerMatcher.allow_asns = effectiveGeoBlock.allow_asns;
        if (effectiveGeoBlock.allow_cidrs?.length) blockerMatcher.allow_cidrs = effectiveGeoBlock.allow_cidrs;
        if (effectiveGeoBlock.allow_ips?.length) blockerMatcher.allow_ips = effectiveGeoBlock.allow_ips;

        // Build the same route matcher as the proxy route (if any)
        const blockRoute: Record<string, unknown> = {
          match: [
            {
              blocker: blockerMatcher,
              ...(route.match ? (route.match as Record<string, unknown>[])[0] : {}),
            },
          ],
          handle: [{ handler: "close" }],
        };
        routes.push(blockRoute);
      }

      routes.push(route);
    }

    // Determine protocol from the hosts on this listen address.
    // All hosts sharing a listen address must use the same protocol.
    const protocol = hosts[0].protocol as string;
    const listenValue = protocol === "udp" ? `udp/${listenAddr}` : listenAddr;

    servers[`l4_server_${serverIdx++}`] = {
      listen: [listenValue],
      routes,
    };
  }

  return servers;
}

/**
 * The settings the configuration build reads, read in one query
 * (withSettingsSnapshot): with the synced copies a slave reads and the
 * instance mode, a key missing here is still read, once.
 */
const CADDY_BUILD_SETTING_KEYS = [
  "general",
  "acme",
  "dns",
  "dns_provider",
  "upstream_dns_resolution",
  "geoblock",
  "waf",
  "trusted_proxies",
  "default_response",
  "rate_limit",
  "error_pages",
  "response_headers",
  "logging",
  "metrics",
  CERTIFICATE_STORAGE_SETTING_KEY,
] as const;

/**
 * The Caddy configuration document, built from the database. Every setting
 * is read once per build (src/lib/settings.ts withSettingsSnapshot).
 */
export async function buildCaddyDocument() {
  return await withSettingsSnapshot(CADDY_BUILD_SETTING_KEYS, buildCaddyDocumentFromDatabase);
}

async function buildCaddyDocumentFromDatabase() {
  const [proxyHostRecords, certRows, accessListEntryRecords, caCertRows, issuedClientCertRows, allIssuedCaCertIds] = await Promise.all([
    appDb
      .select({
        id: proxyHosts.id,
        name: proxyHosts.name,
        domains: proxyHosts.domains,
        upstreams: proxyHosts.upstreams,
        certificateId: proxyHosts.certificateId,
        accessListId: proxyHosts.accessListId,
        sslForced: proxyHosts.sslForced,
        hstsEnabled: proxyHosts.hstsEnabled,
        hstsSubdomains: proxyHosts.hstsSubdomains,
        allowWebsocket: proxyHosts.allowWebsocket,
        preserveHostHeader: proxyHosts.preserveHostHeader,
        skipHttpsHostnameValidation: proxyHosts.skipHttpsHostnameValidation,
        meta: proxyHosts.meta,
        enabled: proxyHosts.enabled
      })
      .from(proxyHosts)
      // In id order: the routes, and so the document, do not depend on how the database stores the rows.
      .orderBy(proxyHosts.id),
    appDb
      .select({
        id: certificates.id,
        name: certificates.name,
        type: certificates.type,
        domainNames: certificates.domainNames,
        certificatePem: certificates.certificatePem,
        privateKeyPem: certificates.privateKeyPem,
        autoRenew: certificates.autoRenew,
        providerOptions: certificates.providerOptions
      })
      .from(certificates)
      .orderBy(certificates.id),
    appDb
      .select({
        accessListId: accessListEntries.accessListId,
        username: accessListEntries.username,
        passwordHash: accessListEntries.passwordHash
      })
      .from(accessListEntries)
      .orderBy(accessListEntries.id),
    appDb
      .select({
        id: caCertificates.id,
        certificatePem: caCertificates.certificatePem
      })
      .from(caCertificates)
      .orderBy(caCertificates.id),
    appDb
      .select({
        id: issuedClientCertificates.id,
        caCertificateId: issuedClientCertificates.caCertificateId,
        certificatePem: issuedClientCertificates.certificatePem
      })
      .from(issuedClientCertificates)
      .where(isNull(issuedClientCertificates.revokedAt))
      .orderBy(issuedClientCertificates.id),
    // Distinct CA IDs that have ever had a tracked issued cert (including revoked).
    // Used to distinguish "managed" CAs (pin to leaf certs) from "unmanaged" CAs
    // (trust any cert signed by that CA).
    appDb
      .selectDistinct({ caCertificateId: issuedClientCertificates.caCertificateId })
      .from(issuedClientCertificates)
      .orderBy(issuedClientCertificates.caCertificateId)
  ]);

  const proxyHostRows: ProxyHostRow[] = proxyHostRecords.map((h) => ({
    id: h.id,
    name: h.name,
    domains: h.domains,
    upstreams: h.upstreams,
    certificateId: h.certificateId,
    accessListId: h.accessListId,
    sslForced: h.sslForced ? 1 : 0,
    hstsEnabled: h.hstsEnabled ? 1 : 0,
    hstsSubdomains: h.hstsSubdomains ? 1 : 0,
    allowWebsocket: h.allowWebsocket ? 1 : 0,
    preserveHostHeader: h.preserveHostHeader ? 1 : 0,
    skipHttpsHostnameValidation: h.skipHttpsHostnameValidation ? 1 : 0,
    meta: h.meta,
    enabled: h.enabled ? 1 : 0
  }));

  const certRowsMapped: CertificateRow[] = certRows.map((c: typeof certRows[0]) => ({
    id: c.id,
    name: c.name,
    type: c.type as "managed" | "imported",
    domainNames: c.domainNames,
    certificatePem: c.certificatePem,
    privateKeyPem: c.privateKeyPem ? decryptSecret(c.privateKeyPem, `certificate "${c.name}"`) : null,
    autoRenew: c.autoRenew ? 1 : 0,
    providerOptions: c.providerOptions
  }));

  const accessListEntryRows: AccessListEntryRow[] = accessListEntryRecords.map((entry) => ({
    accessListId: entry.accessListId,
    username: entry.username,
    passwordHash: entry.passwordHash
  }));

  const certificateMap = new Map(certRowsMapped.map((cert) => [cert.id, cert]));
  const caCertMap = new Map(caCertRows.map((ca) => [ca.id, ca]));
  const issuedClientCertMap = issuedClientCertRows.reduce<Map<number, string[]>>((map, record) => {
    const current = map.get(record.caCertificateId) ?? [];
    current.push(record.certificatePem);
    map.set(record.caCertificateId, current);
    return map;
  }, new Map());
  const cAsWithAnyIssuedCerts = new Set(allIssuedCaCertIds.map(r => r.caCertificateId));
  const accessMap = accessListEntryRows.reduce<Map<number, AccessListEntryRow[]>>((map, entry) => {
    if (!map.has(entry.accessListId)) {
      map.set(entry.accessListId, []);
    }
    map.get(entry.accessListId)!.push(entry);
    return map;
  }, new Map());

  // Build a lookup: issued cert ID → { id, caCertificateId, certificatePem } (active only)
  const issuedCertById = new Map(issuedClientCertRows.map(r => [r.id, r]));

  // Resolve role IDs → cert IDs for trusted_role_ids in mTLS config
  const roleCertIdMap = await buildRoleCertIdMap();

  // Build domain → CA cert IDs map for mTLS-enabled hosts.
  // New model (trusted_client_cert_ids + trusted_role_ids): derive CAs from selected certs and pin to those certs.
  // Old model (ca_certificate_ids): trust entire CAs as before.
  const mTlsDomainMap = new Map<string, number[]>();
  // Per-domain override: which specific leaf cert PEMs to pin (new model only)
  const mTlsDomainLeafOverride = new Map<string, string[]>();
  const mTlsOptionalAuthDomains = new Set<string>();
  for (const row of proxyHostRows) {
    if (!row.enabled) continue;
    const meta = parseJson<{ mtls?: MtlsConfig }>(row.meta, {});
    if (!meta.mtls?.enabled) continue;

    const domains = parseJson<string[]>(row.domains, []).map(d => d.trim().toLowerCase()).filter(Boolean);
    if (domains.length === 0) continue;

    if (meta.mtls.protected_paths?.length || meta.mtls.excluded_paths?.length) {
      for (const domain of domains) {
        mTlsOptionalAuthDomains.add(domain);
      }
    }

    // Collect all trusted cert IDs from both direct selection and roles
    const allCertIds = new Set<number>();
    if (meta.mtls.trusted_client_cert_ids) {
      for (const id of meta.mtls.trusted_client_cert_ids) allCertIds.add(id);
    }
    if (meta.mtls.trusted_role_ids) {
      for (const roleId of meta.mtls.trusted_role_ids) {
        const certIds = roleCertIdMap.get(roleId);
        if (certIds) for (const id of certIds) allCertIds.add(id);
      }
    }

    if (allCertIds.size > 0) {
      // New model: pin trust to the explicitly-selected client certs — derive
      // their CAs for chain validation and collect the leaf PEMs for pinning.
      const derivedCaIds = new Set<number>();
      const leafPems: string[] = [];
      for (const certId of allCertIds) {
        const cert = issuedCertById.get(certId);
        if (cert) {
          derivedCaIds.add(cert.caCertificateId);
          leafPems.push(cert.certificatePem);
        }
      }
      if (leafPems.length > 0) {
        const caIdArr = Array.from(derivedCaIds);
        for (const domain of domains) {
          mTlsDomainMap.set(domain, caIdArr);
          mTlsDomainLeafOverride.set(domain, leafPems);
        }
      } else {
        // Every explicitly-selected cert/role resolved to ZERO active leaves
        // (all revoked or deleted). FAIL CLOSED with a deny-all (drop) policy.
        // Do NOT derive the CA and fall back to whole-CA trust: that would trust
        // other active certs of the same CA that were never assigned to this
        // host (and "request" mode would accept any presented cert). Force
        // require_and_verify with an empty trust set → buildClientAuthentication
        // returns null → buildTlsConnectionPolicies emits a drop-all policy.
        for (const domain of domains) {
          mTlsDomainMap.set(domain, []);
          mTlsOptionalAuthDomains.delete(domain);
        }
      }
    } else if (meta.mtls.ca_certificate_ids?.length) {
      // Legacy model: trust entire CAs (backward compat)
      for (const domain of domains) {
        mTlsDomainMap.set(domain, meta.mtls.ca_certificate_ids);
      }
    } else {
      // mTLS is enabled but no trust resolved — e.g. trust is role-only and
      // every cert in those roles was revoked or the role is empty, or nothing
      // was selected — and there is no legacy CA trust. FAIL CLOSED: keep the
      // domain in the mTLS map with an empty CA set (buildClientAuthentication
      // returns null → buildTlsConnectionPolicies emits a drop-all policy) and
      // force require_and_verify so even protected/excluded-path hosts reject
      // all connections rather than silently serving the backend with no client
      // certificate required.
      for (const domain of domains) {
        mTlsDomainMap.set(domain, []);
        mTlsOptionalAuthDomains.delete(domain);
      }
    }
  }

  // Build mTLS RBAC data for HTTP-layer enforcement
  const enabledProxyHostIds = proxyHostRows.filter((r) => r.enabled).map((r) => r.id);
  const [roleFingerprintMap, certFingerprintMap, accessRulesByHost] = await Promise.all([
    buildRoleFingerprintMap(),
    buildCertFingerprintMap(),
    getAccessRulesForHosts(enabledProxyHostIds),
  ]);

  const [accessListRecords, accessListRuleRecords] = await Promise.all([
    appDb.select().from(accessLists).orderBy(accessLists.id),
    appDb.select().from(accessListRules).orderBy(accessListRules.id),
  ]);

  const { usage: certificateUsage, autoManagedDomains } = collectCertificateUsage(proxyHostRows, certificateMap);
  const [generalSettings, acmeSettings, dnsSettings, upstreamDnsResolutionSettings, globalGeoBlock, globalWaf, trustedProxiesSettings, defaultResponseSettings, globalRateLimit] = await Promise.all([
    getGeneralSettings(),
    getAcmeSettings(),
    getDnsSettings(),
    getUpstreamDnsResolutionSettings(),
    getGeoBlockSettings(),
    getWafSettings(),
    getTrustedProxiesSettings(),
    getDefaultResponseSettings(),
    getRateLimitSettings()
  ]);

  // Optionally seed the global geoblock trusted-proxy list from the server-level
  // value so the two can't silently disagree (issue #222). Only applied as a
  // default: an explicit per-scope geoblock list is left untouched.
  let effectiveGlobalGeoBlock = globalGeoBlock;
  if (trustedProxiesSettings?.default_geoblock && globalGeoBlock) {
    const serverRanges = (trustedProxiesSettings.ranges ?? []).map((r) => r.trim()).filter(Boolean);
    if (serverRanges.length > 0 && !(globalGeoBlock.trusted_proxies?.length)) {
      effectiveGlobalGeoBlock = { ...globalGeoBlock, trusted_proxies: serverRanges };
    }
  }
  const { tlsApp, managedCertificateIds } = await buildTlsAutomation(certificateUsage, autoManagedDomains, {
    acmeEmail: generalSettings?.acmeEmail,
    dnsSettings,
    acmeSettings
  });
  const { policies: tlsConnectionPolicies, readyCertificates, importedCertPems } = buildTlsConnectionPolicies(
    certificateUsage,
    managedCertificateIds,
    autoManagedDomains,
    mTlsDomainMap,
    caCertMap,
    issuedClientCertMap,
    cAsWithAnyIssuedCerts,
    mTlsDomainLeafOverride,
    mTlsOptionalAuthDomains
  );

  // Access list rules: a named route per list, and Blocked sources first on the server.
  const accessListConfig = buildAccessListCaddyConfig(accessListRecords, accessListRuleRecords, trustedProxiesSettings);

  const { routes: httpRoutes, errorRoutes: hostErrorRoutes, namedRoutes } = await buildProxyRoutes(
    proxyHostRows,
    accessMap,
    readyCertificates,
    {
      globalDnsSettings: dnsSettings,
      globalUpstreamDnsResolutionSettings: upstreamDnsResolutionSettings,
      globalGeoBlock: effectiveGlobalGeoBlock,
      globalWaf,
      mtlsRbac: {
        roleFingerprintMap,
        certFingerprintMap,
        accessRulesByHost,
      },
      monetization: await loadMonetizationForCaddy(),
      globalRateLimit,
      wafExclusions: await listWafExclusionRows(),
      accessListInvokes: accessListConfig.invokes,
      trustedProxies: normalizeTrustedProxyRanges(trustedProxiesSettings?.ranges),
    }
  );

  // An administrator-configured matcher-less route replaces Caddy's native
  // unmatched-request behavior and must remain last so it cannot shadow any
  // managed proxy host.
  const defaultResponseRoute = buildDefaultResponseRoute(defaultResponseSettings);
  const hostRoutesWithDefault = defaultResponseRoute ? [...httpRoutes, defaultResponseRoute] : httpRoutes;
  // The global Blocked sources list runs before anything else, on every
  // request the server takes (it has no host matcher and is not terminal:
  // whoever it does not deny goes on to the routes below).
  const blockedSourcesRoutes =
    accessListConfig.blockedSourcesRoute && hostRoutesWithDefault.length > 0
      ? [accessListConfig.blockedSourcesRoute, ...hostRoutesWithDefault]
      : hostRoutesWithDefault;
  // Response headers for every response wrap everything after them, the
  // Blocked sources list's denials included, so they go first. They never
  // start a server on their own.
  const responseHeadersRoute = buildResponseHeadersRoute(await getResponseHeadersSettings());
  const mainRoutes =
    responseHeadersRoute && blockedSourcesRoutes.length > 0 ? [responseHeadersRoute, ...blockedSourcesRoutes] : blockedSourcesRoutes;

  // Server-level error routes (Caddy handle_errors): per-host rules first so they
  // take precedence, then global rules act as a fallback for any unmatched host/status.
  const globalErrorPages = await getErrorPagesSettings();
  const globalErrorRoutes = (globalErrorPages?.rules ?? []).map((rule) => buildErrorPageRoute(rule));

  // Check if access logging should be enabled
  const loggingSettings = await getLoggingSettings();
  const loggingEnabled = loggingSettings?.enabled ?? false;
  const loggingFormat = loggingSettings?.format ?? "json";

  // With rate limiting on any host and access logging on, the limiter's 429s
  // first pass a non-terminal route that names the zone in the access log,
  // which analytics counts (log-parser.ts).
  const hasRateLimits = Object.keys(namedRoutes).length > 0;
  const allNamedRoutes = { ...namedRoutes, ...accessListConfig.namedRoutes };
  const hasNamedRoutes = Object.keys(allNamedRoutes).length > 0;
  // Caddy runs the error routes with the original response writer, so the
  // response headers route is needed there too.
  const errorRoutes: CaddyHttpRoute[] = [
    ...(responseHeadersRoute && mainRoutes.length > 0 ? [responseHeadersRoute] : []),
    ...(hasRateLimits && loggingEnabled ? [buildRateLimitLogRoute()] : []),
    ...hostErrorRoutes,
    ...globalErrorRoutes,
  ];

  const hasTls = tlsConnectionPolicies.length > 0;

  // Check if metrics should be enabled
  const metricsSettings = await getMetricsSettings();
  const metricsEnabled = metricsSettings?.enabled ?? false;
  const metricsPort = metricsSettings?.port ?? 9090;

  const servers: Record<string, unknown> = {};

  // Server-level trusted proxies / client-IP headers. Caddy resolves client_ip
  // in core before any handler, so this is the only place a global list fixes
  // client-IP attribution for access logs, analytics and downstream handlers.
  const serverTrustedProxies = buildServerTrustedProxies(trustedProxiesSettings);
  // PROXY protocol from the listed load balancers: the header's address
  // becomes the connection's, before trusted proxies and any handler.
  const serverListenerWrappers = buildProxyProtocolListenerWrappers(trustedProxiesSettings?.proxy_protocol_ranges);

  // Main HTTP/HTTPS server for proxy hosts
  if (mainRoutes.length > 0) {
    servers.ingressi = {
      listen: hasTls ? [":80", ":443"] : [":80"],
      routes: mainRoutes,
      // Only disable automatic HTTPS if we have TLS automation policies
      // This allows Caddy to handle HTTP-01 challenges for managed certificates
      ...(tlsApp ? {} : { automatic_https: { disable: true } }),
      ...(hasTls ? { tls_connection_policies: tlsConnectionPolicies } : {}),
      // Per-host rate limiters and access list rules, invoked from the host's routes
      ...(hasNamedRoutes ? { named_routes: allNamedRoutes } : {}),
      // Custom error pages (handle_errors)
      ...(errorRoutes.length > 0 ? { errors: { routes: errorRoutes } } : {}),
      // Trusted proxies / client_ip_headers / trusted_proxies_strict (issue #222)
      ...serverTrustedProxies,
      ...serverListenerWrappers,
      // Enable access logging if configured
      ...(loggingEnabled ? { logs: { default_logger_name: "http_access" } } : {})
    };
  }

  // Metrics server - exposes /metrics endpoint on separate port
  if (metricsEnabled) {
    servers.metrics = {
      listen: [`:${metricsPort}`],
      routes: [
        {
          handle: [
            {
              handler: "reverse_proxy",
              upstreams: [{ dial: "localhost:2019" }],
              rewrite: {
                uri: "/metrics"
              }
            }
          ]
        }
      ]
    };
  }

  const httpApp = Object.keys(servers).length > 0 ? { http: { servers } } : {};

  // Build logging configuration
  //
  // Roll settings are spelled out explicitly rather than relying on Caddy's
  // built-in file-writer defaults, so rotation behavior doesn't depend on
  // upstream defaults staying put.
  //
  // IMPORTANT for deployments that bind-mount /logs: Caddy ≥2.11 rolls logs
  // via timberjack, whose housekeeping pass (gzip + prune old rolled files)
  // starts with a directory listing (os.ReadDir). The /logs directory must
  // therefore be READABLE as well as writable by the caddy container's UID —
  // a write-only directory keeps rotation working (create/rename need only
  // w+x) but silently disables compression and pruning: timberjack swallows
  // the EACCES from the listing, and 100MB rolled files accumulate until the
  // disk fills. This actually happened in production (2026-09: 14GB of rolled
  // access logs on a 26G disk). The explicit roll_* settings here cannot
  // prevent that — only correct directory permissions can.
  //
  // Named volumes (default compose setup) inherit the image's chown'd /logs
  // and are fine. For bind mounts, run on the host:
  //   chgrp <CADDY_GID> <host-dir> && chmod 2770 <host-dir>
  // The web container never lists the directory — it needs only traverse (x)
  // plus group access to the files themselves via group_add: CADDY_GID.
  const rollSettings = {
    roll: true,
    roll_size_mb: 100,
    roll_gzip: true,
    roll_keep: 10,
    roll_keep_days: 30
  };
  const loggingLogs: Record<string, unknown> = {
    // WAF rule match logs. Modern Coraza puts the matched rules directly in the
    // audit log (part H), and waf-log-parser reads them from there — this file is
    // only a fallback for older builds that leave `messages` empty, plus a
    // human-readable trail. Do not make event ingestion depend on it: correlating
    // two independently-written files only works when both land in the same parse
    // tick, which silently dropped every non-blocked event (issue #233).
    waf_rules: {
      writer: { output: "file", filename: "/logs/waf-rules.log", mode: "0640", ...rollSettings },
      encoder: { format: "json" },
      include: ["http.handlers.waf"],
      level: "ERROR"
    },
    // Why a certificate could not be obtained or renewed: the ERROR lines of
    // the certificate loggers, which src/lib/tls-issuance-log.ts reads for the
    // certificate pages (sanitized there). Caddy's own output keeps all of
    // them. Few lines are written, so the file rolls small.
    tls_issuance: {
      writer: { output: "file", filename: "/logs/tls-issuance.log", mode: "0640", ...rollSettings, roll_size_mb: 10, roll_keep: 3 },
      encoder: { format: "json" },
      include: [...TLS_ISSUANCE_LOGGERS],
      level: "ERROR"
    }
  };
  if (loggingEnabled) {
    loggingLogs.http_access = {
      writer: { output: "file", filename: "/logs/access.log", mode: "0640", ...rollSettings },
      // x402 payment payloads (a signed transfer authorization) never reach the log.
      encoder: {
        format: "filter",
        wrap: { format: loggingFormat },
        fields: Object.fromEntries(X402_PAYMENT_REQUEST_HEADERS.map((name) => [`request>headers>${name}`, { filter: "delete" }]))
      },
      include: ["http.log.access", "http.handlers.blocker"]
    };
  }
  const loggingApp = { logging: { logs: loggingLogs } };

  // Build L4 (TCP/UDP) proxy servers
  const l4Servers = await buildL4Servers();
  const l4App = l4Servers ? { layer4: { servers: l4Servers } } : {};

  // Shared certificate storage (ee/high-availability): Caddy nodes that use
  // the same storage share certificates, locks and challenge tokens. Absent
  // for local storage, Caddy's default (its own /data).
  const storage = await resolveCaddyStorage();

  return {
    admin: {
      listen: "0.0.0.0:2019",
      origins: ["caddy:2019", "localhost:2019", "localhost"]
    },
    ...(storage ? { storage } : {}),
    ...loggingApp,
    apps: {
      ...httpApp,
      ...(tlsApp || importedCertPems.length > 0 ? {
        tls: {
          ...(tlsApp ?? {}),
          ...(importedCertPems.length > 0 ? { certificates: { load_pem: importedCertPems } } : {})
        }
      } : {}),
      ...l4App
    }
  };
}

/**
 * How long a request to the Caddy admin API may take. An apply holds the
 * cluster lock while it waits for Caddy, so a Caddy that stops answering
 * must not hold up every apply of the deployment for good. Loading a large
 * configuration (many WAF handlers) can take a while.
 */
const CADDY_LOAD_TIMEOUT_MS = 5 * 60_000;
const CADDY_READ_TIMEOUT_MS = 30_000;
/**
 * How long reaching the admin API (the name lookup and the TCP connection)
 * may take. A Caddy that is down often does not refuse the connection: its
 * address answers nothing, or its name resolves elsewhere (through the
 * resolver's search domains, once a stopped container's name is gone), and
 * the connection waits minutes for the operating system to give up, while
 * the apply holds the cluster lock and every other apply (an instance sync
 * received, a change in the dashboard) waits behind it.
 */
export const CADDY_CONNECT_TIMEOUT_MS = 5_000;
/** The code of the error when the admin API could not be reached within CADDY_CONNECT_TIMEOUT_MS. */
export const CADDY_CONNECT_TIMEOUT_CODE = "ECONNTIMEOUT";
/** Errors of a request that never reached Caddy. */
const CADDY_UNREACHABLE_CODES = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "ECONNREFUSED",
  "EHOSTUNREACH",
  "ENETUNREACH",
  CADDY_CONNECT_TIMEOUT_CODE,
]);

function timeoutError(message: string, code: string): Error {
  return Object.assign(new Error(message), { code });
}

/**
 * Resolves once a TCP connection to the admin API opens (and closes it),
 * rejects with the connection's error, or with CADDY_CONNECT_TIMEOUT_CODE
 * after CADDY_CONNECT_TIMEOUT_MS. node:http has no connect timeout, and
 * Bun's ClientRequest neither reports the connection nor fails when it is
 * destroyed while connecting, so the check is a connection of its own.
 */
function connectToCaddy(url: URL): Promise<void> {
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  const host = url.hostname.replace(/^\[(.*)\]$/, "$1");
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port });
    let timer: ReturnType<typeof setTimeout> | null = null;
    const done = (error?: Error) => {
      if (timer) clearTimeout(timer);
      timer = null;
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };
    timer = setTimeout(
      () => done(timeoutError("The Caddy admin API could not be reached in time", CADDY_CONNECT_TIMEOUT_CODE)),
      CADDY_CONNECT_TIMEOUT_MS
    );
    socket.once("connect", () => done());
    socket.once("error", (error) => done(error));
  });
}

/**
 * Plain HTTP/HTTPS request to the Caddy admin API using node:http.
 * Avoids browser-security headers (Sec-Fetch-*) that native fetch sends,
 * which would trigger Caddy's CORS origin enforcement.
 */
async function caddyRequest(url: string, method: string, body?: string): Promise<{ status: number; text: string }> {
  const timeoutMs = method === "GET" ? CADDY_READ_TIMEOUT_MS : CADDY_LOAD_TIMEOUT_MS;
  const parsed = new URL(url);
  await connectToCaddy(parsed);
  return await new Promise((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const settle = (finish: () => void) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      finish();
    };
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          ...(body ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } : {})
        }
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => settle(() => resolve({ status: res.statusCode ?? 0, text: data })));
        res.on("error", (error) => settle(() => reject(error)));
      }
    );
    req.on("error", (error) => settle(() => reject(error)));
    // Rejected here, not through the request's own error: a destroyed
    // request does not always report one (Bun).
    timer = setTimeout(() => {
      const error = timeoutError("The Caddy admin API did not answer in time", "ETIMEDOUT");
      settle(() => reject(error));
      req.destroy(error);
    }, timeoutMs);
    if (body) req.write(body);
    req.end();
  });
}

// ── Applying the configuration ──

/**
 * The cluster lock (src/lib/db/locks.ts) an apply holds from reading the
 * database to recording the outcome: applies never overlap, on any replica,
 * so the last push is built from the latest committed data.
 */
export const CADDY_APPLY_LOCK = "caddy-apply";

/**
 * Fingerprint (sha256) of Caddy's live configuration right after the last
 * successful apply, as this process last read or recorded it: a copy of the
 * cluster's (caddy-apply-status.ts liveHash), which getAppliedConfigHash
 * falls back on when the database cannot be read.
 */
let lastAppliedConfigHash: string | null = null;

export function getLastAppliedConfigHash(): string | null {
  return lastAppliedConfigHash;
}

/**
 * Fingerprint (sha256) of Caddy's live configuration right after the last
 * successful apply on any replica. The CaddyMonitor compares it with the
 * configuration Caddy actually serves to detect restarts and recreations
 * that did not resume the applied configuration, including coming back with
 * the image's default Caddyfile, which has a non-empty `http` app and so
 * cannot be detected by checking for an "empty" config. Read from the
 * database, so an apply by another replica is never taken for drift.
 */
export async function getAppliedConfigHash(): Promise<string | null> {
  try {
    lastAppliedConfigHash = (await readCaddyApplyState()).liveHash;
  } catch (error) {
    console.warn("[caddy] Could not read the apply state; using this process's copy:", error instanceof Error ? error.name : typeof error);
  }
  return lastAppliedConfigHash;
}

export async function getCaddyLiveConfigHash(): Promise<string | null> {
  try {
    const response = await caddyRequest(`${config.caddyApiUrl}/config/`, "GET");
    if (response.status < 200 || response.status >= 300) {
      return null;
    }
    return crypto.createHash("sha256").update(response.text).digest("hex");
  } catch {
    return null;
  }
}

/** What applyHoldingLock found: done, or the lock was lost on the way (another replica may have applied meanwhile). */
type LockedApplyOutcome = "applied" | "lock-lost";

/**
 * One apply, holding the cluster lock: builds the document from what the
 * database holds now, pushes it unless Caddy already serves exactly that
 * document, and records the outcome (caddy-apply-status.ts).
 *
 * The push is skipped only on the cluster's record, never on this process's
 * own: the last document Caddy took (on any replica) is this one, and Caddy
 * still serves what it served right after (it has not restarted or been
 * changed since). Anything else pushes.
 *
 * The outcome is recorded only over the generation read at the start: a
 * different one means another apply ran while this one thought it held the
 * lock (its connection failed, and the server released it). "lock-lost" is
 * returned then, as when the lock's signal says so before or after the
 * push, and nothing is recorded: the caller applies again.
 */
async function applyHoldingLock(signal: AbortSignal): Promise<LockedApplyOutcome> {
  const state = await readCaddyApplyState();
  // A failure is recorded for alerting; when even that fails, the apply's own error is what the caller gets.
  const applyFailed = async (message: string, code: CaddyApplyFailureCode & CaddyApplyError["code"]) => {
    await recordCaddyApplyResult({ ok: false, code, message }, { since: state.generation }).catch((error: unknown) =>
      logCaddyApplyFailure("Recording the failed Caddy apply failed", error)
    );
    return new CaddyApplyError(message, code);
  };

  let document: Awaited<ReturnType<typeof buildCaddyDocument>>;
  try {
    document = await buildCaddyDocument();
  } catch (error) {
    await recordCaddyApplyResult(
      { ok: false, code: "CONFIG_BUILD_FAILED", message: "Building the Caddy configuration from the database failed" },
      { since: state.generation }
    ).catch((recordError: unknown) => logCaddyApplyFailure("Recording the failed Caddy apply failed", recordError));
    throw error;
  }
  const payload = JSON.stringify(document);
  const documentHash = crypto.createHash("sha256").update(payload).digest("hex");

  let liveHash: string | null;
  const serving = state.documentHash === documentHash && state.liveHash !== null
    ? await getCaddyLiveConfigHash()
    : null;
  if (serving !== null && serving === state.liveHash) {
    // Caddy serves exactly this document: nothing to push. A failure
    // recorded since it took it is over.
    liveHash = serving;
    if (state.status?.ok !== true) {
      if (signal.aborted) return "lock-lost";
      if (!(await recordCaddyApplyResult({ ok: true }, { since: state.generation, applied: { documentHash, liveHash } }))) {
        return "lock-lost";
      }
    }
  } else {
    if (signal.aborted) return "lock-lost";
    let response: { status: number; text: string };
    try {
      response = await caddyRequest(`${config.caddyApiUrl}/load`, "POST", payload);
    } catch (error) {
      const systemCode = safeSystemErrorCode(error);
      logCaddyApplyFailure("Caddy admin request failed", error);
      if (systemCode !== null && CADDY_UNREACHABLE_CODES.has(systemCode)) {
        throw await applyFailed("Unable to reach Caddy API", "CADDY_UNREACHABLE");
      }
      throw await applyFailed("Failed to apply Caddy configuration", "CADDY_REQUEST_FAILED");
    }

    if (response.status < 200 || response.status >= 300) {
      const reason = describeCaddyRejection(response.text);
      logCaddyApplyFailure("Caddy rejected configuration", undefined, {
        status: response.status,
        responseBytes: Buffer.byteLength(response.text),
        knownReason: reason !== null,
      });
      throw await applyFailed(
        reason ? `Caddy rejected configuration: ${reason}` : "Caddy rejected configuration",
        "CADDY_REJECTED"
      );
    }

    // Record what Caddy is actually serving now, so the monitor can detect a
    // later restart/recreation that leaves Caddy without this configuration.
    liveHash = await getCaddyLiveConfigHash();
    if (signal.aborted) return "lock-lost";
    if (!(await recordCaddyApplyResult({ ok: true }, { since: state.generation, applied: { documentHash, liveHash } }))) {
      return "lock-lost";
    }
  }
  lastAppliedConfigHash = liveHash;

  // Configuration history (ee): record what Caddy now serves when history is
  // enabled. Never throws.
  await recordConfigSnapshotAfterApply();
  return "applied";
}

/**
 * Applies the configuration in the database to Caddy, then syncs it to the
 * slaves (master mode). Throws CaddyApplyError when Caddy did not take it
 * or the sync failed.
 *
 * With several replicas (PostgreSQL), applies run one at a time across all
 * of them (CADDY_APPLY_LOCK), each building from the database when it
 * starts, so the configuration Caddy ends up with reflects the latest
 * committed data whatever order the requests arrived in. A call made while
 * another call of this process waits for the lock shares that call's apply
 * (withCoalescedClusterLock): it starts after both, so it includes this
 * call's changes, and a burst of changes applies at most twice.
 */
export async function applyCaddyConfig() {
  // Inside a change batch (e.g. an import) the batch applies once at the end.
  if (deferCaddyApplyToBatch()) return;
  let outcome = await withCoalescedClusterLock(CADDY_APPLY_LOCK, (lock) => applyHoldingLock(lock.signal));
  if (outcome === "lock-lost") {
    // Another replica may have pushed while this apply ran without the lock:
    // apply again under it, so the last push is built from the latest data.
    console.warn("[caddy] The Caddy apply lost its cluster lock (its database connection failed); applying again");
    outcome = await withCoalescedClusterLock(CADDY_APPLY_LOCK, (lock) => applyHoldingLock(lock.signal));
    if (outcome === "lock-lost") {
      // The Caddy monitor finds Caddy serving something other than the
      // recorded configuration and applies again.
      console.error("[caddy] The Caddy apply lost its cluster lock twice; the Caddy monitor applies the configuration again");
    }
  }

  try {
    await syncInstances();
  } catch (error) {
    logCaddyApplyFailure("Instance synchronization failed after Caddy apply", error);
    throw new CaddyApplyError(
      "Caddy configuration applied but instance synchronization failed",
      "INSTANCE_SYNC_FAILED"
    );
  }
}

/**
 * Where Caddy reaches the dashboard (forward-auth verify and callback, the API
 * gate): the replicas DASHBOARD_UPSTREAMS lists (src/lib/dashboard-upstreams.ts),
 * otherwise the single address of getDashboardDialAddress(). Empty when there
 * is none.
 */
function getDashboardUpstreams(): string[] {
  const configured = configuredDashboardUpstreams();
  if (configured.length > 0) return configured;
  const single = getDashboardDialAddress();
  return single ? [single] : [];
}

/**
 * Derives the dial address (host:port) for Caddy to reach the dashboard internally.
 * Uses FORWARD_AUTH_INTERNAL_URL env var if set. Otherwise, if CADDY_API_URL
 * points to a Docker service name (e.g. "caddy:2019"), assumes Docker networking
 * and defaults to "web:3000". Falls back to deriving from BASE_URL.
 */
function getDashboardDialAddress(): string | null {
  const internalUrl = config.forwardAuthInternalUrl;
  if (internalUrl) {
    // Strip protocol, trailing slashes, and paths
    return internalUrl.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  }

  // If CADDY_API_URL uses a Docker service name, assume Docker networking
  // and use the web service name directly
  try {
    const caddyUrl = new URL(config.caddyApiUrl);
    if (caddyUrl.hostname !== "localhost" && caddyUrl.hostname !== "127.0.0.1" && caddyUrl.hostname !== "::1") {
      // Caddy is on a Docker network — the dashboard is the "web" service on port 3000
      return "web:3000";
    }
  } catch {
    // ignore
  }

  // Derive from BASE_URL (works for non-Docker setups)
  try {
    const url = new URL(config.baseUrl);
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    return `${url.hostname}:${port}`;
  } catch {
    return null;
  }
}

function parseAuthentikConfig(meta: ProxyHostAuthentikMeta | undefined | null): AuthentikRouteConfig | null {
  if (!meta || !meta.enabled) {
    return null;
  }

  const outpostDomain = typeof meta.outpost_domain === "string" ? meta.outpost_domain.trim() : "";
  const outpostUpstream = typeof meta.outpost_upstream === "string" ? meta.outpost_upstream.trim() : "";
  if (!outpostDomain || !outpostUpstream) {
    return null;
  }

  const authEndpointRaw = typeof meta.auth_endpoint === "string" ? meta.auth_endpoint.trim() : "";
  const authEndpoint = authEndpointRaw || `/${outpostDomain}/auth/caddy`;

  const copyHeaders =
    Array.isArray(meta.copy_headers) && meta.copy_headers.length > 0
      ? meta.copy_headers
          .map((header) => header?.trim())
          .filter((header): header is string => Boolean(header) && FA_HEADER_NAME_RE.test(header))
      : DEFAULT_AUTHENTIK_HEADERS;

  const trustedProxies =
    Array.isArray(meta.trusted_proxies) && meta.trusted_proxies.length > 0
      ? meta.trusted_proxies.map((item) => item?.trim()).filter((item): item is string => Boolean(item))
      : DEFAULT_AUTHENTIK_TRUSTED_PROXIES;

  const setOutpostHostHeader =
    meta.set_outpost_host_header !== undefined ? Boolean(meta.set_outpost_host_header) : true;

  const protectedPaths =
    Array.isArray(meta.protected_paths) && meta.protected_paths.length > 0
      ? meta.protected_paths.map((path) => path?.trim()).filter((path): path is string => Boolean(path))
      : null;

  const excludedPaths =
    Array.isArray(meta.excluded_paths) && meta.excluded_paths.length > 0
      ? meta.excluded_paths.map((path) => path?.trim()).filter((path): path is string => Boolean(path))
      : null;

  return {
    enabled: true,
    outpostDomain,
    outpostUpstream,
    authEndpoint,
    copyHeaders,
    trustedProxies,
    setOutpostHostHeader,
    protectedPaths,
    excludedPaths,
    bypassSources: readBypassSources(meta.bypass_sources)
  };
}

/**
 * Parses the generic forward-auth meta block (issue #188) into the values
 * needed to generate Caddy routes. Returns null unless enabled with a valid
 * upstream URL and endpoint.
 *
 * Defense in depth: values stored via the model layer are already sanitized,
 * but this parser re-validates because it reads the raw meta JSON.
 */
function parseForwardAuthConfig(meta: ForwardAuthMeta | undefined | null): ForwardAuthRouteConfig | null {
  if (!meta || !meta.enabled) {
    return null;
  }

  const upstreamRaw = typeof meta.auth_upstream === "string" ? meta.auth_upstream.trim() : "";
  if (!upstreamRaw) {
    return null;
  }

  let dialAddress: string;
  try {
    const url = new URL(upstreamRaw);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    dialAddress = `${url.hostname}:${port}`;
  } catch {
    return null;
  }

  const provider = meta.provider === "custom" ? "custom" : "authelia";
  const endpointRaw = stripPlaceholders(typeof meta.auth_endpoint === "string" ? meta.auth_endpoint.trim() : "");
  const authEndpoint = endpointRaw || (provider === "authelia" ? DEFAULT_AUTHELIA_FORWARD_AUTH_ENDPOINT : "");
  const hasControlChar = /[\r\n]/.test(authEndpoint) || authEndpoint.includes("\u0000");
  if (!authEndpoint.startsWith("/") || hasControlChar) {
    return null;
  }

  const copyHeaders =
    Array.isArray(meta.copy_headers) && meta.copy_headers.length > 0
      ? meta.copy_headers.map((h) => h?.trim()).filter((h): h is string => Boolean(h) && FA_HEADER_NAME_RE.test(h))
      : provider === "authelia"
        ? [...DEFAULT_AUTHELIA_FORWARD_AUTH_HEADERS]
        : [];

  const trustedProxiesRaw =
    Array.isArray(meta.trusted_proxies) && meta.trusted_proxies.length > 0
      ? meta.trusted_proxies.map((p) => p?.trim()).filter((p): p is string => Boolean(p))
      : ["private_ranges"];
  const trustedProxies = trustedProxiesRaw.includes("private_ranges")
    ? ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fd00::/8", "::1/128"]
    : trustedProxiesRaw;

  const apiBypassHeaders =
    Array.isArray(meta.api_bypass_headers)
      ? meta.api_bypass_headers.map((h) => h?.trim()).filter((h): h is string => Boolean(h) && FA_HEADER_NAME_RE.test(h))
      : [];

  const sanitizePaths = (paths: unknown): string[] | null =>
    Array.isArray(paths) && paths.length > 0
      ? paths
          .map((p) => (typeof p === "string" ? stripPlaceholders(p.trim()) : ""))
          .filter((p): p is string => Boolean(p))
      : null;

  return {
    enabled: true,
    provider,
    dialAddress,
    authEndpoint,
    copyHeaders,
    trustedProxies,
    apiSplit: Boolean(meta.api_split),
    apiBypassHeaders,
    protectedPaths: sanitizePaths(meta.protected_paths),
    excludedPaths: sanitizePaths(meta.excluded_paths),
    bypassSources: readBypassSources(meta.bypass_sources)
  };
}

/**
 * Builds the forward-auth subrequest handler (a reverse_proxy to the auth
 * server with the request rewritten to the auth endpoint).
 *
 * On a 2xx auth response, the configured identity headers are copied from the
 * auth response onto the original request. With `api401` set, any 3xx auth
 * response (the "go log in at the portal" redirect) is converted to a bare
 * 401 so non-browser clients and WebSocket handshakes are never handed an
 * HTML login page.
 */
function buildGenericForwardAuthHandler(cfg: ForwardAuthRouteConfig, api401: boolean): Record<string, unknown> {
  const handleResponseRoutes = buildAuthResponseCopyRoutes(cfg.copyHeaders);

  const handleResponse: Record<string, unknown>[] = [
    {
      match: { status_code: [2] },
      routes: handleResponseRoutes
    }
  ];
  if (api401) {
    handleResponse.push({
      match: { status_code: [301, 302, 303, 307, 308] },
      routes: [
        {
          handle: [
            {
              handler: "static_response",
              status_code: 401,
              body: "Unauthorized"
            }
          ]
        }
      ]
    });
  }

  const handler: Record<string, unknown> = {
    handler: "reverse_proxy",
    upstreams: [{ dial: cfg.dialAddress }],
    rewrite: {
      method: "GET",
      uri: cfg.authEndpoint
    },
    headers: {
      request: {
        set: {
          "X-Forwarded-Method": ["{http.request.method}"],
          "X-Forwarded-Uri": ["{http.request.uri}"],
          "X-Forwarded-Host": ["{http.request.hostport}"],
          "X-Forwarded-Proto": ["{http.request.scheme}"]
        },
        delete: [...FORWARD_AUTH_SUBREQUEST_STRIP_HEADERS]
      }
    },
    handle_response: handleResponse
  };

  if (cfg.trustedProxies.length > 0) {
    handler.trusted_proxies = [...cfg.trustedProxies];
  }
  return handler;
}

const VALID_LB_POLICIES = ["random", "round_robin", "least_conn", "ip_hash", "first", "header", "cookie", "uri_hash"];

function parseLoadBalancerConfig(meta: LoadBalancerMeta | undefined | null): LoadBalancerRouteConfig | null {
  if (!meta || !meta.enabled) {
    return null;
  }

  const policy = meta.policy && VALID_LB_POLICIES.includes(meta.policy) ? meta.policy : "random";
  const policyHeaderField = typeof meta.policy_header_field === "string" ? meta.policy_header_field.trim() || null : null;
  const policyCookieName = typeof meta.policy_cookie_name === "string" ? meta.policy_cookie_name.trim() || null : null;
  const policyCookieSecret = typeof meta.policy_cookie_secret === "string" ? meta.policy_cookie_secret.trim() || null : null;
  const tryDuration = typeof meta.try_duration === "string" ? meta.try_duration.trim() || null : null;
  const tryInterval = typeof meta.try_interval === "string" ? meta.try_interval.trim() || null : null;
  const retries = typeof meta.retries === "number" && Number.isFinite(meta.retries) && meta.retries >= 0 ? meta.retries : null;

  let activeHealthCheck: LoadBalancerRouteConfig["activeHealthCheck"] = null;
  if (meta.active_health_check && meta.active_health_check.enabled) {
    activeHealthCheck = {
      enabled: true,
      uri: typeof meta.active_health_check.uri === "string" ? meta.active_health_check.uri.trim() || null : null,
      port: typeof meta.active_health_check.port === "number" && Number.isFinite(meta.active_health_check.port) && meta.active_health_check.port > 0
        ? meta.active_health_check.port
        : null,
      interval: typeof meta.active_health_check.interval === "string" ? meta.active_health_check.interval.trim() || null : null,
      timeout: typeof meta.active_health_check.timeout === "string" ? meta.active_health_check.timeout.trim() || null : null,
      status: typeof meta.active_health_check.status === "number" && Number.isFinite(meta.active_health_check.status) && meta.active_health_check.status >= 100
        ? meta.active_health_check.status
        : null,
      body: typeof meta.active_health_check.body === "string" ? meta.active_health_check.body.trim() || null : null
    };
  }

  let passiveHealthCheck: LoadBalancerRouteConfig["passiveHealthCheck"] = null;
  if (meta.passive_health_check && meta.passive_health_check.enabled) {
    const unhealthyStatus = Array.isArray(meta.passive_health_check.unhealthy_status)
      ? meta.passive_health_check.unhealthy_status.filter((s): s is number => typeof s === "number" && Number.isFinite(s) && s >= 100)
      : null;

    passiveHealthCheck = {
      enabled: true,
      failDuration: typeof meta.passive_health_check.fail_duration === "string" ? meta.passive_health_check.fail_duration.trim() || null : null,
      maxFails: typeof meta.passive_health_check.max_fails === "number" && Number.isFinite(meta.passive_health_check.max_fails) && meta.passive_health_check.max_fails >= 0
        ? meta.passive_health_check.max_fails
        : null,
      unhealthyStatus: unhealthyStatus && unhealthyStatus.length > 0 ? unhealthyStatus : null,
      unhealthyLatency: typeof meta.passive_health_check.unhealthy_latency === "string" ? meta.passive_health_check.unhealthy_latency.trim() || null : null
    };
  }

  return {
    enabled: true,
    policy,
    policyHeaderField,
    policyCookieName,
    policyCookieSecret,
    tryDuration,
    tryInterval,
    retries,
    activeHealthCheck,
    passiveHealthCheck
  };
}

function buildLoadBalancingConfig(config: LoadBalancerRouteConfig): Record<string, unknown> | null {
  const loadBalancing: Record<string, unknown> = {};

  // Build selection policy
  const selectionPolicy: Record<string, unknown> = { policy: config.policy };

  if (config.policy === "header" && config.policyHeaderField) {
    selectionPolicy.policy = "header";
    selectionPolicy.field = config.policyHeaderField;
  } else if (config.policy === "cookie" && config.policyCookieName) {
    selectionPolicy.policy = "cookie";
    selectionPolicy.name = config.policyCookieName;
    if (config.policyCookieSecret) {
      selectionPolicy.secret = config.policyCookieSecret;
    }
  }

  loadBalancing.selection_policy = selectionPolicy;

  // Add retry settings
  if (config.tryDuration) {
    loadBalancing.try_duration = config.tryDuration;
  }
  if (config.tryInterval) {
    loadBalancing.try_interval = config.tryInterval;
  }
  if (config.retries !== null) {
    loadBalancing.retries = config.retries;
  }

  return Object.keys(loadBalancing).length > 0 ? loadBalancing : null;
}

type DnsResolverRouteConfig = {
  enabled: boolean;
  resolvers: string[];
  fallbacks: string[] | null;
  timeout: string | null;
};

function buildHealthChecksConfig(config: LoadBalancerRouteConfig): Record<string, unknown> | null {
  const healthChecks: Record<string, unknown> = {};

  // Active health checks
  if (config.activeHealthCheck && config.activeHealthCheck.enabled) {
    const active: Record<string, unknown> = {};

    if (config.activeHealthCheck.uri) {
      active.uri = config.activeHealthCheck.uri;
    }
    if (config.activeHealthCheck.port !== null) {
      active.port = config.activeHealthCheck.port;
    }
    if (config.activeHealthCheck.interval) {
      active.interval = config.activeHealthCheck.interval;
    }
    if (config.activeHealthCheck.timeout) {
      active.timeout = config.activeHealthCheck.timeout;
    }
    if (config.activeHealthCheck.status !== null) {
      active.expect_status = config.activeHealthCheck.status;
    }
    if (config.activeHealthCheck.body) {
      active.expect_body = config.activeHealthCheck.body;
    }

    if (Object.keys(active).length > 0) {
      healthChecks.active = active;
    }
  }

  // Passive health checks
  if (config.passiveHealthCheck && config.passiveHealthCheck.enabled) {
    const passive: Record<string, unknown> = {};

    if (config.passiveHealthCheck.failDuration) {
      passive.fail_duration = config.passiveHealthCheck.failDuration;
    }
    if (config.passiveHealthCheck.maxFails !== null) {
      passive.max_fails = config.passiveHealthCheck.maxFails;
    }
    if (config.passiveHealthCheck.unhealthyStatus && config.passiveHealthCheck.unhealthyStatus.length > 0) {
      passive.unhealthy_status = config.passiveHealthCheck.unhealthyStatus;
    }
    if (config.passiveHealthCheck.unhealthyLatency) {
      passive.unhealthy_latency = config.passiveHealthCheck.unhealthyLatency;
    }

    if (Object.keys(passive).length > 0) {
      healthChecks.passive = passive;
    }
  }

  return Object.keys(healthChecks).length > 0 ? healthChecks : null;
}

function parseDnsResolverConfig(meta: DnsResolverMeta | undefined | null): DnsResolverRouteConfig | null {
  if (!meta || !meta.enabled) {
    return null;
  }

  const resolvers = Array.isArray(meta.resolvers)
    ? meta.resolvers.map((r) => (typeof r === "string" ? r.trim() : "")).filter((r) => r.length > 0)
    : [];

  if (resolvers.length === 0) {
    return null;
  }

  const fallbacks = Array.isArray(meta.fallbacks)
    ? meta.fallbacks.map((r) => (typeof r === "string" ? r.trim() : "")).filter((r) => r.length > 0)
    : null;

  const timeout = typeof meta.timeout === "string" ? meta.timeout.trim() || null : null;

  return {
    enabled: true,
    resolvers,
    fallbacks: fallbacks && fallbacks.length > 0 ? fallbacks : null,
    timeout
  };
}

function buildResolverConfig(dnsConfig: DnsResolverRouteConfig): Record<string, unknown> | null {
  if (!dnsConfig || !dnsConfig.enabled || dnsConfig.resolvers.length === 0) {
    return null;
  }

  // Build resolver addresses list (primary + fallbacks)
  // DNS resolvers need port, default to :53 if not specified
  const formatResolver = (r: string) => {
    if (r.includes(":")) return r;
    return `${r}:53`;
  };

  const addresses = dnsConfig.resolvers.map(formatResolver);
  if (dnsConfig.fallbacks && dnsConfig.fallbacks.length > 0) {
    addresses.push(...dnsConfig.fallbacks.map(formatResolver));
  }

  return { addresses };
}
