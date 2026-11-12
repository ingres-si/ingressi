/**
 * Validates the free-form fields a proxy-host / L4-host write can set that
 * flow verbatim into the generated Caddy configuration: durations, DNS
 * resolver addresses, geoblock rules, health-check settings and forward-auth
 * trusted proxies. Caddy rejects the WHOLE document when any one of these is
 * malformed, and applyCaddyConfig rebuilds every host, so a single bad value
 * saved by a tag-scoped operator would block every later apply for everyone
 * until an administrator fixes it. Rejecting the write (400) keeps that from
 * happening.
 *
 * These are availability checks, applied to every writer (admins included):
 * none of them restrict what a legitimate value may be, only that Caddy (Go)
 * will parse it. Go is stricter than Node in places (no IPv6 zones, no
 * leading zeros in a prefix length), so the checks follow Go.
 */
import { isIP } from "node:net";
import { ApiValidationError } from "./api-errors";

// Go/Caddy time.ParseDuration grammar, plus Caddy's "d" (days). "0" needs no unit.
const DURATION_PART = /(\d+\.?\d*|\.\d+)(ns|us|µs|μs|ms|s|m|h|d)/g;
const CADDY_DURATION = new RegExp(`^[+-]?(${DURATION_PART.source})+$`);
const NANOSECONDS: Record<string, number> = {
  ns: 1, us: 1e3, "µs": 1e3, "μs": 1e3, ms: 1e6, s: 1e9, m: 60e9, h: 3600e9, d: 86400e9,
};
// A Go duration is an int64 count of nanoseconds (about 292 years).
const MAX_DURATION_NS = 9.2e18;

export function assertCaddyDuration(value: unknown, label: string): void {
  if (value === null || value === undefined) return;
  const invalid = new ApiValidationError(`${label} must be a duration such as "10s", "500ms" or "1m30s"`);
  if (typeof value !== "string") throw invalid;
  const trimmed = value.trim();
  if (!trimmed || trimmed === "0") return;
  if (!CADDY_DURATION.test(trimmed)) throw invalid;
  let total = 0;
  for (const part of trimmed.matchAll(DURATION_PART)) total += Number(part[1]) * NANOSECONDS[part[2]];
  if (!Number.isFinite(total) || total > MAX_DURATION_NS) throw invalid;
}

/** An IP address as Go's net.ParseIP takes it: no zone, no surrounding space. */
function isGoIp(value: string): 0 | 4 | 6 {
  if (value.includes("%")) return 0;
  return isIP(value) as 0 | 4 | 6;
}

/** A CIDR range as Go's net.ParseCIDR and netip.ParsePrefix both take it. */
function isGoCidr(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash === -1) return false;
  const version = isGoIp(value.slice(0, slash));
  const prefix = value.slice(slash + 1);
  if (version === 0 || !/^(0|[1-9]\d{0,2})$/.test(prefix)) return false;
  return Number(prefix) <= (version === 4 ? 32 : 128);
}

/** An IP address or CIDR range (optionally the "private_ranges" keyword). */
export function assertIpOrCidr(value: unknown, label: string, allowPrivateRanges = false): void {
  if (allowPrivateRanges && value === "private_ranges") return;
  if (typeof value !== "string" || !(value.includes("/") ? isGoCidr(value) : isGoIp(value) !== 0)) {
    throw new ApiValidationError(`${label} must be an IP address or CIDR range`);
  }
}

function isPort(value: string): boolean {
  return /^\d{1,5}$/.test(value) && Number(value) >= 1 && Number(value) <= 65535;
}

/**
 * A DNS resolver address Caddy will dial: an IP, host:port or [ipv6]:port,
 * with an optional udp/ or tcp/ network prefix. No Caddy placeholder, no unix
 * socket, no other network prefix (which would not be a reachable nameserver
 * and could name an in-container socket).
 */
export function assertResolverAddress(value: string, label: string): void {
  const trimmed = value.trim();
  if (!trimmed) return;
  if (trimmed.includes("{")) {
    throw new ApiValidationError(`${label} must not contain a Caddy placeholder`);
  }
  let rest = trimmed;
  const prefix = rest.match(/^(udp|tcp)\//);
  if (prefix) rest = rest.slice(prefix[0].length);
  if (rest.includes("/")) {
    throw new ApiValidationError(`${label} must be a nameserver address, not a socket or path`);
  }
  const invalid = new ApiValidationError(`${label} must be a valid nameserver address`);
  // [ipv6] or [ipv6]:port
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close === -1 || isGoIp(rest.slice(1, close)) !== 6) throw invalid;
    const after = rest.slice(close + 1);
    if (after !== "" && !(after.startsWith(":") && isPort(after.slice(1)))) throw invalid;
    return;
  }
  // bare IP, or host:port / ip:port (exactly one colon)
  if (isGoIp(rest) !== 0) return;
  const colon = rest.indexOf(":");
  const host = colon === -1 ? rest : rest.slice(0, colon);
  if (rest.lastIndexOf(":") !== colon || !/^[A-Za-z0-9._-]+$/.test(host)) throw invalid;
  if (colon !== -1 && !isPort(rest.slice(colon + 1))) throw invalid;
}

/** A list of strings, each passing `check`; anything else in its place is refused. */
function assertStringList(value: unknown, label: string, check: (item: string) => boolean, what: string): void {
  if (value === undefined || value === null) return;
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && check(item))) {
    throw new ApiValidationError(`${label} must be a list of ${what}`);
  }
}

function assertAsnList(value: unknown, label: string): void {
  if (value === undefined || value === null) return;
  // The blocker plugin wants AS numbers above 0, and they are 32-bit.
  if (!Array.isArray(value) || !value.every((item) => Number.isInteger(item) && item >= 1 && item <= 4294967295)) {
    throw new ApiValidationError(`${label} must be a list of AS numbers`);
  }
}

const CONTINENTS = new Set(["AF", "AN", "AS", "EU", "NA", "OC", "SA"]);

/** A geoblock rule set, checked the way the blocker plugin checks it when Caddy loads the configuration. */
function assertGeoBlock(geoblock: unknown, label: string): void {
  if (geoblock === undefined || geoblock === null) return;
  if (typeof geoblock !== "object" || Array.isArray(geoblock)) {
    throw new ApiValidationError(`${label} must be an object`);
  }
  const g = geoblock as Record<string, unknown>;
  for (const side of ["block", "allow"]) {
    assertStringList(g[`${side}_countries`], `${label}.${side}_countries`, (item) => /^[A-Z]{2}$/.test(item), "two-letter uppercase country codes");
    assertStringList(g[`${side}_continents`], `${label}.${side}_continents`, (item) => CONTINENTS.has(item), "continent codes (AF, AN, AS, EU, NA, OC, SA)");
    assertStringList(g[`${side}_cidrs`], `${label}.${side}_cidrs`, isGoCidr, "CIDR ranges");
    assertStringList(g[`${side}_ips`], `${label}.${side}_ips`, (item) => isGoIp(item) !== 0, "IP addresses");
    assertAsnList(g[`${side}_asns`], `${label}.${side}_asns`);
  }
  assertStringList(
    g.trusted_proxies,
    `${label}.trusted_proxies`,
    (item) => item === "private_ranges" || (item.includes("/") ? isGoCidr(item) : isGoIp(item) !== 0),
    "IP addresses or CIDR ranges",
  );
  const status = g.response_status;
  if (status !== undefined && status !== null && status !== 0 && !(Number.isInteger(status) && (status as number) >= 100 && (status as number) <= 599)) {
    throw new ApiValidationError(`${label}.response_status must be a status code from 100 to 599`);
  }
  const redirect = g.redirect_url;
  if (redirect !== undefined && redirect !== null && redirect !== "") {
    // Go's url.ParseRequestURI: an absolute URL or an absolute path, no spaces or control characters.
    if (typeof redirect !== "string" || !/^(https?:\/\/[^\s/]|\/)/.test(redirect) || !isUrlText(redirect)) {
      throw new ApiValidationError(`${label}.redirect_url must be an http(s) URL or a path starting with /`);
    }
  }
  for (const key of ["response_body"]) {
    if (g[key] !== undefined && g[key] !== null && typeof g[key] !== "string") {
      throw new ApiValidationError(`${label}.${key} must be text`);
    }
  }
  const headers = g.response_headers;
  if (headers !== undefined && headers !== null) {
    if (typeof headers !== "object" || Array.isArray(headers) || !Object.values(headers).every((v) => typeof v === "string")) {
      throw new ApiValidationError(`${label}.response_headers must map header names to text`);
    }
  }
}

/** Text Go's url.Parse takes: no space or control character, and only complete percent escapes. */
function isUrlText(value: string): boolean {
  // eslint-disable-next-line no-control-regex
  return !/[\s\u0000-\u001f\u007f]/.test(value) && !/%(?![0-9A-Fa-f]{2})/.test(value);
}

function assertInteger(value: unknown, label: string, min: number, max: number): void {
  if (value === undefined || value === null) return;
  // Anything that is not a number is dropped by the model; a fraction would reach Caddy, which wants an integer.
  if (typeof value === "number" && Number.isFinite(value) && !(Number.isInteger(value) && value >= min && value <= max)) {
    throw new ApiValidationError(`${label} must be a whole number from ${min} to ${max}`);
  }
}

/**
 * A regular expression Go's regexp (RE2) compiles. JavaScript checks the
 * syntax after Go-only spellings are rewritten; what JavaScript takes and RE2
 * does not (lookaround, backreferences, repeat counts above 1000) is refused.
 */
function assertGoRegexp(value: unknown, label: string): void {
  if (value === undefined || value === null || value === "") return;
  const invalid = new ApiValidationError(`${label} must be a valid regular expression (RE2 syntax)`);
  if (typeof value !== "string") throw invalid;
  if (/\(\?<?[=!]/.test(value) || /\\[1-9]/.test(value) || /\\k</.test(value)) throw invalid;
  for (const repeat of value.matchAll(/\{(\d+)(?:,(\d*))?\}/g)) {
    if (Number(repeat[1]) > 1000 || Number(repeat[2] || 0) > 1000) throw invalid;
  }
  const portable = value
    .replace(/\(\?[imsU-]+\)/g, "")
    .replace(/\(\?[imsU-]+:/g, "(?:")
    .replace(/\(\?P</g, "(?<")
    .replace(/\\[Az]/g, "$");
  try {
    new RegExp(portable);
  } catch {
    throw invalid;
  }
}

type LoadBalancerLike = {
  tryDuration?: unknown;
  tryInterval?: unknown;
  retries?: unknown;
  activeHealthCheck?: {
    uri?: unknown;
    port?: unknown;
    interval?: unknown;
    timeout?: unknown;
    status?: unknown;
    body?: unknown;
  } | null;
  passiveHealthCheck?: {
    failDuration?: unknown;
    maxFails?: unknown;
    unhealthyStatus?: unknown;
    unhealthyLatency?: unknown;
  } | null;
} | null | undefined;

function assertLoadBalancer(lb: LoadBalancerLike, label: string): void {
  if (!lb || typeof lb !== "object") return;
  assertCaddyDuration(lb.tryDuration, `${label}.tryDuration`);
  assertCaddyDuration(lb.tryInterval, `${label}.tryInterval`);
  assertInteger(lb.retries, `${label}.retries`, 0, 1_000_000);

  const active = lb.activeHealthCheck;
  if (active && typeof active === "object") {
    assertCaddyDuration(active.interval, `${label}.activeHealthCheck.interval`);
    assertCaddyDuration(active.timeout, `${label}.activeHealthCheck.timeout`);
    assertInteger(active.port, `${label}.activeHealthCheck.port`, 1, 65535);
    assertInteger(active.status, `${label}.activeHealthCheck.status`, 100, 999);
    assertGoRegexp(active.body, `${label}.activeHealthCheck.body`);
    const uri = active.uri;
    if (typeof uri === "string" && uri.trim() && !(uri.trim().startsWith("/") && isUrlText(uri.trim()))) {
      throw new ApiValidationError(`${label}.activeHealthCheck.uri must be a path starting with /`);
    }
  }

  const passive = lb.passiveHealthCheck;
  if (passive && typeof passive === "object") {
    assertCaddyDuration(passive.failDuration, `${label}.passiveHealthCheck.failDuration`);
    assertCaddyDuration(passive.unhealthyLatency, `${label}.passiveHealthCheck.unhealthyLatency`);
    assertInteger(passive.maxFails, `${label}.passiveHealthCheck.maxFails`, 0, 1_000_000);
    if (Array.isArray(passive.unhealthyStatus)) {
      for (const status of passive.unhealthyStatus) {
        assertInteger(status, `${label}.passiveHealthCheck.unhealthyStatus`, 100, 999);
      }
    }
  }
}

function assertResolverList(input: unknown): void {
  if (!input || typeof input !== "object") return;
  const r = input as Record<string, unknown>;
  for (const key of ["resolvers", "fallbacks"]) {
    const list = r[key];
    if (Array.isArray(list)) {
      for (const item of list) {
        if (typeof item === "string" && item.trim()) assertResolverAddress(item.trim(), `dnsResolver.${key}`);
      }
    }
  }
  assertCaddyDuration(r.timeout, "dnsResolver.timeout");
}

/** The model trims these and drops the empty ones before storing them. */
function assertTrustedProxies(list: unknown, label: string): void {
  if (!Array.isArray(list)) return;
  for (const item of list) {
    if (typeof item !== "string") throw new ApiValidationError(`${label} must be an IP address or CIDR range`);
    if (item.trim()) assertIpOrCidr(item.trim(), label, true);
  }
}

/** Validates every Caddy-bound scalar field of a proxy-host write. Throws ApiValidationError (400). */
export function validateProxyHostCaddyScalars(input: {
  loadBalancer?: LoadBalancerLike;
  dnsResolver?: unknown;
  geoblock?: unknown;
  authentik?: { trustedProxies?: unknown } | null;
  forwardAuth?: { trustedProxies?: unknown } | null;
  locationRules?: Array<{ loadBalancer?: LoadBalancerLike } | null> | null;
}): void {
  assertLoadBalancer(input.loadBalancer, "loadBalancer");
  assertResolverList(input.dnsResolver);
  assertGeoBlock(input.geoblock, "geoblock");
  assertTrustedProxies(input.authentik?.trustedProxies, "authentik.trustedProxies");
  assertTrustedProxies(input.forwardAuth?.trustedProxies, "forwardAuth.trustedProxies");
  for (const rule of input.locationRules ?? []) {
    assertLoadBalancer(rule?.loadBalancer, "locationRules.loadBalancer");
  }
}

/** Validates the Caddy-bound scalar fields of an L4-host write. Throws ApiValidationError (400). */
export function validateL4CaddyScalars(input: {
  loadBalancer?: LoadBalancerLike;
  geoblock?: unknown;
}): void {
  assertLoadBalancer(input.loadBalancer, "loadBalancer");
  assertGeoBlock(input.geoblock, "geoblock");
}
