/**
 * Rate limiting: validation of host rules and global defaults,
 * how a host inherits the defaults, and the Caddy configuration of the
 * caddy-ratelimit plugin (http.handlers.rate_limit,
 * github.com/mholt/caddy-ratelimit). See documentation/rate-limiting.md.
 *
 * Each host gets one named route holding its limiters, invoked from every
 * route of the host, so the limiters (and their state) exist once per host
 * however many routes it has:
 *
 *  - The client-IP limiter, then the header limiter, run first on every
 *    route: before the WAF, geo blocking, path blocks, redirects, access
 *    lists, the monetization gate, forward auth and the upstream. Floods are
 *    rejected before the WAF spends time on them, and requests forward auth
 *    would send to the portal are counted too. They see the path as the
 *    client sent it, before any rewrite.
 *  - Rules keyed by the signed-in user need the user that Ingressi forward
 *    auth sets, so their limiter runs right before the upstream. Their path
 *    is matched early (on the original path) and remembered in a variable.
 *
 * The plugin answers 429 with Retry-After as an error, so custom error pages
 * for 429 apply, and (with access logging on) buildRateLimitLogRoute adds the
 * limiting zone to the access log entry for analytics.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { ApiValidationError } from "./api-errors";
import { expandPrivateRanges } from "./caddy-utils";
import { FORWARD_AUTH_COPY_HEADERS, FORWARD_AUTH_IDENTITY_HEADERS } from "./forward-auth-trust";
import {
  RATE_LIMIT_KEYS,
  RATE_LIMIT_LIMITS,
  RATE_LIMIT_METHODS,
  RATE_LIMIT_MODES,
  isValidRateLimitHeader,
  isValidRateLimitPath,
  rateLimitWindowSeconds,
  type ProxyHostRateLimit,
  type RateLimitKey,
  type RateLimitMode,
  type RateLimitRule,
  type RateLimitSettings,
} from "./rate-limit-rules";

type CaddyRoute = Record<string, unknown>;
type CaddyHandler = Record<string, unknown>;
type MatcherSet = Record<string, unknown>;

/** Access log field naming the zone that refused a request (see buildRateLimitLogRoute). */
export const RATE_LIMIT_LOG_FIELD = "rate_limit_zone";

/** The user id Ingressi forward auth sets on the request: a stable key a user cannot choose. */
const FORWARD_AUTH_USER_HEADER = FORWARD_AUTH_IDENTITY_HEADERS.userId;

// The client address Caddy works out (after trusted proxies). Caddy has no
// {http.request.client_ip}: a key with it is empty, and every client shares one bucket.
const CLIENT_IP_KEY = "{http.vars.client_ip}";

// ── Validation ──────────────────────────────────────────────────────────

function fail(message: string): never {
  throw new ApiValidationError(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const unexpected = Object.keys(value).find((key) => !allowed.includes(key));
  if (unexpected !== undefined) fail(`${label} contains unknown field: ${unexpected}`);
}

/**
 * Headers Ingressi sets or strips itself: forward auth's identity headers and
 * the X-Ingressi-* family. Client copies are removed before the limiter, so
 * a rule keyed by one would only ever see it missing.
 */
function isReservedHeader(name: string): boolean {
  const normalized = name.toLowerCase().replace(/_/g, "-");
  return (
    normalized.startsWith("x-ingressi-") ||
    FORWARD_AUTH_COPY_HEADERS.some((header) => header.toLowerCase() === normalized)
  );
}

/** Identity of a rule: two rules with the same one count the same requests the same way. */
function ruleFingerprint(rule: RateLimitRule): string {
  return JSON.stringify([
    rule.path,
    [...rule.methods].sort(),
    rule.key,
    rule.key === "header" ? (rule.header ?? "").toLowerCase() : "",
    rule.events,
    rule.window,
  ]);
}

/**
 * One rule from a request or a form. Strict: unknown fields, a header on a
 * rule not keyed by one and anything outside the documented syntax and
 * limits are refused, so nothing free-form reaches the Caddy configuration.
 */
export function normalizeRateLimitRule(raw: unknown, label: string): RateLimitRule {
  if (!isRecord(raw)) fail(`${label} must be an object`);
  onlyKeys(raw, ["path", "methods", "key", "header", "events", "window"], label);

  const rawPath = raw.path ?? "*";
  if (typeof rawPath !== "string") fail(`${label}.path must be a string`);
  const path = rawPath.trim() || "*";
  if (!isValidRateLimitPath(path)) {
    fail(
      `${label}.path must be "*" or a Caddy path pattern starting with "/" or "*", made of letters, digits, - . _ ~ ! $ & ' ( ) * + , ; = : @ / and %XX escapes (at most ${RATE_LIMIT_LIMITS.maxPathLength} characters)`
    );
  }

  const rawMethods = raw.methods ?? [];
  if (!Array.isArray(rawMethods) || rawMethods.length > RATE_LIMIT_METHODS.length) {
    fail(`${label}.methods must be an array of HTTP methods`);
  }
  const methodSet = new Set<string>();
  rawMethods.forEach((method, index) => {
    const upper = typeof method === "string" ? method.trim().toUpperCase() : "";
    if (!(RATE_LIMIT_METHODS as readonly string[]).includes(upper)) {
      fail(`${label}.methods[${index}] must be one of ${RATE_LIMIT_METHODS.join(", ")}`);
    }
    methodSet.add(upper);
  });
  const methods = RATE_LIMIT_METHODS.filter((method) => methodSet.has(method));

  const key = (raw.key ?? "client_ip") as RateLimitKey;
  if (!(RATE_LIMIT_KEYS as readonly string[]).includes(key)) {
    fail(`${label}.key must be one of ${RATE_LIMIT_KEYS.join(", ")}`);
  }

  let header: string | undefined;
  const rawHeader = raw.header;
  const headerGiven = rawHeader !== undefined && rawHeader !== null && rawHeader !== "";
  if (key === "header") {
    if (typeof rawHeader !== "string" || !rawHeader.trim()) fail(`${label}.header is required when key is "header"`);
    header = rawHeader.trim();
    if (!isValidRateLimitHeader(header)) {
      fail(`${label}.header must be a valid HTTP header name (RFC 7230 token, at most ${RATE_LIMIT_LIMITS.maxHeaderLength} characters)`);
    }
    if (isReservedHeader(header)) {
      fail(`${label}.header ${header} is set by forward auth or Ingressi itself; use the key "forward_auth_user" to limit signed-in users`);
    }
  } else if (headerGiven) {
    fail(`${label}.header is only allowed when key is "header"`);
  }

  const events = raw.events;
  if (typeof events !== "number" || !Number.isInteger(events) || events < 1 || events > RATE_LIMIT_LIMITS.maxEvents) {
    fail(`${label}.events must be an integer from 1 to ${RATE_LIMIT_LIMITS.maxEvents}`);
  }

  const window = typeof raw.window === "string" ? raw.window.trim() : raw.window;
  if (typeof window !== "string" || rateLimitWindowSeconds(window) === null) {
    fail(
      `${label}.window must be a whole number of seconds, minutes or hours such as "30s", "1m" or "1h", from ${RATE_LIMIT_LIMITS.minWindowSeconds}s to ${RATE_LIMIT_LIMITS.maxWindowSeconds / 3600}h`
    );
  }

  return { path, methods, key, ...(header !== undefined ? { header } : {}), events, window };
}

/** A list of rules; at most RATE_LIMIT_LIMITS.maxRules, without repeats. */
export function normalizeRateLimitRules(raw: unknown, label: string): RateLimitRule[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) fail(`${label} must be an array`);
  if (raw.length > RATE_LIMIT_LIMITS.maxRules) fail(`${label} must contain at most ${RATE_LIMIT_LIMITS.maxRules} rules`);
  const seen = new Map<string, number>();
  return raw.map((item, index) => {
    const rule = normalizeRateLimitRule(item, `${label}[${index}]`);
    const fingerprint = ruleFingerprint(rule);
    const earlier = seen.get(fingerprint);
    if (earlier !== undefined) fail(`${label}[${index}] repeats ${label}[${earlier}]`);
    seen.set(fingerprint, index);
    return rule;
  });
}

/** A proxy host's rate limiting from a request: enabled by default, merge mode by default. */
export function normalizeProxyHostRateLimit(raw: unknown, label = "rateLimit"): ProxyHostRateLimit {
  if (!isRecord(raw)) fail(`${label} must be an object or null`);
  onlyKeys(raw, ["enabled", "mode", "rules"], label);
  const enabled = raw.enabled ?? true;
  if (typeof enabled !== "boolean") fail(`${label}.enabled must be a boolean`);
  const mode = (raw.mode ?? "merge") as RateLimitMode;
  if (!(RATE_LIMIT_MODES as readonly string[]).includes(mode)) fail(`${label}.mode must be merge or override`);
  return { enabled, mode, rules: normalizeRateLimitRules(raw.rules, `${label}.rules`) };
}

/** An IP address, a CIDR range or "private_ranges"; no IPv6 zone ids, no leading zeros in the prefix. */
function validateAllowlistEntry(value: string, label: string): void {
  if (value === "private_ranges") return;
  const message = `${label} must be an IP address, a CIDR range or private_ranges`;
  if (!/^[0-9A-Fa-f:.]+(\/(0|[1-9][0-9]{0,2}))?$/.test(value)) fail(message);
  const [address, prefixText] = value.split("/");
  const version = isIP(address);
  if (version === 0) fail(message);
  if (prefixText !== undefined && Number(prefixText) > (version === 4 ? 32 : 128)) fail(message);
}

/** The global defaults from a request or a form. */
export function normalizeRateLimitSettings(raw: unknown, label = "rate-limit"): RateLimitSettings {
  if (!isRecord(raw)) fail(`${label} settings must be an object`);
  onlyKeys(raw, ["enabled", "rules", "allowlist", "ipv6Prefix"], label);
  if (typeof raw.enabled !== "boolean") fail(`${label}.enabled must be a boolean`);
  const rules = normalizeRateLimitRules(raw.rules, `${label}.rules`);

  const rawAllowlist = raw.allowlist ?? [];
  if (!Array.isArray(rawAllowlist) || rawAllowlist.length > RATE_LIMIT_LIMITS.maxAllowlist) {
    fail(`${label}.allowlist must be an array with at most ${RATE_LIMIT_LIMITS.maxAllowlist} entries`);
  }
  const allowlist: string[] = [];
  rawAllowlist.forEach((entry, index) => {
    const itemLabel = `${label}.allowlist[${index}]`;
    if (typeof entry !== "string" || !entry.trim()) fail(`${itemLabel} must be a non-empty string`);
    const value = entry.trim();
    validateAllowlistEntry(value, itemLabel);
    if (!allowlist.includes(value)) allowlist.push(value);
  });

  const ipv6Prefix = raw.ipv6Prefix;
  if (
    ipv6Prefix !== undefined &&
    (typeof ipv6Prefix !== "number" ||
      !Number.isInteger(ipv6Prefix) ||
      ipv6Prefix < RATE_LIMIT_LIMITS.minIpv6Prefix ||
      ipv6Prefix > RATE_LIMIT_LIMITS.maxIpv6Prefix)
  ) {
    fail(`${label}.ipv6Prefix must be an integer from ${RATE_LIMIT_LIMITS.minIpv6Prefix} to ${RATE_LIMIT_LIMITS.maxIpv6Prefix}`);
  }

  return { enabled: raw.enabled, rules, allowlist, ...(ipv6Prefix !== undefined ? { ipv6Prefix } : {}) };
}

// ── Stored values ───────────────────────────────────────────────────────

/** The valid rules of a stored list; an invalid one (edited in the database) is left out and logged. */
function readStoredRules(raw: unknown, source: string): RateLimitRule[] {
  if (!Array.isArray(raw)) return [];
  const rules: RateLimitRule[] = [];
  const seen = new Set<string>();
  for (const [index, item] of raw.slice(0, RATE_LIMIT_LIMITS.maxRules).entries()) {
    try {
      const rule = normalizeRateLimitRule(item, `${source}.rules[${index}]`);
      const fingerprint = ruleFingerprint(rule);
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);
      rules.push(rule);
    } catch (error) {
      console.warn(`[rate-limit] Ignoring an invalid stored rule: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return rules;
}

/** A host's stored meta.rate_limit, or null when absent or not an object. */
export function readStoredHostRateLimit(raw: unknown): ProxyHostRateLimit | null {
  if (!isRecord(raw)) return null;
  return {
    enabled: raw.enabled === true,
    mode: raw.mode === "override" ? "override" : "merge",
    rules: readStoredRules(raw.rules, "rate_limit"),
  };
}

/** The stored global defaults, or null when unset. Invalid entries are left out. */
export function readStoredRateLimitSettings(raw: unknown): RateLimitSettings | null {
  if (!isRecord(raw)) return null;
  const allowlist: string[] = [];
  for (const entry of Array.isArray(raw.allowlist) ? raw.allowlist.slice(0, RATE_LIMIT_LIMITS.maxAllowlist) : []) {
    if (typeof entry !== "string") continue;
    try {
      validateAllowlistEntry(entry.trim(), "allowlist");
      if (!allowlist.includes(entry.trim())) allowlist.push(entry.trim());
    } catch {
      console.warn("[rate-limit] Ignoring an invalid stored allowlist entry");
    }
  }
  const ipv6Prefix =
    typeof raw.ipv6Prefix === "number" &&
    Number.isInteger(raw.ipv6Prefix) &&
    raw.ipv6Prefix >= RATE_LIMIT_LIMITS.minIpv6Prefix &&
    raw.ipv6Prefix <= RATE_LIMIT_LIMITS.maxIpv6Prefix
      ? raw.ipv6Prefix
      : undefined;
  return {
    enabled: raw.enabled === true,
    rules: readStoredRules(raw.rules, "rate_limit"),
    allowlist,
    ...(ipv6Prefix !== undefined ? { ipv6Prefix } : {}),
  };
}

// ── Inheritance ─────────────────────────────────────────────────────────

/**
 * The rules that apply to a host. Without host rules (absent or disabled)
 * the host inherits the enabled defaults; merge adds its rules to them;
 * override replaces them, so override with no rules limits nothing.
 */
export function resolveEffectiveRateLimitRules(
  global: RateLimitSettings | null,
  host: ProxyHostRateLimit | null | undefined
): RateLimitRule[] {
  const defaults = global?.enabled ? global.rules : [];
  let rules: RateLimitRule[];
  if (!host?.enabled) rules = defaults;
  else if (host.mode === "override") rules = host.rules;
  else rules = [...defaults, ...host.rules];

  const seen = new Set<string>();
  return rules.filter((rule) => {
    const fingerprint = ruleFingerprint(rule);
    if (seen.has(fingerprint)) return false;
    seen.add(fingerprint);
    return true;
  });
}

// ── Caddy configuration ─────────────────────────────────────────────────

export type RateLimitContext = {
  /** Client ranges no rule limits, "private_ranges" already expanded. */
  allowlist: string[];
  /** IPv6 prefix length client-IP keys are grouped by; 128 counts each address. */
  ipv6Prefix: number;
};

export function rateLimitContext(settings: RateLimitSettings | null): RateLimitContext {
  return {
    allowlist: expandPrivateRanges(settings?.allowlist ?? []),
    ipv6Prefix: settings?.ipv6Prefix ?? RATE_LIMIT_LIMITS.defaultIpv6Prefix,
  };
}

export type HostRateLimitConfig = {
  /** Named routes to add to the server, by name. */
  namedRoutes: Record<string, CaddyRoute>;
  /** Invokes the client-IP and header limiters: first on every route of the host. */
  early: CaddyHandler | null;
  /** Invokes the signed-in-user limiter: right before the upstream, after Ingressi forward auth. */
  beforeUpstream: CaddyHandler | null;
};

type Zone = {
  match: MatcherSet[];
  key: string;
  window: string;
  max_events: number;
  ipv6_prefix?: number;
};

function zoneBaseName(hostId: number, rule: RateLimitRule): string {
  const digest = createHash("sha256").update(ruleFingerprint(rule)).digest("hex").slice(0, 12);
  return `ingressi_rl_h${hostId}_${digest}`;
}

/**
 * The matcher set of one zone: the rule's methods (and path, unless it was
 * matched early and remembered in `pathVar`), the extra conditions, and
 * never a client on the allowlist.
 */
function zoneMatcher(
  rule: RateLimitRule,
  context: RateLimitContext,
  options: { extra?: MatcherSet; exclude?: MatcherSet[]; pathVar?: string } = {}
): MatcherSet[] {
  const set: MatcherSet = {};
  if (options.pathVar) set.vars = { [options.pathVar]: ["1"] };
  else if (rule.path !== "*") set.path = [rule.path];
  if (rule.methods.length > 0) set.method = [...rule.methods];
  Object.assign(set, options.extra ?? {});
  const exclude = [...(options.exclude ?? [])];
  if (context.allowlist.length > 0) exclude.unshift({ client_ip: { ranges: [...context.allowlist] } });
  if (exclude.length > 0) set.not = exclude;
  return [set];
}

function zone(rule: RateLimitRule, match: MatcherSet[], key: string): Zone {
  return { match, key, window: rule.window, max_events: rule.events };
}

function clientIpZone(rule: RateLimitRule, match: MatcherSet[], context: RateLimitContext): Zone {
  const result = zone(rule, match, CLIENT_IP_KEY);
  // The plugin masks the client IP to this prefix before using it as the key.
  if (context.ipv6Prefix < 128) result.ipv6_prefix = context.ipv6Prefix;
  return result;
}

function rateLimitHandler(zones: Record<string, Zone>): CaddyHandler {
  // Prometheus metrics stay off: the plugin labels them with every key (one
  // series per client IP or header value, never removed).
  return { handler: "rate_limit", rate_limits: zones, disable_metrics: true };
}

/**
 * The limiters of one host. `forwardAuthUser` says whether the host runs
 * Ingressi forward auth; without it, rules keyed by the signed-in user count
 * by client IP. A rule keyed by a header (or the user) counts requests that
 * lack it by client IP, so they never share one bucket.
 */
export function buildHostRateLimit(
  hostId: number,
  rules: readonly RateLimitRule[],
  context: RateLimitContext,
  forwardAuthUser: boolean
): HostRateLimitConfig {
  const ipZones: Record<string, Zone> = {};
  const headerZones: Record<string, Zone> = {};
  const userZones: Record<string, Zone> = {};
  const pathMarks: CaddyRoute[] = [];

  for (const rule of rules) {
    const name = zoneBaseName(hostId, rule);
    if (rule.key === "client_ip") {
      ipZones[`${name}_ip`] = clientIpZone(rule, zoneMatcher(rule, context), context);
    } else if (rule.key === "header" && rule.header) {
      const present: MatcherSet = { header: { [rule.header]: ["*"] } };
      headerZones[`${name}_hdr`] = zone(rule, zoneMatcher(rule, context, { extra: present }), `{http.request.header.${rule.header}}`);
      headerZones[`${name}_hdr_ip`] = clientIpZone(rule, zoneMatcher(rule, context, { exclude: [present] }), context);
    } else if (rule.key === "forward_auth_user" && forwardAuthUser) {
      // Rewrites run between the early and the late limiter: match the
      // path the client sent here and remember it for the late zones.
      let pathVar: string | undefined;
      if (rule.path !== "*") {
        pathVar = `${name}_path`;
        pathMarks.push({ match: [{ path: [rule.path] }], handle: [{ handler: "vars", [pathVar]: "1" }] });
      }
      const present: MatcherSet = { header: { [FORWARD_AUTH_USER_HEADER]: ["*"] } };
      userZones[`${name}_user`] = zone(
        rule,
        zoneMatcher(rule, context, { extra: present, pathVar }),
        `{http.request.header.${FORWARD_AUTH_USER_HEADER}}`
      );
      userZones[`${name}_user_ip`] = clientIpZone(rule, zoneMatcher(rule, context, { exclude: [present], pathVar }), context);
    } else if (rule.key === "forward_auth_user") {
      ipZones[`${name}_user_ip`] = clientIpZone(rule, zoneMatcher(rule, context), context);
    }
  }

  const namedRoutes: Record<string, CaddyRoute> = {};
  const earlyHandlers: CaddyHandler[] = [];
  // Client-IP zones first, in a handler of their own: a client over its IP
  // limit never reaches the header zones, so it cannot make Caddy allocate
  // counters for header values it makes up.
  if (Object.keys(ipZones).length > 0) earlyHandlers.push(rateLimitHandler(ipZones));
  if (Object.keys(headerZones).length > 0) earlyHandlers.push(rateLimitHandler(headerZones));
  if (pathMarks.length > 0) earlyHandlers.push({ handler: "subroute", routes: pathMarks });

  let early: CaddyHandler | null = null;
  if (earlyHandlers.length > 0) {
    const routeName = `ingressi_rl_h${hostId}`;
    namedRoutes[routeName] = { handle: earlyHandlers };
    early = { handler: "invoke", name: routeName };
  }

  let beforeUpstream: CaddyHandler | null = null;
  if (Object.keys(userZones).length > 0) {
    const routeName = `ingressi_rl_h${hostId}_user`;
    namedRoutes[routeName] = { handle: [rateLimitHandler(userZones)] };
    beforeUpstream = { handler: "invoke", name: routeName };
  }

  return { namedRoutes, early, beforeUpstream };
}

/**
 * Server error route that records which zone refused a request: the
 * limiter's 429 is a handler error, so it passes through the error routes,
 * and log_append adds `rate_limit_zone` to that request's access log entry.
 * Non-terminal, so custom error pages for 429 still apply after it. Upstream
 * and monetization-gate 429s are responses, not errors, and never match.
 */
export function buildRateLimitLogRoute(): CaddyRoute {
  return {
    match: [{ not: [{ vars: { "{http.rate_limit.exceeded.name}": [""] } }] }],
    handle: [{ handler: "log_append", key: RATE_LIMIT_LOG_FIELD, value: "{http.rate_limit.exceeded.name}" }],
  };
}
