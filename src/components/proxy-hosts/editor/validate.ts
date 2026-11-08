/**
 * The host editor's checks: what can be told from the form alone, shown next
 * to each field before saving, and the server's messages mapped back to the
 * field they are about. The server stays the authority; these only save a
 * round trip.
 */
import {
  RATE_LIMIT_LIMITS,
  isValidRateLimitHeader,
  isValidRateLimitPath,
  rateLimitWindowSeconds,
} from "@/lib/rate-limit-rules";
import type { SectionId } from "./changes";
import { addressList, splitList, statusList, type HostForm, type LbForm } from "./model";
import { MAX_BYPASS_SOURCES, normalizeBypassSource } from "@/src/lib/sign-in-bypass";

export type FieldError = { message: string; section: SectionId };
export type FieldErrors = Record<string, FieldError>;

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
/** A Go duration as Caddy takes it: 5s, 250ms, 1m30s. */
const DURATION = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/;
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const CIDR = /^[0-9A-Fa-f:.]+\/\d{1,3}$/;

function isIpv6(value: string): boolean {
  return value.includes(":") && /^[0-9a-f:.]+$/i.test(value) && value.split("::").length <= 2;
}

/** The same rule as the server's isValidProxyHostDomain, without Node's net module. */
export function isValidDomain(raw: string): boolean {
  const value = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!value || value.length > 253) return false;
  const name = value.startsWith("*.") ? value.slice(2) : value;
  if (name.includes("*")) return false;
  if (!value.startsWith("*.") && (IPV4.test(value) || isIpv6(value))) return true;
  return name.split(".").every((label) => HOST_LABEL.test(label));
}

/** Normalizes what a user typed as a domain: trimmed, lower case, no scheme, path or trailing dot. */
export function normalizeDomainInput(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function checkDuration(errors: FieldErrors, id: string, value: string, section: SectionId) {
  if (value.trim() && !DURATION.test(value.trim())) {
    errors[id] = { message: "Use a duration such as 5s, 250ms or 1m.", section };
  }
}

function checkInteger(errors: FieldErrors, id: string, value: string, min: number, max: number, section: SectionId, what = "a whole number") {
  if (!value.trim()) return;
  const number = Number(value.trim());
  if (!Number.isInteger(number) || number < min || number > max) {
    errors[id] = { message: `Enter ${what} from ${min} to ${max}.`, section };
  }
}

/** A body limit in MiB: 1 to 1024 (Coraza's maximum is 1 GiB); a stored value may be a fraction. */
function checkMib(errors: FieldErrors, id: string, value: string) {
  if (!value.trim()) return;
  const mib = Number(value.trim());
  if (!Number.isFinite(mib) || mib < 1 || mib > 1024) errors[id] = { message: "Enter a size from 1 to 1024 MiB.", section: "security" };
}

function checkUpstreams(errors: FieldErrors, rows: HostForm["upstreams"], idOf: (index: number) => string, section: SectionId, required: boolean) {
  const filled = rows.filter((row) => row.address.trim());
  if (required && filled.length === 0) errors[idOf(0)] = { message: "Add at least one upstream.", section };
  rows.forEach((row, index) => {
    const address = row.address.trim();
    if (!address) return;
    if (/\s/.test(address)) errors[idOf(index)] = { message: "An address has no spaces.", section };
    else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(address)) errors[idOf(index)] = { message: "Pick the scheme on the left and enter only the address.", section };
    else if (/:2019$/.test(address)) errors[idOf(index)] = { message: "Port 2019 is Caddy's admin API.", section };
  });
}

export function validateLb(errors: FieldErrors, lb: LbForm, prefix: string, section: SectionId) {
  if (!lb.enabled) return;
  if (lb.policy === "header" && !lb.headerField.trim()) errors[`${prefix}-header`] = { message: "Enter the header to hash.", section };
  else if (lb.policy === "header" && !HEADER_NAME.test(lb.headerField.trim())) errors[`${prefix}-header`] = { message: "Enter a header name, such as X-Tenant-Id.", section };
  if (lb.policy === "cookie" && !lb.cookieName.trim()) errors[`${prefix}-cookie`] = { message: "Enter the cookie name.", section };
  checkDuration(errors, `${prefix}-try-duration`, lb.tryDuration, section);
  checkDuration(errors, `${prefix}-try-interval`, lb.tryInterval, section);
  checkInteger(errors, `${prefix}-retries`, lb.retries, 0, 1000, section);
  if (lb.active.enabled) {
    if (lb.active.uri.trim() && !lb.active.uri.trim().startsWith("/")) errors[`${prefix}-active-uri`] = { message: "A path starts with /.", section };
    else if (!lb.active.uri.trim() && !lb.active.port.trim())
      errors[`${prefix}-active-uri`] = { message: "Enter the path to check, such as /health: without a path or a port Caddy runs no active checks.", section };
    checkInteger(errors, `${prefix}-active-port`, lb.active.port, 1, 65535, section, "a port");
    checkDuration(errors, `${prefix}-active-interval`, lb.active.interval, section);
    checkDuration(errors, `${prefix}-active-timeout`, lb.active.timeout, section);
    checkInteger(errors, `${prefix}-active-status`, lb.active.status, 100, 599, section, "a status code");
  }
  if (lb.passive.enabled) {
    if (!lb.passive.failDuration.trim())
      errors[`${prefix}-passive-duration`] = { message: "Enter how long to remember failures, such as 30s: without it Caddy counts none.", section };
    else checkDuration(errors, `${prefix}-passive-duration`, lb.passive.failDuration, section);
    checkInteger(errors, `${prefix}-passive-max`, lb.passive.maxFails, 0, 1000, section);
    checkDuration(errors, `${prefix}-passive-latency`, lb.passive.unhealthyLatency, section);
    const raw = lb.passive.unhealthyStatus.trim();
    if (raw && (raw.split(",").some((part) => !/^\s*\d{3}\s*$/.test(part)) || statusList(raw).some((code) => code < 100 || code > 599))) {
      errors[`${prefix}-passive-status`] = { message: "Enter status codes separated by commas, such as 502, 503.", section };
    }
  }
}

function checkJson(errors: FieldErrors, id: string, value: string, shape: "array" | "object") {
  if (!value.trim()) return;
  try {
    const parsed = JSON.parse(value) as unknown;
    const ok = shape === "array" ? Array.isArray(parsed) : parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
    if (!ok) errors[id] = { message: shape === "array" ? "Enter a JSON array of handlers." : "Enter a JSON object.", section: "advanced" };
  } catch {
    errors[id] = { message: "This is not valid JSON.", section: "advanced" };
  }
}

export type ValidationContext = {
  /** New hosts need a name; the field lives in Routing for them. */
  nameSection: SectionId;
  dnsProviderConfigured: boolean;
  canChooseTrust: boolean;
};

/** Every problem the form shows, keyed by the id of the field it belongs to. */
export function validateForm(form: HostForm, context: ValidationContext): FieldErrors {
  const errors: FieldErrors = {};
  if (!form.name.trim()) errors["f-name"] = { message: "Enter a name for the host.", section: context.nameSection };
  else if (form.name.trim().length > 255) errors["f-name"] = { message: "Use at most 255 characters.", section: context.nameSection };

  // Routing
  if (form.domains.length === 0) errors["f-domains"] = { message: "Add at least one domain.", section: "routing" };
  const invalid = form.domains.find((domain) => !isValidDomain(domain));
  if (invalid) errors["f-domains"] = { message: `${invalid} is not a valid domain. Wildcards go first only, as in *.example.com.`, section: "routing" };
  const wildcard = form.domains.find((domain) => domain.startsWith("*."));
  if (!invalid && wildcard && form.certificateId === null && !context.dnsProviderConfigured) {
    errors["f-domains"] = {
      message: `${wildcard} needs a DNS provider for its certificate. Add one in Certificate settings, or choose a certificate in the Certificate section.`,
      section: "routing",
    };
  }
  checkUpstreams(errors, form.upstreams, (index) => `f-up-${index}`, "routing", true);
  validateLb(errors, form.lb, "f-lb", "routing");
  form.locationRules.forEach((rule, index) => {
    const path = rule.path.trim();
    if (!path) errors[`f-route-${index}-path`] = { message: "Enter the path this route matches, such as /api/*.", section: "routing" };
    else if (!path.startsWith("/") && path !== "*") errors[`f-route-${index}-path`] = { message: "A path starts with /.", section: "routing" };
    checkUpstreams(errors, rule.upstreams, (upstream) => `f-route-${index}-up-${upstream}`, "routing", true);
    validateLb(errors, rule.lb, `f-route-${index}-lb`, "routing");
  });

  // Security
  if (form.waf.mode !== "off") {
    checkMib(errors, "f-waf-body", form.waf.bodyLimit);
    checkMib(errors, "f-waf-memory", form.waf.bodyMemory);
    const limit = Number(form.waf.bodyLimit);
    const memory = Number(form.waf.bodyMemory);
    if (!errors["f-waf-memory"] && form.waf.bodyLimit.trim() && form.waf.bodyMemory.trim() && memory > limit) {
      errors["f-waf-memory"] = { message: "Keep this at or below the maximum request body.", section: "security" };
    }
  }
  if (form.rateLimit.rules.length > RATE_LIMIT_LIMITS.maxRules) {
    errors["f-rl-mode"] = { message: `A host has at most ${RATE_LIMIT_LIMITS.maxRules} rules.`, section: "security" };
  }
  form.rateLimit.rules.forEach((rule, index) => {
    const path = rule.path.trim() || "*";
    if (!isValidRateLimitPath(path)) errors[`f-rl-${index}-path`] = { message: "Enter * or a path starting with /, such as /login or /api/*.", section: "security" };
    if (rule.by === "header" && !isValidRateLimitHeader(rule.header.trim())) {
      errors[`f-rl-${index}-header`] = { message: "Enter a header name, such as X-Api-Key.", section: "security" };
    }
    const events = Number(rule.events);
    if (!Number.isInteger(events) || events < 1 || events > RATE_LIMIT_LIMITS.maxEvents) {
      errors[`f-rl-${index}-events`] = { message: `Enter 1 to ${RATE_LIMIT_LIMITS.maxEvents} requests.`, section: "security" };
    }
    if (rateLimitWindowSeconds(`${rule.windowValue.trim()}${rule.windowUnit}`) === null) {
      errors[`f-rl-${index}-window`] = { message: "Windows run from 1 second to 1 hour.", section: "security" };
    }
  });

  // Security: geo blocking
  const geo = form.geoblock;
  if (geo.enabled) {
    checkInteger(errors, "f-geo-status", geo.responseStatus, 100, 599, "security", "a status code");
    if (geo.redirectUrl.trim() && !isHttpUrl(geo.redirectUrl.trim())) {
      errors["f-geo-redirect"] = { message: "Enter an http:// or https:// address.", section: "security" };
    }
    const badRange = [...geo.blockCidrs, ...geo.allowCidrs].find((cidr) => !CIDR.test(cidr));
    if (badRange) errors["f-geo-ranges"] = { message: `${badRange} is not a range such as 10.0.0.0/8.`, section: "security" };
    geo.headers.forEach((row, index) => {
      if (row.name.trim() && !/^[a-zA-Z0-9\-_]+$/.test(row.name.trim())) {
        errors[`f-geo-header-${index}`] = { message: "Header names use letters, digits, - and _.", section: "security" };
      }
    });
  }
  // Access
  const sourcesError = (value: string): string | null => {
    const entries = addressList(value);
    for (const entry of entries) {
      const result = normalizeBypassSource(entry);
      if ("error" in result) return result.error;
    }
    return entries.length > MAX_BYPASS_SOURCES ? `At most ${MAX_BYPASS_SOURCES} addresses.` : null;
  };
  const sourceMessages: Array<[string, string, string | null]> = [
    ["authentik", "f-ak-sources", sourcesError(form.authentik.bypassSources)],
    ["generic", "f-fa-sources", sourcesError(form.forwardAuth.bypassSources)],
    ["ingressi", "f-fi-sources", sourcesError(form.ingressi.bypassSources)],
  ];
  for (const [signIn, id, message] of sourceMessages) {
    if (form.signIn === signIn && message) errors[id] = { message, section: "access" };
  }
  if (form.signIn === "authentik") {
    if (!form.authentik.outpostDomain.trim()) errors["f-ak-domain"] = { message: "Enter the outpost domain.", section: "access" };
    if (!form.authentik.outpostUpstream.trim()) errors["f-ak-upstream"] = { message: "Enter the outpost's address.", section: "access" };
    else if (!isHttpUrl(form.authentik.outpostUpstream.trim())) errors["f-ak-upstream"] = { message: "Enter an http:// or https:// address.", section: "access" };
  }
  if (form.signIn === "generic") {
    const upstream = form.forwardAuth.authUpstream.trim();
    if (!upstream) errors["f-fa-upstream"] = { message: "Enter the auth server's address.", section: "access" };
    else if (!isHttpUrl(upstream)) errors["f-fa-upstream"] = { message: "Enter an http:// or https:// address.", section: "access" };
    if (form.forwardAuth.provider === "custom" && !form.forwardAuth.authEndpoint.trim()) {
      errors["f-fa-endpoint"] = { message: "Enter the path the auth check is sent to.", section: "access" };
    }
    const badHeader = [...splitList(form.forwardAuth.copyHeaders), ...splitList(form.forwardAuth.apiBypassHeaders)].find((name) => !HEADER_NAME.test(name));
    if (badHeader) errors["f-fa-headers"] = { message: `${badHeader} is not a header name.`, section: "access" };
  }
  const mtlsTrust = form.mtls.trustMode === "ca" ? form.mtls.caIds.length : form.mtls.certIds.length + form.mtls.roleIds.length;
  if (form.mtls.enabled && mtlsTrust === 0) {
    errors["f-mtls"] = {
      message: context.canChooseTrust
        ? form.mtls.trustMode === "ca"
          ? "Choose at least one certificate authority, or turn client certificates off."
          : "Choose at least one role or client certificate, or turn client certificates off."
        : "Client certificates need a role or certificate that your role cannot choose. Turn them off or ask an administrator.",
      section: "access",
    };
  }
  form.pathBlocks.forEach((rule, index) => {
    if (!rule.path.trim()) errors[`f-pb-${index}-path`] = { message: "Enter a path, or remove the row.", section: "access" };
  });
  form.pathAllows.forEach((rule, index) => {
    if (!rule.path.trim()) errors[`f-pa-${index}-path`] = { message: "Enter a path, or remove the row.", section: "access" };
  });

  // Advanced
  form.redirects.forEach((rule, index) => {
    if (!rule.from.trim()) errors[`f-rd-${index}-from`] = { message: "Enter the path to redirect.", section: "advanced" };
    const to = rule.to.trim();
    if (!to) errors[`f-rd-${index}-to`] = { message: "Enter where it goes.", section: "advanced" };
    else if (!to.startsWith("/") && !isHttpUrl(to)) errors[`f-rd-${index}-to`] = { message: "Enter a path or an http(s) address.", section: "advanced" };
  });
  if (form.rewritePrefix.trim() && !form.rewritePrefix.trim().startsWith("/")) {
    errors["f-rewrite-prefix"] = { message: "A path prefix starts with /.", section: "advanced" };
  }
  form.pathRewrites.forEach((rule, index) => {
    if (!rule.from.trim()) errors[`f-rw-${index}-from`] = { message: "Enter the path to rewrite.", section: "advanced" };
    if (!rule.to.trim()) errors[`f-rw-${index}-to`] = { message: "Enter the path the upstream sees.", section: "advanced" };
  });
  form.errorPages.forEach((rule, index) => {
    if (!rule.body.trim()) errors[`f-ep-${index}-body`] = { message: "Enter the page body, or remove the row.", section: "advanced" };
    const raw = rule.statuses.trim();
    if (raw && raw.split(",").some((part) => !/^\s*[45]\d\d\s*$/.test(part))) {
      errors[`f-ep-${index}-statuses`] = { message: "Enter 4xx or 5xx codes separated by commas, or leave blank for every error.", section: "advanced" };
    }
  });
  if (form.dnsResolver.enabled) {
    if (splitList(form.dnsResolver.resolvers).length === 0) errors["f-dns-resolvers"] = { message: "Enter at least one resolver.", section: "advanced" };
    checkDuration(errors, "f-dns-timeout", form.dnsResolver.timeout, "advanced");
  }
  checkJson(errors, "f-pre-handlers", form.customPreHandlersJson, "array");
  checkJson(errors, "f-reverse-proxy", form.customReverseProxyJson, "object");
  return errors;
}

/** The field a server message is about, when it can be told; null otherwise. */
export function fieldOfServerError(message: string, nameSection: SectionId): { id: string; section: SectionId } | null {
  const rules: [RegExp, string, SectionId][] = [
    [/^name is required/i, "f-name", nameSection],
    [/^rateLimit\.rules\[(\d+)\]\.path/, "f-rl-$1-path", "security"],
    [/^rateLimit\.rules\[(\d+)\]\.header/, "f-rl-$1-header", "security"],
    [/^rateLimit\.rules\[(\d+)\]\.events/, "f-rl-$1-events", "security"],
    [/^rateLimit\.rules\[(\d+)\]\.window/, "f-rl-$1-window", "security"],
    [/^rateLimit/, "f-rl-mode", "security"],
    [/^waf\.request_body_in_memory_limit/, "f-waf-memory", "security"],
    [/^waf\.request_body_limit/, "f-waf-body", "security"],
    [/directive|SecRule|SecAction|SecRuleRemove/i, "f-waf-directives", "security"],
    [/^waf\./, "f-waf-mode", "security"],
    [/^authentik\.bypassSources/, "f-ak-sources", "access"],
    [/^forwardAuth\.bypassSources/, "f-fa-sources", "access"],
    [/^ingressiForwardAuth\.bypass_sources/, "f-fi-sources", "access"],
    [/^forwardAuth\.authUpstream/, "f-fa-upstream", "access"],
    [/^forwardAuth\.authEndpoint/, "f-fa-endpoint", "access"],
    [/forward-auth provider/i, "f-sign-in", "access"],
    [/forward auth|users:read|groups:read/i, "f-sign-in-who", "access"],
    [/mTLS|client certificate|mtls role/i, "f-mtls", "access"],
    [/access list/i, "f-access-list", "access"],
    [/custom Caddy JSON|custom_reverse_proxy|reverse_proxy/i, "f-reverse-proxy", "advanced"],
    [/pre[_ -]?handlers?/i, "f-pre-handlers", "advanced"],
    [/wildcard domain|domain/i, "f-domains", "routing"],
    [/upstream|port 2019/i, "f-up-0", "routing"],
    [/certificate/i, "f-certificate", "certificate"],
    [/tag/i, "f-tags", nameSection],
  ];
  for (const [pattern, id, section] of rules) {
    const match = pattern.exec(message);
    if (match) return { id: id.replace("$1", match[1] ?? "0"), section };
  }
  return null;
}
