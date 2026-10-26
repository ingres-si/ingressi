import { isIP } from "node:net";
import { bodyLimitRangeMessage, customDirectivesError, isValidBodyLimit } from "./caddy-waf";
import { normalizeDefaultResponseSettings } from "./caddy-default-response";
import { getProviderDefinition, isValidDnsDuration } from "./dns-providers";
import { normalizeRateLimitSettings } from "./caddy-rate-limit";
import { normalizeProxyProtocolRanges } from "./proxy-protocol";
import { ApiValidationError } from "./api-errors";
import { WAF_TUNING_KEYS, wafTuningError } from "./waf-tuning";

export class SettingsValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SettingsValidationError";
  }
}

export const MAX_SETTINGS_BYTES = 1024 * 1024;
const MAX_SHORT_STRING = 2048;
const MAX_SECRET_LENGTH = 16 * 1024;
const MAX_LIST_ITEMS = 1024;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const CONTINENTS = new Set(["AF", "AN", "AS", "EU", "NA", "OC", "SA"]);

function invalid(message: string): never {
  throw new SettingsValidationError(message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const allowedSet = new Set(allowed);
  const unexpected = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unexpected.length > 0) {
    invalid(`${label} contains unknown field: ${unexpected[0]}`);
  }
}

function required(value: Record<string, unknown>, key: string, label: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(value, key)) {
    invalid(`${label}.${key} is required`);
  }
  return value[key];
}

function hasForbiddenControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function stringValue(
  value: unknown,
  label: string,
  options: { min?: number; max?: number; controls?: boolean } = {}
): string {
  if (typeof value !== "string") invalid(`${label} must be a string`);
  const min = options.min ?? 0;
  const max = options.max ?? MAX_SHORT_STRING;
  if (value.length < min || value.length > max) {
    invalid(`${label} must contain between ${min} and ${max} characters`);
  }
  if (options.controls !== true && hasForbiddenControlCharacter(value)) {
    invalid(`${label} must not contain control characters`);
  }
  return value;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") invalid(`${label} must be a boolean`);
  return value;
}

function integerValue(
  value: unknown,
  label: string,
  min: number,
  max: number
): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    invalid(`${label} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function stringList(
  value: unknown,
  label: string,
  validate?: (item: string, itemLabel: string) => void
): string[] {
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    invalid(`${label} must be an array with at most ${MAX_LIST_ITEMS} entries`);
  }
  return value.map((item, index) => {
    const itemLabel = `${label}[${index}]`;
    const parsed = stringValue(item, itemLabel, { min: 1 });
    validate?.(parsed, itemLabel);
    return parsed;
  });
}

function optionalString(value: Record<string, unknown>, key: string, label: string, max = MAX_SHORT_STRING): void {
  if (value[key] !== undefined) stringValue(value[key], `${label}.${key}`, { max });
}

function optionalMultilineString(
  value: Record<string, unknown>,
  key: string,
  label: string,
  max: number
): void {
  if (value[key] === undefined) return;
  const parsed = stringValue(value[key], `${label}.${key}`, { max, controls: true });
  for (let index = 0; index < parsed.length; index += 1) {
    const code = parsed.charCodeAt(index);
    if ((code < 32 && code !== 10 && code !== 13) || code === 127) {
      invalid(`${label}.${key} must not contain control characters other than line breaks`);
    }
  }
}

function optionalBoolean(value: Record<string, unknown>, key: string, label: string): void {
  if (value[key] !== undefined) booleanValue(value[key], `${label}.${key}`);
}

function httpUrl(value: string, label: string, allowEmpty = false): void {
  if (allowEmpty && value.length === 0) return;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    invalid(`${label} must be a valid HTTP or HTTPS URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    invalid(`${label} must use HTTP or HTTPS`);
  }
}

function ipOrCidr(value: string, label: string, allowPrivateRanges = false): void {
  if (allowPrivateRanges && value === "private_ranges") return;
  const separator = value.lastIndexOf("/");
  if (separator === -1) {
    if (isIP(value) === 0) invalid(`${label} must be an IP address or CIDR range`);
    return;
  }
  const address = value.slice(0, separator);
  const version = isIP(address);
  const prefix = Number(value.slice(separator + 1));
  const maxPrefix = version === 4 ? 32 : version === 6 ? 128 : -1;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    invalid(`${label} must be an IP address or CIDR range`);
  }
}

function headerMap(value: unknown, label: string): void {
  const headers = record(value, label);
  if (Object.keys(headers).length > 100) invalid(`${label} must contain at most 100 headers`);
  for (const [name, rawValue] of Object.entries(headers)) {
    if (!HEADER_NAME.test(name) || name.length > 128) invalid(`${label} contains an invalid header name`);
    stringValue(rawValue, `${label}.${name}`, { max: 8192 });
  }
}

function validateGeneral(value: Record<string, unknown>): void {
  onlyKeys(value, ["primaryDomain", "acmeEmail"], "general settings");
  stringValue(required(value, "primaryDomain", "general settings"), "general.primaryDomain", { min: 1, max: 253 });
  if (value.acmeEmail !== undefined) {
    const email = stringValue(value.acmeEmail, "general.acmeEmail", { max: 320 });
    if (email.length > 0 && !/^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/.test(email)) invalid("general.acmeEmail must be a valid email address");
  }
}

function validateAcme(value: Record<string, unknown>): void {
  onlyKeys(value, ["caUrl", "caRootPem"], "ACME settings");
  optionalString(value, "caUrl", "acme", 4096);
  optionalMultilineString(value, "caRootPem", "acme", 1024 * 1024);
  if (typeof value.caUrl === "string" && value.caUrl.length > 0) httpUrl(value.caUrl, "acme.caUrl");
}

function validateCloudflare(value: Record<string, unknown>): void {
  onlyKeys(value, ["apiToken", "zoneId", "accountId"], "Cloudflare settings");
  stringValue(required(value, "apiToken", "Cloudflare settings"), "cloudflare.apiToken", { min: 1, max: MAX_SECRET_LENGTH });
  optionalString(value, "zoneId", "cloudflare");
  optionalString(value, "accountId", "cloudflare");
}

function validateAuthentik(value: Record<string, unknown>): void {
  onlyKeys(value, ["outpostDomain", "outpostUpstream", "authEndpoint"], "Authentik settings");
  stringValue(required(value, "outpostDomain", "Authentik settings"), "authentik.outpostDomain", { min: 1, max: 253 });
  const upstream = stringValue(required(value, "outpostUpstream", "Authentik settings"), "authentik.outpostUpstream", { min: 1, max: 4096 });
  httpUrl(upstream, "authentik.outpostUpstream");
  optionalString(value, "authEndpoint", "authentik", 4096);
}

function validateForwardAuth(value: Record<string, unknown>): void {
  onlyKeys(value, ["provider", "authUpstream", "authEndpoint"], "Forward Auth settings");
  const provider = required(value, "provider", "Forward Auth settings");
  if (provider !== "authelia" && provider !== "custom") {
    invalid("forward_auth.provider must be 'authelia' or 'custom'");
  }
  const upstream = stringValue(required(value, "authUpstream", "Forward Auth settings"), "forward_auth.authUpstream", { min: 1, max: 4096 });
  httpUrl(upstream, "forward_auth.authUpstream");
  optionalString(value, "authEndpoint", "forward_auth", 4096);
}

function validateMetrics(value: Record<string, unknown>): void {
  onlyKeys(value, ["enabled", "port"], "metrics settings");
  booleanValue(required(value, "enabled", "metrics settings"), "metrics.enabled");
  if (value.port !== undefined) integerValue(value.port, "metrics.port", 1, 65535);
}

function validateLogging(value: Record<string, unknown>): void {
  onlyKeys(value, ["enabled", "format"], "logging settings");
  booleanValue(required(value, "enabled", "logging settings"), "logging.enabled");
  if (value.format !== undefined && value.format !== "json" && value.format !== "console") {
    invalid("logging.format must be json or console");
  }
}

/** Returns the settings to store: the PROXY protocol sources normalized, the rest as given. */
function validateTrustedProxies(value: Record<string, unknown>): Record<string, unknown> {
  onlyKeys(value, ["ranges", "client_ip_headers", "strict", "default_geoblock", "proxy_protocol_ranges"], "trusted proxy settings");
  stringList(required(value, "ranges", "trusted proxy settings"), "trusted-proxies.ranges", (item, label) => ipOrCidr(item, label, true));
  if (value.client_ip_headers !== undefined) {
    stringList(value.client_ip_headers, "trusted-proxies.client_ip_headers", (item, label) => {
      if (!HEADER_NAME.test(item)) invalid(`${label} must be a valid HTTP header name`);
    });
  }
  optionalBoolean(value, "strict", "trusted-proxies");
  optionalBoolean(value, "default_geoblock", "trusted-proxies");
  if (value.proxy_protocol_ranges === undefined) return value;
  if (!Array.isArray(value.proxy_protocol_ranges)) invalid("trusted-proxies.proxy_protocol_ranges must be an array");
  const proxyProtocol = normalizeProxyProtocolRanges(value.proxy_protocol_ranges);
  if ("error" in proxyProtocol) invalid(`trusted-proxies.proxy_protocol_ranges: ${proxyProtocol.error}`);
  return { ...value, proxy_protocol_ranges: proxyProtocol.values };
}

function validateDns(value: Record<string, unknown>): void {
  onlyKeys(value, ["enabled", "resolvers", "fallbacks", "timeout"], "DNS settings");
  const enabled = booleanValue(required(value, "enabled", "DNS settings"), "dns.enabled");
  const resolvers = stringList(required(value, "resolvers", "DNS settings"), "dns.resolvers");
  if (enabled && resolvers.length === 0) invalid("dns.resolvers must not be empty when DNS is enabled");
  if (value.fallbacks !== undefined) stringList(value.fallbacks, "dns.fallbacks");
  optionalString(value, "timeout", "dns", 64);
}

function validateDnsProvider(value: Record<string, unknown>): void {
  onlyKeys(value, ["providers", "default"], "DNS provider settings");
  const providers = record(required(value, "providers", "DNS provider settings"), "dns-provider.providers");
  const providerNames = Object.keys(providers);
  if (providerNames.length > 32) invalid("dns-provider.providers must contain at most 32 providers");
  for (const providerName of providerNames) {
    const definition = getProviderDefinition(providerName);
    if (!definition) invalid(`Unsupported DNS provider: ${providerName}`);
    const credentials = record(providers[providerName], `dns-provider.providers.${providerName}`);
    onlyKeys(credentials, definition.fields.map((field) => field.key), `dns-provider.providers.${providerName}`);
    for (const field of definition.fields) {
      if (field.required) {
        stringValue(required(credentials, field.key, `dns-provider.providers.${providerName}`), `dns-provider.providers.${providerName}.${field.key}`, { min: 1, max: MAX_SECRET_LENGTH });
      } else if (credentials[field.key] !== undefined) {
        const stored = stringValue(credentials[field.key], `dns-provider.providers.${providerName}.${field.key}`, { max: MAX_SECRET_LENGTH });
        if (field.type === "duration" && !isValidDnsDuration(stored)) {
          invalid(`dns-provider.providers.${providerName}.${field.key} must be a duration like "600s" or "10m" (or -1 to disable)`);
        }
      }
    }
  }
  if (value.default !== null && typeof value.default !== "string") {
    invalid("dns-provider.default must be a provider name or null");
  }
  if (typeof value.default === "string" && !Object.prototype.hasOwnProperty.call(providers, value.default)) {
    invalid("dns-provider.default must identify a configured provider");
  }
}

function validateUpstreamDns(value: Record<string, unknown>): void {
  onlyKeys(value, ["enabled", "family"], "upstream DNS settings");
  booleanValue(required(value, "enabled", "upstream DNS settings"), "upstream-dns.enabled");
  const family = required(value, "family", "upstream DNS settings");
  if (family !== "ipv4" && family !== "ipv6" && family !== "both") {
    invalid("upstream-dns.family must be ipv4, ipv6, or both");
  }
}

function validateNumberList(value: unknown, label: string): void {
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) invalid(`${label} must be an array`);
  value.forEach((item, index) => integerValue(item, `${label}[${index}]`, 1, 4_294_967_295));
}

function validateGeoBlock(value: Record<string, unknown>): void {
  const keys = [
    "enabled", "block_countries", "block_continents", "block_asns", "block_cidrs", "block_ips",
    "allow_countries", "allow_continents", "allow_asns", "allow_cidrs", "allow_ips", "trusted_proxies",
    "fail_closed", "response_status", "response_body", "response_headers", "redirect_url",
  ];
  onlyKeys(value, keys, "geoblock settings");
  for (const key of keys) required(value, key, "geoblock settings");
  booleanValue(value.enabled, "geoblock.enabled");
  booleanValue(value.fail_closed, "geoblock.fail_closed");
  for (const key of ["block_countries", "allow_countries"]) {
    stringList(value[key], `geoblock.${key}`, (item, label) => {
      if (!/^[A-Z]{2}$/.test(item)) invalid(`${label} must be an uppercase ISO country code`);
    });
  }
  for (const key of ["block_continents", "allow_continents"]) {
    stringList(value[key], `geoblock.${key}`, (item, label) => {
      if (!CONTINENTS.has(item)) invalid(`${label} must be a valid continent code`);
    });
  }
  validateNumberList(value.block_asns, "geoblock.block_asns");
  validateNumberList(value.allow_asns, "geoblock.allow_asns");
  for (const key of ["block_cidrs", "allow_cidrs"]) {
    stringList(value[key], `geoblock.${key}`, (item, label) => ipOrCidr(item, label));
  }
  for (const key of ["block_ips", "allow_ips"]) {
    stringList(value[key], `geoblock.${key}`, (item, label) => {
      if (isIP(item) === 0) invalid(`${label} must be an IP address`);
    });
  }
  stringList(value.trusted_proxies, "geoblock.trusted_proxies", (item, label) => ipOrCidr(item, label, true));
  integerValue(value.response_status, "geoblock.response_status", 100, 599);
  stringValue(value.response_body, "geoblock.response_body", { max: 65_536, controls: true });
  headerMap(value.response_headers, "geoblock.response_headers");
  const redirect = stringValue(value.redirect_url, "geoblock.redirect_url", { max: 4096 });
  httpUrl(redirect, "geoblock.redirect_url", true);
}

/** The stored global WAF settings an update replaces. */
export type PreviousWafSettings = { custom_directives?: string | null; load_owasp_crs?: boolean } | null;

function validateWaf(value: Record<string, unknown>, previous: PreviousWafSettings): void {
  onlyKeys(
    value,
    [
      "enabled",
      "mode",
      "load_owasp_crs",
      "custom_directives",
      "excluded_rule_ids",
      "request_body_limit",
      "request_body_in_memory_limit",
      "request_body_limit_action",
      ...WAF_TUNING_KEYS,
    ],
    "WAF settings"
  );
  booleanValue(required(value, "enabled", "WAF settings"), "waf.enabled");
  const mode = required(value, "mode", "WAF settings");
  if (mode !== "Off" && mode !== "On" && mode !== "DetectionOnly") {
    invalid("waf.mode must be Off, On, or DetectionOnly");
  }
  const tuningError = wafTuningError(value);
  if (tuningError) invalid(tuningError);
  booleanValue(required(value, "load_owasp_crs", "WAF settings"), "waf.load_owasp_crs");
  const directives = stringValue(required(value, "custom_directives", "WAF settings"), "waf.custom_directives", { max: 100_000, controls: true });
  // Only lines this update newly drops are rejected, as in the dashboard form:
  // a stored rule that a later release started dropping must not block
  // unrelated changes (buildWafHandler still leaves it out and logs it).
  const directiveError = customDirectivesError(
    directives,
    { crsLoaded: value.load_owasp_crs === true },
    previous
      ? { directives: previous.custom_directives, options: { crsLoaded: Boolean(previous.load_owasp_crs) } }
      : undefined
  );
  if (directiveError) invalid(directiveError);
  // Each listed id becomes an exclusion record (src/lib/models/waf-exclusions.ts), whose ids are Int32.
  if (value.excluded_rule_ids !== undefined) {
    const ids = value.excluded_rule_ids;
    if (!Array.isArray(ids) || ids.length > MAX_LIST_ITEMS) invalid("waf.excluded_rule_ids must be an array");
    ids.forEach((item, index) => integerValue(item, `waf.excluded_rule_ids[${index}]`, 1, 2_147_483_647));
  }
  validateBodyLimits(value, "waf");
}

/**
 * Shared by the global WAF settings and the per-host WAF config. Values above
 * Coraza's 1 GiB ceiling make Caddy reject the whole config document, so they
 * are refused at the input layer rather than silently dropped later.
 */
export function validateBodyLimits(value: Record<string, unknown>, prefix: string): void {
  for (const key of ["request_body_limit", "request_body_in_memory_limit"] as const) {
    const raw = value[key];
    if (raw === undefined || raw === null) continue;
    if (!isValidBodyLimit(raw)) invalid(bodyLimitRangeMessage(`${prefix}.${key}`));
  }
  const action = value.request_body_limit_action;
  if (action !== undefined && action !== null && action !== "Reject" && action !== "ProcessPartial") {
    invalid(`${prefix}.request_body_limit_action must be Reject or ProcessPartial`);
  }
  const limit = value.request_body_limit;
  const inMemory = value.request_body_in_memory_limit;
  if (typeof limit === "number" && typeof inMemory === "number" && inMemory > limit) {
    invalid(`${prefix}.request_body_in_memory_limit must not exceed ${prefix}.request_body_limit`);
  }
}

function validateErrorPages(value: Record<string, unknown>): void {
  onlyKeys(value, ["rules"], "error page settings");
  const rules = required(value, "rules", "error page settings");
  if (!Array.isArray(rules) || rules.length > 100) invalid("error-pages.rules must be an array with at most 100 entries");
  rules.forEach((rawRule, index) => {
    const label = `error-pages.rules[${index}]`;
    const rule = record(rawRule, label);
    onlyKeys(rule, ["statuses", "body", "contentType"], label);
    const statuses = required(rule, "statuses", label);
    if (!Array.isArray(statuses) || statuses.length > 200) invalid(`${label}.statuses must be an array`);
    statuses.forEach((status, statusIndex) => integerValue(status, `${label}.statuses[${statusIndex}]`, 400, 599));
    stringValue(required(rule, "body", label), `${label}.body`, { min: 1, max: 65_536, controls: true });
    optionalString(rule, "contentType", label, 128);
  });
}

/** Strict, like every other group; saveRateLimitSettings stores the normalized form. */
function validateRateLimit(value: Record<string, unknown>): void {
  try {
    normalizeRateLimitSettings(value, "rate-limit");
  } catch (error) {
    if (error instanceof ApiValidationError) invalid(error.message);
    throw error;
  }
}

function validateDefaultResponse(value: Record<string, unknown>): void {
  onlyKeys(value, ["mode", "status", "body", "headers", "redirectUrl"], "default response settings");
  normalizeDefaultResponseSettings(value);
}

export function assertSettingsPayloadSize(input: unknown): void {
  let serialized: string;
  try {
    serialized = JSON.stringify(input);
  } catch {
    invalid("Settings payload must be valid JSON data");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_SETTINGS_BYTES) {
    invalid(`Settings payload must not exceed ${MAX_SETTINGS_BYTES} bytes`);
  }
}

/** Strict runtime validation for REST settings writes. */
export function validateSettingsGroup(
  group: string,
  input: unknown,
  { previousWaf = null }: { previousWaf?: PreviousWafSettings } = {}
): unknown {
  assertSettingsPayloadSize(input);

  const value = record(input, `${group} settings`);
  switch (group) {
    case "general": validateGeneral(value); break;
    case "acme": validateAcme(value); break;
    case "cloudflare": validateCloudflare(value); break;
    case "authentik": validateAuthentik(value); break;
    case "forward-auth": validateForwardAuth(value); break;
    case "metrics": validateMetrics(value); break;
    case "logging": validateLogging(value); break;
    case "trusted-proxies": return validateTrustedProxies(value);
    case "dns": validateDns(value); break;
    case "dns-provider": validateDnsProvider(value); break;
    case "upstream-dns": validateUpstreamDns(value); break;
    case "geoblock": validateGeoBlock(value); break;
    case "waf": validateWaf(value, previousWaf); break;
    case "error-pages": validateErrorPages(value); break;
    case "default-response": validateDefaultResponse(value); break;
    case "rate-limit": validateRateLimit(value); break;
    default: invalid("Unknown settings group");
  }
  return input;
}
