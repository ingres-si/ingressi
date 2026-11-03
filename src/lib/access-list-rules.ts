/**
 * Access list rules: ordered allow/deny rules by IP address or
 * CIDR range (IPv4 and IPv6), country, continent or AS number, and the list
 * settings that go with them (what an unmatched request gets, what a denied
 * request gets).
 *
 * Semantics: rules are checked in order and the first rule that matches
 * decides; a request that matches no rule gets the list's default action.
 * Basic-auth members (access_list_entries) apply after the rules.
 *
 * Pure: no database and no Node built-ins, so the dashboard validates input
 * with the same code as the server. Caddy JSON is built in
 * caddy-access-lists.ts.
 */
import { ApiValidationError } from "./api-errors";
import { COUNTRIES } from "@/src/components/proxy-hosts/countries";

export const ACCESS_LIST_RULE_ACTIONS = ["allow", "deny"] as const;
export type AccessListRuleAction = (typeof ACCESS_LIST_RULE_ACTIONS)[number];

export const ACCESS_LIST_RULE_KINDS = ["ip", "country", "continent", "asn"] as const;
export type AccessListRuleKind = (typeof ACCESS_LIST_RULE_KINDS)[number];

export const ACCESS_LIST_DEFAULT_ACTIONS = ["allow", "deny"] as const;
export type AccessListDefaultAction = (typeof ACCESS_LIST_DEFAULT_ACTIONS)[number];

/** systemKey of the global list that applies to every host before anything else. */
export const BLOCKED_SOURCES_KEY = "blocked_sources";
export const BLOCKED_SOURCES_NAME = "Blocked sources";

/** Access log field Caddy adds to requests an access list denied itself (log-parser.ts). */
export const ACCESS_LIST_LOG_FIELD = "access_list";

export const MAX_RULES_PER_LIST = 2000;
export const MAX_VALUES_PER_RULE = 500;
export const MAX_RULE_NOTE_LENGTH = 500;
export const MAX_DENY_BODY_LENGTH = 4096;
export const MAX_REDIRECT_URL_LENGTH = 2048;
export const MAX_LIST_NAME_LENGTH = 200;
export const MAX_LIST_DESCRIPTION_LENGTH = 1000;
/** A rule cannot expire more than ten years ahead. */
export const MAX_EXPIRY_MS = 10 * 366 * 24 * 60 * 60 * 1000;
export const DEFAULT_DENY_STATUS = 403;
export const DEFAULT_DENY_BODY = "Forbidden";

export const CONTINENTS: ReadonlyArray<{ code: string; name: string }> = [
  { code: "AF", name: "Africa" },
  { code: "AN", name: "Antarctica" },
  { code: "AS", name: "Asia" },
  { code: "EU", name: "Europe" },
  { code: "NA", name: "North America" },
  { code: "OC", name: "Oceania" },
  { code: "SA", name: "South America" },
];

const COUNTRY_NAMES: ReadonlyMap<string, string> = new Map(COUNTRIES.map((country) => [country.code, country.name]));
const CONTINENT_NAMES: ReadonlyMap<string, string> = new Map(CONTINENTS.map((continent) => [continent.code, continent.name]));

export function countryName(code: string): string | null {
  return COUNTRY_NAMES.get(code) ?? null;
}

export function continentName(code: string): string | null {
  return CONTINENT_NAMES.get(code) ?? null;
}

/** The private networks the "private_ranges" shorthand stands for (as Caddy's own shorthand). */
export const PRIVATE_RANGES_VALUE = "private_ranges";

// ── IP addresses and CIDR ranges ───────────────────────────────────────

export type ParsedIpRange = {
  version: 4 | 6;
  /** The network address (host bits cleared). */
  network: bigint;
  prefix: number;
  /** Canonical text: a plain address for a full-length prefix, otherwise network/prefix. */
  text: string;
};

const B0 = BigInt(0);
const B8 = BigInt(8);
const B16 = BigInt(16);
const B255 = BigInt(255);
const BFFFF = BigInt(0xffff);

function parseIpv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = B0;
  for (const part of parts) {
    // Go (and so Caddy) refuses leading zeros, which some tools read as octal.
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const byte = Number(part);
    if (byte > 255) return null;
    value = (value << B8) | BigInt(byte);
  }
  return value;
}

function parseIpv6(raw: string): bigint | null {
  let text = raw.toLowerCase();
  if (text.length === 0 || text.length > 45 || text.includes("%")) return null;
  // An IPv4 tail ("::ffff:192.0.2.1") stands for the last two groups.
  const lastColon = text.lastIndexOf(":");
  if (lastColon === -1) return null;
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIpv4(tail);
    if (v4 === null) return null;
    text = `${text.slice(0, lastColon + 1)}${(v4 >> B16).toString(16)}:${(v4 & BFFFF).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  let value = B0;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << B16) | BigInt(Number.parseInt(group, 16));
  }
  return value;
}

function formatIpv4(value: bigint): string {
  const bytes: number[] = [];
  for (let shift = 24; shift >= 0; shift -= 8) bytes.push(Number((value >> BigInt(shift)) & B255));
  return bytes.join(".");
}

/** RFC 5952 text: lowercase, the longest run of two or more zero groups compressed. */
function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let shift = 112; shift >= 0; shift -= 16) groups.push(Number((value >> BigInt(shift)) & BFFFF));
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < 8; ) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < 8 && groups[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestLength < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
}

/** An IP address or CIDR range, IPv4 or IPv6, normalized; null when it is not one. */
export function parseIpRange(input: string): ParsedIpRange | null {
  const text = input.trim();
  if (!text || text.length > 64) return null;
  const parts = text.split("/");
  if (parts.length > 2) return null;
  const [address, prefixText] = parts;
  const version: 4 | 6 = address.includes(":") ? 6 : 4;
  const value = version === 4 ? parseIpv4(address) : parseIpv6(address);
  if (value === null) return null;
  const bits = version === 4 ? 32 : 128;
  let prefix = bits;
  if (prefixText !== undefined) {
    if (!/^(0|[1-9]\d{0,2})$/.test(prefixText)) return null;
    prefix = Number(prefixText);
    if (prefix > bits) return null;
  }
  const shift = BigInt(bits - prefix);
  const network = (value >> shift) << shift;
  const formatted = version === 4 ? formatIpv4(network) : formatIpv6(network);
  return { version, network, prefix, text: prefix === bits ? formatted : `${formatted}/${prefix}` };
}

/** True when `address` (a parsed single address) lies inside `range`. */
export function ipRangeContains(range: ParsedIpRange, address: ParsedIpRange): boolean {
  if (range.version !== address.version || address.prefix < range.prefix) return false;
  const bits = range.version === 4 ? 32 : 128;
  const shift = BigInt(bits - range.prefix);
  return address.network >> shift === range.network >> shift;
}

// ── Values ─────────────────────────────────────────────────────────────

const MAX_ASN = 4294967295;

function hasControlCharacter(value: string, allowNewlines = false): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (allowNewlines && (code === 9 || code === 10 || code === 13)) continue;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function invalid(message: string): never {
  throw new ApiValidationError(message);
}

/** The raw values of a rule: an array of strings or numbers, or one string separated by commas or spaces. */
function rawValues(input: unknown, label: string): string[] {
  if (typeof input === "string") return input.split(/[\s,]+/).filter(Boolean);
  if (typeof input === "number") return [String(input)];
  if (!Array.isArray(input)) invalid(`${label}.values must be an array`);
  if (input.length > MAX_VALUES_PER_RULE) invalid(`${label}.values can hold at most ${MAX_VALUES_PER_RULE} values`);
  return input.map((item, index) => {
    if (typeof item === "number" && Number.isFinite(item)) return String(item);
    if (typeof item !== "string") invalid(`${label}.values[${index}] must be a string`);
    return item.trim();
  }).filter(Boolean);
}

/** One normalized value of `kind`, or a message saying what is wrong with it. */
export function normalizeRuleValue(kind: AccessListRuleKind, raw: string): { value: string } | { error: string } {
  const text = raw.trim();
  switch (kind) {
    case "ip": {
      if (text.toLowerCase() === PRIVATE_RANGES_VALUE) return { value: PRIVATE_RANGES_VALUE };
      const range = parseIpRange(text);
      return range ? { value: range.text } : { error: `"${text}" is not an IP address or CIDR range` };
    }
    case "country": {
      const code = text.toUpperCase();
      return COUNTRY_NAMES.has(code) ? { value: code } : { error: `"${text}" is not a two-letter country code` };
    }
    case "continent": {
      const code = text.toUpperCase();
      return CONTINENT_NAMES.has(code)
        ? { value: code }
        : { error: `"${text}" is not a continent code (AF, AN, AS, EU, NA, OC or SA)` };
    }
    case "asn": {
      const digits = /^(?:as)?(\d{1,10})$/i.exec(text)?.[1];
      const asn = digits === undefined ? Number.NaN : Number(digits);
      return Number.isSafeInteger(asn) && asn >= 1 && asn <= MAX_ASN && String(asn) === digits
        ? { value: String(asn) }
        : { error: `"${text}" is not an AS number` };
    }
  }
}

/** Normalized, deduplicated values of `kind`; throws a 400 naming the first bad value. */
export function normalizeRuleValues(kind: AccessListRuleKind, input: unknown, label = "rule"): string[] {
  const values: string[] = [];
  const seen = new Set<string>();
  for (const raw of rawValues(input, label)) {
    const result = normalizeRuleValue(kind, raw);
    if ("error" in result) invalid(`${label}.values: ${result.error}`);
    if (seen.has(result.value)) continue;
    seen.add(result.value);
    values.push(result.value);
  }
  if (values.length === 0) invalid(`${label}.values must name at least one value`);
  if (values.length > MAX_VALUES_PER_RULE) invalid(`${label}.values can hold at most ${MAX_VALUES_PER_RULE} values`);
  return values;
}

// ── Rules ──────────────────────────────────────────────────────────────

export type AccessListRuleData = {
  action: AccessListRuleAction;
  kind: AccessListRuleKind;
  values: string[];
  note: string | null;
  /** ISO 8601; null for a rule that never expires. */
  expiresAt: string | null;
};

/** Fields of a stored rule that clients may send back unchanged; they are ignored. */
const IGNORED_RULE_FIELDS = new Set(["id", "position", "accessListId", "createdAt", "updatedAt", "createdBy", "expired"]);
const RULE_FIELDS = new Set(["action", "kind", "values", "note", "expiresAt"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isRuleAction(value: unknown): value is AccessListRuleAction {
  return typeof value === "string" && (ACCESS_LIST_RULE_ACTIONS as readonly string[]).includes(value);
}

export function isRuleKind(value: unknown): value is AccessListRuleKind {
  return typeof value === "string" && (ACCESS_LIST_RULE_KINDS as readonly string[]).includes(value);
}

export function normalizeRuleNote(input: unknown, label = "rule"): string | null {
  if (input === undefined || input === null) return null;
  if (typeof input !== "string") invalid(`${label}.note must be a string`);
  const note = input.trim();
  if (note.length > MAX_RULE_NOTE_LENGTH) invalid(`${label}.note can be at most ${MAX_RULE_NOTE_LENGTH} characters`);
  if (hasControlCharacter(note)) invalid(`${label}.note must not contain control characters`);
  return note || null;
}

/** An expiry in the future, as ISO 8601; null for none. */
export function normalizeRuleExpiry(input: unknown, now: Date, label = "rule"): string | null {
  if (input === undefined || input === null || input === "") return null;
  if (typeof input !== "string" || input.length > 64) invalid(`${label}.expiresAt must be an ISO 8601 date and time`);
  const time = Date.parse(input);
  if (!Number.isFinite(time)) invalid(`${label}.expiresAt must be an ISO 8601 date and time`);
  if (time <= now.getTime()) invalid(`${label}.expiresAt must be in the future`);
  if (time - now.getTime() > MAX_EXPIRY_MS) invalid(`${label}.expiresAt can be at most ten years ahead`);
  return new Date(time).toISOString();
}

/**
 * A rule from client input. `existingExpiry` keeps a stored expiry that has
 * not passed when the input sends it back unchanged (an expiry in the past is
 * refused, so a rule saved again just before it expires would otherwise fail).
 */
export function normalizeRuleInput(
  input: unknown,
  options: { now?: Date; label?: string; existingExpiry?: string | null } = {}
): AccessListRuleData {
  const label = options.label ?? "rule";
  if (!isRecord(input)) invalid(`${label} must be an object`);
  for (const key of Object.keys(input)) {
    if (!RULE_FIELDS.has(key) && !IGNORED_RULE_FIELDS.has(key)) invalid(`${label} has an unknown field "${key}"`);
  }
  if (!isRuleAction(input.action)) invalid(`${label}.action must be "allow" or "deny"`);
  if (!isRuleKind(input.kind)) invalid(`${label}.kind must be "ip", "country", "continent" or "asn"`);
  const now = options.now ?? new Date();
  const expiresAt =
    options.existingExpiry && input.expiresAt === options.existingExpiry
      ? options.existingExpiry
      : normalizeRuleExpiry(input.expiresAt, now, label);
  return {
    action: input.action,
    kind: input.kind,
    values: normalizeRuleValues(input.kind, input.values, label),
    note: normalizeRuleNote(input.note, label),
    expiresAt,
  };
}

/** A list of rules in order (for a full replace); throws on the first bad rule. */
export function normalizeRuleList(
  input: unknown,
  options: { now?: Date; existingExpiries?: ReadonlyMap<number, string | null> } = {}
): AccessListRuleData[] {
  if (!Array.isArray(input)) invalid("rules must be an array");
  if (input.length > MAX_RULES_PER_LIST) invalid(`An access list can hold at most ${MAX_RULES_PER_LIST} rules`);
  return input.map((rule, index) => {
    const id = isRecord(rule) && typeof rule.id === "number" ? rule.id : null;
    return normalizeRuleInput(rule, {
      now: options.now,
      label: `rules[${index}]`,
      existingExpiry: id !== null ? options.existingExpiries?.get(id) ?? null : null,
    });
  });
}

/** True once a rule's expiry has passed: it no longer applies. */
export function isRuleExpired(rule: { expiresAt: string | null }, now: Date = new Date()): boolean {
  if (!rule.expiresAt) return false;
  const time = Date.parse(rule.expiresAt);
  return Number.isFinite(time) && time <= now.getTime();
}

// ── List settings ──────────────────────────────────────────────────────

export type AccessListSettings = {
  defaultAction: AccessListDefaultAction;
  denyStatus: number;
  denyBody: string | null;
  denyRedirectUrl: string | null;
  failClosed: boolean;
  skipAuthForAllowed: boolean;
};

const SETTINGS_FIELDS = ["defaultAction", "denyStatus", "denyBody", "denyRedirectUrl", "failClosed", "skipAuthForAllowed"] as const;

/** The settings fields present in `input`, validated; missing fields are left out. */
export function normalizeListSettings(input: Record<string, unknown>): Partial<AccessListSettings> {
  const out: Partial<AccessListSettings> = {};
  if (input.defaultAction !== undefined) {
    if (input.defaultAction !== "allow" && input.defaultAction !== "deny") {
      invalid('defaultAction must be "allow" or "deny"');
    }
    out.defaultAction = input.defaultAction;
  }
  if (input.denyStatus !== undefined) {
    const status = input.denyStatus;
    if (typeof status !== "number" || !Number.isInteger(status) || status < 400 || status > 599) {
      invalid("denyStatus must be an HTTP status from 400 to 599");
    }
    out.denyStatus = status;
  }
  if (input.denyBody !== undefined) {
    if (input.denyBody !== null && typeof input.denyBody !== "string") invalid("denyBody must be a string or null");
    const body = input.denyBody ?? "";
    if (body.length > MAX_DENY_BODY_LENGTH) invalid(`denyBody can be at most ${MAX_DENY_BODY_LENGTH} characters`);
    if (hasControlCharacter(body, true)) invalid("denyBody must not contain control characters");
    out.denyBody = body.length > 0 ? body : null;
  }
  if (input.denyRedirectUrl !== undefined) {
    if (input.denyRedirectUrl !== null && typeof input.denyRedirectUrl !== "string") {
      invalid("denyRedirectUrl must be a string or null");
    }
    const url = (input.denyRedirectUrl ?? "").trim();
    if (url.length > MAX_REDIRECT_URL_LENGTH) invalid(`denyRedirectUrl can be at most ${MAX_REDIRECT_URL_LENGTH} characters`);
    if (url.length > 0) {
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        invalid("denyRedirectUrl must be an HTTP or HTTPS URL");
      }
      if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || hasControlCharacter(url) || /\s/.test(url)) {
        invalid("denyRedirectUrl must be an HTTP or HTTPS URL");
      }
    }
    out.denyRedirectUrl = url.length > 0 ? url : null;
  }
  if (input.failClosed !== undefined) {
    if (typeof input.failClosed !== "boolean") invalid("failClosed must be true or false");
    out.failClosed = input.failClosed;
  }
  if (input.skipAuthForAllowed !== undefined) {
    if (typeof input.skipAuthForAllowed !== "boolean") invalid("skipAuthForAllowed must be true or false");
    out.skipAuthForAllowed = input.skipAuthForAllowed;
  }
  return out;
}

export function hasListSettings(input: Record<string, unknown>): boolean {
  return SETTINGS_FIELDS.some((field) => input[field] !== undefined);
}

/** A list name: required, trimmed, at most 200 characters, no control characters. */
export function normalizeListName(input: unknown): string {
  if (typeof input !== "string") invalid("name is required");
  const name = input.trim();
  if (!name) invalid("name is required");
  if (name.length > MAX_LIST_NAME_LENGTH) invalid(`name can be at most ${MAX_LIST_NAME_LENGTH} characters`);
  if (hasControlCharacter(name)) invalid("name must not contain control characters");
  return name;
}

export function normalizeListDescription(input: unknown): string | null {
  if (input === undefined || input === null) return null;
  if (typeof input !== "string") invalid("description must be a string or null");
  const description = input.trim();
  if (description.length > MAX_LIST_DESCRIPTION_LENGTH) {
    invalid(`description can be at most ${MAX_LIST_DESCRIPTION_LENGTH} characters`);
  }
  if (hasControlCharacter(description, true)) invalid("description must not contain control characters");
  return description || null;
}

/** A basic-auth member: a username Caddy can match (no colon) and a password. */
export function normalizeMemberInput(input: unknown, label = "member"): { username: string; password: string } {
  if (!isRecord(input)) invalid(`${label} must be an object`);
  if (typeof input.username !== "string") invalid(`${label}.username is required`);
  const username = input.username.trim();
  if (!username) invalid(`${label}.username is required`);
  if (username.length > 128) invalid(`${label}.username can be at most 128 characters`);
  if (username.includes(":") || hasControlCharacter(username)) {
    invalid(`${label}.username must not contain a colon or control characters`);
  }
  return { username, password: normalizeMemberPassword(input.password, label) };
}

/** A basic-auth password: 1 to 1024 characters. */
export function normalizeMemberPassword(input: unknown, label = "member"): string {
  if (typeof input !== "string" || input.length === 0) invalid(`${label}.password is required`);
  if (input.length > 1024) invalid(`${label}.password can be at most 1024 characters`);
  return input;
}

// ── Display ────────────────────────────────────────────────────────────

export type AccessListType =
  | "empty"
  | "basic_auth"
  | "geo"
  | "address_allowlist"
  | "address_blocklist"
  | "rules"
  | "blocked_sources";

const TYPE_LABELS: Record<AccessListType, string> = {
  empty: "Empty",
  basic_auth: "Basic auth",
  geo: "Geo",
  address_allowlist: "Address allowlist",
  address_blocklist: "Address blocklist",
  rules: "Rules",
  blocked_sources: "Global blocklist",
};

/** What a list does, for the list table: from its rules, default action and members. */
export function classifyAccessList(list: {
  systemKey?: string | null;
  defaultAction: string;
  rules: ReadonlyArray<{ action: string; kind: string }>;
  memberCount: number;
}): { type: AccessListType; label: string; basicAuth: boolean } {
  if (list.systemKey === BLOCKED_SOURCES_KEY) {
    return { type: "blocked_sources", label: TYPE_LABELS.blocked_sources, basicAuth: false };
  }
  const basicAuth = list.memberCount > 0;
  let type: AccessListType;
  if (list.rules.length === 0) {
    type = list.defaultAction === "deny" ? "rules" : basicAuth ? "basic_auth" : "empty";
  } else if (list.rules.some((rule) => rule.kind === "country" || rule.kind === "continent")) {
    type = "geo";
  } else if (list.defaultAction === "deny" && list.rules.every((rule) => rule.action === "allow")) {
    type = "address_allowlist";
  } else if (list.defaultAction === "allow" && list.rules.every((rule) => rule.action === "deny")) {
    type = "address_blocklist";
  } else {
    type = "rules";
  }
  const label = basicAuth && type !== "basic_auth" ? `${TYPE_LABELS[type]} and basic auth` : TYPE_LABELS[type];
  return { type, label, basicAuth };
}

/** "Address", "Network", "Country", ... for a rule's values. */
export function ruleKindLabel(kind: AccessListRuleKind, values: readonly string[]): string {
  switch (kind) {
    case "ip":
      return values.length === 1 && !values[0].includes("/") && values[0] !== PRIVATE_RANGES_VALUE ? "Address" : "Network";
    case "country":
      return values.length === 1 ? "Country" : "Countries";
    case "continent":
      return values.length === 1 ? "Continent" : "Continents";
    case "asn":
      return values.length === 1 ? "AS number" : "AS numbers";
  }
}

/** A rule's values as text: "IT · Italy", "AS64500", "203.0.113.0/26, 2001:db8::/32". */
export function ruleValuesText(kind: AccessListRuleKind, values: readonly string[]): string {
  if (kind === "asn") return values.map((value) => `AS${value}`).join(", ");
  if (kind === "country" || kind === "continent") {
    if (values.length === 1) {
      const name = kind === "country" ? countryName(values[0]) : continentName(values[0]);
      return name ? `${values[0]} · ${name}` : values[0];
    }
    return values.join(", ");
  }
  return values.join(", ");
}
