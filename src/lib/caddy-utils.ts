/**
 * Pure utility functions extracted from caddy.ts.
 * No DB, network, or filesystem dependencies — safe to unit-test directly.
 */
import { isIP } from "node:net";

// ---------------------------------------------------------------------------
// Private range expansion
// ---------------------------------------------------------------------------

export const PRIVATE_RANGES_CIDRS = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "fd00::/8",
  "::1/128",
];

// ---------------------------------------------------------------------------
// Placeholder escaping for operator-authored response content
// ---------------------------------------------------------------------------

/**
 * Caddy expands placeholders in static_response bodies and header values at
 * serve time, and its global providers read files ({file.*}), environment
 * variables ({env.*}) and host details ({system.*}). Response content typed by
 * an operator (error pages, path-block bodies, default responses) is meant to
 * be served literally, so escape the opening brace of those placeholders.
 * Caddy treats any brace preceded by a backslash as a literal and drops the
 * backslash, so the served text is unchanged.
 */
const HOST_PLACEHOLDER_RE = /(?<!\\)\{(?=(?:file|env|system)\.)/g;

export function escapeHostPlaceholders(value: string): string {
  return value.replace(HOST_PLACEHOLDER_RE, "\\{");
}

export function expandPrivateRanges(proxies: string[]): string[] {
  if (!proxies.includes("private_ranges")) return proxies;
  return proxies.flatMap((p) => (p === "private_ranges" ? PRIVATE_RANGES_CIDRS : [p]));
}

// ---------------------------------------------------------------------------
// Type helpers
// ---------------------------------------------------------------------------

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Deep merge (prototype-pollution safe)
// ---------------------------------------------------------------------------

export function mergeDeep(
  target: Record<string, unknown>,
  source: Record<string, unknown>
) {
  for (const [key, value] of Object.entries(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    const existing = target[key];
    if (isPlainObject(existing) && isPlainObject(value)) {
      mergeDeep(existing, value);
    } else {
      target[key] = value;
    }
  }
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

export function parseJson<T>(value: string | null, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch (error) {
    console.warn("Failed to parse JSON value", value, error);
    return fallback;
  }
}

export function parseOptionalJson(value: string | null | undefined) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch (error) {
    console.warn("Failed to parse custom JSON", error);
    return null;
  }
}

export function parseCustomHandlers(
  value: string | null | undefined
): Record<string, unknown>[] {
  const parsed = parseOptionalJson(value);
  if (!parsed) return [];
  const list = Array.isArray(parsed) ? parsed : [parsed];
  const handlers: Record<string, unknown>[] = [];
  for (const item of list) {
    if (isPlainObject(item)) {
      handlers.push(item);
    } else {
      console.warn("Ignoring custom handler entry that is not an object", item);
    }
  }
  return handlers;
}

// ---------------------------------------------------------------------------
// Address / upstream parsing
// ---------------------------------------------------------------------------

export function formatDialAddress(host: string, port: string) {
  return isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
}

export function parseHostPort(
  value: string
): { host: string; port: string } | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith("[")) {
    const closeIndex = trimmed.indexOf("]");
    if (closeIndex <= 1) return null;
    const host = trimmed.slice(1, closeIndex);
    const remainder = trimmed.slice(closeIndex + 1);
    if (!remainder.startsWith(":")) return null;
    const port = remainder.slice(1).trim();
    if (!port) return null;
    return { host, port };
  }

  const firstColon = trimmed.indexOf(":");
  const lastColon = trimmed.lastIndexOf(":");
  if (firstColon === -1 || firstColon !== lastColon) return null;

  const host = trimmed.slice(0, lastColon).trim();
  const port = trimmed.slice(lastColon + 1).trim();
  if (!host || !port) return null;

  return { host, port };
}

export type ParsedUpstreamTarget = {
  original: string;
  dial: string;
  scheme: "http" | "https" | null;
  host: string | null;
  port: string | null;
};

export function parseUpstreamTarget(upstream: string): ParsedUpstreamTarget {
  const trimmed = upstream.trim();
  if (!trimmed) {
    return { original: upstream, dial: upstream, scheme: null, host: null, port: null };
  }

  try {
    const url = new URL(trimmed);
    if (url.protocol === "http:" || url.protocol === "https:") {
      const scheme = url.protocol === "https:" ? "https" : "http";
      const port = url.port || (scheme === "https" ? "443" : "80");
      const host = url.hostname;
      return { original: trimmed, dial: formatDialAddress(host, port), scheme, host, port };
    }
  } catch {
    // fall through
  }

  const parsed = parseHostPort(trimmed);
  if (!parsed) {
    return { original: trimmed, dial: trimmed, scheme: null, host: null, port: null };
  }

  return {
    original: trimmed,
    dial: formatDialAddress(parsed.host, parsed.port),
    scheme: null,
    host: parsed.host,
    port: parsed.port,
  };
}

/** The dial address of the Authentik outpost route (the outpost's own paths). */
export function authentikOutpostDial(upstream: string): string {
  try {
    const url = new URL(upstream);
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    return `${url.hostname}:${port}`;
  } catch {
    return upstream.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}

/** The dial address of the Authentik forward-auth subrequest. */
export function authentikAuthDial(upstream: string): string {
  return upstream.replace(/^https?:\/\//, "").replace(/\/$/, "").split("/")[0];
}

/** The dial address of a generic forward-auth server, or null when it is not an http(s) URL. */
export function forwardAuthDial(upstream: string): string | null {
  try {
    const url = new URL(upstream);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    return `${url.hostname}:${port}`;
  } catch {
    return null;
  }
}

/**
 * The port of a Caddy dial address as Caddy splits it: an optional network
 * prefix ("tcp/", "udp/", "unix/"), then host:port with an IPv6 host in
 * brackets. The port comes back as written, so a range ("2019-2019") or a
 * placeholder stays visible. Null when the address names no port.
 */
export function dialAddressPort(dial: string): string | null {
  let address = dial.trim();
  const slash = address.indexOf("/");
  if (slash !== -1) address = address.slice(slash + 1);
  if (address.startsWith("[")) {
    const close = address.indexOf("]");
    if (close === -1) return null;
    const rest = address.slice(close + 1);
    return rest.startsWith(":") ? rest.slice(1) : null;
  }
  const colon = address.lastIndexOf(":");
  return colon === -1 ? null : address.slice(colon + 1);
}

// ---------------------------------------------------------------------------
// Duration parsing
// ---------------------------------------------------------------------------

export function toDurationMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;

  const regex = /(\d+(?:\.\d+)?)(ms|s|m|h)/g;
  let total = 0;
  let matched = false;
  let consumed = 0;

  while (true) {
    const match = regex.exec(trimmed);
    if (!match) break;
    matched = true;
    consumed += match[0].length;
    const valueNum = Number.parseFloat(match[1]);
    if (!Number.isFinite(valueNum)) return null;
    const unit = match[2];
    if (unit === "ms") total += valueNum;
    else if (unit === "s") total += valueNum * 1000;
    else if (unit === "m") total += valueNum * 60_000;
    else if (unit === "h") total += valueNum * 3_600_000;
  }

  if (!matched || consumed !== trimmed.length) return null;

  const rounded = Math.round(total);
  return rounded > 0 ? rounded : null;
}
