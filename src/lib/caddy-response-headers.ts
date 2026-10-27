import { escapeHostPlaceholders } from "./caddy-utils";

/**
 * Response headers set or removed on every response of the main HTTP server
 * (Host defaults → Response headers; settings key "response_headers", REST
 * group "response-headers"). Removing Server and Via hides Caddy's own.
 */
export type ResponseHeadersSettings = {
  set: Record<string, string>;
  remove: string[];
};

export type CaddyResponseHeadersRoute = {
  handle: Array<Record<string, unknown>>;
};

const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const MAX_HEADERS = 100;
const MAX_NAME_LENGTH = 128;
const MAX_VALUE_LENGTH = 8192;
/** Framing and hop-by-hop headers: changing them on every response breaks every response. */
const PROTECTED_HEADERS = new Set([
  "connection",
  "content-length",
  "keep-alive",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Placeholders that copy what the client sent: a request cookie or header
 * (Cookie, Authorization) put in a response header is readable by any page
 * script of every host, which defeats HttpOnly session cookies.
 */
const REQUEST_DATA_PLACEHOLDER = /\{http\.request\.(?:header|cookie)s?\./i;

export class ResponseHeadersValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ResponseHeadersValidationError";
  }
}

function invalid(message: string): never {
  throw new ResponseHeadersValidationError(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasForbiddenControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 127 || (code < 32 && code !== 9)) return true;
  }
  return false;
}

function headerName(raw: unknown, seen: Set<string>): string {
  if (typeof raw !== "string") invalid("Response header names must be strings");
  const name = raw.trim();
  if (!HEADER_NAME_PATTERN.test(name) || name.length > MAX_NAME_LENGTH) {
    invalid(`Invalid response header name: ${raw}`);
  }
  const folded = name.toLowerCase();
  if (PROTECTED_HEADERS.has(folded)) invalid(`${name} cannot be set or removed on every response`);
  if (seen.has(folded)) invalid(`Response header ${name} is listed more than once`);
  seen.add(folded);
  return name;
}

/**
 * Validate and canonicalize the stored/API representation. Strict, so a bad
 * setting is refused when saved instead of making Caddy reject every reload.
 */
export function normalizeResponseHeadersSettings(value: unknown): ResponseHeadersSettings {
  if (!isRecord(value)) invalid("Response header settings must be an object");
  const unexpected = Object.keys(value).find((key) => key !== "set" && key !== "remove");
  if (unexpected) invalid(`Response header settings contain unknown field: ${unexpected}`);

  const rawSet = value.set ?? {};
  const rawRemove = value.remove ?? [];
  if (!isRecord(rawSet)) invalid("Response headers to set must be an object");
  if (!Array.isArray(rawRemove)) invalid("Response headers to remove must be a list");
  if (Object.keys(rawSet).length + rawRemove.length > MAX_HEADERS) {
    invalid(`At most ${MAX_HEADERS} response headers can be set or removed`);
  }

  // One set of names for both lists: a header both set and removed is ambiguous.
  const seen = new Set<string>();
  const set: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(rawSet)) {
    const name = headerName(rawName, seen);
    if (typeof rawValue !== "string" || hasForbiddenControlCharacter(rawValue) || rawValue.length > MAX_VALUE_LENGTH) {
      invalid(`Invalid value for response header: ${name}`);
    }
    if (REQUEST_DATA_PLACEHOLDER.test(rawValue)) {
      invalid(`Response header ${name} cannot copy request headers or cookies`);
    }
    set[name] = rawValue.trim();
  }
  const remove = rawRemove.map((rawName) => headerName(rawName, seen));
  return { set, remove };
}

/** Stored values are checked when saved; one that no longer passes is ignored rather than breaking the build. */
export function readStoredResponseHeadersSettings(value: unknown): ResponseHeadersSettings | null {
  if (value === null || value === undefined) return null;
  try {
    return normalizeResponseHeadersSettings(value);
  } catch (error) {
    console.warn("Ignoring invalid response header settings", error);
    return null;
  }
}

/**
 * A matcher-less, non-terminal route for the start of the main server's
 * routes, and again of its error routes (Caddy runs those with the original
 * response writer). Deferred, so the operations apply when the response is
 * written: after Caddy's own Server header, the reverse proxy's Via header
 * and the upstream's and the host's own headers, which the values here
 * replace.
 *
 * Request placeholders ({http.*}) in values are expanded (request headers and
 * cookies are refused when saved); host placeholders
 * ({env.*}, {system.*}, {file.*}) are escaped and sent literally.
 */
export function buildResponseHeadersRoute(
  settings: ResponseHeadersSettings | null | undefined
): CaddyResponseHeadersRoute | null {
  if (!settings) return null;
  const set = Object.entries(settings.set);
  if (set.length === 0 && settings.remove.length === 0) return null;
  return {
    handle: [
      {
        handler: "headers",
        response: {
          ...(set.length > 0
            ? { set: Object.fromEntries(set.map(([name, value]) => [name, [escapeHostPlaceholders(value)]])) }
            : {}),
          ...(settings.remove.length > 0 ? { delete: [...settings.remove] } : {}),
          deferred: true,
        },
      },
    ],
  };
}
