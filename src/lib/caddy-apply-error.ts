import { randomUUID } from "node:crypto";

export type CaddyApplyErrorCode =
  | "CADDY_REJECTED"
  | "CADDY_UNREACHABLE"
  | "CADDY_REQUEST_FAILED"
  | "INSTANCE_SYNC_FAILED";

export class CaddyApplyError extends Error {
  readonly code: CaddyApplyErrorCode;
  /** The proxy host a create stored before the apply failed (createProxyHost), so callers can say it was saved. */
  proxyHostId?: number;
  /** The L4 host a create stored before the apply failed (createL4ProxyHost). */
  l4ProxyHostId?: number;
  /**
   * The host Caddy stopped at when it rejected the configuration (its domains
   * or listen address; locateCaddyRejection), when that is known. Not part of
   * the message: only people who can see every host are told.
   */
  rejectedAt?: string;

  constructor(message: string, code: CaddyApplyErrorCode) {
    super(message);
    this.name = "CaddyApplyError";
    this.code = code;
  }
}

export function safeSystemErrorCode(error: unknown): string | null {
  if (typeof error !== "object" || error === null || !("code" in error)) return null;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && /^[A-Z0-9_-]{1,64}$/.test(code)
    ? code
    : null;
}

/**
 * Caddy's /load error body quotes the config it choked on, so it is never
 * surfaced or logged verbatim. Matching it against known failure modes gives
 * back an application-authored explanation instead: enough to fix the config,
 * with nothing echoed out of it.
 *
 * Coraza builds its WAF during config load, so these validation errors reject
 * the entire document — without a reason the operator only sees every host
 * stop updating, with no hint as to which knob did it.
 */
const KNOWN_CADDY_REJECTIONS: ReadonlyArray<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /request body limit should be at most 1GiB/i,
    reason: "a WAF request body limit exceeds Coraza's maximum of 1 GiB",
  },
  {
    pattern: /request body limit should be at least the memory limit/i,
    reason: "a WAF in-memory body limit is larger than its request body limit",
  },
  {
    pattern: /body limit should be bigger than 0/i,
    reason: "a WAF body limit is zero",
  },
  {
    pattern: /unknown module: http\.handlers\.rate_limit/i,
    reason: "the Caddy image has no rate limit plugin; update it to the image of this release",
  },
  // Shared certificate storage (ee/high-availability): the redis module
  // connects and signs in while the configuration loads.
  {
    pattern: /loading storage module: .*(module not registered|unknown module)/i,
    reason: "this Caddy build has no Redis storage module; update the Caddy image",
  },
  {
    pattern: /loading storage module: .*(WRONGPASS|NOAUTH|invalid username-password|invalid password|AUTH <password>)/i,
    reason: "the certificate storage server did not accept the user name or password",
  },
  {
    pattern: /loading storage module: .*encryption_key/i,
    reason: "the certificate storage encryption key is missing or shorter than 32 bytes on this node (check its CADDY_STORAGE_* variables)",
  },
  {
    pattern: /loading storage module: .*(x509|tls:|certificate)/i,
    reason: "the TLS connection to the certificate storage server failed",
  },
  {
    pattern: /loading storage module: .*(no such host|connection refused|i\/o timeout|deadline exceeded|no route to host|network is unreachable|EOF)/i,
    reason: "Caddy could not reach the certificate storage server",
  },
  {
    pattern: /loading storage module:/i,
    reason: "Caddy could not set up the certificate storage",
  },
];

/** Known, safe-to-report explanation for a Caddy config rejection, if any. */
export function describeCaddyRejection(responseBody: string): string | null {
  return KNOWN_CADDY_REJECTIONS.find(({ pattern }) => pattern.test(responseBody))?.reason ?? null;
}

/** Where Caddy stopped when it rejected the configuration. */
export type CaddyRejectionPlace = {
  /** The kind of setting, in words that name nothing of the installation. */
  summary: string;
  /** The host it belongs to ("proxy host a.example.com", "L4 host on :5432"); null when Caddy's answer does not lead to one. */
  host: string | null;
};

/** HTTP handlers by module name, as the setting they come from. */
const HANDLER_SETTINGS: Readonly<Record<string, string>> = {
  waf: "the WAF rules (the global ones or the proxy host's own)",
  reverse_proxy: "the upstream settings of a proxy host",
  blocker: "the geoblocking rules",
  rate_limit: "the rate limit rules",
  authentication: "the basic-auth users of an access list",
  forward_auth: "the forward-auth settings of a proxy host",
  headers: "the header settings of a proxy host",
  rewrite: "the rewrite settings of a proxy host",
  static_response: "a redirect or fixed response of a proxy host",
  encode: "the compression settings",
};

const HOST_NAME = /^[A-Za-z0-9*_.-]{1,253}$/;
const LISTEN_ADDRESS = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]*):\d{1,5}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function at(value: unknown, ...path: (string | number)[]): unknown {
  let current = value;
  for (const key of path) {
    if (Array.isArray(current) && typeof key === "number") current = current[key];
    else if (isRecord(current) && typeof key === "string" && Object.hasOwn(current, key)) current = current[key];
    else return undefined;
  }
  return current;
}

/** The proxy host with these names in the configuration document, for a message: a few of them, and only what looks like a name. */
function hostNames(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const names = [...new Set(value.filter((name): name is string => typeof name === "string" && HOST_NAME.test(name)))];
  if (names.length === 0) return null;
  const shown = names.slice(0, 3).join(", ");
  return `proxy host ${names.length > 3 ? `${shown} and ${names.length - 3} more` : shown}`;
}

function routeHosts(route: unknown): string | null {
  const matchers = at(route, "match");
  if (!Array.isArray(matchers)) return null;
  return hostNames(matchers.flatMap((matcher) => (Array.isArray(at(matcher, "host")) ? (at(matcher, "host") as unknown[]) : [])));
}

/**
 * Where Caddy stopped, read off the chain of steps its error starts with
 * ("loading http app module: provision http: server …: route 2: … loading
 * module 'waf': …"). Only that chain is used: the steps are Caddy's own
 * words, while the end of the error quotes values out of the configuration.
 * Nothing of the error is returned, only phrases written here; the host is
 * looked up in `document`, the configuration that was sent.
 */
export function locateCaddyRejection(responseBody: string, document: unknown): CaddyRejectionPlace | null {
  let text = responseBody;
  try {
    const parsed: unknown = JSON.parse(responseBody);
    if (isRecord(parsed) && typeof parsed.error === "string") text = parsed.error;
  } catch {
    // Not JSON: Caddy's words as they came.
  }
  // The chain is at the start; what follows can be as long as a quoted configuration.
  text = text.slice(0, 2000);

  // Caddy's own steps come first and what it quotes out of the configuration last, so of the
  // steps below the one that appears first in the text is the real one.
  const steps: { pattern: RegExp; place: (match: RegExpExecArray, rest: string) => CaddyRejectionPlace }[] = [
    {
      // An imported certificate and key (tls.X509KeyPair).
      pattern: /provision tls: loading certificates: /,
      place: () => ({ summary: "an imported certificate or its private key, which Caddy cannot load", host: null }),
    },
    {
      // The trust anchors of a host with client certificates (mTLS).
      pattern: /server ([A-Za-z0-9_-]{1,64}): setting up TLS connection policies: connection policy (\d{1,6}):/,
      place: (match, rest) => ({
        summary: /^ building standard TLS config: provisioning client CA: /.test(rest)
          ? "a CA or client certificate that a proxy host trusts for mTLS"
          : "the TLS settings of a proxy host",
        host: hostNames(at(document, "apps", "http", "servers", match[1], "tls_connection_policies", Number(match[2]), "match", "sni")),
      }),
    },
    {
      // Certificate issuance: the ACME account, the certificate authority, the DNS provider.
      pattern: /provision tls: provisioning automation policy \d{1,6}: /,
      place: (_match, rest) => ({
        summary: /^(?:[a-zA-Z ]+: )*(?:position \d+: )?loading module 'acme': provision tls\.issuance\.acme: expanding email address /.test(rest)
          ? "the ACME contact e-mail address (certificate settings)"
          : "the certificate issuance settings (ACME account, certificate authority or DNS provider)",
        host: null,
      }),
    },
    {
      // An HTTP route: the handler Caddy was loading says which setting, the route's host matcher which host.
      pattern: /server ([A-Za-z0-9_-]{1,64}): setting up route handlers: route (\d{1,6}): /,
      place: (match, rest) => {
        const host = routeHosts(at(document, "apps", "http", "servers", match[1], "routes", Number(match[2])));
        // The first handler that is not a subroute: subroutes only lead to it.
        const handler = [...rest.matchAll(/loading module '([a-z0-9_]{1,40})': (provision|decoding module config:|unknown module:) /g)].find(
          (found) => found[1] !== "subroute"
        );
        if (!handler) return { summary: "the settings of a proxy host", host };
        if (handler[2] === "unknown module:") {
          return { summary: "a handler or module this Caddy image does not have (custom Caddy JSON of a proxy host)", host };
        }
        if (handler[1] === "reverse_proxy") {
          const after = rest.slice((handler.index ?? 0) + handler[0].length);
          if (handler[2] === "decoding module config:") {
            return { summary: "the upstream settings or the custom reverse-proxy JSON of a proxy host", host };
          }
          if (/^http\.handlers\.reverse_proxy: loading transport: loading module '[a-z0-9_]{1,40}': unknown module: /.test(after)) {
            return { summary: "a handler or module this Caddy image does not have (custom Caddy JSON of a proxy host)", host };
          }
        }
        return {
          summary: Object.hasOwn(HANDLER_SETTINGS, handler[1]) ? HANDLER_SETTINGS[handler[1]] : "the settings of a proxy host",
          host,
        };
      },
    },
    {
      // An L4 listener Caddy could not open.
      pattern: /layer4 app module: start: listen (?:tcp|udp)[46]? (\S{1,80}): bind: /,
      place: (match) => ({
        summary: "the listen address of an L4 host, which is in use or not an address of the Caddy container",
        host: LISTEN_ADDRESS.test(match[1]) ? `L4 host on ${match[1]}` : null,
      }),
    },
  ];
  let first: { index: number; place: () => CaddyRejectionPlace } | null = null;
  for (const step of steps) {
    const match = step.pattern.exec(text);
    if (match && (first === null || match.index < first.index)) {
      first = { index: match.index, place: () => step.place(match, text.slice(match.index + match[0].length)) };
    }
  }
  if (first) return first.place();
  if (/layer4 app module/.test(text)) return { summary: "the settings of an L4 host", host: null };
  if (/loading tls app module/.test(text)) return { summary: "the certificate (TLS) settings", host: null };
  if (/loading http app module/.test(text)) return { summary: "the proxy host or HTTP settings", host: null };
  return null;
}

/**
 * What a rejection says beyond "Caddy rejected configuration" (a known reason
 * or where the problem is), to end another sentence with; "" when Caddy's
 * answer led to neither. `withHost` adds the host Caddy stopped at: only for
 * people who can see every host.
 */
export function caddyRejectionDetail(error: unknown, options: { withHost: boolean }): string {
  if (!(error instanceof CaddyApplyError) || error.code !== "CADDY_REJECTED") return "";
  const detail = error.message.replace(/^Caddy rejected configuration:?\s*/, "").trim();
  if (!detail) return "";
  return options.withHost && error.rejectedAt ? `${detail} (${error.rejectedAt})` : detail;
}

/** Log diagnostic metadata without exception messages, response bodies, URLs, or stacks. */
export function logCaddyApplyFailure(
  context: string,
  error?: unknown,
  metadata: Record<string, number | boolean | null> = {}
): string {
  const errorId = randomUUID();
  const code = safeSystemErrorCode(error);
  const rawType = error instanceof Error ? error.name : typeof error;
  const errorType = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(rawType)
    ? rawType
    : error instanceof Error ? "Error" : "unknown";
  console.error("Caddy apply failure", {
    errorId,
    context,
    errorType,
    ...(code ? { code } : {}),
    ...metadata,
  });
  return errorId;
}
