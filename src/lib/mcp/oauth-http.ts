/**
 * HTTP plumbing shared by the OAuth endpoints: reading parameters from a
 * form or a JSON body, client authentication (none, client_secret_basic,
 * client_secret_post), and the RFC 6749 error response.
 */
import { NextResponse } from "next/server";
import { OAuthError, authenticateClientSecret, requireActiveClient, type StoredClient } from "./oauth";
import { logUnexpectedApiError } from "../api-auth";

const MAX_PARAM_LENGTH = 4_000;

export async function readOAuthParams(request: Request): Promise<Record<string, string>> {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > 32_000) {
    throw new OAuthError("invalid_request", "Request body too large", 413);
  }
  const contentType = (request.headers.get("content-type") ?? "").toLowerCase();
  const read = (entries: Iterable<[string, unknown]>) => {
    const values: Record<string, string> = {};
    for (const [key, value] of entries) {
      if (typeof value !== "string") continue;
      if (key.length > 100 || value.length > MAX_PARAM_LENGTH) {
        throw new OAuthError("invalid_request", `The parameter ${key.slice(0, 40)} is too long`);
      }
      values[key] = value;
    }
    return values;
  };

  if (contentType.startsWith("application/x-www-form-urlencoded")) {
    let form: FormData;
    try {
      form = await request.formData();
    } catch {
      throw new OAuthError("invalid_request", "Could not read the form body");
    }
    return read(form.entries());
  }
  if (contentType.startsWith("application/json")) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      throw new OAuthError("invalid_request", "Could not read the JSON body");
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new OAuthError("invalid_request", "The JSON body must be an object");
    }
    return read(Object.entries(body));
  }
  throw new OAuthError(
    "invalid_request",
    "Use application/x-www-form-urlencoded (or application/json)"
  );
}

/** RFC 6749 §2.3.1: Basic credentials are form-urlencoded before base64. */
function decodeBasic(value: string): { clientId: string; secret: string } | null {
  let decoded: string;
  try {
    decoded = Buffer.from(value, "base64").toString("utf8");
  } catch {
    return null;
  }
  const separator = decoded.indexOf(":");
  if (separator < 0) return null;
  try {
    return {
      clientId: decodeURIComponent(decoded.slice(0, separator)),
      secret: decodeURIComponent(decoded.slice(separator + 1)),
    };
  } catch {
    return null;
  }
}

export type AuthenticatedClient = { client: StoredClient; method: "none" | "basic" | "post" };

/**
 * The client the request speaks for. `requireSecret` is false on the
 * revocation endpoint for a public client, which only sends its client_id.
 */
export async function authenticateOAuthClient(
  request: Request,
  params: Record<string, string>
): Promise<AuthenticatedClient> {
  const header = request.headers.get("authorization");
  if (header?.startsWith("Basic ")) {
    const basic = decodeBasic(header.slice(6).trim());
    if (!basic) throw new OAuthError("invalid_client", "Malformed Basic credentials", 401);
    const client = await requireActiveClient(basic.clientId);
    authenticateClientSecret(client, basic.secret);
    return { client, method: client.tokenEndpointAuthMethod === "none" ? "none" : "basic" };
  }

  const clientId = params.client_id;
  if (!clientId) throw new OAuthError("invalid_client", "client_id is required", 401);
  const client = await requireActiveClient(clientId);
  const secret = typeof params.client_secret === "string" && params.client_secret !== "" ? params.client_secret : null;
  authenticateClientSecret(client, secret);
  return { client, method: secret === null ? "none" : "post" };
}

export function oauthJson(body: Record<string, unknown>, status = 200, headers: Record<string, string> = {}): NextResponse {
  return NextResponse.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

/** An RFC 6749 §5.2 error response; unexpected failures stay opaque. */
export function oauthErrorResponse(error: unknown): NextResponse {
  if (error instanceof OAuthError) {
    return oauthJson(
      { error: error.error, error_description: error.message },
      error.status,
      error.headers
    );
  }
  const errorId = logUnexpectedApiError("Unhandled OAuth endpoint error", error);
  return oauthJson({ error: "server_error", error_description: "Internal server error", errorId }, 500);
}
