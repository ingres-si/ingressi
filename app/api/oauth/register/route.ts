import { NextRequest, NextResponse } from "next/server";
import { getClientIp } from "@/src/lib/client-ip";
import { getMcpSettings } from "@/src/lib/mcp/config";
import { OAuthError, registerClient } from "@/src/lib/mcp/oauth";
import { oauthErrorResponse } from "@/src/lib/mcp/oauth-http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * RFC 7591 dynamic client registration. Open when MCP is enabled and dynamic
 * registration is not switched off; rate-limited per address because it is
 * the one unauthenticated write on the instance.
 */
const WINDOW_MS = 60 * 60 * 1000;
const MAX_PER_WINDOW = 20;
const registrations = new Map<string, { count: number; resetAt: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  // Drop expired windows so the map stays bounded on a long-running process.
  if (registrations.size > 10_000) {
    for (const [key, value] of registrations) if (value.resetAt <= now) registrations.delete(key);
  }
  const entry = registrations.get(ip);
  if (!entry || entry.resetAt <= now) {
    registrations.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_PER_WINDOW;
}

export async function POST(request: NextRequest) {
  try {
    const settings = await getMcpSettings();
    if (!settings.enabled) {
      throw new OAuthError("registration_not_supported", "The MCP server is disabled", 403);
    }
    if (!settings.allowDynamicRegistration) {
      throw new OAuthError(
        "registration_not_supported",
        "This instance does not allow MCP clients to register themselves; ask an administrator",
        403
      );
    }

    const ip = getClientIp(request.headers);
    if (rateLimited(ip)) {
      return oauthErrorResponse(
        new OAuthError("temporarily_unavailable", "Too many client registrations from this address", 429, {
          "Retry-After": "3600",
        })
      );
    }

    const length = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(length) && length > 16_000) {
      throw new OAuthError("invalid_client_metadata", "The client metadata is too large", 413);
    }
    const contentType = (request.headers.get("content-type") ?? "").toLowerCase();
    if (!contentType.startsWith("application/json")) {
      throw new OAuthError("invalid_client_metadata", "Use application/json");
    }
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      throw new OAuthError("invalid_client_metadata", "The JSON body is not valid");
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new OAuthError("invalid_client_metadata", "The JSON body must be an object");
    }

    const client = await registerClient(body as Record<string, unknown>);
    const issuedAt = Math.floor(Date.parse(client.createdAt) / 1000) || Math.floor(Date.now() / 1000);
    return NextResponse.json(
      {
        client_id: client.clientId,
        ...(client.clientSecret ? { client_secret: client.clientSecret } : {}),
        client_id_issued_at: issuedAt,
        ...(client.clientSecret ? { client_secret_expires_at: 0 } : {}),
        client_name: client.name,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        response_types: ["code"],
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      },
      {
        status: 201,
        headers: {
          "Cache-Control": "no-store",
          Pragma: "no-cache",
          "X-Content-Type-Options": "nosniff",
        },
      }
    );
  } catch (error) {
    return oauthErrorResponse(error);
  }
}
