import { NextRequest } from "next/server";
import { getMcpSettings } from "@/src/lib/mcp/config";
import {
  clientGrantTypes,
  exchangeAuthorizationCode,
  issueTokensForGrant,
  OAuthError,
  pruneMcpOAuthArtifacts,
  rotateRefreshToken,
  type IssuedTokens,
} from "@/src/lib/mcp/oauth";
import { authenticateOAuthClient, oauthErrorResponse, oauthJson, readOAuthParams } from "@/src/lib/mcp/oauth-http";
import { scopeString } from "@/src/lib/mcp/scopes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Housekeeping at most once an hour per process. */
let lastPrune = 0;
function prune(): void {
  const now = Date.now();
  if (now - lastPrune < 60 * 60 * 1000) return;
  lastPrune = now;
  void pruneMcpOAuthArtifacts();
}

function tokenResponse(tokens: IssuedTokens) {
  return oauthJson({
    access_token: tokens.accessToken,
    token_type: "Bearer",
    expires_in: tokens.expiresIn,
    refresh_token: tokens.refreshToken,
    refresh_token_expires_in: tokens.refreshExpiresIn,
    scope: scopeString(tokens.scopes),
  });
}

/**
 * The token endpoint (RFC 6749 §4.1.3 and §6, OAuth 2.1). Accepts
 * application/x-www-form-urlencoded and application/json; clients
 * authenticate with none, client_secret_basic or client_secret_post.
 */
export async function POST(request: NextRequest) {
  try {
    const settings = await getMcpSettings();
    if (!settings.enabled) throw new OAuthError("invalid_request", "The MCP server is disabled", 404);

    const params = await readOAuthParams(request);
    const { client } = await authenticateOAuthClient(request, params);
    const grantType = params.grant_type;
    if (!grantType) throw new OAuthError("invalid_request", "grant_type is required");

    const allowed = clientGrantTypes(client);
    if (!allowed.includes(grantType)) {
      throw new OAuthError("unauthorized_client", `The client may not use the ${grantType} grant`);
    }

    prune();

    if (grantType === "authorization_code") {
      const code = params.code;
      const redirectUri = params.redirect_uri;
      const codeVerifier = params.code_verifier;
      if (!code) throw new OAuthError("invalid_request", "code is required");
      if (!redirectUri) throw new OAuthError("invalid_request", "redirect_uri is required");
      if (!codeVerifier) throw new OAuthError("invalid_request", "code_verifier is required for PKCE");

      const grant = await exchangeAuthorizationCode({
        code,
        client,
        redirectUri,
        codeVerifier,
        resource: params.resource,
      });
      const tokens = await issueTokensForGrant({
        clientId: client.clientId,
        userId: grant.userId,
        scopes: grant.scopes,
        resource: grant.resource,
      });
      return tokenResponse(tokens);
    }

    if (grantType === "refresh_token") {
      const refreshToken = params.refresh_token;
      if (!refreshToken) throw new OAuthError("invalid_request", "refresh_token is required");
      const tokens = await rotateRefreshToken({
        refreshToken,
        client,
        scope: params.scope,
        resource: params.resource,
      });
      return tokenResponse(tokens);
    }

    throw new OAuthError("unsupported_grant_type", `Unsupported grant_type: ${grantType.slice(0, 40)}`);
  } catch (error) {
    return oauthErrorResponse(error);
  }
}

/** Only POST is defined for the token endpoint (RFC 6749 §3.2). */
export async function GET() {
  return oauthErrorResponse(new OAuthError("invalid_request", "Use POST for the token endpoint", 405, { Allow: "POST" }));
}
