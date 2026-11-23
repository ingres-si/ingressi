import { NextRequest, NextResponse } from "next/server";
import { getMcpSettings } from "@/src/lib/mcp/config";
import { OAuthError, revokeToken } from "@/src/lib/mcp/oauth";
import { authenticateOAuthClient, oauthErrorResponse, readOAuthParams } from "@/src/lib/mcp/oauth-http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * RFC 7009 token revocation. The whole grant (access token and its refresh
 * family) is revoked. Unknown tokens answer 200, so the endpoint never says
 * whether a token exists.
 */
export async function POST(request: NextRequest) {
  try {
    const settings = await getMcpSettings();
    if (!settings.enabled) throw new OAuthError("invalid_request", "The MCP server is disabled", 404);

    const params = await readOAuthParams(request);
    const token = params.token;
    if (!token) throw new OAuthError("invalid_request", "token is required");

    const { client } = await authenticateOAuthClient(request, params);
    await revokeToken(token, client.clientId, null);

    return new NextResponse(null, {
      status: 200,
      headers: { "Cache-Control": "no-store", Pragma: "no-cache", "X-Content-Type-Options": "nosniff" },
    });
  } catch (error) {
    return oauthErrorResponse(error);
  }
}

export async function GET() {
  return oauthErrorResponse(new OAuthError("invalid_request", "Use POST for the revocation endpoint", 405, { Allow: "POST" }));
}
