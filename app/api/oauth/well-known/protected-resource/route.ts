import { NextResponse } from "next/server";
import { getMcpSettings, protectedResourceMetadata } from "@/src/lib/mcp/config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * RFC 9728 OAuth 2.0 Protected Resource Metadata for the MCP endpoint.
 * Served at /.well-known/oauth-protected-resource and at the endpoint's own
 * path-specific well-known URI through the rewrites in next.config.mjs.
 * Public: a client reads it before it has a token.
 */
export async function GET() {
  const settings = await getMcpSettings();
  if (!settings.enabled) return new NextResponse("Not found", { status: 404 });
  return NextResponse.json(protectedResourceMetadata(), {
    headers: {
      "Cache-Control": "public, max-age=300",
      "Access-Control-Allow-Origin": "*",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      Allow: "GET, OPTIONS",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Max-Age": "600",
    },
  });
}
