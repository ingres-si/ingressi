import { NextResponse } from "next/server";
import { authorizationServerMetadata, getMcpSettings } from "@/src/lib/mcp/config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * RFC 8414 Authorization Server Metadata, served at
 * /.well-known/oauth-authorization-server through the rewrite in
 * next.config.mjs. The issuer is BASE_URL, so this document names exactly the
 * URLs the endpoints answer on.
 */
export async function GET() {
  const settings = await getMcpSettings();
  if (!settings.enabled) return new NextResponse("Not found", { status: 404 });
  return NextResponse.json(authorizationServerMetadata(), {
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
