import { NextRequest, NextResponse } from "next/server";
import { apiErrorResponse, requireApiPermission } from "@/src/lib/api-auth";
import { listConnections } from "@/src/lib/mcp/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Live MCP grants: which client, which account, which scopes, when last used. */
export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "settings:read");
    return NextResponse.json({ connections: await listConnections() });
  } catch (error) {
    return apiErrorResponse(error);
  }
}
