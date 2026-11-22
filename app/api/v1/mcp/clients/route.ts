import { NextRequest, NextResponse } from "next/server";
import { apiErrorResponse, requireApiPermission } from "@/src/lib/api-auth";
import { listClients } from "@/src/lib/mcp/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** MCP OAuth clients registered on this instance (administrators see every user's). */
export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "settings:read");
    return NextResponse.json({ clients: await listClients() });
  } catch (error) {
    return apiErrorResponse(error);
  }
}
