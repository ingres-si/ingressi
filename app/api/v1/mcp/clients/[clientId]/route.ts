import { NextRequest, NextResponse } from "next/server";
import { apiErrorResponse, requireApiPermission, NotFoundError } from "@/src/lib/api-auth";
import { revokeClient } from "@/src/lib/mcp/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CLIENT_ID = /^mcp_[A-Za-z0-9_-]{10,80}$/;

/** Revokes an MCP client and every token issued through it. */
export async function DELETE(request: NextRequest, { params }: { params: Promise<{ clientId: string }> }) {
  try {
    await requireApiPermission(request, "settings:write");
    const { clientId } = await params;
    if (!CLIENT_ID.test(clientId)) throw new NotFoundError("MCP client not found");
    const revoked = await revokeClient(clientId);
    if (!revoked) throw new NotFoundError("MCP client not found");
    return NextResponse.json({ ok: true });
  } catch (error) {
    return apiErrorResponse(error);
  }
}
