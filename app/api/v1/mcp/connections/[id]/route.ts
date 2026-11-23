import { NextRequest, NextResponse } from "next/server";
import { apiErrorResponse, NotFoundError, requireApiPermission } from "@/src/lib/api-auth";
import { revokeConnection } from "@/src/lib/mcp/oauth";
import { routeRowId } from "@/src/lib/row-ids";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Disconnects one MCP grant (its access and refresh tokens). */
export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    await requireApiPermission(request, "settings:write");
    const { id } = await params;
    const revoked = await revokeConnection(routeRowId(id, "MCP connection not found"));
    if (!revoked) throw new NotFoundError("MCP connection not found");
    return NextResponse.json({ ok: true });
  } catch (error) {
    return apiErrorResponse(error);
  }
}
