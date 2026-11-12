import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission, apiErrorResponse } from "@/src/lib/api-auth";
import { updateL4ProxyHost, deleteL4ProxyHost } from "@/src/lib/models/l4-proxy-hosts";
import {
  assertL4WriteAllowed,
  assertListenPortFreeOutsideScope,
  findL4ProxyHostInScope,
  getL4ProxyHostInScope,
  tagsForWrite,
} from "@/src/lib/access-scope";
import { gateHostChange } from "@/ee/approvals/requests";
import { routeRowId } from "@/src/lib/row-ids";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { access } = await requireApiPermission(request, "l4_proxy_hosts:read");
    const { id } = await params;
    // 404 for a host outside the caller's tag scope, as for a missing one.
    const host = await findL4ProxyHostInScope(access, routeRowId(id, "Not found"));
    if (!host) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
    return NextResponse.json(host);
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { userId, access } = await requireApiPermission(request, "l4_proxy_hosts:write");
    const { id } = await params;
    const existing = await getL4ProxyHostInScope(access, routeRowId(id));
    const body = await request.json();
    const tags = tagsForWrite(access, "l4_proxy_hosts", body?.tags, existing.tags);
    assertL4WriteAllowed(access, body ?? {}, existing);
    await assertListenPortFreeOutsideScope(
      access,
      body?.protocol ?? existing.protocol,
      body?.listenAddress ?? (body?.protocol !== undefined ? existing.listenAddress : undefined),
      existing.id
    );
    const input = { ...body, ...(tags !== undefined ? { tags } : {}) };
    // A host a change approval policy protects: the change becomes a change request (202).
    const gate = await gateHostChange({ access, change: { targetType: "l4_proxy_host", kind: "update", target: existing, input: { host: input } } });
    if (gate) return NextResponse.json(gate.request, { status: 202 });
    const host = await updateL4ProxyHost(existing.id, input, userId);
    return NextResponse.json(host);
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { userId, access } = await requireApiPermission(request, "l4_proxy_hosts:write");
    const { id } = await params;
    const existing = await getL4ProxyHostInScope(access, routeRowId(id));
    const gate = await gateHostChange({ access, change: { targetType: "l4_proxy_host", kind: "delete", target: existing, input: {} } });
    if (gate) return NextResponse.json(gate.request, { status: 202 });
    await deleteL4ProxyHost(existing.id, userId);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return apiErrorResponse(error);
  }
}
