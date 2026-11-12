import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission, apiErrorResponse, logUnexpectedApiError } from "@/src/lib/api-auth";
import { CaddyApplyError } from "@/src/lib/caddy-apply-error";
import { applyCaddyConfig } from "@/src/lib/caddy";

export async function POST(request: NextRequest) {
  try {
    await requireApiPermission(request, "settings:write");
    await applyCaddyConfig();
    return NextResponse.json({ ok: true });
  } catch (error) {
    // Nothing is stored here, so not the "saved, but not live" answer of apiErrorResponse.
    if (error instanceof CaddyApplyError) {
      logUnexpectedApiError("Caddy apply failed", error);
      const detail = error.rejectedAt ? `${error.message} (${error.rejectedAt})` : error.message;
      return NextResponse.json({ error: detail, code: error.code }, { status: 502 });
    }
    return apiErrorResponse(error);
  }
}
