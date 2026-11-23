import { NextRequest, NextResponse } from "next/server";
import { auth, checkSameOrigin } from "@/src/lib/auth";
import { getUserById } from "@/src/lib/models/user";
import { accessForUser } from "@/ee/custom-roles/access";
import { logAuditEvent } from "@/src/lib/audit";
import {
  authorizationErrorRedirect,
  buildRedirect,
  parseAuthorizationRequest,
} from "@/src/lib/mcp/authorize";
import { getMcpSettings } from "@/src/lib/mcp/config";
import { createAuthorizationCode, saveConsent } from "@/src/lib/mcp/oauth";
import { scopeString } from "@/src/lib/mcp/scopes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The consent decision. The form only carries the authorization request
 * again; every value is re-validated here (client, redirect URI, PKCE,
 * scopes, resource), so a tampered hidden field cannot widen the grant.
 */
export async function POST(request: NextRequest) {
  const settings = await getMcpSettings();
  if (!settings.enabled) return new NextResponse("Not found", { status: 404 });

  // A form POST from the consent page: the session cookie decides who
  // approves, and the Origin check stops another site from posting one.
  const csrf = checkSameOrigin(request);
  if (csrf) return csrf;

  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const user = await getUserById(Number(session.user.id));
  if (!user || user.status !== "active") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const access = await accessForUser({
    id: user.id,
    role: user.role,
    customRoleId: user.customRoleId ?? null,
  });

  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > 32_000) {
    return NextResponse.json({ error: "Request body too large" }, { status: 413 });
  }
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return NextResponse.json({ error: "Invalid form body" }, { status: 400 });
  }
  const field = (name: string): string | null => {
    const value = form.get(name);
    return typeof value === "string" && value !== "" ? value : null;
  };

  const params = new URLSearchParams();
  for (const name of [
    "client_id",
    "redirect_uri",
    "response_type",
    "response_mode",
    "state",
    "scope",
    "resource",
    "code_challenge",
    "code_challenge_method",
    "prompt",
  ]) {
    const value = field(name);
    if (value !== null) params.set(name, value);
  }

  const parsed = await parseAuthorizationRequest(params, access);
  if (!parsed.ok) {
    if (parsed.fatal) {
      // Nothing trustworthy to redirect to.
      return NextResponse.json({ error: parsed.error, error_description: parsed.description }, { status: 400 });
    }
    return NextResponse.redirect(authorizationErrorRedirect(parsed), 303);
  }

  const authorization = parsed.request;
  const decision = field("decision");
  if (decision !== "allow") {
    await logAuditEvent({
      userId: user.id,
      action: "mcp_authorization_denied",
      entityType: "mcp_client",
      summary: `MCP authorization denied for ${authorization.clientName}`,
      data: { clientId: authorization.clientId, scopes: authorization.scopes },
    });
    return NextResponse.redirect(
      buildRedirect(authorization.redirectUri, {
        state: authorization.state,
        error: "access_denied",
        errorDescription: "The user denied the request",
      }),
      303
    );
  }

  await saveConsent(user.id, authorization.clientId, authorization.scopes, authorization.resource);
  const code = await createAuthorizationCode({
    clientId: authorization.clientId,
    userId: user.id,
    redirectUri: authorization.redirectUri,
    codeChallenge: authorization.codeChallenge,
    scopes: authorization.scopes,
    resource: authorization.resource,
  });
  await logAuditEvent({
    userId: user.id,
    action: "mcp_authorization_granted",
    entityType: "mcp_client",
    summary: `MCP client authorized: ${authorization.clientName} (${scopeString(authorization.scopes)})`,
    data: { clientId: authorization.clientId, scopes: authorization.scopes, resource: authorization.resource },
  });

  return NextResponse.redirect(
    buildRedirect(authorization.redirectUri, { state: authorization.state, code }),
    303
  );
}
