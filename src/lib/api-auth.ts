import { type NextRequest, NextResponse } from "next/server";
import { auth, checkSameOrigin } from "./auth";
import { validateToken } from "./models/api-tokens";
import { randomUUID } from "node:crypto";
import { ApiClientError } from "./api-errors";
import { CaddyApplyError } from "./caddy-apply-error";
import { mfaEnrolmentRequired } from "./mfa";
import { can, permissionDeniedMessage, type Access, type Permission } from "./permissions";
import { applyTokenScopes } from "./api-token-scopes";
import { accessForUser } from "@/ee/custom-roles/access";

export class ApiAuthError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiAuthError";
    this.status = status;
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export type ApiAuthResult = {
  userId: number;
  role: string;
  /** The user's custom role (ee/custom-roles), or null for a built-in role. API tokens act with it. */
  customRoleId?: number | null;
  authMethod: "bearer" | "session";
  /**
   * The scopes of the API token the request carried (src/lib/api-token-scopes.ts);
   * null or absent for a session or a token without scopes.
   */
  tokenScopes?: readonly Permission[] | null;
};

/** Options of requireApiUser. */
export type RequireApiUserOptions = {
  /**
   * Let a token with scopes through. Only for endpoints that check a
   * permission with getApiAccess afterwards, or that return nothing about any
   * account. Every other endpoint (the owner's sessions, tokens, passkeys,
   * preferences, access review assignments) refuses such a token: its scopes
   * do not cover them.
   */
  allowScopedToken?: boolean;
};

export const SCOPED_TOKEN_REFUSED_MESSAGE =
  "This API token is limited to its scopes and cannot use this endpoint. Use a session or a token without scopes.";

/** A request that passed requireApiPermission, with what the caller may do. */
export type ApiPermissionResult = ApiAuthResult & { access: Access };

export async function authenticateApiRequest(
  request: NextRequest
): Promise<ApiAuthResult> {
  // Try Bearer token first
  const authHeader = request.headers.get("authorization") ?? "";
  if (authHeader.startsWith("Bearer ")) {
    const rawToken = authHeader.slice(7);
    if (!rawToken) {
      throw new ApiAuthError("Invalid Bearer token", 401);
    }

    const result = await validateToken(rawToken);
    if (!result) {
      throw new ApiAuthError("Invalid or expired API token", 401);
    }

    return {
      userId: result.user.id,
      role: result.user.role,
      customRoleId: result.user.customRoleId ?? null,
      authMethod: "bearer",
      tokenScopes: result.token.scopes ?? null,
    };
  }

  // Fall back to session auth
  const session = await auth();
  if (!session?.user?.id) {
    throw new ApiAuthError("Unauthorized", 401);
  }

  // Deny access when role is missing rather than defaulting to "user"
  const role = session.user.role;
  if (!role) {
    throw new ApiAuthError("Session missing role claim", 401);
  }

  // The MFA policy's grace period is over and the account has not set up
  // MFA: its dashboard session can only do that (src/lib/mfa.ts). API tokens
  // are separate credentials and are not affected.
  if (await mfaEnrolmentRequired(Number(session.user.id))) {
    throw new ApiAuthError("Set up multi-factor authentication to continue", 403);
  }

  return {
    userId: Number(session.user.id),
    role,
    customRoleId: session.user.customRoleId ?? null,
    authMethod: "session",
  };
}

export async function requireApiUser(request: NextRequest, options: RequireApiUserOptions = {}): Promise<ApiAuthResult> {
  const result = await authenticateApiRequest(request);

  if (result.tokenScopes && !options.allowScopedToken) {
    throw new ApiAuthError(SCOPED_TOKEN_REFUSED_MESSAGE, 403);
  }

  // CSRF check for session-authenticated mutating requests
  if (result.authMethod === "session") {
    const method = request.method.toUpperCase();
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      const csrfResponse = checkSameOrigin(request);
      if (csrfResponse) {
        throw new ApiAuthError("Forbidden", 403);
      }
    }
  }

  return result;
}

/**
 * What an authenticated caller may do. API tokens act with their owner's
 * role, limited to the token's scopes when it has some
 * (src/lib/api-token-scopes.ts). Every permission
 * check on a REST request goes through here, so a scoped token can never do
 * more than its owner or its scopes.
 */
export async function getApiAccess(result: ApiAuthResult): Promise<Access> {
  const access = await accessForUser({
    id: result.userId,
    role: result.role,
    customRoleId: result.customRoleId ?? null,
  });
  return applyTokenScopes(access, result.tokenScopes ?? null);
}

/**
 * Require one permission from the catalogue (src/lib/permissions.ts); 403
 * otherwise. Administrators hold every permission, built-in user and viewer
 * roles none. A role's tag scope is applied by the route with the helpers in
 * src/lib/access-scope.ts.
 */
export async function requireApiPermission(request: NextRequest, permission: Permission): Promise<ApiPermissionResult> {
  const result = await requireApiUser(request, { allowScopedToken: true });
  const access = await getApiAccess(result);
  if (!can(access, permission)) {
    throw new ApiAuthError(permissionDeniedMessage(access, permission), 403);
  }
  return { ...result, access };
}

/**
 * Require the built-in admin role. Kept for the paths that stay
 * administrator-only whatever a custom role holds (ee/docs/custom-roles.md).
 * A token with scopes is never an administrator.
 */
export async function requireApiAdmin(request: NextRequest): Promise<ApiAuthResult> {
  const result = await requireApiUser(request);
  if (!(await getApiAccess(result)).isAdmin) {
    throw new ApiAuthError("Administrator privileges required", 403);
  }
  return result;
}

/**
 * Helper to build an error response from an ApiAuthError or generic error.
 */
export function apiErrorResponse(error: unknown): NextResponse {
  if (error instanceof ApiAuthError) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  if (error instanceof ApiClientError) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  if (error instanceof NotFoundError) {
    return NextResponse.json({ error: error.message }, { status: 404 });
  }
  // The change is stored, but Caddy does not serve it (it refused the
  // configuration, could not be reached, or the replicas were not synced).
  // The models take a change Caddy rejects back themselves and answer 400 or
  // 409 (rejected-apply.ts); what arrives here is what was kept. The message
  // is written by the application (caddy-apply-error.ts).
  if (error instanceof CaddyApplyError) {
    logUnexpectedApiError("Change stored but not applied", error);
    const id = error.proxyHostId ?? error.l4ProxyHostId;
    return NextResponse.json(
      {
        error:
          error.code === "INSTANCE_SYNC_FAILED"
            ? `Saved and applied on this instance, but not on every instance: ${error.message}.`
            : `Saved, but not live yet: ${error.message}. Caddy keeps serving its previous configuration until an apply succeeds.`,
        code: error.code,
        saved: true,
        ...(id !== undefined ? { id } : {}),
      },
      { status: 502 }
    );
  }
  // Several model functions predate NotFoundError and use a fixed
  // "<resource> not found" message. Preserve their 404 contract without
  // reflecting the unexpected message (or any resource/internal detail).
  if (error instanceof Error && error.message.trim().toLowerCase().endsWith("not found")) {
    return NextResponse.json({ error: "Resource not found" }, { status: 404 });
  }
  const errorId = logUnexpectedApiError("Unhandled API error", error);
  return NextResponse.json(
    { error: "Internal server error", errorId },
    { status: 500 }
  );
}

/**
 * Log enough metadata to correlate unexpected failures without copying raw
 * exception messages, response bodies, URLs, or stacks into centralized logs.
 */
export function logUnexpectedApiError(context: string, error: unknown): string {
  const errorId = randomUUID();
  const rawType = error instanceof Error ? error.name : typeof error;
  const errorType = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(rawType)
    ? rawType
    : error instanceof Error ? "Error" : "unknown";
  const safeDetails: Record<string, unknown> = {
    errorId,
    context,
    errorType,
  };
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && /^[A-Z0-9_-]{1,64}$/.test(code)) {
      safeDetails.code = code;
    } else if (typeof code === "number" && Number.isFinite(code)) {
      safeDetails.code = code;
    }
  }
  console.error("Unexpected API failure", safeDetails);
  return errorId;
}
