/**
 * The scopes of the MCP authorization server.
 *
 * A client asks for `mcp.read`, `mcp.write`, or for single permissions from
 * the REST API's catalogue (`proxy_hosts:read`, `certificates:write`, …).
 * The two MCP scopes are what {@link parseAuthorizationRequest} advertises in
 * the discovery documents; the per-permission scopes exist so a client that
 * wants less can ask for less, and so a step-up challenge can name exactly
 * what a tool needs.
 *
 * What a token may actually do is never the scope string alone: it is the
 * owner's access, read fresh on every request, intersected with the
 * permissions its scopes expand to (src/lib/api-token-scopes.ts). A user who
 * is demoted, or loses a custom role, loses the permission on their next
 * request even if the token still names the scope.
 */
import {
  can,
  isPermission,
  listHeldPermissions,
  normalizePermissions,
  PERMISSION_AREAS,
  permissionArea,
  type Access,
  type Permission,
} from "../permissions";

/** Read-only access to everything the user may read. */
export const MCP_READ_SCOPE = "mcp.read";
/** Read and write access to everything the user may read or write. */
export const MCP_WRITE_SCOPE = "mcp.write";

/** The scopes the authorization server advertises (RFC 9728 / RFC 8414). */
export const MCP_ADVERTISED_SCOPES = [MCP_READ_SCOPE, MCP_WRITE_SCOPE] as const;

/** The scope granted when a request names none: least privilege. */
export const MCP_DEFAULT_SCOPE = MCP_READ_SCOPE;

/** Most scopes one request may name. */
export const MAX_SCOPES = 40;
const MAX_SCOPE_LENGTH = 120;
const SCOPE_SYNTAX = /^[A-Za-z0-9._:-]+$/;

/**
 * Reads an RFC 6749 `scope` value: space-separated tokens, deduplicated in
 * order. An empty or absent value is `[]`; a malformed value is null.
 */
export function parseScopeString(raw: string | null | undefined): string[] | null {
  if (raw === null || raw === undefined) return [];
  const trimmed = raw.trim();
  if (trimmed === "") return [];
  const parts = trimmed.split(/\s+/);
  if (parts.length > MAX_SCOPES) return null;
  const seen = new Set<string>();
  const scopes: string[] = [];
  for (const part of parts) {
    if (part.length > MAX_SCOPE_LENGTH || !SCOPE_SYNTAX.test(part)) return null;
    if (seen.has(part)) continue;
    seen.add(part);
    scopes.push(part);
  }
  return scopes;
}

export function scopeString(scopes: readonly string[]): string {
  return scopes.join(" ");
}

/** Whether the authorization server knows the scope. */
export function isSupportedScope(scope: string): boolean {
  return scope === MCP_READ_SCOPE || scope === MCP_WRITE_SCOPE || isPermission(scope);
}

/**
 * Whether `access` may grant `scopes`: every one is known, and a
 * per-permission scope is one the user holds now. `mcp.read` and `mcp.write`
 * are always grantable (they expand to whatever the user holds at request
 * time, which may be nothing).
 */
export function validateScopesForAccess(scopes: readonly string[], access: Access): string | null {
  for (const scope of scopes) {
    if (!isSupportedScope(scope)) return `Unknown scope: ${scope}`;
    if (isPermission(scope) && !can(access, scope)) return `You do not hold the permission ${scope}`;
  }
  return null;
}

/**
 * The permissions a set of scopes expands to for this principal. Scopes the
 * principal no longer holds grant nothing; write permissions carry their
 * area's read permission, as in custom roles and API tokens.
 */
export function expandScopes(access: Access, scopes: readonly string[]): Permission[] {
  const held = listHeldPermissions(access);
  const expanded = new Set<Permission>();
  for (const scope of scopes) {
    if (scope === MCP_READ_SCOPE) {
      for (const permission of held) if (permission.endsWith(":read")) expanded.add(permission);
      continue;
    }
    if (scope === MCP_WRITE_SCOPE) {
      for (const permission of held) expanded.add(permission);
      continue;
    }
    if (!isPermission(scope) || !can(access, scope)) continue;
    expanded.add(scope);
    // normalizePermissions adds the read action of a write permission.
  }
  return normalizePermissions([...expanded]);
}

/** Whether a token with `scopes` may perform `permission` (for this principal). */
export function scopesAllow(access: Access, scopes: readonly string[], permission: Permission): boolean {
  return expandScopes(access, scopes).includes(permission);
}

/** Whether an earlier consent covers everything a new request asks for. */
export function scopesCover(consented: readonly string[], requested: readonly string[]): boolean {
  const granted = new Set(consented);
  return requested.every((scope) => granted.has(scope));
}

/**
 * What a step-up challenge should ask for when `access` holds `permission`
 * but the token's scopes do not grant it. Null when no scope can help (the
 * permission is the user's role, not the scope) or when the token already
 * names the broad scope that would have granted it.
 */
export function stepUpScopes(
  access: Access,
  currentScopes: readonly string[],
  permission: Permission
): string[] | null {
  if (!can(access, permission)) return null;
  const broad = permission.endsWith(":read") ? MCP_READ_SCOPE : MCP_WRITE_SCOPE;
  const hasBroad = currentScopes.includes(broad);
  const hasPermissionScope = currentScopes.includes(permission);
  if (hasBroad || hasPermissionScope) return null;
  // Ask for the broad scope the client already knows, plus the specific one
  // for a client that prefers fine-grained scopes.
  const scopes = new Set<string>(
    currentScopes.filter((scope) => scope === MCP_READ_SCOPE || scope === MCP_WRITE_SCOPE)
  );
  scopes.add(broad);
  scopes.add(permission);
  return [...scopes];
}

export type ScopeDescription = {
  scope: string;
  title: string;
  description: string;
};

const AREA_ACTION_LABELS: Record<string, string> = {
  read: "View",
  write: "Change",
  export: "Export",
  import: "Import",
  restore: "Restore",
  approve: "Approve",
  emergency: "Make emergency changes to",
  manage: "Manage",
  promote: "Promote",
  replicas: "Manage replicas of",
  payments: "Manage payments of",
};

function permissionDescription(permission: Permission): ScopeDescription {
  const area = permissionArea(permission);
  const action = permission.slice(area.length + 1);
  const info = PERMISSION_AREAS[area];
  const label = AREA_ACTION_LABELS[action] ?? action;
  return {
    scope: permission,
    title: `${label} ${info.label.toLowerCase()}`,
    description: info.description,
  };
}

/** The scopes of a consent screen, in the order the request named them. */
export function describeScopes(scopes: readonly string[]): ScopeDescription[] {
  return scopes.map((scope) => {
    if (scope === MCP_READ_SCOPE) {
      return {
        scope,
        title: "Read everything you can read",
        description:
          "Hosts, certificates, access lists, users, analytics and the audit log — every area your role may view, now and after a role change.",
      };
    }
    if (scope === MCP_WRITE_SCOPE) {
      return {
        scope,
        title: "Read and change everything you can change",
        description:
          "Create, edit and delete hosts, access lists and certificates, and apply the Caddy configuration — every area your role may change, now and after a role change.",
      };
    }
    return isPermission(scope)
      ? permissionDescription(scope)
      : { scope, title: scope, description: "Unknown scope" };
  });
}
