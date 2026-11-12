/**
 * The permission catalogue: every area of the dashboard and REST API that an
 * administrator-only guard protects, and the actions on it. Each guarded call
 * site names exactly one permission (requirePermission in auth.ts,
 * requireApiPermission in api-auth.ts); ee/docs/custom-roles.md has the
 * call-site table and tests/unit/permission-call-sites.test.ts keeps the two
 * in step.
 *
 * Built-in roles: "admin" holds every permission; "user" and "viewer" hold
 * none of them, which is exactly what they could do before custom roles
 * existed (their profile, their API tokens and the overview page). Custom
 * roles (ee/custom-roles) hold a chosen subset, optionally limited to hosts
 * that carry one of the role's tags.
 *
 * Nothing here reads the database, so the client can import it
 * for the permission matrix and the navigation.
 */

export type PermissionAreaInfo = {
  label: string;
  description: string;
  actions: readonly string[];
  /** Limited to tagged hosts when the role has a tag scope. */
  scopable?: boolean;
  /** Reads or changes data of every host, whatever the role's tag scope. */
  instanceWide?: boolean;
};

export const PERMISSION_AREAS = {
  proxy_hosts: {
    label: "Proxy hosts",
    description: "HTTP proxy hosts, their mTLS access rules and forward-auth access.",
    actions: ["read", "write"],
    scopable: true,
  },
  l4_proxy_hosts: {
    label: "L4 proxy hosts",
    description: "TCP/UDP proxy hosts and applying their listening ports.",
    actions: ["read", "write"],
    scopable: true,
  },
  certificates: {
    label: "Certificates",
    description: "Certificates; without a tag scope also CA certificates, client certificates and mTLS roles.",
    actions: ["read", "write"],
    scopable: true,
  },
  access_lists: {
    label: "Access lists",
    description: "Access lists: rules by address, country and AS number, basic-auth users, and the global Blocked sources list.",
    actions: ["read", "write"],
  },
  groups: {
    label: "Groups",
    description: "Forward-auth groups and their members.",
    actions: ["read", "write"],
  },
  waf: {
    label: "WAF",
    description: "WAF events and why a request was blocked, global WAF settings, per-host WAF modes, rule exclusions and tuning suggestions.",
    actions: ["read", "write"],
    instanceWide: true,
  },
  analytics: {
    label: "Analytics",
    description: "Traffic analytics for every host, and asking questions about it in plain language (AI analyst).",
    actions: ["read"],
    instanceWide: true,
  },
  users: {
    label: "Users and roles",
    description: "Dashboard users, their roles, custom roles, MFA resets and forward-auth sessions.",
    actions: ["read", "write"],
  },
  audit_log: {
    label: "Audit log",
    description: "Reading, exporting and verifying the audit log.",
    actions: ["read"],
    instanceWide: true,
  },
  settings: {
    label: "Settings",
    description: "Global settings: the Settings page, the settings pages next to what they configure, and the setup checklist.",
    actions: ["read", "write"],
    instanceWide: true,
  },
  instances: {
    label: "Instances",
    description: "Instance mode, sync tokens, slave instances and sync-key pins.",
    actions: ["read", "write"],
    instanceWide: true,
  },
  fleet: {
    label: "Fleet management",
    description: "Environments of slave instances, revisions, drift status, pull replicas; write: environments and assignments; promote: promotions, rollbacks, aborts and re-syncs, which change what slaves serve; replicas: adding pull replicas and issuing, rotating and revoking their credentials, which can fetch the whole configuration.",
    actions: ["read", "write", "promote", "replicas"],
    instanceWide: true,
  },
  high_availability: {
    label: "High availability",
    description: "Where the Caddy nodes keep TLS certificates and their private keys (local or shared Redis/Valkey storage), and testing that storage; read also shows the dashboard cluster (leader, standbys, replication).",
    actions: ["read", "write"],
    instanceWide: true,
  },
  api_docs: {
    label: "API docs",
    description: "The REST API reference.",
    actions: ["read"],
  },
  config: {
    label: "Configuration export/import",
    description: "Export the whole configuration (with its secrets) or replace it from an export.",
    actions: ["export", "import"],
    instanceWide: true,
  },
  alerts: {
    label: "Alerts",
    description: "Alert channels, rules and history.",
    actions: ["read", "write"],
  },
  ai: {
    label: "AI analyst",
    description: "AI provider settings, the security digest and the settings of analytics questions.",
    actions: ["read", "write"],
  },
  audit_streaming: {
    label: "Audit streaming",
    description: "Audit sinks and audit log retention.",
    actions: ["read", "write"],
  },
  config_history: {
    label: "Configuration history",
    description: "Configuration snapshots, history settings and rollback.",
    actions: ["read", "write", "restore"],
    instanceWide: true,
  },
  backups: {
    label: "Scheduled backups",
    description: "Backup destinations, runs and restores.",
    actions: ["read", "write", "restore"],
    instanceWide: true,
  },
  sso: {
    label: "Single sign-on",
    description: "OAuth/OIDC providers, SAML providers and enforced SSO.",
    actions: ["read", "write"],
  },
  mfa_policy: {
    label: "MFA policy",
    description: "The multi-factor authentication policy.",
    actions: ["read", "write"],
  },
  approvals: {
    label: "Change approvals",
    description:
      "Change requests for protected hosts (read: see them and comment, cancel your own; approve: approve, reject and apply other people's), " +
      "emergency changes that skip approval, and the approval policies. Requests are limited to hosts the role can read.",
    actions: ["read", "approve", "emergency", "manage"],
  },
  compliance: {
    label: "Compliance reports",
    description: "Compliance reports (access review, change log, certificate inventory, protection coverage), report schedules, the live control status, recorded test restores and the incident register with NIS2 notification drafts. Reports list every user, API token name and host.",
    actions: ["read", "write"],
    instanceWide: true,
  },
  ldap: {
    label: "LDAP / Active Directory",
    description: "Directories for dashboard sign-in with LDAP or Active Directory accounts, their group-to-role mapping, and testing them.",
    actions: ["read", "write"],
  },
  scim: {
    label: "SCIM provisioning",
    description: "SCIM settings, SCIM tokens, group-to-role mappings and which users and groups SCIM manages.",
    actions: ["read", "write"],
  },
  access_reviews: {
    label: "Access reviews",
    description: "Access review campaigns and schedules, their decisions and records.",
    actions: ["read", "write"],
  },
  monetization: {
    label: "API monetization",
    description: "API plans, consumers with their keys and balances, monetized hosts and the ledger; payments: the Stripe account that receives consumers' money.",
    actions: ["read", "write", "payments"],
    instanceWide: true,
  },
  branding: {
    label: "Branding",
    description: "White-label branding: product name, logos, favicon, colours and the texts of the sign-in pages and e-mails.",
    actions: ["read", "write"],
    instanceWide: true,
  },
} as const satisfies Record<string, PermissionAreaInfo>;

export type PermissionArea = keyof typeof PERMISSION_AREAS;

type AreaPermission<A extends PermissionArea> = `${A}:${(typeof PERMISSION_AREAS)[A]["actions"][number]}`;
export type Permission = { [A in PermissionArea]: AreaPermission<A> }[PermissionArea];

export const PERMISSION_AREA_NAMES = Object.keys(PERMISSION_AREAS) as PermissionArea[];

/** Every permission, in catalogue order. */
export const PERMISSIONS: readonly Permission[] = PERMISSION_AREA_NAMES.flatMap((area) =>
  (PERMISSION_AREAS[area].actions as readonly string[]).map((action) => `${area}:${action}` as Permission)
);

const PERMISSION_SET: ReadonlySet<string> = new Set(PERMISSIONS);

export function isPermission(value: unknown): value is Permission {
  return typeof value === "string" && PERMISSION_SET.has(value);
}

export function permissionArea(permission: Permission): PermissionArea {
  return permission.slice(0, permission.indexOf(":")) as PermissionArea;
}

/** Areas whose permissions a role's tag scope limits. */
export const SCOPABLE_AREAS = ["proxy_hosts", "l4_proxy_hosts", "certificates"] as const;
export type ScopableArea = (typeof SCOPABLE_AREAS)[number];

export function isScopableArea(area: string): area is ScopableArea {
  return (SCOPABLE_AREAS as readonly string[]).includes(area);
}

/**
 * Permissions only administrators may grant, in a custom role or by assigning
 * one: they decide who can sign in or what the instance is (sso, MFA policy,
 * LDAP directories and the roles their groups grant, instance sync
 * and the pull replica credentials that fetch the whole configuration,
 * where consumers' payments go, where every certificate's private key is
 * kept, and the name and logo every sign-in page shows, which could make
 * them pass for another organisation's), or they set
 * aside segregation of duties (change approval policies, emergency changes).
 * scim:write issues tokens that create users and, through group-to-role
 * mappings, give them roles; access_reviews:write starts campaigns whose
 * reviewers can take access away from every user, administrators included.
 * config:import replaces the whole configuration with a file the caller
 * supplies, which holds everything an administrator can set (raw Caddy JSON
 * on hosts, upstreams on Caddy's admin API); so does backups:restore held
 * with backups:write, which names the destination the backup is read from.
 * Holding users:write and settings:write together is also administrator-level,
 * and so is users:write with approvals:approve, which could create a second
 * account to approve one's own changes (see ADMIN_LEVEL_COMBINATIONS).
 */
export const ADMIN_LEVEL_PERMISSIONS: readonly Permission[] = [
  "sso:write",
  "mfa_policy:write",
  "ldap:write",
  "instances:write",
  "fleet:replicas",
  "monetization:payments",
  "branding:write",
  "high_availability:write",
  "approvals:emergency",
  "approvals:manage",
  "scim:write",
  "access_reviews:write",
  "config:import",
];

export const ADMIN_LEVEL_COMBINATIONS: readonly (readonly Permission[])[] = [
  ["users:write", "settings:write"],
  ["users:write", "approvals:approve"],
  ["backups:write", "backups:restore"],
];

export function isAdminLevel(permissions: Iterable<Permission>): boolean {
  const held = new Set(permissions);
  if (ADMIN_LEVEL_PERMISSIONS.some((permission) => held.has(permission))) return true;
  return ADMIN_LEVEL_COMBINATIONS.some((combination) => combination.every((permission) => held.has(permission)));
}

/**
 * Permissions a role with a tag scope cannot hold: they read or replace the
 * configuration of every host at once (with its secrets), so a scope could
 * not limit them.
 */
export const UNSCOPED_ONLY_PERMISSIONS: readonly Permission[] = [
  "config:export",
  "config:import",
  "config_history:restore",
  "backups:write",
  "backups:restore",
  "fleet:write",
  "fleet:promote",
  "fleet:replicas",
  "high_availability:write",
];

/**
 * Validates and completes a permission list: unknown names are refused, the
 * list is deduplicated and put in catalogue order, and every write, restore
 * or import action also grants the area's read action when it has one (a
 * role that can change something can see it).
 */
export function normalizePermissions(input: readonly unknown[]): Permission[] {
  const held = new Set<Permission>();
  for (const value of input) {
    if (!isPermission(value)) {
      throw new PermissionCatalogueError(`Unknown permission: ${String(value).slice(0, 80)}`);
    }
    held.add(value);
    const area = permissionArea(value);
    const actions = PERMISSION_AREAS[area].actions as readonly string[];
    if (actions.includes("read") && !value.endsWith(":read")) {
      held.add(`${area}:read` as Permission);
    }
  }
  return PERMISSIONS.filter((permission) => held.has(permission));
}

export class PermissionCatalogueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PermissionCatalogueError";
  }
}

export const BUILT_IN_ROLES = ["admin", "user", "viewer"] as const;
export type BuiltInRole = (typeof BUILT_IN_ROLES)[number];

export function isBuiltInRole(value: unknown): value is BuiltInRole {
  return typeof value === "string" && (BUILT_IN_ROLES as readonly string[]).includes(value);
}

/**
 * What a principal (a session or an API token's owner) may do. Built once per
 * request by resolveAccess (ee/custom-roles/access.ts) from the user's row.
 */
export type Access = {
  userId: number;
  /** users.role as stored. Custom-role users have "viewer". */
  role: string;
  isAdmin: boolean;
  customRole: { id: number; name: string } | null;
  permissions: ReadonlySet<Permission>;
  /** Tags limiting the scopable areas; empty means every host. Always empty for admins. */
  scopeTags: readonly string[];
  /**
   * Set when the principal is an API token with scopes
   * (src/lib/api-token-scopes.ts): what the scopes allow. Such a principal
   * is never an administrator and holds at most these permissions.
   */
  tokenScopes?: readonly Permission[] | null;
};

export function adminAccess(userId: number): Access {
  return {
    userId,
    role: "admin",
    isAdmin: true,
    customRole: null,
    permissions: new Set(PERMISSIONS),
    scopeTags: [],
  };
}

export function builtInAccess(userId: number, role: string): Access {
  if (role === "admin") return adminAccess(userId);
  return { userId, role, isAdmin: false, customRole: null, permissions: new Set(), scopeTags: [] };
}

export function can(access: Access, permission: Permission): boolean {
  return access.isAdmin || access.permissions.has(permission);
}

/**
 * The tags that limit `area` for this principal, or null when every host is
 * in scope (administrators, unscoped roles and areas a scope does not limit).
 */
export function scopeTagsFor(access: Access, area: PermissionArea): readonly string[] | null {
  if (access.isAdmin || !isScopableArea(area) || access.scopeTags.length === 0) return null;
  return access.scopeTags;
}

/** True when `tags` include one of the scope's tags (or there is no scope). */
export function tagsInScope(tags: readonly string[], scope: readonly string[] | null): boolean {
  if (scope === null) return true;
  return tags.some((tag) => scope.includes(tag));
}

/** The permissions a principal holds, for the client (navigation, page controls). */
export function listHeldPermissions(access: Access): Permission[] {
  return access.isAdmin ? [...PERMISSIONS] : PERMISSIONS.filter((permission) => access.permissions.has(permission));
}

/** The message a refused permission check carries. Built-in non-admin roles keep the old wording. */
export function permissionDeniedMessage(
  access: Pick<Access, "customRole"> & Partial<Pick<Access, "tokenScopes">>,
  permission: Permission
): string {
  if (access.tokenScopes && !access.tokenScopes.includes(permission)) {
    return `This API token's scopes do not include ${permission}`;
  }
  return access.customRole || access.tokenScopes
    ? `Permission required: ${permission}`
    : "Administrator privileges required";
}
