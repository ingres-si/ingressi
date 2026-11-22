// SPDX-License-Identifier: Elastic-2.0
/**
 * The license boundary (ee/README.md, "Where ee/ code lives"). Code under
 * ee/ is under the Elastic License 2.0; everything else is MIT. Next.js only
 * finds pages and route handlers under app/, so an ee/ page or route keeps a
 * file there that only re-exports its
 * implementation from ee/ (a shim: `export { GET, POST } from "@/ee/…"`, or
 * `export { default, metadata } from "@/ee/…"`, plus literal segment config
 * such as `export const dynamic = "force-dynamic"`, which Next.js reads from
 * the route file itself).
 *
 * tests/unit/license-boundary.test.ts checks that every file under the
 * prefixes below is such a shim, that every source file under ee/ carries the
 * Elastic-2.0 SPDX header, and that core code outside app/ that imports ee/
 * is listed in CORE_EE_HOOKS.
 */
export type EeRouteGroup = {
  /** The ee/ module the files route to. */
  module: string;
  /** Files, or directories ending in "/", under app/ that only route to `module`. */
  prefixes: readonly string[];
};

export const EE_ROUTES: readonly EeRouteGroup[] = [
  {
    module: "ee/access-reviews",
    prefixes: [
      "app/(dashboard)/access-reviews/",
      "app/(dashboard)/my-reviews/",
      "app/api/v1/access-review-assignments/",
      "app/api/v1/access-review-schedules/",
      "app/api/v1/access-reviews/",
    ],
  },
  {
    module: "ee/ai",
    prefixes: ["app/api/v1/ai/", "app/api/v1/analytics/questions/", "app/api/v1/waf/tuning-suggestions/"],
  },
  {
    module: "ee/alerting",
    prefixes: [
      "app/(dashboard)/alerts/",
      "app/api/v1/alert-channels/",
      "app/api/v1/alert-events/",
      "app/api/v1/alert-rules/",
      "app/api/v1/alert-silences/",
    ],
  },
  {
    module: "ee/approvals",
    prefixes: ["app/(dashboard)/approvals/", "app/api/v1/approval-policies/", "app/api/v1/change-requests/"],
  },
  {
    module: "ee/audit",
    prefixes: [
      "app/(dashboard)/audit-log/streaming/",
      "app/api/v1/audit-sinks/",
      "app/api/v1/audit-log/export/",
      "app/api/v1/audit-log/retention/",
      "app/api/v1/audit-log/verify/",
    ],
  },
  {
    module: "ee/backups",
    prefixes: ["app/(dashboard)/backups/", "app/api/v1/backup-destinations/", "app/api/v1/backup-runs/"],
  },
  {
    module: "ee/compliance",
    prefixes: ["app/(dashboard)/compliance/", "app/print/compliance/", "app/api/v1/compliance/"],
  },
  {
    module: "ee/config-history",
    prefixes: ["app/(dashboard)/history/", "app/api/v1/config-history/"],
  },
  {
    module: "ee/custom-roles",
    prefixes: ["app/api/v1/roles/", "app/api/v1/permissions/"],
  },
  {
    module: "ee/fleet",
    prefixes: ["app/(dashboard)/fleet/", "app/api/v1/fleet/", "app/api/instances/pull/"],
  },
  {
    module: "ee/high-availability",
    prefixes: ["app/(dashboard)/high-availability/", "app/api/v1/high-availability/", "app/api/v1/cluster/"],
  },
  {
    module: "ee/ldap",
    prefixes: ["app/(dashboard)/ldap/", "app/api/v1/ldap-directories/"],
  },
  {
    module: "ee/monetization",
    prefixes: ["app/(dashboard)/api-monetization/", "app/api-portal/", "app/api/monetization/", "app/api/v1/monetization/"],
  },
  {
    module: "ee/saml",
    prefixes: ["app/(dashboard)/saml/", "app/api/v1/saml-providers/"],
  },
  {
    module: "ee/scim",
    prefixes: ["app/(dashboard)/scim/", "app/api/v1/scim/", "app/scim/"],
  },
  {
    module: "ee/sso",
    prefixes: ["app/(dashboard)/sso/", "app/api/v1/sso/"],
  },
  {
    module: "ee/white-label",
    prefixes: ["app/(dashboard)/branding/", "app/api/v1/branding/", "app/api/branding/"],
  },
];

/** Every app/ prefix of EE_ROUTES. */
export const EE_ROUTE_PREFIXES: readonly string[] = EE_ROUTES.flatMap((group) => group.prefixes);

/**
 * Core files outside app/ that import ee/: small hooks through which core
 * code reads ee/ state or lets an ee/ feature take part, never ee/ logic of
 * their own. A new entry needs a reason a reviewer can check.
 */
export const CORE_EE_HOOKS: Readonly<Record<string, string>> = {
  "proxy.ts": "High availability: a standby's 503, the request-path routes it still serves, and a refused replica's 503.",
  "src/components/auth/AuthBrand.tsx": "White-label: the product name and logo on the sign-in pages.",
  "src/components/l4-proxy-hosts/L4HostDialogs.tsx": "Change approvals: the notice that a protected host's change needs approval.",
  "src/components/l4-proxy-hosts/editor/L4HostEditor.tsx": "Change approvals: whether a policy covers the L4 host being edited.",
  "src/components/mfa/BackupCodesPanel.tsx": "White-label: the product name in the backup codes file.",
  "src/components/proxy-hosts/editor/AccessSection.tsx": "White-label: the product name in help text.",
  "src/components/proxy-hosts/editor/HostEditor.tsx": "Change approvals: whether a policy covers the host being edited.",
  "src/components/proxy-hosts/editor/ReviewPanel.tsx": "Change approvals: the type of a change preview.",
  "src/components/proxy-hosts/editor/types.ts": "Change approvals: the type of a host's approval context.",
  "src/components/proxy-hosts/HostDialogs.tsx": "Change approvals: the notice that a protected host's change needs approval.",
  "src/instrumentation.ts": "Starts the background jobs of ee/ features (schedulers, workers, the pull agent, the leader watchdog).",
  "src/lib/api-auth.ts": "Custom roles: the permissions of a token's owner.",
  "src/lib/attention/index.ts": "Registers the overview's \"needs attention\" providers of ee/ features.",
  "src/lib/audit-chain.ts": "Configuration history: links an audit event to the versions it made.",
  "src/lib/audit-log-view.ts": "Configuration history: the type of the diff shown with an audit event.",
  "src/lib/auth-server.ts": "SAML, LDAP, SCIM and enforced SSO: their Better Auth plugins and sign-in checks.",
  "src/lib/auth.ts": "Custom roles: a session's permissions.",
  "src/lib/background-jobs.ts": "High availability: which node of a cluster runs the jobs.",
  "src/lib/caddy.ts": "Config history, API monetization and certificate storage: their parts of the Caddy configuration.",
  "src/lib/cluster-nodes.ts": "High availability: admitting a new PostgreSQL replica, and refusing a duplicate node id.",
  "src/lib/config-content.ts": "High availability: encrypts certificate storage secrets in exported configuration.",
  "src/lib/config-replace.ts": "Change approvals and high availability: checks before a configuration import replaces everything.",
  "src/lib/db/startup.ts": "High availability: refuses the SQLite cluster with a PostgreSQL database.",
  "src/lib/forward-auth-state.ts": "High availability: forward-auth sessions in shared state.",
  "src/lib/identity-health.ts": "LDAP: the health of directories for the sign-in overview.",
  "src/lib/init-db.ts": "Enforced SSO: keeps a break-glass account when the first administrator is created.",
  "src/lib/instance-sync-status.ts": "Fleet: the fingerprint token of a pull replica.",
  "src/lib/instance-sync-validation.ts": "White-label and API monetization: their parts of a sync payload.",
  "src/lib/instance-sync.ts": "Fleet, white-label, API monetization and certificate storage: their parts of instance sync.",
  "src/lib/log-parser.ts": "API monetization: credits failed answers from the access log.",
  "src/lib/mcp/server.ts": "Custom roles: the permissions an MCP client acts with.",
  "src/lib/mcp/tools.ts": "Change approvals: whether a host change must become a change request.",
  "src/lib/mfa-auth.ts": "LDAP, SAML and white-label: directory passwords and sign-in paths under MFA, the product name.",
  "src/lib/mfa.ts": "LDAP and enforced SSO: which accounts sign in with a directory or are break-glass.",
  "src/lib/models/api-tokens.ts": "Custom roles: a token owner's permissions.",
  "src/lib/models/instances.ts": "Fleet: forgets a deleted instance's fleet state.",
  "src/lib/models/l4-proxy-hosts.ts": "Change approvals and white-label: guards on L4 host changes, the product name.",
  "src/lib/models/proxy-hosts.ts": "Change approvals, API monetization and white-label: guards on host changes, the product name.",
  "src/lib/models/user.ts": "Enforced SSO: break-glass accounts.",
  "src/lib/models/waf-exclusions.ts": "Change approvals: guards on WAF exclusions of protected hosts.",
  "src/lib/nav-summary.ts": "Sidebar counters of ee/ pages and the environment.",
  "src/lib/overview.ts": "The overview's fleet nodes.",
  "src/lib/passkey-auth.ts": "White-label: the product name as the passkey relying party.",
  "src/lib/passkeys.ts": "Enforced SSO: whether passkeys may still be used.",
  "src/lib/proxy-host-changes.ts": "Change approvals: gates a host change.",
  "src/lib/proxy-host-detail.ts": "Alerting and configuration history: the host page's alert rules and versions.",
  "src/lib/search.ts": "White-label: the product name, which decides whether documentation results are shown.",
  "src/lib/secret-rotation.ts": "High availability: re-encrypts certificate storage secrets.",
  "src/lib/sign-in-activity.ts": "LDAP and SAML: names their sign-in paths in the activity log.",
  "src/lib/sign-in-overview.ts": "SAML, LDAP, SCIM and enforced SSO: their entries on the sign-in overview.",
  "src/lib/startup-caches.ts": "White-label, API monetization and shared state: loads their caches at start-up.",
  "src/lib/users-overview.ts": "Custom roles, LDAP, SCIM and enforced SSO: the users overview's sources and roles.",
};
