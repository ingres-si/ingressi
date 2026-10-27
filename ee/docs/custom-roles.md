# Custom roles

Code: `ee/custom-roles/` (Elastic License 2.0); the permission catalogue (`src/lib/permissions.ts`), the guards (`requirePermission` in `src/lib/auth.ts`, `requireApiPermission` in `src/lib/api-auth.ts`), the scope checks (`src/lib/access-scope.ts`) and host tags (`src/lib/host-tags.ts`, see `documentation/host-tags.md`) are MIT.

Custom roles give users fine-grained permissions instead of all-or-nothing administrator access, optionally limited to proxy hosts, L4 hosts and certificates that carry one of the role's tags. Two teams can share one install: each team's role is scoped to its own tag.

## Roles

| Role | What it can do |
| --- | --- |
| `admin` (built-in) | Every permission, never limited by a scope. |
| `user`, `viewer` (built-in) | No permission from the catalogue: their profile, their API tokens and the overview page, exactly as before custom roles. |
| Custom role | The permissions it lists, optionally limited by a tag scope. |

A user has either a built-in role or one custom role. `users.role` keeps the built-in role; a custom-role user is stored with `role = "viewer"` and `users.customRoleId` pointing at the role. Every code path that only knows the built-in roles therefore treats a custom-role user as a viewer, and a user whose role is deleted is a viewer. API tokens act with their owner's current role, custom role and scope included (the role is read on every request).

An API token can also carry **scopes**: a list of permissions from the catalogue (`scopes` on `POST /api/v1/tokens`, the Profile page's "Choose permissions"). Such a token holds its owner's current permissions intersected with its scopes, a write scope with its area's read as in custom roles. It keeps the owner's tag scope, it is never an administrator (so the administrator-only paths below refuse it, whatever its owner is), and it cannot use the endpoints for its owner's own account (sessions, tokens, passkeys, preferences, MFA state, access review assignments). A scope can only name a permission the owner holds when the token is created; if the owner later loses it, the token loses it too. `getApiAccess` in `src/lib/api-auth.ts` applies the scopes on every permission check. A refused scope answers `403` with `This API token's scopes do not include <permission>`.

## Permission catalogue

`GET /api/v1/permissions` returns it. A write, restore or import action includes the area's read action (`normalizePermissions`). A saved role or token scope that names a permission this release does not have (written by another release) still loads: the name is ignored, never widened into another permission, and saving the role drops it.

| Area | Actions | Covers |
| --- | --- | --- |
| `proxy_hosts` | read, write | Proxy hosts, their mTLS access rules and forward-auth access, the GeoIP status. **Scoped.** |
| `l4_proxy_hosts` | read, write | L4 proxy hosts and applying their ports. **Scoped.** |
| `certificates` | read, write | Certificates. Without a scope also CA certificates, client certificates and mTLS roles. **Scoped** (see below). |
| `access_lists` | read, write | Access lists: their rules (address, country, continent and AS number), basic-auth users and settings, where they are used and what they stopped (24 h); the global Blocked sources list. |
| `groups` | read, write | Forward-auth groups and members. |
| `waf` | read, write | Security events (what the WAF, geo rules, access lists, sign-in and rate limits stopped) and why a request was blocked, global WAF settings (mode, paranoia level, anomaly thresholds), per-host WAF modes, rule exclusions, tuning suggestions. Every host. Blocking an address from Security events also needs `access_lists:write`. |
| `analytics` | read | Traffic analytics, security events, traffic signals and per-host traffic summaries, the caller's saved analytics views, and plain-language analytics questions with saved questions (the AI analyst, [analytics-questions.md](analytics-questions.md)). Every host; per-host summaries only for the proxy hosts the role reaches, and a question's host tags only name proxy hosts the role reaches. |
| `users` | read, write | Users, roles, custom roles, MFA resets, forward-auth sessions. |
| `audit_log` | read | Audit log, its filters, event details with the before/after diff of configuration changes (from configuration history, secrets masked), its export and verification. Every host. |
| `settings` | read, write | Global settings: the Settings page and the settings pages next to what they configure (Certificate settings, Host defaults, Geo blocking, Rate limiting, Analytics settings, and the pages of instance sync, OAuth providers and high availability, whose contents need their own permission too), re-applying the Caddy configuration, the setup checklist (`write` marks steps done or hides it). |
| `instances` | read, write | Instance mode, sync token, slave instances, sync-key pins; with `monetization:write`, whether and how replicas serve monetized hosts. |
| `fleet` | read, write, promote, replicas | Fleet management: environments, revisions, rollouts, drift, pull replicas. `write` manages environments and assignments and runs drift checks; `promote` starts promotions and rollbacks, aborts rollouts and re-syncs instances, which change what slaves serve. Releasing instances from a promotion-only environment needs both. `replicas` adds and deletes pull replicas and issues, rotates and revokes their credentials; it is administrator-level, since a credential fetches the whole configuration. Every host. |
| `high_availability` | read, write | High availability: where the Caddy nodes keep certificates and their private keys (local or shared Redis/Valkey storage), testing that storage, and whether the web nodes keep forward-auth sessions and API balances there (shared state); `read` also shows the dashboard cluster (leader, standbys, replication). `write` is administrator-level. Every host. |
| `api_docs` | read | The API reference. |
| `config` | export, import | Configuration export (with its secrets) and import. |
| `alerts` | read, write | Alert channels, rules and history. |
| `ai` | read, write | AI provider settings, the security digest and the settings of analytics questions. |
| `audit_streaming` | read, write | Audit sinks and audit retention. |
| `config_history` | read, write, restore | Snapshots, history settings, rollback. |
| `backups` | read, write, restore | Backup destinations, runs, restores (the Backups page). |
| `sso` | read, write | OAuth/OIDC providers, SAML providers (`/api/v1/saml-providers`) and enforced SSO. `write` is administrator-level. |
| `mfa_policy` | read, write | The MFA policy. |
| `ldap` | read, write | LDAP / Active Directory directories for dashboard sign-in, their group-to-role mapping, testing them. `write` is administrator-level. |
| `compliance` | read, write | Compliance reports, report schedules (evidence packs), the live control status, recorded test restores and the incident register with NIS2 notification drafts: `read` lists, views, downloads and prints them; `write` generates reports, sets up, changes, runs and deletes schedules (including which saved analytics questions they re-run), records and deletes test restores, records, classifies, edits and AI-drafts incidents, and deletes reports and incidents. Reports list every user, API token name and host, so grant `compliance:read` like `users:read` and `audit_log:read` together. Every host. |
| `scim` | read, write | SCIM provisioning: settings, SCIM tokens, group-to-role mappings, which users and groups SCIM manages. `write` is administrator-level: its tokens create users and its mappings grant roles. |
| `access_reviews` | read, write | Access review campaigns and schedules, their records and the evidence for their items (sign-ins, last changes, last use). `write` (start, schedule, complete, cancel, delete) is administrator-level: a campaign's reviewers can take access away from every user. Reviewers need no permission to decide the items of a campaign that names them, or to read their evidence. |
| `monetization` | read, write, payments | API monetization: plans, consumers with their keys, balances and saved cards (charging a postpaid consumer's open amount, resuming a suspended one), monetized hosts with their x402 prices, the ledger and retention; replica serving needs `instances:write` as well. `payments` replaces or removes the Stripe account and the x402 settings (the CDP facilitator credentials, and turning x402 on, which creates the Stripe deposit address) that receive consumers' payments, and is administrator-level. Every host. |
| `branding` | read, write | White-label branding: product name, logos, favicon, accent colour, sign-in texts, support contact, e-mail sender name. `write` is administrator-level. Every host. |
| `approvals` | read, approve, emergency, manage | Change approvals (see [change-approvals.md](change-approvals.md)): `read` sees change requests on hosts the role can read (and its own) and comments or cancels its own; `approve` approves, rejects and applies other people's; `emergency` applies a protected change at once with a reason; `manage` creates, changes, disables and deletes approval policies. `emergency` and `manage` are administrator-level. |

"Every host" areas are not limited by a tag scope: a scoped role that holds them sees data of every host.

## Tag scope

A role's `scopeTags` limit its `proxy_hosts`, `l4_proxy_hosts` and `certificates` permissions to hosts carrying at least one of the tags. Without tags the role reaches every host.

- **Proxy hosts and L4 hosts.** Lists are filtered (also counts and search). Reading, changing or deleting a host outside the scope answers `404`, exactly like a missing host; so do its mTLS access rules and forward-auth access. A scoped write may add or remove only the role's own tags; other tags already on the host are kept as they are. The host must keep at least one of the role's tags, so creating a host requires one (the form pre-fills the first). Domains already served by a host outside the scope (equal, or matched through a wildcard either way) are refused, and so are L4 ports (per protocol) used by an L4 host outside the scope: a team cannot take over another team's traffic.
- **Certificates.** Certificates are not tagged; a scoped role sees the certificates that its in-scope proxy hosts use, and the ACME hosts in its scope. It may change or delete a certificate only when every proxy host using it is in its scope (`403` when another team's host uses it too, `404` when none of its hosts does), and it cannot create certificates (a new certificate is used by no host yet). CA certificates, client certificates and mTLS roles are trust anchors for every host, so they need a `certificates` permission **without** a scope (`403` otherwise).
- **Access lists** are not scoped: `access_lists:read` shows every list and `access_lists:write` changes lists that hosts outside a scope may use too. The Access Lists page lists only the hosts using a list that the user can see, and the requests a list stopped only on those hosts. `access_lists:write` also changes the global Blocked sources list, which applies to every host. The request total and what Blocked sources stopped need `analytics:read` as well. Attaching a list to a host needs `access_lists:read`.
- **Permissions a scoped role cannot hold** (they read or replace every host's configuration at once): `config:export`, `config:import`, `config_history:restore`, `backups:write`, `backups:restore`, `fleet:write`, `fleet:promote`, `fleet:replicas`, `high_availability:write`. Saving such a role is refused with `400`.

## Limits on every non-administrator

Whatever their role, only administrators can:

- set raw Caddy JSON on a proxy host (`customReverseProxyJson`, `customPreHandlersJson`; keeping the stored value is allowed);
- proxy (HTTP upstreams, location rules, L4 upstreams) to port 2019, Caddy's admin API;
- reference on a host something they cannot read: a certificate outside their certificate scope, an access list without `access_lists:read`, trusted client certificates or mTLS roles without an unscoped `certificates:read`, forward-auth users without `users:read` or groups without `groups:read`. References the host already has are kept.

`proxy_hosts:write` still lets a role proxy a domain to any internal address; grant it to people you trust with that.

## Escalation guards

- Only users with `users:write` manage roles and assign them.
- Nobody grants a permission they do not hold, or a wider scope than their own for the scoped areas: a scoped actor can only give scopes made of its own tags, and never an unscoped scoped-area permission.
- **Administrator-level** roles can only be created, changed or assigned by administrators, and so can the built-in admin role. A role is administrator-level when it holds any of `sso:write`, `mfa_policy:write`, `ldap:write`, `instances:write`, `fleet:replicas`, `high_availability:write`, `monetization:payments`, `branding:write`, `scim:write`, `access_reviews:write`, `approvals:emergency`, `approvals:manage`, or both `users:write` and `settings:write`, or both `users:write` and `approvals:approve`. These decide who can sign in (SSO, OAuth and SAML providers and the roles SAML groups grant, the MFA policy, LDAP directories and the roles their groups grant), which nodes receive the configuration (pushed to, or fetched with a pull replica credential), where every certificate's private key is kept (certificate storage), where API consumers' payments go, the name and logo every sign-in page shows (which could make the pages pass for another organisation's), who is provisioned with which role (SCIM), whose access is taken away (access reviews), and whether segregation of duties holds (change approval policies and emergency changes); user management plus global settings together approach full administration, and user management plus approving could create a second account to approve one's own changes.
- A non-administrator only manages users whose access they hold themselves (role, status, profile, MFA reset, forward-auth sessions, deletion). An administrator is never covered, so a non-administrator can never demote, disable or delete one.
- Nobody changes their own role, and a non-administrator cannot edit or delete the custom role they hold.
- The last active administrator cannot be demoted, disabled or deleted (`400 This change would leave no active administrator`), and the enforced-SSO break-glass guard (`ee/docs/sso-enforcement.md`) applies to every role change as before.
- Identity providers never set a custom role: the user-creation hook drops `customRoleId` even with `AUTH_ALLOW_OAUTH_ROLE_FROM_CLAIMS=true`, which keeps mapping role claims to the built-in roles only.
- Every role change, creation, edit and deletion is recorded in the audit log (`custom_role` create/update/delete; user `create` naming the role given; user `update` with the old and new role; one event per user who fell back to viewer when a role is deleted).

## MFA policy

The `admins` scope of the MFA policy covers administrators **and every user with a custom role**: a custom role holds management permissions.

## Dashboard

- **Users and groups → Roles** lists the built-in roles and the custom roles with how many permissions each holds, its tag scope and its users. Open a role to see its permissions grouped by area (Traffic, Observe, Identity, Govern, Platform), who holds it, and **Edit role**, **Duplicate** and **Delete role**. The editor has the permission matrix (one row per area) and the tag scope; permissions you do not hold are disabled. Deleting asks for confirmation and says how many users fall back to viewer.
- The role picker (create user, edit user) offers the built-in roles and the custom roles. Admin and administrator-level roles are disabled for non-administrators.
- The sidebar shows the pages whose read permission the user holds (`NAV_GROUPS` in `src/lib/navigation.ts`). Pages and server actions check the same permissions as the REST API. Sections inside a page that belong to another area are hidden: the settings pages of instance sync, OAuth providers and high availability, and certificate storage on Certificate settings, show a notice without `instances:read`, `sso:read` or `high_availability:read` (the traffic totals on Analytics settings need `analytics:read`), the daily digest on the Channels tab of Alerts (`ai:read`), the backups line and export/import on History (`backups:read`, `config:export`, `config:import`), the MFA policy on Users (`mfa_policy:read`), the user picker on Groups (`users:read`).
- Proxy host and L4 host forms have a **Tags** field; the lists show the tags.

## Instance sync

Custom roles and user assignments are master-only, like users: they are not part of instance sync or configuration export/history. Host tags are columns of the host rows, so they are synced, exported and restored with the hosts.

## REST API

| Method and path | Permission | Notes |
| --- | --- | --- |
| `GET /api/v1/roles` | `users:read` | Roles with `userCount` and `adminLevel`. |
| `POST /api/v1/roles` | `users:write` | `{name, description?, permissions, scopeTags?}`; `201`. |
| `GET /api/v1/roles/{id}` | `users:read` | |
| `PUT /api/v1/roles/{id}` | `users:write` | Partial update. |
| `DELETE /api/v1/roles/{id}` | `users:write` | `{affectedUserIds}`. |
| `GET /api/v1/permissions` | `users:read` | The catalogue, administrator-level set and unscoped-only set. |

Users: `GET /api/v1/users` and `/users/{id}` return `customRoleId`. `POST /api/v1/users` and `PUT /api/v1/users/{id}` accept `customRoleId` (a role id to assign it, `null` to take it away; `role` may then only be omitted or `"viewer"`). Hosts: proxy host and L4 host bodies carry `tags`.

```bash
curl -X POST https://dash.example.com/api/v1/roles -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Team A","permissions":["proxy_hosts:write","certificates:read"],"scopeTags":["team-a"]}'
curl -X PUT https://dash.example.com/api/v1/users/7 -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"customRoleId": 3}'
```

`GET /api/v1/search` (the command palette, `documentation/command-palette.md`) checks no single permission: any signed-in user or token may call it, and each group of results is limited to what the caller can read (hosts and certificates with their read permission and the tag scope, users with `users:read`, actions with the write permission of the page they open, settings sections with `settings:read` and the section's own permission).

A refused permission answers `403` with `Permission required: <permission>` for a custom-role user and `Administrator privileges required` for the built-in user and viewer roles (as before).

## Needs attention (overview)

`GET /api/v1/overview/attention` is open to every signed-in user. Each source answers only for callers who hold one of its permissions, and only with what they may see: certificates (`certificates:read`, within the tag scope), the last Caddy apply and the setup checklist (`settings:read`), traffic signals (`analytics:read`; links to a host only with `proxy_hosts:read` and the host in the tag scope, to the security events only with `waf:read`), failing LDAP directories (`ldap:read`) and accounts locked out by the MFA policy (`users:read`), firing alerts (`alerts:read`), change requests (`approvals:read`, the requests the role may see), access reviews (`access_reviews:read`), the fleet (`fleet:read` or `instances:read`), failing backups (`backups:read`). The caller's own access review items need no permission.

The overview page itself (`app/(dashboard)/page.tsx`, `src/lib/overview.ts`) is open to every signed-in user and shows each section only with its read permission: the traffic figures and busiest hosts with `analytics:read` (host links with `proxy_hosts:read`, certificate days with `certificates:read`), the nodes with `fleet:read` or `instances:read`, recent changes with `audit_log:read` (roll-back links with `config_history:restore`), the setup checklist with `settings:read` (marking steps and hiding it with `settings:write`). See `documentation/overview.md`.

## Deliberately administrator-only

These stay tied to the built-in admin role whatever a custom role holds:

- `GET /api/v1/tokens` lists every user's API tokens and `DELETE /api/v1/tokens/{id}` deletes another user's token only for administrators; everyone else, custom roles included, sees and deletes their own.
- Granting the built-in admin role and administrator-level roles (above).
- Raw Caddy JSON on proxy hosts and upstreams on port 2019 (above).
- Break-glass accounts of enforced SSO must be built-in administrators.
- `requireAdmin()` (`src/lib/auth.ts`) and `requireApiAdmin()` (`src/lib/api-auth.ts`) remain for such paths; no route, page or server action calls them any more.

## Call sites

Every guard of a route, page or server action and the permission it checks. Routes and pages are listed by their file in `app/`, which gives the URL; for a feature in `ee/` that file only routes to `ee/` and the guard is in the `ee/` module it names (`ee/README.md`). Server actions of features in `ee/` are listed by their file in `ee/`. `tests/unit/permission-call-sites.test.ts` fails when this table and the code differ, and `tests/integration/custom-roles-route-guards.test.ts` calls every REST handler as a custom role without and with the permission.

<!-- call-sites:start -->
| File | Function | Permission |
| --- | --- | --- |
| `app/(dashboard)/access-lists/[id]/page.tsx` | `AccessListPage` | `access_lists:read` |
| `app/(dashboard)/access-lists/actions.ts` | `createAccessListAction` | `access_lists:write` |
| `app/(dashboard)/access-lists/actions.ts` | `saveAccessListAction` | `access_lists:write` |
| `app/(dashboard)/access-lists/actions.ts` | `deleteAccessListAction` | `access_lists:write` |
| `app/(dashboard)/access-lists/actions.ts` | `saveBlockedSourcesAction` | `access_lists:write` |
| `app/(dashboard)/access-lists/actions.ts` | `blockSourceAction` | `access_lists:write` |
| `app/(dashboard)/access-lists/actions.ts` | `unblockSourceAction` | `access_lists:write` |
| `app/(dashboard)/access-lists/page.tsx` | `AccessListsPage` | `access_lists:read` |
| `app/(dashboard)/access-reviews/[id]/page.tsx` | `AccessReviewCampaignPage` | `access_reviews:read` |
| `app/(dashboard)/access-reviews/page.tsx` | `AccessReviewsPage` | `access_reviews:read` |
| `app/(dashboard)/alerts/page.tsx` | `AlertsPage` | `alerts:read` |
| `app/(dashboard)/analytics/page.tsx` | `AnalyticsPage` | `analytics:read` |
| `app/(dashboard)/analytics/settings/page.tsx` | `AnalyticsSettingsPage` | `settings:read` |
| `app/(dashboard)/api-docs/page.tsx` | `ApiDocsPage` | `api_docs:read` |
| `app/(dashboard)/api-monetization/page.tsx` | `ApiMonetizationPage` | `monetization:read` |
| `app/(dashboard)/approvals/page.tsx` | `ApprovalsPage` | `approvals:read` |
| `app/(dashboard)/audit-log/actions.ts` | `getAuditEventDetailAction` | `audit_log:read` |
| `app/(dashboard)/audit-log/page.tsx` | `AuditLogPage` | `audit_log:read` |
| `app/(dashboard)/audit-log/streaming/page.tsx` | `AuditStreamingPage` | `audit_streaming:read` |
| `app/(dashboard)/backups/page.tsx` | `BackupsPage` | `backups:read` |
| `app/(dashboard)/branding/page.tsx` | `BrandingPage` | `branding:read` |
| `app/(dashboard)/certificates/actions.ts` | `createCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/actions.ts` | `saveManagedCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/actions.ts` | `updateCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/actions.ts` | `deleteCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `createCaCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `updateCaCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `deleteCaCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `generateCaCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `issueClientCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `revokeIssuedClientCertificateAction` | `certificates:write` |
| `app/(dashboard)/certificates/ca-actions.ts` | `revokeIssuedClientCertificatesAction` | `certificates:write` |
| `app/(dashboard)/certificates/page.tsx` | `CertificatesPage` | `certificates:read` |
| `app/(dashboard)/certificates/settings/page.tsx` | `CertificateSettingsPage` | `settings:read` |
| `app/(dashboard)/compliance/incidents/[id]/page.tsx` | `ComplianceIncidentPage` | `compliance:read` |
| `app/(dashboard)/compliance/page.tsx` | `CompliancePage` | `compliance:read` |
| `app/(dashboard)/compliance/reports/[id]/page.tsx` | `ComplianceReportPage` | `compliance:read` |
| `app/(dashboard)/fleet/page.tsx` | `FleetPage` | `fleet:read` |
| `app/(dashboard)/geo-blocking/page.tsx` | `GeoBlockingPage` | `settings:read` |
| `app/(dashboard)/groups/actions.ts` | `createGroupAction` | `groups:write` |
| `app/(dashboard)/groups/actions.ts` | `updateGroupAction` | `groups:write` |
| `app/(dashboard)/groups/actions.ts` | `deleteGroupAction` | `groups:write` |
| `app/(dashboard)/groups/actions.ts` | `addGroupMemberAction` | `groups:write` |
| `app/(dashboard)/groups/actions.ts` | `removeGroupMemberAction` | `groups:write` |
| `app/(dashboard)/groups/page.tsx` | `GroupsPage` | `groups:read` |
| `app/(dashboard)/history/page.tsx` | `HistoryPage` | `config_history:read` |
| `app/(dashboard)/high-availability/page.tsx` | `HighAvailabilityPage` | `settings:read` |
| `app/(dashboard)/instances/page.tsx` | `InstancesPage` | `settings:read` |
| `app/(dashboard)/l4-proxy-hosts/[id]/page.tsx` | `L4HostPage` | `l4_proxy_hosts:read` |
| `app/(dashboard)/l4-proxy-hosts/actions.ts` | `createL4ProxyHostAction` | `l4_proxy_hosts:write` |
| `app/(dashboard)/l4-proxy-hosts/actions.ts` | `updateL4ProxyHostAction` | `l4_proxy_hosts:write` |
| `app/(dashboard)/l4-proxy-hosts/actions.ts` | `deleteL4ProxyHostAction` | `l4_proxy_hosts:write` |
| `app/(dashboard)/l4-proxy-hosts/actions.ts` | `toggleL4ProxyHostAction` | `l4_proxy_hosts:write` |
| `app/(dashboard)/l4-proxy-hosts/bulk-actions.ts` | `bulkL4ProxyHostsAction` | `l4_proxy_hosts:write` |
| `app/(dashboard)/l4-proxy-hosts/new/page.tsx` | `NewL4HostPage` | `l4_proxy_hosts:write` |
| `app/(dashboard)/l4-proxy-hosts/page.tsx` | `L4ProxyHostsPage` | `l4_proxy_hosts:read` |
| `app/(dashboard)/ldap/page.tsx` | `LdapPage` | `ldap:read` |
| `app/(dashboard)/oauth-providers/page.tsx` | `OAuthProvidersPage` | `settings:read` |
| `app/(dashboard)/proxy-hosts/[id]/page.tsx` | `ProxyHostPage` | `proxy_hosts:read` |
| `app/(dashboard)/proxy-hosts/defaults/page.tsx` | `HostDefaultsPage` | `settings:read` |
| `app/(dashboard)/proxy-hosts/actions.ts` | `createProxyHostAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/actions.ts` | `updateProxyHostAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/actions.ts` | `deleteProxyHostAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/actions.ts` | `toggleProxyHostAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/bulk-actions.ts` | `bulkProxyHostsAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/editor-actions.ts` | `saveProxyHostEditorAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/editor-actions.ts` | `previewProxyHostEditorAction` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/new/page.tsx` | `NewProxyHostPage` | `proxy_hosts:write` |
| `app/(dashboard)/proxy-hosts/page.tsx` | `ProxyHostsPage` | `proxy_hosts:read` |
| `app/(dashboard)/rate-limiting/page.tsx` | `RateLimitingPage` | `settings:read` |
| `app/(dashboard)/saml/page.tsx` | `SamlPage` | `sso:read` |
| `app/(dashboard)/scim/page.tsx` | `ScimPage` | `scim:read` |
| `app/(dashboard)/security/actions.ts` | `wafAuditRecordAction` | `waf:read` |
| `app/(dashboard)/security/page.tsx` | `SecurityEventsPage` | `waf:read` |
| `app/(dashboard)/settings/actions.ts` | `updateGeneralSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateAcmeSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateCloudflareSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateDnsProviderSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateAuthentikSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateForwardAuthSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateMetricsSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateLoggingSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateTrustedProxiesSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateDnsSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateUpstreamDnsResolutionSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateInstanceModeActionUnlocked` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `updateSlaveMasterTokenActionUnlocked` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `createSlaveInstanceAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `deleteSlaveInstanceAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `updateSlaveInstanceAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `resetSlaveSyncKeyPinAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `pinSlaveSyncKeyAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `toggleSlaveInstanceAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `updateGeoBlockSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateErrorPagesSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateRateLimitSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateResponseHeadersSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `updateDefaultResponseSettingsActionUnlocked` | `settings:write` |
| `app/(dashboard)/settings/actions.ts` | `syncSlaveInstancesAction` | `instances:write` |
| `app/(dashboard)/settings/actions.ts` | `lookupWafRuleMessageAction` | `waf:read` |
| `app/(dashboard)/settings/actions.ts` | `removeWafRuleGloballyActionUnlocked` | `waf:write` |
| `app/(dashboard)/settings/actions.ts` | `suppressWafRuleGloballyActionUnlocked` | `waf:write` |
| `app/(dashboard)/settings/actions.ts` | `getOAuthProvidersAction` | `sso:read` |
| `app/(dashboard)/settings/actions.ts` | `createOAuthProviderAction` | `sso:write` |
| `app/(dashboard)/settings/actions.ts` | `updateOAuthProviderAction` | `sso:write` |
| `app/(dashboard)/settings/actions.ts` | `deleteOAuthProviderAction` | `sso:write` |
| `app/(dashboard)/settings/actions.ts` | `suppressWafRuleForHostAction` | `waf:write` |
| `app/(dashboard)/settings/actions.ts` | `updateWafSettingsActionUnlocked` | `waf:write` |
| `app/(dashboard)/settings/ai/page.tsx` | `AiSettingsPage` | `ai:read` |
| `app/(dashboard)/settings/page.tsx` | `SettingsPage` | `settings:read` |
| `app/(dashboard)/sign-in/page.tsx` | `SignInPage` | `sso:read` |
| `app/(dashboard)/sso/page.tsx` | `SsoPage` | `sso:read` |
| `app/(dashboard)/users/actions.ts` | `createUserAction` | `users:write` |
| `app/(dashboard)/users/actions.ts` | `updateUserRoleAction` | `users:write` |
| `app/(dashboard)/users/actions.ts` | `updateUserStatusAction` | `users:write` |
| `app/(dashboard)/users/actions.ts` | `updateUserInfoAction` | `users:write` |
| `app/(dashboard)/users/actions.ts` | `deleteUserAction` | `users:write` |
| `app/(dashboard)/users/mfa-actions.ts` | `updateMfaPolicyAction` | `mfa_policy:write` |
| `app/(dashboard)/users/mfa-actions.ts` | `resetUserMfaAction` | `users:write` |
| `app/(dashboard)/users/page.tsx` | `UsersPage` | `users:read` |
| `app/(dashboard)/waf/actions.ts` | `saveWafSettingsAction` | `waf:write` |
| `app/(dashboard)/waf/actions.ts` | `setWafHostModeAction` | `waf:write` |
| `app/(dashboard)/waf/actions.ts` | `createWafExclusionAction` | `waf:write` |
| `app/(dashboard)/waf/actions.ts` | `createWafExclusionsAction` | `waf:write` |
| `app/(dashboard)/waf/actions.ts` | `updateWafExclusionAction` | `waf:write` |
| `app/(dashboard)/waf/actions.ts` | `deleteWafExclusionAction` | `waf:write` |
| `app/(dashboard)/waf/actions.ts` | `explainWafEventAction` | `waf:read` |
| `app/(dashboard)/waf/page.tsx` | `WafPage` | `waf:read` |
| `app/api/geoip-status/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/l4-ports/route.ts` | `GET` | `l4_proxy_hosts:read` |
| `app/api/l4-ports/route.ts` | `POST` | `l4_proxy_hosts:write` |
| `app/api/v1/access-lists/[id]/entries/[entryId]/route.ts` | `DELETE` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/entries/route.ts` | `POST` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-lists/[id]/route.ts` | `PUT` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/route.ts` | `DELETE` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/rules/[ruleId]/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-lists/[id]/rules/[ruleId]/route.ts` | `PUT` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/rules/[ruleId]/route.ts` | `DELETE` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/rules/reorder/route.ts` | `POST` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/rules/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-lists/[id]/rules/route.ts` | `POST` | `access_lists:write` |
| `app/api/v1/access-lists/[id]/rules/route.ts` | `PUT` | `access_lists:write` |
| `app/api/v1/access-lists/blocked-sources/entries/[entryId]/route.ts` | `DELETE` | `access_lists:write` |
| `app/api/v1/access-lists/blocked-sources/entries/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-lists/blocked-sources/entries/route.ts` | `POST` | `access_lists:write` |
| `app/api/v1/access-lists/blocked-sources/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-lists/blocked-sources/route.ts` | `PUT` | `access_lists:write` |
| `app/api/v1/access-lists/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-lists/route.ts` | `POST` | `access_lists:write` |
| `app/api/v1/access-lists/stats/route.ts` | `GET` | `access_lists:read` |
| `app/api/v1/access-review-schedules/[id]/route.ts` | `GET` | `access_reviews:read` |
| `app/api/v1/access-review-schedules/[id]/route.ts` | `PUT` | `access_reviews:write` |
| `app/api/v1/access-review-schedules/[id]/route.ts` | `DELETE` | `access_reviews:write` |
| `app/api/v1/access-review-schedules/route.ts` | `GET` | `access_reviews:read` |
| `app/api/v1/access-review-schedules/route.ts` | `POST` | `access_reviews:write` |
| `app/api/v1/access-reviews/[id]/cancel/route.ts` | `POST` | `access_reviews:write` |
| `app/api/v1/access-reviews/[id]/complete/route.ts` | `POST` | `access_reviews:write` |
| `app/api/v1/access-reviews/[id]/evidence/route.ts` | `GET` | `access_reviews:read` |
| `app/api/v1/access-reviews/[id]/record/route.ts` | `GET` | `access_reviews:read` |
| `app/api/v1/access-reviews/[id]/route.ts` | `GET` | `access_reviews:read` |
| `app/api/v1/access-reviews/[id]/route.ts` | `DELETE` | `access_reviews:write` |
| `app/api/v1/access-reviews/route.ts` | `GET` | `access_reviews:read` |
| `app/api/v1/access-reviews/route.ts` | `POST` | `access_reviews:write` |
| `app/api/v1/ai/digest/preview/route.ts` | `POST` | `ai:write` |
| `app/api/v1/ai/digest/route.ts` | `GET` | `ai:read` |
| `app/api/v1/ai/digest/route.ts` | `PUT` | `ai:write` |
| `app/api/v1/ai/digest/send/route.ts` | `POST` | `ai:write` |
| `app/api/v1/ai/question-settings/route.ts` | `GET` | `ai:read` |
| `app/api/v1/ai/question-settings/route.ts` | `PUT` | `ai:write` |
| `app/api/v1/ai/settings/route.ts` | `GET` | `ai:read` |
| `app/api/v1/ai/settings/route.ts` | `PUT` | `ai:write` |
| `app/api/v1/ai/settings/route.ts` | `DELETE` | `ai:write` |
| `app/api/v1/ai/test/route.ts` | `POST` | `ai:write` |
| `app/api/v1/alert-channels/[id]/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-channels/[id]/route.ts` | `PUT` | `alerts:write` |
| `app/api/v1/alert-channels/[id]/route.ts` | `DELETE` | `alerts:write` |
| `app/api/v1/alert-channels/[id]/test/route.ts` | `POST` | `alerts:write` |
| `app/api/v1/alert-channels/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-channels/route.ts` | `POST` | `alerts:write` |
| `app/api/v1/alert-channels/test/route.ts` | `POST` | `alerts:write` |
| `app/api/v1/alert-events/firing/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-events/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-rules/[id]/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-rules/[id]/route.ts` | `PUT` | `alerts:write` |
| `app/api/v1/alert-rules/[id]/route.ts` | `DELETE` | `alerts:write` |
| `app/api/v1/alert-rules/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-rules/route.ts` | `POST` | `alerts:write` |
| `app/api/v1/alert-silences/[id]/route.ts` | `DELETE` | `alerts:write` |
| `app/api/v1/alert-silences/route.ts` | `GET` | `alerts:read` |
| `app/api/v1/alert-silences/route.ts` | `POST` | `alerts:write` |
| `app/api/v1/analytics/hosts/[id]/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/hosts/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/query/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/questions/route.ts` | `POST` | `analytics:read` |
| `app/api/v1/analytics/questions/saved/[id]/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/questions/saved/[id]/route.ts` | `PATCH` | `analytics:read` |
| `app/api/v1/analytics/questions/saved/[id]/route.ts` | `DELETE` | `analytics:read` |
| `app/api/v1/analytics/questions/saved/[id]/run/route.ts` | `POST` | `analytics:read` |
| `app/api/v1/analytics/questions/saved/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/questions/saved/route.ts` | `POST` | `analytics:read` |
| `app/api/v1/analytics/requests/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/security/events/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/security/hosts/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/security/rules/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/security/series/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/security/sources/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/signals/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/top/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/values/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/views/[id]/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/views/[id]/route.ts` | `PATCH` | `analytics:read` |
| `app/api/v1/analytics/views/[id]/route.ts` | `DELETE` | `analytics:read` |
| `app/api/v1/analytics/views/route.ts` | `GET` | `analytics:read` |
| `app/api/v1/analytics/views/route.ts` | `POST` | `analytics:read` |
| `app/api/v1/approval-policies/[id]/route.ts` | `GET` | `approvals:read` |
| `app/api/v1/approval-policies/[id]/route.ts` | `PUT` | `approvals:manage` |
| `app/api/v1/approval-policies/[id]/route.ts` | `DELETE` | `approvals:manage` |
| `app/api/v1/approval-policies/route.ts` | `GET` | `approvals:read` |
| `app/api/v1/approval-policies/route.ts` | `POST` | `approvals:manage` |
| `app/api/v1/audit-log/[id]/route.ts` | `GET` | `audit_log:read` |
| `app/api/v1/audit-log/export/route.ts` | `GET` | `audit_log:read` |
| `app/api/v1/audit-log/facets/route.ts` | `GET` | `audit_log:read` |
| `app/api/v1/audit-log/retention/route.ts` | `GET` | `audit_streaming:read` |
| `app/api/v1/audit-log/retention/route.ts` | `PUT` | `audit_streaming:write` |
| `app/api/v1/audit-log/route.ts` | `GET` | `audit_log:read` |
| `app/api/v1/audit-log/verify/route.ts` | `GET` | `audit_log:read` |
| `app/api/v1/audit-sinks/[id]/route.ts` | `GET` | `audit_streaming:read` |
| `app/api/v1/audit-sinks/[id]/route.ts` | `PUT` | `audit_streaming:write` |
| `app/api/v1/audit-sinks/[id]/route.ts` | `DELETE` | `audit_streaming:write` |
| `app/api/v1/audit-sinks/[id]/test/route.ts` | `POST` | `audit_streaming:write` |
| `app/api/v1/audit-sinks/route.ts` | `GET` | `audit_streaming:read` |
| `app/api/v1/audit-sinks/route.ts` | `POST` | `audit_streaming:write` |
| `app/api/v1/backup-destinations/[id]/objects/route.ts` | `GET` | `backups:read` |
| `app/api/v1/backup-destinations/[id]/restore/route.ts` | `POST` | `backups:restore` |
| `app/api/v1/backup-destinations/[id]/route.ts` | `GET` | `backups:read` |
| `app/api/v1/backup-destinations/[id]/route.ts` | `PUT` | `backups:write` |
| `app/api/v1/backup-destinations/[id]/route.ts` | `DELETE` | `backups:write` |
| `app/api/v1/backup-destinations/[id]/run/route.ts` | `POST` | `backups:write` |
| `app/api/v1/backup-destinations/[id]/test/route.ts` | `POST` | `backups:write` |
| `app/api/v1/backup-destinations/route.ts` | `GET` | `backups:read` |
| `app/api/v1/backup-destinations/route.ts` | `POST` | `backups:write` |
| `app/api/v1/backup-runs/route.ts` | `GET` | `backups:read` |
| `app/api/v1/branding/assets/[asset]/route.ts` | `PUT` | `branding:write` |
| `app/api/v1/branding/assets/[asset]/route.ts` | `DELETE` | `branding:write` |
| `app/api/v1/branding/route.ts` | `GET` | `branding:read` |
| `app/api/v1/branding/route.ts` | `PUT` | `branding:write` |
| `app/api/v1/branding/route.ts` | `DELETE` | `branding:write` |
| `app/api/v1/ca-certificates/[id]/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/ca-certificates/[id]/route.ts` | `PUT` | `certificates:write` |
| `app/api/v1/ca-certificates/[id]/route.ts` | `DELETE` | `certificates:write` |
| `app/api/v1/ca-certificates/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/ca-certificates/route.ts` | `POST` | `certificates:write` |
| `app/api/v1/caddy/apply/route.ts` | `POST` | `settings:write` |
| `app/api/v1/certificates/[id]/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/certificates/[id]/route.ts` | `PUT` | `certificates:write` |
| `app/api/v1/certificates/[id]/route.ts` | `DELETE` | `certificates:write` |
| `app/api/v1/certificates/managed/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/certificates/overview/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/certificates/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/certificates/route.ts` | `POST` | `certificates:write` |
| `app/api/v1/change-requests/[id]/apply/route.ts` | `POST` | `approvals:approve` |
| `app/api/v1/change-requests/[id]/approve/route.ts` | `POST` | `approvals:approve` |
| `app/api/v1/change-requests/[id]/cancel/route.ts` | `POST` | `approvals:read` |
| `app/api/v1/change-requests/[id]/comments/route.ts` | `POST` | `approvals:read` |
| `app/api/v1/change-requests/[id]/emergency/route.ts` | `POST` | `approvals:emergency` |
| `app/api/v1/change-requests/[id]/reject/route.ts` | `POST` | `approvals:approve` |
| `app/api/v1/change-requests/[id]/route.ts` | `GET` | `approvals:read` |
| `app/api/v1/change-requests/route.ts` | `GET` | `approvals:read` |
| `app/api/v1/client-certificates/[id]/roles/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/client-certificates/[id]/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/client-certificates/[id]/route.ts` | `DELETE` | `certificates:write` |
| `app/api/v1/client-certificates/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/client-certificates/route.ts` | `POST` | `certificates:write` |
| `app/api/v1/cluster/nodes/route.ts` | `GET` | `high_availability:read` |
| `app/api/v1/compliance/controls/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/controls/status/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/incidents/[id]/draft/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/compliance/incidents/[id]/facts/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/compliance/incidents/[id]/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/incidents/[id]/route.ts` | `PUT` | `compliance:write` |
| `app/api/v1/compliance/incidents/[id]/route.ts` | `DELETE` | `compliance:write` |
| `app/api/v1/compliance/incidents/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/incidents/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/compliance/packs/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/reports/[id]/export/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/reports/[id]/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/reports/[id]/route.ts` | `DELETE` | `compliance:write` |
| `app/api/v1/compliance/reports/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/reports/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/compliance/restore-tests/[id]/route.ts` | `DELETE` | `compliance:write` |
| `app/api/v1/compliance/restore-tests/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/restore-tests/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/compliance/schedules/[id]/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/schedules/[id]/route.ts` | `PUT` | `compliance:write` |
| `app/api/v1/compliance/schedules/[id]/route.ts` | `DELETE` | `compliance:write` |
| `app/api/v1/compliance/schedules/[id]/run/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/compliance/schedules/route.ts` | `GET` | `compliance:read` |
| `app/api/v1/compliance/schedules/route.ts` | `POST` | `compliance:write` |
| `app/api/v1/config-history/[id]/diff/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config-history/[id]/restore/route.ts` | `POST` | `config_history:restore` |
| `app/api/v1/config-history/[id]/rollback-preview/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config-history/[id]/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config-history/[id]/route.ts` | `DELETE` | `config_history:write` |
| `app/api/v1/config-history/compare/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config-history/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config-history/route.ts` | `POST` | `config_history:write` |
| `app/api/v1/config-history/route.ts` | `DELETE` | `config_history:write` |
| `app/api/v1/config-history/settings/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config-history/settings/route.ts` | `PUT` | `config_history:write` |
| `app/api/v1/config-history/versions/route.ts` | `GET` | `config_history:read` |
| `app/api/v1/config/export/route.ts` | `POST` | `config:export` |
| `app/api/v1/config/import/route.ts` | `POST` | `config:import` |
| `app/api/v1/fleet/drift/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/drift/route.ts` | `POST` | `fleet:write` |
| `app/api/v1/fleet/environments/[id]/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/environments/[id]/route.ts` | `PATCH` | `fleet:write` |
| `app/api/v1/fleet/environments/[id]/route.ts` | `DELETE` | `fleet:write` |
| `app/api/v1/fleet/environments/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/environments/route.ts` | `POST` | `fleet:write` |
| `app/api/v1/fleet/instances/[id]/environment/route.ts` | `PUT` | `fleet:write` |
| `app/api/v1/fleet/instances/[id]/resync/route.ts` | `POST` | `fleet:promote` |
| `app/api/v1/fleet/instances/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/promotions/preview/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/pull-replicas/[id]/credential/route.ts` | `POST` | `fleet:replicas` |
| `app/api/v1/fleet/pull-replicas/[id]/credential/route.ts` | `DELETE` | `fleet:replicas` |
| `app/api/v1/fleet/pull-replicas/[id]/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/pull-replicas/[id]/route.ts` | `DELETE` | `fleet:replicas` |
| `app/api/v1/fleet/pull-replicas/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/pull-replicas/route.ts` | `POST` | `fleet:replicas` |
| `app/api/v1/fleet/revisions/[id]/diff/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/revisions/[id]/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/revisions/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/rollouts/[id]/abort/route.ts` | `POST` | `fleet:promote` |
| `app/api/v1/fleet/rollouts/[id]/rollback/route.ts` | `POST` | `fleet:promote` |
| `app/api/v1/fleet/rollouts/[id]/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/rollouts/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/fleet/rollouts/route.ts` | `POST` | `fleet:promote` |
| `app/api/v1/fleet/route.ts` | `GET` | `fleet:read` |
| `app/api/v1/forward-auth-sessions/[id]/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/forward-auth-sessions/route.ts` | `GET` | `users:read` |
| `app/api/v1/forward-auth-sessions/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/groups/[id]/members/[userId]/route.ts` | `DELETE` | `groups:write` |
| `app/api/v1/groups/[id]/members/route.ts` | `POST` | `groups:write` |
| `app/api/v1/groups/[id]/route.ts` | `GET` | `groups:read` |
| `app/api/v1/groups/[id]/route.ts` | `PATCH` | `groups:write` |
| `app/api/v1/groups/[id]/route.ts` | `DELETE` | `groups:write` |
| `app/api/v1/groups/overview/route.ts` | `GET` | `groups:read` |
| `app/api/v1/groups/route.ts` | `GET` | `groups:read` |
| `app/api/v1/groups/route.ts` | `POST` | `groups:write` |
| `app/api/v1/high-availability/cluster/route.ts` | `GET` | `high_availability:read` |
| `app/api/v1/high-availability/shared-state/route.ts` | `GET` | `high_availability:read` |
| `app/api/v1/high-availability/shared-state/route.ts` | `PUT` | `high_availability:write` |
| `app/api/v1/high-availability/shared-state/route.ts` | `DELETE` | `high_availability:write` |
| `app/api/v1/high-availability/shared-state/status/route.ts` | `GET` | `high_availability:read` |
| `app/api/v1/high-availability/storage/route.ts` | `GET` | `high_availability:read` |
| `app/api/v1/high-availability/storage/route.ts` | `PUT` | `high_availability:write` |
| `app/api/v1/high-availability/storage/route.ts` | `DELETE` | `high_availability:write` |
| `app/api/v1/high-availability/storage/test/route.ts` | `POST` | `high_availability:write` |
| `app/api/v1/instances/[id]/route.ts` | `PUT` | `instances:write` |
| `app/api/v1/instances/[id]/route.ts` | `DELETE` | `instances:write` |
| `app/api/v1/instances/[id]/sync-key-pin/route.ts` | `PUT` | `instances:write` |
| `app/api/v1/instances/[id]/sync-key-pin/route.ts` | `DELETE` | `instances:write` |
| `app/api/v1/instances/route.ts` | `GET` | `instances:read` |
| `app/api/v1/instances/route.ts` | `POST` | `instances:write` |
| `app/api/v1/instances/sync-key-pins/route.ts` | `GET` | `instances:read` |
| `app/api/v1/instances/sync-key-pins/route.ts` | `PUT` | `instances:write` |
| `app/api/v1/instances/sync-key-pins/route.ts` | `DELETE` | `instances:write` |
| `app/api/v1/instances/sync-key/route.ts` | `GET` | `instances:read` |
| `app/api/v1/instances/sync/route.ts` | `POST` | `instances:write` |
| `app/api/v1/l4-proxy-hosts/[id]/route.ts` | `GET` | `l4_proxy_hosts:read` |
| `app/api/v1/l4-proxy-hosts/[id]/route.ts` | `PUT` | `l4_proxy_hosts:write` |
| `app/api/v1/l4-proxy-hosts/[id]/route.ts` | `DELETE` | `l4_proxy_hosts:write` |
| `app/api/v1/l4-proxy-hosts/route.ts` | `GET` | `l4_proxy_hosts:read` |
| `app/api/v1/l4-proxy-hosts/route.ts` | `POST` | `l4_proxy_hosts:write` |
| `app/api/v1/ldap-directories/[id]/route.ts` | `GET` | `ldap:read` |
| `app/api/v1/ldap-directories/[id]/route.ts` | `PUT` | `ldap:write` |
| `app/api/v1/ldap-directories/[id]/route.ts` | `DELETE` | `ldap:write` |
| `app/api/v1/ldap-directories/[id]/test-sign-in/route.ts` | `POST` | `ldap:write` |
| `app/api/v1/ldap-directories/[id]/test/route.ts` | `POST` | `ldap:write` |
| `app/api/v1/ldap-directories/route.ts` | `GET` | `ldap:read` |
| `app/api/v1/ldap-directories/route.ts` | `POST` | `ldap:write` |
| `app/api/v1/mfa/policy/route.ts` | `GET` | `mfa_policy:read` |
| `app/api/v1/mfa/policy/route.ts` | `PUT` | `mfa_policy:write` |
| `app/api/v1/monetization/consumers/[id]/adjust/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/billing/card/route.ts` | `DELETE` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/billing/charge/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/billing/resume/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/keys/[keyId]/route.ts` | `DELETE` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/keys/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/consumers/[id]/keys/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/portal-link/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/portal-link/route.ts` | `DELETE` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/consumers/[id]/route.ts` | `PUT` | `monetization:write` |
| `app/api/v1/monetization/consumers/[id]/route.ts` | `DELETE` | `monetization:write` |
| `app/api/v1/monetization/consumers/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/consumers/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/hosts/[id]/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/hosts/[id]/route.ts` | `PUT` | `monetization:write` |
| `app/api/v1/monetization/hosts/[id]/route.ts` | `DELETE` | `monetization:write` |
| `app/api/v1/monetization/hosts/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/ledger/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/overview/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/payments/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/plans/[id]/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/plans/[id]/route.ts` | `PUT` | `monetization:write` |
| `app/api/v1/monetization/plans/[id]/route.ts` | `DELETE` | `monetization:write` |
| `app/api/v1/monetization/plans/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/plans/route.ts` | `POST` | `monetization:write` |
| `app/api/v1/monetization/settings/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/settings/route.ts` | `PUT` | `monetization:write` |
| `app/api/v1/monetization/stripe/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/stripe/route.ts` | `PUT` | `monetization:payments` |
| `app/api/v1/monetization/stripe/route.ts` | `DELETE` | `monetization:payments` |
| `app/api/v1/monetization/x402/payments/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/x402/route.ts` | `GET` | `monetization:read` |
| `app/api/v1/monetization/x402/route.ts` | `PUT` | `monetization:payments` |
| `app/api/v1/monetization/x402/route.ts` | `DELETE` | `monetization:payments` |
| `app/api/v1/mtls-roles/[id]/certificates/[certId]/route.ts` | `DELETE` | `certificates:write` |
| `app/api/v1/mtls-roles/[id]/certificates/route.ts` | `POST` | `certificates:write` |
| `app/api/v1/mtls-roles/[id]/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/mtls-roles/[id]/route.ts` | `PUT` | `certificates:write` |
| `app/api/v1/mtls-roles/[id]/route.ts` | `DELETE` | `certificates:write` |
| `app/api/v1/mtls-roles/route.ts` | `GET` | `certificates:read` |
| `app/api/v1/mtls-roles/route.ts` | `POST` | `certificates:write` |
| `app/api/v1/oauth-providers/[id]/route.ts` | `GET` | `sso:read` |
| `app/api/v1/oauth-providers/[id]/route.ts` | `PUT` | `sso:write` |
| `app/api/v1/oauth-providers/[id]/route.ts` | `DELETE` | `sso:write` |
| `app/api/v1/oauth-providers/route.ts` | `GET` | `sso:read` |
| `app/api/v1/oauth-providers/route.ts` | `POST` | `sso:write` |
| `app/api/v1/openapi.json/route.ts` | `GET` | `api_docs:read` |
| `app/api/v1/permissions/route.ts` | `GET` | `users:read` |
| `app/api/v1/proxy-hosts/[id]/forward-auth-access/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/v1/proxy-hosts/[id]/forward-auth-access/route.ts` | `PUT` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/[id]/health/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/v1/proxy-hosts/[id]/mtls-access-rules/[ruleId]/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/v1/proxy-hosts/[id]/mtls-access-rules/[ruleId]/route.ts` | `PUT` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/[id]/mtls-access-rules/[ruleId]/route.ts` | `DELETE` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/[id]/mtls-access-rules/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/v1/proxy-hosts/[id]/mtls-access-rules/route.ts` | `POST` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/[id]/preview/route.ts` | `POST` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/[id]/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/v1/proxy-hosts/[id]/route.ts` | `PUT` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/[id]/route.ts` | `DELETE` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/preview/route.ts` | `POST` | `proxy_hosts:write` |
| `app/api/v1/proxy-hosts/route.ts` | `GET` | `proxy_hosts:read` |
| `app/api/v1/proxy-hosts/route.ts` | `POST` | `proxy_hosts:write` |
| `app/api/v1/roles/[id]/route.ts` | `GET` | `users:read` |
| `app/api/v1/roles/[id]/route.ts` | `PUT` | `users:write` |
| `app/api/v1/roles/[id]/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/roles/route.ts` | `GET` | `users:read` |
| `app/api/v1/roles/route.ts` | `POST` | `users:write` |
| `app/api/v1/saml-providers/[id]/metadata/route.ts` | `GET` | `sso:read` |
| `app/api/v1/saml-providers/[id]/route.ts` | `GET` | `sso:read` |
| `app/api/v1/saml-providers/[id]/route.ts` | `PUT` | `sso:write` |
| `app/api/v1/saml-providers/[id]/route.ts` | `DELETE` | `sso:write` |
| `app/api/v1/saml-providers/route.ts` | `GET` | `sso:read` |
| `app/api/v1/saml-providers/route.ts` | `POST` | `sso:write` |
| `app/api/v1/scim/groups/[id]/route.ts` | `DELETE` | `scim:write` |
| `app/api/v1/scim/groups/route.ts` | `GET` | `scim:read` |
| `app/api/v1/scim/groups/route.ts` | `POST` | `scim:write` |
| `app/api/v1/scim/role-mappings/[id]/route.ts` | `PUT` | `scim:write` |
| `app/api/v1/scim/role-mappings/[id]/route.ts` | `DELETE` | `scim:write` |
| `app/api/v1/scim/role-mappings/route.ts` | `GET` | `scim:read` |
| `app/api/v1/scim/role-mappings/route.ts` | `POST` | `scim:write` |
| `app/api/v1/scim/settings/route.ts` | `GET` | `scim:read` |
| `app/api/v1/scim/settings/route.ts` | `PUT` | `scim:write` |
| `app/api/v1/scim/tokens/[id]/route.ts` | `DELETE` | `scim:write` |
| `app/api/v1/scim/tokens/route.ts` | `GET` | `scim:read` |
| `app/api/v1/scim/tokens/route.ts` | `POST` | `scim:write` |
| `app/api/v1/scim/users/[id]/route.ts` | `DELETE` | `scim:write` |
| `app/api/v1/scim/users/route.ts` | `GET` | `scim:read` |
| `app/api/v1/scim/users/route.ts` | `POST` | `scim:write` |
| `app/api/v1/settings/[group]/route.ts` | `GET` | `instances:read` |
| `app/api/v1/settings/[group]/route.ts` | `GET` | `waf:read` |
| `app/api/v1/settings/[group]/route.ts` | `GET` | `settings:read` |
| `app/api/v1/settings/[group]/route.ts` | `PUT` | `instances:write` |
| `app/api/v1/settings/[group]/route.ts` | `PUT` | `waf:write` |
| `app/api/v1/settings/[group]/route.ts` | `PUT` | `settings:write` |
| `app/api/v1/setup-checklist/route.ts` | `GET` | `settings:read` |
| `app/api/v1/setup-checklist/route.ts` | `PUT` | `settings:write` |
| `app/api/v1/sign-in/overview/route.ts` | `GET` | `sso:read` |
| `app/api/v1/sso/enforcement/route.ts` | `GET` | `sso:read` |
| `app/api/v1/sso/enforcement/route.ts` | `PUT` | `sso:write` |
| `app/api/v1/users/[id]/mfa/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/users/[id]/route.ts` | `PUT` | `users:write` |
| `app/api/v1/users/[id]/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/users/[id]/sessions/[sessionId]/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/users/[id]/sessions/route.ts` | `GET` | `users:read` |
| `app/api/v1/users/[id]/sessions/route.ts` | `DELETE` | `users:write` |
| `app/api/v1/users/overview/route.ts` | `GET` | `users:read` |
| `app/api/v1/users/route.ts` | `GET` | `users:read` |
| `app/api/v1/users/route.ts` | `POST` | `users:write` |
| `app/api/v1/waf/events/[id]/explain/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/events/[id]/suggested-exclusion/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/events/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/exclusions/[id]/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/exclusions/[id]/route.ts` | `PATCH` | `waf:write` |
| `app/api/v1/waf/exclusions/[id]/route.ts` | `DELETE` | `waf:write` |
| `app/api/v1/waf/exclusions/batch/route.ts` | `POST` | `waf:write` |
| `app/api/v1/waf/exclusions/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/exclusions/route.ts` | `POST` | `waf:write` |
| `app/api/v1/waf/hosts/[id]/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/hosts/[id]/route.ts` | `PUT` | `waf:write` |
| `app/api/v1/waf/hosts/route.ts` | `GET` | `waf:read` |
| `app/api/v1/waf/tuning-suggestions/[id]/apply/route.ts` | `POST` | `waf:write` |
| `app/api/v1/waf/tuning-suggestions/[id]/dismiss/route.ts` | `POST` | `waf:write` |
| `app/api/v1/waf/tuning-suggestions/route.ts` | `GET` | `waf:read` |
| `app/api/waf-events/route.ts` | `GET` | `waf:read` |
| `app/print/compliance/incidents/[id]/page.tsx` | `ComplianceIncidentPrintPage` | `compliance:read` |
| `app/print/compliance/reports/[id]/page.tsx` | `ComplianceReportPrintPage` | `compliance:read` |
| `ee/ai/ui/digest-actions.ts` | `run` | `ai:write` |
| `ee/ai/ui/tuning-actions.ts` | `run` | `waf:write` |
| `ee/alerting/ui/actions.ts` | `saveAlertChannelAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `setAlertChannelEnabledAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `deleteAlertChannelAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `testAlertChannelAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `testAlertChannelDraftAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `saveAlertRuleAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `setAlertRuleEnabledAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `deleteAlertRuleAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `silenceAlertAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `endAlertSilenceAction` | `alerts:write` |
| `ee/alerting/ui/actions.ts` | `saveAiSettingsAction` | `ai:write` |
| `ee/alerting/ui/actions.ts` | `removeAiSettingsAction` | `ai:write` |
| `ee/alerting/ui/actions.ts` | `testAiProviderAction` | `ai:write` |
| `ee/alerting/ui/actions.ts` | `saveQuestionSettingsAction` | `ai:write` |
| `ee/audit/ui/actions.ts` | `verifyAuditLogAction` | `audit_log:read` |
| `ee/audit/ui/streaming-actions.ts` | `run` | `audit_streaming:write` |
| `ee/custom-roles/ui/actions.ts` | `saveRoleAction` | `users:write` |
| `ee/custom-roles/ui/actions.ts` | `deleteRoleAction` | `users:write` |
| `ee/high-availability/ui/certificate-storage-actions.ts` | `saveCertificateStorageAction` | `high_availability:write` |
| `ee/high-availability/ui/certificate-storage-actions.ts` | `removeCertificateStorageAction` | `high_availability:write` |
| `ee/high-availability/ui/certificate-storage-actions.ts` | `testCertificateStorageAction` | `high_availability:write` |
| `ee/high-availability/ui/shared-state-actions.ts` | `saveSharedStateAction` | `high_availability:write` |
| `ee/high-availability/ui/shared-state-actions.ts` | `removeSharedStateAction` | `high_availability:write` |
| `ee/high-availability/ui/shared-state-actions.ts` | `sharedStateStatusAction` | `high_availability:read` |
| `ee/sso/ui/actions.ts` | `saveSsoEnforcementAction` | `sso:write` |
| `ee/white-label/ui/actions.ts` | `saveBrandingAction` | `branding:write` |
| `ee/white-label/ui/actions.ts` | `uploadBrandingAssetAction` | `branding:write` |
| `ee/white-label/ui/actions.ts` | `deleteBrandingAssetAction` | `branding:write` |
| `ee/white-label/ui/actions.ts` | `resetBrandingAction` | `branding:write` |
<!-- call-sites:end -->
