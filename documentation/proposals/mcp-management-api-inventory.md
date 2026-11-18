# MCP proposal: versioned REST coverage inventory

Companion to the [design RFC](mcp-management.md) and [planned acceptance gates](mcp-management-acceptance.md).

Reviewed source: `4728b9e514c41383d073cb69cf0274f838b422b8` (`develop`,18November2026).

## Scope and method

This is an exhaustive filename/export inventory of `app/api/v1/**/route.ts` at the reviewed revision: **246 route files,395 distinct exported HTTP handlers,55 first-level route groups**.147 files forward exports to enterprise modules. Neither a route file nor an HTTP handler is automatically an MCP tool. The RFC selects nine initial reads; all other rows remain subject to their documented later/human disposition.

The scan reads exported HTTP method names, resolves direct `@/ee/` re-exports where present, and collects literal `requireApiPermission`/`requirePermission` strings and named auth helpers from those files. The permission column is a **file-level hint, not a per-method authorization proof**: it can combine multiple methods, omit indirect/dynamic guards and does not describe all ownership, tag scope, field-level, edition or side-effect checks. An empty hint means manual review required, not an asserted vulnerability. The implementation must read each selected handler and service, verify OpenAPI/query/response contracts and execute authorization tests.

`app/api/auth`, internal service routes, public callbacks, health/metrics outside `/api/v1`, the dashboard, host OS, DNS, Docker and external security products are outside this route count. Their trust and operational boundaries are addressed in the RFC; none becomes a generic MCP endpoint.

## Route-group coverage

| Group | Route files |
| --- | ---: |
| `access-lists` | 11 |
| `access-review-assignments` | 4 |
| `access-review-schedules` | 2 |
| `access-reviews` | 6 |
| `ai` | 6 |
| `alert-channels` | 4 |
| `alert-events` | 2 |
| `alert-rules` | 2 |
| `alert-silences` | 2 |
| `analytics` | 18 |
| `approval-policies` | 2 |
| `audit-log` | 6 |
| `audit-sinks` | 3 |
| `backup-destinations` | 6 |
| `backup-runs` | 1 |
| `branding` | 2 |
| `ca-certificates` | 2 |
| `caddy` | 1 |
| `certificates` | 4 |
| `change-requests` | 8 |
| `client-certificates` | 3 |
| `cluster` | 1 |
| `compliance` | 15 |
| `config` | 2 |
| `config-history` | 8 |
| `dns-providers` | 1 |
| `fleet` | 18 |
| `forward-auth-sessions` | 2 |
| `groups` | 5 |
| `high-availability` | 5 |
| `instances` | 6 |
| `l4-proxy-hosts` | 2 |
| `ldap-directories` | 4 |
| `mfa` | 2 |
| `monetization` | 20 |
| `mtls-roles` | 4 |
| `oauth-providers` | 2 |
| `openapi.json` | 1 |
| `overview` | 1 |
| `passkeys` | 2 |
| `permissions` | 1 |
| `preferences` | 1 |
| `proxy-hosts` | 8 |
| `roles` | 2 |
| `saml-providers` | 3 |
| `scim` | 9 |
| `search` | 1 |
| `sessions` | 2 |
| `settings` | 1 |
| `setup-checklist` | 1 |
| `sign-in` | 1 |
| `sso` | 1 |
| `tokens` | 2 |
| `users` | 6 |
| `waf` | 11 |

## Full reviewed inventory

All paths below are existing REST paths, not newly implemented MCP routes. Bracket segments are Next.js path parameters. “EE” links identify direct forwarded implementations under the enterprise license; absence of that marker does not prove a handler is independent of enterprise feature code. Only source is inspected here; no application credentials or instance data were collected for this inventory.

| Existing REST path | HTTP exports | Auth/permission hints (file union) | Source / direct EE target |
| --- | --- | --- | --- |
| `/api/v1/access-lists/[id]/entries/[entryId]` | DELETE | `access_lists:write` | [route](../../app/api/v1/access-lists/[id]/entries/[entryId]/route.ts) |
| `/api/v1/access-lists/[id]/entries` | POST | `access_lists:write` | [route](../../app/api/v1/access-lists/[id]/entries/route.ts) |
| `/api/v1/access-lists/[id]` | DELETE, GET, PUT | `access_lists:read`, `access_lists:write` | [route](../../app/api/v1/access-lists/[id]/route.ts) |
| `/api/v1/access-lists/[id]/rules/[ruleId]` | DELETE, GET, PUT | `access_lists:read`, `access_lists:write` | [route](../../app/api/v1/access-lists/[id]/rules/[ruleId]/route.ts) |
| `/api/v1/access-lists/[id]/rules/reorder` | POST | `access_lists:write` | [route](../../app/api/v1/access-lists/[id]/rules/reorder/route.ts) |
| `/api/v1/access-lists/[id]/rules` | GET, POST, PUT | `access_lists:read`, `access_lists:write` | [route](../../app/api/v1/access-lists/[id]/rules/route.ts) |
| `/api/v1/access-lists/blocked-sources/entries/[entryId]` | DELETE | `access_lists:write` | [route](../../app/api/v1/access-lists/blocked-sources/entries/[entryId]/route.ts) |
| `/api/v1/access-lists/blocked-sources/entries` | GET, POST | `access_lists:read`, `access_lists:write` | [route](../../app/api/v1/access-lists/blocked-sources/entries/route.ts) |
| `/api/v1/access-lists/blocked-sources` | GET, PUT | `access_lists:read`, `access_lists:write` | [route](../../app/api/v1/access-lists/blocked-sources/route.ts) |
| `/api/v1/access-lists` | GET, POST | `access_lists:read`, `access_lists:write` | [route](../../app/api/v1/access-lists/route.ts) |
| `/api/v1/access-lists/stats` | GET | `access_lists:read` | [route](../../app/api/v1/access-lists/stats/route.ts) |
| `/api/v1/access-review-assignments/[id]` | PUT | `requireApiUser` | [route](../../app/api/v1/access-review-assignments/[id]/route.ts); [EE](../../ee/access-reviews/routes/v1/access-review-assignments/[id].ts) |
| `/api/v1/access-review-assignments/confirm` | POST | `requireApiUser` | [route](../../app/api/v1/access-review-assignments/confirm/route.ts); [EE](../../ee/access-reviews/routes/v1/access-review-assignments/confirm.ts) |
| `/api/v1/access-review-assignments/evidence` | GET | `requireApiUser` | [route](../../app/api/v1/access-review-assignments/evidence/route.ts); [EE](../../ee/access-reviews/routes/v1/access-review-assignments/evidence.ts) |
| `/api/v1/access-review-assignments` | GET | `requireApiUser` | [route](../../app/api/v1/access-review-assignments/route.ts); [EE](../../ee/access-reviews/routes/v1/access-review-assignments.ts) |
| `/api/v1/access-review-schedules/[id]` | DELETE, GET, PUT | `access_reviews:read`, `access_reviews:write` | [route](../../app/api/v1/access-review-schedules/[id]/route.ts); [EE](../../ee/access-reviews/routes/v1/access-review-schedules/[id].ts) |
| `/api/v1/access-review-schedules` | GET, POST | `access_reviews:read`, `access_reviews:write` | [route](../../app/api/v1/access-review-schedules/route.ts); [EE](../../ee/access-reviews/routes/v1/access-review-schedules.ts) |
| `/api/v1/access-reviews/[id]/cancel` | POST | `access_reviews:write` | [route](../../app/api/v1/access-reviews/[id]/cancel/route.ts); [EE](../../ee/access-reviews/routes/v1/access-reviews/[id]/cancel.ts) |
| `/api/v1/access-reviews/[id]/complete` | POST | `access_reviews:write` | [route](../../app/api/v1/access-reviews/[id]/complete/route.ts); [EE](../../ee/access-reviews/routes/v1/access-reviews/[id]/complete.ts) |
| `/api/v1/access-reviews/[id]/evidence` | GET | `access_reviews:read` | [route](../../app/api/v1/access-reviews/[id]/evidence/route.ts); [EE](../../ee/access-reviews/routes/v1/access-reviews/[id]/evidence.ts) |
| `/api/v1/access-reviews/[id]/record` | GET | `access_reviews:read` | [route](../../app/api/v1/access-reviews/[id]/record/route.ts); [EE](../../ee/access-reviews/routes/v1/access-reviews/[id]/record.ts) |
| `/api/v1/access-reviews/[id]` | DELETE, GET | `access_reviews:read`, `access_reviews:write` | [route](../../app/api/v1/access-reviews/[id]/route.ts); [EE](../../ee/access-reviews/routes/v1/access-reviews/[id].ts) |
| `/api/v1/access-reviews` | GET, POST | `access_reviews:read`, `access_reviews:write` | [route](../../app/api/v1/access-reviews/route.ts); [EE](../../ee/access-reviews/routes/v1/access-reviews.ts) |
| `/api/v1/ai/digest/preview` | POST | `ai:write` | [route](../../app/api/v1/ai/digest/preview/route.ts); [EE](../../ee/ai/routes/v1/ai/digest/preview.ts) |
| `/api/v1/ai/digest` | GET, PUT | `ai:read`, `ai:write` | [route](../../app/api/v1/ai/digest/route.ts); [EE](../../ee/ai/routes/v1/ai/digest.ts) |
| `/api/v1/ai/digest/send` | POST | `ai:write` | [route](../../app/api/v1/ai/digest/send/route.ts); [EE](../../ee/ai/routes/v1/ai/digest/send.ts) |
| `/api/v1/ai/question-settings` | GET, PUT | `ai:read`, `ai:write` | [route](../../app/api/v1/ai/question-settings/route.ts); [EE](../../ee/ai/routes/v1/ai/question-settings.ts) |
| `/api/v1/ai/settings` | DELETE, GET, PUT | `ai:read`, `ai:write` | [route](../../app/api/v1/ai/settings/route.ts); [EE](../../ee/ai/routes/v1/ai/settings.ts) |
| `/api/v1/ai/test` | POST | `ai:write` | [route](../../app/api/v1/ai/test/route.ts); [EE](../../ee/ai/routes/v1/ai/test.ts) |
| `/api/v1/alert-channels/[id]` | DELETE, GET, PUT | `alerts:read`, `alerts:write` | [route](../../app/api/v1/alert-channels/[id]/route.ts); [EE](../../ee/alerting/routes/v1/alert-channels/[id].ts) |
| `/api/v1/alert-channels/[id]/test` | POST | `alerts:write` | [route](../../app/api/v1/alert-channels/[id]/test/route.ts); [EE](../../ee/alerting/routes/v1/alert-channels/[id]/test.ts) |
| `/api/v1/alert-channels` | GET, POST | `alerts:read`, `alerts:write` | [route](../../app/api/v1/alert-channels/route.ts); [EE](../../ee/alerting/routes/v1/alert-channels.ts) |
| `/api/v1/alert-channels/test` | POST | `alerts:write` | [route](../../app/api/v1/alert-channels/test/route.ts); [EE](../../ee/alerting/routes/v1/alert-channels/test.ts) |
| `/api/v1/alert-events/firing` | GET | `alerts:read` | [route](../../app/api/v1/alert-events/firing/route.ts); [EE](../../ee/alerting/routes/v1/alert-events/firing.ts) |
| `/api/v1/alert-events` | GET | `alerts:read` | [route](../../app/api/v1/alert-events/route.ts); [EE](../../ee/alerting/routes/v1/alert-events.ts) |
| `/api/v1/alert-rules/[id]` | DELETE, GET, PUT | `alerts:read`, `alerts:write` | [route](../../app/api/v1/alert-rules/[id]/route.ts); [EE](../../ee/alerting/routes/v1/alert-rules/[id].ts) |
| `/api/v1/alert-rules` | GET, POST | `alerts:read`, `alerts:write` | [route](../../app/api/v1/alert-rules/route.ts); [EE](../../ee/alerting/routes/v1/alert-rules.ts) |
| `/api/v1/alert-silences/[id]` | DELETE | `alerts:write` | [route](../../app/api/v1/alert-silences/[id]/route.ts); [EE](../../ee/alerting/routes/v1/alert-silences/[id].ts) |
| `/api/v1/alert-silences` | GET, POST | `alerts:read`, `alerts:write` | [route](../../app/api/v1/alert-silences/route.ts); [EE](../../ee/alerting/routes/v1/alert-silences.ts) |
| `/api/v1/analytics/hosts/[id]` | GET | `analytics:read` | [route](../../app/api/v1/analytics/hosts/[id]/route.ts) |
| `/api/v1/analytics/hosts` | GET | `analytics:read` | [route](../../app/api/v1/analytics/hosts/route.ts) |
| `/api/v1/analytics/query` | GET | `analytics:read` | [route](../../app/api/v1/analytics/query/route.ts) |
| `/api/v1/analytics/questions` | POST | `analytics:read` | [route](../../app/api/v1/analytics/questions/route.ts); [EE](../../ee/ai/routes/v1/analytics/questions.ts) |
| `/api/v1/analytics/questions/saved/[id]` | DELETE, GET, PATCH | `analytics:read` | [route](../../app/api/v1/analytics/questions/saved/[id]/route.ts); [EE](../../ee/ai/routes/v1/analytics/questions/saved/[id].ts) |
| `/api/v1/analytics/questions/saved/[id]/run` | POST | `analytics:read` | [route](../../app/api/v1/analytics/questions/saved/[id]/run/route.ts); [EE](../../ee/ai/routes/v1/analytics/questions/saved/[id]/run.ts) |
| `/api/v1/analytics/questions/saved` | GET, POST | `analytics:read` | [route](../../app/api/v1/analytics/questions/saved/route.ts); [EE](../../ee/ai/routes/v1/analytics/questions/saved.ts) |
| `/api/v1/analytics/requests` | GET | `analytics:read` | [route](../../app/api/v1/analytics/requests/route.ts) |
| `/api/v1/analytics/security/events` | GET | `analytics:read` | [route](../../app/api/v1/analytics/security/events/route.ts) |
| `/api/v1/analytics/security/hosts` | GET | `analytics:read` | [route](../../app/api/v1/analytics/security/hosts/route.ts) |
| `/api/v1/analytics/security/rules` | GET | `analytics:read` | [route](../../app/api/v1/analytics/security/rules/route.ts) |
| `/api/v1/analytics/security/series` | GET | `analytics:read` | [route](../../app/api/v1/analytics/security/series/route.ts) |
| `/api/v1/analytics/security/sources` | GET | `analytics:read` | [route](../../app/api/v1/analytics/security/sources/route.ts) |
| `/api/v1/analytics/signals` | GET | `analytics:read` | [route](../../app/api/v1/analytics/signals/route.ts) |
| `/api/v1/analytics/top` | GET | `analytics:read` | [route](../../app/api/v1/analytics/top/route.ts) |
| `/api/v1/analytics/values` | GET | `analytics:read` | [route](../../app/api/v1/analytics/values/route.ts) |
| `/api/v1/analytics/views/[id]` | DELETE, GET, PATCH | `analytics:read` | [route](../../app/api/v1/analytics/views/[id]/route.ts) |
| `/api/v1/analytics/views` | GET, POST | `analytics:read` | [route](../../app/api/v1/analytics/views/route.ts) |
| `/api/v1/approval-policies/[id]` | DELETE, GET, PUT | `approvals:manage`, `approvals:read` | [route](../../app/api/v1/approval-policies/[id]/route.ts); [EE](../../ee/approvals/routes/v1/approval-policies/[id].ts) |
| `/api/v1/approval-policies` | GET, POST | `approvals:manage`, `approvals:read` | [route](../../app/api/v1/approval-policies/route.ts); [EE](../../ee/approvals/routes/v1/approval-policies.ts) |
| `/api/v1/audit-log/[id]` | GET | `audit_log:read` | [route](../../app/api/v1/audit-log/[id]/route.ts) |
| `/api/v1/audit-log/export` | GET | `audit_log:read` | [route](../../app/api/v1/audit-log/export/route.ts); [EE](../../ee/audit/routes/v1/audit-log/export.ts) |
| `/api/v1/audit-log/facets` | GET | `audit_log:read` | [route](../../app/api/v1/audit-log/facets/route.ts) |
| `/api/v1/audit-log/retention` | GET, PUT | `audit_streaming:read`, `audit_streaming:write` | [route](../../app/api/v1/audit-log/retention/route.ts); [EE](../../ee/audit/routes/v1/audit-log/retention.ts) |
| `/api/v1/audit-log` | GET | `audit_log:read` | [route](../../app/api/v1/audit-log/route.ts) |
| `/api/v1/audit-log/verify` | GET | `audit_log:read` | [route](../../app/api/v1/audit-log/verify/route.ts); [EE](../../ee/audit/routes/v1/audit-log/verify.ts) |
| `/api/v1/audit-sinks/[id]` | DELETE, GET, PUT | `audit_streaming:read`, `audit_streaming:write` | [route](../../app/api/v1/audit-sinks/[id]/route.ts); [EE](../../ee/audit/routes/v1/audit-sinks/[id].ts) |
| `/api/v1/audit-sinks/[id]/test` | POST | `audit_streaming:write` | [route](../../app/api/v1/audit-sinks/[id]/test/route.ts); [EE](../../ee/audit/routes/v1/audit-sinks/[id]/test.ts) |
| `/api/v1/audit-sinks` | GET, POST | `audit_streaming:read`, `audit_streaming:write` | [route](../../app/api/v1/audit-sinks/route.ts); [EE](../../ee/audit/routes/v1/audit-sinks.ts) |
| `/api/v1/backup-destinations/[id]/objects` | GET | `backups:read` | [route](../../app/api/v1/backup-destinations/[id]/objects/route.ts); [EE](../../ee/backups/routes/v1/backup-destinations/[id]/objects.ts) |
| `/api/v1/backup-destinations/[id]/restore` | POST | `backups:restore` | [route](../../app/api/v1/backup-destinations/[id]/restore/route.ts); [EE](../../ee/backups/routes/v1/backup-destinations/[id]/restore.ts) |
| `/api/v1/backup-destinations/[id]` | DELETE, GET, PUT | `backups:read`, `backups:write` | [route](../../app/api/v1/backup-destinations/[id]/route.ts); [EE](../../ee/backups/routes/v1/backup-destinations/[id].ts) |
| `/api/v1/backup-destinations/[id]/run` | POST | `backups:write` | [route](../../app/api/v1/backup-destinations/[id]/run/route.ts); [EE](../../ee/backups/routes/v1/backup-destinations/[id]/run.ts) |
| `/api/v1/backup-destinations/[id]/test` | POST | `backups:write` | [route](../../app/api/v1/backup-destinations/[id]/test/route.ts); [EE](../../ee/backups/routes/v1/backup-destinations/[id]/test.ts) |
| `/api/v1/backup-destinations` | GET, POST | `backups:read`, `backups:write` | [route](../../app/api/v1/backup-destinations/route.ts); [EE](../../ee/backups/routes/v1/backup-destinations.ts) |
| `/api/v1/backup-runs` | GET | `backups:read` | [route](../../app/api/v1/backup-runs/route.ts); [EE](../../ee/backups/routes/v1/backup-runs.ts) |
| `/api/v1/branding/assets/[asset]` | DELETE, PUT | `branding:write` | [route](../../app/api/v1/branding/assets/[asset]/route.ts); [EE](../../ee/white-label/routes/v1/branding/assets/[asset].ts) |
| `/api/v1/branding` | DELETE, GET, PUT | `branding:read`, `branding:write` | [route](../../app/api/v1/branding/route.ts); [EE](../../ee/white-label/routes/v1/branding.ts) |
| `/api/v1/ca-certificates/[id]` | DELETE, GET, PUT | `certificates:read`, `certificates:write` | [route](../../app/api/v1/ca-certificates/[id]/route.ts) |
| `/api/v1/ca-certificates` | GET, POST | `certificates:read`, `certificates:write` | [route](../../app/api/v1/ca-certificates/route.ts) |
| `/api/v1/caddy/apply` | POST | `settings:write` | [route](../../app/api/v1/caddy/apply/route.ts) |
| `/api/v1/certificates/[id]` | DELETE, GET, PUT | `certificates:read`, `certificates:write` | [route](../../app/api/v1/certificates/[id]/route.ts) |
| `/api/v1/certificates/managed` | GET | `certificates:read` | [route](../../app/api/v1/certificates/managed/route.ts) |
| `/api/v1/certificates/overview` | GET | `certificates:read` | [route](../../app/api/v1/certificates/overview/route.ts) |
| `/api/v1/certificates` | GET, POST | `certificates:read`, `certificates:write` | [route](../../app/api/v1/certificates/route.ts) |
| `/api/v1/change-requests/[id]/apply` | POST | `approvals:approve` | [route](../../app/api/v1/change-requests/[id]/apply/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id]/apply.ts) |
| `/api/v1/change-requests/[id]/approve` | POST | `approvals:approve` | [route](../../app/api/v1/change-requests/[id]/approve/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id]/approve.ts) |
| `/api/v1/change-requests/[id]/cancel` | POST | `approvals:read` | [route](../../app/api/v1/change-requests/[id]/cancel/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id]/cancel.ts) |
| `/api/v1/change-requests/[id]/comments` | POST | `approvals:read` | [route](../../app/api/v1/change-requests/[id]/comments/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id]/comments.ts) |
| `/api/v1/change-requests/[id]/emergency` | POST | `approvals:emergency` | [route](../../app/api/v1/change-requests/[id]/emergency/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id]/emergency.ts) |
| `/api/v1/change-requests/[id]/reject` | POST | `approvals:approve` | [route](../../app/api/v1/change-requests/[id]/reject/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id]/reject.ts) |
| `/api/v1/change-requests/[id]` | GET | `approvals:read` | [route](../../app/api/v1/change-requests/[id]/route.ts); [EE](../../ee/approvals/routes/v1/change-requests/[id].ts) |
| `/api/v1/change-requests` | GET | `approvals:read` | [route](../../app/api/v1/change-requests/route.ts); [EE](../../ee/approvals/routes/v1/change-requests.ts) |
| `/api/v1/client-certificates/[id]/roles` | GET | `certificates:read` | [route](../../app/api/v1/client-certificates/[id]/roles/route.ts) |
| `/api/v1/client-certificates/[id]` | DELETE, GET | `certificates:read`, `certificates:write` | [route](../../app/api/v1/client-certificates/[id]/route.ts) |
| `/api/v1/client-certificates` | GET, POST | `certificates:read`, `certificates:write` | [route](../../app/api/v1/client-certificates/route.ts) |
| `/api/v1/cluster/nodes` | GET | `high_availability:read` | [route](../../app/api/v1/cluster/nodes/route.ts); [EE](../../ee/high-availability/routes/v1/cluster/nodes.ts) |
| `/api/v1/compliance/controls` | GET | `compliance:read` | [route](../../app/api/v1/compliance/controls/route.ts); [EE](../../ee/compliance/routes/v1/compliance/controls.ts) |
| `/api/v1/compliance/controls/status` | GET | `compliance:read` | [route](../../app/api/v1/compliance/controls/status/route.ts); [EE](../../ee/compliance/routes/v1/compliance/controls/status.ts) |
| `/api/v1/compliance/incidents/[id]/draft` | POST | `compliance:write` | [route](../../app/api/v1/compliance/incidents/[id]/draft/route.ts); [EE](../../ee/compliance/routes/v1/compliance/incidents/[id]/draft.ts) |
| `/api/v1/compliance/incidents/[id]/facts` | POST | `compliance:write` | [route](../../app/api/v1/compliance/incidents/[id]/facts/route.ts); [EE](../../ee/compliance/routes/v1/compliance/incidents/[id]/facts.ts) |
| `/api/v1/compliance/incidents/[id]` | DELETE, GET, PUT | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/incidents/[id]/route.ts); [EE](../../ee/compliance/routes/v1/compliance/incidents/[id].ts) |
| `/api/v1/compliance/incidents` | GET, POST | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/incidents/route.ts); [EE](../../ee/compliance/routes/v1/compliance/incidents.ts) |
| `/api/v1/compliance/packs` | GET | `compliance:read` | [route](../../app/api/v1/compliance/packs/route.ts); [EE](../../ee/compliance/routes/v1/compliance/packs.ts) |
| `/api/v1/compliance/reports/[id]/export` | GET | `compliance:read` | [route](../../app/api/v1/compliance/reports/[id]/export/route.ts); [EE](../../ee/compliance/routes/v1/compliance/reports/[id]/export.ts) |
| `/api/v1/compliance/reports/[id]` | DELETE, GET | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/reports/[id]/route.ts); [EE](../../ee/compliance/routes/v1/compliance/reports/[id].ts) |
| `/api/v1/compliance/reports` | GET, POST | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/reports/route.ts); [EE](../../ee/compliance/routes/v1/compliance/reports.ts) |
| `/api/v1/compliance/restore-tests/[id]` | DELETE | `compliance:write` | [route](../../app/api/v1/compliance/restore-tests/[id]/route.ts); [EE](../../ee/compliance/routes/v1/compliance/restore-tests/[id].ts) |
| `/api/v1/compliance/restore-tests` | GET, POST | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/restore-tests/route.ts); [EE](../../ee/compliance/routes/v1/compliance/restore-tests.ts) |
| `/api/v1/compliance/schedules/[id]` | DELETE, GET, PUT | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/schedules/[id]/route.ts); [EE](../../ee/compliance/routes/v1/compliance/schedules/[id].ts) |
| `/api/v1/compliance/schedules/[id]/run` | POST | `compliance:write` | [route](../../app/api/v1/compliance/schedules/[id]/run/route.ts); [EE](../../ee/compliance/routes/v1/compliance/schedules/[id]/run.ts) |
| `/api/v1/compliance/schedules` | GET, POST | `compliance:read`, `compliance:write` | [route](../../app/api/v1/compliance/schedules/route.ts); [EE](../../ee/compliance/routes/v1/compliance/schedules.ts) |
| `/api/v1/config/export` | POST | `config:export` | [route](../../app/api/v1/config/export/route.ts) |
| `/api/v1/config/import` | POST | `config:import` | [route](../../app/api/v1/config/import/route.ts) |
| `/api/v1/config-history/[id]/diff` | GET | `config_history:read` | [route](../../app/api/v1/config-history/[id]/diff/route.ts); [EE](../../ee/config-history/routes/v1/config-history/[id]/diff.ts) |
| `/api/v1/config-history/[id]/restore` | POST | `config_history:restore` | [route](../../app/api/v1/config-history/[id]/restore/route.ts); [EE](../../ee/config-history/routes/v1/config-history/[id]/restore.ts) |
| `/api/v1/config-history/[id]/rollback-preview` | GET | `config_history:read` | [route](../../app/api/v1/config-history/[id]/rollback-preview/route.ts); [EE](../../ee/config-history/routes/v1/config-history/[id]/rollback-preview.ts) |
| `/api/v1/config-history/[id]` | DELETE, GET | `config_history:read`, `config_history:write` | [route](../../app/api/v1/config-history/[id]/route.ts); [EE](../../ee/config-history/routes/v1/config-history/[id].ts) |
| `/api/v1/config-history/compare` | GET | `config_history:read` | [route](../../app/api/v1/config-history/compare/route.ts); [EE](../../ee/config-history/routes/v1/config-history/compare.ts) |
| `/api/v1/config-history` | DELETE, GET, POST | `config_history:read`, `config_history:write` | [route](../../app/api/v1/config-history/route.ts); [EE](../../ee/config-history/routes/v1/config-history.ts) |
| `/api/v1/config-history/settings` | GET, PUT | `config_history:read`, `config_history:write` | [route](../../app/api/v1/config-history/settings/route.ts); [EE](../../ee/config-history/routes/v1/config-history/settings.ts) |
| `/api/v1/config-history/versions` | GET | `config_history:read` | [route](../../app/api/v1/config-history/versions/route.ts); [EE](../../ee/config-history/routes/v1/config-history/versions.ts) |
| `/api/v1/dns-providers` | GET | `requireApiUser` | [route](../../app/api/v1/dns-providers/route.ts) |
| `/api/v1/fleet/drift` | GET, POST | `fleet:read`, `fleet:write` | [route](../../app/api/v1/fleet/drift/route.ts); [EE](../../ee/fleet/routes/v1/fleet/drift.ts) |
| `/api/v1/fleet/environments/[id]` | DELETE, GET, PATCH | `fleet:read`, `fleet:write` | [route](../../app/api/v1/fleet/environments/[id]/route.ts); [EE](../../ee/fleet/routes/v1/fleet/environments/[id].ts) |
| `/api/v1/fleet/environments` | GET, POST | `fleet:read`, `fleet:write` | [route](../../app/api/v1/fleet/environments/route.ts); [EE](../../ee/fleet/routes/v1/fleet/environments.ts) |
| `/api/v1/fleet/instances/[id]/environment` | PUT | `fleet:write` | [route](../../app/api/v1/fleet/instances/[id]/environment/route.ts); [EE](../../ee/fleet/routes/v1/fleet/instances/[id]/environment.ts) |
| `/api/v1/fleet/instances/[id]/resync` | POST | `fleet:promote` | [route](../../app/api/v1/fleet/instances/[id]/resync/route.ts); [EE](../../ee/fleet/routes/v1/fleet/instances/[id]/resync.ts) |
| `/api/v1/fleet/instances` | GET | `fleet:read` | [route](../../app/api/v1/fleet/instances/route.ts); [EE](../../ee/fleet/routes/v1/fleet/instances.ts) |
| `/api/v1/fleet/promotions/preview` | GET | `fleet:read` | [route](../../app/api/v1/fleet/promotions/preview/route.ts); [EE](../../ee/fleet/routes/v1/fleet/promotions/preview.ts) |
| `/api/v1/fleet/pull-replicas/[id]/credential` | DELETE, POST | `fleet:replicas` | [route](../../app/api/v1/fleet/pull-replicas/[id]/credential/route.ts); [EE](../../ee/fleet/routes/v1/fleet/pull-replicas/[id]/credential.ts) |
| `/api/v1/fleet/pull-replicas/[id]` | DELETE, GET | `fleet:read`, `fleet:replicas` | [route](../../app/api/v1/fleet/pull-replicas/[id]/route.ts); [EE](../../ee/fleet/routes/v1/fleet/pull-replicas/[id].ts) |
| `/api/v1/fleet/pull-replicas` | GET, POST | `fleet:read`, `fleet:replicas` | [route](../../app/api/v1/fleet/pull-replicas/route.ts); [EE](../../ee/fleet/routes/v1/fleet/pull-replicas.ts) |
| `/api/v1/fleet/revisions/[id]/diff` | GET | `fleet:read` | [route](../../app/api/v1/fleet/revisions/[id]/diff/route.ts); [EE](../../ee/fleet/routes/v1/fleet/revisions/[id]/diff.ts) |
| `/api/v1/fleet/revisions/[id]` | GET | `fleet:read` | [route](../../app/api/v1/fleet/revisions/[id]/route.ts); [EE](../../ee/fleet/routes/v1/fleet/revisions/[id].ts) |
| `/api/v1/fleet/revisions` | GET | `fleet:read` | [route](../../app/api/v1/fleet/revisions/route.ts); [EE](../../ee/fleet/routes/v1/fleet/revisions.ts) |
| `/api/v1/fleet/rollouts/[id]/abort` | POST | `fleet:promote` | [route](../../app/api/v1/fleet/rollouts/[id]/abort/route.ts); [EE](../../ee/fleet/routes/v1/fleet/rollouts/[id]/abort.ts) |
| `/api/v1/fleet/rollouts/[id]/rollback` | POST | `fleet:promote` | [route](../../app/api/v1/fleet/rollouts/[id]/rollback/route.ts); [EE](../../ee/fleet/routes/v1/fleet/rollouts/[id]/rollback.ts) |
| `/api/v1/fleet/rollouts/[id]` | GET | `fleet:read` | [route](../../app/api/v1/fleet/rollouts/[id]/route.ts); [EE](../../ee/fleet/routes/v1/fleet/rollouts/[id].ts) |
| `/api/v1/fleet/rollouts` | GET, POST | `fleet:promote`, `fleet:read` | [route](../../app/api/v1/fleet/rollouts/route.ts); [EE](../../ee/fleet/routes/v1/fleet/rollouts.ts) |
| `/api/v1/fleet` | GET | `fleet:read` | [route](../../app/api/v1/fleet/route.ts); [EE](../../ee/fleet/routes/v1/fleet.ts) |
| `/api/v1/forward-auth-sessions/[id]` | DELETE | `users:write` | [route](../../app/api/v1/forward-auth-sessions/[id]/route.ts) |
| `/api/v1/forward-auth-sessions` | DELETE, GET | `users:read`, `users:write` | [route](../../app/api/v1/forward-auth-sessions/route.ts) |
| `/api/v1/groups/[id]/members/[userId]` | DELETE | `groups:write` | [route](../../app/api/v1/groups/[id]/members/[userId]/route.ts) |
| `/api/v1/groups/[id]/members` | POST | `groups:write` | [route](../../app/api/v1/groups/[id]/members/route.ts) |
| `/api/v1/groups/[id]` | DELETE, GET, PATCH | `groups:read`, `groups:write` | [route](../../app/api/v1/groups/[id]/route.ts) |
| `/api/v1/groups/overview` | GET | `groups:read` | [route](../../app/api/v1/groups/overview/route.ts) |
| `/api/v1/groups` | GET, POST | `groups:read`, `groups:write` | [route](../../app/api/v1/groups/route.ts) |
| `/api/v1/high-availability/cluster` | GET | `high_availability:read` | [route](../../app/api/v1/high-availability/cluster/route.ts); [EE](../../ee/high-availability/routes/v1/high-availability/cluster.ts) |
| `/api/v1/high-availability/shared-state` | DELETE, GET, PUT | `high_availability:read`, `high_availability:write` | [route](../../app/api/v1/high-availability/shared-state/route.ts); [EE](../../ee/high-availability/routes/v1/high-availability/shared-state.ts) |
| `/api/v1/high-availability/shared-state/status` | GET | `high_availability:read` | [route](../../app/api/v1/high-availability/shared-state/status/route.ts); [EE](../../ee/high-availability/routes/v1/high-availability/shared-state/status.ts) |
| `/api/v1/high-availability/storage` | DELETE, GET, PUT | `high_availability:read`, `high_availability:write` | [route](../../app/api/v1/high-availability/storage/route.ts); [EE](../../ee/high-availability/routes/v1/high-availability/storage.ts) |
| `/api/v1/high-availability/storage/test` | POST | `high_availability:write` | [route](../../app/api/v1/high-availability/storage/test/route.ts); [EE](../../ee/high-availability/routes/v1/high-availability/storage/test.ts) |
| `/api/v1/instances/[id]` | DELETE, PUT | `instances:write` | [route](../../app/api/v1/instances/[id]/route.ts) |
| `/api/v1/instances/[id]/sync-key-pin` | DELETE, PUT | `instances:write` | [route](../../app/api/v1/instances/[id]/sync-key-pin/route.ts) |
| `/api/v1/instances` | GET, POST | `instances:read`, `instances:write` | [route](../../app/api/v1/instances/route.ts) |
| `/api/v1/instances/sync` | POST | `instances:write` | [route](../../app/api/v1/instances/sync/route.ts) |
| `/api/v1/instances/sync-key` | GET | `instances:read` | [route](../../app/api/v1/instances/sync-key/route.ts) |
| `/api/v1/instances/sync-key-pins` | DELETE, GET, PUT | `instances:read`, `instances:write` | [route](../../app/api/v1/instances/sync-key-pins/route.ts) |
| `/api/v1/l4-proxy-hosts/[id]` | DELETE, GET, PUT | Manual review required | [route](../../app/api/v1/l4-proxy-hosts/[id]/route.ts) |
| `/api/v1/l4-proxy-hosts` | GET, POST | Manual review required | [route](../../app/api/v1/l4-proxy-hosts/route.ts) |
| `/api/v1/ldap-directories/[id]` | DELETE, GET, PUT | `ldap:read`, `ldap:write` | [route](../../app/api/v1/ldap-directories/[id]/route.ts); [EE](../../ee/ldap/routes/v1/ldap-directories/[id].ts) |
| `/api/v1/ldap-directories/[id]/test` | POST | `ldap:write` | [route](../../app/api/v1/ldap-directories/[id]/test/route.ts); [EE](../../ee/ldap/routes/v1/ldap-directories/[id]/test.ts) |
| `/api/v1/ldap-directories/[id]/test-sign-in` | POST | `ldap:write` | [route](../../app/api/v1/ldap-directories/[id]/test-sign-in/route.ts); [EE](../../ee/ldap/routes/v1/ldap-directories/[id]/test-sign-in.ts) |
| `/api/v1/ldap-directories` | GET, POST | `ldap:read`, `ldap:write` | [route](../../app/api/v1/ldap-directories/route.ts); [EE](../../ee/ldap/routes/v1/ldap-directories.ts) |
| `/api/v1/mfa/policy` | GET, PUT | `mfa_policy:read`, `mfa_policy:write` | [route](../../app/api/v1/mfa/policy/route.ts) |
| `/api/v1/mfa` | GET | `requireApiUser` | [route](../../app/api/v1/mfa/route.ts) |
| `/api/v1/monetization/consumers/[id]/adjust` | POST | `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/adjust/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/adjust.ts) |
| `/api/v1/monetization/consumers/[id]/billing/card` | DELETE | `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/billing/card/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/billing/card.ts) |
| `/api/v1/monetization/consumers/[id]/billing/charge` | POST | `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/billing/charge/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/billing/charge.ts) |
| `/api/v1/monetization/consumers/[id]/billing/resume` | POST | `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/billing/resume/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/billing/resume.ts) |
| `/api/v1/monetization/consumers/[id]/keys/[keyId]` | DELETE | `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/keys/[keyId]/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/keys/[keyId].ts) |
| `/api/v1/monetization/consumers/[id]/keys` | GET, POST | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/keys/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/keys.ts) |
| `/api/v1/monetization/consumers/[id]/portal-link` | DELETE, POST | `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/portal-link/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id]/portal-link.ts) |
| `/api/v1/monetization/consumers/[id]` | DELETE, GET, PUT | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/consumers/[id]/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers/[id].ts) |
| `/api/v1/monetization/consumers` | GET, POST | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/consumers/route.ts); [EE](../../ee/monetization/routes/v1/monetization/consumers.ts) |
| `/api/v1/monetization/hosts/[id]` | DELETE, GET, PUT | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/hosts/[id]/route.ts); [EE](../../ee/monetization/routes/v1/monetization/hosts/[id].ts) |
| `/api/v1/monetization/hosts` | GET | `monetization:read` | [route](../../app/api/v1/monetization/hosts/route.ts); [EE](../../ee/monetization/routes/v1/monetization/hosts.ts) |
| `/api/v1/monetization/ledger` | GET | `monetization:read` | [route](../../app/api/v1/monetization/ledger/route.ts); [EE](../../ee/monetization/routes/v1/monetization/ledger.ts) |
| `/api/v1/monetization/overview` | GET | `monetization:read` | [route](../../app/api/v1/monetization/overview/route.ts); [EE](../../ee/monetization/routes/v1/monetization/overview.ts) |
| `/api/v1/monetization/payments` | GET | `monetization:read` | [route](../../app/api/v1/monetization/payments/route.ts); [EE](../../ee/monetization/routes/v1/monetization/payments.ts) |
| `/api/v1/monetization/plans/[id]` | DELETE, GET, PUT | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/plans/[id]/route.ts); [EE](../../ee/monetization/routes/v1/monetization/plans/[id].ts) |
| `/api/v1/monetization/plans` | GET, POST | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/plans/route.ts); [EE](../../ee/monetization/routes/v1/monetization/plans.ts) |
| `/api/v1/monetization/settings` | GET, PUT | `monetization:read`, `monetization:write` | [route](../../app/api/v1/monetization/settings/route.ts); [EE](../../ee/monetization/routes/v1/monetization/settings.ts) |
| `/api/v1/monetization/stripe` | DELETE, GET, PUT | `monetization:payments`, `monetization:read` | [route](../../app/api/v1/monetization/stripe/route.ts); [EE](../../ee/monetization/routes/v1/monetization/stripe.ts) |
| `/api/v1/monetization/x402/payments` | GET | `monetization:read` | [route](../../app/api/v1/monetization/x402/payments/route.ts); [EE](../../ee/monetization/routes/v1/monetization/x402/payments.ts) |
| `/api/v1/monetization/x402` | DELETE, GET, PUT | `monetization:payments`, `monetization:read` | [route](../../app/api/v1/monetization/x402/route.ts); [EE](../../ee/monetization/routes/v1/monetization/x402.ts) |
| `/api/v1/mtls-roles/[id]/certificates/[certId]` | DELETE | `certificates:write` | [route](../../app/api/v1/mtls-roles/[id]/certificates/[certId]/route.ts) |
| `/api/v1/mtls-roles/[id]/certificates` | POST | `certificates:write` | [route](../../app/api/v1/mtls-roles/[id]/certificates/route.ts) |
| `/api/v1/mtls-roles/[id]` | DELETE, GET, PUT | `certificates:read`, `certificates:write` | [route](../../app/api/v1/mtls-roles/[id]/route.ts) |
| `/api/v1/mtls-roles` | GET, POST | `certificates:read`, `certificates:write` | [route](../../app/api/v1/mtls-roles/route.ts) |
| `/api/v1/oauth-providers/[id]` | DELETE, GET, PUT | `sso:read`, `sso:write` | [route](../../app/api/v1/oauth-providers/[id]/route.ts) |
| `/api/v1/oauth-providers` | GET, POST | `sso:read`, `sso:write` | [route](../../app/api/v1/oauth-providers/route.ts) |
| `/api/v1/openapi.json` | GET | `api_docs:read` | [route](../../app/api/v1/openapi.json/route.ts) |
| `/api/v1/overview/attention` | GET | `requireApiUser` | [route](../../app/api/v1/overview/attention/route.ts) |
| `/api/v1/passkeys/[id]` | DELETE, PATCH | `requireApiUser` | [route](../../app/api/v1/passkeys/[id]/route.ts) |
| `/api/v1/passkeys` | GET | `requireApiUser` | [route](../../app/api/v1/passkeys/route.ts) |
| `/api/v1/permissions` | GET | `users:read` | [route](../../app/api/v1/permissions/route.ts); [EE](../../ee/custom-roles/routes/v1/permissions.ts) |
| `/api/v1/preferences` | GET, PUT | `requireApiUser` | [route](../../app/api/v1/preferences/route.ts) |
| `/api/v1/proxy-hosts/[id]/forward-auth-access` | GET, PUT | `proxy_hosts:read`, `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/[id]/forward-auth-access/route.ts) |
| `/api/v1/proxy-hosts/[id]/health` | GET | `proxy_hosts:read` | [route](../../app/api/v1/proxy-hosts/[id]/health/route.ts) |
| `/api/v1/proxy-hosts/[id]/mtls-access-rules/[ruleId]` | DELETE, GET, PUT | `proxy_hosts:read`, `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/[id]/mtls-access-rules/[ruleId]/route.ts) |
| `/api/v1/proxy-hosts/[id]/mtls-access-rules` | GET, POST | `proxy_hosts:read`, `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/[id]/mtls-access-rules/route.ts) |
| `/api/v1/proxy-hosts/[id]/preview` | POST | `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/[id]/preview/route.ts) |
| `/api/v1/proxy-hosts/[id]` | DELETE, GET, PUT | `proxy_hosts:read`, `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/[id]/route.ts) |
| `/api/v1/proxy-hosts/preview` | POST | `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/preview/route.ts) |
| `/api/v1/proxy-hosts` | GET, POST | `proxy_hosts:read`, `proxy_hosts:write` | [route](../../app/api/v1/proxy-hosts/route.ts) |
| `/api/v1/roles/[id]` | DELETE, GET, PUT | `users:read`, `users:write` | [route](../../app/api/v1/roles/[id]/route.ts); [EE](../../ee/custom-roles/routes/v1/roles/[id].ts) |
| `/api/v1/roles` | GET, POST | `users:read`, `users:write` | [route](../../app/api/v1/roles/route.ts); [EE](../../ee/custom-roles/routes/v1/roles.ts) |
| `/api/v1/saml-providers/[id]/metadata` | GET | `sso:read` | [route](../../app/api/v1/saml-providers/[id]/metadata/route.ts); [EE](../../ee/saml/routes/v1/saml-providers/[id]/metadata.ts) |
| `/api/v1/saml-providers/[id]` | DELETE, GET, PUT | `sso:read`, `sso:write` | [route](../../app/api/v1/saml-providers/[id]/route.ts); [EE](../../ee/saml/routes/v1/saml-providers/[id].ts) |
| `/api/v1/saml-providers` | GET, POST | `sso:read`, `sso:write` | [route](../../app/api/v1/saml-providers/route.ts); [EE](../../ee/saml/routes/v1/saml-providers.ts) |
| `/api/v1/scim/groups/[id]` | DELETE | `scim:write` | [route](../../app/api/v1/scim/groups/[id]/route.ts); [EE](../../ee/scim/routes/v1/scim/groups/[id].ts) |
| `/api/v1/scim/groups` | GET, POST | `scim:read`, `scim:write` | [route](../../app/api/v1/scim/groups/route.ts); [EE](../../ee/scim/routes/v1/scim/groups.ts) |
| `/api/v1/scim/role-mappings/[id]` | DELETE, PUT | `scim:write` | [route](../../app/api/v1/scim/role-mappings/[id]/route.ts); [EE](../../ee/scim/routes/v1/scim/role-mappings/[id].ts) |
| `/api/v1/scim/role-mappings` | GET, POST | `scim:read`, `scim:write` | [route](../../app/api/v1/scim/role-mappings/route.ts); [EE](../../ee/scim/routes/v1/scim/role-mappings.ts) |
| `/api/v1/scim/settings` | GET, PUT | `scim:read`, `scim:write` | [route](../../app/api/v1/scim/settings/route.ts); [EE](../../ee/scim/routes/v1/scim/settings.ts) |
| `/api/v1/scim/tokens/[id]` | DELETE | `scim:write` | [route](../../app/api/v1/scim/tokens/[id]/route.ts); [EE](../../ee/scim/routes/v1/scim/tokens/[id].ts) |
| `/api/v1/scim/tokens` | GET, POST | `scim:read`, `scim:write` | [route](../../app/api/v1/scim/tokens/route.ts); [EE](../../ee/scim/routes/v1/scim/tokens.ts) |
| `/api/v1/scim/users/[id]` | DELETE | `scim:write` | [route](../../app/api/v1/scim/users/[id]/route.ts); [EE](../../ee/scim/routes/v1/scim/users/[id].ts) |
| `/api/v1/scim/users` | GET, POST | `scim:read`, `scim:write` | [route](../../app/api/v1/scim/users/route.ts); [EE](../../ee/scim/routes/v1/scim/users.ts) |
| `/api/v1/search` | GET | `requireApiUser` | [route](../../app/api/v1/search/route.ts) |
| `/api/v1/sessions/[id]` | DELETE | `requireApiUser` | [route](../../app/api/v1/sessions/[id]/route.ts) |
| `/api/v1/sessions` | DELETE, GET | `requireApiUser` | [route](../../app/api/v1/sessions/route.ts) |
| `/api/v1/settings/[group]` | GET, PUT | `instances:read`, `instances:write`, `settings:read`, `settings:write`, `waf:read`, `waf:write` | [route](../../app/api/v1/settings/[group]/route.ts) |
| `/api/v1/setup-checklist` | GET, PUT | `settings:read`, `settings:write` | [route](../../app/api/v1/setup-checklist/route.ts) |
| `/api/v1/sign-in/overview` | GET | `sso:read` | [route](../../app/api/v1/sign-in/overview/route.ts) |
| `/api/v1/sso/enforcement` | GET, PUT | `sso:read`, `sso:write` | [route](../../app/api/v1/sso/enforcement/route.ts); [EE](../../ee/sso/routes/v1/sso/enforcement.ts) |
| `/api/v1/tokens/[id]` | DELETE | `requireApiUser` | [route](../../app/api/v1/tokens/[id]/route.ts) |
| `/api/v1/tokens` | GET, POST | `requireApiUser` | [route](../../app/api/v1/tokens/route.ts) |
| `/api/v1/users/[id]/mfa` | DELETE, GET | `users:write`, `requireApiUser` | [route](../../app/api/v1/users/[id]/mfa/route.ts) |
| `/api/v1/users/[id]` | DELETE, GET, PUT | `users:write`, `requireApiUser` | [route](../../app/api/v1/users/[id]/route.ts) |
| `/api/v1/users/[id]/sessions/[sessionId]` | DELETE | `users:write` | [route](../../app/api/v1/users/[id]/sessions/[sessionId]/route.ts) |
| `/api/v1/users/[id]/sessions` | DELETE, GET | `users:read`, `users:write` | [route](../../app/api/v1/users/[id]/sessions/route.ts) |
| `/api/v1/users/overview` | GET | `users:read` | [route](../../app/api/v1/users/overview/route.ts) |
| `/api/v1/users` | GET, POST | `users:read`, `users:write` | [route](../../app/api/v1/users/route.ts) |
| `/api/v1/waf/events/[id]/explain` | GET | `waf:read` | [route](../../app/api/v1/waf/events/[id]/explain/route.ts) |
| `/api/v1/waf/events/[id]/suggested-exclusion` | GET | `waf:read` | [route](../../app/api/v1/waf/events/[id]/suggested-exclusion/route.ts) |
| `/api/v1/waf/events` | GET | `waf:read` | [route](../../app/api/v1/waf/events/route.ts) |
| `/api/v1/waf/exclusions/[id]` | DELETE, GET, PATCH | `waf:read`, `waf:write` | [route](../../app/api/v1/waf/exclusions/[id]/route.ts) |
| `/api/v1/waf/exclusions/batch` | POST | `waf:write` | [route](../../app/api/v1/waf/exclusions/batch/route.ts) |
| `/api/v1/waf/exclusions` | GET, POST | `waf:read`, `waf:write` | [route](../../app/api/v1/waf/exclusions/route.ts) |
| `/api/v1/waf/hosts/[id]` | GET, PUT | `waf:read`, `waf:write` | [route](../../app/api/v1/waf/hosts/[id]/route.ts) |
| `/api/v1/waf/hosts` | GET | `waf:read` | [route](../../app/api/v1/waf/hosts/route.ts) |
| `/api/v1/waf/tuning-suggestions/[id]/apply` | POST | `waf:write` | [route](../../app/api/v1/waf/tuning-suggestions/[id]/apply/route.ts); [EE](../../ee/ai/routes/v1/waf/tuning-suggestions/[id]/apply.ts) |
| `/api/v1/waf/tuning-suggestions/[id]/dismiss` | POST | `waf:write` | [route](../../app/api/v1/waf/tuning-suggestions/[id]/dismiss/route.ts); [EE](../../ee/ai/routes/v1/waf/tuning-suggestions/[id]/dismiss.ts) |
| `/api/v1/waf/tuning-suggestions` | GET | `waf:read` | [route](../../app/api/v1/waf/tuning-suggestions/route.ts); [EE](../../ee/ai/routes/v1/waf/tuning-suggestions.ts) |

## Implementation coverage process

1. Keep this versioned inventory as a starting point and regenerate it against the implementation target; do not assume this snapshot is current forever.
2. For each registered tool, record exact method/path, required scopes, actual host/field scope, enterprise availability, output projection, side effects, range/size budgets and lifecycle/error behavior.
3. Verify both visibility and direct invocation with allowed, denied, revoked and out-of-scope credentials. No auto-registration from the rows above.
4. Changes to REST/OpenAPI/permissions must trigger registry-contract review. A new REST endpoint remains absent from MCP until explicitly reviewed and tested.
5. Report coverage as implemented tools and accepted workflows, not as “395 operations supported” merely because this inventory has395 handler exports.
