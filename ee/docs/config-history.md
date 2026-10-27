# Configuration history, rollback, export and import

- **Configuration history** (`ee/config-history/`, Elastic License 2.0): a snapshot of the configuration after every applied change, diffs between snapshots or against the current configuration, and one-click restore.
- **Export and import** (`src/lib/config-transfer.ts`, MIT): download the configuration as a passphrase-protected JSON file and load it back, on the same or another installation.

Both live on the **Change history** page of the dashboard (`/history`, under Govern) and under `/api/v1/`.

## The Change history page

- A strip shows whether recording is on, how many versions are kept and the oldest one, and the scheduled backups. **History settings** turns recording on or off, sets the retention and deletes every version.
- **Versions** lists the versions on a timeline, newest first and grouped by day, each with its title, who made it, its size, the live marker and the change request it came from. Select one to see what it changed against the previous version, the live configuration or any other version, unified or side by side, and the **rollback preview**: the hosts and settings that would change, the later changes it would undo, later changes to the same hosts, and approval policies that would refuse it. **Roll back** asks for confirmation; the live configuration is saved as a version first.
- **Save a version now** saves a manual version with a note. **Export or import** downloads or loads the passphrase-protected configuration file.
- The backups line links to **Backups** (`/backups`, under Change history in the sidebar), where scheduled backups are set up ([scheduled-backups.md](scheduled-backups.md)); `/history?tab=backups` opens it too.
- Links can open a version directly: `/history?version=<id>`, with `&compare=previous|live|<id>` and `&rollback=1` to jump to the rollback preview (the audit log links its configuration changes this way).

Scheduled backups of the same export file to S3-compatible storage are on the Backups page; see [scheduled-backups.md](scheduled-backups.md).

## What "the configuration" is

Defined once in `src/lib/config-content.ts` and shared by snapshots, restore, export and import.

Included:

| Entity | Table |
| --- | --- |
| Proxy hosts | `proxy_hosts` |
| L4 proxy hosts | `l4_proxy_hosts` |
| Access lists, their users and rules | `access_lists`, `access_list_entries`, `access_list_rules` |
| Certificates, as stored | `certificates` |
| CA certificates | `ca_certificates` |
| Issued client certificates | `issued_client_certificates` |
| mTLS roles, role assignments, access rules | `mtls_roles`, `mtls_certificate_roles`, `mtls_access_rules` |
| Forward-auth groups and per-host grants | `groups`, `forward_auth_access` |
| Settings groups managed by `/api/v1/settings/{group}` | `settings` keys `general`, `acme`, `cloudflare`, `dns_provider`, `authentik`, `forward_auth`, `metrics`, `logging`, `dns`, `upstream_dns_resolution`, `geoblock`, `waf`, `error_pages`, `default_response`, `response_headers`, `trusted_proxies` |
| Certificate storage ([high-availability.md](high-availability.md)) | `settings` key `certificate_storage` |

Excluded, so that a restore or an import can never lock anyone out or sign anyone in: users, group memberships, dashboard sessions, sign-in accounts, OAuth state and providers, API tokens, audit events, instances and sync tokens and keys, forward-auth sessions, the instance mode, the history settings and every other settings key.

A unit test keeps the settings list equal to the storage keys of `SETTINGS_HANDLERS` plus `certificate_storage`; a new settings group added there must be added to `CONFIG_SETTING_KEYS` too.

## Snapshots

Table `config_snapshots` (migration `0027_config_history`): `id`, `createdAt`, `userId` (who caused it; not a foreign key, so deleting a user never touches history), `reason`, `summary`, `fingerprint`, `content` (JSON), `sizeBytes`.

Reasons:

- `auto`: recorded after an applied change.
- `manual`: created by an administrator, optionally with a note.
- `before_restore`: the configuration a restore replaced.
- `import`: the configuration an import replaced.

Rows are stored exactly as in the database. Secret columns (certificate and CA private keys) and encrypted strings inside settings (DNS provider credentials, the legacy Cloudflare token) stay encrypted with this instance's `SESSION_SECRET` key; nothing is decrypted into a snapshot. Access-list password hashes are stored as the database stores them.

### Automatic recording

`applyCaddyConfig` (`src/lib/caddy.ts`) calls `recordConfigSnapshotAfterApply()` once Caddy has accepted a configuration and before slaves are synced. When history is enabled it reads the configuration in one transaction and stores it unless its fingerprint equals the newest snapshot's. The hook never throws.

The fingerprint is the SHA-256 of the canonical content (sorted keys) without the `createdAt`/`updatedAt` columns and with each secret replaced by an HMAC of its plaintext (key derived from `SESSION_SECRET`). Saving something without changing it, or re-encrypting a secret, therefore records nothing, and the stored fingerprint cannot be used to guess a secret. Turning recording on records a first snapshot right away.

Sync slaves record nothing: their configuration comes from the master.

### Retention

The newest `retention` snapshots are kept (default 200, 1 to 10000); older ones are deleted whenever a snapshot is stored or the retention is lowered.

### Diffs

`GET /api/v1/config-history/{id}/diff?against=current|previous|<id>` returns, per entity type, the items added, removed and changed going from `against` to the snapshot, with field-level changes. With `against=current` it is exactly what restoring the snapshot would change. JSON columns (`meta`, `domains`, `upstreams`, ...) and settings groups are compared by path (`meta.waf.enabled`). Timestamps are ignored. Secrets are never returned: secret columns, encrypted values, fields named like passwords, tokens, keys or credentials, and the whole legacy Cloudflare group are reported as `{ "path": ..., "secret": true }`. Secrets are compared by plaintext, so a re-encrypted secret is not a change.

### Restore

`POST /api/v1/config-history/{id}/restore`:

1. In one database transaction: save the current configuration as a `before_restore` snapshot, then replace every configuration table and settings group with the snapshot's content, keeping row ids.
2. Apply the configuration to Caddy.
3. If Caddy does not accept it, write the previous configuration back, re-apply it and answer 502; the `before_restore` snapshot stays. If only syncing slaves failed, the restore stands and the response carries a `warning`.
4. Record an audit event (`config_restored` or `config_restore_failed`).

While replacing, references the content cannot satisfy are repaired the way the schema's `onDelete` rules would (the database enforces no foreign keys, on SQLite or PostgreSQL): attribution (`createdBy`, `ownerUserId`) to a user that no longer exists is cleared, and a forward-auth grant for a user, group or host that no longer exists is dropped. Group memberships survive for groups that still exist; forward-auth sessions survive for hosts that still exist. Encrypted values that only `SESSION_SECRET_PREVIOUS` decrypts are re-encrypted with the current key. A snapshot that conflicts with itself (for example two groups with the same name) is refused with 409 and nothing changes. Restores are serialized with settings updates.

L4 port changes are not applied automatically, as with any L4 change: the L4 page shows the usual "apply ports" banner.

Restore is refused on a sync slave (409): the master would overwrite it on the next sync. It is also refused (409, nothing changed) when it would create, change or delete a host that an enabled change approval policy protects; see [change-approvals.md](change-approvals.md).

### Versions, titles and sizes

`GET /api/v1/config-history/versions?limit&offset` lists the snapshots as versions, newest first, each with:

- `title`: what the version is about. For an automatic version, the summary of the audit event that produced it (`"Changed the upstream of langfuse.example.com"`, or `"… and 2 more changes"`); the note of a manual version; otherwise the summary computed from the diff.
- `actors` (who made the changes, from the audit events), `auditEventIds`, and `changeRequestIds`: the change requests ([change-approvals.md](change-approvals.md)) whose approved changes it contains.
- `size` in words (`"1 host · 2 fields"`, `"1 host added"`, `"2 settings groups · 4 fields"`, `"First version"`, `"No changes"`), `totals` and the hosts and settings groups it `touched`.
- `live`: the configuration running now is exactly this version. `liveId` is null when the running configuration has changes no version holds (recording was off, or Caddy refused the last apply).

What a version changed is computed against the newest version kept before it, when it is recorded (column `changes`); versions recorded before this release get it the first time they are listed.

### Audit events and versions

An audit event about a configuration entity (proxy and L4 hosts, access lists and their users, certificates, CA and client certificates, mTLS roles and rules, groups, forward-auth grants, settings groups, certificate storage, imports and restores), recorded while history is on, stores the version before it and the version its apply recorded (`audit_events.configBeforeId`, `configAfterId`, `ee/config-history/links.ts`), and the change request that applied it (`changeRequestId`). These columns are not covered by the hash chain.

- Most changes are recorded before Caddy is applied: the event stays pending until the apply records the next version. An apply that finds the configuration unchanged closes it with the same version on both sides ("no change").
- Settings saves, restores and imports are recorded after the apply that stored their version: when the newest version is automatic, at most five minutes old, changed that entity and has no event for it yet, the event is linked to it.
- Turning recording off drops the link of pending events. Events recorded before this release, or while recording was off, have none.

`GET /api/v1/audit-log/{id}` returns an event's before/after diff from these versions, limited to the event's own entity (a proxy host with its mTLS rules and forward-auth grants; every change for imports and restores). Secrets are masked as everywhere else. When retention deleted one of the versions the diff says so.

### Comparing two versions

`GET /api/v1/config-history/compare?from=&to=` returns every difference from `from` (a version id, `previous` (the default: the version before `to`) or `current`) to `to` (a version id or `current`, the default), per row and settings group, field by field. Rows of a host (mTLS rules, forward-auth grants) name the host they belong to, and references such as `accessListId` and `certificateId` carry the names they point to (`beforeLabel`, `afterLabel`). An added or removed row lists all its fields.

### Rollback preview

`GET /api/v1/config-history/{id}/rollback-preview` says what restoring version `id` would do, without changing anything:

- the hosts that change (`added`: it comes back; `removed`: it did not exist yet; `changed`, with the fields), the settings groups and the other rows that change;
- the later versions it undoes, and whether the running configuration has changes no version holds (they are undone too);
- later versions that changed a host this version itself changed (`sameHostWarnings`): rolling back undoes those changes as well;
- the approval policies that protect hosts it changes (`blocked`), in which case restore answers 409;
- how many Caddy nodes reload (this node plus, on a master, the enabled instances outside promotion-only environments);
- `canRestore` and `reasons`: not on a sync slave, the caller's `config_history:restore` permission, no protecting policy, and something to change.

## Export and import

`POST /api/v1/config/export` with `{ "passphrase": "..." }` (at least 12 characters) downloads `ingressi-configuration-<time>.json`:

```json
{
  "format": "ingressi-configuration",
  "version": 1,
  "exportedAt": "2026-10-02T12:00:00.000Z",
  "appVersion": "1.2.3",
  "kdf": { "name": "scrypt", "N": 131072, "r": 8, "p": 1, "salt": "<base64>" },
  "cipher": "aes-256-gcm",
  "check": "pp:v1:...",
  "users": { "7": "alice@example.com" },
  "content": { "version": 1, "tables": { ... }, "settings": { ... } }
}
```

Every secret (certificate and CA private keys, access-list password hashes, encrypted strings inside settings) is decrypted with this instance's key and encrypted again with a key derived from the passphrase (scrypt N=2^17, r=8, p=1; AES-256-GCM, each value bound to its place in the file as associated data), as `pp:v1:<iv>:<tag>:<ciphertext>`. Everything else stays readable. `check` is a known value sealed the same way, which tells a wrong passphrase apart from a damaged file. User attribution is left out; `users` maps the user ids that forward-auth grants name to their email addresses. Export is refused when a stored secret no key decrypts (409) and on a sync slave (409).

`POST /api/v1/config/import` takes a multipart form (`file`, `passphrase`) or JSON `{ "passphrase", "file" }` (the file as an object or as text), up to 50 MiB. The file is validated strictly (known fields, tables, columns and settings groups only, column types, unique ids, scrypt parameters in range) and the passphrase checked before anything is written: a wrong passphrase is a 400 and changes nothing. Then it replaces the configuration like a restore, with secrets encrypted with this instance's key, and applies it (502 and nothing changed if Caddy rejects it). When history is enabled, the configuration being replaced is saved first as an `import` snapshot, in the same transaction. Because ids from another installation mean something else here:

- forward-auth grants for users are mapped to the local user with the same email address, and dropped when there is none;
- local group memberships are kept only for groups whose name did not change;
- all forward-auth sessions end (users sign in to protected hosts again).

Import is refused on a sync slave (409), and when it would create, change or delete a host that an enabled change approval policy protects (409, see [change-approvals.md](change-approvals.md)).

## API

All endpoints need a `config_history` permission (`read` for listing, diffs, comparisons and previews; `write`, `restore`), are documented in the OpenAPI spec (tags "Configuration History" and "Configuration") and audited.

| Method and path | What |
| --- | --- |
| `GET /api/v1/config-history?limit&offset` | List snapshots, newest first |
| `GET /api/v1/config-history/versions?limit&offset` | Versions with titles, actors and sizes |
| `GET /api/v1/config-history/compare?from&to` | Field-level differences between two versions |
| `GET /api/v1/config-history/{id}/rollback-preview` | What restoring a version would do |
| `POST /api/v1/config-history` `{summary?}` | Create a manual snapshot |
| `DELETE /api/v1/config-history` | Delete all snapshots |
| `GET /api/v1/config-history/settings` | `{enabled, retention}` |
| `PUT /api/v1/config-history/settings` `{enabled?, retention?}` | Change settings |
| `GET /api/v1/config-history/{id}` | Metadata and a content summary (names and counts, no values) |
| `DELETE /api/v1/config-history/{id}` | Delete a snapshot |
| `GET /api/v1/config-history/{id}/diff?against=` | Diff |
| `POST /api/v1/config-history/{id}/restore` | Restore |
| `POST /api/v1/config/export` `{passphrase}` | Export file |
| `POST /api/v1/config/import` | Import file |

Audit actions: `config_snapshot_created`, `config_snapshot_deleted`, `config_snapshots_deleted`, `config_history_settings_updated`, `config_restored`, `config_restore_failed`, `config_exported`, `config_imported`.

## Instance sync

History settings (settings key `config_history`) and snapshots are not synced to slaves, and the settings are not a `/api/v1/settings/{group}` group. Slaves record no history and refuse restore, manual snapshots, export and import with 409, because their configuration is whatever the master last sent. A restore or import on a master is applied and synced to its slaves like any other change.

## Known limitations

- Automatic snapshots carry no user (`applyCaddyConfig` has no request context); the audit log shows who made the change.
- Automatic snapshots follow `applyCaddyConfig`. Changes that never reach Caddy (renaming a group, editing forward-auth grants on their own, which the proxy host editor does right after saving the host) are recorded with the next applied change. Nothing is lost on a restore: the `before_restore` snapshot is taken from the database, not from the history.
- After a `SESSION_SECRET` rotation, secrets in older snapshots stay encrypted with the old key. Restoring them works while `SESSION_SECRET_PREVIOUS` still holds that key (they are re-encrypted with the new one); once it is gone, they are restored as stored and Caddy cannot use them. Export files do not depend on `SESSION_SECRET`.
- Snapshot content is validated against the current schema on restore; a snapshot from an older release that lacks a column without a default is refused with 409.
