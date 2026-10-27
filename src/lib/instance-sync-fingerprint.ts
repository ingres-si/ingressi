/**
 * Fingerprints of the configuration a sync slave runs, and the status a slave
 * reports on GET /api/instances/sync?status=1. A master uses them to tell
 * whether a slave still runs what it last pushed (drift detection, see
 * ee/fleet). Free of database access, so both sides and tests can use it.
 *
 * Both sides fingerprint the same content: the settings groups and tables a
 * sync payload carries, with secrets in plaintext, without createdAt and
 * updatedAt, rows sorted by id, serialized with sorted keys. The master
 * computes it over the payload before sealing; the slave over the payload it
 * opened, so the two agree whatever release each side runs. It is an
 * HMAC-SHA256 keyed with a key derived from the slave's sync token, which
 * only the master and that slave hold: a fingerprint covers private keys and
 * credentials, and must not let anybody without the token test a guess.
 */
import { createHmac, hkdfSync } from "node:crypto";
import { sanitizeInstanceSyncError } from "./instance-sync-error";

/** Query parameter of GET /api/instances/sync that asks for the status instead of the sync key. */
export const SYNC_STATUS_PARAM = "status";
export const SYNC_STATUS_VERSION = 1;

/** The settings groups a sync payload carries. */
export const SYNC_FINGERPRINT_SETTING_KEYS = [
  "general",
  "acme",
  "cloudflare",
  "dns_provider",
  "authentik",
  "metrics",
  "logging",
  "dns",
  "upstream_dns_resolution",
  "waf",
  "geoblock",
  "error_pages",
  "trusted_proxies",
  "forward_auth",
  "default_response",
  "rate_limit",
  "response_headers",
  "monetization_replica",
] as const;

/**
 * Groups added after the fingerprint format was fixed. They enter the
 * canonical content only when set, so a master and a slave from an older
 * release still agree while the group is unused; once it is used, the older
 * slave cannot apply it anyway and the difference is real drift.
 */
const OPTIONAL_FINGERPRINT_SETTING_KEYS: ReadonlySet<string> = new Set(["rate_limit", "monetization_replica", "response_headers"]);

/** The tables a sync payload carries, by their key in `payload.data`. */
export const SYNC_FINGERPRINT_TABLES = [
  "certificates",
  "caCertificates",
  "issuedClientCertificates",
  "accessLists",
  "accessListEntries",
  "accessListRules",
  "proxyHosts",
  "l4ProxyHosts",
  "wafRuleExclusions",
] as const;

/**
 * Tables added after the fingerprint format was fixed. Like the optional
 * settings groups, they enter the canonical content only when they hold rows,
 * so a master and an older slave agree until the table is used.
 */
const OPTIONAL_FINGERPRINT_TABLES: ReadonlySet<string> = new Set(["wafRuleExclusions", "accessListRules"]);

/** Columns that change without changing what is served. */
const VOLATILE_COLUMNS: ReadonlySet<string> = new Set(["createdAt", "updatedAt"]);

const FINGERPRINT_INFO = "ingressi:instance-sync:fingerprint:v1";
const LOCAL_DIGEST_INFO = "ingressi:instance-sync:local-digest:v1";
const KEY_ID_INFO = "ingressi:instance-sync:status-key-id:v1";

/** What is fingerprinted: a sync payload's `settings` and `data`, or the same read from a slave's database. */
export type SyncFingerprintContent = {
  settings: Record<string, unknown> | null | undefined;
  data: Record<string, unknown> | null | undefined;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isRecord(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeys(value[key])]));
  }
  return value;
}

function rowId(row: unknown): number {
  return isRecord(row) && typeof row.id === "number" ? row.id : Number.NaN;
}

/** The canonical serialization both sides hash. */
export function canonicalSyncContent(content: SyncFingerprintContent): string {
  const settings = isRecord(content.settings) ? content.settings : {};
  const data = isRecord(content.data) ? content.data : {};
  const canonical = {
    v: 1,
    settings: Object.fromEntries(
      SYNC_FINGERPRINT_SETTING_KEYS
        .filter((key) => !OPTIONAL_FINGERPRINT_SETTING_KEYS.has(key) || (settings[key] ?? null) !== null)
        .map((key) => [key, settings[key] ?? null])
    ),
    data: Object.fromEntries(
      SYNC_FINGERPRINT_TABLES.filter(
        (name) => !OPTIONAL_FINGERPRINT_TABLES.has(name) || (Array.isArray(data[name]) && (data[name] as unknown[]).length > 0)
      ).map((name) => {
        const rows = Array.isArray(data[name]) ? (data[name] as unknown[]) : [];
        return [
          name,
          rows
            .map((row) => (isRecord(row) ? Object.fromEntries(Object.entries(row).filter(([column]) => !VOLATILE_COLUMNS.has(column))) : row))
            .sort((a, b) => rowId(a) - rowId(b)),
        ];
      })
    ),
  };
  return JSON.stringify(sortKeys(canonical));
}

function tokenKey(token: string, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", token, Buffer.alloc(0), info, 32));
}

/** HMAC of canonical content for the slave holding `token`. */
export function syncFingerprintOfCanonical(canonical: string, token: string): string {
  return createHmac("sha256", tokenKey(token, FINGERPRINT_INFO)).update(canonical).digest("hex");
}

/** The fingerprint of a payload's (or a slave's) synced content for the slave holding `token`. */
export function syncContentFingerprint(content: SyncFingerprintContent, token: string): string {
  return syncFingerprintOfCanonical(canonicalSyncContent(content), token);
}

/**
 * A slave's digest of its own stored copy of the synced configuration, to
 * notice changes made on the slave itself. Keyed like the fingerprint, with
 * a separate key.
 */
export function syncLocalDigest(content: SyncFingerprintContent, token: string): string {
  return createHmac("sha256", tokenKey(token, LOCAL_DIGEST_INFO)).update(canonicalSyncContent(content)).digest("hex");
}

/** A short id of the keys derived from `token`, to notice that the token changed. */
export function syncTokenKeyId(token: string): string {
  return createHmac("sha256", tokenKey(token, KEY_ID_INFO)).update("key-id").digest("hex").slice(0, 16);
}

export function isSyncFingerprint(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

/** The status of a slave, as GET /api/instances/sync?status=1 reports it (`{ syncStatus: ... }`). */
export type ReplicaSyncStatus = {
  version: typeof SYNC_STATUS_VERSION;
  /** The release the slave runs. */
  appVersion: string;
  /** Fingerprint of the configuration last applied from a master; null when the slave recorded none. */
  fingerprint: string | null;
  appliedAt: string | null;
  /**
   * Whether the synced configuration was changed on the slave since it was
   * applied; null when the slave cannot tell (it was upgraded or its sync
   * token changed since).
   */
  localChanges: boolean | null;
  /** Settings groups for which the slave uses a value of its own instead of the synced one. */
  overriddenSettings: string[];
  lastSync: { at: string | null; error: string | null };
  /** The slave's last attempt to apply its configuration to Caddy; null before the first. */
  caddy: { ok: boolean; at: string; code: string | null } | null;
};

const MAX_TIMESTAMP_LENGTH = 40;

function readTimestamp(value: unknown): string | null | undefined {
  if (value === null) return null;
  if (typeof value !== "string" || value.length > MAX_TIMESTAMP_LENGTH || Number.isNaN(Date.parse(value))) return undefined;
  return value;
}

/**
 * The status in a slave's reply: "absent" for a reply without one (a slave
 * from an older release answers with its sync key), "invalid" for a status
 * that is not well formed. Only known fields of the expected shape are kept;
 * the error is reduced to the fixed sync messages.
 */
export function parseReplicaSyncStatus(
  body: unknown
): { kind: "absent" } | { kind: "invalid" } | { kind: "ok"; status: ReplicaSyncStatus } {
  if (!isRecord(body) || !("syncStatus" in body)) return { kind: "absent" };
  const raw = body.syncStatus;
  if (!isRecord(raw) || raw.version !== SYNC_STATUS_VERSION) return { kind: "invalid" };

  const appVersion = typeof raw.appVersion === "string" && /^[\x21-\x7e]{1,64}$/.test(raw.appVersion) ? raw.appVersion : null;
  const fingerprint = raw.fingerprint === null || isSyncFingerprint(raw.fingerprint) ? raw.fingerprint : undefined;
  const appliedAt = readTimestamp(raw.appliedAt);
  const localChanges = raw.localChanges === null || typeof raw.localChanges === "boolean" ? raw.localChanges : undefined;
  if (appVersion === null || fingerprint === undefined || appliedAt === undefined || localChanges === undefined) {
    return { kind: "invalid" };
  }

  const overriddenSettings = Array.isArray(raw.overriddenSettings)
    ? raw.overriddenSettings.filter(
        (key): key is string =>
          typeof key === "string" && (SYNC_FINGERPRINT_SETTING_KEYS as readonly string[]).includes(key)
      ).slice(0, SYNC_FINGERPRINT_SETTING_KEYS.length)
    : [];

  const lastSyncRaw = isRecord(raw.lastSync) ? raw.lastSync : {};
  const lastSyncAt = readTimestamp(lastSyncRaw.at ?? null) ?? null;
  const lastSyncError = typeof lastSyncRaw.error === "string" ? sanitizeInstanceSyncError(lastSyncRaw.error) : null;

  let caddy: ReplicaSyncStatus["caddy"] = null;
  if (isRecord(raw.caddy)) {
    const at = readTimestamp(raw.caddy.at);
    const code = typeof raw.caddy.code === "string" && /^[A-Z_]{1,40}$/.test(raw.caddy.code) ? raw.caddy.code : null;
    if (typeof raw.caddy.ok !== "boolean" || !at) return { kind: "invalid" };
    caddy = { ok: raw.caddy.ok, at, code };
  } else if (raw.caddy !== null && raw.caddy !== undefined) {
    return { kind: "invalid" };
  }

  return {
    kind: "ok",
    status: {
      version: SYNC_STATUS_VERSION,
      appVersion,
      fingerprint,
      appliedAt,
      localChanges,
      overriddenSettings,
      lastSync: { at: lastSyncAt, error: lastSyncError },
      caddy,
    },
  };
}
