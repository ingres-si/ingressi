import { createHash } from "node:crypto";
import { eq, getTableColumns, type Column } from "drizzle-orm";
import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import { appDb, nowIso } from "./db";
import { accessListEntries, accessListRules, accessLists, caCertificates, certificates, instances, issuedClientCertificates, l4ProxyHosts, monetizationHosts, proxyHosts, settings as settingsTable, wafRuleExclusions } from "./db/schema";
import { encryptCloudflareSettingToken, getSetting, setSetting } from "./settings";
import { instanceBaseUrlValidationError, recordInstanceSyncResult, updateInstance } from "./models/instances";
import { decryptSecret, encryptSecret, isEncryptedSecret, reencryptSecret } from "./secret";
import { encryptDnsProviderSettingCredentials } from "./dns-providers";
import { sanitizeStoredCertificateProviderOptions } from "./certificate-provider-options";
import {
  SYNC_INVALID_KEY_ERROR,
  SYNC_KEY_CHANGED_ERROR,
  SYNC_KEY_CONFIG_MISMATCH_ERROR,
  SYNC_NOT_ACKNOWLEDGED_ERROR,
  SYNC_SLAVE_CHANGED_DURING_SYNC_ERROR,
  SYNC_TIMED_OUT_ERROR,
  sanitizeInstanceSyncError,
} from "./instance-sync-error";
import {
  SEALED_SYNC_SECRET_PREFIX,
  SYNC_KEY_CHALLENGE_PARAM,
  SyncSealError,
  createSyncKeyChallenge,
  decodeSyncPublicKey,
  getSyncPublicKey,
  isSyncKeyId,
  isSyncNonce,
  openSyncSecret,
  syncKeyId,
  parseSyncKeyRotationProofs,
  parseSyncPublicKeyResponse,
  sealSyncSecret,
  verifySyncKeyRotationProof,
  type SyncKeyChallenge,
  type SyncKeyRotationProof,
  type SyncSealTarget,
} from "./sync-crypto";
import { getSyncKeyPin, isUnreadableSyncKeyPin, syncKeyPinIdentity, updateSyncKeyPin } from "./instance-sync-key-pins";
import { logAuditEvent } from "./audit";
import { applyL4Ports, getL4PortsDiff } from "./l4-ports";
import {
  assertValidInstanceSyncToken,
  isValidInstanceSyncToken,
} from "./instance-sync-token";
import { refreshBranding } from "@/ee/white-label/store";
import { WHITE_LABEL_SETTING_KEY } from "@/ee/white-label/types";
import { encryptCertificateStorageSecrets } from "@/ee/high-availability/settings";
import { buildReplicaSection } from "@/ee/monetization/replica-sync";
import { parseReplicaSection, REPLICA_SETTING_KEY } from "@/ee/monetization/replica-index";
import {
  SYNC_STATUS_PARAM,
  canonicalSyncContent,
  parseReplicaSyncStatus,
  syncContentFingerprint,
  syncFingerprintOfCanonical,
  type ReplicaSyncStatus,
} from "./instance-sync-fingerprint";
import type { ConfigContent } from "./config-content";
import type { AppliedSync } from "./instance-sync-status";
import { getSlaveFingerprintToken } from "@/ee/fleet/pull-config";
import { listPinnedInstanceIds, recordFleetPush } from "@/ee/fleet/state";
import { first, resyncIdentity } from "@/src/lib/db/ops";
import { tryWithClusterLock, withCoalescedClusterLock } from "./db/locks";
import { useSyncNonce } from "./sync-nonces";
import { isHttpSyncAllowed } from "./instance-sync-http";

export type InstanceMode = "standalone" | "master" | "slave";

export type SyncSettings = {
  general: unknown | null;
  acme: unknown | null;
  cloudflare: unknown | null;
  dns_provider: unknown | null;
  authentik: unknown | null;
  metrics: unknown | null;
  logging: unknown | null;
  dns: unknown | null;
  upstream_dns_resolution: unknown | null;
  waf: unknown | null;
  geoblock: unknown | null;
  error_pages: unknown | null;
  trusted_proxies: unknown | null;
  /** Optional for backward compatibility with payloads from older masters. */
  forward_auth?: unknown | null;
  /** Optional for backward compatibility with payloads from older masters. */
  default_response?: unknown | null;
  /**
   * Rate limiting defaults and allowlist. Optional for older masters; a
   * slave stores null then, so it limits by its hosts' own rules only.
   */
  rate_limit?: unknown | null;
  /** Response headers for every response. Optional for older masters. */
  response_headers?: unknown | null;
  /**
   * White-label branding with its logos (ee/white-label). Replicas serve the
   * forward-auth portal and sign-in pages too. Optional for older masters.
   */
  white_label?: unknown | null;
  /**
   * Where the slave's Caddy keeps certificates (ee/high-availability), its
   * secrets sealed like DNS provider credentials. Optional for older masters;
   * older slaves ignore it and keep local storage.
   */
  certificate_storage?: unknown | null;
  /**
   * API monetization on replicas (ee/monetization/replica-index.ts): the
   * gate's index without balances and the monetized proxy hosts, sent while
   * the master serves them on replicas. Optional; older slaves ignore it and
   * so never serve monetized hosts.
   */
  monetization_replica?: unknown | null;
};

export type SyncPayload = {
  generated_at: string;
  settings: SyncSettings;
  /**
   * Where the master decrypted a secret inside `settings` for transport; the
   * slave encrypts the strings at these paths again. Absent in payloads from
   * older masters, which sent secrets as stored (encrypted with their key).
   */
  settings_secret_paths?: SettingPath[];
  /**
   * Key id of the slave key that the secrets in this payload (the strings at
   * settings_secret_paths and the certificate private keys) are sealed to;
   * see sync-crypto.ts. Absent when they travel unsealed: to slaves from
   * older releases, and in payloads from older masters.
   */
  secrets_sealed_key_id?: string;
  /**
   * The single-use nonce the slave issued with its key. Sent with
   * secrets_sealed_key_id; the sealed secrets are bound to it and to the rest
   * of the payload (see sealSyncPayload).
   */
  secrets_sealed_nonce?: string;
  data: {
    certificates: Array<typeof certificates.$inferSelect>;
    caCertificates: Array<typeof caCertificates.$inferSelect>;
    issuedClientCertificates: Array<typeof issuedClientCertificates.$inferSelect>;
    /** The rule settings (defaultAction ... systemKey) are missing in payloads from masters older than access list rules; the column defaults apply. */
    accessLists: Array<WithOptionalAccessListSettings<typeof accessLists.$inferSelect>>;
    accessListEntries: Array<typeof accessListEntries.$inferSelect>;
    /** Optional: not present in payloads from masters older than access list rules. */
    accessListRules?: Array<typeof accessListRules.$inferSelect>;
    /** `tags` is missing in payloads from masters older than host tags; the column default applies. */
    proxyHosts: Array<WithOptionalTags<typeof proxyHosts.$inferSelect>>;
    /** Optional — not present in payloads from older master instances */
    l4ProxyHosts?: Array<WithOptionalTags<typeof l4ProxyHosts.$inferSelect>>;
    /**
     * WAF rule exclusion records (src/lib/models/waf-exclusions.ts), without
     * attribution. Missing in payloads from older masters: the slave then
     * keeps none and the excluded_rule_ids lists in the settings and host
     * meta still apply.
     */
    wafRuleExclusions?: Array<typeof wafRuleExclusions.$inferSelect>;
  };
};

type WithOptionalTags<T extends { tags: string }> = Omit<T, "tags"> & { tags?: string };
type AccessListSettingColumns = "defaultAction" | "denyStatus" | "denyBody" | "denyRedirectUrl" | "failClosed" | "systemKey";
type WithOptionalAccessListSettings<T extends Record<AccessListSettingColumns, unknown>> = Omit<T, AccessListSettingColumns> &
  Partial<Pick<T, AccessListSettingColumns>>;

const INSTANCE_MODE_KEY = "instance_mode";
const MASTER_TOKEN_KEY = "instance_master_token";
const SYNCED_PREFIX = "synced:";
const SLAVE_LAST_SYNC_AT_KEY = "instance_last_sync_at";
const SLAVE_LAST_SYNC_ERROR_KEY = "instance_last_sync_error";

/**
 * Environment variable names for instance sync configuration.
 * These take precedence over database settings when set.
 */
const ENV_INSTANCE_MODE = "INSTANCE_MODE";
const ENV_INSTANCE_SYNC_TOKEN = "INSTANCE_SYNC_TOKEN";
const ENV_INSTANCE_SLAVES = "INSTANCE_SLAVES";
const ENV_SYNC_INTERVAL = "INSTANCE_SYNC_INTERVAL";
const ENV_SYNC_TIMEOUT_MS = "INSTANCE_SYNC_TIMEOUT_MS";

/**
 * Type for slave instances configured via environment variable.
 */
export type EnvSlaveInstance = {
  name: string;
  url: string;
  token: string;
  /**
   * The key id the slave's sync key must have (see syncKeyId in
   * sync-crypto.ts). Pins the key explicitly: no first-use pin and no
   * rotation. Set from syncPublicKey when only that is configured.
   */
  syncKeyId?: string;
  /**
   * The slave's full sync public key (raw X25519, base64), which the key it
   * presents must equal. A stricter explicit pin than syncKeyId, which is a
   * 64-bit fingerprint.
   */
  syncPublicKey?: string;
};

/**
 * Parses INSTANCE_SLAVES environment variable.
 * Expected format: JSON array of {name, url, token, syncKeyId?, syncPublicKey?} objects
 * Example: [{"name":"slave1","url":"http://slave:3000","token":"secret"}]
 */
export function getEnvSlaveInstances(): EnvSlaveInstance[] {
  const envValue = process.env[ENV_INSTANCE_SLAVES];
  if (!envValue || envValue.trim().length === 0) {
    return [];
  }

  try {
    const parsed = JSON.parse(envValue);
    if (!Array.isArray(parsed)) {
      console.warn("INSTANCE_SLAVES must be a JSON array");
      return [];
    }

    return parsed
      .filter((item, index): item is EnvSlaveInstance => {
        if (typeof item !== "object" || item === null) return false;
        if (typeof item.name !== "string" || item.name.trim().length === 0) return false;
        if (typeof item.url !== "string" || item.url.trim().length === 0) return false;
        if (!isValidInstanceSyncToken(item.token)) return false;
        const urlError = instanceBaseUrlValidationError(item.url);
        if (urlError) {
          // The message is a fixed validation string; never log the URL or the
          // entry itself, which may carry the token.
          console.warn(`Skipping INSTANCE_SLAVES entry ${index}: ${urlError}`);
          return false;
        }
        // An entry whose pin cannot apply is skipped, not synced unpinned.
        if (item.syncKeyId !== undefined && item.syncKeyId !== null && !isSyncKeyId(item.syncKeyId)) {
          console.warn(`Skipping INSTANCE_SLAVES entry ${index}: syncKeyId must be a sync key id (16 lowercase hex characters)`);
          return false;
        }
        if (item.syncPublicKey !== undefined && item.syncPublicKey !== null) {
          const publicKey = decodeSyncPublicKey(item.syncPublicKey);
          if (!publicKey) {
            console.warn(`Skipping INSTANCE_SLAVES entry ${index}: syncPublicKey must be a sync public key (base64 of 32 bytes)`);
            return false;
          }
          if (typeof item.syncKeyId === "string" && item.syncKeyId !== syncKeyId(publicKey)) {
            console.warn(`Skipping INSTANCE_SLAVES entry ${index}: syncKeyId is not the key id of syncPublicKey`);
            return false;
          }
        }
        return true;
      })
      // Validation trims the URL, so sync must use the trimmed value too
      // (UI/API instances are stored trimmed).
      .map((item) => {
        const publicKey = typeof item.syncPublicKey === "string" ? decodeSyncPublicKey(item.syncPublicKey) : null;
        const pinnedKeyId = publicKey ? syncKeyId(publicKey) : item.syncKeyId;
        return {
          name: item.name.trim(),
          url: item.url.trim(),
          token: item.token,
          ...(typeof pinnedKeyId === "string" ? { syncKeyId: pinnedKeyId } : {}),
          ...(publicKey ? { syncPublicKey: publicKey.toString("base64") } : {}),
        };
      });
  } catch {
    // JSON.parse errors can include excerpts from the input, which contains
    // bearer tokens. Never attach the exception or environment value here.
    console.warn("Failed to parse INSTANCE_SLAVES environment variable");
    return [];
  }
}

/**
 * Gets the sync interval in milliseconds from environment variable.
 * Default is 0 (disabled). Set INSTANCE_SYNC_INTERVAL to enable periodic sync.
 * Value is in seconds.
 */
export function getSyncIntervalMs(): number {
  const envValue = process.env[ENV_SYNC_INTERVAL];
  if (!envValue) return 0;

  const seconds = parseInt(envValue, 10);
  if (isNaN(seconds) || seconds <= 0) return 0;

  // Minimum 30 seconds to prevent abuse
  return Math.max(seconds, 30) * 1000;
}

const DEFAULT_SYNC_TIMEOUT_MS = 60_000;
const MIN_SYNC_TIMEOUT_MS = 5_000;
// Bun's fetch gives up after 300 s on its own (Node's undici fails a request
// whose headers take longer than that), so a larger limit would never apply.
const MAX_SYNC_TIMEOUT_MS = 300_000;

/**
 * Timeout for one sync request to a slave, covering the upload and the
 * slave's apply (including its Caddy reload). Read from
 * INSTANCE_SYNC_TIMEOUT_MS; defaults to 60 s (also for 0 or an invalid value)
 * and is clamped to 5 s..5 min.
 */
export function getSyncRequestTimeoutMs(): number {
  const envValue = process.env[ENV_SYNC_TIMEOUT_MS]?.trim();
  if (!envValue || !/^\d+$/.test(envValue)) return DEFAULT_SYNC_TIMEOUT_MS;
  const ms = Number(envValue);
  if (ms === 0) return DEFAULT_SYNC_TIMEOUT_MS;
  return Math.min(Math.max(ms, MIN_SYNC_TIMEOUT_MS), MAX_SYNC_TIMEOUT_MS);
}

/**
 * Checks if HTTP sync is explicitly allowed via environment variable.
 * HTTP sync transmits tokens in plaintext and should only be used in trusted networks.
 * (The rule lives in instance-sync-http.ts, shared with API monetization's gate URL.)
 */
export { isHttpSyncAllowed };

/**
 * Checks if a URL uses HTTP (not HTTPS).
 */
function isHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * Checks if instance mode is configured via environment variable.
 * Environment variables take precedence over database settings.
 */
export function isInstanceModeFromEnv(): boolean {
  const envMode = process.env[ENV_INSTANCE_MODE];
  return envMode === "master" || envMode === "slave" || envMode === "standalone";
}

/**
 * Checks if sync token is configured via environment variable.
 */
export function isSyncTokenFromEnv(): boolean {
  const envToken = process.env[ENV_INSTANCE_SYNC_TOKEN];
  return typeof envToken === "string" && envToken.length > 0;
}

export async function getInstanceMode(): Promise<InstanceMode> {
  // Environment variable takes precedence
  const envMode = process.env[ENV_INSTANCE_MODE];
  if (envMode === "master" || envMode === "slave" || envMode === "standalone") {
    return envMode;
  }

  // Fall back to database setting
  const stored = await getSetting<string>(INSTANCE_MODE_KEY);
  if (stored === "master" || stored === "slave" || stored === "standalone") {
    return stored;
  }
  return "standalone";
}

export async function setInstanceMode(mode: InstanceMode): Promise<void> {
  // If mode is set via environment, don't allow changing it
  if (isInstanceModeFromEnv()) {
    console.warn("Instance mode is configured via INSTANCE_MODE environment variable and cannot be changed at runtime");
    return;
  }
  await setSetting(INSTANCE_MODE_KEY, mode);
  // A slave shows the master's branding unless it has its own.
  await refreshBranding();
}

export async function getSlaveMasterToken(): Promise<string | null> {
  // Environment variable takes precedence
  const envToken = process.env[ENV_INSTANCE_SYNC_TOKEN];
  if (typeof envToken === "string" && envToken.length > 0) {
    assertValidInstanceSyncToken(envToken, ENV_INSTANCE_SYNC_TOKEN);
    return envToken;
  }

  // Fall back to database setting
  const stored = await getSetting<string>(MASTER_TOKEN_KEY);
  if (!stored) {
    return null;
  }
  if (!isEncryptedSecret(stored)) {
    assertValidInstanceSyncToken(stored, "Stored instance sync token");
    try {
      await setSetting(MASTER_TOKEN_KEY, encryptSecret(stored));
    } catch (error) {
      console.warn("Failed to encrypt stored master token:", error);
    }
    return stored;
  }
  try {
    const token = decryptSecret(stored, "instance sync master token");
    assertValidInstanceSyncToken(token, "Stored instance sync token");
    return token;
  } catch (error) {
    console.error("Failed to decrypt stored master token:", error);
    return null;
  }
}

export async function setSlaveMasterToken(token: string | null): Promise<void> {
  // If token is set via environment, don't allow changing it
  if (isSyncTokenFromEnv()) {
    console.warn("Sync token is configured via INSTANCE_SYNC_TOKEN environment variable and cannot be changed at runtime");
    return;
  }
  if (token) {
    assertValidInstanceSyncToken(token);
  }
  const next = token ? encryptSecret(token) : "";
  await setSetting(MASTER_TOKEN_KEY, next);
}

export async function getSlaveLastSync(): Promise<{ at: string | null; error: string | null }> {
  const [at, error] = await Promise.all([
    getSetting<string>(SLAVE_LAST_SYNC_AT_KEY),
    getSetting<string>(SLAVE_LAST_SYNC_ERROR_KEY)
  ]);

  return {
    at: at ?? null,
    error: sanitizeInstanceSyncError(error)
  };
}

export async function setSlaveLastSync(result: { ok: boolean; error?: string | null }) {
  await setSetting(SLAVE_LAST_SYNC_AT_KEY, nowIso());
  await setSetting(
    SLAVE_LAST_SYNC_ERROR_KEY,
    result.ok
      ? ""
      : sanitizeInstanceSyncError(result.error) ?? "Previous synchronization failed"
  );
}

export async function getSyncedSetting<T>(key: string): Promise<T | null> {
  return await getSetting<T>(`${SYNCED_PREFIX}${key}`);
}

export async function setSyncedSetting<T>(key: string, value: T | null): Promise<void> {
  await setSetting(`${SYNCED_PREFIX}${key}`, value ?? null);
}

export async function clearSyncedSetting(key: string): Promise<void> {
  await setSetting(`${SYNCED_PREFIX}${key}`, null);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Location of a string inside the synced settings: the settings group key,
 * then the object keys and array indexes down to the string.
 */
export type SettingPath = Array<string | number>;

function formatSettingPath(path: SettingPath): string {
  return path.map((part, index) => (typeof part === "number" ? `[${part}]` : index === 0 ? part : `.${part}`)).join("");
}

/** Apply `transform` to every string inside a JSON setting value. */
function mapSettingStrings(
  value: unknown,
  path: SettingPath,
  transform: (value: string, path: SettingPath) => string
): unknown {
  if (typeof value === "string") return transform(value, path);
  if (Array.isArray(value)) {
    return value.map((item, index) => mapSettingStrings(item, [...path, index], transform));
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, mapSettingStrings(item, [...path, key], transform)])
    );
  }
  return value;
}

/** Undecryptable setting paths already reported by this process. */
const reportedUndecryptableSettingPaths = new Set<string>();

/**
 * Replace every encrypted string in a setting value with its plaintext and
 * record where it was in `decryptedPaths`, so a slave does not need the
 * master's SESSION_SECRET: the strings at those paths are sealed to each
 * slave's key for transport (see sealSyncPayload), and the slave encrypts
 * them with its own key (see encryptSyncedSettingSecrets). Slaves from older
 * releases get them encrypted with this instance's key instead (see
 * legacySyncPayload). A value no key here decrypts is sent as stored, as
 * older releases sent every value, and reported once per process.
 */
function decryptSettingSecrets(key: string, value: unknown, decryptedPaths: SettingPath[]): unknown {
  return mapSettingStrings(value, [key], (item, path) => {
    if (!isEncryptedSecret(item)) return item;
    try {
      const plaintext = decryptSecret(item, `setting ${formatSettingPath(path)}`);
      decryptedPaths.push(path);
      return plaintext;
    } catch {
      const pathKey = JSON.stringify(path);
      if (!reportedUndecryptableSettingPaths.has(pathKey)) {
        reportedUndecryptableSettingPaths.add(pathKey);
        console.warn(
          `Instance sync: setting ${formatSettingPath(path)} cannot be decrypted with SESSION_SECRET or SESSION_SECRET_PREVIOUS; sending it as stored`
        );
      }
      return item;
    }
  });
}

/** The well-formed entries of a payload's settings_secret_paths, as JSON strings. */
function parseSettingSecretPaths(paths: unknown): Set<string> {
  const parsed = new Set<string>();
  if (!Array.isArray(paths)) return parsed;
  for (const path of paths) {
    if (Array.isArray(path) && path.every((part) => typeof part === "string" || typeof part === "number")) {
      parsed.add(JSON.stringify(path));
    }
  }
  return parsed;
}

/**
 * Store a synced setting's secrets under this instance's SESSION_SECRET.
 * Strings the master decrypted for transport (listed in the payload's
 * settings_secret_paths) are encrypted, whatever this release knows about
 * the setting. Ciphertext from an older master (which sent values as stored,
 * under its own key) is re-encrypted when a key here decrypts it and kept as
 * sent otherwise. DNS provider password fields known to this release are
 * encrypted as well, which covers masters that send no secret paths.
 */
function encryptSyncedSettingSecrets(key: string, value: unknown, secretPaths: Set<string>): unknown {
  const encrypted = mapSettingStrings(value, [key], (item, path) => {
    if (isEncryptedSecret(item)) {
      try {
        return reencryptSecret(item, `synced setting ${formatSettingPath(path)}`) ?? item;
      } catch {
        return item;
      }
    }
    return item && secretPaths.has(JSON.stringify(path)) ? encryptSecret(item) : item;
  });
  if (key === "dns_provider") return encryptDnsProviderSettingCredentials(encrypted);
  if (key === "cloudflare") return encryptCloudflareSettingToken(encrypted);
  if (key === "certificate_storage") return encryptCertificateStorageSecrets(encrypted);
  return encrypted;
}

/** Where a secret sits in a sync payload. */
type SyncSecretPlace = Array<string | number>;

/**
 * Apply `transform` to every secret in a payload: the strings at
 * `secretPaths` (see parseSettingSecretPaths) and the certificate private
 * keys. Everything else, key order included, is kept.
 */
function mapSyncSecrets(
  payload: SyncPayload,
  secretPaths: Set<string>,
  transform: (value: string, place: SyncSecretPlace) => string
): SyncPayload {
  const settings = Object.fromEntries(
    Object.entries(payload.settings).map(([group, value]) => [
      group,
      mapSettingStrings(value, [group], (item, path) =>
        secretPaths.has(JSON.stringify(path)) ? transform(item, ["settings", ...path]) : item
      ),
    ])
  ) as SyncSettings;

  return {
    ...payload,
    settings,
    data: {
      ...payload.data,
      certificates: payload.data.certificates.map((certificate) => ({
        ...certificate,
        privateKeyPem: certificate.privateKeyPem
          ? transform(certificate.privateKeyPem, ["data", "certificates", certificate.id, "privateKeyPem"])
          : certificate.privateKeyPem,
      })),
    },
  };
}

/**
 * SHA-256 of a sealed payload as serialized, with every sealed value replaced
 * by the bare prefix. It covers the key id, the slave's nonce and everything
 * sent alongside the secrets.
 */
function sealedPayloadDigest(payload: SyncPayload, secretPaths: Set<string>): string {
  const outline = mapSyncSecrets(payload, secretPaths, () => SEALED_SYNC_SECRET_PREFIX);
  return createHash("sha256").update(JSON.stringify(outline)).digest("hex");
}

/**
 * Associated data for one sealed secret: the payload digest and the secret's
 * place. A sealed value therefore opens only at its place, in the payload it
 * was sealed in; with the nonce, only once.
 */
function syncSecretAad(payloadDigest: string, place: SyncSecretPlace): string {
  return JSON.stringify([payloadDigest, ...place]);
}

/**
 * The payload for one slave, with every secret sealed to that slave's key:
 * the strings at settings_secret_paths and the certificate private keys.
 */
function sealSyncPayload(payload: SyncPayload, target: SyncSealTarget): SyncPayload {
  const secretPaths = parseSettingSecretPaths(payload.settings_secret_paths);
  const addressed: SyncPayload = {
    ...payload,
    secrets_sealed_key_id: target.keyId,
    secrets_sealed_nonce: target.nonce,
  };
  const digest = sealedPayloadDigest(addressed, secretPaths);
  return mapSyncSecrets(addressed, secretPaths, (value, place) =>
    sealSyncSecret(value, target.publicKey, syncSecretAad(digest, place))
  );
}

/**
 * The payload for a pull replica (ee/fleet/pull-server.ts), sealed to the key
 * it presented and proved, with the nonce it issued for this poll: exactly
 * what a push to it would carry.
 */
export function sealSyncPayloadForReplica(payload: SyncPayload, target: SyncSealTarget): SyncPayload {
  return sealSyncPayload(payload, target);
}

/**
 * The payload for a slave from an older release, which cannot open sealed
 * values and stores settings as sent: the settings secrets encrypted with
 * this instance's key, as older masters sent them (a slave that shares
 * SESSION_SECRET can use them), and without settings_secret_paths.
 * Certificate private keys stay decrypted, as older masters sent them.
 */
function legacySyncPayload(payload: SyncPayload): SyncPayload {
  const secretPaths = parseSettingSecretPaths(payload.settings_secret_paths);
  const settings = Object.fromEntries(
    Object.entries(payload.settings).map(([group, value]) => [
      group,
      mapSettingStrings(value, [group], (item, path) =>
        secretPaths.has(JSON.stringify(path)) ? encryptSecret(item) : item
      ),
    ])
  ) as SyncSettings;
  const legacy: SyncPayload = { ...payload, settings };
  delete legacy.settings_secret_paths;
  return legacy;
}

/**
 * Open the secrets of a payload sealed to this instance's key. The payload's
 * nonce is used up first, whatever the outcome. Every path in
 * settings_secret_paths must hold a sealed string, no other setting string
 * may look sealed, and every certificate private key must be sealed;
 * otherwise, or when the payload was sealed to another key, its nonce is
 * unknown, expired or used, or anything fails to open, this throws
 * SyncSealError, so a sealed value is never stored.
 */
function openSealedSyncPayload(payload: SyncPayload, fresh: boolean): SyncPayload {
  if (payload.secrets_sealed_key_id !== getSyncPublicKey().keyId) throw new SyncSealError("key_mismatch");
  if (!fresh) throw new SyncSealError("stale");

  const listedPaths: unknown = payload.settings_secret_paths ?? [];
  const secretPaths = parseSettingSecretPaths(listedPaths);
  if (!Array.isArray(listedPaths) || secretPaths.size !== listedPaths.length) {
    throw new SyncSealError("malformed");
  }
  let listedStrings = 0;
  for (const [group, value] of Object.entries(payload.settings)) {
    // Unlisted strings are left as they are: they are part of the digest every
    // sealed value is bound to, so a sealed value moved to one cannot open.
    mapSettingStrings(value, [group], (item, path) => {
      if (secretPaths.has(JSON.stringify(path))) listedStrings++;
      return item;
    });
  }
  // A listed path that holds no string would not be opened.
  if (listedStrings !== secretPaths.size) throw new SyncSealError("malformed");

  const digest = sealedPayloadDigest(payload, secretPaths);
  return mapSyncSecrets(payload, secretPaths, (value, place) =>
    openSyncSecret(value, syncSecretAad(digest, place))
  );
}

/** The stored configuration a payload is built from: settings as stored and table rows. */
type SyncSource = {
  settings: Record<(typeof SYNC_SETTING_ORDER)[number] | (typeof LIVE_SYNC_SETTINGS)[number], unknown>;
  certificates: Array<typeof certificates.$inferSelect>;
  caCertificates: Array<typeof caCertificates.$inferSelect>;
  issuedClientCertificates: Array<typeof issuedClientCertificates.$inferSelect>;
  accessLists: Array<typeof accessLists.$inferSelect>;
  accessListEntries: Array<typeof accessListEntries.$inferSelect>;
  accessListRules: Array<typeof accessListRules.$inferSelect>;
  proxyHosts: Array<typeof proxyHosts.$inferSelect>;
  l4ProxyHosts: Array<typeof l4ProxyHosts.$inferSelect>;
  wafRuleExclusions: Array<typeof wafRuleExclusions.$inferSelect>;
};

/** The settings groups a payload carries, in the order they are sent. */
const SYNC_SETTING_ORDER = [
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
  "default_response",
  "forward_auth",
  "rate_limit",
  "response_headers",
  "certificate_storage",
] as const;

/**
 * Settings groups a payload carries that are not configuration and so not in
 * configuration revisions (ee/fleet) or history: they always come from the
 * master's current settings, also when a stored revision is promoted.
 */
const LIVE_SYNC_SETTINGS = ["white_label"] as const;

async function readLiveSyncSource(): Promise<SyncSource> {
  const [certRows, caCertRows, issuedClientCertRows, accessListRows, accessEntryRows, accessRuleRows, proxyRows, l4Rows, wafExclusionRows] = await Promise.all([
    appDb.select().from(certificates).orderBy(certificates.id),
    appDb.select().from(caCertificates).orderBy(caCertificates.id),
    appDb.select().from(issuedClientCertificates).orderBy(issuedClientCertificates.id),
    appDb.select().from(accessLists).orderBy(accessLists.id),
    appDb.select().from(accessListEntries).orderBy(accessListEntries.id),
    appDb.select().from(accessListRules).orderBy(accessListRules.id),
    appDb.select().from(proxyHosts).orderBy(proxyHosts.id),
    appDb.select().from(l4ProxyHosts).orderBy(l4ProxyHosts.id),
    appDb.select().from(wafRuleExclusions).orderBy(wafRuleExclusions.id),
  ]);

  const settings = {
    general: await getSetting("general"),
    acme: await getSetting("acme"),
    cloudflare: await getSetting("cloudflare"),
    dns_provider: await getSetting("dns_provider"),
    authentik: await getSetting("authentik"),
    metrics: await getSetting("metrics"),
    logging: await getSetting("logging"),
    dns: await getSetting("dns"),
    upstream_dns_resolution: await getSetting("upstream_dns_resolution"),
    waf: await getSetting("waf"),
    geoblock: await getSetting("geoblock"),
    error_pages: await getSetting("error_pages"),
    trusted_proxies: await getSetting("trusted_proxies"),
    default_response: await getSetting("default_response"),
    forward_auth: await getSetting("forward_auth"),
    rate_limit: await getSetting("rate_limit"),
    response_headers: await getSetting("response_headers"),
    certificate_storage: await getSetting("certificate_storage"),
    white_label: await getSetting(WHITE_LABEL_SETTING_KEY),
  };
  return {
    settings,
    certificates: certRows,
    caCertificates: caCertRows,
    issuedClientCertificates: issuedClientCertRows,
    accessLists: accessListRows,
    accessListEntries: accessEntryRows,
    accessListRules: accessRuleRows,
    proxyHosts: proxyRows,
    l4ProxyHosts: l4Rows,
    wafRuleExclusions: wafExclusionRows,
  };
}

/**
 * A stored row with every column of `table`: a column added after the row
 * was stored (a revision captured by an older release) gets its default, or
 * null.
 */
function withColumnDefaults<T>(table: SQLiteTable, row: Record<string, unknown>): T {
  const complete: Record<string, unknown> = { ...row };
  for (const [key, column] of Object.entries(getTableColumns(table) as Record<string, Column>)) {
    if (complete[key] !== undefined) continue;
    const fallback = column.default;
    complete[key] = fallback !== undefined && (fallback === null || typeof fallback !== "object") ? fallback : null;
  }
  return complete as T;
}

async function syncSourceFromContent(content: ConfigContent): Promise<SyncSource> {
  const rows = <T>(table: SQLiteTable, stored: Array<Record<string, unknown>>): T[] =>
    stored.map((row) => withColumnDefaults<T>(table, row));
  return {
    settings: {
      ...Object.fromEntries(SYNC_SETTING_ORDER.map((key) => [key, content.settings[key] ?? null])),
      ...Object.fromEntries(await Promise.all(LIVE_SYNC_SETTINGS.map(async (key) => [key, await getSetting(key)] as const))),
    } as SyncSource["settings"],
    certificates: rows(certificates, content.tables.certificates),
    caCertificates: rows(caCertificates, content.tables.caCertificates),
    issuedClientCertificates: rows(issuedClientCertificates, content.tables.issuedClientCertificates),
    accessLists: rows(accessLists, content.tables.accessLists),
    accessListEntries: rows(accessListEntries, content.tables.accessListEntries),
    accessListRules: rows(accessListRules, content.tables.accessListRules),
    proxyHosts: rows(proxyHosts, content.tables.proxyHosts),
    l4ProxyHosts: rows(l4ProxyHosts, content.tables.l4ProxyHosts),
    wafRuleExclusions: rows(wafRuleExclusions, content.tables.wafRuleExclusions),
  };
}

async function buildSyncPayloadFromSource(source: SyncSource): Promise<SyncPayload> {
  // Secrets inside settings (DNS provider credentials) are decrypted here,
  // like certificate private keys below, and sealed to each slave's key
  // before sending (see syncToSlave).
  const settingsSecretPaths: SettingPath[] = [];
  // Monetized hosts reach replicas only inside this section, with what their
  // gate needs (null: not served there). Its key digests are sealed below.
  const replicaSection = await buildReplicaSection(source.proxyHosts, source.wafRuleExclusions);
  const sourceSettings: Record<string, unknown> = replicaSection
    ? { ...source.settings, [REPLICA_SETTING_KEY]: replicaSection }
    : source.settings;
  const settings = Object.fromEntries(
    Object.entries(sourceSettings).map(([key, value]) => [key, decryptSettingSecrets(key, value, settingsSecretPaths)])
  ) as SyncSettings;

  const sanitizedAccessLists = source.accessLists.map((row) => ({
    ...row,
    createdBy: null
  }));

  const sanitizedAccessListRules = source.accessListRules.map((row) => ({
    ...row,
    createdBy: null
  }));

  const sanitizedCertificates = source.certificates.map((row) => ({
    ...row,
    providerOptions: sanitizeStoredCertificateProviderOptions(row.providerOptions),
    // The operational value, sealed to each slave's key for transport (see
    // syncToSlave); the slave re-encrypts it with its own SESSION_SECRET.
    privateKeyPem: row.privateKeyPem ? decryptSecret(row.privateKeyPem, "instance sync certificate private key") : null,
    createdBy: null
  }));

  // Slaves only need the CA certificate to verify client certificates; the
  // signing key stays on the master.
  const sanitizedCaCertificates = source.caCertificates.map((row) => ({
    ...row,
    privateKeyPem: null,
    createdBy: null
  }));

  const sanitizedIssuedClientCertificates = source.issuedClientCertificates.map((row) => ({
    ...row,
    createdBy: null
  }));

  // Hosts with API monetization on (ee/monetization) never go in the plain
  // host list: a slave would serve them ungated. Replicas that can gate them
  // get them in the monetization_replica section above.
  const monetizedHostIds = new Set(
    (await appDb.select({ id: monetizationHosts.proxyHostId }).from(monetizationHosts).where(eq(monetizationHosts.enabled, true)))
      .map((row) => row.id)
  );
  const sanitizedProxyHosts = source.proxyHosts
    .filter((row) => !monetizedHostIds.has(row.id))
    .map((row) => ({
      ...row,
      ownerUserId: null
    }));

  const sanitizedL4ProxyHosts = source.l4ProxyHosts.map((row) => ({
    ...row,
    ownerUserId: null
  }));

  // Exclusions of hosts kept on this node stay with them.
  const syncedHostIds = new Set(sanitizedProxyHosts.map((row) => row.id));
  const sanitizedWafExclusions = source.wafRuleExclusions
    .filter((row) => row.proxyHostId === null || syncedHostIds.has(row.proxyHostId))
    .map((row) => ({ ...row, createdBy: null }));

  return {
    generated_at: nowIso(),
    settings,
    settings_secret_paths: settingsSecretPaths,
    data: {
      certificates: sanitizedCertificates,
      caCertificates: sanitizedCaCertificates,
      issuedClientCertificates: sanitizedIssuedClientCertificates,
      accessLists: sanitizedAccessLists,
      accessListEntries: source.accessListEntries,
      accessListRules: sanitizedAccessListRules,
      proxyHosts: sanitizedProxyHosts,
      l4ProxyHosts: sanitizedL4ProxyHosts,
      wafRuleExclusions: sanitizedWafExclusions,
    }
  };
}

/** The payload of the master's current configuration. */
export async function buildSyncPayload(): Promise<SyncPayload> {
  return buildSyncPayloadFromSource(await readLiveSyncSource());
}

/**
 * The payload of stored configuration content (a fleet revision, in the
 * format of src/lib/config-content.ts, secrets encrypted with this
 * instance's key), prepared exactly like the live one: secrets decrypted for
 * sealing, CA signing keys and attribution left out, and hosts with API
 * monetization on (as they are now) kept on this node.
 */
export async function buildSyncPayloadFromContent(content: ConfigContent): Promise<SyncPayload> {
  return buildSyncPayloadFromSource(await syncSourceFromContent(content));
}

/** Canonical content of payloads already fingerprinted, so a sync to many slaves serializes once. */
const canonicalPayloads = new WeakMap<SyncPayload, string>();

/** The sync fingerprint of `payload` for the slave holding `token` (see instance-sync-fingerprint.ts). */
export function syncPayloadFingerprint(payload: SyncPayload, token: string): string {
  let canonical = canonicalPayloads.get(payload);
  if (canonical === undefined) {
    canonical = canonicalSyncContent({ settings: payload.settings, data: payload.data });
    canonicalPayloads.set(payload, canonical);
  }
  return syncFingerprintOfCanonical(canonical, token);
}

function isTimeoutError(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { name?: unknown }).name === "TimeoutError";
}

type SlaveSyncFailure = { ok: false; error: string; status?: number };
/** `legacy`: the slave answered like an older release and got the legacy payload. */
type SlaveSyncResult = { ok: true; legacy?: boolean } | SlaveSyncFailure;

/**
 * The sync endpoint of the slave at `baseUrl`, built from its normalized base
 * URL, the one its sync key pin is kept under (see syncKeyPinIdentity), so
 * that URLs sharing a pin always reach the same endpoint.
 */
function slaveSyncUrl(baseUrl: string): string {
  return `${syncKeyPinIdentity(baseUrl)}/api/instances/sync`;
}

/**
 * Largest slave reply the master reads. Both replies are small JSON (an
 * acknowledgement, or a key with at most MAX_SYNC_KEY_ROTATION_PROOFS proofs);
 * without a limit, a slave or whoever answers at its URL could stream until
 * the master runs out of memory.
 */
const MAX_SLAVE_REPLY_BYTES = 64 * 1024;

/**
 * The JSON body of a slave's reply, or null when it is not JSON or is larger
 * than MAX_SLAVE_REPLY_BYTES (the rest is not read). A timeout is rethrown.
 */
async function readSlaveReplyJson(response: Response): Promise<unknown> {
  try {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_SLAVE_REPLY_BYTES) {
      await response.body?.cancel().catch(() => {});
      return null;
    }
    if (!response.body) return null;
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_SLAVE_REPLY_BYTES) {
        await reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch (error) {
    if (isTimeoutError(error)) throw error;
    return null;
  }
}

/**
 * Fetch a slave's sync public key and a nonce, with the safeguards of the
 * sync POST (no redirects, bounded in time, fixed error messages), sending
 * `challenge` for the slave's rotation proofs. A slave from an older release
 * exports no GET handler for the sync route, so Next.js answers 405: `key` is
 * then null. Any other reply without a key, a 404 included, is a failure.
 */
async function fetchSlaveSyncKey(
  baseUrl: string,
  token: string,
  challenge: SyncKeyChallenge
): Promise<
  | { ok: true; key: SyncSealTarget; rotationProofs: SyncKeyRotationProof[] }
  | { ok: true; key: null }
  | SlaveSyncFailure
> {
  try {
    const response = await fetch(`${slaveSyncUrl(baseUrl)}?${SYNC_KEY_CHALLENGE_PARAM}=${challenge.value}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`
      },
      redirect: "manual",
      signal: AbortSignal.timeout(getSyncRequestTimeoutMs()),
    });
    if (response.status === 405) {
      return { ok: true, key: null };
    }
    if (response.status < 200 || response.status >= 300) {
      return { ok: false, error: `Sync key request failed with HTTP ${response.status}`, status: response.status };
    }
    const body = await readSlaveReplyJson(response);
    const key = parseSyncPublicKeyResponse(body);
    return key
      ? { ok: true, key, rotationProofs: parseSyncKeyRotationProofs(body) }
      : { ok: false, error: SYNC_INVALID_KEY_ERROR, status: response.status };
  } catch (error) {
    return { ok: false, error: isTimeoutError(error) ? SYNC_TIMED_OUT_ERROR : "Sync request failed" };
  }
}

/**
 * POST the sync payload to one slave. Redirects are not followed (the body
 * carries key material, unsealed for slaves from older releases, and must
 * only reach the configured URL), the request is bounded in time, and only a
 * 2xx `{ ok: true }` reply from an Ingressi slave counts as success. Failures carry
 * a fixed message that is safe to store and show (see instance-sync-error.ts).
 */
async function postSyncPayload(
  baseUrl: string,
  token: string,
  payload: SyncPayload
): Promise<SlaveSyncResult> {
  try {
    const response = await fetch(slaveSyncUrl(baseUrl), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload),
      redirect: "manual",
      signal: AbortSignal.timeout(getSyncRequestTimeoutMs()),
    });
    if (response.status < 200 || response.status >= 300) {
      return { ok: false, error: `Sync failed with HTTP ${response.status}`, status: response.status };
    }
    const body = await readSlaveReplyJson(response) as { ok?: unknown } | null;
    return body?.ok === true
      ? { ok: true }
      : { ok: false, error: SYNC_NOT_ACKNOWLEDGED_ERROR, status: response.status };
  } catch (error) {
    return { ok: false, error: isTimeoutError(error) ? SYNC_TIMED_OUT_ERROR : "Sync request failed" };
  }
}

type SyncSlave = {
  /** Tells slaves apart in this process's reports. */
  id: string;
  name: string;
  baseUrl: string;
  token: string;
  /** Set for instances configured in the database; used in audit events. */
  instanceId?: number;
  /** From INSTANCE_SLAVES; see EnvSlaveInstance. */
  syncKeyId?: string;
  /** From INSTANCE_SLAVES, raw; see EnvSlaveInstance. */
  syncPublicKey?: Buffer;
};

/** How a presented key compares with the slave's pin; see checkSlaveSyncKey. */
type SyncKeyCheck =
  | { outcome: "pinned" | "matched" | "unreadable" | "slave_changed" }
  | { outcome: "rotated" | "changed"; pinnedKeyId: string };

/** Slaves already reported as receiving the legacy payload. */
const reportedLegacySlaves = new Set<string>();
/** The sync key problem last reported for each slave and kind of problem. */
const reportedSyncKeyProblems = new Map<string, string>();

/**
 * Log a sync key problem of `slave` unless the same problem (`kind` and
 * `detail`, such as the key ids involved) was the last one of its kind
 * reported for it, so a lasting problem is logged once and a slave presenting
 * a new key every time cannot grow what is remembered.
 */
function reportSyncKeyProblemOnce(slave: SyncSlave, kind: string, detail: unknown[], message: string) {
  const reportKey = JSON.stringify([slave.id, slave.baseUrl, kind]);
  const reportDetail = JSON.stringify(detail);
  if (reportedSyncKeyProblems.get(reportKey) === reportDetail) return;
  reportedSyncKeyProblems.set(reportKey, reportDetail);
  console.warn(message);
}

/**
 * Whether the instance `instanceId` still exists with the base URL a sync of
 * `baseUrl` started with. Synchronous, so it can run inside the pin store's
 * transaction.
 */
async function instanceStillAt(instanceId: number, baseUrl: string): Promise<boolean> {
  const row = await first(appDb.select({ baseUrl: instances.baseUrl }).from(instances).where(eq(instances.id, instanceId)).limit(1));
  return row !== undefined && syncKeyPinIdentity(row.baseUrl) === syncKeyPinIdentity(baseUrl);
}

/**
 * Check the key a slave presented against its pin (see
 * instance-sync-key-pins.ts) before anything is sealed to it. A
 * syncPublicKey or syncKeyId from INSTANCE_SLAVES must match exactly.
 * Otherwise the first key a slave presents is pinned, and a different key is
 * accepted, and pinned in its place, only with a rotation proof by the pinned
 * key for this key request's challenge; a pin this release cannot read
 * matches no key. Returns the failure, or null when the payload may be sealed
 * to the key. Pinning and re-pinning are logged and audited; key ids are
 * logged, never keys or tokens.
 */
async function checkSlaveSyncKey(
  slave: SyncSlave,
  key: SyncSealTarget,
  rotationProofs: readonly SyncKeyRotationProof[],
  challenge: SyncKeyChallenge
): Promise<SlaveSyncFailure | null> {
  if (slave.syncPublicKey !== undefined || slave.syncKeyId !== undefined) {
    const matches = slave.syncPublicKey !== undefined
      ? slave.syncPublicKey.equals(key.publicKey)
      : key.keyId === slave.syncKeyId;
    if (matches) return null;
    reportSyncKeyProblemOnce(
      slave,
      "config",
      [slave.syncKeyId, key.keyId],
      `Instance sync: slave "${slave.name}" presented sync key ${key.keyId}, but INSTANCE_SLAVES pins ` +
      `${slave.syncKeyId}; not syncing.`
    );
    return { ok: false, error: SYNC_KEY_CONFIG_MISMATCH_ERROR };
  }

  const check = await updateSyncKeyPin<SyncKeyCheck>(slave.baseUrl, async (pin) => {
    if (!pin) {
      // The instance may have been removed, or moved to another URL, while
      // its key was fetched; pinning for it now would leave a pin behind that
      // nothing uses (see releaseSyncKeyPin in models/instances.ts).
      if (slave.instanceId !== undefined && !await instanceStillAt(slave.instanceId, slave.baseUrl)) {
        return { result: { outcome: "slave_changed" } };
      }
      return { result: { outcome: "pinned" }, pin: { publicKey: key.publicKey, source: "first-use" } };
    }
    if (isUnreadableSyncKeyPin(pin)) return { result: { outcome: "unreadable" } };
    const pinned = { keyId: pin.keyId, publicKey: Buffer.from(pin.publicKey, "base64") };
    if (pinned.keyId === key.keyId && pinned.publicKey.equals(key.publicKey)) {
      return { result: { outcome: "matched" } };
    }
    if (verifySyncKeyRotationProof(challenge, pinned, key, rotationProofs)) {
      return {
        result: { outcome: "rotated", pinnedKeyId: pin.keyId },
        pin: { publicKey: key.publicKey, source: "rotation" },
      };
    }
    return { result: { outcome: "changed", pinnedKeyId: pin.keyId } };
  });

  const auditData = { identity: syncKeyPinIdentity(slave.baseUrl), keyId: key.keyId };
  switch (check.outcome) {
    case "matched":
      return null;
    case "pinned":
      console.log(`Instance sync: pinned sync key ${key.keyId} of slave "${slave.name}" on first use`);
      await logAuditEvent({
        action: "instance_sync_key_pinned",
        entityType: "instance",
        entityId: slave.instanceId ?? null,
        summary: `Pinned sync key ${key.keyId} of slave "${slave.name}" on first use`,
        data: { ...auditData, source: "first-use" },
      });
      return null;
    case "rotated":
      console.log(
        `Instance sync: slave "${slave.name}" proved its new sync key ${key.keyId} with the pinned key ` +
        `${check.pinnedKeyId}; pinned the new key`
      );
      await logAuditEvent({
        action: "instance_sync_key_rotated",
        entityType: "instance",
        entityId: slave.instanceId ?? null,
        summary: `Re-pinned sync key of slave "${slave.name}" from ${check.pinnedKeyId} to ${key.keyId} (rotation proof)`,
        data: { ...auditData, previousKeyId: check.pinnedKeyId, source: "rotation" },
      });
      return null;
    case "changed":
      reportSyncKeyProblemOnce(
        slave,
        "pin",
        [check.pinnedKeyId, key.keyId],
        `Instance sync: slave "${slave.name}" presented sync key ${key.keyId}, but ${check.pinnedKeyId} is pinned ` +
        "and the slave sent no valid rotation proof; not syncing. If the slave's SESSION_SECRET was rotated, set " +
        "SESSION_SECRET_PREVIOUS on the slave to the old value until the next sync; otherwise pin the key the " +
        "slave's own Instance sync page shows (or reset its key pin)."
      );
      return { ok: false, error: SYNC_KEY_CHANGED_ERROR };
    case "unreadable":
      reportSyncKeyProblemOnce(
        slave,
        "pin",
        ["unreadable", key.keyId],
        `Instance sync: the sync key pin stored for slave "${slave.name}" cannot be read by this release; not ` +
        `syncing. It presented sync key ${key.keyId}; pin the key the slave's own Instance sync page shows (or reset its ` +
        "key pin)."
      );
      return { ok: false, error: SYNC_KEY_CHANGED_ERROR };
    case "slave_changed":
      return { ok: false, error: SYNC_SLAVE_CHANGED_DURING_SYNC_ERROR };
  }
}

/**
 * Sync one slave: fetch its key, check it against the slave's pin, seal the
 * payload's secrets to it and POST the result. A slave from an older release,
 * which has no key endpoint, gets the legacy payload (see legacySyncPayload)
 * unless it has a pinned key (it published one before, or an admin pinned
 * one) or a key set in INSTANCE_SLAVES; that is reported once per slave.
 * Slaves are told apart by `id` and base URL.
 */
async function syncToSlave(slave: SyncSlave, payload: SyncPayload): Promise<SlaveSyncResult> {
  const slaveKey = JSON.stringify([slave.id, slave.baseUrl]);
  const challenge = createSyncKeyChallenge();
  const keyResult = await fetchSlaveSyncKey(slave.baseUrl, slave.token, challenge);
  if (!keyResult.ok) return keyResult;

  if (!keyResult.key) {
    // A downgrade, or something else answering at the slave's address.
    if (slave.syncKeyId !== undefined || (await getSyncKeyPin(slave.baseUrl))) {
      reportSyncKeyProblemOnce(
        slave,
        "405",
        [],
        `Instance sync: slave "${slave.name}" has a pinned sync key but answered the key request with HTTP 405; ` +
        "not sending it the legacy payload. If the slave was downgraded, reset its key pin (or remove the syncKeyId " +
        "and syncPublicKey of its INSTANCE_SLAVES entry)."
      );
      return { ok: false, error: "Sync key request failed with HTTP 405", status: 405 };
    }
    if (!reportedLegacySlaves.has(slaveKey)) {
      reportedLegacySlaves.add(slaveKey);
      console.warn(
        `Instance sync: slave "${slave.name}" does not publish a sync key (older release); ` +
        "sending certificate private keys unsealed over the authenticated sync channel and settings " +
        "secrets encrypted with this instance's SESSION_SECRET. Upgrade the slave to seal them."
      );
    }
    const legacyResult = await postSyncPayload(slave.baseUrl, slave.token, legacySyncPayload(payload));
    return legacyResult.ok ? { ok: true, legacy: true } : legacyResult;
  }

  let sealed: SyncPayload;
  try {
    // parseSyncPublicKeyResponse already refused keys the key exchange
    // rejects (low-order points), so a payload without secrets never pins
    // one; sealing before the key is checked keeps it that way.
    sealed = sealSyncPayload(payload, keyResult.key);
  } catch (error) {
    if (!(error instanceof SyncSealError)) throw error;
    return { ok: false, error: SYNC_INVALID_KEY_ERROR };
  }
  const refusal = await checkSlaveSyncKey(slave, keyResult.key, keyResult.rotationProofs, challenge);
  if (refusal) return refusal;
  return postSyncPayload(slave.baseUrl, slave.token, sealed);
}

type InstanceRow = typeof instances.$inferSelect;

/** Why nothing is pushed to, or asked of, a pull replica. */
export const PULL_REPLICA_NOT_PUSHED_ERROR = "Pull replicas fetch their configuration from the master; nothing is pushed to them";

function isPullInstance(instance: Pick<InstanceRow, "syncMode">): boolean {
  return instance.syncMode === "pull";
}

/**
 * Check the key a pull replica presented (and proved, see
 * ee/fleet/pull-server.ts) against its pin, exactly as a push checks a
 * slave's key: the first key is pinned, a different one is accepted only
 * with a rotation proof by the pinned key for `challenge`, and pinning is
 * logged and audited. The pin is kept under the replica's identity (its
 * "pull:" base URL). Returns null when secrets may be sealed to the key, or
 * the fixed reason they may not.
 */
export async function checkPullReplicaSyncKey(
  instance: Pick<InstanceRow, "id" | "name" | "baseUrl">,
  key: SyncSealTarget,
  rotationProofs: readonly SyncKeyRotationProof[],
  challenge: SyncKeyChallenge
): Promise<string | null> {
  const refusal = await checkSlaveSyncKey(
    { id: `instance:${instance.id}`, name: instance.name, baseUrl: instance.baseUrl, token: "", instanceId: instance.id },
    key,
    rotationProofs,
    challenge
  );
  return refusal ? refusal.error : null;
}

/** How a push to one instance configured in the database went. */
export type InstanceSyncOutcome =
  | { ok: true }
  | { ok: false; error: string; skippedHttp: boolean };

/**
 * Push `payload` to one slave configured in the database (`instance`), with
 * every safeguard of a sync: the stored token is decrypted and checked
 * against the token policy, plain HTTP is refused unless
 * INSTANCE_SYNC_ALLOW_HTTP is set, and the push goes through syncToSlave (key
 * pinning, sealed secrets, no redirects, timeouts, fixed error messages).
 * Records the result on the instance and, after a success, what was pushed
 * for fleet management (`revisionId`: the fleet revision, null for the live
 * configuration). Throws only on unexpected errors.
 */
export async function syncInstanceWithPayload(
  instance: InstanceRow,
  payload: SyncPayload,
  options: { revisionId?: number | null; httpAllowed?: boolean } = {}
): Promise<InstanceSyncOutcome> {
  // A pull replica has no URL to push to; it fetches what it should run.
  if (isPullInstance(instance)) return { ok: false, error: PULL_REPLICA_NOT_PUSHED_ERROR, skippedHttp: false };
  if (!isEncryptedSecret(instance.apiToken)) {
    try {
      await updateInstance(instance.id, { apiToken: instance.apiToken });
    } catch (error) {
      console.warn(`Failed to encrypt stored token for instance "${instance.name}":`, error);
    }
  }

  let token: string;
  try {
    token = decryptSecret(instance.apiToken, `instance "${instance.name}" API token`);
  } catch {
    const message = "Stored token could not be decrypted";
    await recordInstanceSyncResult(instance.id, { ok: false, error: message });
    return { ok: false, error: message, skippedHttp: false };
  }

  if (!isValidInstanceSyncToken(token)) {
    const message = "Stored instance sync token does not meet the current security policy";
    console.warn(`Skipping sync to "${instance.name}": ${message}`);
    await recordInstanceSyncResult(instance.id, { ok: false, error: message });
    return { ok: false, error: message, skippedHttp: false };
  }

  // Check for HTTP URL
  if (isHttpUrl(instance.baseUrl) && !(options.httpAllowed ?? isHttpSyncAllowed())) {
    const message = "HTTP sync blocked. Set INSTANCE_SYNC_ALLOW_HTTP=true to allow insecure sync.";
    console.warn(`Skipping sync to "${instance.name}": ${message}`);
    await recordInstanceSyncResult(instance.id, { ok: false, error: message });
    return { ok: false, error: message, skippedHttp: true };
  }

  const result = await syncToSlave(
    { id: `instance:${instance.id}`, name: instance.name, baseUrl: instance.baseUrl, token, instanceId: instance.id },
    payload
  );
  if (!result.ok) {
    await recordInstanceSyncResult(instance.id, { ok: false, error: result.error });
    return { ok: false, error: sanitizeInstanceSyncError(result.error) ?? "Previous synchronization failed", skippedHttp: false };
  }
  await recordInstanceSyncResult(instance.id, { ok: true });
  try {
    await recordFleetPush(instance.id, {
      revisionId: options.revisionId ?? null,
      fingerprint: syncPayloadFingerprint(payload, token),
      legacy: result.legacy === true,
    });
  } catch (error) {
    // Bookkeeping for drift detection only; the sync itself succeeded.
    console.warn(`Could not record the sync to "${instance.name}" for fleet management:`, error instanceof Error ? error.name : typeof error);
  }
  return { ok: true };
}

/** INSTANCE_SLAVES entries already reported as skipped for pointing at a pinned instance. */
const reportedPinnedEnvSlaves = new Set<string>();

export type SyncInstancesResult = { total: number; success: number; failed: number; skippedHttp: number };

/**
 * The cluster lock (src/lib/db/locks.ts) a sync to the slaves holds from
 * building the payload to the last push: syncs never overlap, on any
 * replica, so the last payload a slave receives is built from the latest
 * committed data. The periodic sync skips its round while one runs.
 */
export const INSTANCE_SYNC_LOCK = "instance-sync";

/**
 * Pushes the current configuration to every slave that receives every
 * change (master mode only). A call made while another call of this process
 * waits for the lock shares that call's sync, which starts after both.
 */
export async function syncInstances(): Promise<SyncInstancesResult> {
  if ((await getInstanceMode()) !== "master") {
    return { total: 0, success: 0, failed: 0, skippedHttp: 0 };
  }
  return await withCoalescedClusterLock(INSTANCE_SYNC_LOCK, () => syncInstancesHoldingLock());
}

async function syncInstancesHoldingLock(): Promise<SyncInstancesResult> {
  const mode = await getInstanceMode();
  if (mode !== "master") {
    return { total: 0, success: 0, failed: 0, skippedHttp: 0 };
  }

  // Get database-configured instances. Instances in a promotion-only fleet
  // environment (ee/fleet) only receive the configuration their environment
  // is pinned to, through rollouts; every other instance gets every change.
  // Pull replicas fetch it themselves on their next poll.
  const pinned = await listPinnedInstanceIds();
  const enabledInstances = await appDb.query.instances.findMany({
    where: (table, operators) => operators.eq(table.enabled, true)
  });
  const dbTargets = enabledInstances.filter((instance) => !pinned.has(instance.id) && !isPullInstance(instance));

  // Get environment-configured instances. An INSTANCE_SLAVES entry for the
  // URL of a pinned instance would push every change past the promotion, so
  // it is skipped (and reported once).
  const pinnedIdentities = new Set(
    pinned.size === 0
      ? []
      : (await appDb.select({ id: instances.id, baseUrl: instances.baseUrl }).from(instances))
        .filter((row) => pinned.has(row.id))
        .map((row) => syncKeyPinIdentity(row.baseUrl))
  );
  const envTargets = getEnvSlaveInstances().filter((instance) => {
    if (!pinnedIdentities.has(syncKeyPinIdentity(instance.url))) return true;
    if (!reportedPinnedEnvSlaves.has(instance.name)) {
      reportedPinnedEnvSlaves.add(instance.name);
      console.warn(
        `Instance sync: INSTANCE_SLAVES entry "${instance.name}" has the URL of an instance in a promotion-only ` +
        "fleet environment; not syncing it. Remove the entry: the instance receives its environment's revision."
      );
    }
    return false;
  });

  if (dbTargets.length === 0 && envTargets.length === 0) {
    return { total: 0, success: 0, failed: 0, skippedHttp: 0 };
  }

  const httpAllowed = isHttpSyncAllowed();
  const payload = await buildSyncPayload();

  // Sync database-configured instances
  const dbResults = await Promise.all(
    dbTargets.map(async (instance) => {
      const outcome = await syncInstanceWithPayload(instance, payload, { revisionId: null, httpAllowed });
      return { ok: outcome.ok, skippedHttp: !outcome.ok && outcome.skippedHttp };
    })
  );

  // Sync environment-configured instances
  const envResults = await Promise.all(
    envTargets.map(async (instance) => {
      // Check for HTTP URL
      if (isHttpUrl(instance.url) && !httpAllowed) {
        console.warn(`Skipping sync to env-configured instance "${instance.name}": HTTP sync blocked. Set INSTANCE_SYNC_ALLOW_HTTP=true to allow insecure sync.`);
        return { ok: false, skippedHttp: true };
      }

      const result = await syncToSlave(
        {
          id: `env:${instance.name}`,
          name: instance.name,
          baseUrl: instance.url,
          token: instance.token,
          syncKeyId: instance.syncKeyId,
          syncPublicKey: instance.syncPublicKey === undefined ? undefined : Buffer.from(instance.syncPublicKey, "base64"),
        },
        payload
      );
      if (result.ok) {
        console.log(`Sync to env-configured instance "${instance.name}" succeeded`);
        return { ok: true, skippedHttp: false };
      }
      console.error("Environment-configured instance sync failed", {
        instanceName: instance.name,
        reason: result.error,
        ...(result.status === undefined ? {} : { status: result.status }),
      });
      return { ok: false, skippedHttp: false };
    })
  );

  const allResults = [...dbResults, ...envResults];
  const success = allResults.filter((r) => r.ok).length;
  const skippedHttp = allResults.filter((r) => r.skippedHttp).length;
  const failed = allResults.length - success - skippedHttp;

  return { total: allResults.length, success, failed, skippedHttp };
}

/**
 * Entry point for the periodic sync timer. A tick that fires while a sync
 * is running or waiting anywhere in the deployment (the previous periodic
 * sync still waiting on a slow slave, a sync after a change, a sync on
 * another replica) is skipped (returns null), so ticks never pile up, each
 * holding a full payload with decrypted key material, when the request
 * timeout exceeds the interval. Syncs triggered by config changes call
 * syncInstances() directly.
 */
export async function runPeriodicInstanceSync(): Promise<SyncInstancesResult | null> {
  const outcome = await tryWithClusterLock(INSTANCE_SYNC_LOCK, () => syncInstancesHoldingLock());
  return outcome.acquired ? outcome.value : null;
}

/** Longest a status or health request may take; they are small and must not hold up a rollout. */
const MAX_STATUS_TIMEOUT_MS = 15_000;

function statusRequestTimeoutMs(): number {
  return Math.min(getSyncRequestTimeoutMs(), MAX_STATUS_TIMEOUT_MS);
}

/** How asking a slave for its status went. `status` is null for a slave from an older release. */
export type InstanceStatusResult =
  | { reachable: false; error: string }
  | { reachable: true; status: ReplicaSyncStatus | null };

/** The token of a database-configured slave, or the fixed reason it cannot be used. */
function usableInstanceToken(instance: InstanceRow): { token: string } | { error: string } {
  let token: string;
  try {
    token = decryptSecret(instance.apiToken, `instance "${instance.name}" API token`);
  } catch {
    return { error: "Stored token could not be decrypted" };
  }
  if (!isValidInstanceSyncToken(token)) {
    return { error: "Stored instance sync token does not meet the current security policy" };
  }
  if (isHttpUrl(instance.baseUrl) && !isHttpSyncAllowed()) {
    return { error: "HTTP sync blocked. Set INSTANCE_SYNC_ALLOW_HTTP=true to allow insecure sync." };
  }
  return { token };
}

/**
 * Ask a slave configured in the database which configuration it runs (GET
 * /api/instances/sync?status=1, authenticated like the sync, see
 * instance-sync-status.ts). The request has the safeguards of the sync: the
 * token is checked first, plain HTTP needs INSTANCE_SYNC_ALLOW_HTTP,
 * redirects are not followed, it is bounded in time and the reply in size,
 * and failures carry fixed messages. A slave from an older release answers
 * 405 (no key endpoint) or with its sync key and no status: `status` is then
 * null, not a failure.
 */
export async function fetchInstanceSyncStatus(instance: InstanceRow): Promise<InstanceStatusResult> {
  // A pull replica reports its status with every poll (ee/fleet/pull-server.ts).
  if (isPullInstance(instance)) return { reachable: false, error: PULL_REPLICA_NOT_PUSHED_ERROR };
  const usable = usableInstanceToken(instance);
  if ("error" in usable) return { reachable: false, error: usable.error };
  try {
    const response = await fetch(`${slaveSyncUrl(instance.baseUrl)}?${SYNC_STATUS_PARAM}=1`, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${usable.token}` },
      redirect: "manual",
      signal: AbortSignal.timeout(statusRequestTimeoutMs()),
    });
    if (response.status === 405) {
      await response.body?.cancel().catch(() => {});
      return { reachable: true, status: null };
    }
    if (response.status < 200 || response.status >= 300) {
      await response.body?.cancel().catch(() => {});
      return { reachable: false, error: `Status request failed with HTTP ${response.status}` };
    }
    const parsed = parseReplicaSyncStatus(await readSlaveReplyJson(response));
    if (parsed.kind === "invalid") return { reachable: false, error: "Slave returned an invalid status" };
    return { reachable: true, status: parsed.kind === "ok" ? parsed.status : null };
  } catch (error) {
    return { reachable: false, error: isTimeoutError(error) ? "Status request timed out" : "Status request failed" };
  }
}

/**
 * Whether a slave configured in the database answers its health endpoint
 * (GET /api/health) with `{ "status": "ok" }`. Sent without the sync token,
 * with the same limits as the status request.
 */
export async function fetchInstanceHealth(instance: InstanceRow): Promise<{ ok: true } | { ok: false; error: string }> {
  if (isPullInstance(instance)) return { ok: false, error: PULL_REPLICA_NOT_PUSHED_ERROR };
  if (isHttpUrl(instance.baseUrl) && !isHttpSyncAllowed()) {
    return { ok: false, error: "HTTP sync blocked. Set INSTANCE_SYNC_ALLOW_HTTP=true to allow insecure sync." };
  }
  try {
    const response = await fetch(`${syncKeyPinIdentity(instance.baseUrl)}/api/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(statusRequestTimeoutMs()),
    });
    if (response.status < 200 || response.status >= 300) {
      await response.body?.cancel().catch(() => {});
      return { ok: false, error: `Health check failed with HTTP ${response.status}` };
    }
    const body = await readSlaveReplyJson(response) as { status?: unknown } | null;
    return body?.status === "ok" ? { ok: true } : { ok: false, error: "Health check did not report ok" };
  } catch (error) {
    return { ok: false, error: isTimeoutError(error) ? "Health check timed out" : "Health check failed" };
  }
}

/**
 * Store a sync payload as this slave's configuration, pushed or pulled.
 * Secrets sealed to this instance's key are opened before anything is
 * written; a payload that does not open throws SyncSealError and changes
 * nothing. Returns the payload's sync fingerprint for this slave's token
 * (undefined without a token), which is recorded once Caddy accepted the
 * configuration (see instance-sync-apply.ts and instance-sync-status.ts).
 */
export async function applySyncPayload(received: SyncPayload): Promise<AppliedSync> {
  // The nonce is used up first, whatever the outcome (on PostgreSQL, for every replica: src/lib/sync-nonces.ts).
  const payload = received.secrets_sealed_key_id === undefined && received.secrets_sealed_nonce === undefined
    ? received
    : openSealedSyncPayload(received, isSyncNonce(received.secrets_sealed_nonce) && await useSyncNonce(received.secrets_sealed_nonce));
  const syncedSettings: Array<[string, unknown]> = [
    ["general", payload.settings.general],
    ["acme", payload.settings.acme ?? null],
    ["cloudflare", payload.settings.cloudflare],
    ["dns_provider", payload.settings.dns_provider ?? null],
    ["authentik", payload.settings.authentik],
    ["metrics", payload.settings.metrics],
    ["logging", payload.settings.logging],
    ["dns", payload.settings.dns],
    ["upstream_dns_resolution", payload.settings.upstream_dns_resolution ?? null],
    ["waf", payload.settings.waf ?? null],
    ["geoblock", payload.settings.geoblock ?? null],
    ["error_pages", payload.settings.error_pages ?? null],
    ["trusted_proxies", payload.settings.trusted_proxies ?? null],
    ["forward_auth", payload.settings.forward_auth ?? null],
    ["default_response", payload.settings.default_response ?? null],
    ["rate_limit", payload.settings.rate_limit ?? null],
    ["response_headers", payload.settings.response_headers ?? null],
    ["certificate_storage", payload.settings.certificate_storage ?? null],
    [WHITE_LABEL_SETTING_KEY, payload.settings.white_label ?? null],
    // API monetization on replicas (validated with the payload).
    [REPLICA_SETTING_KEY, payload.settings.monetization_replica ?? null],
  ];
  const replicaSection = parseReplicaSection(payload.settings.monetization_replica ?? null);
  const secretPaths = parseSettingSecretPaths(payload.settings_secret_paths);
  const syncedSettingsToStore = syncedSettings.map(
    ([key, value]) => [key, encryptSyncedSettingSecrets(key, value, secretPaths)] as const
  );
  const settingsUpdatedAt = nowIso();

  // Settings are written in the same transaction as the tables, so a payload
  // that fails part-way leaves neither applied.
  await appDb.transaction(async (tx) => {
    for (const [key, value] of syncedSettingsToStore) {
      const serialized = JSON.stringify(value ?? null);
      await tx.insert(settingsTable)
        .values({ key: `${SYNCED_PREFIX}${key}`, value: serialized, updatedAt: settingsUpdatedAt })
        .onConflictDoUpdate({ target: settingsTable.key, set: { value: serialized, updatedAt: settingsUpdatedAt } });
    }
    await tx.delete(wafRuleExclusions);
    await tx.delete(l4ProxyHosts);
    await tx.delete(proxyHosts);
    await tx.delete(accessListRules);
    await tx.delete(accessListEntries);
    await tx.delete(accessLists);
    await tx.delete(issuedClientCertificates);
    await tx.delete(certificates);
    await tx.delete(caCertificates);

    if (payload.data.certificates.length > 0) {
      await tx.insert(certificates).values(payload.data.certificates.map((certificate) => ({
        ...certificate,
        providerOptions: sanitizeStoredCertificateProviderOptions(certificate.providerOptions),
        privateKeyPem: certificate.privateKeyPem
          ? encryptSecret(certificate.privateKeyPem)
          : null,
      })));
    }
    if (payload.data.caCertificates && payload.data.caCertificates.length > 0) {
      await tx.insert(caCertificates).values(payload.data.caCertificates.map((ca) => ({
        ...ca,
        // Never accept a CA signing key over sync (older masters sent it).
        privateKeyPem: null,
      })));
    }
    if (payload.data.issuedClientCertificates && payload.data.issuedClientCertificates.length > 0) {
      await tx.insert(issuedClientCertificates).values(payload.data.issuedClientCertificates);
    }
    if (payload.data.accessLists.length > 0) {
      await tx.insert(accessLists).values(payload.data.accessLists);
    }
    if (payload.data.accessListEntries.length > 0) {
      await tx.insert(accessListEntries).values(payload.data.accessListEntries);
    }
    // Absent in payloads from older masters: their lists have no rules.
    const rules = payload.data.accessListRules ?? [];
    for (let index = 0; index < rules.length; index += 200) {
      await tx.insert(accessListRules).values(rules.slice(index, index + 200));
    }
    if (payload.data.proxyHosts.length > 0) {
      await tx.insert(proxyHosts).values(payload.data.proxyHosts);
    }
    // Monetized hosts, gated by this replica's gate with the master's balances.
    if (replicaSection && replicaSection.proxyHosts.length > 0) {
      await tx.insert(proxyHosts).values(replicaSection.proxyHosts as Array<typeof proxyHosts.$inferInsert>);
    }
    if (payload.data.l4ProxyHosts && payload.data.l4ProxyHosts.length > 0) {
      await tx.insert(l4ProxyHosts).values(payload.data.l4ProxyHosts);
    }
    // Older masters send no exclusion records: the slave keeps none, and the
    // excluded_rule_ids lists in the synced settings and host meta apply.
    if (payload.data.wafRuleExclusions && payload.data.wafRuleExclusions.length > 0) {
      await tx.insert(wafRuleExclusions).values(payload.data.wafRuleExclusions.map((row) => ({ ...row, createdBy: null })));
    }
    if (replicaSection && replicaSection.wafRuleExclusions.length > 0) {
      await tx.insert(wafRuleExclusions).values(
        (replicaSection.wafRuleExclusions as Array<typeof wafRuleExclusions.$inferInsert>).map((row) => ({ ...row, createdBy: null }))
      );
    }
    // The rows keep the master's ids: on PostgreSQL this database's
    // identities move past them, for rows created here later.
    for (const table of [certificates, caCertificates, issuedClientCertificates, accessLists, accessListEntries, accessListRules, proxyHosts, l4ProxyHosts, wafRuleExclusions]) {
      await resyncIdentity(table, tx);
    }
  });
  // The branding is validated again when it is read (ee/white-label/store.ts).
  await refreshBranding();
  // The gate learns the monetized hosts (or forgets them) before Caddy routes to it.
  try {
    const { reloadMonetization } = await import("@/ee/monetization/engine");
    await reloadMonetization({ quiet: true });
  } catch (error) {
    console.warn("Instance sync: could not reload the API monetization gate:", error instanceof Error ? error.name : typeof error);
  }

  // If the synced L4 proxy hosts require different ports than currently applied,
  // write the override file and trigger the sidecar to recreate the caddy container.
  const diff = await getL4PortsDiff();
  if (diff.needsApply) {
    await applyL4Ports();
  }

  // The route authenticated the master with this token (a pull replica: the
  // token derived from its pull credential, see ee/fleet/pull-config.ts); a token
  // that cannot be read now only leaves the fingerprint unrecorded.
  const token = await getSlaveFingerprintToken().catch(() => null);
  return token ? { fingerprint: syncContentFingerprint({ settings: payload.settings, data: payload.data }, token) } : undefined;
}
