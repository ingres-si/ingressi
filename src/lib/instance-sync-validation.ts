/**
 * Validation of a sync payload a slave received, pushed by its master
 * (app/api/instances/sync/route.ts) or pulled by a pull replica
 * (ee/fleet/pull-agent.ts): the structure, and the content checks that keep
 * a compromised master or a stolen sync credential from injecting
 * configuration the dashboard would never write. Messages are fixed or name
 * only the offending row.
 */
import { extractL4ListenPort, isReservedL4Port } from "./l4-reserved-ports";
import { isSyncKeyId, isSyncNonce } from "./sync-crypto";
import type { SyncPayload } from "./instance-sync";
import { brandName } from "@/ee/white-label/store";
import { replicaSectionError } from "@/ee/monetization/replica-index";
import { isHttpSyncAllowed } from "./instance-sync-http";
import {
  BLOCKED_SOURCES_KEY,
  isRuleAction,
  isRuleKind,
  normalizeListSettings,
  normalizeRuleValue,
} from "./access-list-rules";

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isNullableNumber(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isFinite(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function validateArray<T>(value: unknown, validator: (item: unknown) => item is T): value is T[] {
  return Array.isArray(value) && value.every(validator);
}

function isCertificate(value: unknown): value is SyncPayload["data"]["certificates"][number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isString(value.name) &&
    isString(value.type) &&
    isString(value.domainNames) &&
    isBoolean(value.autoRenew) &&
    isNullableString(value.providerOptions) &&
    isNullableString(value.certificatePem) &&
    isNullableString(value.privateKeyPem) &&
    isNullableNumber(value.createdBy) &&
    isString(value.createdAt) &&
    isString(value.updatedAt)
  );
}

function isAccessList(value: unknown): value is SyncPayload["data"]["accessLists"][number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isString(value.name) &&
    isNullableString(value.description) &&
    isNullableNumber(value.createdBy) &&
    isString(value.createdAt) &&
    isString(value.updatedAt) &&
    // Rule settings: missing in payloads from masters older than access list rules.
    (value.defaultAction === undefined || isString(value.defaultAction)) &&
    (value.denyStatus === undefined || isNumber(value.denyStatus)) &&
    (value.denyBody === undefined || isNullableString(value.denyBody)) &&
    (value.denyRedirectUrl === undefined || isNullableString(value.denyRedirectUrl)) &&
    (value.failClosed === undefined || isBoolean(value.failClosed)) &&
    (value.skipAuthForAllowed === undefined || isBoolean(value.skipAuthForAllowed)) &&
    (value.systemKey === undefined || isNullableString(value.systemKey))
  );
}

function isAccessListRule(value: unknown): value is NonNullable<SyncPayload["data"]["accessListRules"]>[number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isNumber(value.accessListId) &&
    isNumber(value.position) &&
    isString(value.action) &&
    isString(value.kind) &&
    isString(value.matchValues) &&
    isNullableString(value.note) &&
    isNullableString(value.expiresAt) &&
    isNullableNumber(value.createdBy) &&
    isString(value.createdAt) &&
    isString(value.updatedAt)
  );
}

/**
 * Access list settings a master sends must be ones the dashboard would
 * write: they end up in the Caddy configuration (status, body, redirect).
 */
function validateAccessListContent(list: Record<string, unknown>): string | null {
  try {
    normalizeListSettings({
      defaultAction: list.defaultAction,
      denyStatus: list.denyStatus,
      denyBody: list.denyBody,
      denyRedirectUrl: list.denyRedirectUrl,
    });
  } catch {
    return `Access list ${list.id} has invalid rule settings`;
  }
  if (list.systemKey !== undefined && list.systemKey !== null && list.systemKey !== BLOCKED_SOURCES_KEY) {
    return `Access list ${list.id} has an unknown system key`;
  }
  return null;
}

/** Rules a master sends must hold values the dashboard would write, for lists it sends. */
function validateAccessListRuleContent(rule: Record<string, unknown>, listIds: ReadonlySet<number>): string | null {
  if (!listIds.has(rule.accessListId as number)) return `Access list rule ${rule.id} belongs to no access list`;
  if (!isRuleAction(rule.action) || !isRuleKind(rule.kind)) return `Access list rule ${rule.id} is invalid`;
  const kind = rule.kind;
  if (typeof rule.matchValues !== "string" || rule.matchValues.length > 100_000) return `Access list rule ${rule.id} is invalid`;
  let values: unknown;
  try {
    values = JSON.parse(rule.matchValues);
  } catch {
    return `Access list rule ${rule.id} is invalid`;
  }
  if (!Array.isArray(values) || values.length === 0) return `Access list rule ${rule.id} is invalid`;
  for (const value of values) {
    if (typeof value !== "string" || "error" in normalizeRuleValue(kind, value)) {
      return `Access list rule ${rule.id} has an invalid value`;
    }
  }
  return null;
}

function isCaCertificate(value: unknown): value is SyncPayload["data"]["caCertificates"][number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isString(value.name) &&
    isString(value.certificatePem) &&
    isNullableString(value.privateKeyPem) &&
    isNullableNumber(value.createdBy) &&
    isString(value.createdAt) &&
    isString(value.updatedAt)
  );
}

function isIssuedClientCertificate(value: unknown): value is SyncPayload["data"]["issuedClientCertificates"][number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isNumber(value.caCertificateId) &&
    isString(value.commonName) &&
    isString(value.serialNumber) &&
    isString(value.fingerprintSha256) &&
    isString(value.certificatePem) &&
    isString(value.validFrom) &&
    isString(value.validTo) &&
    isNullableString(value.revokedAt) &&
    isNullableNumber(value.createdBy) &&
    isString(value.createdAt) &&
    isString(value.updatedAt)
  );
}

function isAccessListEntry(value: unknown): value is SyncPayload["data"]["accessListEntries"][number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isNumber(value.accessListId) &&
    isString(value.username) &&
    isString(value.passwordHash) &&
    isString(value.createdAt) &&
    isString(value.updatedAt)
  );
}

function isWafRuleExclusion(value: unknown): value is NonNullable<SyncPayload["data"]["wafRuleExclusions"]>[number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isNumber(value.ruleId) &&
    isNullableNumber(value.proxyHostId) &&
    isNullableString(value.pathMatch) &&
    isNullableString(value.path) &&
    isNullableString(value.variable) &&
    isString(value.reason) &&
    isNullableNumber(value.createdBy) &&
    isString(value.createdAt) &&
    isString(value.updatedAt)
  );
}

function isProxyHost(value: unknown): value is SyncPayload["data"]["proxyHosts"][number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isString(value.name) &&
    isString(value.domains) &&
    isString(value.upstreams) &&
    isNullableNumber(value.certificateId) &&
    isNullableNumber(value.accessListId) &&
    isNullableNumber(value.ownerUserId) &&
    isBoolean(value.sslForced) &&
    isBoolean(value.hstsEnabled) &&
    isBoolean(value.hstsSubdomains) &&
    isBoolean(value.allowWebsocket) &&
    isBoolean(value.preserveHostHeader) &&
    isNullableString(value.meta) &&
    isBoolean(value.enabled) &&
    isString(value.createdAt) &&
    isString(value.updatedAt) &&
    isBoolean(value.skipHttpsHostnameValidation) &&
    (value.tags === undefined || isString(value.tags))
  );
}

function isL4ProxyHost(value: unknown): value is NonNullable<SyncPayload["data"]["l4ProxyHosts"]>[number] {
  if (!isRecord(value)) return false;
  return (
    isNumber(value.id) &&
    isString(value.name) &&
    isString(value.protocol) &&
    isString(value.listenAddress) &&
    isString(value.upstreams) &&
    isString(value.matcherType) &&
    isNullableString(value.matcherValue) &&
    isBoolean(value.tlsTermination) &&
    isNullableString(value.proxyProtocolVersion) &&
    isBoolean(value.proxyProtocolReceive) &&
    isNullableNumber(value.ownerUserId) &&
    isNullableString(value.meta) &&
    isBoolean(value.enabled) &&
    isString(value.createdAt) &&
    isString(value.updatedAt) &&
    (value.tags === undefined || isString(value.tags))
  );
}

/**
 * Validate semantic content of L4 proxy host fields. The listen port must not
 * collide with the ports Ingressi's generated Caddy config always binds itself
 * (HTTP 80/443, admin API 2019) — two listeners on the same port silently
 * split connections via SO_REUSEPORT (issue #295).
 */
function validateL4ProxyHostContent(host: Record<string, unknown>): string | null {
  if (isString(host.listenAddress) && isReservedL4Port(host.listenAddress)) {
    const port = extractL4ListenPort(host.listenAddress);
    return `L4 proxy host ${host.id}: listen port ${port} is reserved for ${brandName()}'s own Caddy listeners (HTTP 80/443, admin API 2019)`;
  }
  return null;
}

/**
 * Validate semantic content of proxy host fields to prevent
 * config injection via compromised master or stolen sync token.
 */
function validateProxyHostContent(host: Record<string, unknown>): string | null {
  // Validate domains are valid hostnames
  if (typeof host.domains === "string" && host.domains) {
    try {
      const domains = JSON.parse(host.domains);
      if (Array.isArray(domains)) {
        for (const d of domains) {
          if (typeof d !== "string" || d.length > 253) {
            return `Invalid domain in proxy host ${host.id}: ${String(d).slice(0, 50)}`;
          }
        }
      }
    } catch {
      // domains might be comma-separated string; just check length
      if (host.domains.length > 5000) {
        return `Proxy host ${host.id} domains field too large`;
      }
    }
  }

  // Validate upstreams don't target dangerous internal services
  if (typeof host.upstreams === "string" && host.upstreams) {
    try {
      const upstreams = JSON.parse(host.upstreams);
      if (Array.isArray(upstreams)) {
        for (const u of upstreams) {
          if (typeof u !== "string") continue;
          const lower = u.toLowerCase();
          // Block cloud metadata endpoints
          if (lower.includes("169.254.169.254") || lower.includes("metadata.google")) {
            return `Proxy host ${host.id} upstream targets blocked metadata endpoint: ${u.slice(0, 80)}`;
          }
        }
      }
    } catch {
      // non-JSON upstreams — skip
    }
  }

  // Validate meta field size to prevent oversized config injection
  if (typeof host.meta === "string" && host.meta && host.meta.length > 100_000) {
    return `Proxy host ${host.id} meta field exceeds 100KB limit`;
  }

  return null;
}

/**
 * Validates that the payload has the expected structure for syncing
 */
export function isValidSyncPayload(payload: unknown): payload is SyncPayload {
  if (payload === null || typeof payload !== "object") {
    return false;
  }

  const p = payload as Record<string, unknown>;

  // Check required top-level properties
  if (!("generated_at" in p) || !("settings" in p) || !("data" in p)) {
    return false;
  }

  if (!isString(p.generated_at)) {
    return false;
  }

  // Validate settings is an object
  if (p.settings !== null && typeof p.settings !== "object") {
    return false;
  }

  // A sealed payload carries a key id and a nonce, and must say exactly where
  // its sealed settings secrets are. Unsealed payloads keep the lenient
  // handling of settings_secret_paths.
  if (p.secrets_sealed_key_id !== undefined || p.secrets_sealed_nonce !== undefined) {
    if (!isSyncKeyId(p.secrets_sealed_key_id)) {
      return false;
    }
    if (!isSyncNonce(p.secrets_sealed_nonce)) {
      return false;
    }
    if (
      p.settings_secret_paths !== undefined &&
      !validateArray(p.settings_secret_paths, (path): path is unknown[] =>
        Array.isArray(path) && path.length > 0 && path.every((part) => isString(part) || isNumber(part)))
    ) {
      return false;
    }
  }

  // Validate data has required array properties
  const data = p.data;
  if (data === null || typeof data !== "object") {
    return false;
  }

  const d = data as Record<string, unknown>;

  // l4ProxyHosts is optional for backward compatibility with older master instances
  if (d.l4ProxyHosts !== undefined && !validateArray(d.l4ProxyHosts, isL4ProxyHost)) {
    return false;
  }
  // So are the WAF rule exclusions. Their paths and variables are validated
  // again when the WAF directives are built (src/lib/waf-exclusions.ts).
  if (d.wafRuleExclusions !== undefined && !validateArray(d.wafRuleExclusions, isWafRuleExclusion)) {
    return false;
  }

  // accessListRules is optional for backward compatibility with older master instances
  if (d.accessListRules !== undefined && !validateArray(d.accessListRules, isAccessListRule)) {
    return false;
  }

  return (
    validateArray(d.certificates, isCertificate) &&
    validateArray(d.caCertificates, isCaCertificate) &&
    validateArray(d.issuedClientCertificates, isIssuedClientCertificate) &&
    validateArray(d.accessLists, isAccessList) &&
    validateArray(d.accessListEntries, isAccessListEntry) &&
    validateArray(d.proxyHosts, isProxyHost)
  );
}

/**
 * Why `payload` cannot be applied, or null when it may be: "Invalid sync
 * payload structure", or the first content check that fails.
 */
export function syncPayloadValidationError(payload: unknown): string | null {
  if (!isValidSyncPayload(payload)) return "Invalid sync payload structure";
  for (const list of payload.data.accessLists) {
    const error = validateAccessListContent(list as unknown as Record<string, unknown>);
    if (error) return error;
  }
  const listIds = new Set(payload.data.accessLists.map((list) => list.id));
  for (const rule of payload.data.accessListRules ?? []) {
    const error = validateAccessListRuleContent(rule as unknown as Record<string, unknown>, listIds);
    if (error) return error;
  }
  for (const host of payload.data.proxyHosts) {
    const error = validateProxyHostContent(host as unknown as Record<string, unknown>);
    if (error) return error;
  }
  // l4ProxyHosts is optional for backward compatibility with older master instances.
  for (const host of payload.data.l4ProxyHosts ?? []) {
    const error = validateL4ProxyHostContent(host as unknown as Record<string, unknown>);
    if (error) return error;
  }
  // API monetization on replicas: its hosts get the same checks as the others.
  const replica = isRecord(payload.settings) ? (payload.settings as Record<string, unknown>).monetization_replica : null;
  const replicaError = replicaSectionError(replica ?? null, {
    isProxyHost,
    isWafRuleExclusion,
    proxyHostContentError: validateProxyHostContent,
    allowHttpGate: isHttpSyncAllowed(),
  });
  if (replicaError) return replicaError;
  const plainHostIds = new Set(payload.data.proxyHosts.map((host) => host.id));
  if (isRecord(replica) && Array.isArray(replica.proxyHosts) && replica.proxyHosts.some((host) => isRecord(host) && plainHostIds.has(host.id as number))) {
    return "Invalid API monetization replica section";
  }
  return null;
}

/** The payload with the parts older masters leave out filled in (l4ProxyHosts, wafRuleExclusions, accessListRules). */
export function normalizeSyncPayload(payload: SyncPayload): SyncPayload {
  return {
    ...payload,
    data: {
      ...payload.data,
      l4ProxyHosts: payload.data.l4ProxyHosts ?? [],
      wafRuleExclusions: payload.data.wafRuleExclusions ?? [],
      accessListRules: payload.data.accessListRules ?? [],
    },
  };
}
