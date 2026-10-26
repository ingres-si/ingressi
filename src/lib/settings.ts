import { AsyncLocalStorage } from "node:async_hooks";
import { appDb, nowIso } from "./db";
import { settings } from "./db/schema";
import { eq, inArray } from "drizzle-orm";
import { encryptSecret, isEncryptedSecret } from "./secret";
import { sanitizeErrorPageRules, type ErrorPageRule } from "./models/proxy-hosts";
import {
  normalizeDefaultResponseSettings,
  type DefaultResponseSettings,
} from "./caddy-default-response";
import { normalizeRateLimitSettings, readStoredRateLimitSettings } from "./caddy-rate-limit";
import type { RateLimitSettings } from "./rate-limit-rules";
import { storedWafTuning, type WafTuningSettings } from "./waf-tuning";
import { replaceWholeScopeExclusions, syncWafExclusionMirror } from "./models/waf-exclusion-mirror";

export type { DefaultResponseSettings } from "./caddy-default-response";
export type { RateLimitSettings } from "./rate-limit-rules";

export type SettingValue<T> = T | null;

export type CloudflareSettings = {
  apiToken: string;
  zoneId?: string;
  accountId?: string;
};

export type GeneralSettings = {
  primaryDomain: string;
  acmeEmail?: string;
};

export type AcmeSettings = {
  /** Custom ACME directory URL (e.g. an internal CA). Empty = Let's Encrypt default. */
  caUrl?: string;
  /** PEM-encoded trusted root for the ACME CA's HTTPS endpoint, if not in the system trust store. */
  caRootPem?: string;
};

export type AuthentikSettings = {
  outpostDomain: string;
  outpostUpstream: string;
  authEndpoint?: string;
};

export type ForwardAuthSettings = {
  /** Preset used to prefill new proxy hosts: "authelia" or "custom". */
  provider: "authelia" | "custom";
  /** Base URL of the default forward-auth server, e.g. http://authelia:9091 */
  authUpstream: string;
  /** Optional default auth endpoint (provider presets supply one otherwise). */
  authEndpoint?: string;
};

export type MetricsSettings = {
  enabled: boolean;
  port?: number; // Port to expose metrics on (default: 9090, separate from admin API)
};

export type LoggingSettings = {
  enabled: boolean;
  format?: "json" | "console"; // Log format (default: json)
};

export type TrustedProxiesSettings = {
  // Proxy ranges to trust for X-Forwarded-For / client IP resolution at the
  // server level (Caddy `trusted_proxies`). Accepts CIDRs, bare IPs, and the
  // "private_ranges" shorthand. Empty = feature disabled (current behaviour).
  ranges: string[];
  // Headers Caddy reads the real client IP from (Caddy `client_ip_headers`).
  // Empty = Caddy default of X-Forwarded-For. Useful for e.g. Cf-Connecting-Ip.
  client_ip_headers?: string[];
  // Only trust client_ip_headers from the configured proxies, rejecting
  // spoofed values from untrusted peers (Caddy `trusted_proxies_strict`).
  strict?: boolean;
  // When true, use `ranges` as the default trusted-proxy list for global
  // geoblocking so the two settings can't silently disagree.
  default_geoblock?: boolean;
  // Load balancers allowed to send a PROXY protocol header on ports 80 and
  // 443 (Caddy's `proxy_protocol` listener wrapper; src/lib/proxy-protocol.ts).
  // IPs and CIDRs, no private_ranges. Empty = no PROXY protocol.
  proxy_protocol_ranges?: string[];
};

export type DnsSettings = {
  enabled: boolean;
  resolvers: string[]; // Primary DNS resolvers (e.g., "1.1.1.1", "8.8.8.8")
  fallbacks?: string[]; // Fallback DNS resolvers if primary fails
  timeout?: string; // DNS query timeout (e.g., "5s")
};

export type DnsProviderSettings = {
  /** Configured providers: keyed by provider name, value is credential map */
  providers: Record<string, Record<string, string>>;
  /** Name of the default provider (null = no DNS-01 challenges) */
  default: string | null;
};

export type UpstreamDnsAddressFamily = "ipv6" | "ipv4" | "both";

export type UpstreamDnsResolutionSettings = {
  enabled: boolean;
  family: UpstreamDnsAddressFamily;
};

export type GeoBlockSettings = {
  enabled: boolean;

  // Block rules
  block_countries: string[];    // ISO 3166-1 alpha-2, e.g. ["CN", "RU"]
  block_continents: string[];   // AF, AN, AS, EU, NA, OC, SA
  block_asns: number[];
  block_cidrs: string[];
  block_ips: string[];

  // Allow rules (win over block rules)
  allow_countries: string[];
  allow_continents: string[];
  allow_asns: number[];
  allow_cidrs: string[];
  allow_ips: string[];

  // Trusted proxies for X-Forwarded-For parsing
  trusted_proxies: string[];
  // When true, block requests where the real client IP cannot be determined
  // (e.g. connection from trusted proxy but no usable XFF entry). Default: false (fail-open)
  fail_closed: boolean;

  // Block response customization
  response_status: number;        // default 403
  response_body: string;          // default "Forbidden"
  response_headers: Record<string, string>;
  redirect_url: string;           // if set, 302 redirect instead of status/body
};

type InstanceMode = "standalone" | "master" | "slave";

const INSTANCE_MODE_KEY = "instance_mode";
const SYNCED_PREFIX = "synced:";

// ── Settings snapshots ──

/**
 * The settings a snapshot (withSettingsSnapshot) has read: the stored value
 * of each key (null when the key is not set), as a promise so that callers
 * running side by side share one read.
 */
type SettingsSnapshot = { values: Map<string, Promise<string | null>>; closed: boolean };

const snapshotGlobal = globalThis as typeof globalThis & {
  __ingressiSettingsSnapshotStorage?: AsyncLocalStorage<SettingsSnapshot>;
};
const snapshotStorage = (snapshotGlobal.__ingressiSettingsSnapshotStorage ??= new AsyncLocalStorage<SettingsSnapshot>());

function openSnapshot(): SettingsSnapshot | null {
  const snapshot = snapshotStorage.getStore();
  return snapshot && !snapshot.closed ? snapshot : null;
}

/**
 * Runs `fn`, which only reads, with every setting it reads through this
 * module read once: `keys` (with the synced copies a slave reads and the
 * instance mode) in one query up front, any other key when first asked for.
 * The Caddy configuration build reads some twenty settings, each behind the
 * instance mode; on PostgreSQL every read is a round trip. A setting `fn`
 * writes through setSetting or clearSetting is read back as written; a
 * setting written elsewhere meanwhile is not seen, as in one transaction.
 */
export async function withSettingsSnapshot<T>(keys: readonly string[], fn: () => Promise<T>): Promise<T> {
  if (openSnapshot()) return await fn();
  const wanted = [...new Set([INSTANCE_MODE_KEY, ...keys, ...keys.map((key) => `${SYNCED_PREFIX}${key}`)])];
  const loaded = appDb
    .select({ key: settings.key, value: settings.value })
    .from(settings)
    .where(inArray(settings.key, wanted))
    .then((rows) => new Map(rows.map((row) => [row.key, row.value])));
  const snapshot: SettingsSnapshot = { values: new Map(), closed: false };
  for (const key of wanted) {
    const value = loaded.then((rows) => rows.get(key) ?? null);
    // A failed read reaches the callers that ask for the key, not the process.
    value.catch(() => undefined);
    snapshot.values.set(key, value);
  }
  try {
    return await snapshotStorage.run(snapshot, fn);
  } finally {
    snapshot.closed = true;
  }
}

async function readStoredSetting(key: string): Promise<string | null> {
  const snapshot = openSnapshot();
  const remembered = snapshot?.values.get(key);
  if (remembered) return await remembered;
  const read = appDb.query.settings
    .findFirst({ where: (table, { eq }) => eq(table.key, key) })
    .then((row) => row?.value ?? null);
  snapshot?.values.set(key, read);
  return await read;
}

/** Keeps an open snapshot in step with a write made inside it. */
function rememberWrite(key: string, value: string | null): void {
  openSnapshot()?.values.set(key, Promise.resolve(value));
}

export async function getSetting<T>(key: string): Promise<SettingValue<T>> {
  const value = await readStoredSetting(key);
  if (value === null) {
    return null;
  }

  try {
    return JSON.parse(value) as T;
  } catch (error) {
    console.warn(`Failed to parse setting ${key}`, error);
    return null;
  }
}

/**
 * This instance's mode as the settings layer sees it (the environment first,
 * then the stored mode); a slave reads synced:* values.
 */
export async function getInstanceModeForSettings(): Promise<InstanceMode> {
  // Environment variable takes precedence — mirrors getInstanceMode() in
  // instance-sync.ts. An env-configured slave never writes the mode to the DB
  // (setInstanceMode refuses when env-set), so reading the DB alone here would
  // report "standalone" and getEffectiveSetting would never serve synced:* values.
  const envMode = process.env.INSTANCE_MODE;
  if (envMode === "master" || envMode === "slave" || envMode === "standalone") {
    return envMode;
  }

  const stored = await getSetting<string>(INSTANCE_MODE_KEY);
  if (stored === "master" || stored === "slave" || stored === "standalone") {
    return stored;
  }
  return "standalone";
}

async function getSyncedSetting<T>(key: string): Promise<SettingValue<T>> {
  return await getSetting<T>(`${SYNCED_PREFIX}${key}`);
}

export async function getEffectiveSetting<T>(key: string): Promise<SettingValue<T>> {
  const mode = await getInstanceModeForSettings();
  if (mode !== "slave") {
    return await getSetting<T>(key);
  }

  const override = await getSetting<T>(key);
  if (override !== null) {
    return override;
  }

  return await getSyncedSetting<T>(key);
}

export async function setSetting<T>(key: string, value: T): Promise<void> {
  const payload = JSON.stringify(value);
  const now = nowIso();

  await appDb
    .insert(settings)
    .values({
      key,
      value: payload,
      updatedAt: now
    })
    .onConflictDoUpdate({
      target: settings.key,
      set: {
        value: payload,
        updatedAt: now
      }
    });
  rememberWrite(key, payload);
}

/**
 * Writes `value` only if the setting does not exist yet, and returns what is
 * stored either way: when two writers race, the first one wins for both.
 */
export async function setSettingIfAbsent<T>(key: string, value: T): Promise<SettingValue<T>> {
  const payload = JSON.stringify(value);
  await appDb.insert(settings).values({ key, value: payload, updatedAt: nowIso() }).onConflictDoNothing({ target: settings.key });
  const row = await appDb.query.settings.findFirst({ where: (table, { eq }) => eq(table.key, key) });
  const stored = row?.value ?? payload;
  rememberWrite(key, stored);
  try {
    return JSON.parse(stored) as T;
  } catch {
    return null;
  }
}

/** When a setting was last written (ISO time), or null when it is not set. */
export async function getSettingUpdatedAt(key: string): Promise<string | null> {
  const row = await appDb.query.settings.findFirst({ where: (table, { eq }) => eq(table.key, key) });
  return row?.updatedAt ?? null;
}

export async function clearSetting(key: string): Promise<void> {
  await appDb.delete(settings).where(eq(settings.key, key));
  rememberWrite(key, null);
}

export async function getCloudflareSettings(): Promise<CloudflareSettings | null> {
  return await getEffectiveSetting<CloudflareSettings>("cloudflare");
}

/**
 * The legacy cloudflare setting with its API token encrypted. Only the
 * token's presence is ever read, but it is a live credential. Anything that is
 * not a settings object with a plaintext token is returned unchanged.
 */
export function encryptCloudflareSettingToken(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const { apiToken } = value as { apiToken?: unknown };
  if (typeof apiToken !== "string" || !apiToken || isEncryptedSecret(apiToken)) return value;
  return { ...value, apiToken: encryptSecret(apiToken) };
}

export async function saveCloudflareSettings(settings: CloudflareSettings): Promise<void> {
  await setSetting("cloudflare", encryptCloudflareSettingToken(settings));
}

export async function getGeneralSettings(): Promise<GeneralSettings | null> {
  return await getEffectiveSetting<GeneralSettings>("general");
}

export async function saveGeneralSettings(settings: GeneralSettings): Promise<void> {
  await setSetting("general", settings);
}

export async function getAcmeSettings(): Promise<AcmeSettings | null> {
  return await getEffectiveSetting<AcmeSettings>("acme");
}

export async function saveAcmeSettings(settings: AcmeSettings): Promise<void> {
  await setSetting("acme", settings);
}

export async function getAuthentikSettings(): Promise<AuthentikSettings | null> {
  return await getEffectiveSetting<AuthentikSettings>("authentik");
}

export async function saveAuthentikSettings(settings: AuthentikSettings): Promise<void> {
  await setSetting("authentik", settings);
}

export async function getForwardAuthSettings(): Promise<ForwardAuthSettings | null> {
  return await getEffectiveSetting<ForwardAuthSettings>("forward_auth");
}

export async function saveForwardAuthSettings(settings: ForwardAuthSettings): Promise<void> {
  await setSetting("forward_auth", settings);
}

export async function getMetricsSettings(): Promise<MetricsSettings | null> {
  return await getEffectiveSetting<MetricsSettings>("metrics");
}

export async function saveMetricsSettings(settings: MetricsSettings): Promise<void> {
  await setSetting("metrics", settings);
}

export async function getLoggingSettings(): Promise<LoggingSettings | null> {
  return await getEffectiveSetting<LoggingSettings>("logging");
}

export async function saveLoggingSettings(settings: LoggingSettings): Promise<void> {
  await setSetting("logging", settings);
}

export async function getTrustedProxiesSettings(): Promise<TrustedProxiesSettings | null> {
  return await getEffectiveSetting<TrustedProxiesSettings>("trusted_proxies");
}

export async function saveTrustedProxiesSettings(settings: TrustedProxiesSettings): Promise<void> {
  await setSetting("trusted_proxies", settings);
}

export async function getDnsSettings(): Promise<DnsSettings | null> {
  return await getEffectiveSetting<DnsSettings>("dns");
}

export async function saveDnsSettings(settings: DnsSettings): Promise<void> {
  await setSetting("dns", settings);
}

export async function getDnsProviderSettings(): Promise<DnsProviderSettings | null> {
  const raw = await getEffectiveSetting<Record<string, unknown>>("dns_provider");
  if (!raw) return null;

  // Normalize old single-provider format { provider, credentials }
  // to new multi-provider format { providers, default }
  if ("provider" in raw && "credentials" in raw && !("providers" in raw)) {
    const name = raw.provider as string;
    const creds = raw.credentials as Record<string, string>;
    return { providers: { [name]: creds }, default: name };
  }

  return raw as unknown as DnsProviderSettings;
}

export async function saveDnsProviderSettings(settings: DnsProviderSettings): Promise<void> {
  await setSetting("dns_provider", settings);
}

export async function getUpstreamDnsResolutionSettings(): Promise<UpstreamDnsResolutionSettings | null> {
  return await getEffectiveSetting<UpstreamDnsResolutionSettings>("upstream_dns_resolution");
}

export async function saveUpstreamDnsResolutionSettings(settings: UpstreamDnsResolutionSettings): Promise<void> {
  await setSetting("upstream_dns_resolution", settings);
}

export async function getGeoBlockSettings(): Promise<GeoBlockSettings | null> {
  return await getEffectiveSetting<GeoBlockSettings>("geoblock");
}

export async function saveGeoBlockSettings(settings: GeoBlockSettings): Promise<void> {
  await setSetting("geoblock", settings);
}

export type WafSettings = WafTuningSettings & {
  // Whether the WAF applies to every proxy host ("Apply to all hosts"); when
  // false only hosts that turn their WAF section on use it.
  enabled: boolean;
  // The global mode, as Coraza's SecRuleEngine values: Off, DetectionOnly
  // (log, never block) or On (blocking). buildWafHandler rejects anything
  // else. Hosts that inherit their mode use it.
  mode: 'Off' | 'On' | 'DetectionOnly';
  load_owasp_crs: boolean;
  custom_directives: string;
  // Whole-scope global rule exclusions. Mirrors the waf_rule_exclusions rows
  // without a host, path or variable (src/lib/models/waf-exclusions.ts).
  excluded_rule_ids?: number[];
  // Request body limits, in bytes. Unset means Coraza's own default applies
  // (12.5 MiB from @coraza.conf-recommended when load_owasp_crs is on, else
  // 128 MiB). Coraza caps both at 1 GiB — see CORAZA_MAX_BODY_LIMIT.
  request_body_limit?: number;
  request_body_in_memory_limit?: number;
  // ProcessPartial inspects the leading bytes and forwards the rest instead of
  // rejecting oversized uploads outright.
  request_body_limit_action?: 'Reject' | 'ProcessPartial';
};

export async function getWafSettings(): Promise<WafSettings | null> {
  return await getEffectiveSetting<WafSettings>("waf");
}

/**
 * Stores the global WAF settings. Tuning fields are kept only where they
 * differ from the CRS defaults. `excluded_rule_ids` is the legacy view of the
 * global whole-scope rule exclusions: a list replaces those records (each
 * record created gets `actorUserId` as its author); no list keeps them. Either
 * way the stored list is rewritten from the records, in the same transaction.
 */
export async function saveWafSettings(s: WafSettings, options: { actorUserId?: number | null } = {}): Promise<void> {
  const {
    excluded_rule_ids: excluded,
    paranoia_level: _paranoia,
    detection_paranoia_level: _detection,
    inbound_anomaly_threshold: _inbound,
    outbound_anomaly_threshold: _outbound,
    anomaly_action: _action,
    ...rest
  } = s;
  void [_paranoia, _detection, _inbound, _outbound, _action];
  const value = JSON.stringify({ ...rest, ...storedWafTuning(s) });
  const now = nowIso();
  await appDb.transaction(async (tx) => {
    await tx.insert(settings)
      .values({ key: "waf", value, updatedAt: now })
      .onConflictDoUpdate({ target: settings.key, set: { value, updatedAt: now } });
    if (Array.isArray(excluded)) await replaceWholeScopeExclusions(tx, null, excluded, options.actorUserId ?? null);
    else await syncWafExclusionMirror(tx, null);
  });
}

// Global error pages, applied as fallback error routes across every proxy host.
// Per-host error pages take precedence over these.
export type ErrorPagesSettings = {
  rules: ErrorPageRule[];
};

export async function getErrorPagesSettings(): Promise<ErrorPagesSettings | null> {
  return await getEffectiveSetting<ErrorPagesSettings>("error_pages");
}

export async function saveErrorPagesSettings(s: ErrorPagesSettings): Promise<void> {
  await setSetting("error_pages", { rules: sanitizeErrorPageRules(s?.rules) });
}

// Response for requests that do not match any configured proxy host. A missing
// setting (or mode "caddy") preserves Caddy's native routing/HTTPS behavior.
export async function getDefaultResponseSettings(): Promise<DefaultResponseSettings | null> {
  const value = await getEffectiveSetting<unknown>("default_response");
  if (value === null) return null;

  try {
    return normalizeDefaultResponseSettings(value);
  } catch (error) {
    console.warn("Ignoring invalid default response settings", error);
    return null;
  }
}

export async function saveDefaultResponseSettings(value: DefaultResponseSettings): Promise<void> {
  await setSetting("default_response", normalizeDefaultResponseSettings(value));
}

// Rate limiting defaults: rules that hosts inherit, merge or
// override, and the client ranges no rule limits. See caddy-rate-limit.ts.
export async function getRateLimitSettings(): Promise<RateLimitSettings | null> {
  return readStoredRateLimitSettings(await getEffectiveSetting<unknown>("rate_limit"));
}

export async function saveRateLimitSettings(value: RateLimitSettings): Promise<void> {
  await setSetting("rate_limit", normalizeRateLimitSettings(value));
}
