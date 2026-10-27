/**
 * "The configuration": everything stored in the database that decides what
 * Caddy serves. Configuration export/import and configuration
 * history (ee/config-history) read and replace exactly this set.
 *
 * Included: proxy hosts, L4 proxy hosts, access lists with their entries and rules,
 * certificates (as stored), CA certificates, issued client certificates,
 * mTLS roles, role assignments and access rules, forward-auth groups and
 * per-host forward-auth access grants, WAF rule exclusions, and the settings groups managed by
 * /api/v1/settings/{group} plus the certificate storage of
 * /api/v1/high-availability/storage (CONFIG_SETTING_KEYS).
 *
 * Deliberately excluded, so that replacing the configuration can never lock
 * anybody out of the dashboard or sign anybody in: users, group memberships,
 * dashboard sessions, sign-in accounts and OAuth state, OAuth providers, API
 * tokens, audit events, instances and sync tokens/keys, forward-auth sessions,
 * the instance mode and every other settings key.
 *
 * Rows are kept as stored: secret columns stay encrypted with this instance's
 * key (see secret.ts) and nothing here decrypts them.
 */
import { eq, getTableColumns, getTableName, inArray, type Column } from "drizzle-orm";
import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import { appDb, nowIso } from "./db";
import {
  accessListEntries,
  accessListRules,
  accessLists,
  caCertificates,
  certificates,
  forwardAuthAccess,
  forwardAuthExchanges,
  forwardAuthRedirectIntents,
  forwardAuthSessions,
  groupMembers,
  groups,
  issuedClientCertificates,
  l4ProxyHosts,
  mtlsAccessRules,
  mtlsCertificateRoles,
  mtlsRoles,
  proxyHosts,
  settings,
  users,
  wafRuleExclusions,
} from "./db/schema";
import { isEncryptedSecret, reencryptSecret } from "./secret";
import { encryptDnsProviderSettingCredentials } from "./dns-providers";
import { encryptCloudflareSettingToken } from "./settings";
import { encryptCertificateStorageSecrets } from "@/ee/high-availability/settings";
import { importLegacyWafExclusions } from "./models/waf-exclusion-mirror";
import type { AppTx } from "@/src/lib/db/types";
import { pgIntegerType } from "@/src/lib/db/pg-column-types";
import { resyncIdentity } from "@/src/lib/db/ops";

export type DbTransaction = AppTx;

export const CONFIG_CONTENT_VERSION = 1;

/**
 * Storage keys of the settings groups that /api/v1/settings/{group} manages
 * (SETTINGS_HANDLERS), and the certificate storage (ee/high-availability).
 * The instance mode and the sync token are not part of the configuration.
 */
export const CONFIG_SETTING_KEYS = [
  "general",
  "acme",
  "cloudflare",
  "dns_provider",
  "authentik",
  "forward_auth",
  "metrics",
  "logging",
  "dns",
  "upstream_dns_resolution",
  "geoblock",
  "waf",
  "error_pages",
  "default_response",
  "trusted_proxies",
  "rate_limit",
  "response_headers",
  "certificate_storage",
] as const;
export type ConfigSettingKey = (typeof CONFIG_SETTING_KEYS)[number];

export const CONFIG_SETTING_LABELS: Record<ConfigSettingKey, string> = {
  general: "General",
  acme: "ACME",
  cloudflare: "Cloudflare (legacy)",
  dns_provider: "DNS providers",
  authentik: "Authentik defaults",
  forward_auth: "Forward auth defaults",
  metrics: "Metrics",
  logging: "Logging",
  dns: "DNS resolvers",
  upstream_dns_resolution: "Upstream DNS resolution",
  geoblock: "Geoblocking",
  waf: "WAF",
  error_pages: "Error pages",
  default_response: "Default response",
  trusted_proxies: "Trusted proxies",
  rate_limit: "Rate limiting",
  response_headers: "Response headers",
  certificate_storage: "Certificate storage",
};

export type ConfigRow = Record<string, unknown>;

/** How a secret column is protected at rest. */
export type SecretProtection = "encrypted" | "hash";

type Reference = {
  column: string;
  target: ConfigTableName | "users";
  /** "drop" removes the row when the target is missing; "null" clears the column. */
  onMissing: "drop" | "null";
};

type TableSpec = {
  table: SQLiteTable;
  singular: string;
  plural: string;
  /** Columns that only record which user created or owns the row. */
  attributionColumns: readonly string[];
  references: readonly Reference[];
  secretColumns: Readonly<Record<string, SecretProtection>>;
  describe: (row: ConfigRow) => string;
};

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function describeRuleValues(value: unknown): string {
  try {
    const values = JSON.parse(text(value));
    if (!Array.isArray(values)) return "";
    const shown = values.slice(0, 3).map(String).join(", ");
    return values.length > 3 ? `${shown}, ...` : shown;
  } catch {
    return "";
  }
}

/**
 * The configuration tables, parents before children: rows are inserted in
 * this order and deleted in the reverse order.
 */
export const CONFIG_TABLE_NAMES = [
  "certificates",
  "caCertificates",
  "issuedClientCertificates",
  "accessLists",
  "accessListEntries",
  "accessListRules",
  "proxyHosts",
  "l4ProxyHosts",
  "mtlsRoles",
  "mtlsCertificateRoles",
  "mtlsAccessRules",
  "groups",
  "forwardAuthAccess",
  "wafRuleExclusions",
] as const;
export type ConfigTableName = (typeof CONFIG_TABLE_NAMES)[number];

/**
 * Tables added to the configuration after fingerprints were first stored.
 * Left out of fingerprints while empty, so a configuration that does not use
 * them keeps the fingerprint it had before (no spurious history snapshot or
 * drift after an upgrade).
 */
export const CONFIG_TABLES_ADDED_LATER: ReadonlySet<ConfigTableName> = new Set<ConfigTableName>(["wafRuleExclusions"]);

export const CONFIG_TABLES: Record<ConfigTableName, TableSpec> = {
  certificates: {
    table: certificates,
    singular: "certificate",
    plural: "Certificates",
    attributionColumns: ["createdBy"],
    references: [],
    secretColumns: { privateKeyPem: "encrypted" },
    describe: (row) => text(row.name),
  },
  caCertificates: {
    table: caCertificates,
    singular: "CA certificate",
    plural: "CA certificates",
    attributionColumns: ["createdBy"],
    references: [],
    secretColumns: { privateKeyPem: "encrypted" },
    describe: (row) => text(row.name),
  },
  issuedClientCertificates: {
    table: issuedClientCertificates,
    singular: "client certificate",
    plural: "Client certificates",
    attributionColumns: ["createdBy"],
    references: [{ column: "caCertificateId", target: "caCertificates", onMissing: "drop" }],
    secretColumns: {},
    describe: (row) => `${text(row.commonName)} (${text(row.serialNumber)})`,
  },
  accessLists: {
    table: accessLists,
    singular: "access list",
    plural: "Access lists",
    attributionColumns: ["createdBy"],
    references: [],
    secretColumns: {},
    describe: (row) => text(row.name),
  },
  accessListEntries: {
    table: accessListEntries,
    singular: "access list user",
    plural: "Access list users",
    attributionColumns: [],
    references: [{ column: "accessListId", target: "accessLists", onMissing: "drop" }],
    secretColumns: { passwordHash: "hash" },
    describe: (row) => `${text(row.username)} (list ${String(row.accessListId)})`,
  },
  accessListRules: {
    table: accessListRules,
    singular: "access list rule",
    plural: "Access list rules",
    attributionColumns: ["createdBy"],
    references: [{ column: "accessListId", target: "accessLists", onMissing: "drop" }],
    secretColumns: {},
    describe: (row) => `${text(row.action)} ${text(row.kind)} ${describeRuleValues(row.matchValues)} (list ${String(row.accessListId)})`,
  },
  proxyHosts: {
    table: proxyHosts,
    singular: "proxy host",
    plural: "Proxy hosts",
    attributionColumns: ["ownerUserId"],
    references: [
      { column: "certificateId", target: "certificates", onMissing: "null" },
      { column: "accessListId", target: "accessLists", onMissing: "null" },
    ],
    secretColumns: {},
    describe: (row) => text(row.name),
  },
  l4ProxyHosts: {
    table: l4ProxyHosts,
    singular: "L4 proxy host",
    plural: "L4 proxy hosts",
    attributionColumns: ["ownerUserId"],
    references: [],
    secretColumns: {},
    describe: (row) => text(row.name),
  },
  mtlsRoles: {
    table: mtlsRoles,
    singular: "mTLS role",
    plural: "mTLS roles",
    attributionColumns: ["createdBy"],
    references: [],
    secretColumns: {},
    describe: (row) => text(row.name),
  },
  mtlsCertificateRoles: {
    table: mtlsCertificateRoles,
    singular: "mTLS role assignment",
    plural: "mTLS role assignments",
    attributionColumns: [],
    references: [
      { column: "issuedClientCertificateId", target: "issuedClientCertificates", onMissing: "drop" },
      { column: "mtlsRoleId", target: "mtlsRoles", onMissing: "drop" },
    ],
    secretColumns: {},
    describe: (row) => `certificate ${String(row.issuedClientCertificateId)} in role ${String(row.mtlsRoleId)}`,
  },
  mtlsAccessRules: {
    table: mtlsAccessRules,
    singular: "mTLS access rule",
    plural: "mTLS access rules",
    attributionColumns: ["createdBy"],
    references: [{ column: "proxyHostId", target: "proxyHosts", onMissing: "drop" }],
    secretColumns: {},
    describe: (row) => `${text(row.pathPattern)} on proxy host ${String(row.proxyHostId)}`,
  },
  groups: {
    table: groups,
    singular: "group",
    plural: "Groups",
    attributionColumns: ["createdBy"],
    references: [],
    secretColumns: {},
    describe: (row) => text(row.name),
  },
  forwardAuthAccess: {
    table: forwardAuthAccess,
    singular: "forward-auth grant",
    plural: "Forward-auth grants",
    attributionColumns: [],
    references: [
      { column: "proxyHostId", target: "proxyHosts", onMissing: "drop" },
      { column: "groupId", target: "groups", onMissing: "drop" },
      // A grant names a user; it is dropped, never widened, when that user is gone.
      { column: "userId", target: "users", onMissing: "drop" },
    ],
    secretColumns: {},
    describe: (row) =>
      row.groupId != null
        ? `group ${String(row.groupId)} on proxy host ${String(row.proxyHostId)}`
        : `user ${String(row.userId)} on proxy host ${String(row.proxyHostId)}`,
  },
  wafRuleExclusions: {
    table: wafRuleExclusions,
    singular: "WAF rule exclusion",
    plural: "WAF rule exclusions",
    attributionColumns: ["createdBy"],
    // A global exclusion has no proxy host; a host's goes with the host.
    references: [{ column: "proxyHostId", target: "proxyHosts", onMissing: "drop" }],
    secretColumns: {},
    describe: (row) =>
      `rule ${String(row.ruleId)}${row.proxyHostId != null ? ` on proxy host ${String(row.proxyHostId)}` : " (global)"}` +
      `${typeof row.path === "string" && row.path ? ` for ${row.path}` : ""}${typeof row.variable === "string" && row.variable ? ` in ${row.variable}` : ""}`,
  },
};

export type ConfigContent = {
  version: typeof CONFIG_CONTENT_VERSION;
  tables: Record<ConfigTableName, ConfigRow[]>;
  /** Parsed setting values; null when the setting is not set. */
  settings: Record<ConfigSettingKey, unknown>;
};

export type ConfigCounts = Record<ConfigTableName, number> & { settings: number };

export function emptyConfigContent(): ConfigContent {
  return {
    version: CONFIG_CONTENT_VERSION,
    tables: Object.fromEntries(CONFIG_TABLE_NAMES.map((name) => [name, []])) as unknown as Record<ConfigTableName, ConfigRow[]>,
    settings: Object.fromEntries(CONFIG_SETTING_KEYS.map((key) => [key, null])) as Record<ConfigSettingKey, unknown>,
  };
}

export function countConfigContent(content: ConfigContent): ConfigCounts {
  const counts = Object.fromEntries(
    CONFIG_TABLE_NAMES.map((name) => [name, content.tables[name].length])
  ) as Record<ConfigTableName, number>;
  return {
    ...counts,
    settings: CONFIG_SETTING_KEYS.filter((key) => content.settings[key] !== null && content.settings[key] !== undefined).length,
  };
}

function rowId(row: ConfigRow): number {
  return typeof row.id === "number" ? row.id : Number.NaN;
}

function byId(a: ConfigRow, b: ConfigRow): number {
  return rowId(a) - rowId(b);
}

// ── Reading ─────────────────────────────────────────────────────────────

/** The current configuration. Call inside a transaction for a consistent read. */
export async function readConfigContent(tx: DbTransaction): Promise<ConfigContent> {
  const content = emptyConfigContent();
  for (const name of CONFIG_TABLE_NAMES) {
    const rows = await tx.select().from(CONFIG_TABLES[name].table) as ConfigRow[];
    content.tables[name] = rows.map((row) => ({ ...row })).sort(byId);
  }
  const settingRows = await tx
    .select({ key: settings.key, value: settings.value })
    .from(settings)
    .where(inArray(settings.key, [...CONFIG_SETTING_KEYS]));
  for (const row of settingRows) {
    try {
      content.settings[row.key as ConfigSettingKey] = JSON.parse(row.value);
    } catch {
      // getSetting treats an unparsable value as unset, so does the configuration.
      content.settings[row.key as ConfigSettingKey] = null;
    }
  }
  return content;
}

/** Reads the current configuration in its own read-only transaction: one consistent snapshot. */
export async function readCurrentConfigContent(): Promise<ConfigContent> {
  return await appDb.transaction(async (tx) => await readConfigContent(tx), { readOnly: true });
}

// ── Validation ──────────────────────────────────────────────────────────

/** A structural problem in configuration content; the message is safe to show. */
export class ConfigContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigContentError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

type ColumnInfo = {
  dataType: string;
  notNull: boolean;
  hasDefault: boolean;
  primary: boolean;
  /** A 32-bit integer column on PostgreSQL (src/lib/db/pg-column-types.ts). */
  int4: boolean;
};

const INT4_MIN = -2_147_483_648;
const INT4_MAX = 2_147_483_647;

const columnInfoCache = new Map<ConfigTableName, Map<string, ColumnInfo>>();

function columnsOf(name: ConfigTableName): Map<string, ColumnInfo> {
  let info = columnInfoCache.get(name);
  if (!info) {
    const tableName = getTableName(CONFIG_TABLES[name].table);
    info = new Map(
      Object.entries(getTableColumns(CONFIG_TABLES[name].table) as Record<string, Column>).map(([key, column]) => [
        key,
        {
          dataType: column.dataType,
          notNull: column.notNull,
          hasDefault: column.hasDefault,
          primary: column.primary,
          int4: pgIntegerType(tableName, column.name) === "int4",
        },
      ])
    );
    columnInfoCache.set(name, info);
  }
  return info;
}

export function configTableColumns(name: ConfigTableName): string[] {
  return [...columnsOf(name).keys()];
}

const MAX_ROWS_PER_TABLE = 100_000;

/** Fields of withdrawn features that content written by an older release still has; they are dropped. */
const WITHDRAWN_FIELDS: ReadonlySet<string> = new Set(["organizationId"]);

function validateRow(name: ConfigTableName, raw: unknown, where: string): ConfigRow {
  if (!isRecord(raw)) throw new ConfigContentError(`${where} must be an object`);
  const columns = columnsOf(name);
  for (const key of Object.keys(raw)) {
    if (!columns.has(key) && !WITHDRAWN_FIELDS.has(key)) throw new ConfigContentError(`${where} has an unknown field "${key}"`);
  }
  const row: ConfigRow = {};
  for (const [key, column] of columns) {
    if (!(key in raw) || raw[key] === undefined) {
      if (column.primary || (column.notNull && !column.hasDefault)) {
        throw new ConfigContentError(`${where}.${key} is missing`);
      }
      continue;
    }
    const value = raw[key];
    if (value === null) {
      if (column.notNull) throw new ConfigContentError(`${where}.${key} must not be null`);
      row[key] = null;
      continue;
    }
    const ok =
      column.dataType === "number"
        ? typeof value === "number" && Number.isSafeInteger(value) &&
          // What PostgreSQL stores in the column (the same file imports on either database).
          (!column.int4 || (value >= INT4_MIN && value <= INT4_MAX))
        : column.dataType === "boolean"
          ? typeof value === "boolean"
          : column.dataType === "string"
            ? typeof value === "string"
            : false;
    if (!ok) {
      const expected = column.dataType === "number" ? "an integer" : column.dataType === "boolean" ? "a boolean" : "a string";
      throw new ConfigContentError(`${where}.${key} must be ${expected}`);
    }
    row[key] = value;
  }
  if (typeof row.id !== "number" || row.id < 1) {
    throw new ConfigContentError(`${where}.id must be a positive integer`);
  }
  return row;
}

/**
 * Strictly validates configuration content (from a snapshot or an import
 * file): known tables and settings only, every row with known columns of the
 * right type and a unique positive id. Tables or settings missing from the
 * content (it was written by an older release) are empty or unset.
 */
export function parseConfigContent(raw: unknown): ConfigContent {
  if (!isRecord(raw)) throw new ConfigContentError("content must be an object");
  for (const key of Object.keys(raw)) {
    if (key !== "version" && key !== "tables" && key !== "settings") {
      throw new ConfigContentError(`content has an unknown field "${key}"`);
    }
  }
  if (raw.version !== CONFIG_CONTENT_VERSION) {
    throw new ConfigContentError(`content.version must be ${CONFIG_CONTENT_VERSION}`);
  }
  if (!isRecord(raw.tables)) throw new ConfigContentError("content.tables must be an object");
  if (!isRecord(raw.settings)) throw new ConfigContentError("content.settings must be an object");

  const content = emptyConfigContent();
  for (const [name, rows] of Object.entries(raw.tables)) {
    if (!(name in CONFIG_TABLES)) throw new ConfigContentError(`content.tables has an unknown table "${name}"`);
    const tableName = name as ConfigTableName;
    if (!Array.isArray(rows)) throw new ConfigContentError(`content.tables.${name} must be an array`);
    if (rows.length > MAX_ROWS_PER_TABLE) throw new ConfigContentError(`content.tables.${name} has too many rows`);
    const seen = new Set<number>();
    content.tables[tableName] = rows
      .map((item, index) => {
        const row = validateRow(tableName, item, `content.tables.${name}[${index}]`);
        if (seen.has(row.id as number)) {
          throw new ConfigContentError(`content.tables.${name} has more than one row with id ${String(row.id)}`);
        }
        seen.add(row.id as number);
        return row;
      })
      .sort(byId);
  }
  for (const [key, value] of Object.entries(raw.settings)) {
    if (!(CONFIG_SETTING_KEYS as readonly string[]).includes(key)) {
      throw new ConfigContentError(`content.settings has an unknown setting "${key}"`);
    }
    if (value !== null && !isRecord(value)) {
      throw new ConfigContentError(`content.settings.${key} must be an object or null`);
    }
    content.settings[key as ConfigSettingKey] = value;
  }
  return content;
}

// ── Secrets ─────────────────────────────────────────────────────────────

export type SettingPath = Array<string | number>;

/** Applies `transform` to every string inside a JSON value. */
export function mapJsonStrings(
  value: unknown,
  path: SettingPath,
  transform: (value: string, path: SettingPath) => string
): unknown {
  if (typeof value === "string") return transform(value, path);
  if (Array.isArray(value)) return value.map((item, index) => mapJsonStrings(item, [...path, index], transform));
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, mapJsonStrings(item, [...path, key], transform)])
    );
  }
  return value;
}

export type SecretPlace =
  | { kind: "column"; table: ConfigTableName; rowId: number; column: string; protection: SecretProtection }
  | { kind: "setting"; key: ConfigSettingKey; path: SettingPath };

/** A stable label for a secret's place, e.g. for authenticated encryption. */
export function secretPlaceLabel(place: SecretPlace): string {
  return place.kind === "column"
    ? JSON.stringify(["tables", place.table, place.rowId, place.column])
    : JSON.stringify(["settings", place.key, ...place.path]);
}

/**
 * Applies `transform` to every non-empty secret column value and to every
 * string inside the settings that `isSettingSecret` selects (by default the
 * strings encrypted with encryptSecret). Returns a new content object.
 */
export function mapConfigSecrets(
  content: ConfigContent,
  transform: (value: string, place: SecretPlace) => string,
  isSettingSecret: (value: string) => boolean = isEncryptedSecret
): ConfigContent {
  const tables = { ...content.tables };
  for (const name of CONFIG_TABLE_NAMES) {
    const secretColumns = Object.entries(CONFIG_TABLES[name].secretColumns);
    if (secretColumns.length === 0) continue;
    tables[name] = content.tables[name].map((row) => {
      const next = { ...row };
      for (const [column, protection] of secretColumns) {
        const value = row[column];
        if (typeof value === "string" && value.length > 0) {
          next[column] = transform(value, { kind: "column", table: name, rowId: rowId(row), column, protection });
        }
      }
      return next;
    });
  }
  const settingsOut = { ...content.settings };
  for (const key of CONFIG_SETTING_KEYS) {
    settingsOut[key] = mapJsonStrings(content.settings[key], [], (value, path) =>
      isSettingSecret(value) ? transform(value, { kind: "setting", key, path }) : value
    );
  }
  return { version: content.version, tables, settings: settingsOut };
}

/**
 * Credentials that may still be stored in plaintext (DNS provider password
 * fields, the legacy Cloudflare token, certificate storage secrets),
 * encrypted with this instance's key.
 */
export function encryptPlaintextSettingCredentials(content: ConfigContent): ConfigContent {
  return {
    ...content,
    settings: {
      ...content.settings,
      dns_provider: encryptDnsProviderSettingCredentials(content.settings.dns_provider),
      cloudflare: encryptCloudflareSettingToken(content.settings.cloudflare),
      certificate_storage: encryptCertificateStorageSecrets(content.settings.certificate_storage),
    },
  };
}

/**
 * Encrypted values under the current SESSION_SECRET: a value that only a
 * previous key (SESSION_SECRET_PREVIOUS) decrypts is re-encrypted; a value no
 * key decrypts is kept as stored, as the startup rotation does.
 */
function refreshEncryptedSecrets(content: ConfigContent): ConfigContent {
  return mapConfigSecrets(content, (value, place) => {
    if (place.kind === "column" && place.protection === "hash") return value;
    if (!isEncryptedSecret(value)) return value;
    try {
      return reencryptSecret(value) ?? value;
    } catch {
      return value;
    }
  });
}

// ── Writing ─────────────────────────────────────────────────────────────

/**
 * Rows outside the configuration that point into it. They are never part of
 * a snapshot or an export, but replacing the configuration decides which of
 * them still apply.
 */
export type ConfigDependents = {
  groupMembers: ConfigRow[];
  groupNames: Map<number, string>;
  forwardAuthSessions: ConfigRow[];
  forwardAuthExchanges: ConfigRow[];
  forwardAuthRedirectIntents: ConfigRow[];
};

export async function readConfigDependents(tx: DbTransaction): Promise<ConfigDependents> {
  return {
    groupMembers: await tx.select().from(groupMembers) as ConfigRow[],
    groupNames: new Map((await tx.select({ id: groups.id, name: groups.name }).from(groups)).map((row) => [row.id, row.name])),
    forwardAuthSessions: await tx.select().from(forwardAuthSessions) as ConfigRow[],
    forwardAuthExchanges: await tx.select().from(forwardAuthExchanges) as ConfigRow[],
    forwardAuthRedirectIntents: await tx.select().from(forwardAuthRedirectIntents) as ConfigRow[],
  };
}

/**
 * "restore": a configuration of this instance (a snapshot, or a rollback),
 * whose ids mean what they meant when it was taken. "import": a configuration
 * from a file, possibly from another installation, whose ids may mean
 * something else here.
 */
export type ConfigWriteMode = "restore" | "import";

const INSERT_CHUNK = 50;

/**
 * Inserts rows with their ids. The ids were given, so on PostgreSQL the
 * table's identity is moved past them (resyncIdentity) for the rows created
 * later.
 */
async function insertRows(tx: DbTransaction, table: SQLiteTable, rows: ConfigRow[]): Promise<void> {
  for (let index = 0; index < rows.length; index += INSERT_CHUNK) {
    await tx.insert(table).values(rows.slice(index, index + INSERT_CHUNK) as never);
  }
  if (rows.length > 0) await resyncIdentity(table, tx);
}

/**
 * Replaces the configuration with `content`, keeping row ids. Call inside a
 * transaction. References the content cannot satisfy are repaired the way
 * the schema's onDelete rules would (SQLite runs with foreign keys off, so
 * they never fire): attribution to a user that does not exist is cleared, a
 * grant for a user, group or host that does not exist is dropped.
 *
 * Group memberships survive for groups that still exist; on import only when
 * the group kept its name, so that members of a local group never end up in
 * an unrelated imported group with the same id. Forward-auth sessions survive
 * a restore for hosts that still exist and are all ended by an import.
 */
export async function writeConfigContent(
  tx: DbTransaction,
  input: ConfigContent,
  mode: ConfigWriteMode,
  given?: ConfigDependents
): Promise<void> {
  const dependents = given ?? (await readConfigDependents(tx));
  const content = refreshEncryptedSecrets(encryptPlaintextSettingCredentials(input));

  await tx.delete(forwardAuthExchanges);
  await tx.delete(forwardAuthRedirectIntents);
  await tx.delete(forwardAuthSessions);
  await tx.delete(groupMembers);
  for (const name of [...CONFIG_TABLE_NAMES].reverse()) {
    await tx.delete(CONFIG_TABLES[name].table);
  }

  const userIds = new Set((await tx.select({ id: users.id }).from(users)).map((row) => row.id));
  const kept = new Map<ConfigTableName | "users", Set<number>>([["users", userIds]]);

  for (const name of CONFIG_TABLE_NAMES) {
    const spec = CONFIG_TABLES[name];
    const rows: ConfigRow[] = [];
    for (const source of content.tables[name]) {
      const row = { ...source };
      for (const column of spec.attributionColumns) {
        if (typeof row[column] === "number" && !userIds.has(row[column] as number)) row[column] = null;
      }
      let keep = true;
      for (const reference of spec.references) {
        const value = row[reference.column];
        if (value === null || value === undefined) continue;
        if (kept.get(reference.target)?.has(value as number)) continue;
        if (reference.onMissing === "null") {
          row[reference.column] = null;
        } else {
          keep = false;
          break;
        }
      }
      if (keep) rows.push(row);
    }
    await insertRows(tx, spec.table, rows);
    kept.set(name, new Set(rows.map(rowId)));
  }

  const keptGroups = kept.get("groups")!;
  const newGroupNames = new Map(content.tables.groups.map((row) => [rowId(row), text(row.name)]));
  await insertRows(
    tx,
    groupMembers,
    dependents.groupMembers.filter((member) => {
      const groupId = member.groupId as number;
      if (!keptGroups.has(groupId) || !userIds.has(member.userId as number)) return false;
      return mode === "restore" || dependents.groupNames.get(groupId) === newGroupNames.get(groupId);
    })
  );

  if (mode === "restore") {
    const keptHosts = kept.get("proxyHosts")!;
    const sessions = dependents.forwardAuthSessions.filter(
      (session) => keptHosts.has(session.proxyHostId as number) && userIds.has(session.userId as number)
    );
    const sessionIds = new Set(sessions.map(rowId));
    await insertRows(tx, forwardAuthSessions, sessions);
    await insertRows(
      tx,
      forwardAuthExchanges,
      dependents.forwardAuthExchanges.filter(
        (exchange) => sessionIds.has(exchange.sessionId as number) && keptHosts.has(exchange.proxyHostId as number)
      )
    );
    await insertRows(
      tx,
      forwardAuthRedirectIntents,
      dependents.forwardAuthRedirectIntents.filter((intent) => keptHosts.has(intent.proxyHostId as number))
    );
  }

  const updatedAt = nowIso();
  for (const key of CONFIG_SETTING_KEYS) {
    const value = content.settings[key];
    if (value === null || value === undefined) {
      await tx.delete(settings).where(eq(settings.key, key));
      continue;
    }
    const serialized = JSON.stringify(value);
    await tx.insert(settings)
      .values({ key, value: serialized, updatedAt })
      .onConflictDoUpdate({ target: settings.key, set: { value: serialized, updatedAt } });
  }

  // Content written before exclusion records existed carries its excluded
  // rules only in the excluded_rule_ids lists: give them records.
  await importLegacyWafExclusions(tx);
}
