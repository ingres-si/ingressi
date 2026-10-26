/**
 * The SQLite database file: opening it (bun:sqlite in production,
 * better-sqlite3 in tests and Node builds), its PRAGMAs and file modes, the
 * schema migrations and the legacy schema repairs that run before them, and
 * the statement runner the asynchronous layer (executor.ts) uses on the same
 * connection. Everything here is synchronous and runs when the module loads,
 * as it did in src/lib/db.ts.
 *
 * `db` is the synchronous Drizzle instance the migrations and repairs here
 * use; the application uses the asynchronous `appDb`
 * (src/lib/db/executor.ts), the default export of src/lib/db.ts.
 */
import { Database } from "bun:sqlite";
import { drizzle } from "drizzle-orm/bun-sqlite";
import { migrate } from "drizzle-orm/bun-sqlite/migrator";
import { chmodSync, existsSync, mkdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, resolve as resolvePath } from "node:path";
import * as schema from "./schema";
import {
  CREDENTIAL_ACCOUNT_ISSUER,
  resolveOAuthAccountIssuer,
} from "../account-issuer";
import { adoptLegacyDatabaseFile, DATABASE_FILE_NAME, LEGACY_DATABASE_FILE_NAME } from "../db-file";
import { getDialect } from "./dialect";

const DEFAULT_SQLITE_URL = `file:./data/${DATABASE_FILE_NAME}`;

type GlobalForDrizzle = typeof globalThis & {
  __DRIZZLE_DB__?: ReturnType<typeof drizzle<typeof schema>>;
  __SQLITE_CLIENT__?: InstanceType<typeof Database>;
  __MIGRATIONS_RAN__?: boolean;
};

function resolveSqlitePath(rawUrl: string): string {
  if (!rawUrl) {
    return ":memory:";
  }
  if (rawUrl === ":memory:" || rawUrl === "file::memory:") {
    return ":memory:";
  }

  if (rawUrl.startsWith("file:./") || rawUrl.startsWith("file:../")) {
    const relative = rawUrl.slice("file:".length);
    return resolvePath(/* turbopackIgnore: true */ process.cwd(), relative);
  }

  if (rawUrl.startsWith("file:")) {
    try {
      const fileUrl = new URL(rawUrl);
      if (fileUrl.host && fileUrl.host !== "localhost") {
        throw new Error("Remote SQLite hosts are not supported.");
      }
      return decodeURIComponent(fileUrl.pathname);
    } catch {
      const remainder = rawUrl.slice("file:".length);
      if (!remainder) {
        return ":memory:";
      }
      return isAbsolute(remainder)
        ? remainder
        : resolvePath(/* turbopackIgnore: true */ process.cwd(), remainder);
    }
  }

  return isAbsolute(rawUrl)
    ? rawUrl
    : resolvePath(/* turbopackIgnore: true */ process.cwd(), rawUrl);
}

/**
 * Whether the application runs on SQLite. On PostgreSQL the URL is not a
 * file name: nothing here may open or create a file named after it.
 */
const usesSqlite = getDialect() === "sqlite";

/** An object that throws on any use: the SQLite connection when the application runs on PostgreSQL. */
function unavailableOnPostgres<T extends object>(what: string): T {
  return new Proxy({} as T, {
    get() {
      throw new Error(`${what} is not available: the application runs on PostgreSQL (DATABASE_URL)`);
    },
  });
}

const databaseUrl = process.env.DATABASE_URL ?? DEFAULT_SQLITE_URL;
/** The database file, or ":memory:" (also on PostgreSQL, which has no file here). */
export const sqlitePath = usesSqlite ? resolveSqlitePath(databaseUrl) : ":memory:";

function ensureDirectoryFor(pathname: string) {
  if (pathname === ":memory:") {
    return;
  }
  const dir = dirname(pathname);
  mkdirSync(dir, { recursive: true });
}

/**
 * The database holds password hashes, session tokens and encrypted secrets,
 * but SQLite creates its files with the process umask (usually world-readable).
 * Remove world access from the database and its journal files. Owner and group
 * bits are kept, so group-based access (e.g. a backup job) keeps working.
 */
export function restrictDatabaseFileModes(pathname: string = sqlitePath): void {
  if (pathname === ":memory:") return;
  for (const file of [pathname, `${pathname}-journal`, `${pathname}-wal`, `${pathname}-shm`]) {
    try {
      if (!existsSync(file)) continue;
      const mode = statSync(file).mode & 0o7777;
      if (mode & 0o007) chmodSync(file, mode & ~0o007);
    } catch (error) {
      console.warn(`Could not restrict permissions on ${file}:`, (error as NodeJS.ErrnoException).code ?? error);
    }
  }
}

const globalForDrizzle = globalThis as GlobalForDrizzle;

/**
 * High availability (ee/docs/high-availability.md). The cluster supervisor
 * starts a standby's dashboard (HA_ROLE=standby) on a read-only copy of the
 * leader's database that Litestream keeps current: nothing here may write to
 * it, and Litestream locks it while it applies the leader's changes. The
 * leader's database (HA_ROLE=leader) is replicated by Litestream, which needs
 * WAL mode and briefly locks the database while it syncs.
 */
const haRole = process.env.HA_ROLE;
/** Whether this is a high availability standby's read-only copy of the leader's database. */
export const readOnlyCopy = haRole === "standby";
/** A standby without a copy yet opens an empty in-memory schema instead. */
let readOnlyCopyMissing = false;

function openSqliteConnection(): InstanceType<typeof Database> {
  if (readOnlyCopy) {
    if (sqlitePath !== ":memory:" && existsSync(sqlitePath)) {
      const copy = new Database(sqlitePath, { readonly: true });
      copy.exec("PRAGMA busy_timeout = 5000");
      return copy;
    }
    readOnlyCopyMissing = true;
    return new Database(":memory:");
  }
  ensureDirectoryFor(sqlitePath);
  if (adoptLegacyDatabaseFile(sqlitePath)) {
    console.log(`Renamed the database file ${LEGACY_DATABASE_FILE_NAME} to ${DATABASE_FILE_NAME}`);
  }
  const client = new Database(sqlitePath);
  restrictDatabaseFileModes(sqlitePath);
  // Overwrite deleted and replaced content with zeros instead of leaving it
  // in free pages and page slack, where secrets encrypted or removed after
  // the fact (legacy plaintext keys and tokens) could be read back from
  // the file or a copy of it.
  client.exec("PRAGMA secure_delete = ON");
  if (haRole === "leader") {
    client.exec("PRAGMA busy_timeout = 5000");
    client.exec("PRAGMA journal_mode = WAL");
  }
  return client;
}

/** The SQLite connection (throws when used on PostgreSQL). */
export const sqlite: InstanceType<typeof Database> = usesSqlite
  ? (globalForDrizzle.__SQLITE_CLIENT__ ?? openSqliteConnection())
  : unavailableOnPostgres("The SQLite connection");

if (usesSqlite && process.env.NODE_ENV !== "production") {
  globalForDrizzle.__SQLITE_CLIENT__ = sqlite;
}

/** The synchronous Drizzle instance: the schema migrations and legacy repairs below use it. */
export const db: ReturnType<typeof drizzle<typeof schema>> = usesSqlite
  ? (globalForDrizzle.__DRIZZLE_DB__ ?? drizzle(sqlite, { schema }))
  : unavailableOnPostgres("The synchronous SQLite database");

if (usesSqlite && process.env.NODE_ENV !== "production") {
  globalForDrizzle.__DRIZZLE_DB__ = db;
}

const migrationsFolder = resolvePath(process.cwd(), "drizzle");

/**
 * Rename a column if the snake_case form exists and the camelCase form does not.
 * No-ops silently if the table doesn't exist or the column is already correct.
 */
function renameColumnIfNeeded(table: string, from: string, to: string) {
  try {
    const cols = db.$client.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name: string }>;
    const names = new Set(cols.map((c) => c.name));
    if (names.has(from) && !names.has(to)) {
      db.$client.prepare(`ALTER TABLE "${table}" RENAME COLUMN "${from}" TO "${to}"`).run();
    }
  } catch {
    // ignore
  }
}

/**
 * Add a column if it is absent from the table (checks both snake_case and camelCase
 * forms so we don't add a column that was already renamed by a later migration).
 */
function addColumnIfMissing(table: string, snake: string, camel: string, definition: string) {
  try {
    const cols = db.$client.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name: string }>;
    if (cols.length === 0) return; // table doesn't exist yet
    const names = new Set(cols.map((c) => c.name));
    if (!names.has(snake) && !names.has(camel)) {
      db.$client.prepare(`ALTER TABLE "${table}" ADD COLUMN "${snake}" ${definition}`).run();
    }
  } catch {
    // ignore
  }
}

/**
 * Ensure the sessions table uses INTEGER PRIMARY KEY AUTOINCREMENT for `id`.
 * Better Auth is configured with generateId:"serial" so it omits `id` from INSERT
 * and relies on the DB to generate it. If the table was created with `id TEXT NOT NULL`
 * (older schema), the insert fails with NOT NULL constraint. Sessions are ephemeral
 * so we simply recreate the table with the correct schema when needed.
 */
function fixSessionsSchema() {
  try {
    const cols = db.$client.prepare('PRAGMA table_info("sessions")').all() as Array<{
      name: string; type: string; pk: number;
    }>;
    if (cols.length === 0) return; // table doesn't exist yet
    const idCol = cols.find((c) => c.name === "id");
    if (!idCol) return;
    // INTEGER PRIMARY KEY is an alias for rowid — auto-generates on insert
    if (idCol.type.toUpperCase() === "INTEGER" && idCol.pk === 1) return;
    // Wrong type (e.g. TEXT NOT NULL) — recreate as autoincrement
    db.$client.prepare(`CREATE TABLE "sessions_patch" (
      "id"        INTEGER PRIMARY KEY AUTOINCREMENT,
      "userId"    INTEGER NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
      "token"     TEXT NOT NULL,
      "expiresAt" TEXT NOT NULL,
      "ipAddress" TEXT,
      "userAgent" TEXT,
      "createdAt" TEXT NOT NULL,
      "updatedAt" TEXT NOT NULL
    )`).run();
    // Sessions are short-lived — skip copying stale rows
    db.$client.prepare('DROP TABLE "sessions"').run();
    db.$client.prepare('ALTER TABLE "sessions_patch" RENAME TO "sessions"').run();
    db.$client.prepare('CREATE UNIQUE INDEX IF NOT EXISTS "sessions_token_unique" ON "sessions" ("token")').run();
    db.$client.prepare('CREATE INDEX IF NOT EXISTS "sessions_user_idx" ON "sessions" ("userId")').run();
  } catch {
    // ignore
  }
}

/**
 * Ensure the accounts table uses INTEGER PRIMARY KEY AUTOINCREMENT for `id`.
 * Some upgraded deployments can end up with an `accounts.id` column that is
 * NOT NULL but not rowid-backed, so inserts that omit `id` fail. Unlike
 * sessions, accounts are durable, so preserve rows while rebuilding the table.
 */
function fixAccountsSchema() {
  try {
    const cols = db.$client.prepare('PRAGMA table_info("accounts")').all() as Array<{
      name: string; type: string; notnull: number; pk: number; dflt_value: string | null;
    }>;
    if (cols.length === 0) return;
    const idCol = cols.find((c) => c.name === 'id');
    if (!idCol) return;
    const issuerCol = cols.find((c) => c.name === "issuer");
    const indexes = db.$client.prepare('PRAGMA index_list("accounts")').all() as Array<{
      name: string;
      unique: number;
    }>;
    const issuerIndex = indexes.find(
      (index) => index.name === "accounts_issuer_account_idx" && index.unique === 1
    );
    const issuerIndexColumns = issuerIndex
      ? db.$client.prepare('PRAGMA index_info("accounts_issuer_account_idx")').all() as Array<{
          name: string;
          seqno: number;
        }>
      : [];
    const hasCorrectIssuerIndex = issuerIndexColumns
      .sort((left, right) => left.seqno - right.seqno)
      .map((column) => column.name)
      .join(",") === "issuer,accountId";
    const hasLegacyProviderIndex = indexes.some(
      (index) => index.name === "accounts_provider_account_idx"
    );
    const idIsCorrect = idCol.type.toUpperCase() === "INTEGER" && idCol.pk === 1;
    // "Correct" means a shape Better Auth accepts. Since Better Auth 1.7.3+ the
    // runtime schema validation fails closed on NOT NULL columns it never
    // writes unless they carry a database default (issue #283) — so the
    // Ingressi-only `issuer` column must be NOT NULL *with* a default, not merely
    // NOT NULL. Deployments upgraded from ≤ v1.11.2 carry the pre-0025 shape
    // and are rebuilt here at boot, before Better Auth's check runs.
    const issuerIsCorrect = issuerCol?.notnull === 1 && issuerCol?.dflt_value != null;

    if (idIsCorrect && issuerIsCorrect && hasCorrectIssuerIndex && !hasLegacyProviderIndex) {
      return;
    }

    type LegacyAccountRow = {
      id: number | string;
      userId: number;
      issuer?: string | null;
      accountId: string;
      providerId: string;
      accessToken: string | null;
      refreshToken: string | null;
      idToken: string | null;
      accessTokenExpiresAt: string | null;
      refreshTokenExpiresAt: string | null;
      scope: string | null;
      password: string | null;
      createdAt: string;
      updatedAt: string;
    };

    const accountRows = db.$client
      .prepare('SELECT * FROM "accounts" ORDER BY "id"')
      .all() as LegacyAccountRow[];
    const providerIssuers = new Map<string, string | null>();
    const hasProviderTable = db.$client
      .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'oauth_providers'")
      .get();
    if (hasProviderTable) {
      const providers = db.$client
        .prepare('SELECT "id", "issuer" FROM "oauth_providers"')
        .all() as Array<{ id: string; issuer: string | null }>;
      for (const provider of providers) {
        providerIssuers.set(provider.id, provider.issuer);
      }
    }

    const normalizedRows = accountRows.map((row) => {
      const existingIssuer = row.issuer?.trim();
      const issuer = existingIssuer || (
        row.providerId === "credential"
          ? CREDENTIAL_ACCOUNT_ISSUER
          : resolveOAuthAccountIssuer(row.providerId, providerIssuers.get(row.providerId))
      );
      return { ...row, issuer };
    });

    // Better Auth 1.7 keys external identities by (issuer, accountId). Never
    // merge a collision implicitly: two legacy rows may belong to different
    // users, and choosing either one could turn a migration into account takeover.
    const identityOwners = new Map<string, number | string>();
    for (const row of normalizedRows) {
      const key = JSON.stringify([row.issuer, row.accountId]);
      const existingOwner = identityOwners.get(key);
      if (existingOwner !== undefined) {
        throw new Error(
          `account identity collision for issuer "${row.issuer}" and accountId "${row.accountId}"`
        );
      }
      identityOwners.set(key, row.id);
    }

    const repair = db.$client.transaction(() => {
      db.$client.prepare('DROP TABLE IF EXISTS "accounts_patch"').run();
      db.$client.prepare(`CREATE TABLE "accounts_patch" (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "userId" INTEGER NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
        "issuer" TEXT NOT NULL DEFAULT '',
        "accountId" TEXT NOT NULL,
        "providerId" TEXT NOT NULL,
        "accessToken" TEXT,
        "refreshToken" TEXT,
        "idToken" TEXT,
        "accessTokenExpiresAt" TEXT,
        "refreshTokenExpiresAt" TEXT,
        "scope" TEXT,
        "password" TEXT,
        "createdAt" TEXT NOT NULL,
        "updatedAt" TEXT NOT NULL
      )`).run();
      const insert = db.$client.prepare(`INSERT INTO "accounts_patch" (
        "id", "userId", "issuer", "accountId", "providerId", "accessToken", "refreshToken", "idToken",
        "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt"
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      for (const row of normalizedRows) {
        insert.run(
          row.id,
          row.userId,
          row.issuer,
          row.accountId,
          row.providerId,
          row.accessToken,
          row.refreshToken,
          row.idToken,
          row.accessTokenExpiresAt,
          row.refreshTokenExpiresAt,
          row.scope,
          row.password,
          row.createdAt,
          row.updatedAt
        );
      }
      db.$client.prepare('DROP TABLE "accounts"').run();
      db.$client.prepare('ALTER TABLE "accounts_patch" RENAME TO "accounts"').run();
      db.$client.prepare(
        'CREATE UNIQUE INDEX "accounts_issuer_account_idx" ON "accounts" ("issuer", "accountId")'
      ).run();
      db.$client.prepare(
        'CREATE INDEX "accounts_user_idx" ON "accounts" ("userId")'
      ).run();
    });
    repair();
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    const code = (error as { code?: string } | null)?.code;
    if (code === "SQLITE_READONLY" || code === "SQLITE_READONLY_DBMOVED" || /readonly/i.test(detail)) {
      // The repair is the first write of the boot sequence, so an unwritable
      // database file surfaces here first. Callers hitting this after a
      // `docker cp` round-trip saw a bare driver error with no hint (issue
      // #283) — name the likely cause and the fix.
      throw new Error(
        `Failed to repair Better Auth accounts schema: ${detail}. ` +
          "The SQLite database file is not writable by the application user " +
          "(uid 10001 in the published image). Check ownership and permissions " +
          "of the database file and its parent directory on the host volume " +
          "(for example after a `docker cp`, run: chown 10001:10001 <file>).",
        { cause: error }
      );
    }
    throw new Error(`Failed to repair Better Auth accounts schema: ${detail}`, {
      cause: error,
    });
  }
}

/**
 * Pre-migration compatibility patch for deployments that ran an older version of
 * migration 0020 with different column names. Migration 0021 renames columns in
 * many tables but does NOT touch `accounts`, `sessions`, or `verifications` — if
 * those were created with snake_case names they stay that way and Better Auth fails.
 *
 * This function runs before `migrate()` and brings any stale table schemas up to
 * the state that 0021/0022 expect, so the Drizzle migrations can complete cleanly.
 */
function patchTablesForMigration020() {
  // ── users ────────────────────────────────────────────────────────────────────
  // Columns added by 0020 that older deployments may be missing
  addColumnIfMissing("users", "email_verified", "emailVerified", "INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing("users", "username",        "username",      "TEXT");
  addColumnIfMissing("users", "display_username", "displayUsername", "TEXT");

  // ── accounts ─────────────────────────────────────────────────────────────────
  // 0020 should create these with camelCase; older versions used snake_case.
  // 0021 does NOT rename accounts columns, so we must fix them here.
  renameColumnIfNeeded("accounts", "user_id",                  "userId");
  renameColumnIfNeeded("accounts", "account_id",               "accountId");
  renameColumnIfNeeded("accounts", "provider_id",              "providerId");
  renameColumnIfNeeded("accounts", "access_token",             "accessToken");
  renameColumnIfNeeded("accounts", "refresh_token",            "refreshToken");
  renameColumnIfNeeded("accounts", "id_token",                 "idToken");
  renameColumnIfNeeded("accounts", "access_token_expires_at",  "accessTokenExpiresAt");
  renameColumnIfNeeded("accounts", "refresh_token_expires_at", "refreshTokenExpiresAt");
  renameColumnIfNeeded("accounts", "created_at",               "createdAt");
  renameColumnIfNeeded("accounts", "updated_at",               "updatedAt");
  fixAccountsSchema();

  // ── sessions ─────────────────────────────────────────────────────────────────
  // auth-server.ts uses generateId:"serial" — Better Auth omits `id` from INSERT
  // and relies on INTEGER PRIMARY KEY AUTOINCREMENT. If the cloud's older schema
  // had `id TEXT NOT NULL`, the insert fails. Recreate the table when needed.
  // Sessions are ephemeral so data loss is acceptable.
  fixSessionsSchema();
  renameColumnIfNeeded("sessions", "user_id",    "userId");
  renameColumnIfNeeded("sessions", "expires_at", "expiresAt");
  renameColumnIfNeeded("sessions", "ip_address", "ipAddress");
  renameColumnIfNeeded("sessions", "user_agent", "userAgent");
  renameColumnIfNeeded("sessions", "created_at", "createdAt");
  renameColumnIfNeeded("sessions", "updated_at", "updatedAt");

  // ── verifications ─────────────────────────────────────────────────────────────
  renameColumnIfNeeded("verifications", "expires_at", "expiresAt");
  renameColumnIfNeeded("verifications", "created_at", "createdAt");
  renameColumnIfNeeded("verifications", "updated_at", "updatedAt");
}

/**
 * Indexes that older installs never got. 0007 and 0008 carry timestamps
 * older than 0006, so the migrator skipped them on every database that had
 * already passed 0006 when they were added; 0021 recreates linking_tokens
 * later, but without 0007's expiry index. Idempotent.
 */
function repairSkippedMigrationIndexes() {
  try {
    db.$client.prepare('CREATE INDEX IF NOT EXISTS "linking_tokens_expires_at_idx" ON "linking_tokens" ("expiresAt")').run();
  } catch {
    // linking_tokens has another shape: its migrations own it
  }
}

function runMigrations() {
  if (readOnlyCopy) {
    // The copy is the leader's database, migrated by the leader's dashboard.
    if (readOnlyCopyMissing) migrate(db, { migrationsFolder });
    return;
  }
  if (sqlitePath === ":memory:") {
    return;
  }
  if (globalForDrizzle.__MIGRATIONS_RAN__) {
    return;
  }
  patchTablesForMigration020();
  try {
    migrate(db, { migrationsFolder });
    repairSkippedMigrationIndexes();
    globalForDrizzle.__MIGRATIONS_RAN__ = true;
  } catch (error: unknown) {
    // During build, pages may be pre-rendered in parallel, causing race conditions
    // with migrations. If tables already exist, just continue.
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      "message" in error &&
      error.code === "SQLITE_ERROR" &&
      typeof error.message === "string" &&
      error.message.includes("already exists")
    ) {
      console.log('Database tables already exist, skipping migrations');
      globalForDrizzle.__MIGRATIONS_RAN__ = true;
      return;
    }
    throw error;
  }
}

try {
  if (usesSqlite) runMigrations();
} catch (error) {
  console.error("Failed to run database migrations:", error);
  // Next's production build can import this module from parallel workers that
  // share the temporary build database. Runtime, development, and tests must
  // fail closed on migration errors so identity collisions are never ignored.
  if (process.env.NEXT_PHASE === 'phase-production-build') {
    console.warn('Continuing despite migration error during build phase');
  } else {
    throw error;
  }
}

/**
 * PRAGMA user_version once the database has been vacuumed with secure_delete
 * on. Nothing else in Ingressi uses user_version.
 */
const SECURE_DELETE_VACUUM_VERSION = 1;

/**
 * VACUUMs the database, which rebuilds the file without the free pages and
 * page slack that secure_delete does not reach: content deleted or replaced
 * before it was on. Runs when `force` is set (a startup migration just
 * rewrote secrets) and once on a database that was never vacuumed this way.
 * Returns whether it ran; failures (VACUUM needs room for a copy of the
 * database) are logged and leave the database as it was.
 *
 * Synchronous and ungated: call it through purgeDeletedDatabaseContent
 * (src/lib/db/startup.ts), which waits for open transactions first.
 */
export function vacuumSqliteDatabase(force = false): boolean {
  if (sqlitePath === ":memory:") return false;
  try {
    const row = sqlite.prepare("PRAGMA user_version").get() as { user_version?: number } | null;
    const version = row?.user_version ?? 0;
    if (!force && version >= SECURE_DELETE_VACUUM_VERSION) return false;
    sqlite.exec("VACUUM");
    if (version < SECURE_DELETE_VACUUM_VERSION) sqlite.exec(`PRAGMA user_version = ${SECURE_DELETE_VACUUM_VERSION}`);
    return true;
  } catch (error) {
    console.error("Failed to VACUUM the database; deleted content may remain in its free pages:", error);
    return false;
  }
}

// ── Statement runner (the asynchronous layer's access to the connection) ──

/**
 * A synchronous SQLite connection: bun:sqlite's Database in production,
 * better-sqlite3's in tests and Node builds (vitest and next.config.mjs alias
 * bun:sqlite to it).
 */
export interface SqliteClient {
  prepare(sql: string): unknown;
  exec(sql: string): unknown;
  readonly inTransaction: boolean;
}

export interface SqliteRunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

export interface SqliteQueryResult extends SqliteRunResult {
  /** Whether the statement returns rows (a SELECT, PRAGMA or RETURNING). */
  returnsRows: boolean;
  rows: Record<string, unknown>[];
}

/** One connection's statements, prepared once and kept in a bounded cache. */
export interface SqliteStatementRunner {
  readonly client: SqliteClient;
  /** Rows as arrays of column values in column order (Drizzle's array mode). */
  values(sql: string, params: readonly unknown[]): unknown[][];
  /** The first row as an array of column values, or undefined. */
  firstValues(sql: string, params: readonly unknown[]): unknown[] | undefined;
  /** Rows as objects keyed by column name, or the changes of a statement that returns none. */
  query(sql: string, params: readonly unknown[]): SqliteQueryResult;
  run(sql: string, params: readonly unknown[]): SqliteRunResult;
  /** Runs SQL without parameters (BEGIN, COMMIT, PRAGMA, several statements). */
  exec(sql: string): void;
  inTransaction(): boolean;
}

type BunStatement = {
  columnNames: string[];
  values(...params: unknown[]): unknown[][];
  all(...params: unknown[]): Record<string, unknown>[];
  run(...params: unknown[]): SqliteRunResult;
  finalize?(): void;
};

type BetterSqliteStatement = {
  reader: boolean;
  raw(toggle?: boolean): BetterSqliteStatement;
  all(...params: unknown[]): unknown[];
  get(...params: unknown[]): unknown;
  run(...params: unknown[]): SqliteRunResult;
};

type AnyStatement = BunStatement | BetterSqliteStatement;

function isBetterSqliteStatement(statement: AnyStatement): statement is BetterSqliteStatement {
  // Newer bun:sqlite statements also carry raw() and reader, so bun's own values() rules them out.
  return typeof (statement as BunStatement).values !== "function"
    && typeof (statement as BetterSqliteStatement).raw === "function"
    && typeof (statement as BetterSqliteStatement).reader === "boolean";
}

function returnsRows(statement: AnyStatement): boolean {
  return isBetterSqliteStatement(statement) ? statement.reader : statement.columnNames.length > 0;
}

/** bun:sqlite binds booleans as 1/0 and better-sqlite3 refuses them: bind 1/0 on both. */
function bindable(params: readonly unknown[]): unknown[] {
  return params.map((param) => (typeof param === "boolean" ? (param ? 1 : 0) : param));
}

const STATEMENT_CACHE_SIZE = 500;

export function createSqliteStatementRunner(client: SqliteClient): SqliteStatementRunner {
  const cache = new Map<string, AnyStatement>();

  function prepare(sql: string): AnyStatement {
    const cached = cache.get(sql);
    if (cached) {
      // Most recently used last.
      cache.delete(sql);
      cache.set(sql, cached);
      return cached;
    }
    const statement = client.prepare(sql) as AnyStatement;
    cache.set(sql, statement);
    if (cache.size > STATEMENT_CACHE_SIZE) {
      const [oldestSql, oldest] = cache.entries().next().value as [string, AnyStatement];
      cache.delete(oldestSql);
      (oldest as BunStatement).finalize?.();
    }
    return statement;
  }

  function run(sql: string, params: readonly unknown[]): SqliteRunResult {
    const result = prepare(sql).run(...bindable(params));
    return { changes: result.changes, lastInsertRowid: result.lastInsertRowid };
  }

  return {
    client,
    values(sql, params) {
      const statement = prepare(sql);
      if (isBetterSqliteStatement(statement)) {
        if (!statement.reader) {
          statement.run(...bindable(params));
          return [];
        }
        return statement.raw(true).all(...bindable(params)) as unknown[][];
      }
      return statement.values(...bindable(params));
    },
    firstValues(sql, params) {
      const statement = prepare(sql);
      if (isBetterSqliteStatement(statement)) {
        if (!statement.reader) {
          statement.run(...bindable(params));
          return undefined;
        }
        return statement.raw(true).get(...bindable(params)) as unknown[] | undefined;
      }
      // As Drizzle's bun-sqlite driver does for .get().
      return statement.values(...bindable(params))[0];
    },
    query(sql, params) {
      const statement = prepare(sql);
      if (returnsRows(statement)) {
        const rows = isBetterSqliteStatement(statement)
          ? (statement.raw(false).all(...bindable(params)) as Record<string, unknown>[])
          : statement.all(...bindable(params));
        return { returnsRows: true, rows, changes: 0, lastInsertRowid: 0 };
      }
      const result = statement.run(...bindable(params));
      return { returnsRows: false, rows: [], changes: result.changes, lastInsertRowid: result.lastInsertRowid };
    },
    run,
    exec(sql) {
      client.exec(sql);
    },
    inTransaction() {
      return client.inTransaction;
    },
  };
}

/** What a Drizzle sqlite-proxy callback returns for one statement. */
export type SqliteProxyResult = { rows: unknown } & Partial<SqliteRunResult>;

/**
 * Runs one statement as Drizzle's sqlite-proxy driver expects: "all" and
 * "values" return arrays of column values, "get" the first such array (or
 * undefined), "run" the number of changed rows.
 */
export function runSqliteProxyStatement(
  runner: SqliteStatementRunner,
  sql: string,
  params: readonly unknown[],
  method: "run" | "all" | "values" | "get"
): SqliteProxyResult {
  switch (method) {
    case "run": {
      const result = runner.run(sql, params);
      return { rows: [], changes: result.changes, lastInsertRowid: result.lastInsertRowid };
    }
    case "get":
      return { rows: runner.firstValues(sql, params) };
    default:
      return { rows: runner.values(sql, params) };
  }
}
