/**
 * deleteUser applies the schema's onDelete rules itself: production SQLite
 * runs with foreign_keys off, so nothing cascades on its own, and a user
 * created later under the same id (the primary admin is always id 1) would
 * take over the deleted user's sessions, API tokens and sign-in methods.
 * ensureAdminUser clears what older releases' deleteUser left behind.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { count, eq, is, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { SQLiteTable, getTableConfig, type SQLiteColumn } from 'drizzle-orm/sqlite-core';
import { createTestDb, disableForeignKeys, syncTestDb, testDbIsPostgres, type TestDb } from '../helpers/db';
import { createSqliteExecutor } from '../../src/lib/db/executor';
import * as schema from '../../src/lib/db/schema';
import * as authoringSchema from '../../src/lib/db/schema.sqlite';
import { referencesTo as schemaReferencesTo } from '../../src/lib/db/references';

const ctx = vi.hoisted(() => ({
  db: null as unknown as TestDb,
  /** The environment credentials ensureAdminUser reads. */
  admin: { adminUsername: 'admin', adminPassword: 'Env-Password-2026!' },
}));

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));
vi.mock('../../src/lib/config', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../src/lib/config')>();
  return {
    ...original,
    config: new Proxy(original.config, { get: (target, key) => (key in ctx.admin ? ctx.admin[key as keyof typeof ctx.admin] : Reflect.get(target, key)) }),
  };
});

import { deleteUser, getUserById } from '../../src/lib/models/user';
import { createApiToken, validateToken } from '../../src/lib/models/api-tokens';
import { ensureAdminUser } from '../../src/lib/init-db';
import { execRaw, first } from '@/src/lib/db/ops';

beforeEach(async () => {
  ctx.db = createTestDb();
  ctx.admin.adminPassword = 'Env-Password-2026!';
  // better-sqlite3 turns foreign keys on; production (bun:sqlite) leaves them
  // off, and PostgreSQL databases have none.
  await disableForeignKeys(ctx.db);
});

async function seedUser(email: string): Promise<number> {
  const now = new Date().toISOString();
  const [user] = await ctx.db.insert(schema.users).values({
    email, name: email, role: 'admin', provider: 'credentials', subject: email,
    status: 'active', createdAt: now, updatedAt: now,
  }).returning();
  return user.id;
}

/**
 * seedUser for a database migrated only part of the way: the users columns
 * of the current schema (such as twoFactorEnabled) do not exist there yet.
 */
async function seedLegacyUser(email: string): Promise<number> {
  const now = new Date().toISOString();
  const row = await first(execRaw<{ id: number }>(sql`
    insert into users (email, name, role, provider, subject, status, createdAt, updatedAt)
    values (${email}, ${email}, 'admin', 'credentials', ${email}, 'active', ${now}, ${now})
    returning id`, ctx.db));
  return row!.id;
}

/**
 * A row for `userId` in every table that references users.id, plus a
 * forward-auth exchange code for its forward-auth session and the state of an
 * OAuth "link account" flow it started. Returns the API token and the
 * forward-auth session id.
 */
async function seedReferences(userId: number): Promise<{ rawToken: string; forwardAuthSessionId: number }> {
  const now = new Date().toISOString();
  const later = new Date(Date.now() + 3_600_000).toISOString();
  const tag = `${userId}-${Math.random().toString(36).slice(2)}`;
  const db = ctx.db;

  await db.insert(schema.sessions).values({
    userId, token: `session-${tag}`, expiresAt: later, createdAt: now, updatedAt: now,
  });
  await db.insert(schema.accounts).values({
    userId, issuer: 'https://idp.example.com', accountId: `subject-${tag}`, providerId: 'oidc',
    createdAt: now, updatedAt: now,
  });
  await db.insert(schema.twoFactors).values({
    userId, secret: `totp-secret-${tag}`, backupCodes: `backup-codes-${tag}`, verified: true,
  });
  await db.insert(schema.passkeys).values({
    userId, publicKey: `public-key-${tag}`, credentialID: `credential-${tag}`, counter: 0, deviceType: 'multiDevice',
    backedUp: true, createdAt: now,
  });
  await db.insert(schema.userPreferences).values({ userId, theme: 'dark', updatedAt: now });
  await db.insert(schema.pendingOAuthLinks).values({
    userId, provider: 'oidc', userEmail: `user-${tag}@example.com`, createdAt: now, expiresAt: later,
  });
  // Better Auth stores link.userId as a string or a number depending on the caller.
  for (const linkUserId of [String(userId), userId]) {
    await db.insert(schema.verifications).values({
      identifier: `state-${tag}-${typeof linkUserId}`,
      value: JSON.stringify({
        callbackURL: 'https://ingressi.example.com/profile',
        codeVerifier: 'verifier',
        expiresAt: Date.now() + 600_000,
        link: { email: `user-${tag}@example.com`, userId: linkUserId },
      }),
      expiresAt: later, createdAt: now, updatedAt: now,
    });
  }
  const { rawToken } = await createApiToken('automation', userId);

  const [group] = await db.insert(schema.groups).values({
    name: `group-${tag}`, createdBy: userId, createdAt: now, updatedAt: now,
  }).returning();
  await db.insert(schema.groupMembers).values({ groupId: group.id, userId, createdAt: now });

  const [host] = await db.insert(schema.proxyHosts).values({
    name: `host-${tag}`, domains: '["app.example.com"]', upstreams: '["backend:8080"]',
    ownerUserId: userId, createdAt: now, updatedAt: now,
  }).returning();
  await db.insert(schema.forwardAuthAccess).values({ proxyHostId: host.id, userId, createdAt: now });
  const [forwardAuthSession] = await db.insert(schema.forwardAuthSessions).values({
    userId, proxyHostId: host.id, audienceOrigin: 'https://app.example.com',
    tokenHash: `fa-${tag}`, expiresAt: later, createdAt: now,
  }).returning();
  await db.insert(schema.forwardAuthExchanges).values({
    sessionId: forwardAuthSession.id, proxyHostId: host.id, audienceOrigin: 'https://app.example.com',
    codeHash: `code-${tag}`, sessionToken: 'placeholder', redirectUri: 'https://app.example.com/',
    expiresAt: later, createdAt: now,
  });

  await db.insert(schema.l4ProxyHosts).values({
    name: `l4-${tag}`, protocol: 'tcp', listenAddress: ':5432', upstreams: '["db:5432"]',
    ownerUserId: userId, createdAt: now, updatedAt: now,
  });
  const [list] = await db.insert(schema.accessLists).values({
    name: `list-${tag}`, createdBy: userId, createdAt: now, updatedAt: now,
  }).returning();
  await db.insert(schema.accessListRules).values({
    accessListId: list.id, position: 0, action: 'deny', kind: 'ip', matchValues: '["198.51.100.1"]',
    createdBy: userId, createdAt: now, updatedAt: now,
  });
  await db.insert(schema.certificates).values({
    name: `cert-${tag}`, type: 'managed', domainNames: '["app.example.com"]',
    createdBy: userId, createdAt: now, updatedAt: now,
  });
  const [ca] = await db.insert(schema.caCertificates).values({
    name: `ca-${tag}`, certificatePem: 'ca-pem', createdBy: userId, createdAt: now, updatedAt: now,
  }).returning();
  await db.insert(schema.issuedClientCertificates).values({
    caCertificateId: ca.id, commonName: `client-${tag}`, serialNumber: tag, fingerprintSha256: tag,
    certificatePem: 'client-pem', validFrom: now, validTo: later, createdBy: userId, createdAt: now, updatedAt: now,
  });
  await db.insert(schema.mtlsRoles).values({
    name: `role-${tag}`, createdBy: userId, createdAt: now, updatedAt: now,
  });
  await db.insert(schema.mtlsAccessRules).values({
    proxyHostId: host.id, pathPattern: '/admin/*', createdBy: userId, createdAt: now, updatedAt: now,
  });
  await db.insert(schema.auditEvents).values({
    userId, action: 'create', entityType: 'proxy_host', entityId: host.id, summary: 'Created host', createdAt: now,
  });
  await db.insert(schema.customRoles).values({
    name: `custom-role-${tag}`, permissions: '["proxy_hosts:read"]', createdBy: userId, createdAt: now, updatedAt: now,
  });

  return { rawToken, forwardAuthSessionId: forwardAuthSession.id };
}

async function countWhere(table: SQLiteTable, column: SQLiteColumn, userId: number): Promise<number> {
  const row = await first(ctx.db.select({ n: count() }).from(table).where(eq(column, userId)).limit(1));
  return row!.n;
}

/** Link-account flow states in the verifications table that name `userId`. */
async function linkStatesFor(userId: number): Promise<number> {
  const rows = await ctx.db.select().from(schema.verifications);
  return rows.filter((row) => {
    try {
      return String(JSON.parse(row.value)?.link?.userId) === String(userId);
    } catch {
      return false;
    }
  }).length;
}

/** Rows that reference `userId`, per table, in the column that references users.id. */
async function referencesTo(userId: number) {
  return {
    sessions: await countWhere(schema.sessions, schema.sessions.userId, userId),
    accounts: await countWhere(schema.accounts, schema.accounts.userId, userId),
    twoFactors: await countWhere(schema.twoFactors, schema.twoFactors.userId, userId),
    passkeys: await countWhere(schema.passkeys, schema.passkeys.userId, userId),
    userPreferences: await countWhere(schema.userPreferences, schema.userPreferences.userId, userId),
    pendingOAuthLinks: await countWhere(schema.pendingOAuthLinks, schema.pendingOAuthLinks.userId, userId),
    linkStates: await linkStatesFor(userId),
    apiTokens: await countWhere(schema.apiTokens, schema.apiTokens.createdBy, userId),
    groupMembers: await countWhere(schema.groupMembers, schema.groupMembers.userId, userId),
    forwardAuthAccess: await countWhere(schema.forwardAuthAccess, schema.forwardAuthAccess.userId, userId),
    forwardAuthSessions: await countWhere(schema.forwardAuthSessions, schema.forwardAuthSessions.userId, userId),
    auditEvents: await countWhere(schema.auditEvents, schema.auditEvents.userId, userId),
    proxyHosts: await countWhere(schema.proxyHosts, schema.proxyHosts.ownerUserId, userId),
    l4ProxyHosts: await countWhere(schema.l4ProxyHosts, schema.l4ProxyHosts.ownerUserId, userId),
    accessLists: await countWhere(schema.accessLists, schema.accessLists.createdBy, userId),
    accessListRules: await countWhere(schema.accessListRules, schema.accessListRules.createdBy, userId),
    certificates: await countWhere(schema.certificates, schema.certificates.createdBy, userId),
    caCertificates: await countWhere(schema.caCertificates, schema.caCertificates.createdBy, userId),
    issuedClientCertificates:
      await countWhere(schema.issuedClientCertificates, schema.issuedClientCertificates.createdBy, userId),
    mtlsRoles: await countWhere(schema.mtlsRoles, schema.mtlsRoles.createdBy, userId),
    mtlsAccessRules: await countWhere(schema.mtlsAccessRules, schema.mtlsAccessRules.createdBy, userId),
    groups: await countWhere(schema.groups, schema.groups.createdBy, userId),
    customRoles: await countWhere(schema.customRoles, schema.customRoles.createdBy, userId),
  };
}

type References = Awaited<ReturnType<typeof referencesTo>>;

/** What seedReferences adds for one user. */
const SEEDED: References = {
  sessions: 1, accounts: 1, twoFactors: 1, passkeys: 1, userPreferences: 1, pendingOAuthLinks: 1, linkStates: 2, apiTokens: 1, groupMembers: 1,
  forwardAuthAccess: 1, forwardAuthSessions: 1, auditEvents: 1, proxyHosts: 1, l4ProxyHosts: 1,
  accessLists: 1, accessListRules: 1, certificates: 1, caCertificates: 1, issuedClientCertificates: 1, mtlsRoles: 1,
  mtlsAccessRules: 1, groups: 1, customRoles: 1,
};
const NONE = Object.fromEntries(Object.keys(SEEDED).map((key) => [key, 0])) as References;

/** Rows whose user column (onDelete: "set null") is null, per table. */
async function rowsWithoutUser() {
  const nulls = async (table: SQLiteTable, column: SQLiteColumn) =>
    (await first(ctx.db.select({ n: count() }).from(table).where(sql`${column} is null`).limit(1)))!.n;
  return {
    auditEvents: await nulls(schema.auditEvents, schema.auditEvents.userId),
    proxyHosts: await nulls(schema.proxyHosts, schema.proxyHosts.ownerUserId),
    l4ProxyHosts: await nulls(schema.l4ProxyHosts, schema.l4ProxyHosts.ownerUserId),
    accessLists: await nulls(schema.accessLists, schema.accessLists.createdBy),
    accessListRules: await nulls(schema.accessListRules, schema.accessListRules.createdBy),
    certificates: await nulls(schema.certificates, schema.certificates.createdBy),
    caCertificates: await nulls(schema.caCertificates, schema.caCertificates.createdBy),
    issuedClientCertificates: await nulls(schema.issuedClientCertificates, schema.issuedClientCertificates.createdBy),
    mtlsRoles: await nulls(schema.mtlsRoles, schema.mtlsRoles.createdBy),
    mtlsAccessRules: await nulls(schema.mtlsAccessRules, schema.mtlsAccessRules.createdBy),
    groups: await nulls(schema.groups, schema.groups.createdBy),
    customRoles: await nulls(schema.customRoles, schema.customRoles.createdBy),
  };
}

async function exchangesFor(forwardAuthSessionId: number): Promise<number> {
  return countWhere(schema.forwardAuthExchanges, schema.forwardAuthExchanges.sessionId, forwardAuthSessionId);
}

const migrationsFolder = resolve(process.cwd(), 'drizzle');

/** A database with foreign keys off (as in production) and the migrations up to and including `lastTag`. */
async function databaseMigratedTo(lastTag: string): Promise<TestDb> {
  const folder = mkdtempSync(join(tmpdir(), 'ingressi-migrations-'));
  try {
    cpSync(migrationsFolder, folder, { recursive: true });
    const journalPath = join(folder, 'meta', '_journal.json');
    const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as { entries: { tag: string }[] };
    expect(journal.entries.map((entry) => entry.tag)).toContain(lastTag);
    journal.entries = journal.entries.filter((entry) => entry.tag <= lastTag);
    writeFileSync(journalPath, JSON.stringify(journal));

    const connection = new Database(':memory:');
    connection.pragma('foreign_keys = OFF');
    migrate(drizzle(connection, { schema, casing: 'snake_case' }), { migrationsFolder: folder });
    return createSqliteExecutor(connection, { casing: 'snake_case', exposeClient: true }).db as TestDb;
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
}

/** The accounts the primary admin has, by providerId. */
async function adminAccounts(): Promise<string[]> {
  const rows = await ctx.db.select().from(schema.accounts).where(eq(schema.accounts.userId, 1));
  return rows.map((row) => row.providerId);
}

describe('deleteUser with foreign keys off', () => {
  it('runs against a database that does not cascade', async () => {
    if (testDbIsPostgres()) {
      const constraints = await execRaw<{ n: number }>(
        sql`select count(*)::int as n from information_schema.table_constraints where constraint_type = 'FOREIGN KEY' and table_schema = current_schema()`,
        ctx.db
      );
      expect(constraints).toEqual([{ n: 0 }]);
      return;
    }
    expect(await first(execRaw(sql`PRAGMA foreign_keys`, ctx.db))).toEqual({ foreign_keys: 0 });
  });

  it('covers every reference to users.id in the schema', () => {
    // deleteUserReferences and referencesTo handle exactly these; a new
    // reference has to be added to both.
    const references = (Object.values(authoringSchema) as unknown[])
      .filter((value): value is SQLiteTable => is(value, SQLiteTable))
      .flatMap((table) => {
        const { name, foreignKeys } = getTableConfig(table);
        return foreignKeys
          .filter((foreignKey) => foreignKey.reference().foreignTable === authoringSchema.users)
          .map((foreignKey) => `${name}.${foreignKey.reference().columns[0].name} ${foreignKey.onDelete}`);
      });
    // deleteOrphanedUserReferences reads them through referencesTo("users").
    expect(
      schemaReferencesTo('users').map(({ tableName, columnName, onDelete }) => `${tableName}.${columnName} ${onDelete}`).sort()
    ).toEqual([...references].sort());
    expect(schemaReferencesTo('users').every(({ table, column }) =>
      (Object.values(schema) as unknown[]).includes(table) && Object.values(table).includes(column)
    )).toBe(true);
    expect(references.sort()).toEqual([
      'access_list_rules.createdBy set null',
      'access_lists.createdBy set null',
      'accounts.userId cascade',
      'api_tokens.createdBy cascade',
      'audit_events.userId set null',
      'ca_certificates.createdBy set null',
      'certificates.createdBy set null',
      'custom_roles.createdBy set null',
      'forward_auth_access.userId cascade',
      'forward_auth_sessions.userId cascade',
      'group_members.userId cascade',
      'groups.createdBy set null',
      'issued_client_certificates.createdBy set null',
      'l4_proxy_hosts.ownerUserId set null',
      'mcp_oauth_codes.userId cascade',
      'mcp_oauth_consents.userId cascade',
      'mcp_oauth_tokens.userId cascade',
      'mtls_access_rules.createdBy set null',
      'mtls_roles.createdBy set null',
      'passkeys.userId cascade',
      'pending_oauth_links.userId cascade',
      'proxy_hosts.ownerUserId set null',
      'sessions.userId cascade',
      'two_factors.userId cascade',
      'user_preferences.userId cascade',
    ]);
  });

  it("deletes the user's rows and clears the user from rows that only record it", async () => {
    const doomed = await seedUser('doomed@example.com');
    const kept = await seedUser('kept@example.com');
    const doomedRefs = await seedReferences(doomed);
    const keptRefs = await seedReferences(kept);
    await ctx.db.insert(schema.verifications).values({
      identifier: 'unrelated', value: 'not json', expiresAt: new Date().toISOString(),
    });
    expect(await referencesTo(doomed)).toEqual(SEEDED);

    await deleteUser(doomed);

    expect(await getUserById(doomed)).toBeNull();
    expect(await referencesTo(doomed)).toEqual(NONE);
    expect(await exchangesFor(doomedRefs.forwardAuthSessionId)).toBe(0);
    expect(await validateToken(doomedRefs.rawToken)).toBeNull();
    // The rows themselves survive, without a user.
    expect(Object.values(await rowsWithoutUser())).toEqual(Array(12).fill(1));
    const audit = await ctx.db.select().from(schema.auditEvents);
    expect(audit.map((event) => event.userId).sort()).toEqual([kept, null].sort());

    // Nothing of the other user changes.
    expect(await referencesTo(kept)).toEqual(SEEDED);
    expect(await exchangesFor(keptRefs.forwardAuthSessionId)).toBe(1);
    expect(await validateToken(keptRefs.rawToken)).not.toBeNull();
    expect(await first(ctx.db.select().from(schema.verifications).where(eq(schema.verifications.identifier, 'unrelated')).limit(1)))
      .toBeDefined();
  });

  it('leaves nothing for a primary admin recreated after deleteUser', { timeout: 20_000 }, async () => {
    await ensureAdminUser();
    const { rawToken, forwardAuthSessionId } = await seedReferences(1);
    expect(await validateToken(rawToken)).not.toBeNull();

    await deleteUser(1);
    // A deleted primary admin comes back only when the environment credentials change (account recovery).
    await ensureAdminUser();
    expect(await getUserById(1)).toBeNull();
    ctx.admin.adminPassword = 'Recovery-Password-2026!';
    await ensureAdminUser();

    expect((await getUserById(1))?.role).toBe('admin');
    expect(await validateToken(rawToken)).toBeNull();
    expect(await exchangesFor(forwardAuthSessionId)).toBe(0);
    // Only the credential account ensureAdminUser creates.
    expect(await adminAccounts()).toEqual(['credential']);
    expect(await referencesTo(1)).toEqual({ ...NONE, accounts: 1 });
  });
});

describe('ensureAdminUser after a deletion that did not cascade', { timeout: 20_000 }, () => {
  it('clears what the deleted primary admin left under its id', async () => {
    await ensureAdminUser();
    const { rawToken, forwardAuthSessionId } = await seedReferences(1);
    // What deleteUser did before it cascaded: only the users row goes.
    await ctx.db.delete(schema.users).where(eq(schema.users.id, 1));
    expect(await referencesTo(1)).toEqual({ ...SEEDED, accounts: 2 });

    ctx.admin.adminPassword = 'Recovery-Password-2026!';
    await ensureAdminUser();

    expect((await getUserById(1))?.role).toBe('admin');
    expect(await validateToken(rawToken)).toBeNull();
    expect(await exchangesFor(forwardAuthSessionId)).toBe(0);
    expect(await adminAccounts()).toEqual(['credential']);
    expect(await referencesTo(1)).toEqual({ ...NONE, accounts: 1 });
    expect((await rowsWithoutUser()).auditEvents).toBe(1);
  });

  // SQLite's own history: the migrations before 0022 and its table rebuild.
  it.skipIf(testDbIsPostgres())('clears what any deleted user left before a users-table rebuild hands its id out again', async () => {
    // A release before migration 0022, where deleteUser removed only the users row.
    ctx.db = await databaseMigratedTo('0021_camelcase_columns');
    await seedLegacyUser('admin@example.com');
    const kept = await seedLegacyUser('kept@example.com');
    const doomed = await seedLegacyUser('doomed@example.com');
    await execRaw(sql`delete from users where id = ${doomed}`, ctx.db);

    // The upgrade: 0022 rebuilds the users table, which resets its
    // AUTOINCREMENT counter to the highest id left.
    migrate(syncTestDb(ctx.db), { migrationsFolder });
    const keptRefs = await seedReferences(kept);
    const doomedRefs = await seedReferences(doomed);
    // A link-account flow that is all another deleted user left, and
    // verification rows that are not link-account flows.
    const now = new Date().toISOString();
    for (const [identifier, value] of [
      ['state-only', JSON.stringify({ codeVerifier: 'verifier', link: { email: 'gone@example.com', userId: '7' } })],
      ['sign-in-state', JSON.stringify({ codeVerifier: 'verifier', callbackURL: 'https://ingressi.example.com/' })],
      ['not-json', 'not json'],
    ]) {
      await ctx.db.insert(schema.verifications).values({ identifier, value, expiresAt: now, createdAt: now, updatedAt: now });
    }

    await ensureAdminUser();
    const newcomer = await seedUser('new@example.com');

    expect(newcomer).toBe(doomed);
    expect(await referencesTo(newcomer)).toEqual(NONE);
    expect(await validateToken(doomedRefs.rawToken)).toBeNull();
    expect(await exchangesFor(doomedRefs.forwardAuthSessionId)).toBe(0);
    expect(Object.values(await rowsWithoutUser())).toEqual(Array(12).fill(1));
    expect(await linkStatesFor(7)).toBe(0);
    expect(await referencesTo(kept)).toEqual(SEEDED);
    expect(await validateToken(keptRefs.rawToken)).not.toBeNull();
    expect(await exchangesFor(keptRefs.forwardAuthSessionId)).toBe(1);
    const verifications = await ctx.db.select({ identifier: schema.verifications.identifier })
      .from(schema.verifications);
    expect(verifications.map((row) => row.identifier)).toEqual(expect.arrayContaining(['sign-in-state', 'not-json']));
  });

  it('keeps verification rows that are not link-account states when no user exists yet', async () => {
    const now = new Date().toISOString();
    for (const [identifier, value] of [
      ['sign-in-state', JSON.stringify({ codeVerifier: 'verifier', callbackURL: 'https://ingressi.example.com/' })],
      ['not-json', 'not json'],
    ]) {
      await ctx.db.insert(schema.verifications).values({ identifier, value, expiresAt: now, createdAt: now, updatedAt: now });
    }
    expect(await first(ctx.db.select({ n: count() }).from(schema.users).limit(1))).toEqual({ n: 0 });

    await ensureAdminUser();

    const verifications = await ctx.db.select({ identifier: schema.verifications.identifier })
      .from(schema.verifications);
    expect(verifications.map((row) => row.identifier).sort()).toEqual(['not-json', 'sign-in-state']);
  });

  it('keeps the rows of an admin that still exists', async () => {
    await ensureAdminUser();
    await seedReferences(1);

    await ensureAdminUser();

    expect(await referencesTo(1)).toEqual({ ...SEEDED, accounts: 2 });
  });
});
