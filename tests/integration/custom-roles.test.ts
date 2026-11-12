/**
 * Custom roles end to end through the REST API, with real API tokens and the
 * real guards: the roles and permissions endpoints, the escalation guards,
 * role assignment on the user endpoints and deleting a role.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import * as schema from '../../src/lib/db/schema';
import { apiRequest, idParams, insertRole, insertToken, insertUser, json } from '../helpers/custom-roles';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));

import * as rolesRoute from '@/app/api/v1/roles/route';
import * as roleRoute from '@/app/api/v1/roles/[id]/route';
import * as permissionsRoute from '@/app/api/v1/permissions/route';
import * as usersRoute from '@/app/api/v1/users/route';
import * as userRoute from '@/app/api/v1/users/[id]/route';
import * as userMfaRoute from '@/app/api/v1/users/[id]/mfa/route';
import * as proxyHostsRoute from '@/app/api/v1/proxy-hosts/route';
import { logAuditEvent } from '@/src/lib/audit';
import { assertActiveAdminRemains, LAST_ADMIN_MESSAGE } from '@/ee/custom-roles/escalation';
import { accessForUser } from '@/ee/custom-roles/access';
import { PERMISSIONS } from '@/src/lib/permissions';
import { isMfaRequiredFor, MFA_POLICY_SETTING_KEY } from '@/src/lib/mfa';
import { first } from '@/src/lib/db/ops';

const ADMIN = 1;
const ADMIN2 = 2;
const MANAGER = 3; // custom role "Managers": users:write, proxy_hosts:write
const MEMBER = 4; // built-in user
const SCOPED_MANAGER = 5; // custom role scoped to team-a: users:write, proxy_hosts:write
const SSO_MANAGER = 6; // custom role holding sso:write as well (created by an administrator)

const MANAGERS = 1;
const SCOPED = 2;
const SSO_MANAGERS = 3;
const READERS = 4; // proxy_hosts:read only

let tokens: Record<'admin' | 'manager' | 'member' | 'scoped' | 'sso', string>;

async function user(id: number) {
  return (await first(ctx.db.select().from(schema.users).where(eq(schema.users.id, id)).limit(1)))!;
}

beforeEach(async () => {
  ctx.db = createTestDb();
  vi.mocked(logAuditEvent).mockClear();
  await insertRole(ctx.db, MANAGERS, ['users:read', 'users:write', 'proxy_hosts:read', 'proxy_hosts:write'], [], 'Managers');
  await insertRole(ctx.db, SCOPED, ['users:read', 'users:write', 'proxy_hosts:read', 'proxy_hosts:write'], ['team-a'], 'Team A leads');
  await insertRole(ctx.db, SSO_MANAGERS, ['users:read', 'users:write', 'sso:read', 'sso:write'], [], 'SSO managers');
  await insertRole(ctx.db, READERS, ['proxy_hosts:read'], [], 'Readers');
  await insertUser(ctx.db, ADMIN, 'admin');
  await insertUser(ctx.db, ADMIN2, 'admin');
  await insertUser(ctx.db, MANAGER, 'viewer', MANAGERS);
  await insertUser(ctx.db, MEMBER, 'user');
  await insertUser(ctx.db, SCOPED_MANAGER, 'viewer', SCOPED);
  await insertUser(ctx.db, SSO_MANAGER, 'viewer', SSO_MANAGERS);
  tokens = {
    admin: await insertToken(ctx.db, ADMIN),
    manager: await insertToken(ctx.db, MANAGER),
    member: await insertToken(ctx.db, MEMBER),
    scoped: await insertToken(ctx.db, SCOPED_MANAGER),
    sso: await insertToken(ctx.db, SSO_MANAGER),
  };
});

async function createRole(token: string, body: unknown) {
  return rolesRoute.POST(apiRequest('POST', '/api/v1/roles', token, body));
}

async function setUser(token: string, id: number, body: unknown) {
  return userRoute.PUT(apiRequest('PUT', `/api/v1/users/${id}`, token, body), idParams(id));
}

describe('roles and permissions endpoints', () => {
  it('describes the catalogue', async () => {
    const response = await permissionsRoute.GET(apiRequest('GET', '/api/v1/permissions', tokens.manager));
    expect(response.status).toBe(200);
    const catalogue = await json(response);
    expect(catalogue.areas.flatMap((area: { permissions: string[] }) => area.permissions)).toEqual([...PERMISSIONS]);
    expect(catalogue.adminLevel.permissions).toContain('sso:write');
    expect(catalogue.adminLevel.combinations).toEqual([['users:write', 'settings:write'], ['users:write', 'approvals:approve'], ['backups:write', 'backups:restore']]);
    expect(catalogue.adminLevel.permissions).toContain('config:import');
    expect(catalogue.unscopedOnly).toContain('config:export');
    expect((await permissionsRoute.GET(apiRequest('GET', '/api/v1/permissions', tokens.member))).status).toBe(403);
  });

  it('creates a role, completing read permissions, and records it', async () => {
    const response = await createRole(tokens.admin, {
      name: 'Operators', description: 'Runs the hosts', permissions: ['proxy_hosts:write', 'certificates:read'], scopeTags: ['Team-B'],
    });
    expect(response.status).toBe(201);
    const role = await json(response);
    expect(role).toMatchObject({
      name: 'Operators',
      description: 'Runs the hosts',
      permissions: ['proxy_hosts:read', 'proxy_hosts:write', 'certificates:read'],
      scopeTags: ['team-b'],
      userCount: 0,
      adminLevel: false,
    });
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'create', entityType: 'custom_role', entityId: role.id }));

    const list = await json(await rolesRoute.GET(apiRequest('GET', '/api/v1/roles', tokens.manager)));
    expect(list.map((item: { name: string }) => item.name)).toContain('Operators');
    const one = await json(await roleRoute.GET(apiRequest('GET', `/api/v1/roles/${role.id}`, tokens.admin), idParams(role.id)));
    expect(one.id).toBe(role.id);
    expect((await roleRoute.GET(apiRequest('GET', '/api/v1/roles/999', tokens.admin), idParams(999))).status).toBe(404);
  });

  it.each([
    [{ name: 'X', permissions: ['proxy_hosts:delete'] }, 400, /Unknown permission/],
    [{ name: 'X', permissions: ['proxy_hosts:read'], colour: 'red' }, 400, /Unknown role field/],
    [{ name: '', permissions: [] }, 400, /name is required/],
    [{ name: 'Admin', permissions: [] }, 400, /built-in role/],
    [{ name: 'X', permissions: 'proxy_hosts:read' }, 400, /permissions must be an array/],
    [{ name: 'X', permissions: [], scopeTags: ['bad tag'] }, 400, /Invalid tag/],
    [{ name: 'X', permissions: ['config:export'], scopeTags: ['team-a'] }, 400, /tag scope cannot have config:export/],
    [{ name: 'X', permissions: ['backups:restore'], scopeTags: ['team-a'] }, 400, /tag scope cannot have/],
    [{ name: 'managers', permissions: [] }, 409, /already exists/],
  ])('refuses %j', async (body, status, message) => {
    const response = await createRole(tokens.admin, body);
    expect(response.status).toBe(status);
    expect((await json(response)).error).toMatch(message);
  });

  it('updates a role partially and records before and after', async () => {
    const response = await roleRoute.PUT(
      apiRequest('PUT', `/api/v1/roles/${READERS}`, tokens.admin, { permissions: ['proxy_hosts:write'] }),
      idParams(READERS)
    );
    expect(response.status).toBe(200);
    expect(await json(response)).toMatchObject({ name: 'Readers', permissions: ['proxy_hosts:read', 'proxy_hosts:write'] });
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      action: 'update', entityType: 'custom_role', entityId: READERS,
      data: expect.objectContaining({ before: expect.objectContaining({ permissions: ['proxy_hosts:read'] }) }),
    }));
  });
});

describe('a role saved by another release', () => {
  it('loads with the permissions this release knows; unknown names are ignored and dropped when it is saved', async () => {
    // import:write belonged to an area this release no longer has.
    await insertRole(ctx.db, 10, ['proxy_hosts:read', 'import:write', 'not_an_area:write'], [], 'Older release');
    await insertUser(ctx.db, 30, 'viewer', 10);
    const token = await insertToken(ctx.db, 30);

    const one = await roleRoute.GET(apiRequest('GET', '/api/v1/roles/10', tokens.admin), idParams(10));
    expect(one.status).toBe(200);
    expect(await json(one)).toMatchObject({ name: 'Older release', permissions: ['proxy_hosts:read'], userCount: 1, adminLevel: false });
    const list = await json(await rolesRoute.GET(apiRequest('GET', '/api/v1/roles', tokens.admin)));
    expect(list.find((role: { id: number }) => role.id === 10).permissions).toEqual(['proxy_hosts:read']);

    // Its users keep what it still grants, and nothing else.
    expect([...(await accessForUser({ id: 30, role: 'viewer', customRoleId: 10 }, ctx.db)).permissions]).toEqual(['proxy_hosts:read']);
    expect((await proxyHostsRoute.GET(apiRequest('GET', '/api/v1/proxy-hosts', token))).status).toBe(200);
    expect((await usersRoute.GET(apiRequest('GET', '/api/v1/users', token))).status).toBe(403);

    const saved = await roleRoute.PUT(apiRequest('PUT', '/api/v1/roles/10', tokens.admin, { description: 'Kept' }), idParams(10));
    expect(saved.status).toBe(200);
    const row = (await first(ctx.db.select().from(schema.customRoles).where(eq(schema.customRoles.id, 10)).limit(1)))!;
    expect(JSON.parse(row.permissions)).toEqual(['proxy_hosts:read']);
  });
});

describe('taking a custom role away', () => {
  it('assigns a built-in role in its place', async () => {
    const removed = await setUser(tokens.admin, MANAGER, { role: 'user' });
    expect(removed.status).toBe(200);
    expect(await user(MANAGER)).toMatchObject({ role: 'user', customRoleId: null });
  });

  it('deletes a role; its users fall back to viewer, each recorded', async () => {
    await insertUser(ctx.db, 20, 'viewer', READERS);
    await insertUser(ctx.db, 21, 'viewer', READERS);
    const response = await roleRoute.DELETE(apiRequest('DELETE', `/api/v1/roles/${READERS}`, tokens.admin), idParams(READERS));
    expect(response.status).toBe(200);
    expect(await json(response)).toEqual({ affectedUserIds: [20, 21] });
    expect(await user(20)).toMatchObject({ role: 'viewer', customRoleId: null });
    expect(await first(ctx.db.select().from(schema.customRoles).where(eq(schema.customRoles.id, READERS)).limit(1))).toBeUndefined();
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'delete', entityType: 'custom_role', entityId: READERS }));
    for (const id of [20, 21]) {
      expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ entityType: 'user', entityId: id, summary: expect.stringMatching(/fell back to role viewer/) }));
    }
  });
});

describe('API tokens act with their owner\'s role', () => {
  it('lets a custom-role token use its permissions and nothing else', async () => {
    expect((await proxyHostsRoute.GET(apiRequest('GET', '/api/v1/proxy-hosts', tokens.manager))).status).toBe(200);
    const refused = await createRole(tokens.member, { name: 'X', permissions: [] });
    expect(refused.status).toBe(403);
    expect((await json(refused)).error).toBe('Administrator privileges required');
  });

  it('follows a role change on the next request', async () => {
    expect((await usersRoute.GET(apiRequest('GET', '/api/v1/users', tokens.manager))).status).toBe(200);
    await ctx.db.update(schema.users).set({ customRoleId: READERS }).where(eq(schema.users.id, MANAGER));
    const response = await usersRoute.GET(apiRequest('GET', '/api/v1/users', tokens.manager));
    expect(response.status).toBe(403);
    expect((await json(response)).error).toBe('Permission required: users:read');
  });

  it('acts as a viewer when its custom role is gone', async () => {
    await ctx.db.delete(schema.customRoles).where(eq(schema.customRoles.id, MANAGERS));
    expect((await proxyHostsRoute.GET(apiRequest('GET', '/api/v1/proxy-hosts', tokens.manager))).status).toBe(403);
  });
});

describe('escalation guards', () => {
  it('lets a role manager create roles within their own permissions only', async () => {
    expect((await createRole(tokens.manager, { name: 'Host readers', permissions: ['proxy_hosts:read'] })).status).toBe(201);
    const wider = await createRole(tokens.manager, { name: 'Certs', permissions: ['certificates:read'] });
    expect(wider.status).toBe(403);
    expect((await json(wider)).error).toMatch(/only grant permissions/);
  });

  it('keeps administrator-level permissions to administrators, even for a role that holds them', async () => {
    const response = await createRole(tokens.sso, { name: 'SSO', permissions: ['sso:write'] });
    expect(response.status).toBe(403);
    expect((await json(response)).error).toMatch(/Only administrators/);
    expect((await createRole(tokens.admin, { name: 'Platform', permissions: ['users:write', 'settings:write'] })).status).toBe(201);
    const view = await json(await rolesRoute.GET(apiRequest('GET', '/api/v1/roles', tokens.admin)));
    expect(view.find((role: { name: string }) => role.name === 'Platform').adminLevel).toBe(true);
  });

  it('limits a scoped manager to scopes made of their own tags', async () => {
    expect((await createRole(tokens.scoped, { name: 'Team A readers', permissions: ['proxy_hosts:read'], scopeTags: ['team-a'] })).status).toBe(201);
    expect((await createRole(tokens.scoped, { name: 'Everything', permissions: ['proxy_hosts:read'] })).status).toBe(403);
    expect((await createRole(tokens.scoped, { name: 'Team B', permissions: ['proxy_hosts:read'], scopeTags: ['team-b'] })).status).toBe(403);
    // Permissions outside the scoped areas need no scope.
    expect((await createRole(tokens.scoped, { name: 'User readers', permissions: ['users:read'] })).status).toBe(201);
  });

  it('refuses editing or deleting the role you have, or one with more than you hold', async () => {
    expect((await roleRoute.PUT(apiRequest('PUT', `/api/v1/roles/${MANAGERS}`, tokens.manager, { name: 'Bosses' }), idParams(MANAGERS))).status).toBe(403);
    expect((await roleRoute.DELETE(apiRequest('DELETE', `/api/v1/roles/${MANAGERS}`, tokens.manager), idParams(MANAGERS))).status).toBe(403);
    expect((await roleRoute.PUT(apiRequest('PUT', `/api/v1/roles/${SSO_MANAGERS}`, tokens.manager, { name: 'Mine' }), idParams(SSO_MANAGERS))).status).toBe(403);
    expect((await roleRoute.DELETE(apiRequest('DELETE', `/api/v1/roles/${SSO_MANAGERS}`, tokens.manager), idParams(SSO_MANAGERS))).status).toBe(403);
    expect((await roleRoute.PUT(apiRequest('PUT', `/api/v1/roles/${READERS}`, tokens.manager, { name: 'Viewers of hosts' }), idParams(READERS))).status).toBe(200);
  });

  it('needs users:write to manage roles', async () => {
    const readers = await insertToken(ctx.db, await insertUser(ctx.db, 30, 'viewer', READERS));
    expect((await createRole(readers, { name: 'X', permissions: [] })).status).toBe(403);
    expect((await setUser(readers, MEMBER, { customRoleId: READERS })).status).toBe(403);
  });

  it('lets a manager assign a role they cover, and records the change', async () => {
    const response = await setUser(tokens.manager, MEMBER, { customRoleId: READERS });
    expect(response.status).toBe(200);
    expect(await json(response)).toMatchObject({ role: 'viewer', customRoleId: READERS });
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      userId: MANAGER, entityType: 'user', entityId: MEMBER, summary: expect.stringMatching(/from user to custom role Readers/),
    }));
    // Back to a built-in role.
    expect((await setUser(tokens.manager, MEMBER, { role: 'user' })).status).toBe(200);
    expect(await user(MEMBER)).toMatchObject({ role: 'user', customRoleId: null });
  });

  it('refuses assignments a manager may not hand out', async () => {
    for (const body of [{ role: 'admin' }, { customRoleId: SSO_MANAGERS }]) {
      const response = await setUser(tokens.manager, MEMBER, body);
      expect(response.status, JSON.stringify(body)).toBe(403);
    }
    expect(await user(MEMBER)).toMatchObject({ role: 'user', customRoleId: null });
    // A scoped manager cannot hand out an unscoped role; an unscoped one can hand out a scoped one.
    expect((await setUser(tokens.scoped, MEMBER, { customRoleId: MANAGERS })).status).toBe(403);
    expect((await setUser(tokens.manager, MEMBER, { customRoleId: SCOPED })).status).toBe(200);
  });

  it('never lets a non-administrator act on an administrator', async () => {
    expect((await setUser(tokens.manager, ADMIN2, { role: 'viewer' })).status).toBe(403);
    expect((await setUser(tokens.manager, ADMIN2, { status: 'disabled' })).status).toBe(403);
    expect((await setUser(tokens.manager, ADMIN2, { name: 'Renamed' })).status).toBe(403);
    expect((await userRoute.DELETE(apiRequest('DELETE', `/api/v1/users/${ADMIN2}`, tokens.manager), idParams(ADMIN2))).status).toBe(403);
    expect((await userMfaRoute.DELETE(apiRequest('DELETE', `/api/v1/users/${ADMIN2}/mfa`, tokens.manager), idParams(ADMIN2))).status).toBe(403);
    expect(await user(ADMIN2)).toMatchObject({ role: 'admin', status: 'active', name: 'User 2' });
    // Nor on a user with more access than they have.
    expect((await setUser(tokens.manager, SSO_MANAGER, { status: 'disabled' })).status).toBe(403);
  });

  it('refuses changing your own role, whoever you are', async () => {
    expect((await setUser(tokens.admin, ADMIN, { role: 'viewer' })).status).toBe(400);
    expect((await setUser(tokens.manager, MANAGER, { customRoleId: READERS })).status).toBe(400);
    expect((await setUser(tokens.manager, MANAGER, { customRoleId: null })).status).toBe(400);
  });

  it('lets administrators assign anything, admin included', async () => {
    expect((await setUser(tokens.admin, MANAGER, { role: 'admin' })).status).toBe(200);
    expect(await user(MANAGER)).toMatchObject({ role: 'admin', customRoleId: null });
    expect((await setUser(tokens.admin, ADMIN2, { customRoleId: SSO_MANAGERS })).status).toBe(200);
    expect(await user(ADMIN2)).toMatchObject({ role: 'viewer', customRoleId: SSO_MANAGERS });
  });

  it('accepts a GET body sent back and refuses a role together with a custom role', async () => {
    const current = await json(await userRoute.GET(apiRequest('GET', `/api/v1/users/${MANAGER}`, tokens.admin), idParams(MANAGER)));
    expect(current).toMatchObject({ role: 'viewer', customRoleId: MANAGERS });
    expect((await setUser(tokens.admin, MANAGER, current)).status).toBe(200);
    expect((await setUser(tokens.admin, MANAGER, { role: 'user', customRoleId: READERS })).status).toBe(400);
    expect((await setUser(tokens.admin, MANAGER, { customRoleId: 999 })).status).toBe(400);
  });

  it('creates users only with roles the caller may grant', async () => {
    const body = (extra: object) => ({ email: `n${Math.random()}@example.com`, password: 'Correct-Horse-9!', ...extra });
    const created = await usersRoute.POST(apiRequest('POST', '/api/v1/users', tokens.manager, body({ customRoleId: READERS })));
    expect(created.status).toBe(201);
    expect(await json(created)).toMatchObject({ role: 'viewer', customRoleId: READERS });
    expect((await usersRoute.POST(apiRequest('POST', '/api/v1/users', tokens.manager, body({ role: 'admin' })))).status).toBe(403);
    expect((await usersRoute.POST(apiRequest('POST', '/api/v1/users', tokens.manager, body({ customRoleId: SSO_MANAGERS })))).status).toBe(403);
  });

  it('lets users:read see other users, and everyone see themselves', async () => {
    expect((await userRoute.GET(apiRequest('GET', `/api/v1/users/${ADMIN}`, tokens.manager), idParams(ADMIN))).status).toBe(200);
    expect((await userRoute.GET(apiRequest('GET', `/api/v1/users/${ADMIN}`, tokens.member), idParams(ADMIN))).status).toBe(403);
    expect((await userRoute.GET(apiRequest('GET', `/api/v1/users/${MEMBER}`, tokens.member), idParams(MEMBER))).status).toBe(200);
  });
});

describe('last active administrator', () => {
  it('refuses demoting, disabling or deleting the only active administrator', async () => {
    await ctx.db.update(schema.users).set({ status: 'disabled' }).where(eq(schema.users.id, ADMIN2));
    await expect(assertActiveAdminRemains(ctx.db, { userId: ADMIN, role: 'viewer' })).rejects.toThrow(LAST_ADMIN_MESSAGE);
    await expect(assertActiveAdminRemains(ctx.db, { userId: ADMIN, status: 'disabled' })).rejects.toThrow(LAST_ADMIN_MESSAGE);
    await expect(assertActiveAdminRemains(ctx.db, { userId: ADMIN, deleted: true })).rejects.toThrow(LAST_ADMIN_MESSAGE);
    await expect(assertActiveAdminRemains(ctx.db, { userId: ADMIN, role: 'admin' })).resolves.not.toThrow();
    await expect(assertActiveAdminRemains(ctx.db, { userId: MEMBER, role: 'viewer' })).resolves.not.toThrow();
  });

  it('allows it while another active administrator remains', async () => {
    await expect(assertActiveAdminRemains(ctx.db, { userId: ADMIN, role: 'viewer' })).resolves.not.toThrow();
  });

  it('does not count a custom-role user stored with role admin as an administrator', async () => {
    await ctx.db.update(schema.users).set({ customRoleId: READERS }).where(eq(schema.users.id, ADMIN2));
    await expect(assertActiveAdminRemains(ctx.db, { userId: ADMIN, role: 'viewer' })).rejects.toThrow(LAST_ADMIN_MESSAGE);
    expect((await accessForUser({ id: ADMIN2, role: 'admin', customRoleId: READERS }, ctx.db)).isAdmin).toBe(false);
  });
});

describe('MFA policy', () => {
  async function withPassword(userId: number) {
    const now = new Date().toISOString();
    await ctx.db.insert(schema.accounts).values({
      userId, issuer: 'credential', accountId: String(userId), providerId: 'credential', password: '$2a$04$hash', createdAt: now, updatedAt: now,
    });
  }

  it('counts custom-role users as administrators for the "admins" scope', async () => {
    for (const id of [ADMIN, MANAGER, MEMBER]) await withPassword(id);
    await ctx.db.insert(schema.settings).values({
      key: MFA_POLICY_SETTING_KEY, value: JSON.stringify({ scope: 'admins', graceDays: 7, since: new Date().toISOString() }), updatedAt: new Date().toISOString(),
    });
    expect(await isMfaRequiredFor(ctx.db, ADMIN)).toBe(true);
    expect(await isMfaRequiredFor(ctx.db, MANAGER)).toBe(true);
    expect(await isMfaRequiredFor(ctx.db, MEMBER)).toBe(false);
  });
});
