/**
 * Permissions that became administrator-level leave the roles that already
 * held them, once (ee/custom-roles/reclassified.ts): until then anybody with
 * users:write could hand them out.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import * as schema from '../../src/lib/db/schema';
import { insertRole } from '../helpers/custom-roles';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));
vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));
const audit = vi.hoisted(() => ({ logAuditEvent: vi.fn() }));
vi.mock('../../src/lib/audit', () => audit);

import { RECLASSIFIED, RECLASSIFIED_KEY, removeReclassifiedPermissions } from '@/ee/custom-roles/reclassified';
import { ADMIN_LEVEL_COMBINATIONS, ADMIN_LEVEL_PERMISSIONS, isAdminLevel, type Permission } from '@/src/lib/permissions';

async function permissionsOf(id: number): Promise<string[]> {
  const [row] = await ctx.db.select().from(schema.customRoles).where(eq(schema.customRoles.id, id));
  return JSON.parse(row.permissions);
}

beforeEach(() => {
  ctx.db = createTestDb();
  audit.logAuditEvent.mockReset();
});

describe('removeReclassifiedPermissions', () => {
  it('takes config:import, and backups:restore held with backups:write, out of existing roles and keeps the rest', async () => {
    await insertRole(ctx.db, 1, ['proxy_hosts:read', 'config:export', 'config:import'], [], 'Importer');
    await insertRole(ctx.db, 2, ['backups:read', 'backups:write', 'backups:restore'], [], 'Backup operator');
    await insertRole(ctx.db, 3, ['backups:read', 'backups:restore'], [], 'Restorer');
    await insertRole(ctx.db, 4, ['proxy_hosts:read', 'proxy_hosts:write'], ['team-a'], 'Team A');
    await insertRole(ctx.db, 5, ['config:import', 'backups:read', 'backups:write', 'backups:restore', 'sso:write'], [], 'Everything');

    const changed = await removeReclassifiedPermissions();

    expect(changed).toEqual([
      { id: 1, name: 'Importer', removed: ['config:import'] },
      { id: 2, name: 'Backup operator', removed: ['backups:restore'] },
      { id: 5, name: 'Everything', removed: ['config:import', 'backups:restore'] },
    ]);
    expect(await permissionsOf(1)).toEqual(['proxy_hosts:read', 'config:export']);
    expect(await permissionsOf(2)).toEqual(['backups:read', 'backups:write']);
    // backups:restore alone restores only from destinations somebody else set up: not administrator-level.
    expect(await permissionsOf(3)).toEqual(['backups:read', 'backups:restore']);
    expect(await permissionsOf(4)).toEqual(['proxy_hosts:read', 'proxy_hosts:write']);
    // What was administrator-level all along was an administrator's to give, and stays.
    expect(await permissionsOf(5)).toEqual(['backups:read', 'backups:write', 'sso:write']);
    for (const id of [1, 2, 3, 4]) expect(isAdminLevel((await permissionsOf(id)) as Permission[]), `role ${id}`).toBe(false);

    expect(audit.logAuditEvent).toHaveBeenCalledTimes(3);
    expect(audit.logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      action: 'update',
      entityType: 'custom_role',
      entityId: 1,
      summary: expect.stringMatching(/^Removed config:import from role Importer: it is administrator-level/),
    }));
  });

  it('does it once: what an administrator grants again afterwards stays', async () => {
    await insertRole(ctx.db, 1, ['config:import'], [], 'Importer');
    expect(await removeReclassifiedPermissions()).toHaveLength(1);

    await ctx.db.update(schema.customRoles).set({ permissions: JSON.stringify(['config:import', 'backups:write', 'backups:restore']) }).where(eq(schema.customRoles.id, 1));
    await insertRole(ctx.db, 2, ['config:import'], [], 'Granted later');
    expect(await removeReclassifiedPermissions()).toEqual([]);
    expect(await permissionsOf(1)).toEqual(['config:import', 'backups:write', 'backups:restore']);
    expect(await permissionsOf(2)).toEqual(['config:import']);
    expect(audit.logAuditEvent).toHaveBeenCalledTimes(1);
  });

  it('records that it ran on an installation without roles, so roles made later are left alone', async () => {
    expect(await removeReclassifiedPermissions()).toEqual([]);
    const [row] = await ctx.db.select().from(schema.settings).where(eq(schema.settings.key, RECLASSIFIED_KEY));
    expect(JSON.parse(row.value)).toEqual(RECLASSIFIED.map((entry) => entry.id));

    await insertRole(ctx.db, 1, ['config:import'], [], 'New');
    expect(await removeReclassifiedPermissions()).toEqual([]);
    expect(await permissionsOf(1)).toEqual(['config:import']);
  });

  it('applies an entry added in a later release, and only that one', async () => {
    await ctx.db.insert(schema.settings).values({ key: RECLASSIFIED_KEY, value: JSON.stringify(['config:import']), updatedAt: new Date().toISOString() });
    await insertRole(ctx.db, 1, ['config:import', 'backups:write', 'backups:restore'], [], 'Both');
    expect(await removeReclassifiedPermissions()).toEqual([{ id: 1, name: 'Both', removed: ['backups:restore'] }]);
    expect(await permissionsOf(1)).toEqual(['config:import', 'backups:write']);
  });

  it('leaves a role with unreadable permissions alone', async () => {
    await insertRole(ctx.db, 1, [], [], 'Broken');
    await ctx.db.update(schema.customRoles).set({ permissions: 'not json' }).where(eq(schema.customRoles.id, 1));
    expect(await removeReclassifiedPermissions()).toEqual([]);
    const [row] = await ctx.db.select().from(schema.customRoles).where(eq(schema.customRoles.id, 1));
    expect(row.permissions).toBe('not json');
  });

  it('covers what is administrator-level: every entry is one, or completes a combination', () => {
    for (const entry of RECLASSIFIED) {
      expect(isAdminLevel(entry.held), entry.id).toBe(true);
      expect(entry.held, entry.id).toContain(entry.remove);
      expect(isAdminLevel(entry.held.filter((permission) => permission !== entry.remove)), entry.id).toBe(false);
      const known =
        (entry.held.length === 1 && ADMIN_LEVEL_PERMISSIONS.includes(entry.held[0])) ||
        ADMIN_LEVEL_COMBINATIONS.some((combination) => combination.length === entry.held.length && combination.every((permission) => entry.held.includes(permission)));
      expect(known, entry.id).toBe(true);
    }
  });
});
