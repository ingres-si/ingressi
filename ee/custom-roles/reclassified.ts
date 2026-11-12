// SPDX-License-Identifier: Elastic-2.0
/**
 * Permissions that became administrator-level after custom roles could
 * already hold them (see ADMIN_LEVEL_PERMISSIONS in src/lib/permissions.ts).
 *
 * Until then anybody with users:write could hand them out, so a role that
 * holds one was not necessarily given it by an administrator. Each of them
 * is therefore taken out of every existing role once, on the first start of
 * a release that knows it: the role keeps everything else, an audit event
 * names the role and what it lost, and an administrator who wants the role
 * to have it grants it again (which only administrators can do from then
 * on). The list of what has been taken out is kept in the settings row
 * `admin_level_reclassified`, so a permission granted again stays.
 */
import { eq } from "drizzle-orm";
import { appDb, nowIso } from "@/src/lib/db";
import { customRoles, settings } from "@/src/lib/db/schema";
import { first } from "@/src/lib/db/ops";
import { logAuditEvent } from "@/src/lib/audit";
import { isPermission, type Permission } from "@/src/lib/permissions";

/** `remove` is taken out of every role that holds all of `held`. Only ever add to this list. */
export const RECLASSIFIED: readonly { id: string; held: readonly Permission[]; remove: Permission }[] = [
  // Replaces the whole configuration with a file the caller supplies.
  { id: "config:import", held: ["config:import"], remove: "config:import" },
  // Together: a restore from a destination the role chose.
  { id: "backups:write+backups:restore", held: ["backups:write", "backups:restore"], remove: "backups:restore" },
];

export const RECLASSIFIED_KEY = "admin_level_reclassified";

export type ReclassifiedRole = { id: number; name: string; removed: Permission[] };

function parseList(raw: string | null | undefined): string[] {
  try {
    const value: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

/**
 * Takes the newly administrator-level permissions out of the existing roles,
 * once per entry of RECLASSIFIED. Returns the roles it changed. Safe to run
 * on every start and on several replicas at once.
 */
export async function removeReclassifiedPermissions(): Promise<ReclassifiedRole[]> {
  const changed = await appDb.transaction(async (tx) => {
    const row = await first(tx.select({ value: settings.value }).from(settings).where(eq(settings.key, RECLASSIFIED_KEY)).limit(1));
    const done = parseList(row?.value);
    const due = RECLASSIFIED.filter((entry) => !done.includes(entry.id));
    if (due.length === 0) return [];

    const roles: ReclassifiedRole[] = [];
    const now = nowIso();
    for (const role of await tx.select().from(customRoles)) {
      const held = parseList(role.permissions).filter(isPermission);
      const removed: Permission[] = [];
      for (const entry of due) {
        if (entry.held.every((permission) => held.includes(permission)) && !removed.includes(entry.remove)) {
          removed.push(entry.remove);
        }
      }
      if (removed.length === 0) continue;
      await tx
        .update(customRoles)
        .set({ permissions: JSON.stringify(held.filter((permission) => !removed.includes(permission))), updatedAt: now })
        .where(eq(customRoles.id, role.id));
      roles.push({ id: role.id, name: role.name, removed });
    }

    const value = JSON.stringify([...done, ...due.map((entry) => entry.id)]);
    await tx
      .insert(settings)
      .values({ key: RECLASSIFIED_KEY, value, updatedAt: now })
      .onConflictDoUpdate({ target: settings.key, set: { value, updatedAt: now } });
    return roles;
  });

  for (const role of changed) {
    await logAuditEvent({
      action: "update",
      entityType: "custom_role",
      entityId: role.id,
      summary:
        `Removed ${role.removed.join(", ")} from role ${role.name}: ` +
        "it is administrator-level from this release on, and only an administrator can grant it (again)",
      data: { removed: role.removed },
    });
  }
  return changed;
}
