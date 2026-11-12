/**
 * The legacy excluded_rule_ids lists ("waf" setting, each host's meta.waf) as
 * a mirror of the whole-scope WAF rule exclusions (no path, no variable), and
 * writes through those lists. See src/lib/models/waf-exclusions.ts.
 *
 * Kept apart from the exclusions model so that configuration import and
 * restore (config-content.ts) can call importLegacyWafExclusions without
 * pulling in the approvals guard, which imports config-content itself.
 */
import { eq, inArray, isNull } from "drizzle-orm";
import { appDb, nowIso } from "../db";
import { proxyHosts, settings, wafRuleExclusions } from "../db/schema";
import type { DbTransaction } from "../config-content";
import { isValidWafRuleId, isWholeScopeExclusion } from "../waf-exclusions";
import { first } from "@/src/lib/db/ops";

/** Reason recorded for exclusions copied in from a legacy rule list. */
export const LEGACY_EXCLUSION_REASON = "Added to the excluded rule list before exclusions had reasons";
/** Reason recorded for exclusions added through a legacy rule list (settings or proxy host API). */
export const LIST_EXCLUSION_REASON = "Added through the excluded rule list";

const GLOBAL_SETTING_KEY = "waf";

async function wholeScopeRuleIds(tx: DbTransaction, proxyHostId: number | null): Promise<number[]> {
  const rows = await tx
    .select({ ruleId: wafRuleExclusions.ruleId, path: wafRuleExclusions.path, variable: wafRuleExclusions.variable })
    .from(wafRuleExclusions)
    .where(proxyHostId === null ? isNull(wafRuleExclusions.proxyHostId) : eq(wafRuleExclusions.proxyHostId, proxyHostId));
  return [...new Set(rows.filter(isWholeScopeExclusion).map((row) => row.ruleId))].sort((a, b) => a - b);
}

function parseJsonObject(value: string | null | undefined): Record<string, unknown> | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function sameIds(a: unknown, b: number[]): boolean {
  return Array.isArray(a) && a.length === b.length && a.every((id, index) => id === b[index]);
}

/**
 * Rewrites the legacy list of one scope from the records. The global list
 * lives in the "waf" setting, which is only updated when it exists: creating
 * it would change what hosts inherit (and on a sync slave, shadow the
 * master's settings).
 */
export async function syncWafExclusionMirror(tx: DbTransaction, proxyHostId: number | null): Promise<void> {
  const ids = await wholeScopeRuleIds(tx, proxyHostId);
  const now = nowIso();
  if (proxyHostId === null) {
    const row = await first(tx.select({ value: settings.value }).from(settings).where(eq(settings.key, GLOBAL_SETTING_KEY)).limit(1));
    const waf = parseJsonObject(row?.value);
    if (!waf || sameIds(waf.excluded_rule_ids, ids)) return;
    if (ids.length === 0 && waf.excluded_rule_ids === undefined) return;
    const value = JSON.stringify({ ...waf, excluded_rule_ids: ids });
    await tx.update(settings).set({ value, updatedAt: now }).where(eq(settings.key, GLOBAL_SETTING_KEY));
    return;
  }
  const host = await first(tx.select({ meta: proxyHosts.meta }).from(proxyHosts).where(eq(proxyHosts.id, proxyHostId)).limit(1));
  if (!host) return;
  const meta = parseJsonObject(host.meta) ?? {};
  const waf = meta.waf && typeof meta.waf === "object" && !Array.isArray(meta.waf) ? (meta.waf as Record<string, unknown>) : null;
  if (ids.length === 0 ? !waf || waf.excluded_rule_ids === undefined : waf && sameIds(waf.excluded_rule_ids, ids)) return;
  // A WAF section holding only the list changes nothing else about the host
  // (resolveEffectiveWaf treats an unset `enabled` like no section).
  const { excluded_rule_ids: _previous, ...rest } = waf ?? {};
  void _previous;
  const nextWaf = ids.length > 0 ? { ...rest, excluded_rule_ids: ids } : rest;
  const nextMeta = { ...meta };
  if (Object.keys(nextWaf).length > 0) nextMeta.waf = nextWaf;
  else delete nextMeta.waf;
  await tx.update(proxyHosts)
    .set({ meta: Object.keys(nextMeta).length > 0 ? JSON.stringify(nextMeta) : null, updatedAt: now })
    .where(eq(proxyHosts.id, proxyHostId));
}

/**
 * Makes the whole-scope exclusions of a scope exactly `ruleIds` (a write
 * through a legacy list): records for ids no longer listed are deleted, ids
 * without a record get one. Exclusions with a path or variable are untouched.
 * Then the mirror is rewritten. Returns what changed.
 */
export async function replaceWholeScopeExclusions(
  tx: DbTransaction,
  proxyHostId: number | null,
  ruleIds: readonly unknown[],
  actorUserId: number | null,
  reason = LIST_EXCLUSION_REASON
): Promise<{ added: number[]; removed: number[] }> {
  const wanted = new Set(ruleIds.filter(isValidWafRuleId));
  const scope = proxyHostId === null ? isNull(wafRuleExclusions.proxyHostId) : eq(wafRuleExclusions.proxyHostId, proxyHostId);
  const existing = (await tx.select().from(wafRuleExclusions).where(scope)).filter(isWholeScopeExclusion);
  const have = new Set(existing.map((row) => row.ruleId));
  const removedRows = existing.filter((row) => !wanted.has(row.ruleId));
  if (removedRows.length > 0) {
    await tx.delete(wafRuleExclusions).where(inArray(wafRuleExclusions.id, removedRows.map((row) => row.id)));
  }
  const added = [...wanted].filter((id) => !have.has(id)).sort((a, b) => a - b);
  const now = nowIso();
  for (const ruleId of added) {
    await tx.insert(wafRuleExclusions)
      .values({ ruleId, proxyHostId, pathMatch: null, path: null, variable: null, reason, createdBy: actorUserId, createdAt: now, updatedAt: now });
  }
  await syncWafExclusionMirror(tx, proxyHostId);
  return { added, removed: [...new Set(removedRows.map((row) => row.ruleId))].sort((a, b) => a - b) };
}

function legacyIds(value: unknown): number[] {
  return Array.isArray(value) ? [...new Set(value.filter(isValidWafRuleId))] : [];
}

/**
 * Copies every id of the legacy lists (the "waf" setting and each host's
 * meta.waf) that has no whole-scope record yet into the table. Idempotent:
 * a second run finds a record for every id and adds nothing. Records are
 * never removed here; an id dropped from a list by an older writer stays
 * until somebody removes the exclusion. Returns the number of records added.
 */
export async function importLegacyWafExclusions(tx: DbTransaction): Promise<number> {
  let added = 0;
  const now = nowIso();
  const insertMissing = async (proxyHostId: number | null, ids: number[]) => {
    if (ids.length === 0) return;
    const have = new Set(await wholeScopeRuleIds(tx, proxyHostId));
    for (const ruleId of ids) {
      if (have.has(ruleId)) continue;
      await tx.insert(wafRuleExclusions)
        .values({ ruleId, proxyHostId, pathMatch: null, path: null, variable: null, reason: LEGACY_EXCLUSION_REASON, createdBy: null, createdAt: now, updatedAt: now });
      added += 1;
    }
  };
  const globalRow = await first(tx.select({ value: settings.value }).from(settings).where(eq(settings.key, GLOBAL_SETTING_KEY)).limit(1));
  await insertMissing(null, legacyIds(parseJsonObject(globalRow?.value)?.excluded_rule_ids));
  for (const host of await tx.select({ id: proxyHosts.id, meta: proxyHosts.meta }).from(proxyHosts)) {
    const waf = parseJsonObject(host.meta)?.waf as Record<string, unknown> | undefined;
    await insertMissing(host.id, legacyIds(waf?.excluded_rule_ids));
  }
  return added;
}

/** importLegacyWafExclusions in its own transaction (start-up). */
export async function importLegacyWafExclusionsNow(): Promise<number> {
  return await appDb.transaction(async (tx) => await importLegacyWafExclusions(tx));
}

/** Deletes a deleted proxy host's exclusions (foreign keys are not enforced). */
export async function deleteWafExclusionsForHost(tx: DbTransaction, proxyHostId: number): Promise<void> {
  await tx.delete(wafRuleExclusions).where(eq(wafRuleExclusions.proxyHostId, proxyHostId));
}

/** The global exclusion records, to put back with restoreGlobalWafExclusionRows. */
export async function readGlobalWafExclusionRows(): Promise<(typeof wafRuleExclusions.$inferSelect)[]> {
  return await appDb.select().from(wafRuleExclusions).where(isNull(wafRuleExclusions.proxyHostId));
}

/**
 * Replaces the global exclusion records with `rows` (as read before a change
 * that failed to apply). The stored list is not rewritten: the caller
 * restores the setting that held it.
 */
export async function restoreGlobalWafExclusionRows(rows: readonly (typeof wafRuleExclusions.$inferSelect)[]): Promise<void> {
  await appDb.transaction(async (tx) => {
    await tx.delete(wafRuleExclusions).where(isNull(wafRuleExclusions.proxyHostId));
    if (rows.length > 0) await tx.insert(wafRuleExclusions).values([...rows]);
  });
}

/** A proxy host's exclusion records, to put back with restoreHostWafExclusionRows. */
export async function readHostWafExclusionRows(proxyHostId: number): Promise<(typeof wafRuleExclusions.$inferSelect)[]> {
  return await appDb.select().from(wafRuleExclusions).where(eq(wafRuleExclusions.proxyHostId, proxyHostId));
}

/**
 * Replaces a proxy host's exclusion records with `rows` (as read before a
 * change that Caddy rejected). The list in the host's meta is not rewritten:
 * the caller restores the host row that held it.
 */
export async function restoreHostWafExclusionRows(
  tx: DbTransaction,
  proxyHostId: number,
  rows: readonly (typeof wafRuleExclusions.$inferSelect)[]
): Promise<void> {
  await tx.delete(wafRuleExclusions).where(eq(wafRuleExclusions.proxyHostId, proxyHostId));
  if (rows.length > 0) await tx.insert(wafRuleExclusions).values([...rows]);
}
