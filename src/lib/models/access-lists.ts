import bcrypt from "bcryptjs";
import { appDb, nowIso, toIso } from "../db";
import { applyCaddyConfig } from "../caddy";
import { logAuditEvent } from "../audit";
import { accessListEntries, accessListRules, accessLists, proxyHosts } from "../db/schema";
import { and, eq, inArray, count, isNull, isNotNull, lte } from "drizzle-orm";
import { ApiConflictError, ApiValidationError } from "../api-errors";
import {
  BLOCKED_SOURCES_KEY,
  BLOCKED_SOURCES_NAME,
  DEFAULT_DENY_STATUS,
  MAX_RULES_PER_LIST,
  hasListSettings,
  isRuleExpired,
  isRuleKind,
  normalizeListDescription,
  normalizeListName,
  normalizeListSettings,
  normalizeMemberInput,
  normalizeMemberPassword,
  normalizeRuleInput,
  normalizeRuleList,
  type AccessListDefaultAction,
  type AccessListRuleAction,
  type AccessListRuleData,
  type AccessListRuleKind,
  type AccessListSettings,
} from "../access-list-rules";
import { asc, first } from "@/src/lib/db/ops";
import type { AppTx } from "@/src/lib/db/types";

export type AccessListEntry = {
  id: number;
  username: string;
  createdAt: string;
  updatedAt: string;
};

export type AccessListRule = {
  id: number;
  /** 0-based; rules are checked in this order. */
  position: number;
  action: AccessListRuleAction;
  kind: AccessListRuleKind;
  values: string[];
  note: string | null;
  expiresAt: string | null;
  /** True once expiresAt has passed: the rule no longer applies and is about to be deleted. */
  expired: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AccessList = {
  id: number;
  name: string;
  description: string | null;
  /** Basic-auth members. */
  entries: AccessListEntry[];
  /** Rules in the order they are checked. */
  rules: AccessListRule[];
  defaultAction: AccessListDefaultAction;
  denyStatus: number;
  denyBody: string | null;
  denyRedirectUrl: string | null;
  failClosed: boolean;
  skipAuthForAllowed: boolean;
  /** "blocked_sources" for the global Blocked sources list; null for lists users create. */
  system: typeof BLOCKED_SOURCES_KEY | null;
  createdAt: string;
  updatedAt: string;
};

export type AccessListInput = {
  name: string;
  description?: string | null;
  users?: { username: string; password: string }[];
  /** Ordered rules (see access-list-rules.ts). */
  rules?: unknown[];
  defaultAction?: AccessListDefaultAction;
  denyStatus?: number;
  denyBody?: string | null;
  denyRedirectUrl?: string | null;
  failClosed?: boolean;
  skipAuthForAllowed?: boolean;
};

export type AccessListUpdate = {
  name?: string;
  description?: string | null;
  /** When present, replaces every rule (rules sent back with their id keep it). */
  rules?: unknown[];
  defaultAction?: AccessListDefaultAction;
  denyStatus?: number;
  denyBody?: string | null;
  denyRedirectUrl?: string | null;
  failClosed?: boolean;
  skipAuthForAllowed?: boolean;
};

export type AccessListSave = AccessListUpdate & {
  /** The list's updatedAt the editor started from; a list changed since answers 409. */
  expectedUpdatedAt?: string;
  members?: {
    add?: { username: string; password: string }[];
    remove?: number[];
    /** New passwords for existing members. */
    passwords?: { id: number; password: string }[];
  };
};

const NOT_FOUND = "Access list not found";
const BLOCKED_SOURCES_DESCRIPTION = "Addresses and networks denied on every host, before anything else";
const RULE_NOT_FOUND = "Access list rule not found";

type AccessListRow = typeof accessLists.$inferSelect;
type AccessListEntryRow = typeof accessListEntries.$inferSelect;
type AccessListRuleRow = typeof accessListRules.$inferSelect;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseStringArray(json: string): string[] {
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function isoOrNull(value: string | null | undefined): string | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

function buildEntry(row: AccessListEntryRow): AccessListEntry {
  return {
    id: row.id,
    username: row.username,
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!
  };
}

export function toAccessListRule(row: AccessListRuleRow, now: Date = new Date()): AccessListRule {
  const expiresAt = isoOrNull(row.expiresAt);
  return {
    id: row.id,
    position: row.position,
    action: row.action === "allow" ? "allow" : "deny",
    kind: isRuleKind(row.kind) ? row.kind : "ip",
    values: parseStringArray(row.matchValues),
    note: row.note ?? null,
    expiresAt,
    expired: isRuleExpired({ expiresAt }, now),
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!
  };
}

function sortRules(rows: AccessListRuleRow[]): AccessListRuleRow[] {
  return rows.slice().sort((a, b) => a.position - b.position || a.id - b.id);
}

function isSystemList(list: Pick<AccessListRow, "systemKey">): boolean {
  return list.systemKey === BLOCKED_SOURCES_KEY;
}

function toAccessList(row: AccessListRow, entries: AccessListEntryRow[], rules: AccessListRuleRow[]): AccessList {
  const now = new Date();
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    entries: entries
      .slice()
      .sort((a, b) => a.username.localeCompare(b.username))
      .map(buildEntry),
    rules: sortRules(rules).map((rule) => toAccessListRule(rule, now)),
    defaultAction: row.defaultAction === "deny" ? "deny" : "allow",
    denyStatus: row.denyStatus ?? DEFAULT_DENY_STATUS,
    denyBody: row.denyBody ?? null,
    denyRedirectUrl: row.denyRedirectUrl ?? null,
    failClosed: Boolean(row.failClosed),
    skipAuthForAllowed: Boolean(row.skipAuthForAllowed),
    system: isSystemList(row) ? BLOCKED_SOURCES_KEY : null,
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!
  };
}

function groupByList<T extends { accessListId: number }>(rows: T[]): Map<number, T[]> {
  const map = new Map<number, T[]>();
  for (const row of rows) {
    const bucket = map.get(row.accessListId) ?? [];
    bucket.push(row);
    map.set(row.accessListId, bucket);
  }
  return map;
}

async function hydrate(lists: AccessListRow[]): Promise<AccessList[]> {
  if (lists.length === 0) return [];
  const listIds = lists.map((list) => list.id);
  const [entries, rules] = await Promise.all([
    appDb.select().from(accessListEntries).where(inArray(accessListEntries.accessListId, listIds)).orderBy(asc(accessListEntries.id)),
    appDb.select().from(accessListRules).where(inArray(accessListRules.accessListId, listIds)).orderBy(asc(accessListRules.id)),
  ]);
  const entriesByList = groupByList(entries);
  const rulesByList = groupByList(rules);
  return lists.map((list) => toAccessList(list, entriesByList.get(list.id) ?? [], rulesByList.get(list.id) ?? []));
}

/** Lists users created: never the global Blocked sources list. */
const USER_LISTS = isNull(accessLists.systemKey);

export async function listAccessLists(): Promise<AccessList[]> {
  const lists = await appDb.query.accessLists.findMany({
    where: USER_LISTS,
    orderBy: (table) => [asc(table.name), asc(table.id)]
  });
  return hydrate(lists);
}

export async function countAccessLists(): Promise<number> {
  const [row] = await appDb
    .select({ value: count() })
    .from(accessLists)
    .where(USER_LISTS);
  return row?.value ?? 0;
}

export async function listAccessListsPaginated(limit: number, offset: number): Promise<AccessList[]> {
  const lists = await appDb.query.accessLists.findMany({
    where: USER_LISTS,
    // The id last, so that every page is the same on every database.
    orderBy: (table) => [asc(table.name), asc(table.id)],
    limit,
    offset,
  });
  return hydrate(lists);
}

export async function getAccessList(id: number): Promise<AccessList | null> {
  const list = await findListRow(id);
  if (!list) return null;
  const [hydrated] = await hydrate([list]);
  return hydrated;
}

async function findListRow(id: number): Promise<AccessListRow | undefined> {
  if (!Number.isSafeInteger(id) || id <= 0) return undefined;
  return appDb.query.accessLists.findFirst({ where: (table, operators) => operators.eq(table.id, id) });
}

/** The list row; "not found" (404) when missing. */
async function requireListRow(id: number): Promise<AccessListRow> {
  const list = await findListRow(id);
  if (!list) throw new Error(NOT_FOUND);
  return list;
}

/** A blocked source must name something narrower than every address. */
export function assertBlockedSourceRules(rules: readonly AccessListRuleData[]): void {
  for (const rule of rules) {
    if (rule.action !== "deny") throw new ApiValidationError("The Blocked sources list only holds deny rules");
    if (rule.kind === "ip" && rule.values.some((value) => value.endsWith("/0"))) {
      throw new ApiValidationError("A blocked source cannot cover every address");
    }
  }
}

/**
 * What the global Blocked sources list cannot take: it only denies, lets
 * through everything it does not name, keeps its name and has no members.
 */
function assertSystemListInput(
  list: AccessListRow,
  input: { name?: string; settings: Partial<AccessListSettings>; rules: AccessListRuleData[] | null }
): void {
  if (!isSystemList(list)) return;
  if (input.name !== undefined && input.name !== list.name) {
    throw new ApiValidationError("The Blocked sources list cannot be renamed");
  }
  if (input.settings.defaultAction === "deny") {
    throw new ApiValidationError("The Blocked sources list lets through every request it does not name");
  }
  if (input.rules) assertBlockedSourceRules(input.rules);
}

function ruleRowValues(
  listId: number,
  position: number,
  rule: AccessListRuleData,
  actorUserId: number | null,
  now: string
): typeof accessListRules.$inferInsert {
  return {
    accessListId: listId,
    position,
    action: rule.action,
    kind: rule.kind,
    matchValues: JSON.stringify(rule.values),
    note: rule.note,
    expiresAt: rule.expiresAt,
    createdBy: actorUserId,
    createdAt: now,
    updatedAt: now,
  };
}

function sameRule(row: AccessListRuleRow, rule: AccessListRuleData): boolean {
  return (
    row.action === rule.action &&
    row.kind === rule.kind &&
    row.matchValues === JSON.stringify(rule.values) &&
    (row.note ?? null) === rule.note &&
    isoOrNull(row.expiresAt) === rule.expiresAt
  );
}

type RuleChanges = { added: number; changed: number; removed: number; moved: boolean };

/**
 * Replaces a list's rules with `rules`, in order, inside `tx`. An input rule
 * carrying the id of one of the list's rules updates it in place (keeping
 * its id and creator); the others are added; rules not sent are deleted.
 */
async function replaceRulesInTx(
  tx: AppTx,
  listId: number,
  rules: AccessListRuleData[],
  ids: Array<number | null>,
  actorUserId: number,
  now: string
): Promise<RuleChanges> {
  if (rules.length > MAX_RULES_PER_LIST) {
    throw new ApiValidationError(`An access list can hold at most ${MAX_RULES_PER_LIST} rules`);
  }
  const existing = await tx.select().from(accessListRules).where(eq(accessListRules.accessListId, listId));
  const byId = new Map(existing.map((row) => [row.id, row]));
  const kept = new Set<number>();
  const changes: RuleChanges = { added: 0, changed: 0, removed: 0, moved: false };
  for (const [position, rule] of rules.entries()) {
    const id = ids[position];
    const row = id !== null && id !== undefined ? byId.get(id) : undefined;
    if (row && !kept.has(row.id)) {
      kept.add(row.id);
      const same = sameRule(row, rule);
      if (row.position !== position) changes.moved = true;
      if (!same) changes.changed += 1;
      if (row.position !== position || !same) {
        await tx.update(accessListRules)
          .set({
            position,
            action: rule.action,
            kind: rule.kind,
            matchValues: JSON.stringify(rule.values),
            note: rule.note,
            expiresAt: rule.expiresAt,
            updatedAt: same ? row.updatedAt : now,
          })
          .where(eq(accessListRules.id, row.id));
      }
    } else {
      await tx.insert(accessListRules).values(ruleRowValues(listId, position, rule, actorUserId, now));
      changes.added += 1;
    }
  }
  const removed = existing.filter((row) => !kept.has(row.id)).map((row) => row.id);
  if (removed.length > 0) {
    await tx.delete(accessListRules).where(inArray(accessListRules.id, removed));
    changes.removed = removed.length;
  }
  return changes;
}

/** Positions 0..n-1 again after a rule was deleted, inside `tx`. */
async function renumberRulesInTx(tx: AppTx, listId: number): Promise<void> {
  const rows = sortRules(await tx.select().from(accessListRules).where(eq(accessListRules.accessListId, listId)));
  for (const [index, rule] of rows.entries()) {
    if (rule.position !== index) await tx.update(accessListRules).set({ position: index }).where(eq(accessListRules.id, rule.id));
  }
}

function ruleIdsOf(input: unknown[]): Array<number | null> {
  return input.map((rule) => (isRecord(rule) && typeof rule.id === "number" ? rule.id : null));
}

async function existingExpiries(listId: number): Promise<Map<number, string | null>> {
  const rows = await appDb
    .select({ id: accessListRules.id, expiresAt: accessListRules.expiresAt })
    .from(accessListRules)
    .where(eq(accessListRules.accessListId, listId));
  return new Map(rows.map((row) => [row.id, isoOrNull(row.expiresAt)]));
}

function describeRuleChanges(changes: RuleChanges): string | null {
  const parts: string[] = [];
  if (changes.added) parts.push(`${changes.added} added`);
  if (changes.changed) parts.push(`${changes.changed} changed`);
  if (changes.removed) parts.push(`${changes.removed} removed`);
  if (changes.moved && parts.length === 0) parts.push("reordered");
  return parts.length > 0 ? `rules ${parts.join(", ")}` : null;
}

function ruleText(rule: Pick<AccessListRuleData, "action" | "kind" | "values">): string {
  const kind = rule.kind === "ip" ? "address" : rule.kind === "asn" ? "AS number" : rule.kind;
  const values = rule.values.slice(0, 5).join(", ") + (rule.values.length > 5 ? ", ..." : "");
  return `${rule.action} ${kind} ${values}`;
}

export async function createAccessList(input: AccessListInput, actorUserId: number) {
  if (!isRecord(input)) throw new ApiValidationError("Access list must be an object");
  const name = normalizeListName(input.name);
  const description = normalizeListDescription(input.description);
  const settings = normalizeListSettings(input as Record<string, unknown>);
  const rules = input.rules === undefined ? [] : normalizeRuleList(input.rules);
  if (input.users !== undefined && !Array.isArray(input.users)) throw new ApiValidationError("users must be an array");
  const members = (input.users ?? []).map((user, index) => normalizeMemberInput(user, `users[${index}]`));
  if (new Set(members.map((member) => member.username)).size !== members.length) {
    throw new ApiValidationError("users must not repeat a username");
  }

  const now = nowIso();
  // Async hashing keeps a bulk create from blocking the event loop (and with
  // it forward-auth checks) for the whole batch.
  const hashes = await Promise.all(members.map((account) => bcrypt.hash(account.password, 10)));

  const listId = await appDb.transaction(async (tx) => {
    const accessList = (await first(tx
      .insert(accessLists)
      .values({
        name,
        description,
        createdBy: actorUserId,
        defaultAction: settings.defaultAction ?? "allow",
        denyStatus: settings.denyStatus ?? DEFAULT_DENY_STATUS,
        denyBody: settings.denyBody ?? null,
        denyRedirectUrl: settings.denyRedirectUrl ?? null,
        failClosed: settings.failClosed ?? false,
        skipAuthForAllowed: settings.skipAuthForAllowed ?? false,
        createdAt: now,
        updatedAt: now
      })
      .returning()))!;
    if (!accessList) {
      throw new Error("Failed to create access list");
    }
    if (members.length > 0) {
      await tx.insert(accessListEntries)
        .values(
          members.map((account, index) => ({
            accessListId: accessList.id,
            username: account.username,
            passwordHash: hashes[index],
            createdAt: now,
            updatedAt: now
          }))
        );
    }
    for (const [position, rule] of rules.entries()) {
      await tx.insert(accessListRules).values(ruleRowValues(accessList.id, position, rule, actorUserId, now));
    }
    return accessList.id;
  });

  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "access_list",
    entityId: listId,
    summary: `Created access list ${name}`,
    data:
      rules.length > 0 || hasListSettings(input as Record<string, unknown>)
        ? { rules: rules.length, ...settings }
        : undefined,
  });

  await applyCaddyConfig();
  return (await getAccessList(listId))!;
}

type PreparedChange = {
  existing: AccessListRow;
  name: string;
  description: string | null;
  settings: Partial<AccessListSettings>;
  rules: AccessListRuleData[] | null;
};

async function prepareListChange(id: number, input: AccessListUpdate): Promise<PreparedChange> {
  if (!isRecord(input)) throw new ApiValidationError("Access list must be an object");
  const existing = await requireListRow(id);
  const name = input.name !== undefined ? normalizeListName(input.name) : existing.name;
  const description = input.description !== undefined ? normalizeListDescription(input.description) : existing.description;
  const settings = normalizeListSettings(input as Record<string, unknown>);
  const rules =
    input.rules !== undefined
      ? normalizeRuleList(input.rules, { existingExpiries: await existingExpiries(id) })
      : null;
  assertSystemListInput(existing, { name: input.name === undefined ? undefined : name, settings, rules });
  return { existing, name, description, settings, rules };
}

/** Updates a list's name, description, settings and, when `rules` is present, all of its rules. */
export async function updateAccessList(id: number, input: AccessListUpdate, actorUserId: number) {
  const { name, description, settings, rules } = await prepareListChange(id, input);

  const now = nowIso();
  const changes = await appDb.transaction(async (tx) => {
    await tx.update(accessLists)
      .set({ name, description, ...settings, updatedAt: now })
      .where(eq(accessLists.id, id));
    return rules ? await replaceRulesInTx(tx, id, rules, ruleIdsOf(input.rules as unknown[]), actorUserId, now) : null;
  });

  const ruleSummary = changes ? describeRuleChanges(changes) : null;
  await logAuditEvent({
    userId: actorUserId,
    action: "update",
    entityType: "access_list",
    entityId: id,
    summary: `Updated access list ${name}${ruleSummary ? ` (${ruleSummary})` : ""}`,
    data: hasListSettings(input as Record<string, unknown>) || changes ? { ...settings, ...(changes ? { rules: changes } : {}) } : undefined,
  });

  await applyCaddyConfig();
  return (await getAccessList(id))!;
}

/**
 * The editor's save: name, description, settings, every rule in order and
 * the member changes, in one transaction and one Caddy apply.
 */
export async function saveAccessList(id: number, input: AccessListSave, actorUserId: number) {
  const { existing, name, description, settings, rules } = await prepareListChange(id, input);
  if (input.expectedUpdatedAt !== undefined && isoOrNull(existing.updatedAt) !== isoOrNull(input.expectedUpdatedAt)) {
    throw new ApiConflictError("Someone else changed this access list since you opened it; reload it and try again");
  }

  const members = input.members ?? {};
  if (!isRecord(members)) throw new ApiValidationError("members must be an object");
  for (const key of ["add", "remove", "passwords"] as const) {
    if (members[key] !== undefined && !Array.isArray(members[key])) throw new ApiValidationError(`members.${key} must be an array`);
  }
  const add = (members.add ?? []).map((member, index) => normalizeMemberInput(member, `members.add[${index}]`));
  const remove = (members.remove ?? []).filter((value): value is number => Number.isSafeInteger(value));
  const passwords = (members.passwords ?? []).map((entry, index) => {
    if (!isRecord(entry) || typeof entry.id !== "number" || !Number.isSafeInteger(entry.id)) {
      throw new ApiValidationError(`members.passwords[${index}].id is required`);
    }
    return { id: entry.id, password: normalizeMemberPassword(entry.password, `members.passwords[${index}]`) };
  });
  if (isSystemList(existing) && add.length > 0) throw new ApiValidationError("The Blocked sources list has no members");

  const currentEntries = await appDb.select().from(accessListEntries).where(eq(accessListEntries.accessListId, id));
  const currentIds = new Set(currentEntries.map((entry) => entry.id));
  const remaining = new Set(currentEntries.filter((entry) => !remove.includes(entry.id)).map((entry) => entry.username));
  for (const member of add) {
    if (remaining.has(member.username)) throw new ApiConflictError(`The list already has a member named ${member.username}`);
    remaining.add(member.username);
  }
  for (const entry of passwords) {
    if (!currentIds.has(entry.id) || remove.includes(entry.id)) {
      throw new ApiValidationError("A new password is for a member the list does not have");
    }
  }

  const [addHashes, passwordHashes] = await Promise.all([
    Promise.all(add.map((member) => bcrypt.hash(member.password, 10))),
    Promise.all(passwords.map((entry) => bcrypt.hash(entry.password, 10))),
  ]);
  const now = nowIso();
  const changes = await appDb.transaction(async (tx) => {
    await tx.update(accessLists)
      .set({ name, description, ...settings, updatedAt: now })
      .where(eq(accessLists.id, id));
    if (remove.length > 0) {
      await tx.delete(accessListEntries)
        .where(and(eq(accessListEntries.accessListId, id), inArray(accessListEntries.id, remove)));
    }
    for (const [index, member] of add.entries()) {
      await tx.insert(accessListEntries)
        .values({ accessListId: id, username: member.username, passwordHash: addHashes[index], createdAt: now, updatedAt: now });
    }
    for (const [index, entry] of passwords.entries()) {
      await tx.update(accessListEntries)
        .set({ passwordHash: passwordHashes[index], updatedAt: now })
        .where(and(eq(accessListEntries.id, entry.id), eq(accessListEntries.accessListId, id)));
    }
    return rules ? await replaceRulesInTx(tx, id, rules, ruleIdsOf(input.rules as unknown[]), actorUserId, now) : null;
  });

  const ruleSummary = changes ? describeRuleChanges(changes) : null;
  await logAuditEvent({
    userId: actorUserId,
    action: "update",
    entityType: "access_list",
    entityId: id,
    summary: `Updated access list ${name}${ruleSummary ? ` (${ruleSummary})` : ""}`,
    data: { ...settings, ...(changes ? { rules: changes } : {}) },
  });
  for (const member of add) {
    await logAuditEvent({
      userId: actorUserId,
      action: "create",
      entityType: "access_list_entry",
      entityId: id,
      summary: `Added user ${member.username} to access list ${name}`,
    });
  }
  for (const entry of currentEntries) {
    if (remove.includes(entry.id)) {
      await logAuditEvent({
        userId: actorUserId,
        action: "delete",
        entityType: "access_list_entry",
        entityId: entry.id,
        summary: `Removed user ${entry.username} from access list ${name}`,
      });
    } else if (passwords.some((item) => item.id === entry.id)) {
      await logAuditEvent({
        userId: actorUserId,
        action: "update",
        entityType: "access_list_entry",
        entityId: entry.id,
        summary: `Set a new password for user ${entry.username} of access list ${name}`,
      });
    }
  }

  await applyCaddyConfig();
  return (await getAccessList(id))!;
}

export async function addAccessListEntry(
  accessListId: number,
  entry: { username: string; password: string },
  actorUserId: number
) {
  const list = await requireListRow(accessListId);
  if (isSystemList(list)) throw new ApiValidationError("The Blocked sources list has no members");
  const member = normalizeMemberInput(entry, "entry");

  const now = nowIso();
  const hash = await bcrypt.hash(member.password, 10);
  // The list is read again in the transaction that inserts the member: it
  // may have been deleted while the password was hashed.
  await appDb.transaction(async (tx) => {
    if (!(await findListRow(accessListId))) throw new Error(NOT_FOUND);
    await tx.insert(accessListEntries).values({
      accessListId,
      username: member.username,
      passwordHash: hash,
      createdAt: now,
      updatedAt: now
    });
  });

  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "access_list_entry",
    entityId: accessListId,
    summary: `Added user ${member.username} to access list ${list.name}`,
  });
  await applyCaddyConfig();
  return (await getAccessList(accessListId))!;
}

export async function removeAccessListEntry(accessListId: number, entryId: number, actorUserId: number) {
  const list = await requireListRow(accessListId);

  // Only an entry of this list: the list is what the caller was checked against.
  await appDb
    .delete(accessListEntries)
    .where(and(eq(accessListEntries.id, entryId), eq(accessListEntries.accessListId, accessListId)));

  await logAuditEvent({
    userId: actorUserId,
    action: "delete",
    entityType: "access_list_entry",
    entityId: entryId,
    summary: `Removed entry from access list ${list.name}`,
  });
  await applyCaddyConfig();
  return (await getAccessList(accessListId))!;
}

/**
 * Deletes a list with its members and rules (foreign keys are not enforced)
 * and detaches it from the hosts that used it. The global Blocked sources
 * list cannot be deleted; its entries can.
 */
export async function deleteAccessList(id: number, actorUserId: number) {
  const existing = await requireListRow(id);
  if (isSystemList(existing)) {
    throw new ApiValidationError("The Blocked sources list cannot be deleted; remove its entries instead");
  }

  const now = nowIso();
  await appDb.transaction(async (tx) => {
    await tx.delete(accessListRules).where(eq(accessListRules.accessListId, id));
    await tx.delete(accessListEntries).where(eq(accessListEntries.accessListId, id));
    await tx.update(proxyHosts).set({ accessListId: null, updatedAt: now }).where(eq(proxyHosts.accessListId, id));
    await tx.delete(accessLists).where(eq(accessLists.id, id));
  });

  await logAuditEvent({
    userId: actorUserId,
    action: "delete",
    entityType: "access_list",
    entityId: id,
    summary: `Deleted access list ${existing.name}`,
  });
  await applyCaddyConfig();
}

// ── Rules ──────────────────────────────────────────────────────────────

/** A list's rules in order. The caller checks that it may see the list. */
export async function listAccessListRules(accessListId: number): Promise<AccessListRule[]> {
  const rows = await appDb.select().from(accessListRules).where(eq(accessListRules.accessListId, accessListId));
  const now = new Date();
  return sortRules(rows).map((row) => toAccessListRule(row, now));
}

async function auditRule(
  actorUserId: number | null,
  list: AccessListRow,
  action: string,
  ruleId: number,
  summary: string,
  data?: unknown
) {
  await logAuditEvent({
    userId: actorUserId,
    action,
    entityType: isSystemList(list) ? "blocked_source" : "access_list_rule",
    entityId: ruleId,
    summary,
    data,
  });
}

async function readRule(ruleId: number): Promise<AccessListRule> {
  const row = await appDb.query.accessListRules.findFirst({ where: (table, operators) => operators.eq(table.id, ruleId) });
  if (!row) throw new Error(RULE_NOT_FOUND);
  return toAccessListRule(row);
}

/** Inserts a validated rule at `position` (default: last), inside one transaction. */
async function insertRule(listId: number, rule: AccessListRuleData, actorUserId: number, position: number | undefined): Promise<number> {
  const now = nowIso();
  return await appDb.transaction(async (tx) => {
    const rows = sortRules(await tx.select().from(accessListRules).where(eq(accessListRules.accessListId, listId)));
    if (rows.length >= MAX_RULES_PER_LIST) {
      throw new ApiValidationError(`An access list can hold at most ${MAX_RULES_PER_LIST} rules`);
    }
    const at = Math.min(position ?? rows.length, rows.length);
    for (const [index, row] of rows.entries()) {
      const next = index >= at ? index + 1 : index;
      if (row.position !== next) await tx.update(accessListRules).set({ position: next }).where(eq(accessListRules.id, row.id));
    }
    const inserted = (await first(tx.insert(accessListRules).values(ruleRowValues(listId, at, rule, actorUserId, now)).returning()))!;
    await tx.update(accessLists).set({ updatedAt: now }).where(eq(accessLists.id, listId));
    return inserted.id;
  });
}

/** Adds a rule at `position` (0-based; default: last). */
export async function addAccessListRule(
  accessListId: number,
  input: unknown,
  actorUserId: number,
  options: { position?: unknown } = {}
): Promise<AccessListRule> {
  const list = await requireListRow(accessListId);
  const rule = normalizeRuleInput(input);
  assertSystemListInput(list, { settings: {}, rules: [rule] });
  const position = options.position;
  if (position !== undefined && (typeof position !== "number" || !Number.isSafeInteger(position) || position < 0)) {
    throw new ApiValidationError("position must be a whole number from 0");
  }

  const ruleId = await insertRule(accessListId, rule, actorUserId, position as number | undefined);
  await auditRule(actorUserId, list, "create", ruleId, `Added rule "${ruleText(rule)}" to access list ${list.name}`, {
    accessListId,
    rule,
  });
  await applyCaddyConfig();
  return readRule(ruleId);
}

async function ruleOfList(accessListId: number, ruleId: number) {
  const list = await requireListRow(accessListId);
  const row =
    Number.isSafeInteger(ruleId) && ruleId > 0
      ? await appDb.query.accessListRules.findFirst({
          where: (table, operators) =>
            operators.and(operators.eq(table.id, ruleId), operators.eq(table.accessListId, accessListId)),
        })
      : undefined;
  if (!row) throw new Error(RULE_NOT_FOUND);
  return { list, row };
}

/** Replaces one rule's action, kind, values, note and expiry; its position stays. */
export async function updateAccessListRule(
  accessListId: number,
  ruleId: number,
  input: unknown,
  actorUserId: number
): Promise<AccessListRule> {
  const { list, row } = await ruleOfList(accessListId, ruleId);
  const rule = normalizeRuleInput(input, { existingExpiry: isoOrNull(row.expiresAt) });
  assertSystemListInput(list, { settings: {}, rules: [rule] });

  const now = nowIso();
  await appDb.transaction(async (tx) => {
    await tx.update(accessListRules)
      .set({
        action: rule.action,
        kind: rule.kind,
        matchValues: JSON.stringify(rule.values),
        note: rule.note,
        expiresAt: rule.expiresAt,
        updatedAt: now,
      })
      .where(eq(accessListRules.id, ruleId));
    await tx.update(accessLists).set({ updatedAt: now }).where(eq(accessLists.id, accessListId));
  });

  await auditRule(actorUserId, list, "update", ruleId, `Changed a rule of access list ${list.name} to "${ruleText(rule)}"`, {
    accessListId,
    rule,
  });
  await applyCaddyConfig();
  return readRule(ruleId);
}

export async function removeAccessListRule(accessListId: number, ruleId: number, actorUserId: number): Promise<void> {
  const { list, row } = await ruleOfList(accessListId, ruleId);
  const now = nowIso();
  await appDb.transaction(async (tx) => {
    await tx.delete(accessListRules).where(eq(accessListRules.id, ruleId));
    await renumberRulesInTx(tx, accessListId);
    await tx.update(accessLists).set({ updatedAt: now }).where(eq(accessLists.id, accessListId));
  });

  await auditRule(actorUserId, list, "delete", ruleId, `Removed rule "${ruleText(toAccessListRule(row))}" from access list ${list.name}`, {
    accessListId,
  });
  await applyCaddyConfig();
}

/** Puts the list's rules in the order of `ruleIds`, which must name each of its rules once. */
export async function reorderAccessListRules(
  accessListId: number,
  ruleIds: unknown,
  actorUserId: number
): Promise<AccessListRule[]> {
  const list = await requireListRow(accessListId);
  if (!Array.isArray(ruleIds) || !ruleIds.every((id) => typeof id === "number" && Number.isSafeInteger(id))) {
    throw new ApiValidationError("ruleIds must be an array of rule ids");
  }
  const order = ruleIds as number[];
  const now = nowIso();
  await appDb.transaction(async (tx) => {
    const rows = await tx.select().from(accessListRules).where(eq(accessListRules.accessListId, accessListId));
    const ids = new Set(rows.map((row) => row.id));
    if (order.length !== rows.length || new Set(order).size !== order.length || !order.every((id) => ids.has(id))) {
      throw new ApiValidationError("ruleIds must name every rule of the list exactly once");
    }
    for (const [position, id] of order.entries()) {
      await tx.update(accessListRules).set({ position }).where(eq(accessListRules.id, id));
    }
    await tx.update(accessLists).set({ updatedAt: now }).where(eq(accessLists.id, accessListId));
  });

  await logAuditEvent({
    userId: actorUserId,
    action: "update",
    entityType: "access_list",
    entityId: accessListId,
    summary: `Reordered the rules of access list ${list.name}`,
    data: { ruleIds: order },
  });
  await applyCaddyConfig();
  return listAccessListRules(accessListId);
}

/** Replaces every rule of a list, in order (rules sent with their id keep it). */
export async function replaceAccessListRules(accessListId: number, input: unknown, actorUserId: number) {
  if (!Array.isArray(input)) throw new ApiValidationError("rules must be an array");
  const list = await updateAccessList(accessListId, { rules: input }, actorUserId);
  return list.rules;
}

// ── The global Blocked sources list ───────────────────────────────────

async function blockedSourcesRow(): Promise<AccessListRow | undefined> {
  return appDb.query.accessLists.findFirst({
    where: (table, operators) => operators.eq(table.systemKey, BLOCKED_SOURCES_KEY),
  });
}

export type BlockedSourcesPlaceholder = Omit<AccessList, "id" | "createdAt" | "updatedAt"> & {
  id: null;
  createdAt: null;
  updatedAt: null;
};

/** What the Blocked sources list looks like before its first use (it has no row yet). */
export function blockedSourcesPlaceholder(): BlockedSourcesPlaceholder {
  return {
    id: null,
    name: BLOCKED_SOURCES_NAME,
    description: BLOCKED_SOURCES_DESCRIPTION,
    entries: [],
    rules: [],
    defaultAction: "allow",
    denyStatus: DEFAULT_DENY_STATUS,
    denyBody: null,
    denyRedirectUrl: null,
    failClosed: false,
    skipAuthForAllowed: false,
    system: BLOCKED_SOURCES_KEY,
    createdAt: null,
    updatedAt: null,
  };
}

/** The Blocked sources list, or null before its first use. */
export async function getBlockedSourcesList(): Promise<AccessList | null> {
  const row = await blockedSourcesRow();
  if (!row) return null;
  const [hydrated] = await hydrate([row]);
  return hydrated;
}

/** The Blocked sources list row, created on first use. */
export async function ensureBlockedSourcesList(): Promise<AccessListRow> {
  const existing = await blockedSourcesRow();
  if (existing) return existing;
  const now = nowIso();
  // The unique index on systemKey keeps a concurrent first use from making two.
  await appDb.insert(accessLists)
    .values({
      name: BLOCKED_SOURCES_NAME,
      description: BLOCKED_SOURCES_DESCRIPTION,
      systemKey: BLOCKED_SOURCES_KEY,
      createdBy: null,
      defaultAction: "allow",
      denyStatus: DEFAULT_DENY_STATUS,
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoNothing();
  const row = await blockedSourcesRow();
  if (!row) throw new Error("Failed to create the Blocked sources list");
  return row;
}

export type BlockedSourceInput = {
  /** An IP address or CIDR range (shorthand for kind "ip"). */
  address?: unknown;
  kind?: unknown;
  value?: unknown;
  values?: unknown;
  /** Why it is blocked; stored as the rule's note. */
  reason?: unknown;
  note?: unknown;
  /** ISO 8601. */
  expiresAt?: unknown;
  /** Seconds from now; an alternative to expiresAt. */
  expiresInSeconds?: unknown;
};

/**
 * Adds an address, network, country, continent or AS number to the global
 * Blocked sources list (created on first use). Blocking what is already
 * blocked by one entry of its own updates that entry's reason and expiry
 * when given, and answers created: false.
 */
export async function addBlockedSource(
  input: BlockedSourceInput,
  actorUserId: number
): Promise<{ entry: AccessListRule; created: boolean }> {
  if (!isRecord(input)) throw new ApiValidationError("The blocked source must be an object");
  const allowed = new Set(["address", "kind", "value", "values", "reason", "note", "expiresAt", "expiresInSeconds"]);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) throw new ApiValidationError(`The blocked source has an unknown field "${key}"`);
  }
  if (input.expiresAt !== undefined && input.expiresInSeconds !== undefined) {
    throw new ApiValidationError("Send expiresAt or expiresInSeconds, not both");
  }
  let expiresAt = input.expiresAt;
  if (input.expiresInSeconds !== undefined && input.expiresInSeconds !== null) {
    const seconds = input.expiresInSeconds;
    if (typeof seconds !== "number" || !Number.isSafeInteger(seconds) || seconds < 60) {
      throw new ApiValidationError("expiresInSeconds must be a whole number of seconds, at least 60");
    }
    expiresAt = new Date(Date.now() + seconds * 1000).toISOString();
  }
  if (input.reason !== undefined && input.note !== undefined) throw new ApiValidationError("Send reason or note, not both");
  const hasAddress = input.address !== undefined;
  if (hasAddress && (input.kind !== undefined || input.value !== undefined || input.values !== undefined)) {
    throw new ApiValidationError("Send address, or kind with value");
  }
  if (!hasAddress && input.value !== undefined && input.values !== undefined) {
    throw new ApiValidationError("Send value or values, not both");
  }
  const rule = normalizeRuleInput({
    action: "deny",
    kind: hasAddress ? "ip" : input.kind,
    values: hasAddress ? [input.address] : input.values ?? (input.value === undefined ? undefined : [input.value]),
    note: input.reason ?? input.note,
    expiresAt,
  });
  assertBlockedSourceRules([rule]);

  const list = await ensureBlockedSourcesList();
  const values = JSON.stringify(rule.values);
  // Looking for the same entry and adding or updating it in one transaction,
  // so two requests blocking the same source do not add it twice.
  const outcome = await appDb.transaction(async (tx) => {
    const rows = await tx.select().from(accessListRules).where(eq(accessListRules.accessListId, list.id));
    const same = rows.find((row) => row.kind === rule.kind && row.matchValues === values);
    if (same) {
      const changes: Partial<typeof accessListRules.$inferInsert> = {};
      if (input.reason !== undefined || input.note !== undefined) changes.note = rule.note;
      if (input.expiresAt !== undefined || input.expiresInSeconds !== undefined) changes.expiresAt = rule.expiresAt;
      if (Object.keys(changes).length === 0) return { ruleId: same.id, created: false, changed: false };
      const now = nowIso();
      await tx.update(accessListRules).set({ ...changes, updatedAt: now }).where(eq(accessListRules.id, same.id));
      await tx.update(accessLists).set({ updatedAt: now }).where(eq(accessLists.id, list.id));
      return { ruleId: same.id, created: false, changed: true };
    }
    return { ruleId: await insertRule(list.id, rule, actorUserId, undefined), created: true, changed: true };
  });

  if (outcome.created) {
    await auditRule(actorUserId, list, "create", outcome.ruleId, `Blocked ${rule.values.join(", ")} on every host`, { rule });
  } else if (outcome.changed) {
    await auditRule(actorUserId, list, "update", outcome.ruleId, `Updated blocked source ${rule.values.join(", ")}`, { rule });
  }
  if (outcome.changed) await applyCaddyConfig();
  return { entry: await readRule(outcome.ruleId), created: outcome.created };
}

/** Removes an entry from the Blocked sources list. */
export async function removeBlockedSource(entryId: number, actorUserId: number): Promise<void> {
  const list = await blockedSourcesRow();
  if (!list) throw new Error(RULE_NOT_FOUND);
  await removeAccessListRule(list.id, entryId, actorUserId);
}

// ── Expiry ─────────────────────────────────────────────────────────────

/** Rules whose expiry has passed, oldest first. */
export async function listExpiredAccessListRules(now: Date = new Date()): Promise<AccessListRuleRow[]> {
  const rows = await appDb
    .select()
    .from(accessListRules)
    .where(and(isNotNull(accessListRules.expiresAt), lte(accessListRules.expiresAt, now.toISOString())))
    .orderBy(asc(accessListRules.expiresAt), asc(accessListRules.id));
  // The text comparison above relies on ISO 8601 in UTC; check each one again.
  return rows.filter((row) => isRuleExpired({ expiresAt: isoOrNull(row.expiresAt) }, now));
}

/**
 * Deletes the rules whose expiry has passed and applies the configuration
 * once; returns how many were deleted. Runs from the expiry job on a master
 * or standalone instance (a slave gets the deletion with the next sync).
 */
export async function deleteExpiredAccessListRules(now: Date = new Date()): Promise<number> {
  const stamp = nowIso();
  // Read in the transaction that deletes them, so a rule whose expiry was
  // just extended is not deleted.
  const { expired, listById } = await appDb.transaction(async (tx) => {
    const expired = await listExpiredAccessListRules(now);
    if (expired.length === 0) return { expired, listById: new Map<number, AccessListRow>() };
    const ids = expired.map((rule) => rule.id);
    const listIds = Array.from(new Set(expired.map((rule) => rule.accessListId)));
    const lists = await tx.select().from(accessLists).where(inArray(accessLists.id, listIds));
    await tx.delete(accessListRules).where(inArray(accessListRules.id, ids));
    for (const listId of listIds) {
      await renumberRulesInTx(tx, listId);
      await tx.update(accessLists).set({ updatedAt: stamp }).where(eq(accessLists.id, listId));
    }
    return { expired, listById: new Map(lists.map((list) => [list.id, list])) };
  });
  if (expired.length === 0) return 0;
  for (const row of expired) {
    const list = listById.get(row.accessListId);
    const rule = toAccessListRule(row, now);
    await logAuditEvent({
      userId: null,
      action: "expire",
      entityType: list && isSystemList(list) ? "blocked_source" : "access_list_rule",
      entityId: row.id,
      summary: `Rule "${ruleText(rule)}" of access list ${list?.name ?? `#${row.accessListId}`} expired`,
    });
  }
  await applyCaddyConfig();
  return expired.length;
}

// ── Usage ──────────────────────────────────────────────────────────────

export type AccessListUsage = {
  id: number;
  name: string;
  domains: string[];
  enabled: boolean;
};

export async function getAccessListUsageMap(): Promise<Map<number, AccessListUsage[]>> {
  const rows = await appDb
    .select({
      id: proxyHosts.id,
      name: proxyHosts.name,
      domains: proxyHosts.domains,
      enabled: proxyHosts.enabled,
      accessListId: proxyHosts.accessListId,
    })
    .from(proxyHosts)
    .orderBy(asc(proxyHosts.id));

  const map = new Map<number, AccessListUsage[]>();
  for (const row of rows) {
    if (row.accessListId == null) continue;
    const bucket = map.get(row.accessListId) ?? [];
    bucket.push({
      id: row.id,
      name: row.name,
      domains: parseStringArray(row.domains),
      enabled: row.enabled,
    });
    map.set(row.accessListId, bucket);
  }
  return map;
}

/** Refuses attaching the global Blocked sources list to a host: it applies to every host already. */
export async function assertAttachableAccessList(accessListId: number | null | undefined): Promise<void> {
  if (accessListId === null || accessListId === undefined) return;
  const row = await findListRow(accessListId);
  if (row && isSystemList(row)) {
    throw new ApiValidationError("The Blocked sources list applies to every host and cannot be attached to one");
  }
}
