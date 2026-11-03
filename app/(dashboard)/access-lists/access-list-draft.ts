/**
 * The access list editor's draft: what the user changed, whether anything
 * changed, and the save payload (saveAccessList in the model). Pure, so it is
 * unit-tested without a browser.
 */
import {
  DEFAULT_DENY_STATUS,
  normalizeRuleValue,
  type AccessListDefaultAction,
  type AccessListRuleAction,
  type AccessListRuleKind,
} from "@/src/lib/access-list-rules";

export type DraftRule = {
  /** Client-side key; stable while the editor is open. */
  key: string;
  /** The stored rule's id, so a save keeps it; null for a new rule. */
  id: number | null;
  action: AccessListRuleAction;
  kind: AccessListRuleKind;
  /** As typed: values separated by commas or spaces. */
  valuesText: string;
  note: string;
  /** ISO 8601, or "" for none. */
  expiresAt: string;
  isNew: boolean;
};

export type DraftMember = {
  key: string;
  id: number | null;
  username: string;
  createdAt: string | null;
  /** New member: the password to add it with. */
  password: string | null;
  removed: boolean;
  /** Existing member: a new password set in this draft. */
  newPassword: string | null;
};

export type AccessListDraft = {
  name: string;
  description: string;
  rules: DraftRule[];
  defaultAction: AccessListDefaultAction;
  denyStatus: string;
  denyBody: string;
  denyRedirectUrl: string;
  failClosed: boolean;
  skipAuthForAllowed: boolean;
  members: DraftMember[];
};

type ListLike = {
  name: string;
  description: string | null;
  rules: ReadonlyArray<{
    id: number;
    action: AccessListRuleAction;
    kind: AccessListRuleKind;
    values: readonly string[];
    note: string | null;
    expiresAt: string | null;
  }>;
  defaultAction: AccessListDefaultAction;
  denyStatus: number;
  denyBody: string | null;
  denyRedirectUrl: string | null;
  failClosed: boolean;
  skipAuthForAllowed: boolean;
  entries: ReadonlyArray<{ id: number; username: string; createdAt: string }>;
};

let counter = 0;
function nextKey(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter}`;
}

export function draftFromList(list: ListLike): AccessListDraft {
  return {
    name: list.name,
    description: list.description ?? "",
    rules: list.rules.map((rule) => ({
      key: `rule-${rule.id}`,
      id: rule.id,
      action: rule.action,
      kind: rule.kind,
      valuesText: rule.values.join(", "),
      note: rule.note ?? "",
      expiresAt: rule.expiresAt ?? "",
      isNew: false,
    })),
    defaultAction: list.defaultAction,
    denyStatus: String(list.denyStatus ?? DEFAULT_DENY_STATUS),
    denyBody: list.denyBody ?? "",
    denyRedirectUrl: list.denyRedirectUrl ?? "",
    failClosed: list.failClosed,
    skipAuthForAllowed: list.skipAuthForAllowed,
    members: list.entries.map((entry) => ({
      key: `member-${entry.id}`,
      id: entry.id,
      username: entry.username,
      createdAt: entry.createdAt,
      password: null,
      removed: false,
      newPassword: null,
    })),
  };
}

export function newDraftRule(action: AccessListRuleAction, kind: AccessListRuleKind): DraftRule {
  return { key: nextKey("new-rule"), id: null, action, kind, valuesText: "", note: "", expiresAt: "", isNew: true };
}

export function newDraftMember(username: string, password: string): DraftMember {
  return { key: nextKey("new-member"), id: null, username, createdAt: null, password, removed: false, newPassword: null };
}

/** The values typed into a rule, split and normalized, with what is wrong with each bad one. */
export function parseDraftValues(kind: AccessListRuleKind, text: string): { values: string[]; errors: string[] } {
  const values: string[] = [];
  const errors: string[] = [];
  for (const raw of text.split(/[\s,]+/).filter(Boolean)) {
    const result = normalizeRuleValue(kind, raw);
    if ("error" in result) errors.push(result.error);
    else if (!values.includes(result.value)) values.push(result.value);
  }
  return { values, errors };
}

/** What is wrong with a draft rule, or null. */
export function draftRuleError(rule: DraftRule): string | null {
  const { values, errors } = parseDraftValues(rule.kind, rule.valuesText);
  if (errors.length > 0) return errors[0];
  if (values.length === 0) return "Add at least one value";
  return null;
}

/** The comparable content of a draft (keys and display-only fields left out). */
function comparable(draft: AccessListDraft) {
  return {
    name: draft.name.trim(),
    description: draft.description.trim(),
    rules: draft.rules.map((rule) => ({
      id: rule.id,
      action: rule.action,
      kind: rule.kind,
      values: parseDraftValues(rule.kind, rule.valuesText).values,
      bad: parseDraftValues(rule.kind, rule.valuesText).errors.length,
      note: rule.note.trim(),
      expiresAt: rule.expiresAt,
    })),
    defaultAction: draft.defaultAction,
    denyStatus: draft.denyStatus.trim(),
    denyBody: draft.denyBody,
    denyRedirectUrl: draft.denyRedirectUrl.trim(),
    failClosed: draft.failClosed,
    skipAuthForAllowed: draft.skipAuthForAllowed,
    members: draft.members.map((member) => ({
      id: member.id,
      username: member.username,
      removed: member.removed,
      added: member.id === null,
      newPassword: member.newPassword !== null,
    })),
  };
}

export function isDraftDirty(draft: AccessListDraft, saved: AccessListDraft): boolean {
  return JSON.stringify(comparable(draft)) !== JSON.stringify(comparable(saved));
}

/** The body of saveAccessListAction for `draft`. */
export function draftToSave(draft: AccessListDraft, options: { system: boolean; expectedUpdatedAt?: string | null }) {
  const denyStatus = Number(draft.denyStatus.trim());
  return {
    ...(options.system ? {} : { name: draft.name, description: draft.description.trim() || null, defaultAction: draft.defaultAction }),
    ...(options.system ? { description: draft.description.trim() || null } : {}),
    ...(options.expectedUpdatedAt ? { expectedUpdatedAt: options.expectedUpdatedAt } : {}),
    rules: draft.rules.map((rule) => ({
      ...(rule.id !== null ? { id: rule.id } : {}),
      action: rule.action,
      kind: rule.kind,
      values: parseDraftValues(rule.kind, rule.valuesText).values,
      note: rule.note.trim() || null,
      expiresAt: rule.expiresAt || null,
    })),
    denyStatus: Number.isInteger(denyStatus) ? denyStatus : (draft.denyStatus as unknown as number),
    denyBody: draft.denyBody.length > 0 ? draft.denyBody : null,
    denyRedirectUrl: draft.denyRedirectUrl.trim() || null,
    failClosed: draft.failClosed,
    skipAuthForAllowed: draft.skipAuthForAllowed,
    members: {
      add: draft.members
        .filter((member) => member.id === null && !member.removed && member.password)
        .map((member) => ({ username: member.username, password: member.password as string })),
      remove: draft.members.filter((member) => member.id !== null && member.removed).map((member) => member.id as number),
      passwords: draft.members
        .filter((member) => member.id !== null && !member.removed && member.newPassword)
        .map((member) => ({ id: member.id as number, password: member.newPassword as string })),
    },
  };
}

/** Moves the rule at `index` by `delta` (-1 up, +1 down); the same array when it cannot move. */
export function moveRule(rules: DraftRule[], index: number, delta: -1 | 1): DraftRule[] {
  const target = index + delta;
  if (index < 0 || index >= rules.length || target < 0 || target >= rules.length) return rules;
  const next = rules.slice();
  [next[index], next[target]] = [next[target], next[index]];
  return next;
}

/** A strong random password for a basic-auth member (no look-alike characters). */
export function generatePassword(length = 20): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#%&*";
  const buffer = new Uint32Array(length);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, (value) => chars[value % chars.length]).join("");
}
