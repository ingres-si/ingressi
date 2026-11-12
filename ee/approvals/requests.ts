// SPDX-License-Identifier: Elastic-2.0
/**
 * Change requests: a change to a protected host waiting for its approvals.
 *
 * - gateHostChange is called by the REST routes and the dashboard server
 *   actions after their permission and scope checks. When no enabled policy
 *   covers the change it returns null and the caller applies the change as
 *   before; otherwise it stores a change request (the validated input and the
 *   host as it is now) and returns it, or, for an emergency change, applies it
 *   at once.
 * - Approvers (approvals:approve) approve or reject; nobody approves their own
 *   request (user ids are compared). With enough distinct approvals the
 *   request is approved and applied at once when every covering policy's
 *   change window is open, or later by the scheduler (scheduler.ts) or an
 *   approver inside a window.
 * - Applying re-checks that the host has not changed since the request (its
 *   fingerprint), that the requester's account is active and still holds the
 *   write permission and tag scope the change needs, and that the approvals
 *   still meet what the covering policies ask now. It then calls the same
 *   model functions as a direct change, inside runApprovedChange so the model
 *   guard (guard.ts) lets it through.
 * - Emergency changes (approvals:emergency, administrator-level) are applied
 *   at once with a mandatory reason, unless a covering policy forbids them;
 *   they are flagged on the request and in the audit log.
 *
 * Applies run one at a time on this node.
 */
import { createHash } from "node:crypto";
import { and, count, eq, inArray, lt } from "drizzle-orm";
import { appDb, nowIso, toIso } from "@/src/lib/db";
import { changeRequestReviews, changeRequests, users } from "@/src/lib/db/schema";
import { ApiClientError, ApiConflictError, ApiValidationError } from "@/src/lib/api-errors";
import { logUnexpectedApiError } from "@/src/lib/api-auth";
import { logAuditEvent } from "@/src/lib/audit";
import { CaddyApplyError } from "@/src/lib/caddy-apply-error";
import { normalizeTags, parseStoredTags } from "@/src/lib/host-tags";
import { can, scopeTagsFor, tagsInScope, type Access, type Permission } from "@/src/lib/permissions";
import {
  assertDomainsFreeOutsideScope,
  assertForwardAuthAccessAllowed,
  assertL4WriteAllowed,
  assertListenPortFreeOutsideScope,
  assertMtlsRuleReferencesAllowed,
  assertProxyHostWriteAllowed,
  findL4ProxyHostInScope,
  findProxyHostInScope,
  tagsForWrite,
} from "@/src/lib/access-scope";
import {
  createProxyHost,
  deleteProxyHost,
  getProxyHost,
  updateProxyHost,
  type ProxyHostInput,
} from "@/src/lib/models/proxy-hosts";
import {
  createL4ProxyHost,
  deleteL4ProxyHost,
  getL4ProxyHost,
  updateL4ProxyHost,
  type L4ProxyHostInput,
} from "@/src/lib/models/l4-proxy-hosts";
import { getForwardAuthAccessForHost, setForwardAuthAccess } from "@/src/lib/models/forward-auth";
import {
  createMtlsAccessRule,
  deleteMtlsAccessRule,
  getMtlsAccessRule,
  listMtlsAccessRules,
  updateMtlsAccessRule,
  type MtlsAccessRuleInput,
} from "@/src/lib/models/mtls-access-rules";
import { accessForUser } from "@/ee/custom-roles/access";
import { canonicalJson } from "@/ee/config-history/fingerprint";
import { diffPartial, diffWhole } from "./diff";
import { runApprovedChange } from "./guard";
import {
  describePolicies,
  policiesCovering,
  policiesForbiddingEmergency,
  requestTtlHoursFor,
  requiredApprovalsFor,
  updateOperations,
} from "./match";
import { readEnabledPolicyRules } from "./store";
import { computeChangeImpact, type ChangeImpact } from "./impact";
import { readConfigurationReach, type ConfigurationReach } from "@/ee/fleet/reach";
import { allWindowsOpenAt, describeWindows, nextOpening } from "./windows";
import {
  MAX_COMMENT_LENGTH,
  MIN_EMERGENCY_REASON_LENGTH,
  OPEN_STATUSES,
  TARGET_LABELS,
  isOperation,
  isRequestStatus,
  isTargetType,
  type ChangeField,
  type ChangeRequestPage,
  type ChangeRequestView,
  type HostApprovalContext,
  type Operation,
  type PolicyRule,
  type RequestStatus,
  type ReviewView,
  type TargetType,
  type WindowStatus,
} from "./types";
import { desc, first } from "@/src/lib/db/ops";
import { parseRowId } from "@/src/lib/row-ids";
import { withClusterLock } from "@/src/lib/db/locks";

type RequestRow = typeof changeRequests.$inferSelect;

export const REQUEST_NOT_FOUND = "Change request not found";

const HOUR_MS = 60 * 60 * 1000;
const MAX_INPUT_BYTES = 256 * 1024;
const MAX_OPEN_REQUESTS_PER_USER = 100;
const MAX_NOTE_LENGTH = MAX_COMMENT_LENGTH;
const MAX_REASON_LENGTH = MAX_COMMENT_LENGTH;
const MAX_ERROR_LENGTH = 1000;

// ── The change ────────────────────────────────────────────────────────

export type ForwardAuthAccessInput = { userIds: number[]; groupIds: number[] };

export type MtlsRuleChange =
  | { action: "create"; input: Omit<MtlsAccessRuleInput, "proxyHostId"> }
  | { action: "update"; ruleId: number; input: Partial<Omit<MtlsAccessRuleInput, "proxyHostId">> }
  | { action: "delete"; ruleId: number };

/** A proxy host change: the host's fields, its forward-auth access and one mTLS access rule. */
export type ProxyHostChangeInput = {
  host?: Partial<ProxyHostInput>;
  forwardAuthAccess?: ForwardAuthAccessInput;
  mtlsRule?: MtlsRuleChange;
};

export type L4HostChangeInput = { host?: Partial<L4ProxyHostInput> };

/** The mTLS access rule fields of a request body, for a change request's input (the model ignores the rest). */
export function mtlsRuleFields(body: unknown): Partial<Omit<MtlsAccessRuleInput, "proxyHostId">> {
  if (!isRecord(body)) return {};
  const keys = ["pathPattern", "allowedRoleIds", "allowedCertIds", "denyAll", "priority", "description"] as const;
  return Object.fromEntries(keys.filter((key) => body[key] !== undefined).map((key) => [key, body[key]]));
}

export type ChangeKind = "create" | "update" | "delete";

/** The host as the caller found it (already checked against the caller's scope). */
export type ChangeTarget = { id: number; name: string; tags: readonly string[]; enabled: boolean };

export type HostChange =
  | { targetType: "proxy_host"; kind: ChangeKind; target: ChangeTarget | null; input: ProxyHostChangeInput }
  | { targetType: "l4_proxy_host"; kind: ChangeKind; target: ChangeTarget | null; input: L4HostChangeInput };

export type GateOutcome =
  | { status: "pending"; request: ChangeRequestView; message: string }
  | { status: "applied"; request: ChangeRequestView; message: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function writePermission(targetType: TargetType): Permission {
  return targetType === "proxy_host" ? "proxy_hosts:write" : "l4_proxy_hosts:write";
}

function readPermission(targetType: TargetType): Permission {
  return targetType === "proxy_host" ? "proxy_hosts:read" : "l4_proxy_hosts:read";
}

function scopeArea(targetType: TargetType) {
  return targetType === "proxy_host" ? ("proxy_hosts" as const) : ("l4_proxy_hosts" as const);
}

function hostInput(change: HostChange): Record<string, unknown> {
  return (change.input.host ?? {}) as Record<string, unknown>;
}

function hasSubResources(change: HostChange): boolean {
  return change.targetType === "proxy_host" && (change.input.forwardAuthAccess !== undefined || change.input.mtlsRule !== undefined);
}

/** The operations a change performs. */
function operationsOf(change: HostChange): { operation: Operation; operations: Operation[] } {
  if (change.kind === "create") return { operation: "create", operations: ["create"] };
  if (change.kind === "delete") return { operation: "delete", operations: ["delete"] };
  return updateOperations(hostInput(change), change.target?.enabled ?? true, hasSubResources(change));
}

/** The host's tags before and after the change. */
function tagsOf(change: HostChange): string[] {
  const requested = hostInput(change).tags;
  const after = requested !== undefined ? normalizeTags(requested) : [];
  return [...new Set([...(change.target?.tags ?? []), ...after])].sort();
}

// ── Reading text input ────────────────────────────────────────────────

/** Control characters other than line breaks and tabs. */
function hasControlCharacters(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code === 9 || code === 10 || code === 13) continue;
    if (code < 32 || (code >= 127 && code < 160)) return true;
  }
  return false;
}

function readText(value: unknown, field: string, options: { required: boolean; min?: number; max: number }): string | null {
  if (value === undefined || value === null || (typeof value === "string" && !value.trim())) {
    if (options.required) throw new ApiValidationError(`${field} is required`);
    return null;
  }
  if (typeof value !== "string") throw new ApiValidationError(`${field} must be a string`);
  const text = value.trim();
  if (options.min !== undefined && text.length < options.min) {
    throw new ApiValidationError(`${field} must be at least ${options.min} characters`);
  }
  if (text.length > options.max) throw new ApiValidationError(`${field} must be at most ${options.max} characters`);
  // Line breaks and tabs are fine; other control characters are not.
  if (hasControlCharacters(text)) throw new ApiValidationError(`${field} must not contain control characters`);
  return text;
}

function readBody(input: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (input === undefined || input === null) return {};
  if (!isRecord(input)) throw new ApiValidationError("Body must be a JSON object");
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) throw new ApiValidationError(`Unknown field "${key}"`);
  }
  return input;
}

// ── Snapshots ─────────────────────────────────────────────────────────

/** The target as it is now (with the parts of it a change can touch), or null when it is gone. */
async function snapshotTarget(targetType: TargetType, id: number): Promise<Record<string, unknown> | null> {
  if (targetType === "proxy_host") {
    const host = await getProxyHost(id);
    if (!host) return null;
    const grants = await getForwardAuthAccessForHost(id);
    const rules = await listMtlsAccessRules(id);
    return {
      host,
      forwardAuthAccess: {
        userIds: grants.filter((entry) => entry.userId !== null).map((entry) => entry.userId!).sort((a, b) => a - b),
        groupIds: grants.filter((entry) => entry.groupId !== null).map((entry) => entry.groupId!).sort((a, b) => a - b),
      },
      mtlsAccessRules: [...rules].sort((a, b) => a.id - b.id),
    };
  }
  const host = await getL4ProxyHost(id);
  return host ? { host } : null;
}

function fingerprint(state: unknown): string {
  return createHash("sha256").update(canonicalJson(state)).digest("hex");
}

// ── Rows and views ────────────────────────────────────────────────────

function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function rowOperations(row: RequestRow): Operation[] {
  const parsed = parseJson<unknown[]>(row.operations, []);
  const operations = Array.isArray(parsed) ? parsed.filter(isOperation) : [];
  return operations.length > 0 ? operations : isOperation(row.operation) ? [row.operation] : ["update"];
}

function rowTargetType(row: RequestRow): TargetType {
  return isTargetType(row.targetType) ? row.targetType : "proxy_host";
}

function rowStatus(row: RequestRow): RequestStatus {
  return isRequestStatus(row.status) ? row.status : "failed";
}

function rowKind(row: RequestRow): ChangeKind {
  return row.operation === "create" ? "create" : row.operation === "delete" ? "delete" : "update";
}

function rowTags(row: RequestRow): string[] {
  return parseStoredTags(row.tags);
}

async function getRow(id: number): Promise<RequestRow | null> {
  return await first(appDb.select().from(changeRequests).where(eq(changeRequests.id, id)).limit(1)) ?? null;
}

/** The enabled policies that cover the request now. */
async function currentPolicies(row: RequestRow, policies?: readonly PolicyRule[]): Promise<PolicyRule[]> {
  return policiesCovering(policies ?? (await readEnabledPolicyRules()), rowTargetType(row), rowTags(row), rowOperations(row));
}

function windowStatus(covering: readonly PolicyRule[], now: Date): WindowStatus {
  const restricted = covering.filter((policy) => policy.windows.length > 0);
  if (restricted.length === 0) return { restricted: false, open: true, nextOpenAt: null, description: null };
  const open = allWindowsOpenAt(restricted, now);
  const next = open ? null : nextOpening(restricted, now);
  return {
    restricted: true,
    open,
    nextOpenAt: next ? next.toISOString() : null,
    description: restricted.map((policy) => describeWindows(policy.windows, policy.timeZone)).join("; "),
  };
}

/** Whether `access` may see the request: it can read the target's area within its scope, or made it. */
function canSee(access: Access, row: RequestRow): boolean {
  if (row.requestedBy === access.userId) return true;
  const targetType = rowTargetType(row);
  if (!can(access, readPermission(targetType))) return false;
  return tagsInScope(rowTags(row), scopeTagsFor(access, scopeArea(targetType)));
}

async function loadVisible(access: Access, id: number): Promise<RequestRow> {
  const row = Number.isSafeInteger(id) && id > 0 ? await getRow(id) : null;
  if (!row || !canSee(access, row)) throw new ApiClientError(REQUEST_NOT_FOUND, 404);
  return row;
}

type ReviewRow = typeof changeRequestReviews.$inferSelect;

async function reviewsOf(ids: readonly number[]): Promise<Map<number, ReviewRow[]>> {
  const map = new Map<number, ReviewRow[]>();
  if (ids.length === 0) return map;
  const rows = await appDb
    .select()
    .from(changeRequestReviews)
    .where(inArray(changeRequestReviews.requestId, [...ids]))
    .orderBy(changeRequestReviews.id);
  for (const row of rows) map.set(row.requestId, [...(map.get(row.requestId) ?? []), row]);
  return map;
}

async function userNames(ids: readonly number[]): Promise<Map<number, string>> {
  const unique = [...new Set(ids)].filter((id) => Number.isSafeInteger(id));
  if (unique.length === 0) return new Map();
  const rows = await appDb.select({ id: users.id, name: users.name, email: users.email }).from(users).where(inArray(users.id, unique));
  return new Map(rows.map((row) => [row.id, row.name?.trim() || row.email]));
}

function approverIds(reviews: readonly ReviewRow[], requestedBy: number): number[] {
  return [...new Set(reviews.filter((review) => review.decision === "approve" && review.userId !== requestedBy).map((review) => review.userId))];
}

const SUMMARY_FIELDS: Record<TargetType, readonly string[]> = {
  proxy_host: ["name", "domains", "upstreams", "enabled", "tags"],
  l4_proxy_host: ["name", "protocol", "listenAddress", "upstreams", "enabled", "tags"],
};

function pick(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(keys.filter((key) => key in value).map((key) => [key, value[key]]));
}

/** What the change changes, field by field, against the host as it was when requested. */
function changesOf(row: RequestRow): ChangeField[] {
  return changeFieldsOf(
    rowKind(row),
    rowTargetType(row),
    parseJson<Record<string, unknown>>(row.input, {}),
    parseJson<Record<string, unknown> | null>(row.baseState, null)
  );
}

function changeFieldsOf(
  kind: ChangeKind,
  targetType: TargetType,
  input: Record<string, unknown>,
  base: Record<string, unknown> | null
): ChangeField[] {
  if (kind === "delete") return diffWhole(pick(base?.host, SUMMARY_FIELDS[targetType]), null, "host");
  const changes: ChangeField[] =
    kind === "create" ? diffWhole(null, input.host ?? {}, "host") : diffPartial(base?.host ?? {}, input.host ?? {}, "host");
  if (input.forwardAuthAccess !== undefined) {
    changes.push(...diffWhole(kind === "create" ? null : base?.forwardAuthAccess ?? null, input.forwardAuthAccess, "forwardAuthAccess"));
  }
  const rule = input.mtlsRule as MtlsRuleChange | undefined;
  if (rule) {
    const rules = Array.isArray(base?.mtlsAccessRules) ? (base!.mtlsAccessRules as { id: number }[]) : [];
    const existing = rule.action === "create" ? null : rules.find((candidate) => candidate.id === rule.ruleId) ?? null;
    const path = rule.action === "create" ? "mtlsAccessRules.new" : `mtlsAccessRules.${rule.ruleId}`;
    if (rule.action === "create") changes.push(...diffWhole(null, rule.input, path));
    else if (rule.action === "update") changes.push(...diffPartial(existing ?? {}, rule.input, path));
    else changes.push(...diffWhole(pick(existing, ["pathPattern", "allowedRoleIds", "allowedCertIds", "denyAll", "priority"]), null, path));
  }
  return changes;
}

async function toView(
  access: Access,
  row: RequestRow,
  reviews: readonly ReviewRow[],
  names: Map<number, string>,
  policies: readonly PolicyRule[],
  now: Date,
  reach: ConfigurationReach
): Promise<ChangeRequestView> {
  const status = rowStatus(row);
  const open = OPEN_STATUSES.includes(status);
  const isRequester = row.requestedBy === access.userId;
  const approvers = approverIds(reviews, row.requestedBy);
  const covering = await currentPolicies(row, policies);
  const window = open ? windowStatus(covering, now) : { restricted: false, open: true, nextOpenAt: null, description: null };
  const storedPolicyIds = parseJson<number[]>(row.policyIds, []);
  const storedPolicyNames = parseJson<string[]>(row.policyNames, []);
  const name = (id: number | null) => (id === null ? null : { id, name: names.get(id) ?? `User #${id}` });
  const canApproveRole = can(access, "approvals:approve");
  const forbidsEmergency = policiesForbiddingEmergency(covering).length > 0;
  return {
    id: row.id,
    targetType: rowTargetType(row),
    targetId: row.targetId ?? null,
    targetName: row.targetName,
    operation: isOperation(row.operation) ? row.operation : "update",
    operations: rowOperations(row),
    status,
    requestedBy: name(row.requestedBy)!,
    note: row.note ?? null,
    emergency: row.emergency,
    emergencyReason: row.emergencyReason ?? null,
    emergencyBy: name(row.emergencyBy ?? null),
    requiredApprovals: row.requiredApprovals,
    approvals: approvers.length,
    policies: storedPolicyIds.map((id, index) => ({ id, name: storedPolicyNames[index] ?? `#${id}` })),
    tags: rowTags(row),
    input: parseJson<Record<string, unknown>>(row.input, {}),
    changes: changesOf(row),
    reviews: reviews.map(
      (review): ReviewView => ({
        id: review.id,
        userId: review.userId,
        userName: names.get(review.userId) ?? `User #${review.userId}`,
        decision: review.decision === "approve" || review.decision === "reject" ? review.decision : "comment",
        comment: review.comment ?? null,
        createdAt: toIso(review.createdAt)!,
      })
    ),
    window,
    expiresAt: toIso(row.expiresAt)!,
    decidedAt: toIso(row.decidedAt),
    appliedAt: toIso(row.appliedAt),
    appliedBy: name(row.appliedBy ?? null),
    error: row.error ?? null,
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!,
    viewer: {
      isRequester,
      canApprove: status === "pending" && !isRequester && canApproveRole && !approvers.includes(access.userId),
      canReject: open && !isRequester && canApproveRole,
      canCancel: open && (isRequester || can(access, "approvals:manage")),
      canApply: status === "approved" && canApproveRole && window.open,
      canEmergency: open && can(access, "approvals:emergency") && !forbidsEmergency,
    },
    impact: computeChangeImpact({
      targetType: rowTargetType(row),
      targetId: row.targetId ?? null,
      targetName: row.targetName,
      operation: isOperation(row.operation) ? row.operation : "update",
      operations: rowOperations(row),
      status,
      change: parseJson<Record<string, unknown>>(row.input, {}),
      base: parseJson<Record<string, unknown> | null>(row.baseState, null),
      window,
      appliedAt: toIso(row.appliedAt),
      reach,
    }),
  };
}

async function viewsOf(access: Access, rows: readonly RequestRow[], now = new Date()): Promise<ChangeRequestView[]> {
  const reviews = await reviewsOf(rows.map((row) => row.id));
  const ids = rows.flatMap((row) => [
    row.requestedBy,
    ...(row.emergencyBy != null ? [row.emergencyBy] : []),
    ...(row.appliedBy != null ? [row.appliedBy] : []),
    ...(reviews.get(row.id) ?? []).map((review) => review.userId),
  ]);
  const names = await userNames(ids);
  const policies = await readEnabledPolicyRules();
  const reach = await readConfigurationReach();
  return Promise.all(rows.map((row) => toView(access, row, reviews.get(row.id) ?? [], names, policies, now, reach)));
}

async function viewOf(access: Access, id: number, now = new Date()): Promise<ChangeRequestView> {
  const row = await getRow(id);
  if (!row) throw new ApiClientError(REQUEST_NOT_FOUND, 404);
  return (await viewsOf(access, [row], now))[0];
}

// ── Listing ───────────────────────────────────────────────────────────

export type ListFilter = "open" | "closed" | "all" | RequestStatus;

export function parseListFilter(value: string | null): ListFilter {
  if (!value || value === "all") return "all";
  if (value === "open" || value === "closed" || isRequestStatus(value)) return value;
  throw new ApiValidationError("status must be open, closed, all or one of: pending, approved, applied, rejected, cancelled, expired, failed");
}

/** The requests `access` may see, newest first. Expired requests are marked first. */
export async function listChangeRequests(
  access: Access,
  options: { status?: ListFilter; page?: number; perPage?: number; mine?: boolean } = {},
  now: Date = new Date()
): Promise<ChangeRequestPage> {
  await expireDueRequests(now);
  const status = options.status ?? "all";
  const page = Math.max(1, options.page ?? 1);
  const perPage = Math.min(100, Math.max(1, options.perPage ?? 25));
  const where =
    status === "all"
      ? undefined
      : status === "open"
        ? inArray(changeRequests.status, [...OPEN_STATUSES])
        : status === "closed"
          ? inArray(changeRequests.status, ["applied", "rejected", "cancelled", "expired", "failed"])
          : eq(changeRequests.status, status);
  const rows = (await appDb
    .select()
    .from(changeRequests)
    .where(options.mine ? and(where, eq(changeRequests.requestedBy, access.userId)) : where)
    .orderBy(desc(changeRequests.id)))
    .filter((row) => canSee(access, row));
  const slice = rows.slice((page - 1) * perPage, page * perPage);
  return { requests: await viewsOf(access, slice, now), total: rows.length, page, perPage };
}

/**
 * Requests waiting for approval that `access` may see (the sidebar's
 * counter). Reads only; requests past their deadline count until the
 * scheduler marks them expired.
 */
export async function countPendingChangeRequests(access: Access): Promise<number> {
  return (await appDb
    .select()
    .from(changeRequests)
    .where(eq(changeRequests.status, "pending")))
    .filter((row) => canSee(access, row)).length;
}

export async function getChangeRequest(access: Access, id: number, now: Date = new Date()): Promise<ChangeRequestView> {
  await expireDueRequests(now);
  return (await viewsOf(access, [await loadVisible(access, id)], now))[0];
}

/** Parses a request id from a route parameter; 404 otherwise. */
export function parseRequestId(raw: string): number {
  const id = parseRowId(raw);
  if (id === null) throw new ApiClientError(REQUEST_NOT_FOUND, 404);
  return id;
}

/** For the host dialogs: the enabled policies and whether the user may make emergency changes. */
export async function getHostApprovalContext(access: Access): Promise<HostApprovalContext> {
  return { policies: await readEnabledPolicyRules(), canEmergency: can(access, "approvals:emergency") };
}

/** What submitting a change would do, before it is submitted (the host editor's review). */
export type HostChangePreview = {
  approval: {
    /** A covering policy turns the change into a change request. */
    required: boolean;
    /** The covering policies. */
    policies: { id: number; name: string }[];
    /** Distinct approvals the change request needs (from someone other than the requester). */
    requiredApprovals: number;
    operations: Operation[];
    /** When the change may be applied once approved. */
    window: WindowStatus;
    /** The requester may apply it at once as an emergency change instead. */
    emergencyAllowed: boolean;
    minEmergencyReasonLength: number;
  };
  /** Field by field, against the host as it is now. */
  changes: ChangeField[];
  /** Hosts affected, Caddy reloads and certificate requests, and when it applies. */
  impact: ChangeImpact;
};

/**
 * Previews a host change without storing anything: whether a change approval
 * policy covers it (and what it asks for), what changes field by field and
 * its impact. The caller has checked the permission and the scope, as for
 * gateHostChange. Reads only.
 */
export async function previewHostChange(params: { access: Access; change: HostChange; now?: Date }): Promise<HostChangePreview> {
  const { access, change } = params;
  const now = params.now ?? new Date();
  validateChangeShape(change);
  const { operation, operations } = operationsOf(change);
  const covering = policiesCovering(await readEnabledPolicyRules(), change.targetType, tagsOf(change), operations);
  const window: WindowStatus = covering.length > 0 ? windowStatus(covering, now) : { restricted: false, open: true, nextOpenAt: null, description: null };
  const base = change.target ? await snapshotTarget(change.targetType, change.target.id) : null;
  if (change.target && !base) throw new ApiClientError(`${TARGET_LABELS[change.targetType]} not found`, 404);
  const input = change.input as Record<string, unknown>;
  const targetName = String(hostInput(change).name ?? change.target?.name ?? "").trim().slice(0, 200) || "(unnamed)";
  return {
    approval: {
      required: covering.length > 0,
      policies: covering.map((policy) => ({ id: policy.id, name: policy.name })),
      requiredApprovals: covering.length > 0 ? requiredApprovalsFor(covering) : 0,
      operations,
      window,
      emergencyAllowed: covering.length > 0 && can(access, "approvals:emergency") && policiesForbiddingEmergency(covering).length === 0,
      minEmergencyReasonLength: MIN_EMERGENCY_REASON_LENGTH,
    },
    changes: changeFieldsOf(change.kind, change.targetType, input, base),
    impact: computeChangeImpact({
      targetType: change.targetType,
      targetId: change.target?.id ?? null,
      targetName,
      operation,
      operations,
      status: "pending",
      change: input,
      base,
      window,
      appliedAt: null,
      reach: await readConfigurationReach(),
    }),
  };
}

// ── Submitting ────────────────────────────────────────────────────────

function validateChangeShape(change: HostChange): void {
  if (change.input.host !== undefined && !isRecord(change.input.host)) {
    throw new ApiValidationError("Body must be a JSON object");
  }
  if (change.kind === "create") {
    const name = hostInput(change).name;
    if (typeof name !== "string" || !name.trim()) throw new ApiValidationError("name is required");
  }
  if (change.kind !== "create" && !change.target) throw new ApiClientError(`${TARGET_LABELS[change.targetType]} not found`, 404);
  if (Buffer.byteLength(JSON.stringify(change.input)) > MAX_INPUT_BYTES) {
    throw new ApiValidationError("The change is too large");
  }
}

function statusMessage(view: ChangeRequestView): string {
  const approvals = `${view.requiredApprovals} approval${view.requiredApprovals === 1 ? "" : "s"}`;
  const window = view.window.restricted ? ` It will be applied in a change window: ${view.window.description}.` : "";
  return `Submitted for approval as change request #${view.id}: it needs ${approvals} from someone other than you.${window}`;
}

/**
 * Turns a protected change into a change request; null when no enabled
 * policy covers it (the caller applies it directly). The caller has already
 * checked the permission, the scope and the references (access-scope.ts) and
 * built the validated input. With `emergencyReason`, the change is applied
 * at once as an emergency change.
 */
export async function gateHostChange(params: {
  access: Access;
  change: HostChange;
  note?: unknown;
  emergencyReason?: unknown;
  now?: Date;
}): Promise<GateOutcome | null> {
  const { access, change } = params;
  const now = params.now ?? new Date();
  const { operation, operations } = operationsOf(change);
  const tags = tagsOf(change);
  const covering = policiesCovering(await readEnabledPolicyRules(), change.targetType, tags, operations);
  if (covering.length === 0) return null;

  validateChangeShape(change);
  const note = readText(params.note, "note", { required: false, max: MAX_NOTE_LENGTH });
  const reason = readText(params.emergencyReason, "emergencyReason", {
    required: false,
    min: MIN_EMERGENCY_REASON_LENGTH,
    max: MAX_REASON_LENGTH,
  });
  if (reason !== null) assertEmergencyAllowed(access, covering);

  const at = now.toISOString();
  const targetName = String(hostInput(change).name ?? change.target?.name ?? "").trim().slice(0, 200) || "(unnamed)";
  // The per-user limit, the target's state and the request in one transaction.
  const row = await appDb.transaction(async (tx) => {
    const [{ value: open }] = await tx
      .select({ value: count() })
      .from(changeRequests)
      .where(and(eq(changeRequests.requestedBy, access.userId), inArray(changeRequests.status, [...OPEN_STATUSES])));
    if (open >= MAX_OPEN_REQUESTS_PER_USER) {
      throw new ApiClientError(`You have ${open} open change requests; wait for them to be decided or cancel some first`, 429);
    }

    const baseState = change.target ? await snapshotTarget(change.targetType, change.target.id) : null;
    if (change.target && !baseState) throw new ApiClientError(`${TARGET_LABELS[change.targetType]} not found`, 404);
    return (await first(tx
      .insert(changeRequests)
      .values({
        targetType: change.targetType,
        targetId: change.target?.id ?? null,
        targetName,
        operation,
        operations: JSON.stringify(operations),
        input: JSON.stringify(change.input),
        baseState: baseState ? JSON.stringify(baseState) : null,
        baseFingerprint: baseState ? fingerprint(baseState) : null,
        tags: JSON.stringify(tags),
        status: "pending",
        requiredApprovals: requiredApprovalsFor(covering),
        policyIds: JSON.stringify(covering.map((policy) => policy.id)),
        policyNames: JSON.stringify(covering.map((policy) => policy.name)),
        note,
        requestedBy: access.userId,
        expiresAt: new Date(now.getTime() + requestTtlHoursFor(covering) * HOUR_MS).toISOString(),
        createdAt: at,
        updatedAt: at,
      })
      .returning()))!;
  });
  const label = `${TARGET_LABELS[change.targetType].toLowerCase()} "${targetName}"`;
  await logAuditEvent({
    userId: access.userId,
    action: "change_request_created",
    entityType: "change_request",
    entityId: row.id,
    summary: `Requested approval to ${operation} ${label} (change request #${row.id})`,
    data: {
      targetType: change.targetType,
      targetId: row.targetId,
      operation,
      operations,
      policies: covering.map((policy) => ({ id: policy.id, name: policy.name })),
      requiredApprovals: row.requiredApprovals,
      emergency: reason !== null,
    },
  });

  if (reason !== null) {
    const view = await applyAsEmergency(access, row.id, reason, now);
    if (view.status !== "applied") {
      throw new ApiConflictError(`The emergency change could not be applied: ${view.error ?? "unknown error"} (change request #${view.id})`);
    }
    return { status: "applied", request: view, message: `Emergency change applied and recorded as change request #${view.id}.` };
  }
  const view = await viewOf(access, row.id, now);
  return { status: "pending", request: view, message: statusMessage(view) };
}

// ── Applying ──────────────────────────────────────────────────────────

/** Runs applies one at a time, on every replica of the deployment (src/lib/db/locks.ts). */
async function withApplyLock<T>(operation: () => Promise<T>): Promise<T> {
  return await withClusterLock("change-request-apply", operation);
}

/** Refused at apply time; the message says why and is stored on the request. */
class ApplyRefused extends Error {}

/** The requester's access now: active account, the write permission, and (below) the scope. */
async function requesterAccess(row: RequestRow): Promise<Access> {
  const user = await first(appDb
    .select({ id: users.id, role: users.role, customRoleId: users.customRoleId, status: users.status })
    .from(users)
    .where(eq(users.id, row.requestedBy))
    .limit(1));
  if (!user || user.status !== "active") throw new ApplyRefused("The requester's account is no longer active");
  const access = await accessForUser({ id: user.id, role: user.role, customRoleId: user.customRoleId });
  const permission = writePermission(rowTargetType(row));
  if (!can(access, permission)) throw new ApplyRefused(`The requester no longer holds the ${permission} permission`);
  return access;
}

/** Re-runs the requester's permission, scope and reference checks against the host as it is now. */
async function authorize(access: Access, row: RequestRow): Promise<void> {
  const kind = rowKind(row);
  const targetType = rowTargetType(row);
  const outOfScope = () => new ApplyRefused("The host is no longer within the requester's scope");
  if (targetType === "proxy_host") {
    const input = parseJson<ProxyHostChangeInput>(row.input, {});
    const host = (input.host ?? {}) as Partial<ProxyHostInput>;
    if (kind === "create") {
      tagsForWrite(access, "proxy_hosts", host.tags, null);
      await assertProxyHostWriteAllowed(access, host, null);
      await assertDomainsFreeOutsideScope(access, host.domains, null);
      if (input.forwardAuthAccess) await assertForwardAuthAccessAllowed(access, input.forwardAuthAccess, { userIds: [], groupIds: [] });
      return;
    }
    const existing = await findProxyHostInScope(access, row.targetId ?? 0);
    if (!existing) throw outOfScope();
    if (kind === "delete") return;
    if (input.host) {
      tagsForWrite(access, "proxy_hosts", host.tags, existing.tags);
      await assertProxyHostWriteAllowed(access, host, existing);
      await assertDomainsFreeOutsideScope(access, host.domains, existing.id);
    }
    if (input.forwardAuthAccess) {
      const grants = await getForwardAuthAccessForHost(existing.id);
      await assertForwardAuthAccessAllowed(access, input.forwardAuthAccess, {
        userIds: grants.filter((entry) => entry.userId !== null).map((entry) => entry.userId!),
        groupIds: grants.filter((entry) => entry.groupId !== null).map((entry) => entry.groupId!),
      });
    }
    if (input.mtlsRule && input.mtlsRule.action !== "delete") {
      const current = input.mtlsRule.action === "update" ? await getMtlsAccessRule(input.mtlsRule.ruleId) : null;
      assertMtlsRuleReferencesAllowed(access, input.mtlsRule.input, current);
    }
    return;
  }
  const input = parseJson<L4HostChangeInput>(row.input, {});
  const host = (input.host ?? {}) as Partial<L4ProxyHostInput>;
  if (kind === "create") {
    tagsForWrite(access, "l4_proxy_hosts", host.tags, null);
    assertL4WriteAllowed(access, host);
    await assertListenPortFreeOutsideScope(access, host.protocol, host.listenAddress, null);
    return;
  }
  const existing = await findL4ProxyHostInScope(access, row.targetId ?? 0);
  if (!existing) throw outOfScope();
  if (kind === "delete" || !input.host) return;
  tagsForWrite(access, "l4_proxy_hosts", host.tags, existing.tags);
  assertL4WriteAllowed(access, host, existing);
  await assertListenPortFreeOutsideScope(
    access,
    host.protocol ?? existing.protocol,
    host.listenAddress ?? (host.protocol !== undefined ? existing.listenAddress : undefined),
    existing.id
  );
}

/** Applies the stored change through the model functions, as the requester. Returns the host's id. */
async function execute(row: RequestRow): Promise<number | null> {
  const kind = rowKind(row);
  const actor = row.requestedBy;
  const targetId = row.targetId ?? 0;
  if (rowTargetType(row) === "proxy_host") {
    const input = parseJson<ProxyHostChangeInput>(row.input, {});
    const grants = input.forwardAuthAccess;
    if (kind === "create") {
      const host = await createProxyHost(input.host as ProxyHostInput, actor);
      if (grants && host.ingressiForwardAuth?.enabled && (grants.userIds.length > 0 || grants.groupIds.length > 0)) {
        await setForwardAuthAccess(host.id, grants, actor);
      }
      return host.id;
    }
    if (kind === "delete") {
      await deleteProxyHost(targetId, actor);
      return targetId;
    }
    if (input.host) await updateProxyHost(targetId, input.host, actor);
    if (grants) await setForwardAuthAccess(targetId, grants, actor);
    const rule = input.mtlsRule;
    if (rule) {
      // A rule of another host is never touched, whatever the input says.
      if (rule.action !== "create") {
        const existing = await getMtlsAccessRule(rule.ruleId);
        if (!existing || existing.proxyHostId !== targetId) throw new ApplyRefused("The mTLS access rule no longer exists");
      }
      if (rule.action === "create") await createMtlsAccessRule({ ...rule.input, proxyHostId: targetId }, actor);
      else if (rule.action === "update") await updateMtlsAccessRule(rule.ruleId, rule.input, actor);
      else await deleteMtlsAccessRule(rule.ruleId, actor);
    }
    return targetId;
  }
  const input = parseJson<L4HostChangeInput>(row.input, {});
  if (kind === "create") return (await createL4ProxyHost(input.host as L4ProxyHostInput, actor)).id;
  if (kind === "delete") await deleteL4ProxyHost(targetId, actor);
  else if (input.host) await updateL4ProxyHost(targetId, input.host, actor);
  return targetId;
}

function truncateError(message: string): string {
  return message.length > MAX_ERROR_LENGTH ? `${message.slice(0, MAX_ERROR_LENGTH - 1)}…` : message;
}

type ApplyVia = "approval" | "manual" | "scheduler" | "emergency";

/**
 * Applies request `id` if it is still in `from` status. Marks it applied or
 * failed (or back to pending when the policies now ask for more approvals)
 * and records the outcome in the audit log.
 */
async function applyRequest(id: number, actorId: number | null, via: ApplyVia, from: readonly RequestStatus[]): Promise<void> {
  await withApplyLock(async () => {
    const row = await getRow(id);
    if (!row || !from.includes(rowStatus(row))) return;
    const at = nowIso();
    const reviews = (await reviewsOf([id])).get(id) ?? [];
    const approvers = approverIds(reviews, row.requestedBy);
    const targetType = rowTargetType(row);
    const label = `${TARGET_LABELS[targetType].toLowerCase()} "${row.targetName}"`;

    if (via !== "emergency") {
      const required = Math.max(row.requiredApprovals, requiredApprovalsFor(await currentPolicies(row)));
      if (approvers.length < required) {
        await appDb.update(changeRequests)
          .set({ status: "pending", requiredApprovals: required, updatedAt: at })
          .where(eq(changeRequests.id, id));
        return;
      }
    }

    let targetId: number | null = row.targetId ?? null;
    let error: string | null = null;
    let applied = false;
    try {
      if (row.baseFingerprint) {
        const current = await snapshotTarget(targetType, row.targetId ?? 0);
        if (!current) throw new ApplyRefused(`The ${TARGET_LABELS[targetType].toLowerCase()} no longer exists`);
        if (fingerprint(current) !== row.baseFingerprint) {
          throw new ApplyRefused("The host changed after this request was made; submit the change again");
        }
      }
      const access = await requesterAccess(row);
      try {
        await authorize(access, row);
      } catch (cause) {
        if (cause instanceof ApplyRefused) throw cause;
        if (cause instanceof ApiClientError) throw new ApplyRefused(`The requester's role no longer allows this change: ${cause.message}`);
        if (cause instanceof Error && /not found$/i.test(cause.message)) throw new ApplyRefused("The host is no longer within the requester's scope");
        throw cause;
      }
      targetId = await runApprovedChange({ targetType, targetId: row.targetId ?? null, requestId: id }, () => execute(row));
      applied = true;
    } catch (cause) {
      if (cause instanceof CaddyApplyError) {
        // The model functions store the change before applying it to Caddy.
        applied = true;
        error = `Saved, but applying the configuration to Caddy failed: ${cause.message}`;
      } else if (cause instanceof ApplyRefused || cause instanceof ApiClientError) {
        error = cause.message;
      } else if (cause instanceof Error && /not found$/i.test(cause.message)) {
        error = cause.message;
      } else {
        error = `The change could not be applied (error id ${logUnexpectedApiError("Change request apply failed", cause)})`;
      }
    }

    await appDb.update(changeRequests)
      .set({
        status: applied ? "applied" : "failed",
        targetId,
        appliedAt: applied ? at : null,
        appliedBy: actorId,
        error: error ? truncateError(error) : null,
        updatedAt: at,
      })
      .where(eq(changeRequests.id, id));
    await logAuditEvent({
      userId: actorId,
      action: applied ? "change_request_applied" : "change_request_failed",
      entityType: "change_request",
      entityId: id,
      summary: applied
        ? `Applied change request #${id}: ${row.operation} ${label}${row.emergency || via === "emergency" ? " (emergency change)" : ""}`
        : `Change request #${id} to ${row.operation} ${label} could not be applied: ${truncateError(error ?? "")}`,
      data: {
        targetType,
        targetId,
        operation: row.operation,
        requestedBy: row.requestedBy,
        approvedBy: approvers,
        appliedBy: actorId,
        via,
        emergency: row.emergency || via === "emergency",
        emergencyReason: row.emergencyReason ?? null,
        error,
      },
    });
  });
}

// ── Decisions ─────────────────────────────────────────────────────────

/** Marks pending requests past their expiry as expired. */
export async function expireDueRequests(now: Date = new Date()): Promise<number> {
  const at = now.toISOString();
  const rows = await appDb
    .update(changeRequests)
    .set({ status: "expired", decidedAt: at, updatedAt: at })
    .where(and(eq(changeRequests.status, "pending"), lt(changeRequests.expiresAt, at)))
    .returning({ id: changeRequests.id, targetName: changeRequests.targetName });
  for (const row of rows) {
    await logAuditEvent({
      userId: null,
      action: "change_request_expired",
      entityType: "change_request",
      entityId: row.id,
      summary: `Change request #${row.id} (${row.targetName}) expired without enough approvals`,
    });
  }
  return rows.length;
}

/** Moves a request from one of `from` to `to`; false when another decision got there first. */
async function transition(id: number, from: readonly RequestStatus[], values: Partial<typeof changeRequests.$inferInsert>): Promise<boolean> {
  const rows = await appDb
    .update(changeRequests)
    .set({ ...values, updatedAt: nowIso() })
    .where(and(eq(changeRequests.id, id), inArray(changeRequests.status, [...from])))
    .returning({ id: changeRequests.id });
  return rows.length > 0;
}

function assertStatus(row: RequestRow, allowed: readonly RequestStatus[]): void {
  const status = rowStatus(row);
  if (!allowed.includes(status)) {
    throw new ApiConflictError(`Change request #${row.id} is ${status}, not ${allowed.join(" or ")}`);
  }
}

async function addReview(requestId: number, userId: number, decision: "approve" | "reject" | "comment", comment: string | null): Promise<void> {
  await appDb.insert(changeRequestReviews).values({ requestId, userId, decision, comment, createdAt: nowIso() });
}

/**
 * Approves request `id` (approvals:approve). Nobody approves their own
 * request; each approver counts once. With enough approvals the request is
 * approved, and applied at once when the change windows are open.
 */
export async function approveChangeRequest(access: Access, id: number, input: unknown, now: Date = new Date()): Promise<ChangeRequestView> {
  const body = readBody(input, ["comment"]);
  const comment = readText(body.comment, "comment", { required: false, max: MAX_COMMENT_LENGTH });
  await expireDueRequests(now);
  const row = await loadVisible(access, id);
  assertStatus(row, ["pending"]);
  if (row.requestedBy === access.userId) {
    throw new ApiClientError("You cannot approve your own change request; someone else has to", 403);
  }
  const reviews = (await reviewsOf([id])).get(id) ?? [];
  if (approverIds(reviews, row.requestedBy).includes(access.userId)) {
    throw new ApiConflictError("You already approved this change request");
  }
  await addReview(id, access.userId, "approve", comment);
  const approvers = approverIds((await reviewsOf([id])).get(id) ?? [], row.requestedBy);
  const covering = await currentPolicies(row);
  const required = Math.max(row.requiredApprovals, requiredApprovalsFor(covering));
  await logAuditEvent({
    userId: access.userId,
    action: "change_request_approved",
    entityType: "change_request",
    entityId: id,
    summary: `Approved change request #${id} (${approvers.length} of ${required})`,
    data: { requestedBy: row.requestedBy, approvedBy: approvers, required, comment },
  });
  if (approvers.length < required) {
    if (required !== row.requiredApprovals) await transition(id, ["pending"], { requiredApprovals: required });
    return await viewOf(access, id, now);
  }
  if (await transition(id, ["pending"], { status: "approved", requiredApprovals: required, decidedAt: now.toISOString() })) {
    if (allWindowsOpenAt(covering, now)) await applyRequest(id, access.userId, "approval", ["approved"]);
  }
  return await viewOf(access, id, now);
}

/** Rejects request `id` (approvals:approve) with a comment. The requester cancels instead. */
export async function rejectChangeRequest(access: Access, id: number, input: unknown, now: Date = new Date()): Promise<ChangeRequestView> {
  const body = readBody(input, ["comment"]);
  const comment = readText(body.comment, "comment", { required: true, max: MAX_COMMENT_LENGTH });
  await expireDueRequests(now);
  const row = await loadVisible(access, id);
  assertStatus(row, OPEN_STATUSES);
  if (row.requestedBy === access.userId) {
    throw new ApiClientError("You cannot reject your own change request; cancel it instead", 403);
  }
  if (!await transition(id, OPEN_STATUSES, { status: "rejected", decidedAt: now.toISOString() })) {
    throw new ApiConflictError(`Change request #${id} was decided in the meantime`);
  }
  await addReview(id, access.userId, "reject", comment);
  await logAuditEvent({
    userId: access.userId,
    action: "change_request_rejected",
    entityType: "change_request",
    entityId: id,
    summary: `Rejected change request #${id} (${row.targetName})`,
    data: { requestedBy: row.requestedBy, comment },
  });
  return await viewOf(access, id, now);
}

/** Cancels request `id`: its requester, or someone holding approvals:manage. */
export async function cancelChangeRequest(access: Access, id: number, input: unknown, now: Date = new Date()): Promise<ChangeRequestView> {
  const body = readBody(input, ["comment"]);
  const comment = readText(body.comment, "comment", { required: false, max: MAX_COMMENT_LENGTH });
  await expireDueRequests(now);
  const row = await loadVisible(access, id);
  if (row.requestedBy !== access.userId && !can(access, "approvals:manage")) {
    throw new ApiClientError("Only the requester or an administrator can cancel a change request", 403);
  }
  assertStatus(row, OPEN_STATUSES);
  if (!await transition(id, OPEN_STATUSES, { status: "cancelled", decidedAt: now.toISOString() })) {
    throw new ApiConflictError(`Change request #${id} was decided in the meantime`);
  }
  if (comment) await addReview(id, access.userId, "comment", comment);
  await logAuditEvent({
    userId: access.userId,
    action: "change_request_cancelled",
    entityType: "change_request",
    entityId: id,
    summary: `Cancelled change request #${id} (${row.targetName})`,
    data: { requestedBy: row.requestedBy, comment },
  });
  return await viewOf(access, id, now);
}

/** Adds a comment to request `id` (anyone who can see it). */
export async function commentOnChangeRequest(access: Access, id: number, input: unknown): Promise<ChangeRequestView> {
  const body = readBody(input, ["comment"]);
  const comment = readText(body.comment, "comment", { required: true, max: MAX_COMMENT_LENGTH })!;
  const row = await loadVisible(access, id);
  await addReview(id, access.userId, "comment", comment);
  await logAuditEvent({
    userId: access.userId,
    action: "change_request_commented",
    entityType: "change_request",
    entityId: id,
    summary: `Commented on change request #${id} (${row.targetName})`,
    data: { comment },
  });
  return await viewOf(access, id);
}

/** Applies an approved request now (approvals:approve), inside the change windows. */
export async function applyChangeRequestNow(access: Access, id: number, now: Date = new Date()): Promise<ChangeRequestView> {
  await expireDueRequests(now);
  const row = await loadVisible(access, id);
  assertStatus(row, ["approved"]);
  const status = windowStatus(await currentPolicies(row), now);
  if (!status.open) {
    throw new ApiConflictError(
      `Outside the change window (${status.description})` +
        (status.nextOpenAt ? `; it opens next at ${status.nextOpenAt}` : "; the covering policies' windows never overlap")
    );
  }
  await applyRequest(id, access.userId, "manual", ["approved"]);
  return await viewOf(access, id, now);
}

function assertEmergencyAllowed(access: Access, policies: readonly PolicyRule[]): void {
  if (!can(access, "approvals:emergency")) {
    throw new ApiClientError("Emergency changes need the approvals:emergency permission", 403);
  }
  const forbidding = policiesForbiddingEmergency(policies);
  if (forbidding.length > 0) {
    throw new ApiClientError(`${describePolicies(forbidding)} does not allow emergency changes`.replace(/^t/, "T"), 403);
  }
}

async function applyAsEmergency(access: Access, id: number, reason: string, now: Date): Promise<ChangeRequestView> {
  const row = (await getRow(id))!;
  assertEmergencyAllowed(access, await currentPolicies(row));
  if (!await transition(id, OPEN_STATUSES, { emergency: true, emergencyReason: reason, emergencyBy: access.userId, decidedAt: now.toISOString() })) {
    throw new ApiConflictError(`Change request #${id} was decided in the meantime`);
  }
  await logAuditEvent({
    userId: access.userId,
    action: "change_request_emergency",
    entityType: "change_request",
    entityId: id,
    summary: `Emergency change: applying change request #${id} (${row.targetName}) without approval`,
    data: { requestedBy: row.requestedBy, reason },
  });
  await applyRequest(id, access.userId, "emergency", OPEN_STATUSES);
  return await viewOf(access, id, now);
}

/**
 * Applies request `id` at once as an emergency change (approvals:emergency),
 * skipping approvals and change windows, with a mandatory reason. Refused
 * when a covering policy forbids emergency changes.
 */
export async function emergencyApplyChangeRequest(access: Access, id: number, input: unknown, now: Date = new Date()): Promise<ChangeRequestView> {
  const body = readBody(input, ["reason"]);
  const reason = readText(body.reason, "reason", { required: true, min: MIN_EMERGENCY_REASON_LENGTH, max: MAX_REASON_LENGTH })!;
  await expireDueRequests(now);
  const row = await loadVisible(access, id);
  assertStatus(row, OPEN_STATUSES);
  return applyAsEmergency(access, id, reason, now);
}

/**
 * The scheduler's run: expires due requests and applies approved ones whose
 * change windows are open.
 */
export async function applyDueChangeRequests(now: Date = new Date()): Promise<{ expired: number; applied: number; failed: number }> {
  const expired = await expireDueRequests(now);
  const approved = await appDb.select().from(changeRequests).where(eq(changeRequests.status, "approved")).orderBy(changeRequests.id);
  const policies = await readEnabledPolicyRules();
  let applied = 0;
  let failed = 0;
  for (const row of approved) {
    if (!allWindowsOpenAt(await currentPolicies(row, policies), now)) continue;
    await applyRequest(row.id, null, "scheduler", ["approved"]);
    const after = await getRow(row.id);
    if (after?.status === "applied") applied += 1;
    else if (after?.status === "failed") failed += 1;
  }
  return { expired, applied, failed };
}
