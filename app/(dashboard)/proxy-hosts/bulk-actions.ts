"use server";

/**
 * Bulk actions of the proxy hosts list: turn WAF blocking on, add a tag,
 * enable, disable or delete several hosts at once. Each host goes through the
 * same checks as a change to one host (the role's tag scope, the
 * references it may use, change approval policies), and a host a policy
 * protects gets a change request instead. The hosts changed at once are
 * written in one change batch and Caddy is applied once at the end; each
 * still gets its own audit event, as a change to one host does.
 */
import { revalidatePath } from "next/cache";
import { requirePermission } from "@/src/lib/auth";
import { assertProxyHostWriteAllowed, getProxyHostInScope, tagsForWrite } from "@/src/lib/access-scope";
import { deleteProxyHost, updateProxyHost, type ProxyHost, type ProxyHostInput } from "@/src/lib/models/proxy-hosts";
import { runAsChangeBatch } from "@/src/lib/change-batch";
import { applyBatchOrUndo, caddyAcceptedLastApply } from "@/src/lib/rejected-apply";
import { logAuditEvent } from "@/src/lib/audit";
import { hostModeOf, withHostMode } from "@/src/lib/waf-host-mode";
import { normalizeTags } from "@/src/lib/host-tags";
import type { Access } from "@/src/lib/permissions";
import { gateHostChange } from "@/ee/approvals/requests";

export type BulkOperation =
  | { type: "enable" }
  | { type: "disable" }
  | { type: "waf_block" }
  | { type: "add_tag"; tag: string }
  | { type: "delete" };

export type BulkResult = {
  ok: boolean;
  /** Hosts changed now. */
  changed: number;
  /** Changes submitted for approval. */
  submitted: number;
  /** Hosts that already were as asked. */
  unchanged: number;
  failed: { id: number; name: string | null; message: string }[];
  message: string;
};

/** At most this many hosts per bulk action (a page of the list is 25). */
const MAX_HOSTS = 100;

const DONE_TEXT: Record<BulkOperation["type"], string> = {
  enable: "Enabled",
  disable: "Disabled",
  waf_block: "Turned WAF blocking on for",
  add_tag: "Tagged",
  delete: "Deleted",
};

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function readIds(value: unknown): number[] {
  if (!Array.isArray(value)) throw new Error("Choose the hosts first.");
  const ids = [...new Set(value)];
  if (ids.length === 0) throw new Error("Choose the hosts first.");
  if (ids.length > MAX_HOSTS) throw new Error(`Choose at most ${MAX_HOSTS} hosts at a time.`);
  if (!ids.every((id): id is number => typeof id === "number" && Number.isSafeInteger(id) && id > 0)) throw new Error("Unknown proxy host.");
  return ids;
}

function readOperation(value: unknown): BulkOperation {
  const op = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  switch (op.type) {
    case "enable":
    case "disable":
    case "waf_block":
    case "delete":
      return { type: op.type };
    case "add_tag": {
      const tags = normalizeTags(typeof op.tag === "string" ? op.tag : "");
      if (tags.length !== 1) throw new Error("Enter one tag.");
      return { type: "add_tag", tag: tags[0] };
    }
    default:
      throw new Error("Unknown bulk action.");
  }
}

/** The change `operation` makes to `host`; null when the host already is as asked. */
function inputFor(access: Access, host: ProxyHost, operation: BulkOperation): Partial<ProxyHostInput> | null {
  switch (operation.type) {
    case "enable":
    case "disable": {
      const enabled = operation.type === "enable";
      return host.enabled === enabled ? null : { enabled };
    }
    case "waf_block":
      return hostModeOf(host.waf) === "block" ? null : { waf: withHostMode(host.waf, "block") };
    case "add_tag": {
      if (host.tags.includes(operation.tag)) return null;
      const tags = tagsForWrite(access, "proxy_hosts", [...host.tags, operation.tag], host.tags);
      return tags ? { tags } : null;
    }
    case "delete":
      return {};
  }
}

function failureMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return message.trim().slice(0, 300) || "The change failed.";
}

export async function bulkProxyHostsAction(rawIds: unknown, rawOperation: unknown): Promise<BulkResult> {
  const session = await requirePermission("proxy_hosts:write");
  const userId = Number(session.user.id);
  const access = session.access;
  let ids: number[];
  let operation: BulkOperation;
  try {
    ids = readIds(rawIds);
    operation = readOperation(rawOperation);
  } catch (error) {
    return { ok: false, changed: 0, submitted: 0, unchanged: 0, failed: [], message: failureMessage(error) };
  }

  const failed: BulkResult["failed"] = [];
  const toApply: { host: ProxyHost; input: Partial<ProxyHostInput> }[] = [];
  let submitted = 0;
  let unchanged = 0;

  // Checks and approvals first, outside the batch, so change requests are recorded as usual.
  for (const id of ids) {
    let host: ProxyHost | null = null;
    try {
      // 404 for a host outside the role's tag scope, as for a missing one.
      host = await getProxyHostInScope(access, id);
      const input = inputFor(access, host, operation);
      if (input === null) {
        unchanged++;
        continue;
      }
      const isDelete = operation.type === "delete";
      if (!isDelete) await assertProxyHostWriteAllowed(access, input, host);
      const gate = await gateHostChange({
        access,
        change: { targetType: "proxy_host", kind: isDelete ? "delete" : "update", target: host, input: isDelete ? {} : { host: input } },
      });
      if (gate) {
        submitted++;
        continue;
      }
      toApply.push({ host, input });
    } catch (error) {
      failed.push({ id, name: host?.name ?? null, message: failureMessage(error) });
    }
  }

  const done: { host: ProxyHost; input: Partial<ProxyHostInput> }[] = [];
  let applyError: string | null = null;
  let undone = false;
  if (toApply.length > 0) {
    const acceptedBefore = await caddyAcceptedLastApply();
    const { applyRequested, undo } = await runAsChangeBatch(async () => {
      for (const item of toApply) {
        try {
          if (operation.type === "delete") await deleteProxyHost(item.host.id, userId);
          else await updateProxyHost(item.host.id, item.input, userId);
          done.push(item);
        } catch (error) {
          failed.push({ id: item.host.id, name: item.host.name, message: failureMessage(error) });
        }
      }
    });
    // One audit event per host, recorded before the apply so each links to the version it produced.
    for (const { host, input } of done) {
      if (operation.type === "delete") {
        await logAuditEvent({
          userId,
          action: "delete",
          entityType: "proxy_host",
          entityId: host.id,
          summary: `Deleted proxy host ${host.name}`,
        });
      } else {
        await logAuditEvent({ userId, action: "update", entityType: "proxy_host", entityId: host.id, summary: `Updated proxy host ${host.name}`, data: input });
      }
    }
    if (applyRequested) {
      // A configuration Caddy rejects is not kept: the hosts go back to what they were (rejected-apply.ts).
      const failure = await applyBatchOrUndo({ actorUserId: userId, acceptedBefore, undo });
      if (failure) {
        applyError = failure.message;
        undone = failure.undone;
      }
    }
  }

  revalidatePath("/proxy-hosts");
  if (submitted > 0) revalidatePath("/approvals");

  const parts: string[] = [];
  if (done.length > 0 && !undone) parts.push(`${DONE_TEXT[operation.type]} ${plural(done.length, "host")}.`);
  if (submitted > 0) parts.push(`${plural(submitted, "change")} submitted for approval.`);
  if (unchanged > 0) parts.push(`${plural(unchanged, "host")} already ${unchanged === 1 ? "was" : "were"} as asked.`);
  if (failed.length > 0) parts.push(`${plural(failed.length, "host")} could not be changed: ${failed.map((f) => `${f.name ?? `#${f.id}`} (${f.message})`).join("; ")}.`);
  if (applyError) parts.push(undone ? applyError : `The changes are saved, but Caddy did not take the new configuration: ${applyError}`);
  return {
    ok: failed.length === 0 && applyError === null,
    changed: undone ? 0 : done.length,
    submitted,
    unchanged,
    failed,
    message: parts.join(" ") || "Nothing to change.",
  };
}
