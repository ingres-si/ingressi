"use server";

/**
 * Bulk actions of the L4 hosts list: enable, disable or delete several hosts
 * at once. Each host goes through the same checks as a change to one host
 * (the role's tag scope, change approval policies), and a host a policy
 * protects gets a change request instead. The hosts changed at once are
 * written in one change batch and Caddy is applied once at the end; each
 * still gets its own audit event, as a change to one host does.
 */
import { revalidatePath } from "next/cache";
import { requirePermission } from "@/src/lib/auth";
import { getL4ProxyHostInScope } from "@/src/lib/access-scope";
import { deleteL4ProxyHost, updateL4ProxyHost, type L4ProxyHost } from "@/src/lib/models/l4-proxy-hosts";
import { runAsChangeBatch } from "@/src/lib/change-batch";
import { applyBatchOrUndo, caddyAcceptedLastApply } from "@/src/lib/rejected-apply";
import { logAuditEvent } from "@/src/lib/audit";
import { gateHostChange } from "@/ee/approvals/requests";

export type L4BulkOperation = { type: "enable" } | { type: "disable" } | { type: "delete" };

export type L4BulkResult = {
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

const DONE_TEXT: Record<L4BulkOperation["type"], string> = {
  enable: "Enabled",
  disable: "Disabled",
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
  if (!ids.every((id): id is number => typeof id === "number" && Number.isSafeInteger(id) && id > 0)) throw new Error("Unknown L4 proxy host.");
  return ids;
}

function readOperation(value: unknown): L4BulkOperation {
  const type = value && typeof value === "object" ? (value as Record<string, unknown>).type : undefined;
  if (type === "enable" || type === "disable" || type === "delete") return { type };
  throw new Error("Unknown bulk action.");
}

function failureMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return message.trim().slice(0, 300) || "The change failed.";
}

export async function bulkL4ProxyHostsAction(rawIds: unknown, rawOperation: unknown): Promise<L4BulkResult> {
  const session = await requirePermission("l4_proxy_hosts:write");
  const userId = Number(session.user.id);
  const access = session.access;
  let ids: number[];
  let operation: L4BulkOperation;
  try {
    ids = readIds(rawIds);
    operation = readOperation(rawOperation);
  } catch (error) {
    return { ok: false, changed: 0, submitted: 0, unchanged: 0, failed: [], message: failureMessage(error) };
  }
  const isDelete = operation.type === "delete";
  const enabled = operation.type === "enable";

  const failed: L4BulkResult["failed"] = [];
  const toApply: L4ProxyHost[] = [];
  let submitted = 0;
  let unchanged = 0;

  // Checks and approvals first, outside the batch, so change requests are recorded as usual.
  for (const id of ids) {
    let host: L4ProxyHost | null = null;
    try {
      // 404 for a host outside the role's tag scope, as for a missing one.
      host = await getL4ProxyHostInScope(access, id);
      if (!isDelete && host.enabled === enabled) {
        unchanged++;
        continue;
      }
      const gate = await gateHostChange({
        access,
        change: isDelete
          ? { targetType: "l4_proxy_host", kind: "delete", target: host, input: {} }
          : { targetType: "l4_proxy_host", kind: "update", target: host, input: { host: { enabled } } },
      });
      if (gate) {
        submitted++;
        continue;
      }
      toApply.push(host);
    } catch (error) {
      failed.push({ id, name: host?.name ?? null, message: failureMessage(error) });
    }
  }

  const done: L4ProxyHost[] = [];
  let applyError: string | null = null;
  let undone = false;
  if (toApply.length > 0) {
    const acceptedBefore = await caddyAcceptedLastApply();
    const { applyRequested, undo } = await runAsChangeBatch(async () => {
      for (const host of toApply) {
        try {
          if (isDelete) await deleteL4ProxyHost(host.id, userId);
          else await updateL4ProxyHost(host.id, { enabled }, userId);
          done.push(host);
        } catch (error) {
          failed.push({ id: host.id, name: host.name, message: failureMessage(error) });
        }
      }
    });
    // One audit event per host, recorded before the apply so each links to the version it produced.
    for (const host of done) {
      if (isDelete) {
        await logAuditEvent({ userId, action: "delete", entityType: "l4_proxy_host", entityId: host.id, summary: `Deleted L4 proxy host ${host.name}` });
      } else {
        await logAuditEvent({
          userId,
          action: "update",
          entityType: "l4_proxy_host",
          entityId: host.id,
          summary: `Updated L4 proxy host ${host.name}`,
          data: { enabled },
        });
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

  revalidatePath("/l4-proxy-hosts");
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
