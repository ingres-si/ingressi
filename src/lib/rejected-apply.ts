/**
 * Undoing a host change Caddy refuses.
 *
 * Caddy takes the configuration as one document, and every apply rebuilds it
 * from all hosts. A stored change that Caddy refuses would therefore make
 * every later apply fail, for every host, until somebody finds and fixes it.
 * Input validation (caddy-input-validation.ts) refuses what is known to be
 * malformed; this is the net under it: when Caddy rejects the configuration
 * right after a host is created or updated, the change is taken back and the
 * previous configuration applied again, so one writer cannot stop everybody
 * else's changes from going live.
 *
 * The change that is taken back is the one that turned an accepted
 * configuration into a rejected one, which is not always the one at fault:
 * a setting Caddy only reads once a host needs it (the ACME contact, say) is
 * accepted while nothing uses it, and then every host that would use it is
 * refused until the setting is corrected. The message therefore speaks of
 * the configuration with the change and adds where Caddy stopped
 * (locateCaddyRejection in caddy-apply-error.ts), which names that setting.
 * Caddy's own reason is never quoted: it can contain the whole configuration.
 *
 * One case keeps the change ("saved, but not live yet"): an administrator
 * writing while Caddy was already refusing the configuration. The cause is
 * then somewhere else, and undoing each step would keep an administrator
 * from repairing a configuration that is broken in more than one place.
 */
import { eq } from "drizzle-orm";
import { appDb } from "./db";
import { users } from "./db/schema";
import { first } from "./db/ops";
import { applyCaddyConfig } from "./caddy";
import { CaddyApplyError, caddyRejectionDetail } from "./caddy-apply-error";
import { getCaddyApplyStatus } from "./caddy-apply-status";
import { ApiConflictError, ApiValidationError } from "./api-errors";
import { registerBatchUndo } from "./change-batch";

/** Whether Caddy took the configuration at the last apply. Read before the change is stored. */
export async function caddyAcceptedLastApply(): Promise<boolean> {
  try {
    return (await getCaddyApplyStatus())?.ok === true;
  } catch {
    return false;
  }
}

async function isAdministrator(userId: number): Promise<boolean> {
  const row = await first(appDb.select({ role: users.role }).from(users).where(eq(users.id, userId)).limit(1));
  return row?.role === "admin";
}

/**
 * Applies the configuration after a stored host change. When Caddy rejects
 * it, runs `undo` (which puts the stored data back as it was), applies again
 * and throws an error saying the change was not saved; see the file comment
 * for the one case where the change stays and the CaddyApplyError is thrown
 * as it is. Any other apply failure (Caddy unreachable, instance sync) leaves
 * the change stored, as before.
 */
export async function applyOrUndo(options: {
  actorUserId: number;
  /** caddyAcceptedLastApply(), read before the change was stored. */
  acceptedBefore: boolean;
  /** What was being saved, for the message: "proxy host", "L4 host", or "changes" for several. */
  what: string;
  undo: () => Promise<void>;
}): Promise<void> {
  // Inside a change batch the apply comes at the end of the batch: the undo goes with it (applyBatchOrUndo).
  if (registerBatchUndo(options.undo)) {
    await applyCaddyConfig();
    return;
  }
  try {
    await applyCaddyConfig();
    return;
  } catch (error) {
    if (!(error instanceof CaddyApplyError) || error.code !== "CADDY_REJECTED") throw error;
    const administrator = await isAdministrator(options.actorUserId);
    if (!options.acceptedBefore && administrator) {
      // An administrator repairing a broken configuration is told which host Caddy stopped at.
      if (error.rejectedAt) error.message = `${error.message} (${error.rejectedAt})`;
      throw error;
    }

    await options.undo();
    try {
      await applyCaddyConfig();
    } catch (reapplyError) {
      const code = reapplyError instanceof CaddyApplyError ? reapplyError.code : "unknown";
      console.error(`[caddy] Applying the configuration again after undoing a rejected ${options.what} change failed (${code})`);
    }
    const subject = options.what === "changes" ? "the changes were" : `the ${options.what} was`;
    if (options.acceptedBefore) {
      // Which host Caddy stopped at is for administrators: it can be one outside the writer's tag scope.
      const detail = caddyRejectionDetail(error, { withHost: administrator });
      throw new ApiValidationError(
        `Caddy did not accept the configuration with this change, so ${subject} not saved${detail ? `: ${detail}` : ""}`
      );
    }
    throw new ApiConflictError(
      `Caddy is not accepting the configuration at the moment, so ${subject} not saved. An administrator has to repair the configuration first.`
    );
  }
}

/**
 * The apply at the end of a change batch (runAsChangeBatch), with the same
 * rule as applyOrUndo: when Caddy rejects the configuration, the batch's
 * changes are taken back with `undo` and the previous configuration applied
 * again. Returns null when Caddy took the configuration, otherwise what to
 * tell the user and whether the changes were taken back.
 */
export async function applyBatchOrUndo(options: {
  actorUserId: number;
  /** caddyAcceptedLastApply(), read before the batch ran. */
  acceptedBefore: boolean;
  /** The `undo` runAsChangeBatch returned; null when the batch has nothing to take back. */
  undo: (() => Promise<void>) | null;
}): Promise<{ message: string; undone: boolean } | null> {
  try {
    if (options.undo) await applyOrUndo({ ...options, undo: options.undo, what: "changes" });
    else await applyCaddyConfig();
    return null;
  } catch (error) {
    const message = (error instanceof Error ? error.message : "").trim().slice(0, 300) || "The apply failed.";
    return { message, undone: error instanceof ApiValidationError || error instanceof ApiConflictError };
  }
}
