/**
 * Change batches: run many model writes as one change.
 *
 * Model functions (createProxyHost, createAccessList, ...) each apply the
 * Caddy configuration and record an audit event. A bulk operation such as
 * the proxy host list's bulk actions calls them through runAsChangeBatch so
 * that all their validation still applies, but Caddy is applied once at the
 * end and the batch records one audit event summarising it.
 *
 * Inside a batch, applyCaddyConfig() only notes that an apply is needed and
 * logAuditEvent() records nothing. The scope follows the async call chain
 * (AsyncLocalStorage), so concurrent requests are not affected. The caller
 * must apply the configuration and log its own audit event after the batch.
 */
import { AsyncLocalStorage } from "node:async_hooks";

type ChangeBatchState = { applyRequested: boolean; undos: (() => Promise<void>)[] };

const batchGlobal = globalThis as typeof globalThis & {
  __ingressiChangeBatchStorage?: AsyncLocalStorage<ChangeBatchState>;
};
const storage = (batchGlobal.__ingressiChangeBatchStorage ??= new AsyncLocalStorage<ChangeBatchState>());

/**
 * Runs `operation` as a change batch; reports whether anything in it asked
 * for a Caddy apply. `undo` takes back the batch's changes that can be taken
 * back (see registerBatchUndo), latest first, and is null when there are
 * none (deletions): for the caller's apply, when Caddy rejects the
 * configuration (applyBatchOrUndo in rejected-apply.ts).
 */
export async function runAsChangeBatch<T>(
  operation: () => Promise<T>
): Promise<{ result: T; applyRequested: boolean; undo: (() => Promise<void>) | null }> {
  const state: ChangeBatchState = { applyRequested: false, undos: [] };
  const result = await storage.run(state, operation);
  const steps = [...state.undos].reverse();
  const undo = async () => {
    for (const step of steps) await step();
  };
  return { result, applyRequested: state.applyRequested, undo: steps.length > 0 ? undo : null };
}

/**
 * Inside a change batch, keeps how to take a stored change back, for the
 * batch's own apply, and returns true. False outside a batch.
 */
export function registerBatchUndo(undo: () => Promise<void>): boolean {
  const state = storage.getStore();
  if (!state) return false;
  state.undos.push(undo);
  return true;
}

/** True inside a change batch. */
export function inChangeBatch(): boolean {
  return storage.getStore() !== undefined;
}

/**
 * Called first by applyCaddyConfig: inside a change batch it records the
 * request and returns true, and the caller skips the apply.
 */
export function deferCaddyApplyToBatch(): boolean {
  const state = storage.getStore();
  if (!state) return false;
  state.applyRequested = true;
  return true;
}
