/**
 * Lets a caller learn that Caddy rejected the configuration during an
 * operation, even when the operation catches the apply error itself and
 * answers "saved, but not applied" (settings-rollback.ts). The scope follows
 * the async call chain, so concurrent requests do not see each other.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { CaddyApplyError } from "./caddy-apply-error";

type Observation = { rejection: CaddyApplyError | null };

const observerGlobal = globalThis as typeof globalThis & {
  __ingressiApplyObserver?: AsyncLocalStorage<Observation>;
};
const storage = (observerGlobal.__ingressiApplyObserver ??= new AsyncLocalStorage<Observation>());

/** Runs `operation` and reports the last rejection by Caddy of an apply made inside it, or null. */
export async function observeCaddyRejection<T>(operation: () => Promise<T>): Promise<{ result: T; rejection: CaddyApplyError | null }> {
  const state: Observation = { rejection: null };
  const result = await storage.run(state, operation);
  return { result, rejection: state.rejection };
}

/** Called by applyCaddyConfig with every error it throws. */
export function noteCaddyApplyFailure(error: unknown): void {
  const state = storage.getStore();
  if (state && error instanceof CaddyApplyError && error.code === "CADDY_REJECTED") state.rejection = error;
}
