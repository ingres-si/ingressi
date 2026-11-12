/**
 * Taking back settings Caddy refuses.
 *
 * Global settings end in the one document Caddy takes or rejects as a whole,
 * so a stored value Caddy refuses would make every later apply fail, for
 * every host. The REST route rolls such a change back itself; this does the
 * same around a dashboard settings action: when an apply made inside the
 * action is rejected, the settings the action changed are put back, the
 * previous configuration is applied again and the action answers that
 * nothing was saved.
 *
 * As with hosts (rejected-apply.ts), settings stay as saved when Caddy was
 * already refusing the configuration before: the cause is then elsewhere,
 * and the settings page is where an administrator repairs it.
 */
import { isDeepStrictEqual } from "node:util";
import { applyCaddyConfig } from "./caddy";
import { CaddyApplyError, caddyRejectionDetail } from "./caddy-apply-error";
import { observeCaddyRejection } from "./apply-observer";
import { getCaddyApplyStatus } from "./caddy-apply-status";
import { inArray } from "drizzle-orm";
import { appDb } from "./db";
import { settings } from "./db/schema";
import { clearSetting, setSetting } from "./settings";
import { readGlobalWafExclusionRows, restoreGlobalWafExclusionRows } from "./models/waf-exclusion-mirror";

/**
 * The settings rows the Caddy configuration is built from. All of them are
 * written under the settings update lock only, which the caller holds, so
 * putting them back cannot overwrite somebody else's change.
 */
const CADDY_SETTING_KEYS = [
  "general",
  "acme",
  "cloudflare",
  "authentik",
  "forward_auth",
  "metrics",
  "logging",
  "dns",
  "dns_provider",
  "upstream_dns_resolution",
  "geoblock",
  "waf",
  "error_pages",
  "default_response",
  "response_headers",
  "trusted_proxies",
  "rate_limit",
] as const;

/** The stored rows as they are, read at once: the action waits for this before it saves anything. */
async function snapshot() {
  const [rows, exclusions] = await Promise.all([
    appDb.select({ key: settings.key, value: settings.value }).from(settings).where(inArray(settings.key, [...CADDY_SETTING_KEYS])),
    readGlobalWafExclusionRows(),
  ]);
  return { values: new Map(rows.map((row) => [row.key, row.value])), exclusions };
}

/**
 * Runs a settings action (under the settings update lock). When Caddy
 * rejects the configuration inside it, puts the settings back as they were
 * and returns `rejected(message)` in place of the action's own answer.
 */
export async function undoSettingsCaddyRejects<T>(action: () => Promise<T>, rejected: (message: string) => T): Promise<T> {
  let before: Awaited<ReturnType<typeof snapshot>> | null = null;
  try {
    const [status, stored] = await Promise.all([getCaddyApplyStatus(), snapshot()]);
    if (status?.ok === true) before = stored;
  } catch {
    // Unknown: the action runs as it always did.
  }
  if (!before) return await action();

  // A rejection is seen even when the action catches the error and answers "saved, but not applied".
  const { result, rejection } = await observeCaddyRejection(action);
  if (!rejection) return result;

  const after = await snapshot();
  let restored = false;
  for (const key of CADDY_SETTING_KEYS) {
    const previous = before.values.get(key) ?? null;
    if (previous === (after.values.get(key) ?? null)) continue;
    if (previous === null) await clearSetting(key);
    else await setSetting(key, JSON.parse(previous));
    restored = true;
  }
  if (!isDeepStrictEqual(before.exclusions, after.exclusions)) {
    await restoreGlobalWafExclusionRows(before.exclusions);
    restored = true;
  }
  // Nothing of this action's is in the way: its answer stands.
  if (!restored) return result;

  try {
    await applyCaddyConfig();
  } catch (error) {
    const code = error instanceof CaddyApplyError ? error.code : "unknown";
    console.error(`[caddy] Applying the configuration again after undoing rejected settings failed (${code})`);
  }
  // Settings are instance-wide, so whoever writes them may be told which host Caddy stopped at.
  const detail = caddyRejectionDetail(rejection, { withHost: true });
  return rejected(`Caddy did not accept these settings, so they were not saved${detail ? `: ${detail}` : ""}`);
}
