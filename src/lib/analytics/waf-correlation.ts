/**
 * Which access log lines are requests the WAF interrupted, and by which rule.
 *
 * Coraza logs an interruption with its server-generated `unique_id`. The
 * enclosing log_append handler evaluates {http.transaction_id} on the way
 * out (including errors), putting that same ID in the access log. Matching
 * client/Host/URI/time is unsafe: concurrent successful and interrupted
 * requests can have identical values (issue #397). Coraza writes its WAF
 * records before Caddy writes the completed request's access
 * log line. log-parser.ts reads the access log first and waf-rules.log right
 * after, so every interrupted request it reads has its violation in hand;
 * violations whose access log line is not written yet are carried to the next
 * pass (pruneWafCorrelation bounds how long).
 */
import { extractBracketField, ruleInfoFromMessage } from '../waf-log-parser';

export const WAF_VIOLATION_MESSAGE = 'WAF rule violation detected';
/** How long unmatched violations and rule ids are carried across passes. */
const CARRYOVER_SEC = 180;
const MAX_TRACKED = 50_000;

type Violation = { ts: number; uniqueId: string };

export type WafCorrelation = {
  /** Server-generated transaction ID → interruption not yet matched. */
  violations: Map<string, Violation>;
  /** Transaction id → first specific rule that matched, with when it was seen. */
  rules: Map<string, { ruleId: number; ts: number }>;
};

export function createWafCorrelation(): WafCorrelation {
  return { violations: new Map(), rules: new Map() };
}

function transactionId(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 ? value : null;
}

function size(correlation: WafCorrelation): number {
  return correlation.rules.size + correlation.violations.size;
}

/** Adds the violations and rule matches of waf-rules.log `lines` to `into`. */
export function collectWafLogLines(lines: string[], into: WafCorrelation = createWafCorrelation()): WafCorrelation {
  for (const line of lines) {
    if (size(into) >= MAX_TRACKED) break;
    let entry: { msg?: unknown; ts?: unknown; unique_id?: unknown };
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (!entry || typeof entry !== 'object' || typeof entry.msg !== 'string') continue;
    const ts = typeof entry.ts === 'number' && Number.isFinite(entry.ts) ? entry.ts : Date.now() / 1000;
    if (entry.msg === WAF_VIOLATION_MESSAGE) {
      const uniqueId = transactionId(entry.unique_id);
      if (uniqueId && !into.violations.has(uniqueId)) into.violations.set(uniqueId, { ts, uniqueId });
      continue;
    }
    const uniqueId = transactionId(extractBracketField(entry.msg, 'unique_id'));
    if (!uniqueId || into.rules.has(uniqueId)) continue;
    const info = ruleInfoFromMessage(entry.msg);
    if (info?.ruleId != null && Number.isInteger(info.ruleId) && info.ruleId > 0) {
      into.rules.set(uniqueId, { ruleId: info.ruleId, ts });
    }
  }
  return into;
}

/**
 * Consumes the violation of the request an access log line describes, if the
 * WAF interrupted it, and returns the rule that matched (0 when unknown).
 */
export function consumeWafViolation(
  correlation: WafCorrelation | undefined,
  loggedTransactionId: unknown
): { ruleId: number } | null {
  if (!correlation) return null;
  const id = transactionId(loggedTransactionId);
  // No heuristic fallback for legacy/malformed rows. In particular, never
  // borrow a nearby interruption to claim a successful request was blocked.
  if (!id || !correlation.violations.has(id)) return null;
  correlation.violations.delete(id);
  const ruleId = correlation.rules.get(id)?.ruleId ?? 0;
  correlation.rules.delete(id);
  return { ruleId };
}

/** Drops violations and rule ids older than the carry-over window. */
export function pruneWafCorrelation(correlation: WafCorrelation, refTs: number): WafCorrelation {
  const cutoff = refTs - CARRYOVER_SEC;
  for (const [key, violation] of correlation.violations) {
    if (violation.ts < cutoff) correlation.violations.delete(key);
  }
  for (const [id, rule] of correlation.rules) {
    if (rule.ts < cutoff) correlation.rules.delete(id);
  }
  return correlation;
}
