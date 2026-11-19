// SPDX-License-Identifier: Elastic-2.0
/**
 * Plain-language analytics questions: the strict validation of a structured
 * query and of the model's answer. Everything the model returns passes
 * through here before anything runs:
 *
 *  - every object is checked for unknown keys (an extra "sql" key, or
 *    "__proto__", is refused, not ignored);
 *  - metric, breakdown, filter dimension, operator, range preset and
 *    comparison come from fixed lists (types.ts) and pick constant SQL in the
 *    analytics layer (src/lib/analytics/dimensions.ts);
 *  - filter values are validated for their dimension exactly as the
 *    analytics API validates them, and later reach ClickHouse only as bound
 *    parameters;
 *  - sizes are bounded (filters, tags, limit, text lengths, range).
 *
 * The same validation applies to queries a client sends to save a question.
 */
import { ApiValidationError } from "@/src/lib/api-errors";
import { DIMENSION_SPECS } from "@/src/lib/analytics/dimensions";
import { isValidTag } from "@/src/lib/host-tags";
import {
  MAX_QUESTION_RANGE_MINUTES,
  DEFAULT_QUESTION_LIMIT,
  MAX_QUESTION_FILTERS,
  MAX_QUESTION_LENGTH,
  MAX_QUESTION_LIMIT,
  MAX_QUESTION_TAGS,
  QUESTION_BREAKDOWNS,
  QUESTION_COMPARISONS,
  QUESTION_DIMENSIONS,
  QUESTION_METRICS,
  QUESTION_RANGE_PRESETS,
  type QuestionBreakdown,
  type QuestionComparison,
  type QuestionDimension,
  type QuestionFilter,
  type QuestionMetric,
  type QuestionQuery,
  type QuestionRange,
  type QuestionRangePreset,
} from "./types";

const QUERY_KEYS = ["metric", "breakdown", "filters", "hostTags", "range", "comparison", "limit"] as const;
const FILTER_KEYS = ["dim", "op", "value"] as const;
const MAX_FILTER_VALUE = 512;
const MAX_MESSAGE_CHARS = 300;
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:?\d{2})$/i;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function requireObject(value: unknown, what: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new ApiValidationError(`${what} must be a JSON object`);
  return value;
}

function rejectUnknownKeys(record: Record<string, unknown>, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) throw new ApiValidationError(`Unknown field "${key.slice(0, 40)}" in ${what}`);
  }
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  if (typeof value === "string" && (allowed as readonly string[]).includes(value)) return value as T;
  throw new ApiValidationError(`${field} must be one of: ${allowed.join(", ")}`);
}

/** A question as typed: one line, printable, 3 to 500 characters. */
export function parseQuestionText(value: unknown): string {
  if (typeof value !== "string") throw new ApiValidationError("question is required");
  const text = value.replace(/\s+/g, " ").trim();
  if (text.length < 3) throw new ApiValidationError("question is required");
  if (text.length > MAX_QUESTION_LENGTH) throw new ApiValidationError(`question must be at most ${MAX_QUESTION_LENGTH} characters`);
  if (/\p{Cc}/u.test(text)) throw new ApiValidationError("question must not contain control characters");
  return text;
}

/** A filter value as the analytics page stores it: trimmed, country codes and methods in capitals. */
function normalizeValue(dim: QuestionDimension, value: string): string {
  const trimmed = value.trim();
  if (dim === "country" || dim === "method") return trimmed.toUpperCase();
  if (dim === "status") return trimmed.toLowerCase();
  if (dim === "asn") return trimmed.replace(/^AS/i, "");
  return trimmed;
}

function parseFilter(input: unknown, index: number): QuestionFilter {
  const what = `filter ${index + 1}`;
  const record = requireObject(input, what);
  rejectUnknownKeys(record, FILTER_KEYS, what);
  const dim = oneOf(record.dim, QUESTION_DIMENSIONS, `${what}: dim`);
  const op = record.op === undefined ? "is" : oneOf(record.op, ["is", "is_not"] as const, `${what}: op`);
  const raw = typeof record.value === "number" && Number.isFinite(record.value) ? String(record.value) : record.value;
  if (typeof raw !== "string") throw new ApiValidationError(`${what}: value must be a string`);
  if (raw.length > MAX_FILTER_VALUE) throw new ApiValidationError(`${what}: value is longer than ${MAX_FILTER_VALUE} characters`);
  if (/\p{Cc}/u.test(raw)) throw new ApiValidationError(`${what}: value must not contain control characters`);
  const value = normalizeValue(dim, raw);
  if (!value) throw new ApiValidationError(`${what}: value must not be empty`);
  // The analytics layer's own check for the dimension (throws ApiValidationError).
  DIMENSION_SPECS[dim].compare(value);
  return { dim, op, value };
}

function parseFilters(value: unknown): QuestionFilter[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new ApiValidationError("filters must be an array");
  if (value.length > MAX_QUESTION_FILTERS) throw new ApiValidationError(`At most ${MAX_QUESTION_FILTERS} filters`);
  const seen = new Set<string>();
  const filters: QuestionFilter[] = [];
  value.forEach((item, index) => {
    const filter = parseFilter(item, index);
    const key = `${filter.dim}\u0000${filter.op}\u0000${filter.value}`;
    if (seen.has(key)) return;
    seen.add(key);
    filters.push(filter);
  });
  return filters;
}

function parseTags(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new ApiValidationError("hostTags must be an array of tags");
  if (value.length > MAX_QUESTION_TAGS) throw new ApiValidationError(`At most ${MAX_QUESTION_TAGS} host tags`);
  const tags = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string") throw new ApiValidationError("hostTags must be an array of tags");
    const tag = item.trim().toLowerCase();
    if (!isValidTag(tag)) throw new ApiValidationError(`"${tag.slice(0, 40)}" is not a valid host tag`);
    tags.add(tag);
  }
  return [...tags].sort();
}

function parseInstantText(value: unknown, field: string, allowNow: boolean): string {
  if (typeof value !== "string") throw new ApiValidationError(`range.${field} must be a date (YYYY-MM-DD)`);
  const text = value.trim();
  if (allowNow && text.toLowerCase() === "now") return "now";
  if (text.length > 40 || !(DATE_ONLY.test(text) || DATE_TIME.test(text))) {
    throw new ApiValidationError(`range.${field} must be a date (YYYY-MM-DD) or a date-time with a time zone`);
  }
  const ms = Date.parse(DATE_ONLY.test(text) ? `${text}T00:00:00.000Z` : text);
  if (!Number.isFinite(ms)) throw new ApiValidationError(`range.${field} is not a valid date`);
  // Reject dates JavaScript rolls over (2026-02-31).
  if (DATE_ONLY.test(text) && new Date(ms).toISOString().slice(0, 10) !== text) throw new ApiValidationError(`range.${field} is not a valid date`);
  return text;
}

function parseRange(value: unknown): QuestionRange {
  if (value === undefined) return { preset: "24h" };
  if (typeof value === "string") return { preset: oneOf(value, QUESTION_RANGE_PRESETS, "range") };
  const record = requireObject(value, "range");
  if ("preset" in record) {
    rejectUnknownKeys(record, ["preset"], "range");
    return { preset: oneOf<QuestionRangePreset>(record.preset, QUESTION_RANGE_PRESETS, "range.preset") };
  }
  if ("minutes" in record) {
    rejectUnknownKeys(record, ["minutes"], "range");
    const minutes = record.minutes;
    if (typeof minutes !== "number" || !Number.isInteger(minutes) || minutes < 1 || minutes > MAX_QUESTION_RANGE_MINUTES) {
      throw new ApiValidationError(`range.minutes must be a whole number from 1 to ${MAX_QUESTION_RANGE_MINUTES}`);
    }
    return { minutes };
  }
  rejectUnknownKeys(record, ["from", "to"], "range");
  const from = parseInstantText(record.from, "from", false);
  const to = record.to === undefined ? "now" : parseInstantText(record.to, "to", true);
  return { from, to };
}

function parseLimit(value: unknown): number {
  if (value === undefined) return DEFAULT_QUESTION_LIMIT;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_QUESTION_LIMIT) {
    throw new ApiValidationError(`limit must be a whole number from 1 to ${MAX_QUESTION_LIMIT}`);
  }
  return value;
}

/** Breakdowns each metric supports, as the analytics layer can compute them. */
export function breakdownAllowed(metric: QuestionMetric, breakdown: QuestionBreakdown): boolean {
  if (breakdown === "none" || breakdown === "time") return true;
  if (metric === "visitors") return false;
  if (metric === "bytes") return breakdown === "host";
  return true;
}

/**
 * A WAF rule ranks WAF interruptions, not everything a security control
 * stopped. Bind that scope before totals, shares, comparisons and summaries
 * are computed. Saved questions pass here too, so old unscoped queries get
 * the same correction without a data migration.
 *
 * Several positive filters on one dimension are ORed by the analytics API.
 * Never append WAF to an explicitly different outcome: that would broaden
 * the question instead of restricting it.
 */
function scopeWafRules(breakdown: QuestionBreakdown, filters: QuestionFilter[]): QuestionFilter[] {
  if (breakdown !== "waf_rule") return filters;
  const outcomes = filters.filter((filter) => filter.dim === "outcome");
  if (outcomes.some((filter) => filter.op === "is" ? filter.value !== "waf" : filter.value === "waf")) {
    throw new ApiValidationError("A WAF rule breakdown describes WAF-blocked requests only; use an outcome breakdown for other controls");
  }
  if (outcomes.some((filter) => filter.op === "is" && filter.value === "waf")) return filters;
  if (filters.length >= MAX_QUESTION_FILTERS) {
    throw new ApiValidationError(`A WAF rule breakdown needs its WAF outcome filter; use at most ${MAX_QUESTION_FILTERS - 1} other filters`);
  }
  return [...filters, { dim: "outcome", op: "is", value: "waf" }];
}

/**
 * Validates a structured query (throws ApiValidationError). metric,
 * breakdown and range are required; filters, hostTags, comparison and limit
 * default to none, none, "none" and 10.
 */
export function parseQuestionQuery(input: unknown): QuestionQuery {
  const record = requireObject(input, "query");
  rejectUnknownKeys(record, QUERY_KEYS, "the query");
  if (record.metric === undefined) throw new ApiValidationError("query.metric is required");
  if (record.breakdown === undefined) throw new ApiValidationError("query.breakdown is required");
  if (record.range === undefined) throw new ApiValidationError("query.range is required");
  const metric = oneOf<QuestionMetric>(record.metric, QUESTION_METRICS, "metric");
  const breakdown = oneOf<QuestionBreakdown>(record.breakdown, QUESTION_BREAKDOWNS, "breakdown");
  if (!breakdownAllowed(metric, breakdown)) {
    throw new ApiValidationError(
      metric === "bytes"
        ? "Bytes sent can be shown as a total, over time or by host"
        : "Unique client addresses can be shown as a total or over time"
    );
  }
  const comparison = record.comparison === undefined ? "none" : oneOf<QuestionComparison>(record.comparison, QUESTION_COMPARISONS, "comparison");
  return {
    metric,
    breakdown,
    filters: scopeWafRules(breakdown, parseFilters(record.filters)),
    hostTags: parseTags(record.hostTags),
    range: parseRange(record.range),
    comparison,
    limit: parseLimit(record.limit),
  };
}

// ── The model's answer ────────────────────────────────────────────────

export type ModelAnswer =
  | { kind: "query"; query: unknown }
  | { kind: "clarify"; message: string }
  | { kind: "unsupported"; message: string }
  /** Nothing usable: not JSON, not one of the three shapes, or extra keys. */
  | { kind: "invalid"; reason: string };

/** A short, single-line, printable message from the model, or null. */
export function cleanModelMessage(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/\p{Cc}+/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return null;
  return text.length > MAX_MESSAGE_CHARS ? `${text.slice(0, MAX_MESSAGE_CHARS - 1)}…` : text;
}

/**
 * Reads the model's reply: one JSON object (optionally inside a code fence,
 * after a reasoning block) of the shape {"answer":"query","query":{…}},
 * {"answer":"clarify","message":"…"} or {"answer":"unsupported","message":"…"}.
 * The query itself is not validated here (parseQuestionQuery does that).
 */
export function parseModelAnswer(text: string): ModelAnswer {
  const cleaned = text.replace(/<think>[\s\S]*?<\/think>/gi, "");
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start < 0 || end <= start) return { kind: "invalid", reason: "the answer was not JSON" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    return { kind: "invalid", reason: "the answer was not valid JSON" };
  }
  if (!isPlainObject(parsed)) return { kind: "invalid", reason: "the answer was not a JSON object" };
  const answer = parsed.answer;
  if (answer === "query") {
    if (Object.keys(parsed).some((key) => key !== "answer" && key !== "query")) return { kind: "invalid", reason: "the answer had unknown fields" };
    if (!("query" in parsed)) return { kind: "invalid", reason: "the answer had no query" };
    return { kind: "query", query: parsed.query };
  }
  if (answer === "clarify" || answer === "unsupported") {
    if (Object.keys(parsed).some((key) => key !== "answer" && key !== "message")) return { kind: "invalid", reason: "the answer had unknown fields" };
    const message = cleanModelMessage(parsed.message);
    if (answer === "clarify") return { kind: "clarify", message: message ?? "Which hosts, period or measure do you mean?" };
    return { kind: "unsupported", message: message ?? "Traffic data cannot answer that." };
  }
  return { kind: "invalid", reason: "the answer was not a query, a clarification or a refusal" };
}

/** The filters on dimensions whose values describe clients or requests (addresses, user agents, paths). */
export function usesRequestDetails(query: Pick<QuestionQuery, "breakdown" | "filters">, dimensions: readonly QuestionDimension[]): boolean {
  return (dimensions as readonly string[]).includes(query.breakdown) || query.filters.some((filter) => dimensions.includes(filter.dim));
}
