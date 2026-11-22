// SPDX-License-Identifier: Elastic-2.0
/**
 * Plain-language analytics questions (AI analyst, ee): shared types and the
 * vocabulary of the structured query. Safe to import from client components
 * (no server-only dependencies).
 *
 * The configured model turns a question into a QuestionQuery; the server
 * validates it against these lists (schema.ts) and runs it through the
 * analytics query layer (run.ts). The model never writes SQL.
 */

// ── Vocabulary ────────────────────────────────────────────────────────

/** What is counted. The same metrics as the analytics page. */
export const QUESTION_METRICS = ["requests", "mitigated", "errors", "bytes", "visitors"] as const;
export type QuestionMetric = (typeof QUESTION_METRICS)[number];

/** Dimensions a question can filter on or rank. The analytics dimensions. */
export const QUESTION_DIMENSIONS = [
  "host",
  "path",
  "country",
  "asn",
  "status",
  "method",
  "protocol",
  "ip",
  "user_agent",
  "outcome",
  "waf_rule",
] as const;
export type QuestionDimension = (typeof QUESTION_DIMENSIONS)[number];

/** "none": one total; "time": the metric over time; a dimension: its values ranked.
 * "waf_rule" is scoped to WAF-blocked requests, including the total and shares. */
export const QUESTION_BREAKDOWNS = ["none", "time", ...QUESTION_DIMENSIONS] as const;
export type QuestionBreakdown = (typeof QUESTION_BREAKDOWNS)[number];

export const QUESTION_RANGE_PRESETS = ["1h", "24h", "7d", "30d"] as const;
export type QuestionRangePreset = (typeof QUESTION_RANGE_PRESETS)[number];

export const QUESTION_COMPARISONS = ["none", "previous_period"] as const;
export type QuestionComparison = (typeof QUESTION_COMPARISONS)[number];

export const QUESTION_OUTCOMES = ["served", "waf", "geo", "access", "auth", "rate_limit"] as const;

/**
 * Dimensions whose values describe a client or a request rather than an
 * aggregate (client addresses, user agents, paths). Their values reach the
 * model only when the question needs them and the settings allow it.
 */
export const REQUEST_DETAIL_DIMENSIONS: readonly QuestionDimension[] = ["ip", "user_agent", "path"];

export const MAX_QUESTION_LENGTH = 500;
export const MAX_QUESTION_FILTERS = 10;
export const MAX_QUESTION_TAGS = 5;
export const MAX_QUESTION_LIMIT = 50;
export const DEFAULT_QUESTION_LIMIT = 10;
/** Questions per user: 10 per 10 minutes and 100 per day, one at a time. */
export const QUESTION_RATE_LIMITS = {
  short: { maxQuestions: 10, windowMs: 10 * 60_000 },
  daily: { maxQuestions: 100, windowMs: 24 * 60 * 60_000 },
} as const;
/** Longest range a question covers (as the analytics page). */
export const MAX_QUESTION_RANGE_DAYS = 92;
/** Longest "last N minutes" range: a day (longer periods are presets or dates). */
export const MAX_QUESTION_RANGE_MINUTES = 1440;

export type QuestionFilter = { dim: QuestionDimension; op: "is" | "is_not"; value: string };

/** A range ending now, or calendar dates in UTC (both inclusive; "now" as the end). */
export type QuestionRange = { preset: QuestionRangePreset } | { minutes: number } | { from: string; to: string };

/** The structured query: everything a question can ask for, nothing else. */
export type QuestionQuery = {
  metric: QuestionMetric;
  breakdown: QuestionBreakdown;
  filters: QuestionFilter[];
  /** Proxy host tags ("the shop hosts"); the hosts the asker can see that carry one of them. */
  hostTags: string[];
  range: QuestionRange;
  comparison: QuestionComparison;
  /** Values a breakdown lists. */
  limit: number;
};

// ── Labels ────────────────────────────────────────────────────────────

export const QUESTION_METRIC_LABELS: Record<QuestionMetric, string> = {
  requests: "Requests",
  mitigated: "Mitigated requests",
  errors: "Error responses (4xx and 5xx)",
  bytes: "Bytes sent",
  visitors: "Unique client addresses",
};

export const QUESTION_DIMENSION_LABELS: Record<QuestionDimension, string> = {
  host: "host",
  path: "path",
  country: "country",
  asn: "network (ASN)",
  status: "status code",
  method: "method",
  protocol: "HTTP version",
  ip: "client address",
  user_agent: "user agent",
  outcome: "outcome",
  waf_rule: "WAF rule",
};

// ── Answers ───────────────────────────────────────────────────────────

/**
 * answered: the query ran (result set). clarify: the question is ambiguous;
 * `message` asks back. unsupported: traffic data cannot answer it, or the
 * model's interpretation was refused by the validation (nothing ran).
 */
export type QuestionAnswerStatus = "answered" | "clarify" | "unsupported";

export type QuestionResultRow = {
  value: string;
  /** A readable name for the value (an AS organisation, a WAF rule message, an outcome), when there is one. */
  label: string | null;
  count: number;
  /** Share of the total, 0 to 1. */
  share: number;
  /** Same value in the previous period, with a comparison. */
  previous: number | null;
  /** Relative change from the previous period; null without one or from zero. */
  change: number | null;
};

export type QuestionResult = {
  /** ok: from ClickHouse; disabled: analytics is off; unavailable: ClickHouse did not answer. */
  status: "ok" | "disabled" | "unavailable";
  kind: "total" | "series" | "breakdown";
  metric: QuestionMetric;
  breakdown: QuestionBreakdown;
  unit: "count" | "bytes";
  /** The period (Unix seconds, end exclusive) and its buckets. */
  range: { start: number; end: number; step: number; buckets: number };
  /** The period compared with, when the query asks for a comparison. */
  previous: { start: number; end: number; available: boolean } | null;
  /** The metric over the whole period (for visitors: distinct addresses in it). */
  total: number;
  previousTotal: number | null;
  change: number | null;
  /** Breakdown rows, largest first. */
  rows: QuestionResultRow[];
  /** Distinct values of the breakdown (approximate for large sets). */
  distinct: number | null;
  /** Series: one value per bucket, and the previous period's, bucket by bucket. */
  series: { values: number[]; previous: number[] | null } | null;
  peak: { ts: number; value: number } | null;
  /** Host tags the query was limited to, and how many stored host names they matched. */
  scope: { hostTags: string[]; hostNames: number } | null;
  notes: string[];
};

/** What went to the AI provider for one answer. */
export type QuestionPrivacy = {
  provider: string;
  model: string;
  /** The interpretation call: the question and the query schema, always. */
  interpretation: true;
  /** The summary call: the question, the query in words and the aggregated result. */
  summary: boolean;
  /** Client addresses, user agents or paths were sent as they are (otherwise as placeholders, or not at all). */
  requestDetails: boolean;
  /** Plain-language description for the page. */
  description: string;
};

export type QuestionSummary = {
  text: string;
  /** "ai": written by the model from the aggregates; "computed": written by the dashboard. */
  source: "ai" | "computed";
};

export type QuestionAnswer = {
  status: QuestionAnswerStatus;
  question: string;
  /** Clarification or why it cannot be answered. */
  message: string | null;
  /** The validated query that ran (answered), or null. */
  query: QuestionQuery | null;
  /** The query in words: "Mitigated requests by country, 26 Sep–3 Oct 2026, hosts tagged shop". */
  interpretation: string | null;
  /** The same query on the Analytics page, as far as the page can show it. */
  analyticsHref: string | null;
  result: QuestionResult | null;
  summary: QuestionSummary | null;
  /** Why the AI summary is missing, when it was asked for and failed. */
  summaryError: string | null;
  privacy: QuestionPrivacy | null;
  askedAt: string;
};

// ── Saved questions ───────────────────────────────────────────────────

export type SavedQuestionView = {
  id: number;
  question: string;
  query: QuestionQuery;
  interpretation: string;
  shared: boolean;
  /** The caller saved it (and may change it). */
  owned: boolean;
  ownerName: string | null;
  createdAt: string;
  updatedAt: string;
};

// ── Settings ──────────────────────────────────────────────────────────

export type QuestionSettingsView = {
  /** Users with analytics:read may ask questions (when a provider is configured). */
  enabled: boolean;
  /** Ask the model for a summary of the aggregated result; off: the dashboard writes it. */
  aiSummaries: boolean;
  /** Send client addresses, user agents and paths to the model when a question ranks or filters by them. */
  shareRequestDetails: boolean;
};

/** What the Ask box needs to know before the first question. */
export type QuestionAvailability = {
  /** An AI provider is enabled and complete. */
  providerConfigured: boolean;
  /** Questions are turned on in the AI settings. */
  enabled: boolean;
  analyticsEnabled: boolean;
  /** Provider and model, for the privacy note. */
  provider: { name: string; model: string } | null;
  settings: QuestionSettingsView;
};
