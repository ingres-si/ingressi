// SPDX-License-Identifier: Elastic-2.0
/**
 * OpenAPI paths and schemas of the plain-language analytics questions
 * (ee/ai/questions), spread into app/api/v1/openapi.json/route.ts.
 * Enumerations come from the lists the validation enforces.
 */
import {
  DEFAULT_QUESTION_LIMIT,
  MAX_QUESTION_FILTERS,
  MAX_QUESTION_LENGTH,
  MAX_QUESTION_LIMIT,
  MAX_QUESTION_RANGE_DAYS,
  MAX_QUESTION_RANGE_MINUTES,
  MAX_QUESTION_TAGS,
  QUESTION_BREAKDOWNS,
  QUESTION_COMPARISONS,
  QUESTION_DIMENSIONS,
  QUESTION_METRICS,
  QUESTION_RANGE_PRESETS,
  QUESTION_RATE_LIMITS,
} from "./types";

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: unknown) => ({ "application/json": { schema } });
const errorJson = json({ $ref: "#/components/schemas/Error" });
const errors = (...codes: string[]) => {
  const map: Record<string, unknown> = {
    "400": { $ref: "#/components/responses/BadRequest" },
    "401": { $ref: "#/components/responses/Unauthorized" },
    "403": { $ref: "#/components/responses/Forbidden" },
    "404": { $ref: "#/components/responses/NotFound" },
    "409": { $ref: "#/components/responses/Conflict" },
    "429": { description: "Too many questions, or the previous one is still being answered", content: errorJson },
    "502": { description: "The AI provider failed, timed out or declined to interpret the question", content: errorJson },
  };
  return Object.fromEntries(codes.map((code) => [code, map[code]]));
};
const idParam = { name: "id", in: "path", required: true, schema: { type: "integer", minimum: 1 } };
const ANALYTICS = "Analytics";
const AI = "AI";

export const QUESTIONS_OPENAPI_PATHS = {
  "/api/v1/analytics/questions": {
    post: {
      tags: [ANALYTICS],
      summary: "Ask a question about traffic",
      description:
        `Permission analytics:read. The configured AI provider turns the question into a structured query ` +
        "(AnalyticsQuestionQuery); the query is validated against fixed lists and run here with bound parameters, " +
        "with host tags limited to the proxy hosts the caller's role can see. The model never writes SQL. The provider receives " +
        "the question and the query schema; for the summary, the question, the query in words and the aggregated result, with client " +
        "addresses, user agents and paths as placeholders unless the question ranks or filters by them and the question settings allow " +
        "sending them. status is answered, clarify (an ambiguous question, with a question back) or unsupported (traffic data cannot answer " +
        "it, or the model's reading was refused by the validation; nothing ran). Every question is recorded in the audit log. " +
        `At most ${QUESTION_RATE_LIMITS.short.maxQuestions} questions per ${QUESTION_RATE_LIMITS.short.windowMs / 60_000} minutes and ` +
        `${QUESTION_RATE_LIMITS.daily.maxQuestions} per day per user, one at a time (429). 400 without an AI provider, 409 when questions ` +
        "are turned off in the question settings, 502 when the provider fails.",
      operationId: "askAnalyticsQuestion",
      requestBody: {
        required: true,
        content: json({
          type: "object",
          additionalProperties: false,
          required: ["question"],
          properties: { question: { type: "string", minLength: 3, maxLength: MAX_QUESTION_LENGTH } },
          example: { question: "Which countries were blocked most last week on the shop hosts?" },
        }),
      },
      responses: { "200": { description: "The answer", content: json(ref("AnalyticsQuestionAnswer")) }, ...errors("400", "401", "403", "409", "429", "502") },
    },
  },
  "/api/v1/analytics/questions/saved": {
    get: {
      tags: [ANALYTICS],
      summary: "List saved questions",
      description: "Permission analytics:read. The caller's saved questions and the ones others shared.",
      operationId: "listSavedAnalyticsQuestions",
      responses: { "200": { description: "Saved questions", content: json({ type: "array", items: ref("AnalyticsSavedQuestion") }) }, ...errors("401", "403") },
    },
    post: {
      tags: [ANALYTICS],
      summary: "Save a question",
      description:
        `Permission analytics:read. The query (usually the one an answer returned) is validated again. At most 100 per user (409). ` +
        "Recorded in the audit log.",
      operationId: "createSavedAnalyticsQuestion",
      requestBody: { required: true, content: json(ref("AnalyticsSavedQuestionInput")) },
      responses: { "201": { description: "Saved", content: json(ref("AnalyticsSavedQuestion")) }, ...errors("400", "401", "403", "409") },
    },
  },
  "/api/v1/analytics/questions/saved/{id}": {
    get: {
      tags: [ANALYTICS],
      summary: "Get a saved question",
      operationId: "getSavedAnalyticsQuestion",
      parameters: [idParam],
      responses: { "200": { description: "Saved question", content: json(ref("AnalyticsSavedQuestion")) }, ...errors("400", "401", "403", "404") },
    },
    patch: {
      tags: [ANALYTICS],
      summary: "Change a saved question",
      description: "Only the user who saved it.",
      operationId: "updateSavedAnalyticsQuestion",
      parameters: [idParam],
      requestBody: { required: true, content: json(ref("AnalyticsSavedQuestionInput")) },
      responses: { "200": { description: "Changed", content: json(ref("AnalyticsSavedQuestion")) }, ...errors("400", "401", "403", "404") },
    },
    delete: {
      tags: [ANALYTICS],
      summary: "Delete a saved question",
      description: "The user who saved it, or an administrator for a shared one. Report schedules keep their copies.",
      operationId: "deleteSavedAnalyticsQuestion",
      parameters: [idParam],
      responses: { "204": { description: "Deleted" }, ...errors("400", "401", "403", "404") },
    },
  },
  "/api/v1/analytics/questions/saved/{id}/run": {
    post: {
      tags: [ANALYTICS],
      summary: "Run a saved question again",
      description:
        `Permission analytics:read. Runs the stored query with fresh data (a relative range such as the last 7 days ends now); ` +
        "the model is not asked to interpret it again, only to write the summary when the question settings allow and a provider is configured. " +
        "Same limits and audit as asking.",
      operationId: "runSavedAnalyticsQuestion",
      parameters: [idParam],
      responses: { "200": { description: "The answer", content: json(ref("AnalyticsQuestionAnswer")) }, ...errors("400", "401", "403", "404", "409", "429") },
    },
  },
  "/api/v1/ai/question-settings": {
    get: {
      tags: [AI],
      summary: "Get the analytics question settings",
      description: "Permission ai:read. Not synced to slave instances.",
      operationId: "getAiQuestionSettings",
      responses: { "200": { description: "Settings", content: json(ref("AiQuestionSettings")) }, ...errors("401", "403") },
    },
    put: {
      tags: [AI],
      summary: "Change the analytics question settings",
      description: "Permission ai:write. Partial. Recorded in the audit log.",
      operationId: "updateAiQuestionSettings",
      requestBody: { required: true, content: json(ref("AiQuestionSettings")) },
      responses: { "200": { description: "Saved", content: json(ref("AiQuestionSettings")) }, ...errors("400", "401", "403") },
    },
  },
};

export const QUESTIONS_OPENAPI_SCHEMAS = {
  AnalyticsQuestionFilter: {
    type: "object",
    additionalProperties: false,
    required: ["dim", "value"],
    properties: {
      dim: { type: "string", enum: [...QUESTION_DIMENSIONS] },
      op: { type: "string", enum: ["is", "is_not"], default: "is" },
      value: { type: "string", maxLength: 512, description: "Validated for the dimension as AnalyticsFilter values are" },
    },
  },
  AnalyticsQuestionQuery: {
    type: "object",
    additionalProperties: false,
    required: ["metric", "breakdown", "range"],
    description: "The structured query a question becomes. Unknown fields anywhere are refused.",
    properties: {
      metric: { type: "string", enum: [...QUESTION_METRICS], description: "mitigated: any outcome but served; errors: status 400 and above" },
      breakdown: {
        type: "string",
        enum: [...QUESTION_BREAKDOWNS],
        description: 'none: one total; time: over time; a dimension: its values ranked. bytes allows none, time and host; visitors none and time.',
      },
      filters: {
        type: "array", maxItems: MAX_QUESTION_FILTERS, items: ref("AnalyticsQuestionFilter"),
        description: "A waf_rule breakdown is WAF-only: outcome is waf is added when absent, including for older saved questions. Conflicting outcomes are refused; the added filter counts toward the limit.",
      },
      hostTags: {
        type: "array",
        maxItems: MAX_QUESTION_TAGS,
        items: { type: "string" },
        description: "Proxy host tags: the stored host names of the proxy hosts (that the caller can see) carrying one of them",
      },
      range: {
        oneOf: [
          { type: "object", additionalProperties: false, required: ["preset"], properties: { preset: { type: "string", enum: [...QUESTION_RANGE_PRESETS] } } },
          {
            type: "object",
            additionalProperties: false,
            required: ["minutes"],
            properties: { minutes: { type: "integer", minimum: 1, maximum: MAX_QUESTION_RANGE_MINUTES, description: "The last N minutes, ending now" } },
          },
          {
            type: "object",
            additionalProperties: false,
            required: ["from"],
            properties: {
              from: { type: "string", description: "YYYY-MM-DD (UTC) or a date-time with a time zone" },
              to: { type: "string", description: 'YYYY-MM-DD (that day included), a date-time, or "now" (default)' },
            },
          },
        ],
        description: `At most ${MAX_QUESTION_RANGE_DAYS} days, capped at now`,
      },
      comparison: { type: "string", enum: [...QUESTION_COMPARISONS], default: "none", description: "previous_period: the same length right before" },
      limit: { type: "integer", minimum: 1, maximum: MAX_QUESTION_LIMIT, default: DEFAULT_QUESTION_LIMIT },
    },
  },
  AnalyticsQuestionResult: {
    type: "object",
    properties: {
      status: { type: "string", enum: ["ok", "disabled", "unavailable"] },
      kind: { type: "string", enum: ["total", "series", "breakdown"] },
      metric: { type: "string", enum: [...QUESTION_METRICS] },
      breakdown: { type: "string", enum: [...QUESTION_BREAKDOWNS] },
      unit: { type: "string", enum: ["count", "bytes"] },
      range: { type: "object", properties: { start: { type: "integer" }, end: { type: "integer" }, step: { type: "integer" }, buckets: { type: "integer" } } },
      previous: { type: ["object", "null"], properties: { start: { type: "integer" }, end: { type: "integer" }, available: { type: "boolean" } } },
      total: { type: "number" },
      previousTotal: { type: ["number", "null"] },
      change: { type: ["number", "null"], description: "Relative change from the previous period" },
      rows: {
        type: "array",
        items: {
          type: "object",
          properties: {
            value: { type: "string" },
            label: { type: ["string", "null"] },
            count: { type: "number" },
            share: { type: "number" },
            previous: { type: ["number", "null"] },
            change: { type: ["number", "null"] },
          },
        },
      },
      distinct: { type: ["integer", "null"] },
      series: {
        type: ["object", "null"],
        properties: { values: { type: "array", items: { type: "number" } }, previous: { type: ["array", "null"], items: { type: "number" } } },
      },
      peak: { type: ["object", "null"], properties: { ts: { type: "integer" }, value: { type: "number" } } },
      scope: { type: ["object", "null"], properties: { hostTags: { type: "array", items: { type: "string" } }, hostNames: { type: "integer" } } },
      notes: { type: "array", items: { type: "string" } },
    },
  },
  AnalyticsQuestionAnswer: {
    type: "object",
    properties: {
      status: { type: "string", enum: ["answered", "clarify", "unsupported"] },
      question: { type: "string" },
      message: { type: ["string", "null"], description: "The question back (clarify) or why it cannot be answered (unsupported)" },
      query: { oneOf: [ref("AnalyticsQuestionQuery"), { type: "null" }] },
      interpretation: { type: ["string", "null"], example: "Mitigated requests by country (top 10), 27 Sep–4 Oct 2026, hosts tagged shop" },
      analyticsHref: { type: ["string", "null"], description: "The same query on the Analytics page, as far as the page can show it" },
      result: { oneOf: [ref("AnalyticsQuestionResult"), { type: "null" }] },
      summary: {
        type: ["object", "null"],
        properties: { text: { type: "string" }, source: { type: "string", enum: ["ai", "computed"], description: "ai: AI-generated from the aggregates" } },
      },
      summaryError: { type: ["string", "null"] },
      privacy: {
        type: ["object", "null"],
        description: "What went to the AI provider for this answer",
        properties: {
          provider: { type: "string" },
          model: { type: "string" },
          interpretation: { type: "boolean" },
          summary: { type: "boolean" },
          requestDetails: { type: "boolean", description: "Client addresses, user agents or paths were sent as they are" },
          description: { type: "string" },
        },
      },
      askedAt: { type: "string", format: "date-time" },
    },
  },
  AnalyticsSavedQuestionInput: {
    type: "object",
    additionalProperties: false,
    properties: {
      question: { type: "string", minLength: 3, maxLength: MAX_QUESTION_LENGTH },
      query: ref("AnalyticsQuestionQuery"),
      shared: { type: "boolean", default: false },
    },
  },
  AnalyticsSavedQuestion: {
    type: "object",
    properties: {
      id: { type: "integer" },
      question: { type: "string" },
      query: ref("AnalyticsQuestionQuery"),
      interpretation: { type: "string" },
      shared: { type: "boolean" },
      owned: { type: "boolean" },
      ownerName: { type: ["string", "null"] },
      createdAt: { type: "string" },
      updatedAt: { type: "string" },
    },
  },
  AiQuestionSettings: {
    type: "object",
    additionalProperties: false,
    properties: {
      enabled: { type: "boolean", default: true, description: "Users with analytics:read may ask questions" },
      aiSummaries: { type: "boolean", default: true, description: "The model writes the summary from the aggregated result; off, the dashboard writes it" },
      shareRequestDetails: {
        type: "boolean",
        default: false,
        description: "Send client addresses, user agents and paths to the model when a question ranks or filters by them; otherwise placeholders",
      },
    },
  },
};
