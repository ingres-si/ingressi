/**
 * OpenAPI paths and schemas of the access list endpoints, spread into
 * app/api/v1/openapi.json/route.ts. Enum values come from
 * access-list-rules.ts, so they cannot drift from what the API accepts.
 */
import {
  ACCESS_LIST_DEFAULT_ACTIONS,
  ACCESS_LIST_RULE_ACTIONS,
  ACCESS_LIST_RULE_KINDS,
  BLOCKED_SOURCES_KEY,
  MAX_DENY_BODY_LENGTH,
  MAX_RULE_NOTE_LENGTH,
  MAX_RULES_PER_LIST,
  MAX_VALUES_PER_RULE,
} from "./access-list-rules";

const TAG = "Access Lists";

export const ACCESS_LISTS_OPENAPI_TAG = {
  name: TAG,
  description:
    "Access lists: ordered allow and deny rules by IP address or CIDR range, country, continent or AS number " +
    "(the first matching rule decides; unmatched requests get the list's default action), HTTP basic-auth members, " +
    "and the global Blocked sources list, which applies to every host before anything else.",
};

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: unknown) => ({ "application/json": { schema } });
const ok = (description: string, schema: unknown) => ({ description, content: json(schema) });
const errors = (...codes: string[]) => {
  const map: Record<string, unknown> = {
    "400": { $ref: "#/components/responses/BadRequest" },
    "401": { $ref: "#/components/responses/Unauthorized" },
    "403": { $ref: "#/components/responses/Forbidden" },
    "404": { $ref: "#/components/responses/NotFound" },
    "409": { $ref: "#/components/responses/Conflict" },
  };
  return Object.fromEntries(codes.map((code) => [code, map[code]]));
};
const idPath = { $ref: "#/components/parameters/IdPath" };
const intPath = (name: string, description: string) => ({
  name,
  in: "path",
  required: true,
  schema: { type: "integer" },
  description,
});
const body = (schema: unknown) => ({ required: true, content: json(schema) });

const READ = "Needs access_lists:read.";
const WRITE = "Needs access_lists:write. Applies the Caddy configuration.";

export const ACCESS_LISTS_OPENAPI_PATHS = {
  "/api/v1/access-lists": {
    get: {
      tags: [TAG],
      summary: "List access lists",
      description: `Every access list the caller can see, with its rules and members (never the Blocked sources list). ${READ}`,
      operationId: "listAccessLists",
      responses: { "200": ok("Access lists", { type: "array", items: ref("AccessList") }), ...errors("401", "403") },
    },
    post: {
      tags: [TAG],
      summary: "Create an access list",
      description: `Creates a list with optional rules, settings and basic-auth members. ${WRITE}`,
      operationId: "createAccessList",
      requestBody: body(ref("AccessListInput")),
      responses: { "201": ok("Access list created", ref("AccessList")), ...errors("400", "401", "403") },
    },
  },
  "/api/v1/access-lists/{id}": {
    get: {
      tags: [TAG],
      summary: "Get an access list",
      description: READ,
      operationId: "getAccessList",
      parameters: [idPath],
      responses: { "200": ok("Access list", ref("AccessList")), ...errors("401", "403", "404") },
    },
    put: {
      tags: [TAG],
      summary: "Update an access list",
      description: `Changes the fields sent. With \`rules\`, replaces every rule in the order sent; rules sent with their \`id\` keep it. ${WRITE}`,
      operationId: "updateAccessList",
      parameters: [idPath],
      requestBody: body(ref("AccessListUpdate")),
      responses: { "200": ok("Access list updated", ref("AccessList")), ...errors("400", "401", "403", "404") },
    },
    delete: {
      tags: [TAG],
      summary: "Delete an access list",
      description: `Deletes the list with its rules and members and detaches it from the hosts using it. The Blocked sources list cannot be deleted (400). ${WRITE}`,
      operationId: "deleteAccessList",
      parameters: [idPath],
      responses: { "200": { $ref: "#/components/responses/Ok" }, ...errors("400", "401", "403", "404") },
    },
  },
  "/api/v1/access-lists/{id}/entries": {
    post: {
      tags: [TAG],
      summary: "Add a basic-auth member",
      description: `The password is stored as a bcrypt hash and never returned. ${WRITE}`,
      operationId: "addAccessListEntry",
      parameters: [idPath],
      requestBody: body(ref("AccessListEntryInput")),
      responses: { "201": ok("The access list", ref("AccessList")), ...errors("400", "401", "403", "404") },
    },
  },
  "/api/v1/access-lists/{id}/entries/{entryId}": {
    delete: {
      tags: [TAG],
      summary: "Remove a basic-auth member",
      description: WRITE,
      operationId: "removeAccessListEntry",
      parameters: [idPath, intPath("entryId", "Entry ID")],
      responses: { "200": ok("The access list", ref("AccessList")), ...errors("401", "403", "404") },
    },
  },
  "/api/v1/access-lists/{id}/rules": {
    get: {
      tags: [TAG],
      summary: "List an access list's rules",
      description: `The rules in the order they are checked. ${READ}`,
      operationId: "listAccessListRules",
      parameters: [idPath],
      responses: { "200": ok("Rules", { type: "array", items: ref("AccessListRule") }), ...errors("401", "403", "404") },
    },
    post: {
      tags: [TAG],
      summary: "Add a rule",
      description: `Adds a rule at \`position\` (0-based), last by default. ${WRITE}`,
      operationId: "addAccessListRule",
      parameters: [idPath],
      requestBody: body({
        allOf: [ref("AccessListRuleInput"), { type: "object", properties: { position: { type: "integer", minimum: 0 } } }],
      }),
      responses: { "201": ok("Rule added", ref("AccessListRule")), ...errors("400", "401", "403", "404") },
    },
    put: {
      tags: [TAG],
      summary: "Replace every rule",
      description: `Replaces the list's rules with \`rules\`, in order. Rules sent with their \`id\` keep it; rules not sent are deleted. ${WRITE}`,
      operationId: "replaceAccessListRules",
      parameters: [idPath],
      requestBody: body({
        type: "object",
        properties: { rules: { type: "array", maxItems: MAX_RULES_PER_LIST, items: ref("AccessListRuleInput") } },
        required: ["rules"],
      }),
      responses: { "200": ok("The rules", { type: "array", items: ref("AccessListRule") }), ...errors("400", "401", "403", "404") },
    },
  },
  "/api/v1/access-lists/{id}/rules/{ruleId}": {
    get: {
      tags: [TAG],
      summary: "Get a rule",
      description: READ,
      operationId: "getAccessListRule",
      parameters: [idPath, intPath("ruleId", "Rule ID")],
      responses: { "200": ok("Rule", ref("AccessListRule")), ...errors("401", "403", "404") },
    },
    put: {
      tags: [TAG],
      summary: "Update a rule",
      description: `Replaces the rule's action, kind, values, note and expiry; its position stays. ${WRITE}`,
      operationId: "updateAccessListRule",
      parameters: [idPath, intPath("ruleId", "Rule ID")],
      requestBody: body(ref("AccessListRuleInput")),
      responses: { "200": ok("Rule updated", ref("AccessListRule")), ...errors("400", "401", "403", "404") },
    },
    delete: {
      tags: [TAG],
      summary: "Delete a rule",
      description: WRITE,
      operationId: "deleteAccessListRule",
      parameters: [idPath, intPath("ruleId", "Rule ID")],
      responses: { "200": { $ref: "#/components/responses/Ok" }, ...errors("401", "403", "404") },
    },
  },
  "/api/v1/access-lists/{id}/rules/reorder": {
    post: {
      tags: [TAG],
      summary: "Reorder the rules",
      description: `Puts the rules in the order of \`ruleIds\`, which must name every rule of the list exactly once. ${WRITE}`,
      operationId: "reorderAccessListRules",
      parameters: [idPath],
      requestBody: body({
        type: "object",
        properties: { ruleIds: { type: "array", items: { type: "integer" } } },
        required: ["ruleIds"],
      }),
      responses: { "200": ok("The rules in their new order", { type: "array", items: ref("AccessListRule") }), ...errors("400", "401", "403", "404") },
    },
  },
  "/api/v1/access-lists/blocked-sources": {
    get: {
      tags: [TAG],
      summary: "Get the Blocked sources list",
      description:
        "The global list denied on every host, before rate limiting, the WAF and the hosts' own lists. `id` is null before its first use." +
        ` ${READ}`,
      operationId: "getBlockedSources",
      responses: { "200": ok("The Blocked sources list", ref("AccessList")), ...errors("401", "403") },
    },
    put: {
      tags: [TAG],
      summary: "Update the Blocked sources list",
      description:
        "Changes its description, deny response and failClosed; with `rules`, replaces every entry. It only holds deny rules, " +
        `lets everything else through and keeps its name. ${WRITE}`,
      operationId: "updateBlockedSources",
      requestBody: body(ref("AccessListUpdate")),
      responses: { "200": ok("The Blocked sources list", ref("AccessList")), ...errors("400", "401", "403") },
    },
  },
  "/api/v1/access-lists/blocked-sources/entries": {
    get: {
      tags: [TAG],
      summary: "List blocked sources",
      description: `${READ}`,
      operationId: "listBlockedSources",
      responses: { "200": ok("Entries (deny rules)", { type: "array", items: ref("AccessListRule") }), ...errors("401", "403") },
    },
    post: {
      tags: [TAG],
      summary: "Block a source on every host",
      description:
        "Adds an address or network (`address`), or a country, continent or AS number (`kind` and `value`), with an optional " +
        "reason and expiry. 201 with the new entry; 200 with the existing entry when it is already blocked by an entry of its own " +
        `(its reason and expiry are updated when sent). Expired entries are removed within a minute. ${WRITE}`,
      operationId: "addBlockedSource",
      requestBody: body(ref("BlockedSourceInput")),
      responses: {
        "200": ok("Already blocked", ref("AccessListRule")),
        "201": ok("Blocked", ref("AccessListRule")),
        ...errors("400", "401", "403"),
      },
    },
  },
  "/api/v1/access-lists/blocked-sources/entries/{entryId}": {
    delete: {
      tags: [TAG],
      summary: "Unblock a source",
      description: `${WRITE}`,
      operationId: "removeBlockedSource",
      parameters: [intPath("entryId", "Entry (rule) ID")],
      responses: { "200": { $ref: "#/components/responses/Ok" }, ...errors("401", "403", "404") },
    },
  },
  "/api/v1/access-lists/stats": {
    get: {
      tags: [TAG],
      summary: "Where access lists are used and what they stopped",
      description:
        "Per list, the hosts using it (those the caller can see) and the requests stopped on them in the last 24 hours, from analytics. " +
        "A stopped request is a blocked one on those hosts (outcome geo or access when recorded, otherwise is_blocked), so global geo " +
        "blocking on the same hosts is counted too. failedSignIns counts 401 answers on hosts of lists with basic-auth members. " +
        "Instance-wide numbers (requests, blockedSources.stopped) need analytics:read. Without analytics, " +
        `available is false and the numbers are 0. ${READ}`,
      operationId: "getAccessListStats",
      responses: { "200": ok("Usage and stopped requests", ref("AccessListStats")), ...errors("401", "403") },
    },
  },
};

const ruleValues = {
  type: "array",
  minItems: 1,
  maxItems: MAX_VALUES_PER_RULE,
  items: { type: "string" },
  description:
    "Values of the rule's kind. ip: IPv4 or IPv6 addresses and CIDR ranges (normalized to the network address), or private_ranges. " +
    "country: ISO 3166-1 alpha-2 codes. continent: AF, AN, AS, EU, NA, OC, SA. asn: AS numbers (AS64500 or 64500, stored as 64500). " +
    "A comma- or space-separated string is accepted too.",
  example: ["203.0.113.0/26", "2001:db8::/48"],
};

const settingsProperties = {
  defaultAction: {
    type: "string",
    enum: [...ACCESS_LIST_DEFAULT_ACTIONS],
    description: "What a request that matches no rule gets. Default allow.",
  },
  denyStatus: { type: "integer", minimum: 400, maximum: 599, description: "Status of a denied request. Default 403." },
  denyBody: {
    type: ["string", "null"],
    maxLength: MAX_DENY_BODY_LENGTH,
    description: "Body of a denied request; null serves Forbidden.",
  },
  denyRedirectUrl: {
    type: ["string", "null"],
    format: "uri",
    description: "When set, a denied request gets a 302 to this HTTP or HTTPS URL instead of the status and body.",
  },
  failClosed: {
    type: "boolean",
    description:
      "Deny when the client address cannot be worked out behind a trusted proxy (no usable X-Forwarded-For). Default false.",
  },
  skipAuthForAllowed: {
    type: "boolean",
    description:
      "Clients whose address matches an allow address rule skip the list's Basic Auth; everyone else is asked for credentials. Default false.",
  },
};

export const ACCESS_LISTS_OPENAPI_SCHEMAS = {
  AccessList: {
    type: "object",
    properties: {
      id: { type: ["integer", "null"], description: "Null only for the Blocked sources list before its first use" },
      name: { type: "string" },
      description: { type: ["string", "null"] },
      entries: { type: "array", items: ref("AccessListEntry"), description: "Basic-auth members" },
      rules: { type: "array", items: ref("AccessListRule"), description: "In the order they are checked" },
      ...settingsProperties,
      system: {
        type: ["string", "null"],
        enum: [BLOCKED_SOURCES_KEY, null],
        description: "blocked_sources for the global Blocked sources list; null for lists users create",
      },
      createdAt: { type: ["string", "null"], format: "date-time" },
      updatedAt: { type: ["string", "null"], format: "date-time" },
    },
    required: ["id", "name", "entries", "rules", "defaultAction", "denyStatus", "failClosed", "system", "createdAt", "updatedAt"],
  },
  AccessListInput: {
    type: "object",
    properties: {
      name: { type: "string", maxLength: 200, example: "Office and VPN" },
      description: { type: ["string", "null"], maxLength: 1000 },
      rules: { type: "array", maxItems: MAX_RULES_PER_LIST, items: ref("AccessListRuleInput") },
      ...settingsProperties,
      users: {
        type: "array",
        description: "Basic-auth members",
        items: ref("AccessListEntryInput"),
      },
    },
    required: ["name"],
  },
  AccessListUpdate: {
    type: "object",
    properties: {
      name: { type: "string", maxLength: 200 },
      description: { type: ["string", "null"], maxLength: 1000 },
      rules: {
        type: "array",
        maxItems: MAX_RULES_PER_LIST,
        items: ref("AccessListRuleInput"),
        description: "Replaces every rule, in order; rules sent with their id keep it",
      },
      ...settingsProperties,
    },
  },
  AccessListEntry: {
    type: "object",
    properties: {
      id: { type: "integer" },
      username: { type: "string" },
      createdAt: { type: "string", format: "date-time" },
      updatedAt: { type: "string", format: "date-time" },
    },
    required: ["id", "username", "createdAt", "updatedAt"],
  },
  AccessListEntryInput: {
    type: "object",
    properties: {
      username: { type: "string", maxLength: 128, description: "No colon", example: "s.conti" },
      password: { type: "string", minLength: 1, maxLength: 1024, writeOnly: true },
    },
    required: ["username", "password"],
  },
  AccessListRule: {
    type: "object",
    properties: {
      id: { type: "integer" },
      position: { type: "integer", description: "0-based; rules are checked in this order" },
      action: { type: "string", enum: [...ACCESS_LIST_RULE_ACTIONS] },
      kind: { type: "string", enum: [...ACCESS_LIST_RULE_KINDS] },
      values: { type: "array", items: { type: "string" } },
      note: { type: ["string", "null"] },
      expiresAt: { type: ["string", "null"], format: "date-time" },
      expired: { type: "boolean", description: "The expiry has passed: the rule no longer applies and is removed within a minute" },
      createdAt: { type: "string", format: "date-time" },
      updatedAt: { type: "string", format: "date-time" },
    },
    required: ["id", "position", "action", "kind", "values", "note", "expiresAt", "expired", "createdAt", "updatedAt"],
  },
  AccessListRuleInput: {
    type: "object",
    properties: {
      id: { type: "integer", description: "Ignored, except in a full replace, where it keeps the rule's id" },
      action: { type: "string", enum: [...ACCESS_LIST_RULE_ACTIONS] },
      kind: { type: "string", enum: [...ACCESS_LIST_RULE_KINDS] },
      values: ruleValues,
      note: { type: ["string", "null"], maxLength: MAX_RULE_NOTE_LENGTH },
      expiresAt: { type: ["string", "null"], format: "date-time", description: "In the future, at most ten years ahead" },
    },
    required: ["action", "kind", "values"],
  },
  BlockedSourceInput: {
    type: "object",
    properties: {
      address: { type: "string", description: "An IP address or CIDR range (not /0)", example: "198.51.100.19" },
      kind: { type: "string", enum: [...ACCESS_LIST_RULE_KINDS], description: "With value or values, instead of address" },
      value: { type: ["string", "integer"], example: "AS64500" },
      values: ruleValues,
      reason: { type: ["string", "null"], maxLength: MAX_RULE_NOTE_LENGTH, description: "Stored as the entry's note" },
      expiresAt: { type: ["string", "null"], format: "date-time" },
      expiresInSeconds: { type: "integer", minimum: 60, description: "Instead of expiresAt" },
    },
  },
  AccessListStats: {
    type: "object",
    properties: {
      available: { type: "boolean", description: "False without analytics (ClickHouse) or when it could not be read" },
      windowSeconds: { type: "integer", example: 86400 },
      stopped: { type: "integer", description: "Stopped in the last 24 hours" },
      previous: { type: "integer", description: "Stopped in the 24 hours before" },
      requests: { type: ["integer", "null"], description: "All requests in the last 24 hours; null without analytics:read" },
      failedSignIns: { type: "integer" },
      byOutcome: {
        type: ["object", "null"],
        properties: { geo: { type: "integer" }, access: { type: "integer" } },
        description: "Null when analytics does not record a per-request outcome",
      },
      lists: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string" },
            type: {
              type: "string",
              enum: ["empty", "basic_auth", "geo", "address_allowlist", "address_blocklist", "rules", "blocked_sources"],
            },
            rules: { type: "integer" },
            members: { type: "integer" },
            stopped: { type: "integer" },
            failedSignIns: { type: "integer" },
            hosts: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "integer" },
                  name: { type: "string" },
                  domains: { type: "array", items: { type: "string" } },
                  enabled: { type: "boolean" },
                  stopped: { type: "integer" },
                  failedSignIns: { type: "integer" },
                },
              },
            },
          },
        },
      },
      blockedSources: {
        type: "object",
        properties: {
          id: { type: ["integer", "null"] },
          entries: { type: "integer" },
          stopped: { type: ["integer", "null"] },
        },
      },
      countries: { type: "array", items: { type: "object", properties: { code: { type: "string" }, count: { type: "integer" } } } },
      hosts: { type: "array", items: { type: "object", properties: { host: { type: "string" }, count: { type: "integer" } } } },
    },
    required: ["available", "windowSeconds", "stopped", "previous", "requests", "failedSignIns", "lists", "countries", "hosts"],
  },
};
