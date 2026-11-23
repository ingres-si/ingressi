/**
 * The tools of the MCP server, and what each one does.
 *
 * Every tool maps to something the REST API already offers; the handler calls
 * the same models, the same tag-scope checks and the same change-approval
 * gate, so an MCP client can never do more than its user could do on the
 * dashboard. The permission named by a tool is checked against the token's
 * scopes before the handler runs (server.ts); the models enforce everything
 * else (validation, tag scope, approvals, Caddy apply).
 */
import { type Access, type Permission } from "../permissions";
import { scopeTagsFor } from "../permissions";
import {
  assertDomainsFreeOutsideScope,
  assertL4WriteAllowed,
  assertListenPortFreeOutsideScope,
  assertProxyHostWriteAllowed,
  certificateIdsInScope,
  getL4ProxyHostInScope,
  getProxyHostInScope,
  tagsForWrite,
} from "../access-scope";
import {
  createProxyHost,
  deleteProxyHost,
  listProxyHosts,
  toApiProxyHost,
  updateProxyHost,
  type ProxyHost,
  type ProxyHostInput,
} from "../models/proxy-hosts";
import {
  createL4ProxyHost,
  deleteL4ProxyHost,
  listL4ProxyHosts,
  updateL4ProxyHost,
  type L4ProxyHost,
  type L4ProxyHostInput,
} from "../models/l4-proxy-hosts";
import {
  createAccessList,
  deleteAccessList,
  getAccessList,
  listAccessLists,
  updateAccessList,
  type AccessList,
  type AccessListInput,
  type AccessListUpdate,
} from "../models/access-lists";
import { listUsers } from "../models/user";
import { listGroups } from "../models/groups";
import { countAuditEventsMatching, queryAuditEvents, type AuditFilter } from "../models/audit";
import { listCertificates } from "../models/certificates";
import { toCertificateApiResponse } from "../certificate-api";
import { buildCertificateOverview } from "../certificate-overview";
import { loadOverview } from "../overview";
import { searchDashboard } from "../search";
import { getCaddyApplyStatus } from "../caddy-apply-status";
import { getMonitorState } from "../caddy-monitor";
import { applyCaddyConfig } from "../caddy";
import { CaddyApplyError } from "../caddy-apply-error";
import { resolveRange } from "../analytics/range";
import { parseAnalyticsQuery, queryAnalytics } from "../analytics/query";
import { visibleProxyHostDomains } from "../analytics/service";
import { parseEventKinds, parseSecurityEventFilters, querySecurityEvents } from "../analytics/security";
import { ApiClientError } from "../api-errors";
import { gateHostChange } from "@/ee/approvals/requests";
import {
  errorResult,
  jsonText,
  McpError,
  JSON_RPC,
  textResult,
  type CallToolResult,
} from "./protocol";

export type McpToolContext = {
  access: Access;
  userId: number;
  /** The account's display name, for the overview. */
  userName: string;
  /** The client the request came from; used only for descriptions. */
  clientName: string;
  /** The token's raw scopes, for error messages. */
  scopes: readonly string[];
};

export type McpTool = {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: {
    title: string;
    readOnlyHint: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
  /** The REST permission the handler needs; null for pages every signed-in user may read. */
  permission: Permission | null;
  handler: (args: Record<string, unknown>, context: McpToolContext) => Promise<CallToolResult>;
};

function idArg(args: Record<string, unknown>, field = "id"): number {
  const value = args[field];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) {
    throw new McpError(JSON_RPC.INVALID_PARAMS, `${field} must be a positive integer`);
  }
  return value;
}

function intArg(args: Record<string, unknown>, field: string, fallback: number, min: number, max: number): number {
  const value = args[field];
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new McpError(JSON_RPC.INVALID_PARAMS, `${field} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function stringArg(args: Record<string, unknown>, field: string): string | undefined {
  const value = args[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new McpError(JSON_RPC.INVALID_PARAMS, `${field} must be a string`);
  return value;
}

/** A non-empty array of strings, or a -32602 naming the argument. */
function stringArrayArg(args: Record<string, unknown>, field: string): string[] {
  const value = args[field];
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || item.trim() === "")) {
    throw new McpError(JSON_RPC.INVALID_PARAMS, `${field} must be a non-empty array of strings`);
  }
  return value as string[];
}

/** An ISO 8601 timestamp argument, normalized; anything else is a -32602. */
function timestampArg(args: Record<string, unknown>, field: string): string | undefined {
  const raw = stringArg(args, field);
  if (raw === undefined) return undefined;
  const time = Date.parse(raw);
  if (!Number.isFinite(time)) throw new McpError(JSON_RPC.INVALID_PARAMS, `${field} must be an ISO 8601 timestamp`);
  return new Date(time).toISOString();
}

/** The safe summary of a proxy host used by list resources and tools. */
export function proxyHostSummary(host: ProxyHost) {
  return {
    id: host.id,
    name: host.name,
    domains: host.domains,
    upstreams: host.upstreams,
    enabled: host.enabled,
    sslForced: host.sslForced,
    certificateId: host.certificateId,
    accessListId: host.accessListId,
    tags: host.tags,
    updatedAt: host.updatedAt,
  };
}

function l4HostSummary(host: L4ProxyHost) {
  return {
    id: host.id,
    name: host.name,
    protocol: host.protocol,
    listenAddress: host.listenAddress,
    upstreams: host.upstreams,
    matcherType: host.matcherType,
    matcherValue: host.matcherValue,
    tlsTermination: host.tlsTermination,
    enabled: host.enabled,
    tags: host.tags,
    updatedAt: host.updatedAt,
  };
}

function accessListSummary(list: AccessList) {
  return {
    id: list.id,
    name: list.name,
    description: list.description,
    defaultAction: list.defaultAction,
    rules: list.rules.length,
    members: list.entries.length,
    failClosed: list.failClosed,
    system: list.system,
    updatedAt: list.updatedAt,
  };
}

const ID_SCHEMA = { type: "integer", minimum: 1, description: "The row id." } as const;
const TAGS_SCHEMA = {
  type: "array",
  items: { type: "string" },
  description:
    "Free-form tags. With a custom role limited to tagged hosts, the host must keep at least one of the role's tags.",
} as const;

function paginationProperties(defaultLimit = 50, maxLimit = 200) {
  return {
    limit: { type: "integer", minimum: 1, maximum: maxLimit, default: defaultLimit, description: "Rows to return." },
    offset: { type: "integer", minimum: 0, maximum: 100_000, default: 0, description: "Rows to skip." },
  } as const;
}

function page<T>(items: readonly T[], offset: number, limit: number): { items: T[]; total: number; offset: number; limit: number } {
  return { items: items.slice(offset, offset + limit), total: items.length, offset, limit };
}

// ── Read tools ────────────────────────────────────────────────────────

const getOverview: McpTool = {
  name: "get_overview",
  title: "Instance overview",
  description:
    "The dashboard overview: what needs attention, traffic of the selected range, the busiest hosts, cluster nodes, recent changes and the first-run checklist. Sections the account may not read are null.",
  inputSchema: {
    type: "object",
    properties: {
      range: {
        type: "string",
        enum: ["1h", "6h", "24h", "7d", "30d"],
        default: "24h",
        description: "Traffic range.",
      },
    },
    additionalProperties: false,
  },
  annotations: { title: "Instance overview", readOnlyHint: true, openWorldHint: false },
  permission: null,
  handler: async (args, context) => {
    const range = stringArg(args, "range");
    const overview = await loadOverview(context.access, { range, userName: context.userName });
    return textResult(jsonText(overview), overview as unknown as Record<string, unknown>);
  },
};

const listHosts: McpTool = {
  name: "list_proxy_hosts",
  title: "List proxy hosts",
  description:
    "HTTP/HTTPS proxy hosts the account can see (a custom role's tag scope applies), with their domains, upstreams, certificate, access list and tags. Filter by text, tag or enabled state.",
  inputSchema: {
    type: "object",
    properties: {
      search: { type: "string", description: "Match name, domain or upstream, case-insensitively." },
      tag: { type: "string", description: "Only hosts carrying this tag." },
      enabled: { type: "boolean", description: "Only enabled or only disabled hosts." },
      ...paginationProperties(),
    },
    additionalProperties: false,
  },
  annotations: { title: "List proxy hosts", readOnlyHint: true, openWorldHint: false },
  permission: "proxy_hosts:read",
  handler: async (args, context) => {
    const search = stringArg(args, "search")?.trim().toLowerCase();
    const tag = stringArg(args, "tag");
    const enabled = typeof args.enabled === "boolean" ? args.enabled : undefined;
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    let hosts = await listProxyHosts(scopeTagsFor(context.access, "proxy_hosts"));
    if (search) {
      hosts = hosts.filter((host) =>
        [host.name, ...host.domains, ...host.upstreams].some((value) => value.toLowerCase().includes(search))
      );
    }
    if (tag) hosts = hosts.filter((host) => host.tags.includes(tag));
    if (enabled !== undefined) hosts = hosts.filter((host) => host.enabled === enabled);
    const result = page(hosts.map(proxyHostSummary), offset, limit);
    return textResult(
      `${result.total} proxy host${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`,
      result
    );
  },
};

const getHost: McpTool = {
  name: "get_proxy_host",
  title: "Get a proxy host",
  description:
    "One proxy host in full: routing, TLS and HSTS, headers, access lists, mTLS, WAF, forward auth, rate limiting, redirects, rewrites, path rules, error pages and tags. A host outside a custom role's tag scope is not found.",
  inputSchema: { type: "object", properties: { id: ID_SCHEMA }, required: ["id"], additionalProperties: false },
  annotations: { title: "Get a proxy host", readOnlyHint: true, openWorldHint: false },
  permission: "proxy_hosts:read",
  handler: async (args, context) => {
    const host = await getProxyHostInScope(context.access, idArg(args));
    const api = toApiProxyHost(host);
    return textResult(jsonText(api), api as unknown as Record<string, unknown>);
  },
};

const listL4Hosts: McpTool = {
  name: "list_l4_proxy_hosts",
  title: "List L4 proxy hosts",
  description: "TCP/UDP proxy hosts the account can see, with protocol, listening address, upstreams, matcher and tags.",
  inputSchema: {
    type: "object",
    properties: {
      search: { type: "string", description: "Match name, listening address, upstream or matcher, case-insensitively." },
      ...paginationProperties(),
    },
    additionalProperties: false,
  },
  annotations: { title: "List L4 proxy hosts", readOnlyHint: true, openWorldHint: false },
  permission: "l4_proxy_hosts:read",
  handler: async (args, context) => {
    const search = stringArg(args, "search")?.trim().toLowerCase();
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    let hosts = await listL4ProxyHosts(scopeTagsFor(context.access, "l4_proxy_hosts"));
    if (search) {
      hosts = hosts.filter((host) =>
        [host.name, host.listenAddress, ...host.upstreams, ...host.matcherValue].some((value) =>
          value.toLowerCase().includes(search)
        )
      );
    }
    const result = page(hosts.map(l4HostSummary), offset, limit);
    return textResult(`${result.total} L4 proxy host${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`, result);
  },
};

const getL4Host: McpTool = {
  name: "get_l4_proxy_host",
  title: "Get an L4 proxy host",
  description: "One TCP/UDP proxy host in full, including load balancing, health checks, PROXY protocol and geo blocking.",
  inputSchema: { type: "object", properties: { id: ID_SCHEMA }, required: ["id"], additionalProperties: false },
  annotations: { title: "Get an L4 proxy host", readOnlyHint: true, openWorldHint: false },
  permission: "l4_proxy_hosts:read",
  handler: async (args, context) => {
    const host = await getL4ProxyHostInScope(context.access, idArg(args));
    return textResult(jsonText(host), host as unknown as Record<string, unknown>);
  },
};

const listCerts: McpTool = {
  name: "list_certificates",
  title: "List certificates",
  description:
    "TLS certificates the account can see: ACME certificates Caddy obtains, imported certificates and managed entries, with issuer, validity, days left, renewal state and the hosts that use them. No private keys.",
  inputSchema: {
    type: "object",
    properties: {
      search: { type: "string", description: "Match a certificate or host name, or a domain." },
      expiringWithinDays: { type: "integer", minimum: 0, maximum: 3650, description: "Only rows with this many days left or fewer." },
      ...paginationProperties(),
    },
    additionalProperties: false,
  },
  annotations: { title: "List certificates", readOnlyHint: true, openWorldHint: false },
  permission: "certificates:read",
  handler: async (args, context) => {
    const search = stringArg(args, "search")?.trim().toLowerCase();
    const within = typeof args.expiringWithinDays === "number" ? args.expiringWithinDays : undefined;
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    const overview = await buildCertificateOverview(context.access);
    let rows = overview.certificates;
    if (search) {
      rows = rows.filter((row) =>
        [row.name, ...row.domains].some((value) => value.toLowerCase().includes(search))
      );
    }
    if (within !== undefined) {
      rows = rows.filter((row) => row.daysLeft !== null && row.daysLeft <= within);
    }
    const result = page(rows, offset, limit);
    return textResult(`${result.total} certificate row${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`, result);
  },
};

const listCertificatesRaw: McpTool = {
  name: "list_imported_certificates",
  title: "List imported certificates",
  description:
    "The certificate rows stored by Ingressi (imported PEMs), with domains, auto-renew and whether a private key is stored. No key material.",
  inputSchema: { type: "object", properties: paginationProperties(), additionalProperties: false },
  annotations: { title: "List imported certificates", readOnlyHint: true, openWorldHint: false },
  permission: "certificates:read",
  handler: async (args, context) => {
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    const inScope = await certificateIdsInScope(context.access);
    const certificates = (await listCertificates())
      .filter((cert) => inScope === null || inScope.has(cert.id))
      .map(toCertificateApiResponse);
    const result = page(certificates, offset, limit);
    return textResult(`${result.total} imported certificate${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`, result);
  },
};

const listLists: McpTool = {
  name: "list_access_lists",
  title: "List access lists",
  description: "Access lists (address/country/AS rules, basic-auth members, default action) and the global Blocked sources list.",
  inputSchema: { type: "object", properties: paginationProperties(), additionalProperties: false },
  annotations: { title: "List access lists", readOnlyHint: true, openWorldHint: false },
  permission: "access_lists:read",
  handler: async (args) => {
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    const lists = (await listAccessLists()).map(accessListSummary);
    const result = page(lists, offset, limit);
    return textResult(`${result.total} access list${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`, result);
  },
};

const getList: McpTool = {
  name: "get_access_list",
  title: "Get an access list",
  description: "One access list in full: ordered rules, basic-auth members (usernames only) and deny settings.",
  inputSchema: { type: "object", properties: { id: ID_SCHEMA }, required: ["id"], additionalProperties: false },
  annotations: { title: "Get an access list", readOnlyHint: true, openWorldHint: false },
  permission: "access_lists:read",
  handler: async (args) => {
    const list = await getAccessList(idArg(args));
    if (!list) throw new ApiClientError("Access list not found", 404);
    return textResult(jsonText(list), list as unknown as Record<string, unknown>);
  },
};

const listUsersTool: McpTool = {
  name: "list_users",
  title: "List users",
  description:
    "Dashboard accounts with email, name, role, custom role, status and last sign-in. Never password hashes, MFA secrets or passkeys.",
  inputSchema: {
    type: "object",
    properties: {
      search: { type: "string", description: "Match email or name, case-insensitively." },
      ...paginationProperties(),
    },
    additionalProperties: false,
  },
  annotations: { title: "List users", readOnlyHint: true, openWorldHint: false },
  permission: "users:read",
  handler: async (args) => {
    const search = stringArg(args, "search")?.trim().toLowerCase();
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    let users = await listUsers();
    if (search) {
      users = users.filter((user) =>
        [user.email, user.name ?? "", user.username ?? ""].some((value) => value.toLowerCase().includes(search))
      );
    }
    const rows = users.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      username: user.username,
      role: user.role,
      customRoleId: user.customRoleId,
      status: user.status,
      lastSignInAt: user.lastSignInAt,
      lastSignInMethod: user.lastSignInMethod,
      createdAt: user.createdAt,
    }));
    const result = page(rows, offset, limit);
    return textResult(`${result.total} user${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`, result);
  },
};

const listGroupsTool: McpTool = {
  name: "list_groups",
  title: "List groups",
  description: "Forward-auth groups with their members and the hosts that grant access through them.",
  inputSchema: { type: "object", properties: paginationProperties(), additionalProperties: false },
  annotations: { title: "List groups", readOnlyHint: true, openWorldHint: false },
  permission: "groups:read",
  handler: async (args) => {
    const limit = intArg(args, "limit", 50, 1, 200);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    const groups = await listGroups();
    const result = page(groups, offset, limit);
    return textResult(`${result.total} group${result.total === 1 ? "" : "s"}; showing ${result.items.length}.`, result);
  },
};

const searchTool: McpTool = {
  name: "search",
  title: "Search the dashboard",
  description:
    "Search hosts, certificates, users, actions, pages, settings and documentation, with the same permission and tag filtering as the command palette.",
  inputSchema: {
    type: "object",
    properties: { query: { type: "string", description: "What to look for." } },
    required: ["query"],
    additionalProperties: false,
  },
  annotations: { title: "Search the dashboard", readOnlyHint: true, openWorldHint: false },
  permission: null,
  handler: async (args, context) => {
    const query = stringArg(args, "query")?.trim();
    if (!query) throw new McpError(JSON_RPC.INVALID_PARAMS, "query must not be empty");
    const result = await searchDashboard(context.access, query);
    return textResult(`${result.results.length} result${result.results.length === 1 ? "" : "s"} for “${query}”.`, result as unknown as Record<string, unknown>);
  },
};

const auditLogTool: McpTool = {
  name: "list_audit_events",
  title: "List audit log events",
  description:
    "The audit log, newest first, with the actor, action, entity and summary. Filter by text, actor, action, entity type or a time window; read the hash chain through the REST API's /api/v1/audit-log/verify.",
  inputSchema: {
    type: "object",
    properties: {
      search: { type: "string", description: "Match summary or details." },
      actor: { type: "integer", minimum: 1, description: "Only events by this user id." },
      action: { type: "string", description: "Only this action, e.g. login_success." },
      entityType: { type: "string", description: "Only this entity type, e.g. proxy_host." },
      from: { type: "string", description: "ISO 8601 timestamp, inclusive." },
      to: { type: "string", description: "ISO 8601 timestamp, inclusive." },
      ...paginationProperties(100, 500),
    },
    additionalProperties: false,
  },
  annotations: { title: "List audit log events", readOnlyHint: true, openWorldHint: false },
  permission: "audit_log:read",
  handler: async (args) => {
    const from = timestampArg(args, "from");
    const to = timestampArg(args, "to");
    const filter: AuditFilter = {
      search: stringArg(args, "search"),
      actor: typeof args.actor === "number" ? args.actor : undefined,
      action: stringArg(args, "action"),
      entityType: stringArg(args, "entityType"),
      from,
      to,
    };
    const limit = intArg(args, "limit", 100, 1, 500);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    const [events, total] = await Promise.all([
      queryAuditEvents(filter, { limit, offset }),
      countAuditEventsMatching(filter),
    ]);
    const result = { events, total, limit, offset };
    return textResult(`${total} audit event${total === 1 ? "" : "s"}; showing ${events.length}.`, result);
  },
};

const securityEventsTool: McpTool = {
  name: "list_security_events",
  title: "List security events",
  description:
    "Requests Ingressi stopped (WAF, geo blocking, access lists, rate limiting, sign-in redirects) and the traffic outcomes around them. Requires ClickHouse analytics; status says \"disabled\" or \"unavailable\" when it cannot be read.",
  inputSchema: {
    type: "object",
    properties: {
      range: { type: "string", enum: ["1h", "6h", "24h", "7d", "30d"], default: "24h" },
      kinds: {
        type: "array",
        items: { type: "string", enum: ["waf", "geo", "access", "auth", "rate_limit"] },
        description: "Event kinds; all of them when omitted.",
      },
      host: { type: "string", description: "Only events for this host name." },
      path: { type: "string", description: "Only events whose path contains this text." },
      ip: { type: "string", description: "Only events from this client IP." },
      ...paginationProperties(50, 500),
    },
    additionalProperties: false,
  },
  annotations: { title: "List security events", readOnlyHint: true, openWorldHint: false },
  permission: "waf:read",
  handler: async (args) => {
    const range = resolveRange({ range: stringArg(args, "range") });
    const kinds = parseEventKinds(Array.isArray(args.kinds) ? args.kinds.join(",") : args.kinds);
    const filters = parseSecurityEventFilters(
      [
        ...(stringArg(args, "host") ? [{ dim: "host", op: "is", value: stringArg(args, "host") }] : []),
        ...(stringArg(args, "path") ? [{ dim: "path", op: "contains", value: stringArg(args, "path") }] : []),
        ...(stringArg(args, "ip") ? [{ dim: "ip", op: "is", value: stringArg(args, "ip") }] : []),
      ]
    );
    const limit = intArg(args, "limit", 50, 1, 500);
    const offset = intArg(args, "offset", 0, 0, 100_000);
    const result = await querySecurityEvents({ range, limit, offset, kinds, filters });
    return textResult(
      result.status === "ok"
        ? `${result.events.length} security event${result.events.length === 1 ? "" : "s"} (${range.preset}).`
        : `Security events are ${result.status}.`,
      result as unknown as Record<string, unknown>
    );
  },
};

const trafficTool: McpTool = {
  name: "query_traffic",
  title: "Query traffic analytics",
  description:
    "Requests, bytes, visitors, mitigated requests and 5xx errors over a range, grouped by total, host, outcome or status, with the previous period and the peak bucket. Requires ClickHouse; status says when it is unavailable.",
  inputSchema: {
    type: "object",
    properties: {
      range: { type: "string", enum: ["1h", "6h", "24h", "7d", "30d"], default: "24h" },
      metric: { type: "string", enum: ["requests", "bytes", "visitors", "mitigated", "errors"], default: "requests" },
      groupBy: { type: "string", enum: ["total", "host", "outcome", "status"], default: "total" },
      host: { type: "string", description: "Only this host name." },
      topHosts: { type: "integer", minimum: 1, maximum: 50, description: "Hosts shown separately when grouping by host." },
    },
    additionalProperties: false,
  },
  annotations: { title: "Query traffic analytics", readOnlyHint: true, openWorldHint: false },
  permission: "analytics:read",
  handler: async (args, context) => {
    const query = parseAnalyticsQuery({
      range: stringArg(args, "range"),
      metric: stringArg(args, "metric"),
      groupBy: stringArg(args, "groupBy"),
      topHosts: args.topHosts,
      filters: stringArg(args, "host")
        ? [{ dim: "host", op: "is", value: stringArg(args, "host") }]
        : undefined,
    });
    const visible = await visibleProxyHostDomains(context.access);
    const scope =
      scopeTagsFor(context.access, "proxy_hosts") === null
        ? null
        : visible.flatMap((host) => [...host.domains]);
    const result = await queryAnalytics(query, undefined, scope);
    const summary = {
      status: result.status,
      range: result.range,
      metric: result.metric,
      groupBy: result.groupBy,
      headline: result.headline,
      series: result.series.map((series) => ({
        key: series.key,
        label: series.label,
        total: series.total,
      })),
      peak: result.peak,
      peakMitigated: result.peakMitigated,
    };
    return textResult(
      result.status === "ok"
        ? `${result.headline.requests.value} requests in ${result.range.preset}.`
        : `Traffic analytics are ${result.status}.`,
      summary
    );
  },
};

const caddyStatusTool: McpTool = {
  name: "get_caddy_status",
  title: "Get Caddy status",
  description:
    "Whether Caddy is reachable, the last configuration apply (when, ok, error code) and the monitor's last check, so you can tell a stored change that is not live yet from a live one.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
  annotations: { title: "Get Caddy status", readOnlyHint: true, openWorldHint: false },
  permission: "settings:read",
  handler: async () => {
    const [apply, monitor] = await Promise.all([getCaddyApplyStatus(), Promise.resolve(getMonitorState())]);
    const result = { apply, monitor };
    return textResult(jsonText(result), result as unknown as Record<string, unknown>);
  },
};

// ── Write tools ───────────────────────────────────────────────────────

const createHostTool: McpTool = {
  name: "create_proxy_host",
  title: "Create a proxy host",
  description:
    "Create an HTTP/HTTPS reverse proxy host. Required: name, domains and at least one upstream. Advanced fields of the REST API (loadBalancer, waf, mtls, forwardAuth, redirects, rewrite, locationRules, pathAccessLists, errorPages, rateLimit, tags, …) pass through unchanged and are validated by the model. A host a change-approval policy protects becomes a change request (202) instead.",
  inputSchema: {
    type: "object",
    properties: {
      name: { type: "string", description: "A display name." },
      domains: {
        type: "array",
        items: { type: "string" },
        description: "Domain names (no scheme or path). Wildcards need DNS-01 or a wildcard certificate.",
      },
      upstreams: {
        type: "array",
        items: { type: "string" },
        description: "Upstream addresses, e.g. http://app:8080 or https://10.0.0.5:8443.",
      },
      certificateId: { type: ["integer", "null"], description: "Certificate row to serve, or null for automatic HTTPS." },
      accessListId: { type: ["integer", "null"], description: "Access list to apply, or null." },
      sslForced: { type: "boolean", description: "Redirect HTTP to HTTPS (default true)." },
      hstsEnabled: { type: "boolean" },
      hstsSubdomains: { type: "boolean" },
      allowWebsocket: { type: "boolean" },
      preserveHostHeader: { type: "boolean" },
      enabled: { type: "boolean" },
      tags: TAGS_SCHEMA,
    },
    required: ["name", "domains", "upstreams"],
    additionalProperties: true,
  },
  annotations: { title: "Create a proxy host", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  permission: "proxy_hosts:write",
  handler: async (args, context) => {
    if (typeof args.name !== "string" || args.name.trim() === "") {
      throw new McpError(JSON_RPC.INVALID_PARAMS, "name must be a non-empty string");
    }
    stringArrayArg(args, "domains");
    stringArrayArg(args, "upstreams");
    const tags = tagsForWrite(context.access, "proxy_hosts", args.tags, null);
    await assertProxyHostWriteAllowed(context.access, args as Partial<ProxyHostInput>, null);
    await assertDomainsFreeOutsideScope(
      context.access,
      Array.isArray(args.domains) ? (args.domains as string[]) : undefined,
      null
    );
    const input = { ...args, ...(tags !== undefined ? { tags } : {}) } as unknown as ProxyHostInput;
    const gate = await gateHostChange({
      access: context.access,
      change: { targetType: "proxy_host", kind: "create", target: null, input: { host: input } },
    });
    if (gate) {
      return textResult(
        `Change request #${gate.request.id} submitted: this host is covered by an approval policy and is not live until it is approved.`,
        gate.request as unknown as Record<string, unknown>
      );
    }
    const host = await createProxyHost(input, context.userId);
    const summary = proxyHostSummary(host);
    return textResult(`Created proxy host #${host.id} “${host.name}” for ${host.domains.join(", ")}.`, summary);
  },
};

const updateHostTool: McpTool = {
  name: "update_proxy_host",
  title: "Update a proxy host",
  description:
    "Change a proxy host. Send only the fields to change (the model merges with the stored host); any field of the REST API's PUT passes through. A protected host's change becomes a change request (202).",
  inputSchema: {
    type: "object",
    properties: {
      id: ID_SCHEMA,
      name: { type: "string" },
      domains: { type: "array", items: { type: "string" } },
      upstreams: { type: "array", items: { type: "string" } },
      certificateId: { type: ["integer", "null"] },
      accessListId: { type: ["integer", "null"] },
      sslForced: { type: "boolean" },
      hstsEnabled: { type: "boolean" },
      hstsSubdomains: { type: "boolean" },
      allowWebsocket: { type: "boolean" },
      preserveHostHeader: { type: "boolean" },
      enabled: { type: "boolean" },
      tags: TAGS_SCHEMA,
    },
    required: ["id"],
    additionalProperties: true,
  },
  annotations: { title: "Update a proxy host", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  permission: "proxy_hosts:write",
  handler: async (args, context) => {
    const id = idArg(args);
    const { id: _id, ...changes } = args;
    void _id;
    const existing = await getProxyHostInScope(context.access, id);
    const tags = tagsForWrite(context.access, "proxy_hosts", changes.tags, existing.tags);
    await assertProxyHostWriteAllowed(context.access, changes as Partial<ProxyHostInput>, existing);
    await assertDomainsFreeOutsideScope(
      context.access,
      Array.isArray(changes.domains) ? (changes.domains as string[]) : undefined,
      existing.id
    );
    const input = { ...changes, ...(tags !== undefined ? { tags } : {}) } as Partial<ProxyHostInput>;
    const gate = await gateHostChange({
      access: context.access,
      change: { targetType: "proxy_host", kind: "update", target: existing, input: { host: input } },
    });
    if (gate) {
      return textResult(
        `Change request #${gate.request.id} submitted: this host is covered by an approval policy and is not live until it is approved.`,
        gate.request as unknown as Record<string, unknown>
      );
    }
    const host = await updateProxyHost(existing.id, input, context.userId);
    return textResult(`Updated proxy host #${host.id} “${host.name}”.`, proxyHostSummary(host));
  },
};

const deleteHostTool: McpTool = {
  name: "delete_proxy_host",
  title: "Delete a proxy host",
  description: "Delete a proxy host and stop serving it. A protected host's deletion becomes a change request (202).",
  inputSchema: { type: "object", properties: { id: ID_SCHEMA }, required: ["id"], additionalProperties: false },
  annotations: { title: "Delete a proxy host", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  permission: "proxy_hosts:write",
  handler: async (args, context) => {
    const existing = await getProxyHostInScope(context.access, idArg(args));
    const gate = await gateHostChange({
      access: context.access,
      change: { targetType: "proxy_host", kind: "delete", target: existing, input: {} },
    });
    if (gate) {
      return textResult(
        `Change request #${gate.request.id} submitted: this host is covered by an approval policy; it stays live until the request is approved.`,
        gate.request as unknown as Record<string, unknown>
      );
    }
    await deleteProxyHost(existing.id, context.userId);
    return textResult(`Deleted proxy host #${existing.id} “${existing.name}”.`, { id: existing.id, deleted: true });
  },
};

const createL4Tool: McpTool = {
  name: "create_l4_proxy_host",
  title: "Create an L4 proxy host",
  description:
    "Create a TCP/UDP proxy host. Required: name, protocol, listenAddress and at least one upstream. Matcher, load balancing, health checks, PROXY protocol, geo blocking and tags of the REST API pass through. A protected host becomes a change request (202).",
  inputSchema: {
    type: "object",
    properties: {
      name: { type: "string" },
      protocol: { type: "string", enum: ["tcp", "udp"] },
      listenAddress: { type: "string", description: "The port, or address:port, Caddy listens on." },
      upstreams: { type: "array", items: { type: "string" } },
      matcherType: { type: "string", enum: ["none", "tls_sni", "http_host", "proxy_protocol"] },
      matcherValue: { type: "array", items: { type: "string" } },
      tlsTermination: { type: "boolean" },
      proxyProtocolVersion: { type: ["string", "null"], enum: ["v1", "v2", null] },
      enabled: { type: "boolean" },
      tags: TAGS_SCHEMA,
    },
    required: ["name", "protocol", "listenAddress", "upstreams"],
    additionalProperties: true,
  },
  annotations: { title: "Create an L4 proxy host", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  permission: "l4_proxy_hosts:write",
  handler: async (args, context) => {
    if (typeof args.name !== "string" || args.name.trim() === "") {
      throw new McpError(JSON_RPC.INVALID_PARAMS, "name must be a non-empty string");
    }
    if (args.protocol !== "tcp" && args.protocol !== "udp") {
      throw new McpError(JSON_RPC.INVALID_PARAMS, "protocol must be tcp or udp");
    }
    if (typeof args.listenAddress !== "string" || args.listenAddress.trim() === "") {
      throw new McpError(JSON_RPC.INVALID_PARAMS, "listenAddress must be a non-empty string");
    }
    stringArrayArg(args, "upstreams");
    const tags = tagsForWrite(context.access, "l4_proxy_hosts", args.tags, null);
    assertL4WriteAllowed(context.access, args);
    await assertListenPortFreeOutsideScope(
      context.access,
      stringArg(args, "protocol"),
      stringArg(args, "listenAddress"),
      null
    );
    const input = { ...args, ...(tags !== undefined ? { tags } : {}) } as unknown as L4ProxyHostInput;
    const gate = await gateHostChange({
      access: context.access,
      change: { targetType: "l4_proxy_host", kind: "create", target: null, input: { host: input } },
    });
    if (gate) {
      return textResult(
        `Change request #${gate.request.id} submitted: this host is covered by an approval policy and is not live until it is approved.`,
        gate.request as unknown as Record<string, unknown>
      );
    }
    const host = await createL4ProxyHost(input, context.userId);
    return textResult(`Created L4 proxy host #${host.id} “${host.name}” on ${host.listenAddress}.`, l4HostSummary(host));
  },
};

const updateL4Tool: McpTool = {
  name: "update_l4_proxy_host",
  title: "Update an L4 proxy host",
  description: "Change a TCP/UDP proxy host; send only the fields to change. A protected host's change becomes a change request (202).",
  inputSchema: {
    type: "object",
    properties: {
      id: ID_SCHEMA,
      name: { type: "string" },
      protocol: { type: "string", enum: ["tcp", "udp"] },
      listenAddress: { type: "string" },
      upstreams: { type: "array", items: { type: "string" } },
      matcherType: { type: "string", enum: ["none", "tls_sni", "http_host", "proxy_protocol"] },
      matcherValue: { type: "array", items: { type: "string" } },
      tlsTermination: { type: "boolean" },
      proxyProtocolVersion: { type: ["string", "null"], enum: ["v1", "v2", null] },
      enabled: { type: "boolean" },
      tags: TAGS_SCHEMA,
    },
    required: ["id"],
    additionalProperties: true,
  },
  annotations: { title: "Update an L4 proxy host", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  permission: "l4_proxy_hosts:write",
  handler: async (args, context) => {
    const id = idArg(args);
    const { id: _id, ...changes } = args;
    void _id;
    const existing = await getL4ProxyHostInScope(context.access, id);
    const tags = tagsForWrite(context.access, "l4_proxy_hosts", changes.tags, existing.tags);
    assertL4WriteAllowed(context.access, changes, existing);
    const protocol = typeof changes.protocol === "string" ? changes.protocol : undefined;
    const listenAddress = typeof changes.listenAddress === "string" ? changes.listenAddress : undefined;
    await assertListenPortFreeOutsideScope(
      context.access,
      protocol ?? existing.protocol,
      listenAddress ?? (changes.protocol !== undefined ? existing.listenAddress : undefined),
      existing.id
    );
    const input = { ...changes, ...(tags !== undefined ? { tags } : {}) } as Partial<L4ProxyHostInput>;
    const gate = await gateHostChange({
      access: context.access,
      change: { targetType: "l4_proxy_host", kind: "update", target: existing, input: { host: input } },
    });
    if (gate) {
      return textResult(
        `Change request #${gate.request.id} submitted: this host is covered by an approval policy and is not live until it is approved.`,
        gate.request as unknown as Record<string, unknown>
      );
    }
    const host = await updateL4ProxyHost(existing.id, input, context.userId);
    return textResult(`Updated L4 proxy host #${host.id} “${host.name}”.`, l4HostSummary(host));
  },
};

const deleteL4Tool: McpTool = {
  name: "delete_l4_proxy_host",
  title: "Delete an L4 proxy host",
  description: "Delete a TCP/UDP proxy host. A protected host's deletion becomes a change request (202).",
  inputSchema: { type: "object", properties: { id: ID_SCHEMA }, required: ["id"], additionalProperties: false },
  annotations: { title: "Delete an L4 proxy host", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  permission: "l4_proxy_hosts:write",
  handler: async (args, context) => {
    const existing = await getL4ProxyHostInScope(context.access, idArg(args));
    const gate = await gateHostChange({
      access: context.access,
      change: { targetType: "l4_proxy_host", kind: "delete", target: existing, input: {} },
    });
    if (gate) {
      return textResult(
        `Change request #${gate.request.id} submitted: this host is covered by an approval policy; it stays live until the request is approved.`,
        gate.request as unknown as Record<string, unknown>
      );
    }
    await deleteL4ProxyHost(existing.id, context.userId);
    return textResult(`Deleted L4 proxy host #${existing.id} “${existing.name}”.`, { id: existing.id, deleted: true });
  },
};

const createListTool: McpTool = {
  name: "create_access_list",
  title: "Create an access list",
  description:
    "Create an access list: name, optional basic-auth members, ordered address/country/AS rules, default action and deny settings. Rules are validated by the model.",
  inputSchema: {
    type: "object",
    properties: {
      name: { type: "string" },
      description: { type: ["string", "null"] },
      users: {
        type: "array",
        items: {
          type: "object",
          properties: { username: { type: "string" }, password: { type: "string" } },
          required: ["username", "password"],
        },
        description: "Basic-auth members.",
      },
      rules: { type: "array", items: { type: "object", additionalProperties: true }, description: "Ordered rules." },
      defaultAction: { type: "string", enum: ["allow", "deny"] },
      failClosed: { type: "boolean" },
      denyStatus: { type: "integer", minimum: 400, maximum: 599 },
      denyBody: { type: ["string", "null"] },
    },
    required: ["name"],
    additionalProperties: true,
  },
  annotations: { title: "Create an access list", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  permission: "access_lists:write",
  handler: async (args, context) => {
    if (typeof args.name !== "string" || args.name.trim() === "") {
      throw new McpError(JSON_RPC.INVALID_PARAMS, "name must be a non-empty string");
    }
    const list = await createAccessList(args as unknown as AccessListInput, context.userId);
    return textResult(`Created access list #${list.id} “${list.name}”.`, accessListSummary(list));
  },
};

const updateListTool: McpTool = {
  name: "update_access_list",
  title: "Update an access list",
  description: "Change an access list; send only the fields to change. `rules` replaces the whole ordered rule list.",
  inputSchema: {
    type: "object",
    properties: {
      id: ID_SCHEMA,
      name: { type: "string" },
      description: { type: ["string", "null"] },
      rules: { type: "array", items: { type: "object", additionalProperties: true } },
      defaultAction: { type: "string", enum: ["allow", "deny"] },
      failClosed: { type: "boolean" },
      denyStatus: { type: "integer", minimum: 400, maximum: 599 },
      denyBody: { type: ["string", "null"] },
    },
    required: ["id"],
    additionalProperties: true,
  },
  annotations: { title: "Update an access list", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  permission: "access_lists:write",
  handler: async (args, context) => {
    const id = idArg(args);
    const { id: _id, ...changes } = args;
    void _id;
    const list = await updateAccessList(id, changes as AccessListUpdate, context.userId);
    return textResult(`Updated access list #${list.id} “${list.name}”.`, accessListSummary(list));
  },
};

const deleteListTool: McpTool = {
  name: "delete_access_list",
  title: "Delete an access list",
  description: "Delete an access list. Proxy hosts that use it keep working; the list no longer applies to them.",
  inputSchema: { type: "object", properties: { id: ID_SCHEMA }, required: ["id"], additionalProperties: false },
  annotations: { title: "Delete an access list", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  permission: "access_lists:write",
  handler: async (args, context) => {
    const id = idArg(args);
    await deleteAccessList(id, context.userId);
    return textResult(`Deleted access list #${id}.`, { id, deleted: true });
  },
};

const applyTool: McpTool = {
  name: "apply_caddy_config",
  title: "Apply the Caddy configuration",
  description:
    "Build the configuration from the database and apply it to Caddy. Every host change already applies before it answers; use this after a change was stored but not live (Caddy was unreachable) or to recover from drift.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
  annotations: { title: "Apply the Caddy configuration", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  permission: "settings:write",
  handler: async () => {
    try {
      await applyCaddyConfig();
      return textResult("Caddy serves the current configuration.", { ok: true });
    } catch (error) {
      if (error instanceof CaddyApplyError) {
        return errorResult(
          `Caddy did not take the configuration: ${error.message}`,
          { ok: false, code: error.code, saved: false }
        );
      }
      throw error;
    }
  },
};

export const MCP_TOOLS: readonly McpTool[] = [
  getOverview,
  listHosts,
  getHost,
  listL4Hosts,
  getL4Host,
  listCerts,
  listCertificatesRaw,
  listLists,
  getList,
  listUsersTool,
  listGroupsTool,
  searchTool,
  auditLogTool,
  securityEventsTool,
  trafficTool,
  caddyStatusTool,
  createHostTool,
  updateHostTool,
  deleteHostTool,
  createL4Tool,
  updateL4Tool,
  deleteL4Tool,
  createListTool,
  updateListTool,
  deleteListTool,
  applyTool,
];

export const MCP_TOOL_BY_NAME: ReadonlyMap<string, McpTool> = new Map(MCP_TOOLS.map((tool) => [tool.name, tool]));

/** The public description of a tool (the JSON-RPC tools/list shape). */
export function toolDefinition(tool: McpTool) {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.permission
      ? `${tool.description} Needs the ${tool.permission} permission.`
      : tool.description,
    inputSchema: tool.inputSchema,
    annotations: tool.annotations,
  };
}
