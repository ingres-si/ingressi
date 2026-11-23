/**
 * MCP resources: read-only views of the instance as JSON, plus templates for
 * one host, L4 host or access list. Each resource names the permission it
 * needs; a caller without it gets "resource not found", never a partial view.
 */
import { can, type Access, type Permission } from "../permissions";
import { ApiClientError } from "../api-errors";
import { McpError, JSON_RPC, jsonText, type CallToolResult } from "./protocol";
import { MCP_TOOL_BY_NAME, type McpToolContext } from "./tools";

export type McpResourceDefinition = {
  uri: string;
  name: string;
  description: string;
  mimeType: "application/json";
  permission: Permission | null;
  /** The tool whose handler produces the content. */
  tool: string;
  /** Arguments merged into the tool call. */
  args?: Record<string, unknown>;
};

export type McpResourceTemplate = {
  uriTemplate: string;
  name: string;
  description: string;
  mimeType: "application/json";
  permission: Permission | null;
  tool: string;
  /** The argument the template's path segment fills. */
  argument: string;
  pattern: RegExp;
};

export const MCP_RESOURCES: readonly McpResourceDefinition[] = [
  {
    uri: "ingressi://overview",
    name: "Instance overview",
    description: "What needs attention, traffic, busiest hosts, nodes and recent changes.",
    mimeType: "application/json",
    permission: null,
    tool: "get_overview",
    args: { range: "24h" },
  },
  {
    uri: "ingressi://proxy-hosts",
    name: "Proxy hosts",
    description: "Every HTTP/HTTPS proxy host the caller may read, with domains, upstreams and tags.",
    mimeType: "application/json",
    permission: "proxy_hosts:read",
    tool: "list_proxy_hosts",
    args: { limit: 200 },
  },
  {
    uri: "ingressi://l4-proxy-hosts",
    name: "L4 proxy hosts",
    description: "Every TCP/UDP proxy host the caller may read.",
    mimeType: "application/json",
    permission: "l4_proxy_hosts:read",
    tool: "list_l4_proxy_hosts",
    args: { limit: 200 },
  },
  {
    uri: "ingressi://certificates",
    name: "Certificates",
    description: "Certificate status: ACME, imported and managed rows, with expiry and renewal state.",
    mimeType: "application/json",
    permission: "certificates:read",
    tool: "list_certificates",
    args: { limit: 200 },
  },
  {
    uri: "ingressi://access-lists",
    name: "Access lists",
    description: "Access lists and the global Blocked sources list, summarized.",
    mimeType: "application/json",
    permission: "access_lists:read",
    tool: "list_access_lists",
    args: { limit: 200 },
  },
  {
    uri: "ingressi://audit-log",
    name: "Audit log",
    description: "The 100 most recent audit events.",
    mimeType: "application/json",
    permission: "audit_log:read",
    tool: "list_audit_events",
    args: { limit: 100 },
  },
];

export const MCP_RESOURCE_TEMPLATES: readonly McpResourceTemplate[] = [
  {
    uriTemplate: "ingressi://proxy-hosts/{id}",
    name: "Proxy host",
    description: "One proxy host in full.",
    mimeType: "application/json",
    permission: "proxy_hosts:read",
    tool: "get_proxy_host",
    argument: "id",
    pattern: /^ingressi:\/\/proxy-hosts\/(\d{1,10})$/,
  },
  {
    uriTemplate: "ingressi://l4-proxy-hosts/{id}",
    name: "L4 proxy host",
    description: "One TCP/UDP proxy host in full.",
    mimeType: "application/json",
    permission: "l4_proxy_hosts:read",
    tool: "get_l4_proxy_host",
    argument: "id",
    pattern: /^ingressi:\/\/l4-proxy-hosts\/(\d{1,10})$/,
  },
  {
    uriTemplate: "ingressi://access-lists/{id}",
    name: "Access list",
    description: "One access list with its ordered rules.",
    mimeType: "application/json",
    permission: "access_lists:read",
    tool: "get_access_list",
    argument: "id",
    pattern: /^ingressi:\/\/access-lists\/(\d{1,10})$/,
  },
];

/** The resources a caller may see (resources/list). */
export function listResources(access: Access) {
  return MCP_RESOURCES
    .filter((resource) => resource.permission === null || can(access, resource.permission))
    .map(({ uri, name, description, mimeType }) => ({ uri, name, description, mimeType }));
}

export function listResourceTemplates(access: Access) {
  return MCP_RESOURCE_TEMPLATES
    .filter((template) => template.permission === null || can(access, template.permission))
    .map(({ uriTemplate, name, description, mimeType }) => ({ uriTemplate, name, description, mimeType }));
}

function notFound(): never {
  // The same answer for a missing row and one the caller may not read: a
  // resource URI must not confirm that a host exists.
  throw new McpError(JSON_RPC.RESOURCE_NOT_FOUND, "Resource not found");
}

async function run(toolName: string, args: Record<string, unknown>, context: McpToolContext): Promise<CallToolResult> {
  const tool = MCP_TOOL_BY_NAME.get(toolName);
  if (!tool) notFound();
  if (tool.permission !== null && !can(context.access, tool.permission)) notFound();
  try {
    return await tool.handler(args, context);
  } catch (error) {
    // A missing row, one outside the caller's tag scope and a permission the
    // caller lacks all read the same: the resource does not exist for them.
    if (error instanceof ApiClientError) notFound();
    if (error instanceof Error && error.message.trim().toLowerCase().endsWith("not found")) notFound();
    throw error;
  }
}

/** resources/read for a URI, or "resource not found". */
export async function readResource(uri: string, context: McpToolContext): Promise<{ uri: string; mimeType: string; text: string }> {
  const resource = MCP_RESOURCES.find((candidate) => candidate.uri === uri);
  if (resource) {
    if (resource.permission !== null && !can(context.access, resource.permission)) notFound();
    const result = await run(resource.tool, resource.args ?? {}, context);
    const data = result.structuredContent ?? { text: result.content.map((item) => item.text).join("\n") };
    return { uri, mimeType: resource.mimeType, text: jsonText(data) };
  }
  for (const template of MCP_RESOURCE_TEMPLATES) {
    const match = template.pattern.exec(uri);
    if (!match) continue;
    if (template.permission !== null && !can(context.access, template.permission)) notFound();
    const result = await run(template.tool, { [template.argument]: Number(match[1]) }, context);
    const data = result.structuredContent ?? { text: result.content.map((item) => item.text).join("\n") };
    return { uri, mimeType: template.mimeType, text: jsonText(data) };
  }
  return notFound();
}
