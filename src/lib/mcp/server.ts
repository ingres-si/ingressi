/**
 * The MCP endpoint: Streamable HTTP transport (stateless), JSON-RPC dispatch,
 * bearer-token authentication and the scope checks.
 *
 * Stateless on purpose: every POST carries the whole request, so several
 * dashboard replicas can answer any of them without shared session state.
 * That means GET (server-initiated SSE) and DELETE (session termination)
 * answer 405, which the transport spec allows, and no MCP-Session-Id is
 * issued.
 *
 * Authentication follows the MCP authorization spec (2025-11-25): every
 * request needs `Authorization: Bearer`, tokens must have been issued for this
 * resource, a missing or invalid token answers 401 with a WWW-Authenticate
 * that points at the protected resource metadata, and a token whose scopes do
 * not cover a tool answers 403 with `error="insufficient_scope"` so the
 * client can step up.
 */
import { randomUUID } from "node:crypto";
import { can, type Access } from "../permissions";
import { applyTokenScopes } from "../api-token-scopes";
import { accessForUser } from "@/ee/custom-roles/access";
import { getUserById } from "../models/user";
import { ApiClientError } from "../api-errors";
import { CaddyApplyError } from "../caddy-apply-error";
import { APP_VERSION } from "../app-version";
import { BRAND_NAME, documentationUrl } from "../brand";
import { baseUrl, getMcpSettings, mcpResourceUrl, protectedResourceMetadataUrl } from "./config";
import {
  expandScopes,
  MCP_ADVERTISED_SCOPES,
  scopeString,
  stepUpScopes,
} from "./scopes";
import {
  JSON_RPC,
  McpError,
  errorResult,
  isRecord,
  isSupportedProtocolVersion,
  jsonRpcError,
  jsonRpcResult,
  negotiateProtocolVersion,
  type JsonRpcId,
} from "./protocol";
import { MCP_TOOL_BY_NAME, toolDefinition, type McpToolContext } from "./tools";
import { listResourceTemplates, listResources, readResource } from "./resources";
import { getPrompt, listPrompts } from "./prompts";
import { OAuthError, validateAccessToken, type ValidatedAccessToken } from "./oauth";

const MAX_BODY_BYTES = 1_000_000;
const CORS_ALLOWED_METHODS = "POST, OPTIONS";

function corsHeaders(): Record<string, string> {
  return {
    // No Access-Control-Allow-Origin: MCP clients call this endpoint from a
    // server, and a credential-bearing endpoint must not be usable from an
    // arbitrary web page. OPTIONS is answered for non-browser clients.
    Allow: CORS_ALLOWED_METHODS,
    "Access-Control-Allow-Methods": CORS_ALLOWED_METHODS,
    "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version, Accept, Last-Event-ID",
    "Access-Control-Max-Age": "600",
  };
}

function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function challenge(options: {
  error?: "invalid_token" | "insufficient_scope";
  description?: string;
  scope?: string;
}): string {
  const parts = [`Bearer resource_metadata=${quote(protectedResourceMetadataUrl())}`];
  if (options.error) parts.push(`error=${quote(options.error)}`);
  if (options.description) parts.push(`error_description=${quote(options.description)}`);
  if (options.scope) parts.push(`scope=${quote(options.scope)}`);
  return parts.join(", ");
}

function jsonResponse(id: JsonRpcId, value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

function errorResponse(
  id: JsonRpcId,
  status: number,
  code: number,
  message: string,
  headers: Record<string, string> = {},
  data?: unknown
): Response {
  return jsonResponse(id, jsonRpcError(id, code, message, data), status, headers);
}

function emptyResponse(status: number, headers: Record<string, string> = {}): Response {
  return new Response(null, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
}

/** Whether an Origin header may talk to this endpoint (DNS-rebinding defence). */
function originAllowed(origin: string): boolean {
  try {
    return new URL(origin).origin === new URL(baseUrl()).origin;
  } catch {
    return false;
  }
}

class InsufficientScope extends Error {
  readonly scopes: string[];

  constructor(scopes: string[]) {
    super("insufficient_scope");
    this.name = "InsufficientScope";
    this.scopes = scopes;
  }
}

type Authenticated = {
  userId: number;
  userAccess: Access;
  tokenAccess: Access;
  token: ValidatedAccessToken;
  scopes: string[];
  clientId: string;
  clientName: string;
  userName: string;
};

async function authenticate(request: Request): Promise<Authenticated | Response> {
  const authorization = request.headers.get("authorization");
  if (!authorization) {
    return errorResponse(
      null,
      401,
      JSON_RPC.UNAUTHORIZED,
      "Authorization required",
      { "WWW-Authenticate": challenge({ scope: scopeString(MCP_ADVERTISED_SCOPES) }) }
    );
  }
  if (!authorization.startsWith("Bearer ")) {
    return errorResponse(
      null,
      401,
      JSON_RPC.UNAUTHORIZED,
      "Only Bearer tokens are accepted",
      { "WWW-Authenticate": challenge({ error: "invalid_token", description: "Only Bearer tokens are accepted" }) }
    );
  }
  const raw = authorization.slice(7).trim();
  if (!raw) {
    return errorResponse(
      null,
      401,
      JSON_RPC.UNAUTHORIZED,
      "Invalid Bearer token",
      { "WWW-Authenticate": challenge({ error: "invalid_token", description: "The access token is missing" }) }
    );
  }

  const token = await validateAccessToken(raw);
  if (!token) {
    return errorResponse(
      null,
      401,
      JSON_RPC.UNAUTHORIZED,
      "Invalid or expired access token",
      { "WWW-Authenticate": challenge({ error: "invalid_token", description: "The access token is invalid or expired" }) }
    );
  }
  // Tokens are audience-bound (RFC 8707): one issued for another resource is
  // not accepted here, even if this instance issued it.
  if (token.resource !== mcpResourceUrl()) {
    return errorResponse(
      null,
      401,
      JSON_RPC.UNAUTHORIZED,
      "The access token was issued for another resource",
      { "WWW-Authenticate": challenge({ error: "invalid_token", description: "The access token was issued for another resource" }) }
    );
  }

  const user = await getUserById(token.userId);
  if (!user || user.status !== "active") {
    return errorResponse(
      null,
      401,
      JSON_RPC.UNAUTHORIZED,
      "The account is not active",
      { "WWW-Authenticate": challenge({ error: "invalid_token", description: "The account is not active" }) }
    );
  }

  const userAccess = await accessForUser({
    id: user.id,
    role: user.role,
    customRoleId: user.customRoleId ?? null,
  });
  const expanded = expandScopes(userAccess, token.scopes);
  const tokenAccess = applyTokenScopes(userAccess, expanded);

  return {
    userId: user.id,
    userAccess,
    tokenAccess,
    token,
    scopes: token.scopes,
    clientId: token.clientId,
    clientName: token.clientName,
    userName: user.name ?? user.email,
  };
}

function instructions(): string {
  return [
    `${BRAND_NAME} manages a self-hosted Caddy reverse proxy.`,
    "Tools read and change proxy hosts, L4 hosts, access lists and certificates, and read analytics, security events and the audit log.",
    "Every tool acts with the permissions of the signed-in account, narrowed by the scopes approved during authorization; a change the account cannot make is refused.",
    "Host changes are applied to Caddy before a tool answers. A change that is stored but not live returns isError with saved: true; call get_caddy_status to see why, and apply_caddy_config after fixing it.",
    "A host covered by a change-approval policy returns a change request instead of changing anything; say so instead of retrying.",
    `Documentation: ${documentationUrl("documentation/mcp.md")}`,
  ].join("\n");
}

async function dispatch(
  request: { id: JsonRpcId; method: string; params?: unknown },
  auth: Authenticated
): Promise<{ result: unknown } | { notification: true }> {
  const params = isRecord(request.params) ? request.params : {};
  const context: McpToolContext = {
    access: auth.tokenAccess,
    userId: auth.userId,
    userName: auth.userName,
    clientName: auth.clientName,
    scopes: auth.scopes,
  };

  switch (request.method) {
    case "initialize":
      return {
        result: {
          protocolVersion: negotiateProtocolVersion(params.protocolVersion),
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
            prompts: { listChanged: false },
          },
          serverInfo: {
            name: "ingressi",
            title: `${BRAND_NAME} MCP server`,
            version: APP_VERSION,
            websiteUrl: documentationUrl("documentation/mcp.md"),
          },
          instructions: instructions(),
        },
      };

    case "ping":
      return { result: {} };

    case "logging/setLevel":
      // No logging capability is advertised; accepting the call is harmless
      // and keeps clients that always send it working.
      return { result: {} };

    case "tools/list":
      return { result: { tools: [...MCP_TOOL_BY_NAME.values()].map(toolDefinition) } };

    case "tools/call": {
      const name = params.name;
      if (typeof name !== "string" || name.length > 100) {
        throw new McpError(JSON_RPC.INVALID_PARAMS, "name must be a string of at most 100 characters");
      }
      const tool = MCP_TOOL_BY_NAME.get(name);
      if (!tool) throw new McpError(JSON_RPC.INVALID_PARAMS, `Unknown tool: ${name}`);
      const args = params.arguments === undefined || params.arguments === null ? {} : params.arguments;
      if (!isRecord(args)) throw new McpError(JSON_RPC.INVALID_PARAMS, "arguments must be an object");

      if (tool.permission !== null && !can(auth.tokenAccess, tool.permission)) {
        // The user holds it, but the token's scopes do not: step up.
        const stepUp = stepUpScopes(auth.userAccess, auth.scopes, tool.permission);
        if (stepUp) throw new InsufficientScope(stepUp);
        return {
          result: errorResult(
            `Your account does not hold the permission ${tool.permission}, so this MCP client cannot do this even with a new authorization. Ask an administrator for a role that includes it.`,
            { requiredPermission: tool.permission, reason: "permission" }
          ),
        };
      }

      try {
        const result = await tool.handler(args, context);
        return { result };
      } catch (error) {
        if (error instanceof McpError) throw error;
        if (error instanceof ApiClientError) {
          return { result: errorResult(error.message, { status: error.status }) };
        }
        // Stored, but Caddy did not take it: say so instead of "internal
        // error", and point at the status tool as the REST API does.
        if (error instanceof CaddyApplyError) {
          const id = error.proxyHostId ?? error.l4ProxyHostId;
          return {
            result: errorResult(
              `Saved, but not live yet: ${error.message}. Call get_caddy_status to see why, then apply_caddy_config after fixing it.`,
              { saved: true, code: error.code, ...(id === undefined ? {} : { id }) }
            ),
          };
        }
        // Several model functions predate ApiClientError and answer with a
        // "<resource> not found" message; keep that meaning instead of
        // turning it into an internal error.
        if (error instanceof Error && error.message.trim().toLowerCase().endsWith("not found")) {
          return { result: errorResult(error.message, { status: 404 }) };
        }
        throw error;
      }
    }

    case "resources/list":
      return { result: { resources: listResources(auth.tokenAccess) } };

    case "resources/templates/list":
      return { result: { resourceTemplates: listResourceTemplates(auth.tokenAccess) } };

    case "resources/read": {
      const uri = params.uri;
      if (typeof uri !== "string" || uri.trim() === "" || uri.length > 2_000) {
        throw new McpError(JSON_RPC.INVALID_PARAMS, "uri must be a string of at most 2000 characters");
      }
      return { result: { contents: [await readResource(uri, context)] } };
    }

    case "prompts/list":
      return { result: { prompts: listPrompts() } };

    case "prompts/get": {
      const name = params.name;
      if (typeof name !== "string" || name.length > 100) {
        throw new McpError(JSON_RPC.INVALID_PARAMS, "name must be a string of at most 100 characters");
      }
      const args: Record<string, string> = {};
      if (params.arguments !== undefined && params.arguments !== null) {
        if (!isRecord(params.arguments)) throw new McpError(JSON_RPC.INVALID_PARAMS, "arguments must be an object");
        for (const [key, value] of Object.entries(params.arguments)) {
          if (typeof value !== "string") throw new McpError(JSON_RPC.INVALID_PARAMS, `arguments.${key} must be a string`);
          if (key.length > 100 || value.length > 5_000) {
            throw new McpError(JSON_RPC.INVALID_PARAMS, "A prompt argument is too long");
          }
          args[key] = value;
        }
      }
      const prompt = getPrompt(name, args);
      if (!prompt) throw new McpError(JSON_RPC.INVALID_PARAMS, `Unknown prompt: ${name}`);
      if (!prompt.ok) throw new McpError(JSON_RPC.INVALID_PARAMS, prompt.error);
      return { result: { description: prompt.description, messages: prompt.messages } };
    }

    default:
      // Notifications never reach dispatch (the transport answers 202 for a
      // message without an id), so a "notifications/*" message with an id is
      // a request for a method this server does not implement.
      throw new McpError(JSON_RPC.METHOD_NOT_FOUND, `Method not found: ${request.method.slice(0, 100)}`);
  }
}

/**
 * POST /api/mcp: one JSON-RPC message per request.
 * The route handlers in app/api/mcp/route.ts only call this.
 */
export async function handleMcpRequest(request: Request): Promise<Response> {
  const settings = await getMcpSettings();
  if (!settings.enabled) {
    return errorResponse(null, 404, JSON_RPC.INVALID_REQUEST, "The MCP server is disabled on this instance");
  }

  const origin = request.headers.get("origin");
  if (origin && !originAllowed(origin)) {
    return errorResponse(null, 403, JSON_RPC.INVALID_REQUEST, "Origin not allowed");
  }

  const method = request.method.toUpperCase();
  if (method === "OPTIONS") return emptyResponse(204, corsHeaders());
  if (method === "GET" || method === "DELETE") {
    // No server-initiated SSE stream and no stateful session to terminate.
    return emptyResponse(405, { Allow: CORS_ALLOWED_METHODS });
  }
  if (method !== "POST") {
    return errorResponse(null, 405, JSON_RPC.INVALID_REQUEST, "Method not allowed", { Allow: CORS_ALLOWED_METHODS });
  }

  // Tokens must never travel in the query string (RFC 6750 §2.3).
  if (new URL(request.url).searchParams.has("access_token")) {
    return errorResponse(null, 400, JSON_RPC.INVALID_REQUEST, "Access tokens must be sent in the Authorization header");
  }

  const protocolVersion = request.headers.get("mcp-protocol-version");
  if (protocolVersion !== null && !isSupportedProtocolVersion(protocolVersion)) {
    return errorResponse(
      null,
      400,
      JSON_RPC.INVALID_REQUEST,
      `Unsupported MCP-Protocol-Version: ${protocolVersion.slice(0, 40)}`
    );
  }

  const accept = request.headers.get("accept");
  if (accept && !accept.includes("application/json") && !accept.includes("*/*")) {
    return errorResponse(null, 406, JSON_RPC.INVALID_REQUEST, "This endpoint answers application/json");
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return errorResponse(null, 415, JSON_RPC.INVALID_REQUEST, "Content-Type must be application/json");
  }

  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return errorResponse(null, 413, JSON_RPC.INVALID_REQUEST, "Request body too large");
  }

  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;

  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return errorResponse(null, 400, JSON_RPC.PARSE_ERROR, "Could not read the request body");
  }
  if (raw.length > MAX_BODY_BYTES) {
    return errorResponse(null, 413, JSON_RPC.INVALID_REQUEST, "Request body too large");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return errorResponse(null, 400, JSON_RPC.PARSE_ERROR, "Parse error");
  }

  if (Array.isArray(parsed)) {
    return errorResponse(null, 400, JSON_RPC.INVALID_REQUEST, "JSON-RPC batching is not supported");
  }
  if (!isRecord(parsed)) {
    return errorResponse(null, 400, JSON_RPC.INVALID_REQUEST, "Expected one JSON-RPC message");
  }

  // A response from the client: this server sends no requests, so accept it
  // and carry on. (Streamable HTTP: 202 with no body.)
  if (!("method" in parsed) && ("result" in parsed || "error" in parsed)) {
    return emptyResponse(202);
  }

  if (parsed.jsonrpc !== "2.0" || typeof parsed.method !== "string" || parsed.method.trim() === "") {
    return errorResponse(null, 400, JSON_RPC.INVALID_REQUEST, "Invalid JSON-RPC request");
  }

  const hasId = Object.prototype.hasOwnProperty.call(parsed, "id");
  const rawId = parsed.id;
  const id: JsonRpcId = rawId === undefined || rawId === null
    ? null
    : typeof rawId === "string" || typeof rawId === "number"
      ? rawId
      : null;
  if (hasId && id === null && rawId !== null && rawId !== undefined) {
    return errorResponse(null, 400, JSON_RPC.INVALID_REQUEST, "id must be a string, a number or null");
  }

  const message = { id, method: parsed.method, params: parsed.params };

  if (!hasId) {
    // Notifications (initialized, cancelled, roots/list_changed) are accepted
    // and ignored: this server keeps no session state.
    return emptyResponse(202);
  }

  try {
    const outcome = await dispatch(message, auth);
    if ("notification" in outcome) return emptyResponse(202);
    return jsonResponse(id, jsonRpcResult(id, outcome.result));
  } catch (error) {
    if (error instanceof InsufficientScope) {
      return errorResponse(
        id,
        403,
        JSON_RPC.FORBIDDEN,
        "The access token's scopes do not cover this operation",
        {
          "WWW-Authenticate": challenge({
            error: "insufficient_scope",
            scope: scopeString(error.scopes),
            description: "The access token's scopes do not cover this operation",
          }),
        },
        { requiredScopes: error.scopes }
      );
    }
    if (error instanceof McpError) {
      const status = error.code === JSON_RPC.INVALID_REQUEST ? 400 : 200;
      return errorResponse(id, status, error.code, error.message, {}, error.data);
    }
    if (error instanceof OAuthError) {
      return errorResponse(id, error.status, JSON_RPC.UNAUTHORIZED, error.message, error.headers);
    }
    if (error instanceof ApiClientError) {
      return errorResponse(id, error.status, JSON_RPC.INVALID_PARAMS, error.message);
    }
    // Never reflect an unexpected message, a stack or a query into the reply.
    const errorId = randomUUID();
    console.error("Unexpected MCP failure", {
      errorId,
      errorType: error instanceof Error ? error.name : typeof error,
    });
    return errorResponse(id, 200, JSON_RPC.INTERNAL_ERROR, "Internal server error", {}, { errorId });
  }
}

