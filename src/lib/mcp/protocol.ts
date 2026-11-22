/**
 * The MCP JSON-RPC protocol, as far as this server implements it: message
 * shapes, the error codes, version negotiation, and the result envelope for
 * tools. The transport (Streamable HTTP) is in server.ts; the methods are
 * dispatched there too.
 *
 * Spec: https://modelcontextprotocol.io/specification/2025-11-25
 */

/** The version this server implements, and the ones it still accepts. */
export const LATEST_PROTOCOL_VERSION = "2025-11-25";
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"] as const;
/** Assumed when a request carries no MCP-Protocol-Version header (transports spec). */
export const FALLBACK_PROTOCOL_VERSION = "2025-03-26";

export type JsonRpcId = string | number | null;

export type JsonRpcRequest = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: string;
  params?: unknown;
};

export type JsonRpcNotification = {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
};

export type JsonRpcErrorObject = {
  code: number;
  message: string;
  data?: unknown;
};

export type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: JsonRpcErrorObject;
};

export const JSON_RPC = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  RESOURCE_NOT_FOUND: -32002,
  /** No credentials, or a token that does not validate (HTTP 401). */
  UNAUTHORIZED: -32001,
  /** Valid token, not enough scope for this operation (HTTP 403). */
  FORBIDDEN: -32003,
} as const;

/** A JSON-RPC error the dispatcher turns into an error response. */
export class McpError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "McpError";
    this.code = code;
    this.data = data;
  }
}

export function jsonRpcError(id: JsonRpcId, code: number, message: string, data?: unknown): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: data === undefined ? { code, message } : { code, message, data },
  };
}

export function jsonRpcResult(id: JsonRpcId, result: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The protocol version to answer an initialize request with. */
export function negotiateProtocolVersion(requested: unknown): string {
  return typeof requested === "string" && (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
    ? requested
    : LATEST_PROTOCOL_VERSION;
}

/** Whether an MCP-Protocol-Version header names a version this server speaks. */
export function isSupportedProtocolVersion(value: string): boolean {
  return (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(value);
}

/**
 * The MCP `CallToolResult`: text for every client, structured content for
 * those that understand it. MCP requires structuredContent to be an object;
 * lists are wrapped by the tool layer before they arrive here.
 */
export type CallToolResult = {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

export function textResult(text: string, structuredContent?: Record<string, unknown>): CallToolResult {
  return structuredContent === undefined
    ? { content: [{ type: "text", text }] }
    : { content: [{ type: "text", text }], structuredContent };
}

export function errorResult(text: string, structuredContent?: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: "text", text }],
    ...(structuredContent === undefined ? {} : { structuredContent }),
    isError: true,
  };
}

/** A compact JSON rendering for tool text output, with a size guard. */
export function jsonText(value: unknown, maxLength = 20_000): string {
  const text = JSON.stringify(value, null, 2) ?? "null";
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}\n… (truncated)`;
}
