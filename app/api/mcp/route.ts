import { handleMcpRequest } from "@/src/lib/mcp/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The MCP endpoint (Streamable HTTP, stateless). The transport and the
 * authorization checks live in src/lib/mcp/server.ts, so this file only
 * hands the Web Request over and answers every method the spec defines.
 */
export async function POST(request: Request) {
  return handleMcpRequest(request);
}

export async function GET(request: Request) {
  // No server-initiated SSE stream: 405, as the transport spec allows.
  return handleMcpRequest(request);
}

export async function DELETE(request: Request) {
  // No MCP-Session-Id, so nothing to terminate: 405.
  return handleMcpRequest(request);
}

export async function OPTIONS(request: Request) {
  return handleMcpRequest(request);
}
