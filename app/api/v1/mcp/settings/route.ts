import { NextRequest, NextResponse } from "next/server";
import { apiErrorResponse, requireApiPermission } from "@/src/lib/api-auth";
import { ApiValidationError } from "@/src/lib/api-errors";
import { logAuditEvent } from "@/src/lib/audit";
import {
  AUTHORIZATION_SERVER_METADATA_PATH,
  baseUrl,
  getMcpSettings,
  MCP_PATH,
  PROTECTED_RESOURCE_METADATA_PATH,
  saveMcpSettings,
  type McpSettings,
} from "@/src/lib/mcp/config";
import { MCP_ADVERTISED_SCOPES } from "@/src/lib/mcp/scopes";
import { MCP_TOOL_BY_NAME } from "@/src/lib/mcp/tools";
import { LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS } from "@/src/lib/mcp/protocol";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function summary(settings: McpSettings) {
  return {
    settings,
    endpoint: `${baseUrl()}${MCP_PATH}`,
    resource: `${baseUrl()}${MCP_PATH}`,
    issuer: baseUrl(),
    protectedResourceMetadata: `${baseUrl()}${PROTECTED_RESOURCE_METADATA_PATH}`,
    authorizationServerMetadata: `${baseUrl()}${AUTHORIZATION_SERVER_METADATA_PATH}`,
    scopes: [...MCP_ADVERTISED_SCOPES],
    protocolVersion: LATEST_PROTOCOL_VERSION,
    protocolVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
    tools: [...MCP_TOOL_BY_NAME.keys()],
  };
}

export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "settings:read");
    return NextResponse.json(summary(await getMcpSettings()));
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function PUT(request: NextRequest) {
  try {
    const { userId } = await requireApiPermission(request, "settings:write");
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      throw new ApiValidationError("Request body must be JSON");
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new ApiValidationError("Request body must be an object");
    }
    const input = body as Record<string, unknown>;
    const current = await getMcpSettings();
    const enabled = input.enabled === undefined ? current.enabled : input.enabled;
    const allowDynamicRegistration =
      input.allowDynamicRegistration === undefined ? current.allowDynamicRegistration : input.allowDynamicRegistration;
    if (typeof enabled !== "boolean") throw new ApiValidationError("enabled must be a boolean");
    if (typeof allowDynamicRegistration !== "boolean") {
      throw new ApiValidationError("allowDynamicRegistration must be a boolean");
    }
    const next: McpSettings = { enabled, allowDynamicRegistration };
    await saveMcpSettings(next);
    await logAuditEvent({
      userId,
      action: "mcp_settings_updated",
      entityType: "settings",
      entityId: null,
      summary: `MCP server ${enabled ? "enabled" : "disabled"}${
        allowDynamicRegistration ? "; client registration open" : "; client registration closed"
      }`,
      data: next,
    });
    return NextResponse.json(summary(next));
  } catch (error) {
    return apiErrorResponse(error);
  }
}
