import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import {
  AUTHORIZATION_SERVER_METADATA_PATH,
  MCP_PATH,
  PROTECTED_RESOURCE_METADATA_PATH,
  baseUrl,
  getMcpSettings,
} from "@/src/lib/mcp/config";
import { listClients, listConnections } from "@/src/lib/mcp/oauth";
import { MCP_ADVERTISED_SCOPES } from "@/src/lib/mcp/scopes";
import { MCP_TOOLS } from "@/src/lib/mcp/tools";
import { LATEST_PROTOCOL_VERSION } from "@/src/lib/mcp/protocol";
import McpPageClient from "./McpPageClient";

export const metadata = { title: "MCP server" };
export const dynamic = "force-dynamic";

/**
 * Settings → MCP server: the endpoint and its discovery documents, the two
 * switches, the OAuth clients that registered themselves and the live grants
 * with their scopes. Guarded by settings:read; changing needs settings:write.
 */
export default async function McpPage() {
  const { access } = await requirePermission("settings:read");
  const [settings, clients, connections] = await Promise.all([
    getMcpSettings(),
    listClients(),
    listConnections(),
  ]);

  return (
    <McpPageClient
      initialSettings={settings}
      canWrite={can(access, "settings:write")}
      clients={clients}
      connections={connections}
      endpoint={`${baseUrl()}${MCP_PATH}`}
      protectedResourceMetadataUrl={`${baseUrl()}${PROTECTED_RESOURCE_METADATA_PATH}`}
      authorizationServerMetadataUrl={`${baseUrl()}${AUTHORIZATION_SERVER_METADATA_PATH}`}
      scopes={[...MCP_ADVERTISED_SCOPES]}
      protocolVersion={LATEST_PROTOCOL_VERSION}
      tools={MCP_TOOLS.map((tool) => ({ name: tool.name, title: tool.title, permission: tool.permission }))}
    />
  );
}
