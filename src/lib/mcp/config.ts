/**
 * The MCP server's public identity: the endpoint clients talk to, the
 * canonical resource URI its tokens are bound to, and the two discovery
 * documents (RFC 9728 protected resource metadata and RFC 8414 authorization
 * server metadata). Everything is built from BASE_URL, never from the Host
 * header of the request, so neither discovery nor audience validation can be
 * steered by a hostile Host.
 */
import { BRAND_NAME, documentationUrl } from "../brand";
import { APP_VERSION } from "../app-version";
import { config } from "../config";
import { getSetting, setSetting } from "../settings";
import { MCP_ADVERTISED_SCOPES } from "./scopes";

/** The MCP endpoint, below the API like every other machine-facing route. */
export const MCP_PATH = "/api/mcp";

/** Well-known URIs (served through rewrites in next.config.mjs). */
export const PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";
export const AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";

const SETTINGS_KEY = "mcp";

export type McpSettings = {
  /** Whether the MCP endpoint and the OAuth endpoints answer at all. */
  enabled: boolean;
  /** Whether MCP clients may register themselves (RFC 7591 dynamic registration). */
  allowDynamicRegistration: boolean;
};

export const DEFAULT_MCP_SETTINGS: McpSettings = {
  enabled: true,
  allowDynamicRegistration: true,
};

export function baseUrl(): string {
  return config.baseUrl.replace(/\/+$/, "");
}

/** The canonical URI of the MCP server: what `resource` names and what tokens are bound to. */
export function mcpResourceUrl(): string {
  return `${baseUrl()}${MCP_PATH}`;
}

/** Where a 401 sends clients to discover the authorization server (RFC 9728 §5.1). */
export function protectedResourceMetadataUrl(): string {
  return `${baseUrl()}${PROTECTED_RESOURCE_METADATA_PATH}`;
}

export function issuerUrl(): string {
  return baseUrl();
}

/** Reads the stored settings; both switches are on unless an administrator turned them off. */
export async function getMcpSettings(): Promise<McpSettings> {
  const stored = await getSetting<Partial<McpSettings>>(SETTINGS_KEY);
  return {
    enabled: typeof stored?.enabled === "boolean" ? stored.enabled : DEFAULT_MCP_SETTINGS.enabled,
    allowDynamicRegistration:
      typeof stored?.allowDynamicRegistration === "boolean"
        ? stored.allowDynamicRegistration
        : DEFAULT_MCP_SETTINGS.allowDynamicRegistration,
  };
}

export async function saveMcpSettings(settings: McpSettings): Promise<void> {
  await setSetting<McpSettings>(SETTINGS_KEY, {
    enabled: settings.enabled,
    allowDynamicRegistration: settings.allowDynamicRegistration,
  });
}

/** The RFC 9728 document, for the MCP endpoint and its path-specific well-known URI. */
export function protectedResourceMetadata() {
  return {
    resource: mcpResourceUrl(),
    authorization_servers: [issuerUrl()],
    scopes_supported: [...MCP_ADVERTISED_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: `${BRAND_NAME} MCP server`,
    resource_documentation: documentationUrl("documentation/mcp.md"),
  };
}

/** The RFC 8414 document. `iss` is echoed in authorization responses (RFC 9207). */
export function authorizationServerMetadata() {
  const issuer = issuerUrl();
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    registration_endpoint: `${issuer}/api/oauth/register`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    service_documentation: documentationUrl("documentation/mcp.md"),
    scopes_supported: [...MCP_ADVERTISED_SCOPES],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    revocation_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    // Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document)
    // are not fetched: a self-hosted proxy must not turn a client-supplied URL
    // into an outbound request. Dynamic registration is offered instead.
    client_id_metadata_document_supported: false,
    mcp_protocol_versions_supported: ["2025-11-25", "2025-06-18", "2025-03-26"],
    server_version: APP_VERSION,
  };
}
