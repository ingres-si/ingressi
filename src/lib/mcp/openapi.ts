/**
 * The OpenAPI document's MCP section: the management endpoints behind
 * Settings → MCP server. The MCP endpoint itself speaks JSON-RPC, not REST,
 * so it is documented in documentation/mcp.md rather than here.
 */

export const MCP_OPENAPI_TAG = {
  name: "MCP",
  description: "The MCP server: availability, registered OAuth clients and connected apps",
} as const;

const settingsSchema = { $ref: "#/components/schemas/McpSettings" };

export const MCP_OPENAPI_PATHS = {
  "/api/v1/mcp/settings": {
    get: {
      tags: ["MCP"],
      summary: "MCP server availability and endpoints",
      description:
        "The endpoint and discovery URLs, the advertised scopes and tools, and the two switches. Requires settings:read.",
      operationId: "getMcpSettings",
      responses: {
        "200": {
          description: "MCP server summary",
          content: { "application/json": { schema: { $ref: "#/components/schemas/McpServerSummary" } } },
        },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
      },
    },
    put: {
      tags: ["MCP"],
      summary: "Turn the MCP server or client registration on or off",
      description:
        "Requires settings:write. Turning the server off makes the endpoint, its discovery documents and the OAuth endpoints answer 404; stored grants keep working when it is turned back on.",
      operationId: "updateMcpSettings",
      requestBody: {
        required: true,
        content: { "application/json": { schema: settingsSchema } },
      },
      responses: {
        "200": {
          description: "Updated summary",
          content: { "application/json": { schema: { $ref: "#/components/schemas/McpServerSummary" } } },
        },
        "400": { $ref: "#/components/responses/BadRequest" },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
      },
    },
  },
  "/api/v1/mcp/clients": {
    get: {
      tags: ["MCP"],
      summary: "List MCP OAuth clients",
      description: "Clients that registered dynamically, with their redirect URIs and live grant count. Requires settings:read.",
      operationId: "listMcpClients",
      responses: {
        "200": {
          description: "Registered clients",
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["clients"],
                properties: { clients: { type: "array", items: { $ref: "#/components/schemas/McpClient" } } },
              },
            },
          },
        },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
      },
    },
  },
  "/api/v1/mcp/clients/{clientId}": {
    delete: {
      tags: ["MCP"],
      summary: "Revoke an MCP client",
      description: "Requires settings:write. Revokes every token issued through the client and drops the consent it holds.",
      operationId: "revokeMcpClient",
      parameters: [
        { name: "clientId", in: "path", required: true, schema: { type: "string", pattern: "^mcp_[A-Za-z0-9_-]{10,80}$" } },
      ],
      responses: {
        "200": { description: "Revoked" },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
        "404": { $ref: "#/components/responses/NotFound" },
      },
    },
  },
  "/api/v1/mcp/connections": {
    get: {
      tags: ["MCP"],
      summary: "List live MCP grants",
      description:
        "One row per live grant: client, account, scopes, resource, last use and refresh expiry. Requires settings:read.",
      operationId: "listMcpConnections",
      responses: {
        "200": {
          description: "Live grants",
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["connections"],
                properties: {
                  connections: { type: "array", items: { $ref: "#/components/schemas/McpConnection" } },
                },
              },
            },
          },
        },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
      },
    },
  },
  "/api/v1/mcp/connections/{id}": {
    delete: {
      tags: ["MCP"],
      summary: "Disconnect an MCP grant",
      description: "Requires settings:write. Revokes the grant's access and refresh tokens (the whole rotation family).",
      operationId: "revokeMcpConnection",
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer", minimum: 1 } }],
      responses: {
        "200": { description: "Disconnected" },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
        "404": { $ref: "#/components/responses/NotFound" },
      },
    },
  },
} as const;

export const MCP_OPENAPI_SCHEMAS = {
  McpSettings: {
    type: "object",
    required: ["enabled", "allowDynamicRegistration"],
    properties: {
      enabled: { type: "boolean", description: "Whether the MCP endpoint and its OAuth endpoints answer." },
      allowDynamicRegistration: {
        type: "boolean",
        description: "Whether MCP clients may register themselves (RFC 7591).",
      },
    },
  },
  McpServerSummary: {
    type: "object",
    required: ["settings", "endpoint", "issuer", "scopes", "tools"],
    properties: {
      settings: { $ref: "#/components/schemas/McpSettings" },
      endpoint: { type: "string", format: "uri", description: "The MCP endpoint clients connect to." },
      resource: { type: "string", format: "uri", description: "The canonical resource URI tokens are bound to." },
      issuer: { type: "string", format: "uri" },
      protectedResourceMetadata: { type: "string", format: "uri" },
      authorizationServerMetadata: { type: "string", format: "uri" },
      scopes: { type: "array", items: { type: "string" } },
      protocolVersion: { type: "string" },
      protocolVersions: { type: "array", items: { type: "string" } },
      tools: { type: "array", items: { type: "string" } },
    },
  },
  McpClient: {
    type: "object",
    required: ["clientId", "name", "redirectUris", "createdAt", "activeGrants"],
    properties: {
      clientId: { type: "string" },
      name: { type: "string" },
      redirectUris: { type: "array", items: { type: "string", format: "uri" } },
      tokenEndpointAuthMethod: { type: "string", enum: ["none", "client_secret_basic", "client_secret_post"] },
      clientUri: { type: ["string", "null"] },
      softwareId: { type: ["string", "null"] },
      createdAt: { type: "string", format: "date-time" },
      lastUsedAt: { type: ["string", "null"], format: "date-time" },
      revokedAt: { type: ["string", "null"], format: "date-time" },
      activeGrants: { type: "integer", minimum: 0 },
    },
  },
  McpConnection: {
    type: "object",
    required: ["id", "clientId", "clientName", "userId", "scopes", "createdAt", "refreshExpiresAt"],
    properties: {
      id: { type: "integer" },
      familyId: { type: "string" },
      clientId: { type: "string" },
      clientName: { type: "string" },
      userId: { type: "integer" },
      userName: { type: ["string", "null"] },
      userEmail: { type: "string" },
      scopes: { type: "array", items: { type: "string" } },
      resource: { type: "string", format: "uri" },
      createdAt: { type: "string", format: "date-time" },
      lastUsedAt: { type: ["string", "null"], format: "date-time" },
      refreshExpiresAt: { type: "string", format: "date-time" },
    },
  },
} as const;
