/**
 * The MCP endpoint over Streamable HTTP: bearer-token authentication,
 * discovery challenges, scope checks and step-up, tool calls, resources and
 * prompts, and the transport rules (Origin, methods, notifications).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TestDb } from "../helpers/db";

const ctx = vi.hoisted(() => {
  // Vitest leaks Vite's BASE_URL='/' into process.env; the MCP resource is an
  // absolute URI built from it.
  process.env.BASE_URL = "http://localhost:3000";
  return { db: null as unknown as TestDb };
});

vi.mock("../../src/lib/db", async () => {
  const { createTestDb } = await import("../helpers/db");
  ctx.db = createTestDb();
  return (await import("../helpers/db-module")).mockDbModule(() => ctx.db);
});

import * as schema from "../../src/lib/db/schema";
import { handleMcpRequest } from "../../src/lib/mcp/server";
import { issueTokensForGrant } from "../../src/lib/mcp/oauth";
import { mcpResourceUrl, protectedResourceMetadataUrl, saveMcpSettings } from "../../src/lib/mcp/config";
import { eq } from "drizzle-orm";

const BASE = "http://localhost:3000";

let adminId = 0;
let viewerId = 0;

function body(method: string, id: number | null, params?: unknown, notification = false) {
  return {
    jsonrpc: "2.0",
    ...(notification ? {} : { id }),
    method,
    ...(params === undefined ? {} : { params }),
  };
}

function request(
  payload: unknown,
  options: { token?: string; method?: string; origin?: string; protocol?: string; headers?: Record<string, string> } = {}
): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...(options.headers ?? {}),
  };
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.origin) headers.origin = options.origin;
  if (options.protocol) headers["mcp-protocol-version"] = options.protocol;
  return new Request(`${BASE}/api/mcp`, {
    method: options.method ?? "POST",
    headers,
    ...(options.method && options.method !== "POST" ? {} : { body: JSON.stringify(payload) }),
  });
}

async function token(scopes: string[], userId = adminId): Promise<string> {
  const issued = await issueTokensForGrant({
    clientId: "mcp_testclient0001",
    userId,
    scopes,
    resource: mcpResourceUrl(),
  });
  return issued.accessToken;
}

async function call(payload: unknown, options: Parameters<typeof request>[1] = {}) {
  const response = await handleMcpRequest(request(payload, options));
  const text = await response.text();
  return { response, body: text ? (JSON.parse(text) as any) : null };
}

beforeEach(async () => {
  await ctx.db.delete(schema.mcpOAuthTokens);
  await ctx.db.delete(schema.mcpOAuthCodes);
  await ctx.db.delete(schema.mcpOAuthConsents);
  await ctx.db.delete(schema.mcpOAuthClients);
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.settings);
  await ctx.db.delete(schema.users);
  const now = new Date().toISOString();
  const users = await ctx.db
    .insert(schema.users)
    .values([
      {
        email: "admin@example.com",
        name: "Admin",
        role: "admin",
        provider: "credentials",
        subject: "admin",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
      {
        email: "viewer@example.com",
        name: "Viewer",
        role: "viewer",
        provider: "credentials",
        subject: "viewer",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    ])
    .returning();
  adminId = users[0].id;
  viewerId = users[1].id;
  await ctx.db.insert(schema.mcpOAuthClients).values({
    clientId: "mcp_testclient0001",
    name: "Test client",
    redirectUris: JSON.stringify(["http://127.0.0.1:4321/callback"]),
    grantTypes: JSON.stringify(["authorization_code", "refresh_token"]),
    tokenEndpointAuthMethod: "none",
    createdAt: now,
  });
});

afterEach(() => vi.restoreAllMocks());

describe("the MCP endpoint", () => {
  it("negotiates a protocol version and advertises tools, resources and prompts", async () => {
    const accessToken = await token(["mcp.write"]);
    const { response, body: result } = await call(
      body("initialize", 1, {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "test", version: "1.0.0" },
      }),
      { token: accessToken }
    );
    expect(response.status).toBe(200);
    expect(result.result.protocolVersion).toBe("2025-06-18");
    expect(result.result.capabilities).toMatchObject({ tools: {}, resources: {}, prompts: {} });
    expect(result.result.serverInfo).toMatchObject({ name: "ingressi" });
    expect(result.result.instructions).toContain("Caddy");
  });

  it("accepts notifications with 202 and no body", async () => {
    const accessToken = await token(["mcp.read"]);
    const response = await handleMcpRequest(
      request(body("notifications/initialized", null, undefined, true), { token: accessToken })
    );
    expect(response.status).toBe(202);
    expect(await response.text()).toBe("");
  });

  it("lists the tools with annotations", async () => {
    const accessToken = await token(["mcp.read"]);
    const { body: result } = await call(body("tools/list", 2), { token: accessToken });
    const tools = result.result.tools as Array<{ name: string; annotations: { readOnlyHint: boolean } }>;
    expect(tools.map((tool) => tool.name)).toEqual(expect.arrayContaining(["list_proxy_hosts", "create_proxy_host", "apply_caddy_config"]));
    expect(tools.find((tool) => tool.name === "list_proxy_hosts")?.annotations.readOnlyHint).toBe(true);
    expect(tools.find((tool) => tool.name === "delete_proxy_host")?.annotations.readOnlyHint).toBe(false);
  });

  it("creates a host with a write scope and lists it with a read scope", async () => {
    const writer = await token(["mcp.write"]);
    const created = await call(
      body("tools/call", 3, {
        name: "create_proxy_host",
        arguments: { name: "App", domains: ["app.example.com"], upstreams: ["http://app:8080"] },
      }),
      { token: writer }
    );
    expect(created.response.status).toBe(200);
    expect(created.body.result.isError).toBeUndefined();
    const id = created.body.result.structuredContent.id as number;
    expect(id).toBeGreaterThan(0);
    const stored = await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, id));
    expect(stored[0]).toMatchObject({ name: "App", enabled: true });

    const reader = await token(["mcp.read"]);
    const listed = await call(body("tools/call", 4, { name: "list_proxy_hosts", arguments: {} }), {
      token: reader,
    });
    expect(listed.body.result.structuredContent.items).toHaveLength(1);
    expect(listed.body.result.structuredContent.items[0]).toMatchObject({ id, domains: ["app.example.com"] });
  });

  it("answers 403 insufficient_scope when the token has read but not write", async () => {
    const reader = await token(["mcp.read"]);
    const { response, body: result } = await call(
      body("tools/call", 5, {
        name: "create_proxy_host",
        arguments: { name: "Nope", domains: ["nope.example.com"], upstreams: ["http://app:8080"] },
      }),
      { token: reader }
    );
    expect(response.status).toBe(403);
    expect(response.headers.get("www-authenticate")).toContain('error="insufficient_scope"');
    expect(response.headers.get("www-authenticate")).toContain("mcp.write");
    expect(result.error.code).toBe(-32003);
    expect(result.error.data.requiredScopes).toContain("proxy_hosts:write");
    expect(await ctx.db.select().from(schema.proxyHosts)).toHaveLength(0);
  });

  it("answers a tool error, not a challenge, when the account's role lacks the permission", async () => {
    const reader = await token(["mcp.read"], viewerId);
    const { response, body: result } = await call(body("tools/call", 6, { name: "list_proxy_hosts", arguments: {} }), {
      token: reader,
    });
    expect(response.status).toBe(200);
    expect(result.result.isError).toBe(true);
    expect(result.result.content[0].text).toContain("proxy_hosts:read");
  });

  it("challenges a fine-grained token that does not cover the tool", async () => {
    const fine = await token(["proxy_hosts:read"]);
    const { response, body: result } = await call(body("tools/call", 7, { name: "list_certificates", arguments: {} }), {
      token: fine,
    });
    expect(response.status).toBe(403);
    const header = response.headers.get("www-authenticate") ?? "";
    expect(header).toContain('error="insufficient_scope"');
    expect(header).toContain("certificates:read");
    expect(result.error.code).toBe(-32003);
  });

  it("answers 401 with the protected resource metadata when no or a bad token is sent", async () => {
    for (const tokenValue of [undefined, "mcp_at_not-a-token"]) {
      const { response, body: result } = await call(body("tools/list", 8), { token: tokenValue });
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toContain(
        `resource_metadata="${protectedResourceMetadataUrl()}"`
      );
      if (tokenValue) expect(result.error.code).toBe(-32001);
    }
  });

  it("refuses an Origin other than the dashboard's (DNS rebinding)", async () => {
    const accessToken = await token(["mcp.read"]);
    const { response } = await call(body("tools/list", 9), {
      token: accessToken,
      origin: "https://evil.example.com",
    });
    expect(response.status).toBe(403);
  });

  it("refuses an unsupported protocol version header and an access_token query", async () => {
    const accessToken = await token(["mcp.read"]);
    const versioned = await handleMcpRequest(
      request(body("tools/list", 10), { token: accessToken, protocol: "2099-01-01" })
    );
    expect(versioned.status).toBe(400);

    const query = await handleMcpRequest(
      new Request(`${BASE}/api/mcp?access_token=${accessToken}`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(body("tools/list", 11)),
      })
    );
    expect(query.status).toBe(400);
  });

  it("answers 405 to GET and DELETE, as a stateless server without SSE", async () => {
    const accessToken = await token(["mcp.read"]);
    for (const method of ["GET", "DELETE"]) {
      const response = await handleMcpRequest(request(null, { token: accessToken, method }));
      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toContain("POST");
    }
  });

  it("serves resources and resource templates", async () => {
    const accessToken = await token(["mcp.write"]);
    const created = await call(
      body("tools/call", 12, {
        name: "create_proxy_host",
        arguments: { name: "Docs", domains: ["docs.example.com"], upstreams: ["http://docs:8080"] },
      }),
      { token: accessToken }
    );
    const hostId = created.body.result.structuredContent.id as number;

    const list = await call(body("resources/list", 13), { token: accessToken });
    expect(list.body.result.resources.map((resource: { uri: string }) => resource.uri)).toContain("ingressi://proxy-hosts");

    const templates = await call(body("resources/templates/list", 14), { token: accessToken });
    expect(templates.body.result.resourceTemplates[0].uriTemplate).toBe("ingressi://proxy-hosts/{id}");

    const read = await call(body("resources/read", 15, { uri: "ingressi://proxy-hosts" }), { token: accessToken });
    expect(read.body.result.contents[0]).toMatchObject({ mimeType: "application/json" });
    expect(read.body.result.contents[0].text).toContain("docs.example.com");

    const one = await call(body("resources/read", 16, { uri: `ingressi://proxy-hosts/${hostId}` }), { token: accessToken });
    expect(one.body.result.contents[0].text).toContain("docs.example.com");

    const missing = await call(body("resources/read", 17, { uri: "ingressi://proxy-hosts/999" }), { token: accessToken });
    expect(missing.body.error.code).toBe(-32002);
  });

  it("lists and renders prompts", async () => {
    const accessToken = await token(["mcp.read"]);
    const list = await call(body("prompts/list", 18), { token: accessToken });
    expect(list.body.result.prompts.map((prompt: { name: string }) => prompt.name)).toContain("review_proxy_host");

    const prompt = await call(
      body("prompts/get", 19, { name: "onboard_service", arguments: { domain: "new.example.com", upstream: "http://new:8080" } }),
      { token: accessToken }
    );
    expect(prompt.body.result.messages[0].content.text).toContain("new.example.com");

    const missingArgument = await call(body("prompts/get", 20, { name: "onboard_service", arguments: {} }), {
      token: accessToken,
    });
    expect(missingArgument.body.error.code).toBe(-32602);
  });

  it("answers 404 when an administrator turned the MCP server off", async () => {
    await saveMcpSettings({ enabled: false, allowDynamicRegistration: true });
    const accessToken = await token(["mcp.read"]);
    const { response } = await call(body("tools/list", 21), { token: accessToken });
    expect(response.status).toBe(404);
  });

  it("reports an unknown method and an unknown tool as JSON-RPC errors", async () => {
    const accessToken = await token(["mcp.read"]);
    const method = await call(body("no/such/method", 22), { token: accessToken });
    expect(method.body.error.code).toBe(-32601);
    const tool = await call(body("tools/call", 23, { name: "no_such_tool", arguments: {} }), { token: accessToken });
    expect(tool.body.error.code).toBe(-32602);
  });
});
