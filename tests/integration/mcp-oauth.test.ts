/**
 * The MCP authorization server end to end: dynamic registration, the
 * authorization request rules, the authorization code and token endpoints,
 * audience binding, refresh rotation, reuse detection and revocation.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash, randomBytes } from "node:crypto";
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

// The consent form is posted with the dashboard session; the Origin check is
// covered by its own test in src/lib/auth, so here it always passes.
vi.mock("../../src/lib/auth", () => ({
  auth: vi.fn(async () => ({ user: { id: String(userId), email: "admin@example.com", role: "admin" } })),
  checkSameOrigin: vi.fn(() => null),
}));

import * as schema from "../../src/lib/db/schema";
import { POST as register } from "../../app/api/oauth/register/route";
import { POST as authorizeDecision } from "../../app/api/oauth/authorize/route";
import { POST as token } from "../../app/api/oauth/token/route";
import { POST as revoke } from "../../app/api/oauth/revoke/route";
import {
  exchangeAuthorizationCode,
  getClient,
  issueTokensForGrant,
  listClients,
  listConnections,
  revokeClient,
  validateAccessToken,
} from "../../src/lib/mcp/oauth";
import { parseAuthorizationRequest } from "../../src/lib/mcp/authorize";
import { mcpResourceUrl } from "../../src/lib/mcp/config";
import { adminAccess } from "../../src/lib/permissions";

const BASE = "http://localhost:3000";
let userId = 0;

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function jsonRequest(url: string, body: unknown): NextRequest {
  return new NextRequest(`${BASE}${url}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function formRequest(url: string, params: Record<string, string>): NextRequest {
  return new NextRequest(`${BASE}${url}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
}

async function registerClient(): Promise<string> {
  const response = await register(
    jsonRequest("/api/oauth/register", {
      client_name: "MCP test client",
      redirect_uris: ["http://127.0.0.1:4321/callback"],
      token_endpoint_auth_method: "none",
    })
  );
  expect(response.status).toBe(201);
  const body = (await response.json()) as { client_id: string };
  expect(body.client_id).toMatch(/^mcp_/);
  return body.client_id;
}

async function authorize(clientId: string, verifier: { verifier: string; challenge: string }): Promise<string> {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: "http://127.0.0.1:4321/callback",
    code_challenge: verifier.challenge,
    code_challenge_method: "S256",
    scope: "mcp.write",
    resource: mcpResourceUrl(),
    state: "state-123",
  });
  const parsed = await parseAuthorizationRequest(params, adminAccess(userId));
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error("unreachable");
  const { createAuthorizationCode } = await import("../../src/lib/mcp/oauth");
  return await createAuthorizationCode({
    clientId,
    userId,
    redirectUri: parsed.request.redirectUri,
    codeChallenge: parsed.request.codeChallenge,
    scopes: parsed.request.scopes,
    resource: parsed.request.resource,
  });
}

async function exchange(clientId: string, code: string, verifier: string) {
  const response = await token(
    formRequest("/api/oauth/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: "http://127.0.0.1:4321/callback",
      code_verifier: verifier,
      resource: mcpResourceUrl(),
    })
  );
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

beforeEach(async () => {
  await ctx.db.delete(schema.mcpOAuthTokens);
  await ctx.db.delete(schema.mcpOAuthCodes);
  await ctx.db.delete(schema.mcpOAuthConsents);
  await ctx.db.delete(schema.mcpOAuthClients);
  await ctx.db.delete(schema.users);
  await ctx.db.delete(schema.settings);
  const now = new Date().toISOString();
  const user = await ctx.db
    .insert(schema.users)
    .values({
      email: "admin@example.com",
      name: "Admin",
      role: "admin",
      provider: "credentials",
      subject: "admin",
      status: "active",
      createdAt: now,
      updatedAt: now,
    })
    .returning();
  userId = user[0].id;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("dynamic client registration", () => {
  it("stores a public client and returns its metadata", async () => {
    const clientId = await registerClient();
    const client = await getClient(clientId);
    expect(client).toMatchObject({
      clientId,
      name: "MCP test client",
      tokenEndpointAuthMethod: "none",
      clientSecretHash: null,
    });
    expect((await listClients())[0]).toMatchObject({ clientId, activeGrants: 0 });
  });

  it("refuses a redirect URI that is neither HTTPS nor loopback", async () => {
    const response = await register(
      jsonRequest("/api/oauth/register", {
        client_name: "Plain HTTP",
        redirect_uris: ["http://app.example.com/callback"],
      })
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_redirect_uri" });
  });

  it("refuses registration when an administrator closed it", async () => {
    const { saveMcpSettings } = await import("../../src/lib/mcp/config");
    await saveMcpSettings({ enabled: true, allowDynamicRegistration: false });
    const response = await register(
      jsonRequest("/api/oauth/register", {
        client_name: "Later",
        redirect_uris: ["https://app.example.com/callback"],
      })
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "registration_not_supported" });
  });
});

describe("authorization request rules", () => {
  it("requires a registered redirect URI and PKCE", async () => {
    const clientId = await registerClient();
    const { challenge } = pkce();
    const unknownRedirect = await parseAuthorizationRequest(
      new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "https://evil.example.com/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }),
      adminAccess(userId)
    );
    expect(unknownRedirect).toMatchObject({ ok: false, fatal: true });

    const noPkce = await parseAuthorizationRequest(
      new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1:4321/callback",
      }),
      adminAccess(userId)
    );
    expect(noPkce).toMatchObject({ ok: false, fatal: false, error: "invalid_request" });
  });

  it("refuses a scope the account does not hold", async () => {
    const clientId = await registerClient();
    const { challenge } = pkce();
    const parsed = await parseAuthorizationRequest(
      new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1:4321/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "config:import",
      }),
      (await import("../../src/lib/permissions")).builtInAccess(userId, "user")
    );
    expect(parsed).toMatchObject({ ok: false, fatal: false, error: "invalid_scope" });
  });

  it("refuses a resource that is not the MCP endpoint", async () => {
    const clientId = await registerClient();
    const { challenge } = pkce();
    const parsed = await parseAuthorizationRequest(
      new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1:4321/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: "https://other.example.com/mcp",
      }),
      adminAccess(userId)
    );
    expect(parsed).toMatchObject({ ok: false, fatal: false, error: "invalid_target" });
  });
});

describe("authorization code and tokens", () => {
  it("exchanges a code once, binds the audience and rotates refresh tokens", async () => {
    const clientId = await registerClient();
    const verifier = pkce();
    const code = await authorize(clientId, verifier);

    const first = await exchange(clientId, code, verifier.verifier);
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({
      token_type: "Bearer",
      expires_in: 3600,
      scope: "mcp.write",
    });
    const accessToken = first.body.access_token as string;
    const refreshToken = first.body.refresh_token as string;
    expect(accessToken).toMatch(/^mcp_at_/);
    expect(refreshToken).toMatch(/^mcp_rt_/);

    const validated = await validateAccessToken(accessToken);
    expect(validated).toMatchObject({ userId, clientId, resource: mcpResourceUrl(), scopes: ["mcp.write"] });

    // The same code cannot be redeemed twice.
    const replay = await exchange(clientId, code, verifier.verifier);
    expect(replay.status).toBe(400);
    expect(replay.body).toMatchObject({ error: "invalid_grant" });

    // Refresh rotates: a new pair, the old refresh token is single use.
    const refreshed = await token(
      formRequest("/api/oauth/token", {
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: refreshToken,
      })
    );
    expect(refreshed.status).toBe(200);
    const rotated = (await refreshed.json()) as Record<string, unknown>;
    expect(rotated.access_token).not.toBe(accessToken);
    expect(rotated.refresh_token).not.toBe(refreshToken);
    expect(await validateAccessToken(rotated.access_token as string)).not.toBeNull();

    // Presenting the rotated refresh token again revokes the whole family.
    const reused = await token(
      formRequest("/api/oauth/token", {
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: refreshToken,
      })
    );
    expect(reused.status).toBe(400);
    expect(await reused.json()).toMatchObject({ error: "invalid_grant" });
    expect(await validateAccessToken(rotated.access_token as string)).toBeNull();
  });

  it("refuses a code redeemed with the wrong PKCE verifier", async () => {
    const clientId = await registerClient();
    const verifier = pkce();
    const code = await authorize(clientId, verifier);
    const wrong = pkce();
    const response = await token(
      formRequest("/api/oauth/token", {
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        redirect_uri: "http://127.0.0.1:4321/callback",
        code_verifier: wrong.verifier,
      })
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("refuses a code redeemed with another redirect URI or client", async () => {
    const clientId = await registerClient();
    const otherClientId = await registerClient();
    const verifier = pkce();
    const code = await authorize(clientId, verifier);

    const wrongRedirect = await token(
      formRequest("/api/oauth/token", {
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        redirect_uri: "https://other.example.com/callback",
        code_verifier: verifier.verifier,
      })
    );
    expect(wrongRedirect.status).toBe(400);
    expect(await wrongRedirect.json()).toMatchObject({ error: "invalid_grant" });

    const parsed = await exchange(clientId, code, verifier.verifier);
    expect(parsed.status).toBe(200);

    const second = await authorize(clientId, verifier);
    const wrongClient = await token(
      formRequest("/api/oauth/token", {
        grant_type: "authorization_code",
        client_id: otherClientId,
        code: second,
        redirect_uri: "http://127.0.0.1:4321/callback",
        code_verifier: verifier.verifier,
      })
    );
    expect(wrongClient.status).toBe(400);
    expect(await wrongClient.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("supports a confidential client with HTTP Basic authentication", async () => {
    const response = await register(
      jsonRequest("/api/oauth/register", {
        client_name: "Confidential client",
        redirect_uris: ["https://app.example.com/callback"],
        token_endpoint_auth_method: "client_secret_basic",
      })
    );
    expect(response.status).toBe(201);
    const registered = (await response.json()) as { client_id: string; client_secret: string };
    expect(registered.client_secret).toMatch(/^mcp_cs_/);

    const verifier = pkce();
    const params = new URLSearchParams({
      response_type: "code",
      client_id: registered.client_id,
      redirect_uri: "https://app.example.com/callback",
      code_challenge: verifier.challenge,
      code_challenge_method: "S256",
      scope: "mcp.read",
    });
    const parsed = await parseAuthorizationRequest(params, adminAccess(userId));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error("unreachable");
    const { createAuthorizationCode } = await import("../../src/lib/mcp/oauth");
    const code = await createAuthorizationCode({
      clientId: registered.client_id,
      userId,
      redirectUri: parsed.request.redirectUri,
      codeChallenge: parsed.request.codeChallenge,
      scopes: parsed.request.scopes,
      resource: parsed.request.resource,
    });

    const basic = Buffer.from(`${encodeURIComponent(registered.client_id)}:${encodeURIComponent(registered.client_secret)}`).toString("base64");
    const exchanged = await token(
      new NextRequest(`${BASE}/api/oauth/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${basic}`,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://app.example.com/callback",
          code_verifier: verifier.verifier,
        }).toString(),
      })
    );
    expect(exchanged.status).toBe(200);
    expect((await exchanged.json()).token_type).toBe("Bearer");
  });

  it("revokes a grant when the client asks", async () => {
    const clientId = await registerClient();
    const tokens = await issueTokensForGrant({
      clientId,
      userId,
      scopes: ["mcp.read"],
      resource: mcpResourceUrl(),
    });
    expect(await validateAccessToken(tokens.accessToken)).not.toBeNull();
    expect(await listConnections()).toHaveLength(1);

    const response = await revoke(
      formRequest("/api/oauth/revoke", {
        client_id: clientId,
        token: tokens.refreshToken,
        token_type_hint: "refresh_token",
      })
    );
    expect(response.status).toBe(200);
    expect(await validateAccessToken(tokens.accessToken)).toBeNull();
    expect(await listConnections()).toHaveLength(0);
  });

  it("revokes every grant of a client an administrator removes", async () => {
    const clientId = await registerClient();
    const tokens = await issueTokensForGrant({
      clientId,
      userId,
      scopes: ["mcp.read"],
      resource: mcpResourceUrl(),
    });
    expect(await revokeClient(clientId)).toBe(true);
    expect(await validateAccessToken(tokens.accessToken)).toBeNull();
    expect((await getClient(clientId))?.revokedAt).not.toBeNull();
  });

  it("keeps the authorization code bound to its own client", async () => {
    const clientId = await registerClient();
    const other = await registerClient();
    const verifier = pkce();
    const code = await authorize(clientId, verifier);
    const client = await getClient(other);
    expect(client).not.toBeNull();
    await expect(
      exchangeAuthorizationCode({
        code,
        client: client!,
        redirectUri: "http://127.0.0.1:4321/callback",
        codeVerifier: verifier.verifier,
      })
    ).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("records the consent form's decision and returns the client with a code", async () => {
    const clientId = await registerClient();
    const verifier = pkce();
    const form = new FormData();
    form.set("client_id", clientId);
    form.set("redirect_uri", "http://127.0.0.1:4321/callback");
    form.set("response_type", "code");
    form.set("code_challenge", verifier.challenge);
    form.set("code_challenge_method", "S256");
    form.set("scope", "mcp.write");
    form.set("resource", mcpResourceUrl());
    form.set("state", "form-state");
    form.set("decision", "allow");
    const response = await authorizeDecision(
      new NextRequest(`${BASE}/api/oauth/authorize`, {
        method: "POST",
        headers: { origin: BASE },
        body: form,
      })
    );
    expect(response.status).toBe(303);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin).toBe("http://127.0.0.1:4321");
    expect(location.searchParams.get("state")).toBe("form-state");
    expect(location.searchParams.get("iss")).toBe(BASE);
    const code = location.searchParams.get("code");
    expect(code).toMatch(/^mcp_ac_/);

    const exchanged = await exchange(clientId, code!, verifier.verifier);
    expect(exchanged.status).toBe(200);
    const consent = await ctx.db.select().from(schema.mcpOAuthConsents);
    expect(consent).toHaveLength(1);
    expect(consent[0]).toMatchObject({ userId, clientId, scopes: "mcp.write" });
  });

  it("returns access_denied without creating a code", async () => {
    const clientId = await registerClient();
    const verifier = pkce();
    const form = new FormData();
    form.set("client_id", clientId);
    form.set("redirect_uri", "http://127.0.0.1:4321/callback");
    form.set("response_type", "code");
    form.set("code_challenge", verifier.challenge);
    form.set("code_challenge_method", "S256");
    form.set("scope", "mcp.read");
    form.set("resource", mcpResourceUrl());
    form.set("state", "deny-state");
    form.set("decision", "deny");
    const response = await authorizeDecision(
      new NextRequest(`${BASE}/api/oauth/authorize`, {
        method: "POST",
        headers: { origin: BASE },
        body: form,
      })
    );
    expect(response.status).toBe(303);
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("code")).toBeNull();
    expect(await ctx.db.select().from(schema.mcpOAuthCodes)).toHaveLength(0);
  });

  it("re-validates scopes on the consent form", async () => {
    const clientId = await registerClient();
    const verifier = pkce();
    const form = new FormData();
    form.set("client_id", clientId);
    form.set("redirect_uri", "http://127.0.0.1:4321/callback");
    form.set("response_type", "code");
    form.set("code_challenge", verifier.challenge);
    form.set("code_challenge_method", "S256");
    form.set("scope", "config:import mcp.write");
    form.set("resource", mcpResourceUrl());
    form.set("decision", "allow");
    // The account is an administrator and holds config:import, so tamper with
    // the client instead: a redirect URI that is not registered.
    form.set("redirect_uri", "https://evil.example.com/callback");
    const response = await authorizeDecision(
      new NextRequest(`${BASE}/api/oauth/authorize`, {
        method: "POST",
        headers: { origin: BASE },
        body: form,
      })
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("refuses an unknown access token and an expired one", async () => {
    expect(await validateAccessToken("mcp_at_unknown")).toBeNull();
    // A token row with an expiry in the past.
    const clientId = await registerClient();
    const tokens = await issueTokensForGrant({
      clientId,
      userId,
      scopes: ["mcp.read"],
      resource: mcpResourceUrl(),
    });
    const hash = createHash("sha256").update(tokens.accessToken).digest("hex");
    await ctx.db
      .update(schema.mcpOAuthTokens)
      .set({ accessExpiresAt: new Date(Date.now() - 1000).toISOString() })
      .where((await import("drizzle-orm")).eq(schema.mcpOAuthTokens.accessTokenHash, hash));
    expect(await validateAccessToken(tokens.accessToken)).toBeNull();
  });
});
