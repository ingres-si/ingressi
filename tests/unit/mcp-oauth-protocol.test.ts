/**
 * The pure parts of the MCP authorization server: scope parsing and
 * expansion, consent coverage, step-up suggestions, redirect URI matching and
 * audience validation. The database-backed flow is in
 * tests/integration/mcp-oauth.test.ts.
 */
import { describe, expect, it, vi } from "vitest";

// Vitest leaks Vite's BASE_URL='/' into process.env; the MCP resource is an
// absolute URI built from it.
vi.hoisted(() => {
  process.env.BASE_URL = "http://localhost:3000";
});
import { builtInAccess, adminAccess, type Permission } from "@/src/lib/permissions";
import {
  MCP_DEFAULT_SCOPE,
  MCP_READ_SCOPE,
  MCP_WRITE_SCOPE,
  describeScopes,
  expandScopes,
  parseScopeString,
  scopesCover,
  stepUpScopes,
  validateScopesForAccess,
} from "@/src/lib/mcp/scopes";
import { redirectUriMatches, resolveResource, validateRedirectUri, OAuthError } from "@/src/lib/mcp/oauth";
import { mcpResourceUrl } from "@/src/lib/mcp/config";

describe("MCP scopes", () => {
  it("parses space separated scopes and removes duplicates", () => {
    expect(parseScopeString("mcp.read proxy_hosts:read mcp.read")).toEqual(["mcp.read", "proxy_hosts:read"]);
    expect(parseScopeString("")).toEqual([]);
    expect(parseScopeString(null)).toEqual([]);
    expect(parseScopeString('bad scope with "quotes"')).toBeNull();
    expect(parseScopeString("x".repeat(200))).toBeNull();
  });

  it("expands mcp.read to the read permissions the user holds", () => {
    const access = adminAccess(1);
    const expanded = expandScopes(access, [MCP_READ_SCOPE]);
    expect(expanded).toContain("proxy_hosts:read");
    expect(expanded).toContain("users:read");
    expect(expanded).not.toContain("proxy_hosts:write");
    expect(expanded.every((permission) => permission.endsWith(":read"))).toBe(true);
  });

  it("expands mcp.write to every permission the user holds, reads included", () => {
    const expanded = expandScopes(adminAccess(1), [MCP_WRITE_SCOPE]);
    expect(expanded).toContain("proxy_hosts:read");
    expect(expanded).toContain("proxy_hosts:write");
    expect(expanded).toContain("config:import");
  });

  it("ignores a per-permission scope the user no longer holds", () => {
    // A built-in "user" holds no catalogue permission.
    const viewer = builtInAccess(2, "user");
    expect(expandScopes(viewer, ["proxy_hosts:write"])).toEqual([]);
    expect(expandScopes(adminAccess(1), ["proxy_hosts:write"])).toContain("proxy_hosts:write");
  });

  it("refuses unknown scopes and permissions the user does not hold", () => {
    const viewer = builtInAccess(3, "viewer");
    expect(validateScopesForAccess(["mcp.read"], viewer)).toBeNull();
    expect(validateScopesForAccess(["proxy_hosts:read"], viewer)).toMatch(/do not hold/);
    expect(validateScopesForAccess(["not:a-scope"], viewer)).toMatch(/Unknown scope/);
  });

  it("treats a missing scope as the least-privilege default", () => {
    expect(MCP_DEFAULT_SCOPE).toBe(MCP_READ_SCOPE);
  });

  it("covers a request only when every scope was approved before", () => {
    expect(scopesCover(["mcp.read"], ["mcp.read"])).toBe(true);
    expect(scopesCover(["mcp.read"], ["mcp.read", "proxy_hosts:read"])).toBe(false);
    expect(scopesCover(["mcp.write", "mcp.read"], ["mcp.write"])).toBe(true);
  });

  it("suggest a step-up only when a scope can fix the refusal", () => {
    const access = adminAccess(1);
    expect(stepUpScopes(access, [MCP_READ_SCOPE], "proxy_hosts:write")).toEqual([
      MCP_READ_SCOPE,
      MCP_WRITE_SCOPE,
      "proxy_hosts:write",
    ]);
    // Already has the broad scope: a new authorization would not help.
    expect(stepUpScopes(access, [MCP_WRITE_SCOPE], "proxy_hosts:write")).toBeNull();
    // The user does not hold it at all.
    expect(stepUpScopes(builtInAccess(2, "user"), [], "proxy_hosts:read")).toBeNull();
  });

  it("describes the scopes for the consent screen", () => {
    const described = describeScopes([MCP_READ_SCOPE, "proxy_hosts:write" as Permission]);
    expect(described[0]).toMatchObject({ scope: MCP_READ_SCOPE, title: expect.stringMatching(/Read/) });
    expect(described[1]).toMatchObject({ scope: "proxy_hosts:write", title: expect.stringMatching(/Proxy hosts/i) });
  });
});

describe("MCP authorization request validation", () => {
  it("accepts an exact redirect URI and a loopback one on another port", () => {
    expect(redirectUriMatches("http://127.0.0.1:4321/callback", "http://127.0.0.1:4321/callback")).toBe(true);
    expect(redirectUriMatches("http://127.0.0.1:4321/callback", "http://127.0.0.1:5555/callback")).toBe(true);
    expect(redirectUriMatches("http://localhost:4321/cb", "http://[::1]:4321/cb")).toBe(false);
    expect(redirectUriMatches("https://app.example.com/cb", "https://app.example.com/cb?x=1")).toBe(false);
    expect(redirectUriMatches("https://app.example.com/cb", "https://evil.example.com/cb")).toBe(false);
  });

  it("refuses a redirect URI that is not HTTPS or loopback HTTP", () => {
    expect(validateRedirectUri("https://app.example.com/callback")).toBe("https://app.example.com/callback");
    expect(validateRedirectUri("http://localhost:3000/callback")).toBe("http://localhost:3000/callback");
    expect(() => validateRedirectUri("http://app.example.com/callback")).toThrow(OAuthError);
    expect(() => validateRedirectUri("https://app.example.com/callback#fragment")).toThrow(OAuthError);
    expect(() => validateRedirectUri("javascript:alert(1)")).toThrow(OAuthError);
  });

  it("binds a request to the canonical MCP endpoint", () => {
    expect(resolveResource(undefined)).toBe(mcpResourceUrl());
    expect(resolveResource(mcpResourceUrl())).toBe(mcpResourceUrl());
    expect(resolveResource(`${mcpResourceUrl()}/`)).toBe(mcpResourceUrl());
    expect(() => resolveResource("https://elsewhere.example.com/mcp")).toThrow(/only issues tokens/);
    expect(() => resolveResource(`${mcpResourceUrl()}#fragment`)).toThrow(/fragment/);
  });
});
