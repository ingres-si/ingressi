import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TestDb } from "../helpers/db";

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock("../../src/lib/db", async () => {
  const { createTestDb } = await import("../helpers/db");
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

vi.mock("../../src/lib/caddy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/lib/caddy")>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock("../../src/lib/audit", () => ({ logAuditEvent: vi.fn() }));

import { createProxyHost } from "../../src/lib/models/proxy-hosts";
import { buildCaddyDocument } from "../../src/lib/caddy";
import { saveDefaultResponseSettings, saveResponseHeadersSettings, setSetting } from "../../src/lib/settings";
import {
  buildResponseHeadersRoute,
  normalizeResponseHeadersSettings,
} from "../../src/lib/caddy-response-headers";
import { validateSettingsGroup } from "../../src/lib/settings-validation";
import * as schema from "../../src/lib/db/schema";

type IngressiServer = {
  listen?: string[];
  routes?: Array<Record<string, unknown>>;
  errors?: { routes?: Array<Record<string, unknown>> };
};

function cpmServer(document: unknown): IngressiServer | undefined {
  return (document as { apps?: { http?: { servers?: { ingressi?: IngressiServer } } } })
    .apps?.http?.servers?.ingressi;
}

async function seedAdminAndHost() {
  const now = new Date().toISOString();
  await ctx.db.insert(schema.users).values({
    id: 1,
    email: "admin@example.com",
    name: "Admin",
    role: "admin",
    provider: "credentials",
    subject: "admin",
    status: "active",
    createdAt: now,
    updatedAt: now,
  });
  await createProxyHost(
    { name: "Known host", domains: ["known.example.test"], upstreams: ["10.0.0.5:8080"] },
    1
  );
}

beforeEach(async () => {
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.settings);
  await ctx.db.delete(schema.users);
});

const HIDE_CADDY = {
  handle: [{ handler: "headers", response: { delete: ["Server", "Via"], deferred: true } }],
};

describe("response headers validation and route builder", () => {
  it("builds no route without headers", () => {
    expect(buildResponseHeadersRoute(null)).toBeNull();
    expect(buildResponseHeadersRoute({ set: {}, remove: [] })).toBeNull();
  });

  it("builds one deferred, matcher-less, non-terminal headers handler", () => {
    expect(buildResponseHeadersRoute(normalizeResponseHeadersSettings({
      set: { " Server ": " web ", "X-Host": "{http.request.host} {env.HOME}" },
      remove: ["Via"],
    }))).toEqual({
      handle: [{
        handler: "headers",
        response: {
          set: { Server: ["web"], "X-Host": ["{http.request.host} \\{env.HOME}"] },
          delete: ["Via"],
          deferred: true,
        },
      }],
    });
  });

  it("fills in missing lists", () => {
    expect(normalizeResponseHeadersSettings({})).toEqual({ set: {}, remove: [] });
    expect(normalizeResponseHeadersSettings({ remove: ["Server"] })).toEqual({ set: {}, remove: ["Server"] });
  });

  it("rejects invalid names, values and framing headers", () => {
    expect(() => normalizeResponseHeadersSettings({ remove: ["Bad Name"] })).toThrow(/Invalid response header name/);
    expect(() => normalizeResponseHeadersSettings({ set: { "X-Test": "a\r\nInjected: b" } })).toThrow(/Invalid value/);
    expect(() => normalizeResponseHeadersSettings({ set: { "X-Test": 1 } })).toThrow(/Invalid value/);
    expect(() => normalizeResponseHeadersSettings({ remove: ["Content-Length"] })).toThrow(/every response/);
    expect(() => normalizeResponseHeadersSettings({ set: { "Transfer-Encoding": "chunked" } })).toThrow(/every response/);
    expect(() => normalizeResponseHeadersSettings({ remove: "Server" })).toThrow(/must be a list/);
    expect(() => normalizeResponseHeadersSettings({ set: {}, other: true })).toThrow(/unknown field/);
  });

  it("refuses placeholders that copy request headers or cookies", () => {
    for (const value of ["{http.request.header.Cookie}", "x {HTTP.Request.Cookie.session}", "{http.request.headers.Authorization}"]) {
      expect(() => normalizeResponseHeadersSettings({ set: { "X-Echo": value } })).toThrow(/request headers or cookies/);
    }
    expect(normalizeResponseHeadersSettings({ set: { "X-Host": "{http.request.host}{http.request.uri}" } }).set["X-Host"])
      .toBe("{http.request.host}{http.request.uri}");
  });

  it("rejects a header listed twice, or both set and removed", () => {
    expect(() => normalizeResponseHeadersSettings({ remove: ["Server", "server"] })).toThrow(/more than once/);
    expect(() => normalizeResponseHeadersSettings({ set: { Server: "web" }, remove: ["SERVER"] })).toThrow(/more than once/);
  });

  it("is a 400-class settings validation error on the REST API", () => {
    expect(() => validateSettingsGroup("response-headers", { remove: ["Bad Name"] })).toThrow(
      expect.objectContaining({ name: "SettingsValidationError" })
    );
    expect(validateSettingsGroup("response-headers", { remove: ["Server", "Via"] })).toEqual({ remove: ["Server", "Via"] });
  });
});

describe("buildCaddyDocument response headers", () => {
  it("does not start a server without hosts", async () => {
    await saveResponseHeadersSettings({ set: {}, remove: ["Server", "Via"] });
    expect(cpmServer(await buildCaddyDocument())).toBeUndefined();
  });

  it("goes first in the routes and the error routes", async () => {
    await seedAdminAndHost();
    await saveResponseHeadersSettings({ set: {}, remove: ["Server", "Via"] });

    const server = cpmServer(await buildCaddyDocument());
    expect(server?.routes?.[0]).toEqual(HIDE_CADDY);
    expect(server?.routes?.slice(1).every((route) => route.match !== undefined)).toBe(true);
    expect(server?.errors?.routes).toEqual([HIDE_CADDY]);
  });

  it("also covers the response for unknown hosts", async () => {
    await seedAdminAndHost();
    await saveResponseHeadersSettings({ set: {}, remove: ["Server", "Via"] });
    await saveDefaultResponseSettings({ mode: "respond", status: 404, body: "Not found" });

    const routes = cpmServer(await buildCaddyDocument())?.routes ?? [];
    expect(routes[0]).toEqual(HIDE_CADDY);
    expect(routes.at(-1)).toMatchObject({ handle: [{ handler: "static_response", status_code: 404 }] });
  });

  it("leaves the document as it was without the setting, and ignores an invalid stored one", async () => {
    await seedAdminAndHost();
    const before = cpmServer(await buildCaddyDocument());
    expect(before?.routes?.every((route) => route.match !== undefined)).toBe(true);
    expect(before?.errors).toBeUndefined();

    await setSetting("response_headers", { remove: ["Bad Name"] });
    expect(cpmServer(await buildCaddyDocument())).toEqual(before);
  });
});
