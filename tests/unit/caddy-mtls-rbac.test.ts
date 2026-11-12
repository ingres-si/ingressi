/**
 * Unit tests for mTLS RBAC functions in src/lib/caddy-mtls.ts
 *
 * Covers:
 *  - resolveAllowedFingerprints: union of role + cert fingerprints
 *  - buildFingerprintCelExpression: CEL expression generation
 *  - buildMtlsRbacSubroutes: full subroute generation with path rules
 *  - normalizeFingerprint: colon stripping + lowercase
 */
import { describe, it, expect } from "vitest";
import {
  resolveAllowedFingerprints,
  buildFingerprintCelExpression,
  buildMtlsRbacSubroutes,
  buildValidClientCertCelExpression,
  normalizeFingerprint,
  type MtlsAccessRuleLike,
} from "../../src/lib/caddy-mtls";

// ── Helpers ──────────────────────────────────────────────────────────

function makeRule(overrides: Partial<MtlsAccessRuleLike> = {}): MtlsAccessRuleLike {
  return {
    pathPattern: "/admin/*",
    allowedRoleIds: [],
    allowedCertIds: [],
    denyAll: false,
    ...overrides,
  };
}

// ── normalizeFingerprint ─────────────────────────────────────────────

describe("normalizeFingerprint", () => {
  it("strips colons and lowercases", () => {
    expect(normalizeFingerprint("AB:CD:EF:12")).toBe("abcdef12");
  });

  it("handles already-normalized input", () => {
    expect(normalizeFingerprint("abcdef12")).toBe("abcdef12");
  });

  it("handles empty string", () => {
    expect(normalizeFingerprint("")).toBe("");
  });
});

// ── resolveAllowedFingerprints ───────────────────────────────────────

describe("resolveAllowedFingerprints", () => {
  it("resolves fingerprints from roles", () => {
    const roleFpMap = new Map<number, Set<string>>([
      [1, new Set(["aa01", "bb02"])],
      [2, new Set(["cc03"])],
    ]);
    const certFpMap = new Map<number, string>();

    const rule = makeRule({ allowedRoleIds: [1, 2] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, certFpMap);

    expect(result).toEqual(new Set(["aa01", "bb02", "cc03"]));
  });

  it("resolves fingerprints from direct cert IDs", () => {
    const roleFpMap = new Map<number, Set<string>>();
    const certFpMap = new Map<number, string>([
      [10, "e0a1"],
      [20, "e0b2"],
    ]);

    const rule = makeRule({ allowedCertIds: [10, 20] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, certFpMap);

    expect(result).toEqual(new Set(["e0a1", "e0b2"]));
  });

  it("unions both roles and certs", () => {
    const roleFpMap = new Map<number, Set<string>>([
      [1, new Set(["aa01"])],
    ]);
    const certFpMap = new Map<number, string>([[10, "bb02"]]);

    const rule = makeRule({ allowedRoleIds: [1], allowedCertIds: [10] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, certFpMap);

    expect(result).toEqual(new Set(["aa01", "bb02"]));
  });

  it("deduplicates when a cert is in a role AND directly allowed", () => {
    const roleFpMap = new Map<number, Set<string>>([
      [1, new Set(["aa01"])],
    ]);
    const certFpMap = new Map<number, string>([[10, "aa01"]]);

    const rule = makeRule({ allowedRoleIds: [1], allowedCertIds: [10] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, certFpMap);

    expect(result.size).toBe(1);
    expect(result.has("aa01")).toBe(true);
  });

  it("returns empty set for unknown role/cert IDs", () => {
    const roleFpMap = new Map<number, Set<string>>();
    const certFpMap = new Map<number, string>();

    const rule = makeRule({ allowedRoleIds: [999], allowedCertIds: [999] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, certFpMap);

    expect(result.size).toBe(0);
  });
});

// ── buildFingerprintCelExpression ────────────────────────────────────

describe("buildFingerprintCelExpression", () => {
  it("builds CEL expression with sorted fingerprints", () => {
    const fps = new Set(["bb02", "aa01"]);
    const expr = buildFingerprintCelExpression(fps);
    expect(expr).toBe("{http.request.tls.client.fingerprint} in ['aa01', 'bb02']");
  });

  it("leaves out what is not a fingerprint, so a stored value cannot change what the expression says", () => {
    const fps = new Set(["ab12", "x'] || true || 'a' in ['a", "{env.SECRET}", "AB12", ""]);
    expect(buildFingerprintCelExpression(fps)).toBe("{http.request.tls.client.fingerprint} in ['ab12']");
    expect(buildFingerprintCelExpression(new Set(["' || true || '"]))).toBe("{http.request.tls.client.fingerprint} in []");
  });

  it("handles single fingerprint", () => {
    const fps = new Set(["abc123"]);
    const expr = buildFingerprintCelExpression(fps);
    expect(expr).toBe("{http.request.tls.client.fingerprint} in ['abc123']");
  });
});

// ── buildMtlsRbacSubroutes ──────────────────────────────────────────

describe("buildMtlsRbacSubroutes", () => {
  const baseHandlers = [{ handler: "headers" }];
  const reverseProxy = { handler: "reverse_proxy" };

  it("returns null for empty rules", () => {
    const result = buildMtlsRbacSubroutes(
      [],
      new Map(),
      new Map(),
      baseHandlers,
      reverseProxy
    );
    expect(result).toBeNull();
  });

  it("generates allow + deny routes for a role-based rule", () => {
    const roleFpMap = new Map<number, Set<string>>([
      [1, new Set(["ad0001"])],
    ]);
    const rules = [makeRule({ allowedRoleIds: [1] })];

    const result = buildMtlsRbacSubroutes(rules, roleFpMap, new Map(), baseHandlers, reverseProxy);

    expect(result).not.toBeNull();
    // Should have 3 routes: allow /admin/*, deny /admin/*, catch-all
    expect(result!.length).toBe(3);

    // Allow route has expression matcher
    const allowRoute = result![0] as Record<string, unknown>;
    const match = (allowRoute.match as Record<string, unknown>[])[0];
    expect(match.path).toEqual(["/admin/*"]);
    expect(match.expression).toContain("ad0001");
    expect(allowRoute.terminal).toBe(true);

    // Deny route returns 403
    const denyRoute = result![1] as Record<string, unknown>;
    const denyMatch = (denyRoute.match as Record<string, unknown>[])[0];
    expect(denyMatch.path).toEqual(["/admin/*"]);
    const denyHandler = (denyRoute.handle as Record<string, unknown>[])[0];
    expect(denyHandler.status_code).toBe("403");

    // Catch-all has no match
    const catchAll = result![2] as Record<string, unknown>;
    expect(catchAll.match).toBeUndefined();
    expect(catchAll.terminal).toBe(true);
  });

  it("generates 403 for denyAll rule", () => {
    const rules = [makeRule({ denyAll: true })];
    const result = buildMtlsRbacSubroutes(rules, new Map(), new Map(), baseHandlers, reverseProxy);

    expect(result).not.toBeNull();
    // deny route + catch-all = 2
    expect(result!.length).toBe(2);

    const denyRoute = result![0] as Record<string, unknown>;
    const handler = (denyRoute.handle as Record<string, unknown>[])[0];
    expect(handler.status_code).toBe("403");
  });

  it("generates 403 when rule has no matching fingerprints", () => {
    const rules = [makeRule({ allowedRoleIds: [999] })]; // role doesn't exist
    const result = buildMtlsRbacSubroutes(rules, new Map(), new Map(), baseHandlers, reverseProxy);

    expect(result).not.toBeNull();
    // deny route + catch-all = 2
    expect(result!.length).toBe(2);

    const denyRoute = result![0] as Record<string, unknown>;
    const handler = (denyRoute.handle as Record<string, unknown>[])[0];
    expect(handler.status_code).toBe("403");
  });

  it("handles multiple rules with different paths", () => {
    const roleFpMap = new Map<number, Set<string>>([
      [1, new Set(["ad0001"])],
      [2, new Set(["a0b002"])],
    ]);
    const rules = [
      makeRule({ pathPattern: "/admin/*", allowedRoleIds: [1] }),
      makeRule({ pathPattern: "/api/*", allowedRoleIds: [1, 2] }),
    ];

    const result = buildMtlsRbacSubroutes(rules, roleFpMap, new Map(), baseHandlers, reverseProxy);

    expect(result).not.toBeNull();
    // 2 rules × 2 routes each + 1 catch-all = 5
    expect(result!.length).toBe(5);
  });

  it("uses direct cert fingerprints as overrides", () => {
    const certFpMap = new Map<number, string>([[42, "5bec1a"]]);
    const rules = [makeRule({ allowedCertIds: [42] })];

    const result = buildMtlsRbacSubroutes(rules, new Map(), certFpMap, baseHandlers, reverseProxy);

    expect(result).not.toBeNull();
    const allowRoute = result![0] as Record<string, unknown>;
    const match = (allowRoute.match as Record<string, unknown>[])[0];
    expect(match.expression).toContain("5bec1a");
  });

  it("catch-all route includes base handlers + reverse proxy", () => {
    const rules = [makeRule({ denyAll: true })];
    const result = buildMtlsRbacSubroutes(rules, new Map(), new Map(), baseHandlers, reverseProxy);

    const catchAll = result![result!.length - 1] as Record<string, unknown>;
    const handlers = catchAll.handle as Record<string, unknown>[];
    expect(handlers).toHaveLength(2); // baseHandlers[0] + reverseProxy
    expect(handlers[0]).toEqual({ handler: "headers" });
    expect(handlers[1]).toEqual({ handler: "reverse_proxy" });
  });

  it("allow route includes base handlers + reverse proxy", () => {
    const roleFpMap = new Map<number, Set<string>>([[1, new Set(["f0"])]]);
    const rules = [makeRule({ allowedRoleIds: [1] })];
    const result = buildMtlsRbacSubroutes(rules, roleFpMap, new Map(), baseHandlers, reverseProxy);

    const allowRoute = result![0] as Record<string, unknown>;
    const handlers = allowRoute.handle as Record<string, unknown>[];
    expect(handlers).toHaveLength(2);
    expect(handlers[1]).toEqual({ handler: "reverse_proxy" });
  });

  it("deny route body is 'mTLS access denied'", () => {
    const rules = [makeRule({ denyAll: true })];
    const result = buildMtlsRbacSubroutes(rules, new Map(), new Map(), baseHandlers, reverseProxy);
    const denyHandler = (result![0] as any).handle[0];
    expect(denyHandler.body).toBe("mTLS access denied");
  });

  it("requires a valid client cert on the catch-all when requested", () => {
    const roleFpMap = new Map<number, Set<string>>([[1, new Set(["ad0001"])]]);
    const rules = [makeRule({ allowedRoleIds: [1] })];
    const result = buildMtlsRbacSubroutes(rules, roleFpMap, new Map(), baseHandlers, reverseProxy, true);

    expect(result).not.toBeNull();
    const catchAllAllow = result![2] as Record<string, unknown>;
    const catchAllDeny = result![3] as Record<string, unknown>;
    expect((catchAllAllow.match as Record<string, unknown>[])[0].expression).toBe(buildValidClientCertCelExpression());
    expect(((catchAllDeny.handle as Record<string, unknown>[])[0]).status_code).toBe("403");
  });

  it("handles mixed denyAll and role-based rules", () => {
    const roleFpMap = new Map<number, Set<string>>([[1, new Set(["f0"])]]);
    const rules = [
      makeRule({ pathPattern: "/secret/*", denyAll: true }),
      makeRule({ pathPattern: "/api/*", allowedRoleIds: [1] }),
    ];
    const result = buildMtlsRbacSubroutes(rules, roleFpMap, new Map(), baseHandlers, reverseProxy);

    // /secret/* deny + /api/* allow + /api/* deny + catch-all = 4
    expect(result!.length).toBe(4);

    // First route: deny /secret/*
    expect((result![0] as any).match[0].path).toEqual(["/secret/*"]);
    expect((result![0] as any).handle[0].status_code).toBe("403");

    // Second route: allow /api/*
    expect((result![1] as any).match[0].path).toEqual(["/api/*"]);
    expect((result![1] as any).match[0].expression).toContain("'f0'");
  });

  it("handles rule with both roles and certs combined", () => {
    const roleFpMap = new Map<number, Set<string>>([[1, new Set(["00e001"])]]);
    const certFpMap = new Map<number, string>([[42, "ce0001"]]);
    const rules = [makeRule({ allowedRoleIds: [1], allowedCertIds: [42] })];

    const result = buildMtlsRbacSubroutes(rules, roleFpMap, certFpMap, baseHandlers, reverseProxy);
    const match = (result![0] as any).match[0];
    expect(match.expression).toContain("00e001");
    expect(match.expression).toContain("ce0001");
  });

  it("preserves base handlers order in generated routes", () => {
    const multiHandlers = [{ handler: "waf" }, { handler: "headers" }, { handler: "auth" }];
    const roleFpMap = new Map<number, Set<string>>([[1, new Set(["f0"])]]);
    const rules = [makeRule({ allowedRoleIds: [1] })];

    const result = buildMtlsRbacSubroutes(rules, roleFpMap, new Map(), multiHandlers, reverseProxy);
    const allowHandlers = (result![0] as any).handle;
    expect(allowHandlers[0]).toEqual({ handler: "waf" });
    expect(allowHandlers[1]).toEqual({ handler: "headers" });
    expect(allowHandlers[2]).toEqual({ handler: "auth" });
    expect(allowHandlers[3]).toEqual({ handler: "reverse_proxy" });
  });
});

// ── normalizeFingerprint edge cases ──────────────────────────────────

describe("normalizeFingerprint edge cases", () => {
  it("handles full SHA-256 fingerprint with colons", () => {
    const fp = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    expect(normalizeFingerprint(fp)).toBe("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
  });

  it("handles mixed case without colons", () => {
    expect(normalizeFingerprint("AbCdEf")).toBe("abcdef");
  });

  it("handles fingerprint with only colons", () => {
    expect(normalizeFingerprint(":::")).toBe("");
  });
});

// ── buildFingerprintCelExpression edge cases ─────────────────────────

describe("buildFingerprintCelExpression edge cases", () => {
  it("handles empty fingerprint set", () => {
    const expr = buildFingerprintCelExpression(new Set());
    expect(expr).toBe("{http.request.tls.client.fingerprint} in []");
  });

  it("handles many fingerprints", () => {
    const fps = new Set(Array.from({ length: 50 }, (_, i) => `f0${String(i).padStart(3, "0")}`));
    const expr = buildFingerprintCelExpression(fps);
    expect(expr).toContain("f0000");
    expect(expr).toContain("f0049");
    // Verify sorted order
    const idx0 = expr.indexOf("f0000");
    const idx49 = expr.indexOf("f0049");
    expect(idx0).toBeLessThan(idx49);
  });
});

// ── resolveAllowedFingerprints edge cases ────────────────────────────

describe("resolveAllowedFingerprints edge cases", () => {
  it("handles empty arrays in rule", () => {
    const rule = makeRule({ allowedRoleIds: [], allowedCertIds: [] });
    const result = resolveAllowedFingerprints(rule, new Map(), new Map());
    expect(result.size).toBe(0);
  });

  it("handles role with empty fingerprint set", () => {
    const roleFpMap = new Map<number, Set<string>>([[1, new Set()]]);
    const rule = makeRule({ allowedRoleIds: [1] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, new Map());
    expect(result.size).toBe(0);
  });

  it("merges fingerprints from multiple roles correctly", () => {
    const roleFpMap = new Map<number, Set<string>>([
      [1, new Set(["a", "b"])],
      [2, new Set(["b", "c"])],
      [3, new Set(["c", "d"])],
    ]);
    const rule = makeRule({ allowedRoleIds: [1, 2, 3] });
    const result = resolveAllowedFingerprints(rule, roleFpMap, new Map());
    expect(result).toEqual(new Set(["a", "b", "c", "d"]));
  });
});
