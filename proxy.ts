import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import crypto from "node:crypto";
import { auth } from "@/src/lib/auth";
import { MFA_SETUP_PATH, mfaEnrolmentRequired } from "@/src/lib/mfa";
import { buildCsp } from "@/src/lib/csp";
import { isHaStandby } from "@/ee/high-availability/role";
import { isRequestPathRoute } from "@/ee/high-availability/request-path";
import { standbyResponse } from "@/ee/high-availability/standby-response";
import { replicaRefusal, replicaRefusedResponse } from "@/ee/high-availability/replica-admission";

/**
 * Next.js Proxy for route protection.
 * Provides defense-in-depth by checking authentication at the edge
 * before requests reach page components.
 *
 * Note: Proxy always runs on Node.js runtime.
 */

/**
 * Continue the request with the nonce-based CSP. The policy is also set as a
 * request header, which is where the root layout reads the nonce from; this
 * overwrites any Content-Security-Policy header the client sent.
 */
function withSecurityHeaders(req: NextRequest): NextResponse {
  const nonce = crypto.randomBytes(16).toString("base64");
  const csp = buildCsp(nonce);

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");
  return response;
}

export default async function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname;

  // A high availability standby (ee/docs/high-availability.md) answers the
  // health check and the request-path routes only; the dashboard and the API
  // are the leader's. The routes continue to their usual handling below.
  if (isHaStandby() && pathname !== "/api/health" && !isRequestPathRoute(pathname)) {
    return standbyResponse(pathname);
  }

  // A PostgreSQL replica the cluster did not admit (src/lib/cluster-nodes.ts:
  // another process runs with its node id) serves nothing but its health check.
  const refusal = replicaRefusal();
  if (refusal && pathname !== "/api/health") {
    return replicaRefusedResponse(pathname, refusal);
  }

  // The API monetization gate: Caddy calls it once for every request to a
  // monetized host, and it authenticates Caddy with its own gate token. It
  // skips the session lookup and the page headers to stay cheap.
  if (pathname === "/api/monetization/gate") {
    return NextResponse.next();
  }

  // White-label logos and favicon: public, because the sign-in pages and the
  // forward-auth portal show them before sign-in. The route sets its own
  // image headers (nosniff, a sandboxing CSP), which the page policy below
  // would replace.
  if (pathname.startsWith("/api/branding/")) {
    return NextResponse.next();
  }

  // Allow public routes. They get the same security headers as authenticated
  // pages as defense in depth. After a credential login the login page loads
  // the dashboard as a new document, which gets its own policy and nonce.
  if (
    pathname === "/login" ||
    pathname === "/portal" ||
    pathname.startsWith("/api/auth") ||
    // The MCP endpoint authenticates its own bearer token; the OAuth
    // endpoints are public by design (discovery, registration, token
    // exchange), and the consent POST checks the session and Origin itself.
    pathname === "/api/mcp" ||
    pathname.startsWith("/api/oauth/") ||
    pathname.startsWith("/.well-known/") ||
    pathname === "/api/health" ||
    pathname === "/api/instances/sync" ||
    // Pull replicas (ee/fleet): the route authenticates the replica's pull
    // credential and proof of its sync key itself.
    pathname === "/api/instances/pull" ||
    pathname.startsWith("/api/v1/") ||
    // SCIM provisioning (ee/scim): the route handlers authenticate the
    // identity provider's SCIM token themselves.
    pathname.startsWith("/scim/v2/") ||
    pathname.startsWith("/api/forward-auth/") ||
    // API monetization: the Stripe webhook, the consumer API and the consumer
    // portal authenticate with signatures, API keys and portal tokens.
    pathname.startsWith("/api/monetization/") ||
    pathname === "/api-portal" ||
    pathname.startsWith("/api-portal/")
  ) {
    return withSecurityHeaders(req);
  }

  // Check authentication for protected routes
  const session = await auth(req);
  const isAuthenticated = !!session?.user;

  // Redirect unauthenticated users to login, keeping where they were going so
  // an OAuth consent link (and any deep link) survives the sign-in. Only a
  // same-origin path is kept: a scheme and host would be an open redirect.
  if (!isAuthenticated && !pathname.startsWith("/login")) {
    const loginUrl = new URL("/login", req.url);
    const next = `${pathname}${req.nextUrl.search}`;
    if (next.startsWith("/") && !next.startsWith("//")) loginUrl.searchParams.set("next", next);
    return NextResponse.redirect(loginUrl);
  }

  // An account the MFA policy requires to set up MFA, after the grace
  // period, can only reach the setup page (src/lib/mfa.ts).
  if (session?.user && pathname !== MFA_SETUP_PATH && await mfaEnrolmentRequired(Number(session.user.id))) {
    return NextResponse.redirect(new URL(MFA_SETUP_PATH, req.url));
  }

  return withSecurityHeaders(req);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - maplibre (maplibre-gl's tile worker bundle, staged into public/ at
     *   build time; it must load as a module script even if the session has
     *   expired, otherwise the redirect to /login is parsed as JS and the
     *   analytics map silently breaks)
     * - public folder
     */
    "/((?!_next/static|_next/image|favicon.ico|maplibre/|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
