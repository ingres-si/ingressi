/**
 * Every guard of a route, page or server action (in app/, or in ee/ for ee/
 * features) names one permission from the catalogue, the call-site
 * table in ee/docs/custom-roles.md matches the code, no route or page is left
 * on the old administrator-only guards, and the sidebar shows each page to
 * exactly the users its page guard lets in.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { callSiteKey, findPermissionCallSites, implementationSource, readDocumentedCallSites } from '../helpers/permission-call-sites';
import { builtInAccess, isPermission, listHeldPermissions, PERMISSIONS, type Access } from '@/src/lib/permissions';
import {
  NAV_ACCOUNT,
  NAV_FOOTER,
  NAV_GROUPS,
  NAV_PAGES,
  visibleEntries,
  visibleNavGroups,
  visibleNavPages,
  type NavViewer,
} from '@/src/lib/navigation';

const ROOT = process.cwd();
const sites = findPermissionCallSites();

function files(dir: string, pattern: RegExp, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) files(path, pattern, out);
    else if (pattern.test(entry)) out.push(relative(ROOT, path));
  }
  return out;
}

describe('permission call sites', () => {
  it('finds the guards', () => {
    expect(sites.length).toBeGreaterThan(250);
  });

  it('names a permission from the catalogue at every call site', () => {
    for (const site of sites) {
      expect(isPermission(site.permission), `${site.file}:${site.line} ${site.permission}`).toBe(true);
    }
  });

  it('uses every permission in the catalogue somewhere', () => {
    const used = new Set(sites.map((site) => site.permission));
    expect(PERMISSIONS.filter((permission) => !used.has(permission))).toEqual([]);
  });

  it('matches the table in ee/docs/custom-roles.md row for row', () => {
    const documented = readDocumentedCallSites(readFileSync(join(ROOT, 'ee/docs/custom-roles.md'), 'utf8'));
    expect(documented.sort()).toEqual(sites.map(callSiteKey).sort());
  });

  it('leaves no route, page or action on requireAdmin or requireApiAdmin', () => {
    const eeRoutesAndPages = files(join(ROOT, 'ee'), /\.(ts|tsx)$/).filter((file) => /^ee\/[^/]+\/(.+\/)?(ui|routes)\//.test(file));
    for (const file of [...files(join(ROOT, 'app'), /\.(ts|tsx)$/), ...eeRoutesAndPages]) {
      expect(/\brequire(Api)?Admin\(/.test(implementationSource(file)), file).toBe(false);
    }
  });

  it('guards every REST route except the public, self-service and token routes', () => {
    // Routes that never needed an administrator: sign-in, forward auth,
    // health, instance sync (its own token) and pull replica polls (their
    // own credential), the caller's own account,
    // sessions, MFA, passkeys, interface preferences and API tokens, the DNS provider catalogue, the
    // public API monetization routes (the gate checks Caddy's gate token, the
    // webhook Stripe's signature, the rest the consumer's key or portal token)
    // the white-label logos the sign-in pages show before sign-in, the
    // access review assignments of the caller and their evidence (being named
    // a reviewer of a campaign is the authorization,
    // ee/access-reviews/decisions.ts), and the overview's "needs attention"
    // list, whose providers each check the caller's permissions
    // (src/lib/attention/registry.ts).
    const unguarded = new Set([
      'app/api/branding/[asset]/route.ts',
      'app/api/v1/access-review-assignments/[id]/route.ts',
      'app/api/v1/access-review-assignments/confirm/route.ts',
      'app/api/v1/access-review-assignments/evidence/route.ts',
      'app/api/v1/access-review-assignments/route.ts',
      'app/api/v1/overview/attention/route.ts',
      'app/api/monetization/gate/route.ts',
      'app/api/monetization/me/card/route.ts',
      'app/api/monetization/me/checkout/route.ts',
      'app/api/monetization/me/pay/route.ts',
      'app/api/monetization/me/route.ts',
      'app/api/monetization/portal/card/route.ts',
      'app/api/monetization/portal/checkout/route.ts',
      'app/api/monetization/portal/pay/route.ts',
      // A sync replica's allowance request: the route authenticates the replica's sync credential.
      'app/api/monetization/replica/allowance/route.ts',
      'app/api/monetization/stripe/webhook/route.ts',
      'app/api/auth/[...all]/route.ts',
      // The MCP endpoint authenticates its own bearer token (src/lib/mcp/server.ts).
      'app/api/mcp/route.ts',
      // The OAuth endpoints: discovery and registration are public by design,
      // the token and revocation endpoints authenticate the client, and the
      // consent POST checks the session and the Origin header itself.
      'app/api/oauth/authorize/route.ts',
      'app/api/oauth/register/route.ts',
      'app/api/oauth/revoke/route.ts',
      'app/api/oauth/token/route.ts',
      'app/api/oauth/well-known/authorization-server/route.ts',
      'app/api/oauth/well-known/protected-resource/route.ts',

      'app/api/auth/link-account/route.ts',
      'app/api/auth/logout/route.ts',
      'app/api/forward-auth/callback/route.ts',
      'app/api/forward-auth/login/route.ts',
      'app/api/forward-auth/session-login/route.ts',
      'app/api/forward-auth/verify/route.ts',
      'app/api/health/route.ts',
      'app/api/instances/pull/route.ts',
      'app/api/instances/sync/route.ts',
      'app/api/user/change-password/route.ts',
      'app/api/user/link-oauth-start/route.ts',
      'app/api/user/unlink-oauth/route.ts',
      'app/api/user/update-avatar/route.ts',
      'app/api/v1/dns-providers/route.ts',
      // The command palette's search: every group of results is filtered by permission inside (src/lib/search.ts).
      'app/api/v1/search/route.ts',
      'app/api/v1/mfa/route.ts',
      'app/api/v1/passkeys/[id]/route.ts',
      'app/api/v1/passkeys/route.ts',
      'app/api/v1/preferences/route.ts',
      'app/api/v1/sessions/[id]/route.ts',
      'app/api/v1/sessions/route.ts',
      'app/api/v1/tokens/[id]/route.ts',
      'app/api/v1/tokens/route.ts',
    ]);
    const guardedFiles = new Set(sites.map((site) => site.file));
    for (const file of files(join(ROOT, 'app/api'), /^route\.ts$/)) {
      if (unguarded.has(file)) continue;
      expect(guardedFiles.has(file), `${file} has no permission guard`).toBe(true);
    }
  });

  it('guards every handler of a guarded REST route', () => {
    const byFile = new Map<string, Set<string>>();
    for (const site of sites) {
      if (!site.file.startsWith('app/api/')) continue;
      byFile.set(site.file, (byFile.get(site.file) ?? new Set()).add(site.fn));
    }
    for (const [file, guarded] of byFile) {
      const source = implementationSource(file);
      const handlers = [...source.matchAll(/export async function (GET|POST|PUT|PATCH|DELETE)\b/g)].map((m) => m[1]);
      // GET /api/v1/users/{id} and its /mfa are also open to the user themself (requireApiUser).
      const selfService = file === 'app/api/v1/users/[id]/route.ts' || file === 'app/api/v1/users/[id]/mfa/route.ts';
      for (const handler of handlers) {
        if (selfService && handler === 'GET') continue;
        expect(guarded.has(handler), `${file} ${handler}`).toBe(true);
      }
    }
  });
});

describe('navigation', () => {
  /** The permission a page's guard checks, or null for pages any signed-in user may open. */
  function pageGuard(href: string): string | null {
    const dir = href === '/' ? 'app/(dashboard)' : `app/(dashboard)${href}`;
    const page = sites.find((site) => site.file === `${dir}/page.tsx`);
    return page?.permission ?? null;
  }

  const viewer = (access: Access): NavViewer => ({ permissions: listHeldPermissions(access), isAdmin: access.isAdmin });
  const sidebar = (who: NavViewer, badges = {}) => [
    ...visibleNavGroups(who, badges).flatMap((group) => group.entries),
    ...visibleEntries(who, NAV_FOOTER, badges),
  ];
  const ALL_ENTRY_KEYS = [...NAV_GROUPS.flatMap((group) => group.entries), ...NAV_FOOTER].map((entry) => entry.key);

  // Form pages opened from another page (like the [id] pages): not navigation
  // destinations of their own, so they are not listed, but guarded all the same.
  const FORM_PAGES: Record<string, string> = { '/proxy-hosts/new': 'proxy_hosts:write', '/l4-proxy-hosts/new': 'l4_proxy_hosts:write' };

  it('lists every dashboard page, each with the permission its page guard checks', () => {
    const pages = files(join(ROOT, 'app/(dashboard)'), /^page\.tsx$/)
      .map((file) => file.slice('app/(dashboard)'.length, -'/page.tsx'.length) || '/')
      .filter((href) => !href.includes('[') && !(href in FORM_PAGES));
    expect(NAV_PAGES.map((page) => page.href).sort()).toEqual(pages.sort());
    for (const page of NAV_PAGES) {
      expect(page.permission ?? null, page.href).toBe(pageGuard(page.href));
    }
    for (const [href, permission] of Object.entries(FORM_PAGES)) {
      expect(pageGuard(href), href).toBe(permission);
    }
  });

  it('shows administrators every entry and user/viewer only the overview and their profile', () => {
    expect(sidebar(viewer(builtInAccess(1, 'admin'))).map((entry) => entry.key)).toEqual(ALL_ENTRY_KEYS);
    for (const role of ['user', 'viewer']) {
      const who = viewer(builtInAccess(2, role));
      expect(sidebar(who).map((entry) => entry.href)).toEqual(['/']);
      expect(visibleEntries(who, NAV_ACCOUNT).map((entry) => entry.href)).toEqual(['/profile']);
      expect(visibleNavPages(who).map((page) => page.href)).toEqual(['/', '/profile']);
    }
  });

  it('shows a custom role the entries it can read', () => {
    const entries = sidebar({ permissions: ['proxy_hosts:read', 'proxy_hosts:write', 'certificates:read'] });
    expect(entries.map((entry) => entry.href)).toEqual(['/', '/proxy-hosts', '/certificates']);
  });

  it('links an entry to the first of its pages the role may open', () => {
    const [, auditLog] = sidebar({ permissions: ['audit_streaming:read'] });
    expect([auditLog.key, auditLog.href]).toEqual(['audit-log', '/audit-log/streaming']);
    const hrefs = sidebar({ permissions: ['groups:read', 'ldap:read', 'branding:read'] }).map((entry) => [entry.key, entry.href]);
    expect(hrefs).toEqual([['overview', '/'], ['users', '/groups'], ['sign-in', '/ldap'], ['branding', '/branding']]);
  });

  it('shows a reviewer without access_reviews:read their own reviews only while some are pending', () => {
    const who = viewer(builtInAccess(3, 'viewer'));
    expect(sidebar(who).map((entry) => entry.key)).toEqual(['overview']);
    const pending = { reviewsDue: { text: '3d', tone: 'warn' as const, label: '2 review items to decide, due in 3 days' } };
    const entries = sidebar(who, pending);
    expect(entries.map((entry) => [entry.key, entry.href])).toEqual([['overview', '/'], ['access-reviews', '/my-reviews']]);
  });

  it('treats administrators as holding every permission', () => {
    expect(sidebar({ permissions: [...PERMISSIONS], isAdmin: false }).length).toBe(ALL_ENTRY_KEYS.length);
  });
});
