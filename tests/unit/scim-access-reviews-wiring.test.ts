/**
 * Wiring of SCIM provisioning and access reviews: the middleware lets
 * /scim/v2 through to its route handlers (which authenticate the SCIM token
 * themselves) without a dashboard session, the OpenAPI document describes
 * every endpoint and every reference resolves, and the navigation shows the
 * pages to the permissions their page guards check.
 */
import { describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';

vi.mock('@/src/lib/auth', () => ({ auth: vi.fn().mockResolvedValue(null) }));
vi.mock('@/src/lib/api-auth', () => ({
  requireApiPermission: vi.fn((request: unknown) => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireApiAdmin(request))),
  requireApiAdmin: vi.fn().mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' }),
  apiErrorResponse: vi.fn(),
}));

import middleware from '@/proxy';
import { GET } from '@/app/api/v1/openapi.json/route';
import { NAV_PAGES } from '@/src/lib/navigation';

async function spec() {
  return (await GET({ headers: { get: () => null } } as never)).json();
}

function expectRefsResolve(doc: any, documented: unknown) {
  const refs = JSON.stringify(documented).match(/"\$ref":"#\/components\/[^"]+"/g) ?? [];
  expect(refs.length).toBeGreaterThan(10);
  for (const ref of new Set(refs)) {
    const path = JSON.parse(`{${ref}}`).$ref.slice('#/'.length).split('/');
    expect(path.reduce((node: any, key: string) => node?.[key], doc), ref).toBeDefined();
  }
}

describe('middleware', () => {
  it('lets SCIM requests through without a dashboard session', async () => {
    for (const path of ['/scim/v2/Users', '/scim/v2/Groups/7', '/scim/v2/ServiceProviderConfig']) {
      const response = await middleware(new NextRequest(`http://localhost:3000${path}`, { headers: { authorization: 'Bearer scim_x' } }));
      expect(response.headers.get('location'), path).toBeNull();
      expect(response.headers.get('content-security-policy')).toBeTruthy();
    }
  });

  it('still sends dashboard pages without a session to the login page', async () => {
    for (const path of ['/scim', '/access-reviews', '/my-reviews']) {
      const response = await middleware(new NextRequest(`http://localhost:3000${path}`));
      const location = new URL(response.headers.get('location')!);
      expect(location.pathname, path).toBe('/login');
      // The page the user asked for survives the sign-in.
      expect(location.searchParams.get('next'), path).toBe(path);
    }
  });
});

describe('OpenAPI', () => {
  it('documents the SCIM administration and protocol endpoints', async () => {
    const doc = await spec();
    const expected: Record<string, string[]> = {
      '/api/v1/scim/settings': ['get', 'put'],
      '/api/v1/scim/tokens': ['get', 'post'],
      '/api/v1/scim/tokens/{id}': ['delete'],
      '/api/v1/scim/role-mappings': ['get', 'post'],
      '/api/v1/scim/role-mappings/{id}': ['put', 'delete'],
      '/api/v1/scim/users': ['get', 'post'],
      '/api/v1/scim/users/{id}': ['delete'],
      '/api/v1/scim/groups': ['get', 'post'],
      '/api/v1/scim/groups/{id}': ['delete'],
      '/scim/v2/ServiceProviderConfig': ['get'],
      '/scim/v2/ResourceTypes': ['get'],
      '/scim/v2/ResourceTypes/{id}': ['get'],
      '/scim/v2/Schemas': ['get'],
      '/scim/v2/Schemas/{id}': ['get'],
      '/scim/v2/Users': ['get', 'post'],
      '/scim/v2/Users/{id}': ['get', 'put', 'patch', 'delete'],
      '/scim/v2/Groups': ['get', 'post'],
      '/scim/v2/Groups/{id}': ['get', 'put', 'patch', 'delete'],
    };
    for (const [path, methods] of Object.entries(expected)) {
      expect(Object.keys(doc.paths[path] ?? {}).sort(), path).toEqual([...methods].sort());
      for (const method of methods) expect(doc.paths[path][method].operationId).toBeTruthy();
    }
    const tags = doc.tags.map((tag: { name: string }) => tag.name);
    expect(tags).toEqual(expect.arrayContaining(['SCIM', 'SCIM 2.0 protocol']));
    const scimSchemas = Object.fromEntries(Object.entries(doc.components.schemas).filter(([name]) => name.startsWith('Scim')));
    expectRefsResolve(doc, [Object.fromEntries(Object.keys(expected).map((path) => [path, doc.paths[path]])), scimSchemas]);
    // Tokens are an output only once, and never part of the token list.
    expect(doc.components.schemas.ScimToken.properties.token).toBeUndefined();
  });

  it('documents the access review endpoints', async () => {
    const doc = await spec();
    const expected: Record<string, string[]> = {
      '/api/v1/access-reviews': ['get', 'post'],
      '/api/v1/access-reviews/{id}': ['get', 'delete'],
      '/api/v1/access-reviews/{id}/complete': ['post'],
      '/api/v1/access-reviews/{id}/cancel': ['post'],
      '/api/v1/access-reviews/{id}/record': ['get'],
      '/api/v1/access-review-schedules': ['get', 'post'],
      '/api/v1/access-review-schedules/{id}': ['get', 'put', 'delete'],
      '/api/v1/access-review-assignments': ['get'],
      '/api/v1/access-review-assignments/{id}': ['put'],
      '/api/v1/access-review-assignments/confirm': ['post'],
    };
    for (const [path, methods] of Object.entries(expected)) {
      expect(Object.keys(doc.paths[path] ?? {}).sort(), path).toEqual([...methods].sort());
      for (const method of methods) {
        expect(doc.paths[path][method].tags).toEqual(['Access Reviews']);
        expect(doc.paths[path][method].operationId).toBeTruthy();
      }
    }
    const reviewSchemas = Object.fromEntries(Object.entries(doc.components.schemas).filter(([name]) => name.startsWith('AccessReview')));
    expectRefsResolve(doc, [Object.fromEntries(Object.keys(expected).map((path) => [path, doc.paths[path]])), reviewSchemas]);
  });
});

describe('navigation', () => {
  it('shows Provisioning and Access Reviews to the read permissions', () => {
    expect(NAV_PAGES.find((page) => page.href === '/scim')?.permission).toBe('scim:read');
    expect(NAV_PAGES.find((page) => page.href === '/access-reviews')?.permission).toBe('access_reviews:read');
    // Reviewers reach /my-reviews from the banner, and from the sidebar only while they have reviews pending.
    expect(NAV_PAGES.find((page) => page.href === '/my-reviews')).toMatchObject({ permission: null, onlyWithBadge: true, entry: 'access-reviews' });
  });
});
