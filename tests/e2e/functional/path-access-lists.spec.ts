/**
 * Functional tests: access lists for some paths of a host (#387), enforced by
 * the real Caddy. The host itself stays public; only the listed paths run the
 * list's rules and Basic Auth.
 *
 * The test client reaches Caddy from a private address (the Docker bridge),
 * so private_ranges stands for "this client".
 *
 * Domain: func-path-acl.test
 */
import { resolve } from 'node:path';
import { test, expect, request as playwrightRequest } from '@playwright/test';
import { httpGet, waitForRoute } from '../../helpers/http';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
const DOMAIN = 'func-path-acl.test';
const ECHO_BODY = 'echo-ok';
const BASIC = `Basic ${Buffer.from('carol:Carol-Passw0rd!').toString('base64')}`;

async function waitForPathStatus(path: string, expected: number, headers: Record<string, string> = {}, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 0;
  while (Date.now() < deadline) {
    last = (await httpGet(DOMAIN, path, headers).catch(() => ({ status: 0 }))).status;
    if (last === expected) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${DOMAIN}${path} answered ${last}, expected ${expected}`);
}

test.describe.serial('Access lists for paths', () => {
  const listIds: number[] = [];
  let hostId: number | null = null;
  let officeId = 0;
  let membersId = 0;

  test.afterAll(async () => {
    const request = await playwrightRequest.newContext({ storageState: resolve(__dirname, '../../.auth/admin.json') });
    if (hostId !== null) await request.delete(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS });
    for (const id of listIds) await request.delete(`${API}/access-lists/${id}`, { headers: HEADERS });
    await request.dispose();
  });

  test('setup: a public host with a deny-all list on /admin and a members list on /members', async ({ request }) => {
    const office = await request.post(`${API}/access-lists`, {
      headers: HEADERS,
      data: { name: 'Functional path ACL', defaultAction: 'deny', denyStatus: 451, denyBody: 'Not from here' },
    });
    expect(office.status()).toBe(201);
    officeId = ((await office.json()) as { id: number }).id;
    listIds.push(officeId);

    const members = await request.post(`${API}/access-lists`, {
      headers: HEADERS,
      data: { name: 'Functional path members', users: [{ username: 'carol', password: 'Carol-Passw0rd!' }] },
    });
    expect(members.status()).toBe(201);
    membersId = ((await members.json()) as { id: number }).id;
    listIds.push(membersId);

    const hostRes = await request.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: {
        name: 'Functional path ACL host',
        domains: [DOMAIN],
        upstreams: ['echo-server:8080'],
        sslForced: false,
        pathAccessLists: [
          { path: '/admin', accessListId: officeId },
          { path: '/admin/*', accessListId: officeId },
          { path: '/members/*', accessListId: membersId },
        ],
      },
    });
    expect(hostRes.status()).toBe(201);
    const host = (await hostRes.json()) as { id: number; pathAccessLists: unknown };
    hostId = host.id;
    expect(host.pathAccessLists).toHaveLength(3);
    await waitForRoute(DOMAIN);
  });

  test('the listed paths are denied while the rest of the host is public', async () => {
    await waitForPathStatus('/admin/settings', 451);
    expect((await httpGet(DOMAIN, '/admin/settings')).body).toBe('Not from here');
    expect((await httpGet(DOMAIN, '/admin')).status).toBe(451);
    expect((await httpGet(DOMAIN, '/ADMIN/settings')).status).toBe(451);
    const open = await httpGet(DOMAIN, '/');
    expect(open.status).toBe(200);
    expect(open.body).toContain(ECHO_BODY);
    expect((await httpGet(DOMAIN, '/administrator')).status).toBe(200);
  });

  test("a path list's members must sign in, only on that path", async () => {
    expect((await httpGet(DOMAIN, '/members/area')).status).toBe(401);
    const signedIn = await httpGet(DOMAIN, '/members/area', { Authorization: BASIC });
    expect(signedIn.status).toBe(200);
    expect(signedIn.body).toContain(ECHO_BODY);
    expect((await httpGet(DOMAIN, '/other')).status).toBe(200);
  });

  test('an allow rule for the client opens the path', async ({ request }) => {
    const res = await request.put(`${API}/access-lists/${officeId}/rules`, {
      headers: HEADERS,
      data: { rules: [{ action: 'allow', kind: 'ip', values: ['private_ranges'] }] },
    });
    expect(res.status()).toBe(200);
    await waitForPathStatus('/admin/settings', 200);
  });

  test('a list that does not exist is refused', async ({ request }) => {
    const res = await request.put(`${API}/proxy-hosts/${hostId}`, {
      headers: HEADERS,
      data: { pathAccessLists: [{ path: '/admin/*', accessListId: 987654 }] },
    });
    expect(res.status()).toBe(400);
  });

  test('deleting a list takes it off the paths that used it', async ({ request }) => {
    const del = await request.delete(`${API}/access-lists/${membersId}`, { headers: HEADERS });
    expect(del.ok()).toBe(true);
    listIds.splice(listIds.indexOf(membersId), 1);
    await waitForPathStatus('/members/area', 200);
    const host = (await (await request.get(`${API}/proxy-hosts/${hostId}`)).json()) as { pathAccessLists: Array<{ path: string }> };
    expect(host.pathAccessLists.map((rule) => rule.path)).toEqual(['/admin', '/admin/*']);
  });
});
