/**
 * Functional tests: rate limiting (caddy-ratelimit plugin).
 *
 * Proxy hosts point at whoami-server:80 and are created over the REST API.
 * Requests go to Caddy on localhost:80 with a Host header (helpers/http.ts),
 * so Caddy sees the Docker gateway address as the client IP.
 *
 * Coverage:
 *   - A per-host client-IP rule answers 429 with Retry-After once the limit
 *     is reached, only on its path; other paths keep working.
 *   - Method filters: only the listed methods are counted.
 *   - A header-keyed rule counts each header value on its own.
 *   - A client-IP rule counts each client on its own (two clients behind a
 *     trusted proxy, told apart by X-Forwarded-For).
 *   - A custom error page for 429 is served with the status preserved.
 *   - Global defaults apply to hosts without rules of their own, an
 *     override with no rules opts a host out, and the allowlist exempts
 *     clients from every rule.
 *   - The Rate limiting sections exist in the host editor and on the Rate limiting page.
 *
 * Every rule uses a one-minute window and paths unique to its test, so
 * counters never carry over between tests. The global defaults are reset
 * afterwards so no other spec is limited.
 *
 * Domains: func-rate-limit-*.test
 */
import http from 'node:http';
import { test, expect } from '@playwright/test';
import { openCreateHostDialog, openEditorSection } from '../../helpers/proxy-api';
import type { Page } from '@playwright/test';
import { httpGet, waitForRoute, waitForStatus } from '../../helpers/http';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const UPSTREAM = 'whoami-server:80';

type Rule = { path?: string; methods?: string[]; key?: string; header?: string; events: number; window: string };

function httpPost(domain: string, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port: 80, path, method: 'POST', headers: { Host: domain, 'Content-Length': '0' } },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode!));
      }
    );
    req.on('error', reject);
    req.end();
  });
}

async function createHost(page: Page, name: string, domain: string, extra: Record<string, unknown> = {}): Promise<number> {
  const res = await page.request.post(`${API}/proxy-hosts`, {
    data: { name, domains: [domain], upstreams: [UPSTREAM], sslForced: false, ...extra },
    headers: { 'Content-Type': 'application/json', Origin: BASE_URL },
  });
  expect(res.status(), await res.text()).toBe(201);
  return (await res.json()).id as number;
}

async function deleteHosts(page: Page, ids: number[]): Promise<void> {
  for (const id of ids) {
    await page.request.delete(`${API}/proxy-hosts/${id}`, { headers: { Origin: BASE_URL } });
  }
}

async function setDefaults(page: Page, value: { enabled: boolean; rules: Rule[]; allowlist: string[] }): Promise<void> {
  const res = await page.request.put(`${API}/settings/rate-limit`, {
    data: value,
    headers: { 'Content-Type': 'application/json', Origin: BASE_URL },
  });
  expect(res.status(), await res.text()).toBe(200);
}

/** The statuses of `count` GET requests, sent one after another. */
async function statuses(domain: string, path: string, count: number, headers: Record<string, string> = {}): Promise<number[]> {
  const result: number[] = [];
  for (let i = 0; i < count; i++) result.push((await httpGet(domain, path, headers)).status);
  return result;
}

test.describe.serial('Rate limiting — per host', () => {
  const DOMAIN = 'func-rate-limit-host.test';
  const hostIds: number[] = [];

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await setDefaults(page, { enabled: false, rules: [], allowlist: [] });
    hostIds.push(await createHost(page, 'Functional Rate Limit Host', DOMAIN, {
      rateLimit: {
        mode: 'override',
        rules: [
          { path: '/limited/*', events: 3, window: '1m' },
          { path: '/login', methods: ['POST'], events: 2, window: '1m' },
          { path: '/api/*', key: 'header', header: 'X-Api-Key', events: 2, window: '1m' },
        ],
      },
      errorPages: [{ statuses: [429], body: 'Slow down, please', contentType: 'text/plain' }],
    }));
    await waitForRoute(DOMAIN);
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    await deleteHosts(page, hostIds);
    await page.close();
  });

  test('answers 429 with Retry-After past the limit, on the rule path only', async () => {
    expect(await statuses(DOMAIN, '/limited/a', 3)).toEqual([200, 200, 200]);
    const limited = await httpGet(DOMAIN, '/limited/b');
    expect(limited.status).toBe(429);
    const retryAfter = Number(limited.headers['retry-after']);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(61);
    // Other paths are not counted by the rule.
    expect((await httpGet(DOMAIN, '/free')).status).toBe(200);
  });

  test('serves the custom 429 error page with the status preserved', async () => {
    const limited = await httpGet(DOMAIN, '/limited/c');
    expect(limited.status).toBe(429);
    expect(limited.body).toBe('Slow down, please');
    expect(limited.headers['retry-after']).toBeDefined();
  });

  test('counts only the listed methods', async () => {
    expect(await statuses(DOMAIN, '/login', 4)).toEqual([200, 200, 200, 200]);
    expect([await httpPost(DOMAIN, '/login'), await httpPost(DOMAIN, '/login'), await httpPost(DOMAIN, '/login')]).toEqual([200, 200, 429]);
  });

  test('counts each header value on its own, and requests without it by client IP', async () => {
    expect(await statuses(DOMAIN, '/api/one', 3, { 'X-Api-Key': 'key-one' })).toEqual([200, 200, 429]);
    expect(await statuses(DOMAIN, '/api/one', 2, { 'X-Api-Key': 'key-two' })).toEqual([200, 200]);
    expect(await statuses(DOMAIN, '/api/one', 3)).toEqual([200, 200, 429]);
  });
});

test.describe.serial('Rate limiting — one counter per client', () => {
  const DOMAIN = 'func-rate-limit-per-client.test';
  const hostIds: number[] = [];
  let originalTrustedProxies: Record<string, unknown> = { ranges: [] };

  async function putTrustedProxies(page: Page, data: Record<string, unknown>): Promise<void> {
    const res = await page.request.put(`${API}/settings/trusted-proxies`, {
      data,
      headers: { 'Content-Type': 'application/json', Origin: BASE_URL },
    });
    expect(res.status(), await res.text()).toBe(200);
  }

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const current = (await (await page.request.get(`${API}/settings/trusted-proxies`)).json()) as Record<string, unknown> | null;
    if (current && Object.keys(current).length > 0) originalTrustedProxies = { ranges: [], ...current };
    await setDefaults(page, { enabled: false, rules: [], allowlist: [] });
    // The test client reaches Caddy from the private Docker gateway: trusted,
    // its X-Forwarded-For names the client, so one test client can be several.
    await putTrustedProxies(page, { ranges: ['private_ranges'] });
    hostIds.push(await createHost(page, 'Functional Rate Limit Per Client', DOMAIN, {
      rateLimit: { mode: 'override', rules: [{ path: '/per-client/*', events: 2, window: '1m' }] },
    }));
    await waitForRoute(DOMAIN);
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    await putTrustedProxies(page, originalTrustedProxies);
    await deleteHosts(page, hostIds);
    await page.close();
  });

  test('a client over the limit does not limit the others', async () => {
    expect(await statuses(DOMAIN, '/per-client/a', 3, { 'X-Forwarded-For': '203.0.113.1' })).toEqual([200, 200, 429]);
    expect(await statuses(DOMAIN, '/per-client/a', 2, { 'X-Forwarded-For': '203.0.113.2' })).toEqual([200, 200]);
    expect(await statuses(DOMAIN, '/per-client/a', 1, { 'X-Forwarded-For': '2001:db8:1::1' })).toEqual([200]);
    expect(await statuses(DOMAIN, '/per-client/b', 1, { 'X-Forwarded-For': '203.0.113.1' })).toEqual([429]);
    expect(await statuses(DOMAIN, '/per-client/b', 1, { 'X-Forwarded-For': '203.0.113.2' })).toEqual([429]);
  });
});

test.describe.serial('Rate limiting — global defaults and allowlist', () => {
  const INHERIT = 'func-rate-limit-inherit.test';
  const OPT_OUT = 'func-rate-limit-optout.test';
  const hostIds: number[] = [];

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await setDefaults(page, { enabled: true, rules: [{ path: '/global/*', events: 2, window: '1m' }], allowlist: [] });
    hostIds.push(await createHost(page, 'Functional Rate Limit Inherit', INHERIT));
    hostIds.push(await createHost(page, 'Functional Rate Limit Opt-out', OPT_OUT, { rateLimit: { mode: 'override', rules: [] } }));
    await waitForRoute(INHERIT);
    await waitForRoute(OPT_OUT);
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    await setDefaults(page, { enabled: false, rules: [], allowlist: [] });
    await deleteHosts(page, hostIds);
    await page.close();
  });

  test('a host without rules of its own inherits the defaults', async () => {
    expect(await statuses(INHERIT, '/global/a', 3)).toEqual([200, 200, 429]);
  });

  test('override with no rules opts a host out', async () => {
    expect(await statuses(OPT_OUT, '/global/a', 4)).toEqual([200, 200, 200, 200]);
  });

  test('allowlisted clients are never limited', async ({ page }) => {
    await setDefaults(page, {
      enabled: true,
      rules: [{ path: '/global/*', events: 2, window: '1m' }],
      allowlist: ['0.0.0.0/0', '::/0'],
    });
    await waitForStatus(INHERIT, 200);
    expect(await statuses(INHERIT, '/global/b', 4)).toEqual([200, 200, 200, 200]);
  });
});

test.describe('Rate limiting — dashboard', () => {
  test('the host editor and the Rate limiting page have the rules', async ({ page }) => {
    await openCreateHostDialog(page);
    await openEditorSection(page, 'Security');
    await expect(page.getByRole('heading', { name: 'Rate limiting', exact: true })).toBeVisible();
    const card = page.locator('#rate-limiting');
    await card.getByRole('group', { name: 'Limits' }).getByRole('button', { name: "Global and this host's" }).click();
    await card.getByRole('button', { name: 'Add rule' }).click();
    await expect(card.getByTestId('rate-limit-rule')).toHaveCount(1);

    await page.goto('/rate-limiting');
    await expect(page.getByTestId('rate-limit-settings')).toBeVisible();
    await expect(page.getByTestId('settings-save-bar').getByRole('button', { name: 'Save changes' })).toBeVisible();
  });
});
