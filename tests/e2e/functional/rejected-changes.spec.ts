/**
 * A change Caddy rejects is not kept (src/lib/rejected-apply.ts,
 * src/lib/settings-rollback.ts), against the real Caddy: stored, it would
 * make every later apply fail for every host. Each case stores something no
 * validation catches, lets Caddy reject the configuration, and checks that
 * the change is gone, that the answer says so, and that the hosts keep
 * serving and later changes still apply.
 */
import { test, expect, type Page } from '@playwright/test';
import { httpGet, waitForStatus } from '../../helpers/http';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
const DOMAIN = 'rejected-changes.test';
const BULK_DOMAIN = 'rejected-bulk.test';

// The directive filter lets it through; Coraza cannot compile the regular
// expression, so Caddy rejects the whole configuration.
const BROKEN_WAF = { enabled: true, mode: 'On', custom_directives: 'SecRule ARGS "@rx (" "id:900001,phase:1,deny"' };

type Host = { id: number; name: string; enabled: boolean; waf: unknown; certificateId: number | null };

async function hosts(page: Page): Promise<Host[]> {
  const res = await page.request.get(`${API}/proxy-hosts`);
  expect(res.ok(), await res.text()).toBe(true);
  const body = (await res.json()) as Host[] | { hosts: Host[] };
  return Array.isArray(body) ? body : body.hosts;
}

async function host(page: Page, id: number): Promise<Host> {
  const res = await page.request.get(`${API}/proxy-hosts/${id}`);
  expect(res.ok(), await res.text()).toBe(true);
  return (await res.json()) as Host;
}

test.describe.serial('A change Caddy rejects is not kept', () => {
  let hostId: number;
  const cleanup: Array<{ path: string }> = [];

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const res = await page.request.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: { name: 'Rejected changes', domains: [DOMAIN], upstreams: ['echo-server:8080'], sslForced: false },
    });
    expect(res.status(), await res.text()).toBe(201);
    hostId = ((await res.json()) as Host).id;
    await waitForStatus(DOMAIN, 200, 30_000);
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    for (const { path } of cleanup) await page.request.delete(`${API}${path}`, { headers: HEADERS });
    await page.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS });
    await page.close();
  });

  test('a new host is refused and not stored', async ({ page }) => {
    const res = await page.request.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: { name: 'Rejected new host', domains: ['rejected-new.test'], upstreams: ['echo-server:8080'], sslForced: false, waf: BROKEN_WAF },
    });
    expect(res.status(), await res.text()).toBe(400);
    // Where Caddy stopped, and for an administrator at which host.
    expect(((await res.json()) as { error: string }).error).toBe(
      'Caddy did not accept the configuration with this change, so the proxy host was not saved: ' +
        "the problem is in the WAF rules (the global ones or the proxy host's own) (proxy host rejected-new.test)"
    );
    expect((await hosts(page)).map((h) => h.name)).not.toContain('Rejected new host');
  });

  test('an update is taken back, and the host keeps serving as before', async ({ page }) => {
    const before = await host(page, hostId);
    const res = await page.request.put(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS, data: { name: 'Renamed with a broken WAF', waf: BROKEN_WAF } });
    expect(res.status(), await res.text()).toBe(400);
    expect(await host(page, hostId)).toEqual(before);
    expect((await httpGet(DOMAIN)).status).toBe(200);
  });

  test('a bulk enable is taken back as a whole', async ({ page }) => {
    // A disabled host is not in the configuration, so Caddy does not see its WAF rules yet.
    const res = await page.request.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: { name: 'Rejected bulk', domains: [BULK_DOMAIN], upstreams: ['echo-server:8080'], sslForced: false, enabled: false, waf: BROKEN_WAF },
    });
    expect(res.status(), await res.text()).toBe(201);
    const bulkId = ((await res.json()) as Host).id;
    cleanup.push({ path: `/proxy-hosts/${bulkId}` });

    await page.goto('/proxy-hosts?search=rejected-bulk');
    await page.getByRole('checkbox', { name: `Select ${BULK_DOMAIN}` }).click();
    await page.getByRole('button', { name: 'Enable', exact: true }).click();
    await expect(page.getByText(/so the changes were not saved/)).toBeVisible({ timeout: 20_000 });
    expect((await host(page, bulkId)).enabled).toBe(false);
    expect((await httpGet(DOMAIN)).status).toBe(200);
  });

  test('a certificate that is not one is refused before it is stored', async ({ page }) => {
    const cert = await page.request.post(`${API}/certificates`, {
      headers: HEADERS,
      data: { name: 'Not PEM', type: 'imported', domainNames: [DOMAIN], certificatePem: 'not pem', privateKeyPem: 'not a key' },
    });
    expect(cert.status(), await cert.text()).toBe(400);
    expect(((await cert.json()) as { error: string }).error).toMatch(/The certificate must be PEM/);

    const ca = await page.request.post(`${API}/ca-certificates`, { headers: HEADERS, data: { name: 'Not PEM CA', certificatePem: 'not pem' } });
    expect(ca.status(), await ca.text()).toBe(400);

    const names = async (path: string) => ((await (await page.request.get(`${API}${path}`)).json()) as { name: string }[]).map((item) => item.name);
    expect(await names('/certificates')).not.toContain('Not PEM');
    expect(await names('/ca-certificates')).not.toContain('Not PEM CA');
    expect((await host(page, hostId)).certificateId).toBeNull();
  });

  test('settings saved from the dashboard are put back', async ({ page }) => {
    const before = await (await page.request.get(`${API}/settings/geoblock`)).json();
    try {
      await page.goto('/geo-blocking');
      const main = page.getByRole('main');
      const enable = main.getByRole('switch');
      if (!(await enable.isChecked())) await enable.click();
      await main.getByRole('tab', { name: /block rules/i }).click();
      const cidrs = main.locator('div:has(> input[name="geoblockBlockCidrs"])').locator('input[type="text"]');
      await cidrs.fill('not-a-cidr');
      await cidrs.press('Enter');
      await main.getByRole('button', { name: 'Save changes' }).click();
      await expect(main.getByText(/Caddy did not accept these settings, so they were not saved/)).toBeVisible({ timeout: 20_000 });
      expect(await (await page.request.get(`${API}/settings/geoblock`)).json()).toEqual(before);
      expect((await httpGet(DOMAIN)).status).toBe(200);
    } finally {
      // Only if the settings were kept after all, so that the specs after this one are not affected.
      const after = await (await page.request.get(`${API}/settings/geoblock`)).json();
      if (JSON.stringify(after) !== JSON.stringify(before)) {
        await page.request.put(`${API}/settings/geoblock`, {
          headers: HEADERS,
          data: { ...after, enabled: false, block_cidrs: [] },
        });
      }
    }
  });

  test('later changes still apply', async ({ page }) => {
    const res = await page.request.put(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS, data: { name: 'Rejected changes, renamed' } });
    expect(res.status(), await res.text()).toBe(200);
    expect((await host(page, hostId)).name).toBe('Rejected changes, renamed');
    expect((await httpGet(DOMAIN)).status).toBe(200);
  });
});
