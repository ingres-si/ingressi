/**
 * The PROXY protocol sources across instance sync: a master (web-master:3002)
 * pushes them to its slave (web-slave:3003) with the other trusted proxy
 * settings, the slave's own Caddy (caddy-slave) reads PROXY headers from
 * them, and a slave that overrides Trusted proxies keeps sources of its own
 * until the override is turned off again.
 *
 * Both instances have isolated Caddy sidecars, so nothing here touches the
 * shared E2E Caddy.
 */
import { execFileSync } from 'node:child_process';
import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';

const MASTER = 'http://localhost:3002';
const SLAVE = 'http://localhost:3003';
const DOMAIN = 'pp-sync.test';

async function loginContext(browser: Browser, baseURL: string): Promise<BrowserContext> {
  const context = await browser.newContext({ baseURL });
  const page = await context.newPage();
  await page.goto(`${baseURL}/login`);
  await page.getByRole('textbox', { name: /username/i }).fill('testadmin');
  await page.getByRole('textbox', { name: /password/i }).fill('TestPassword2026!');
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 20_000 });
  await page.close();
  return context;
}

/** The `allow` list of the PROXY protocol listener wrapper in `container`'s Caddy, or null without one. */
function liveAllow(container: string): string[] | null {
  try {
    const out = execFileSync(
      'docker',
      ['exec', container, 'wget', '-qO-', 'http://localhost:2019/config/apps/http/servers/ingressi/listener_wrappers'],
      { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const wrappers = JSON.parse(out) as Array<{ wrapper: string; allow?: string[] }> | null;
    return wrappers?.find((wrapper) => wrapper.wrapper === 'proxy_protocol')?.allow ?? null;
  } catch {
    return null;
  }
}

test.describe.serial('Instance sync — PROXY protocol sources', () => {
  let master: BrowserContext;
  let slave: BrowserContext;
  let hostId: number | null = null;

  const masterHeaders = { 'Content-Type': 'application/json', Origin: MASTER };

  async function setOnMaster(data: Record<string, unknown>) {
    const res = await master.request.put(`${MASTER}/api/v1/settings/trusted-proxies`, { headers: masterHeaders, data });
    expect(res.status(), await res.text()).toBe(200);
  }

  async function sync() {
    const res = await master.request.post(`${MASTER}/api/v1/instances/sync`, { headers: { Origin: MASTER } });
    expect(res.status(), await res.text()).toBe(200);
    expect(await res.json()).toMatchObject({ total: 1, success: 1, failed: 0 });
  }

  async function slaveSources(): Promise<unknown> {
    const res = await slave.request.get(`${SLAVE}/api/v1/settings/trusted-proxies`);
    if (res.status() !== 200) return 'unreachable';
    return ((await res.json()) as { proxy_protocol_ranges?: string[] }).proxy_protocol_ranges ?? null;
  }

  async function openSlaveCard(): Promise<Page> {
    const page = await slave.newPage();
    await page.goto(`${SLAVE}/proxy-hosts/defaults`);
    await page.waitForLoadState('networkidle');
    return page;
  }

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(120_000);
    master = await loginContext(browser, MASTER);
    slave = await loginContext(browser, SLAVE);
    // Caddy runs the main server, which carries the listener wrappers, only with a host.
    const res = await master.request.post(`${MASTER}/api/v1/proxy-hosts`, {
      headers: masterHeaders,
      data: { name: 'PROXY protocol sync', domains: [DOMAIN], upstreams: ['echo-server:8080'], sslForced: false },
    });
    expect(res.status(), await res.text()).toBe(201);
    hostId = ((await res.json()) as { id: number }).id;
    await setOnMaster({ ranges: [] });
    await sync();
  });

  test.afterAll(async () => {
    // A slave override left behind would outlive this spec: turn it off from the slave's page.
    const page = await openSlaveCard().catch(() => null);
    if (page) {
      const override = page.locator('#trusted-proxies').getByRole('switch', { name: "Override the master's settings on this replica" });
      if ((await override.getAttribute('aria-checked')) === 'true') {
        await override.click();
        await page.getByTestId('settings-save-bar').getByRole('button', { name: 'Save changes' }).click();
        await expect(page.getByTestId('settings-save-bar')).toContainText('reset to master defaults');
      }
      await page.close();
    }
    await setOnMaster({ ranges: [] });
    if (hostId !== null) await master.request.delete(`${MASTER}/api/v1/proxy-hosts/${hostId}`, { headers: { Origin: MASTER } });
    await master.request.post(`${MASTER}/api/v1/instances/sync`, { headers: { Origin: MASTER } });
    await master.close();
    await slave.close();
  });

  test('the master pushes its sources to the slave, and both Caddys read PROXY headers from them', async () => {
    await setOnMaster({ ranges: [], proxy_protocol_ranges: ['192.0.2.80', '198.51.100.7/24'] });
    await expect.poll(() => liveAllow('ingressi-caddy-master')).toEqual(['192.0.2.80/32', '198.51.100.0/24']);
    await sync();
    await expect.poll(slaveSources, { timeout: 20_000 }).toEqual(['192.0.2.80', '198.51.100.0/24']);
    await expect.poll(() => liveAllow('ingressi-caddy-slave'), { timeout: 20_000 }).toEqual(['192.0.2.80/32', '198.51.100.0/24']);
  });

  test("the slave's page shows the master's sources, read-only until it overrides", async () => {
    const page = await openSlaveCard();
    const card = page.locator('#trusted-proxies');
    const field = card.getByLabel('PROXY protocol from');
    await expect(field).toHaveValue('192.0.2.80\n198.51.100.0/24');
    await expect(field).toBeDisabled();
    await card.getByRole('switch', { name: "Override the master's settings on this replica" }).click();
    await expect(field).toBeEnabled();
    await page.close();
  });

  test('a slave that overrides Trusted proxies keeps its own sources across syncs', async () => {
    const page = await openSlaveCard();
    const card = page.locator('#trusted-proxies');
    await card.getByRole('switch', { name: "Override the master's settings on this replica" }).click();
    await card.getByLabel('PROXY protocol from').fill('192.0.2.99');
    await page.getByTestId('settings-save-bar').getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByTestId('settings-save-bar')).toContainText('Trusted proxies settings saved and applied successfully');
    await page.close();
    expect(await slaveSources()).toEqual(['192.0.2.99']);
    await expect.poll(() => liveAllow('ingressi-caddy-slave')).toEqual(['192.0.2.99/32']);

    await setOnMaster({ ranges: [], proxy_protocol_ranges: ['192.0.2.81'] });
    await sync();
    // The master moved on; the slave keeps its own list.
    await expect.poll(() => liveAllow('ingressi-caddy-master')).toEqual(['192.0.2.81/32']);
    expect(await slaveSources()).toEqual(['192.0.2.99']);
    expect(liveAllow('ingressi-caddy-slave')).toEqual(['192.0.2.99/32']);
  });

  test("turning the override off returns the slave to the master's sources", async () => {
    const page = await openSlaveCard();
    const card = page.locator('#trusted-proxies');
    await card.getByRole('switch', { name: "Override the master's settings on this replica" }).click();
    await page.getByTestId('settings-save-bar').getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByTestId('settings-save-bar')).toContainText('Trusted proxies settings reset to master defaults');
    await page.close();
    await expect.poll(slaveSources).toEqual(['192.0.2.81']);
    await expect.poll(() => liveAllow('ingressi-caddy-slave')).toEqual(['192.0.2.81/32']);
  });

  test('clearing the sources on the master clears them on the slave', async () => {
    await setOnMaster({ ranges: [] });
    await sync();
    await expect.poll(slaveSources, { timeout: 20_000 }).toBeNull();
    await expect.poll(() => liveAllow('ingressi-caddy-slave'), { timeout: 20_000 }).toBeNull();
    expect(liveAllow('ingressi-caddy-master')).toBeNull();
  });
});
