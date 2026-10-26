/**
 * The PROXY protocol sources on Host defaults → Trusted proxies, in the
 * browser: the field, saving it with the page's one save bar, what is
 * refused and how the page says so, how it lives next to the other trusted
 * proxy settings, what the REST API and the running Caddy get from it, and
 * how it is found (command palette, old links, the API reference).
 *
 * What Caddy then does with the header is tested through the real Caddy in
 * functional/proxy-protocol.spec.ts.
 */
import { execFileSync } from 'node:child_process';
import { test, expect, type Page } from '@playwright/test';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
const SAVED = 'Trusted proxies settings saved and applied successfully';

/** Open a page and wait until it is interactive: fields typed into before hydration do not count as changes. */
async function open(page: Page, path = '/proxy-hosts/defaults') {
  await page.goto(path);
  await page.waitForLoadState('networkidle');
}

function card(page: Page) {
  return page.getByRole('main').locator('#trusted-proxies');
}

function sourcesField(page: Page) {
  return card(page).getByLabel('PROXY protocol from');
}

function saveBar(page: Page) {
  return page.getByRole('main').getByTestId('settings-save-bar');
}

async function save(page: Page) {
  await saveBar(page).getByRole('button', { name: 'Save changes' }).click();
}

async function readSettings(page: Page): Promise<Record<string, unknown>> {
  const res = await page.request.get(`${API}/settings/trusted-proxies`);
  expect(res.ok(), await res.text()).toBe(true);
  return (await res.json()) as Record<string, unknown>;
}

async function writeSettings(page: Page, data: Record<string, unknown>) {
  const res = await page.request.put(`${API}/settings/trusted-proxies`, { headers: HEADERS, data });
  expect(res.status(), await res.text()).toBe(200);
}

/** The `allow` list of the PROXY protocol listener wrapper in the running Caddy, or null without one. */
function liveAllow(): string[] | null {
  try {
    const out = execFileSync(
      'docker',
      ['exec', 'ingressi-caddy', 'wget', '-qO-', 'http://localhost:2019/config/apps/http/servers/ingressi/listener_wrappers'],
      { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const wrappers = JSON.parse(out) as Array<{ wrapper: string; allow?: string[] }> | null;
    return wrappers?.find((wrapper) => wrapper.wrapper === 'proxy_protocol')?.allow ?? null;
  } catch {
    return null;
  }
}

test.describe.serial('Host defaults — PROXY protocol sources', () => {
  let original: Record<string, unknown> = { ranges: [] };
  let hostId: number | null = null;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const settings = await readSettings(page);
    if (Object.keys(settings).length > 0) original = { ranges: [], ...settings };
    // Caddy runs the main server, which carries the listener wrappers, only with a host.
    const res = await page.request.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: { name: 'PROXY protocol settings', domains: ['pp-settings.test'], upstreams: ['echo-server:8080'], sslForced: false },
    });
    expect(res.status(), await res.text()).toBe(201);
    hostId = ((await res.json()) as { id: number }).id;
    await page.close();
  });

  test.beforeEach(async ({ page }) => {
    await writeSettings(page, { ranges: [] });
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    await writeSettings(page, original);
    if (hostId !== null) await page.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS });
    await page.close();
  });

  test('Trusted proxies has the field, empty without sources, with what it does', async ({ page }) => {
    await open(page);
    await expect(card(page).getByRole('heading', { level: 2, name: 'Trusted proxies' })).toBeVisible();
    await expect(sourcesField(page)).toBeVisible();
    await expect(sourcesField(page)).toHaveValue('');
    await expect(sourcesField(page)).toBeEditable();
    await expect(sourcesField(page)).toHaveAttribute('placeholder', '192.168.1.1\n10.0.10.0/24');
    await expect(card(page)).toContainText('TCP load balancers that send a PROXY header (v1 or v2) to ports 80 and 443.');
    await expect(card(page)).toContainText('other clients connect as before');
    // It comes after the X-Forwarded-For settings of the same card.
    const ranges = await card(page).getByLabel('Trusted ranges').boundingBox();
    const sources = await sourcesField(page).boundingBox();
    expect(sources!.y).toBeGreaterThan(ranges!.y);
  });

  test('saving sources applies them; the page, the REST API and Caddy read them back normalized', async ({ page }) => {
    await open(page);
    await sourcesField(page).fill('192.168.1.1/24\n10.0.10.7\n10.0.10.7\n\n2001:DB8::1');
    await expect(saveBar(page)).toContainText('1 unsaved change in Host defaults');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    await expect(saveBar(page)).toContainText(/Saved at \d\d:\d\d UTC\./);

    expect((await readSettings(page)).proxy_protocol_ranges).toEqual(['192.168.1.0/24', '10.0.10.7', '2001:db8::1']);
    await expect.poll(liveAllow).toEqual(['192.168.1.0/24', '10.0.10.7/32', '2001:db8::1/128']);

    await page.reload();
    await page.waitForLoadState('networkidle');
    await expect(sourcesField(page)).toHaveValue('192.168.1.0/24\n10.0.10.7\n2001:db8::1');
    await expect(saveBar(page)).toContainText('No unsaved changes.');
  });

  test('commas and spaces separate sources too', async ({ page }) => {
    await open(page);
    await sourcesField(page).fill('192.0.2.10, 192.0.2.11   192.0.2.12');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect((await readSettings(page)).proxy_protocol_ranges).toEqual(['192.0.2.10', '192.0.2.11', '192.0.2.12']);
  });

  test('the save bar counts the field as a change, and Discard puts it back', async ({ page }) => {
    await writeSettings(page, { ranges: [], proxy_protocol_ranges: ['192.0.2.20'] });
    await open(page);
    await expect(sourcesField(page)).toHaveValue('192.0.2.20');
    await sourcesField(page).fill('192.0.2.21');
    await expect(saveBar(page)).toContainText('1 unsaved change in Host defaults');
    await saveBar(page).getByRole('button', { name: 'Discard' }).click();
    await expect(sourcesField(page)).toHaveValue('192.0.2.20');
    await expect(saveBar(page)).toContainText('No unsaved changes');
    expect((await readSettings(page)).proxy_protocol_ranges).toEqual(['192.0.2.20']);
  });

  for (const [entry, message] of [
    ['0.0.0.0/0', 'PROXY protocol sources: "0.0.0.0/0" matches every address, so any client could set its own address'],
    ['::/0', 'PROXY protocol sources: "::/0" matches every address, so any client could set its own address'],
    ['private_ranges', 'PROXY protocol sources: "private_ranges" is not accepted here; list the addresses of the load balancers'],
    ['firewall.lan', 'PROXY protocol sources: "firewall.lan" is not an IP address or a CIDR range'],
    ['10.0.0.0/33', 'PROXY protocol sources: "10.0.0.0/33" is not an IP address or a CIDR range'],
  ] as const) {
    test(`"${entry}" is refused by name, nothing is saved and the change stays unsaved`, async ({ page }) => {
      await writeSettings(page, { ranges: [], proxy_protocol_ranges: ['192.0.2.30'] });
      await open(page);
      await sourcesField(page).fill(`192.0.2.31\n${entry}`);
      await save(page);
      const outcome = saveBar(page).getByRole('status').filter({ hasText: 'PROXY protocol sources' });
      await expect(outcome).toContainText(message);
      await expect(saveBar(page)).toContainText('1 unsaved change in Host defaults');
      await expect(sourcesField(page)).toHaveValue(`192.0.2.31\n${entry}`);
      expect((await readSettings(page)).proxy_protocol_ranges).toEqual(['192.0.2.30']);
      expect(liveAllow()).toEqual(['192.0.2.30/32']);
    });
  }

  test('fixing a refused entry and saving again works', async ({ page }) => {
    await open(page);
    await sourcesField(page).fill('0.0.0.0/0');
    await save(page);
    await expect(saveBar(page)).toContainText('matches every address');
    await sourcesField(page).fill('192.0.2.40');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect((await readSettings(page)).proxy_protocol_ranges).toEqual(['192.0.2.40']);
  });

  test('saving the field keeps the other trusted proxy settings', async ({ page }) => {
    await writeSettings(page, { ranges: ['10.0.0.0/8'], client_ip_headers: ['Cf-Connecting-Ip'], strict: true, default_geoblock: true });
    await open(page);
    await sourcesField(page).fill('192.0.2.50');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect(await readSettings(page)).toEqual({
      ranges: ['10.0.0.0/8'],
      client_ip_headers: ['Cf-Connecting-Ip'],
      strict: true,
      default_geoblock: true,
      proxy_protocol_ranges: ['192.0.2.50'],
    });
  });

  test('changing the other trusted proxy settings keeps the sources', async ({ page }) => {
    await writeSettings(page, { ranges: [], proxy_protocol_ranges: ['192.0.2.60', '198.51.100.0/24'] });
    await open(page);
    await card(page).getByLabel('Trusted ranges').fill('172.21.0.1/32');
    await card(page).getByRole('switch', { name: 'Accept these headers only from trusted proxies' }).click();
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect(await readSettings(page)).toEqual({ ranges: ['172.21.0.1/32'], strict: true, proxy_protocol_ranges: ['192.0.2.60', '198.51.100.0/24'] });
    expect(liveAllow()).toEqual(['192.0.2.60/32', '198.51.100.0/24']);
  });

  test('sources set over the REST API show in the field', async ({ page }) => {
    await writeSettings(page, { ranges: [], proxy_protocol_ranges: ['203.0.113.1', '2001:db8:1::/48'] });
    await open(page);
    await expect(sourcesField(page)).toHaveValue('203.0.113.1\n2001:db8:1::/48');
  });

  test('clearing the field turns PROXY protocol off', async ({ page }) => {
    await writeSettings(page, { ranges: [], proxy_protocol_ranges: ['192.0.2.70'] });
    await expect.poll(liveAllow).toEqual(['192.0.2.70/32']);
    await open(page);
    await sourcesField(page).fill('');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect((await readSettings(page)).proxy_protocol_ranges).toBeUndefined();
    await expect.poll(liveAllow).toBeNull();
    await page.reload();
    await expect(sourcesField(page)).toHaveValue('');
  });

  test('the command palette finds the setting by "proxy protocol"', async ({ page }) => {
    await open(page, '/settings');
    await page.keyboard.press('ControlOrMeta+k');
    const dialog = page.getByRole('dialog', { name: 'Command palette' });
    await dialog.getByRole('combobox', { name: 'Search hosts, actions, settings and documentation' }).fill('proxy protocol');
    const option = dialog.getByRole('option', { name: /Trusted proxies/ }).first();
    await expect(option).toBeVisible();
    await option.click();
    await expect(page).toHaveURL(/\/proxy-hosts\/defaults#trusted-proxies$/);
    await expect(sourcesField(page)).toBeVisible();
  });

  test('the palette also finds it by "load balancer" and "haproxy"', async ({ page }) => {
    await open(page, '/settings');
    for (const query of ['load balancer', 'haproxy']) {
      await page.keyboard.press('ControlOrMeta+k');
      const dialog = page.getByRole('dialog', { name: 'Command palette' });
      await dialog.getByRole('combobox', { name: 'Search hosts, actions, settings and documentation' }).fill(query);
      await expect(dialog.getByRole('option', { name: /Trusted proxies/ }).first(), query).toBeVisible();
      await page.keyboard.press('Escape');
      await page.keyboard.press('Escape');
      await expect(dialog).not.toBeVisible();
    }
  });

  test('the old networking link opens the card with the field', async ({ page }) => {
    await page.goto('/settings?group=networking');
    await expect(page).toHaveURL(/\/proxy-hosts\/defaults#trusted-proxies$/);
    await expect(sourcesField(page)).toBeVisible();
  });

  test('the API reference documents the trusted-proxies group and proxy_protocol_ranges', async ({ page }) => {
    const res = await page.request.get(`${API}/openapi.json`);
    expect(res.ok()).toBe(true);
    const spec = (await res.json()) as {
      paths: Record<string, Record<string, { parameters?: Array<{ name: string; schema: { enum?: string[] } }> }>>;
      components: { schemas: Record<string, { properties: Record<string, { type: string; maxItems?: number; description?: string }>; required?: string[] }> };
    };
    const settingsPath = spec.paths['/api/v1/settings/{group}'];
    for (const method of ['get', 'put']) {
      expect(settingsPath[method].parameters?.find((p) => p.name === 'group')?.schema.enum, method).toContain('trusted-proxies');
    }
    const schema = spec.components.schemas.TrustedProxiesSettings;
    expect(schema.required).toEqual(['ranges']);
    expect(Object.keys(schema.properties)).toEqual(['ranges', 'client_ip_headers', 'strict', 'default_geoblock', 'proxy_protocol_ranges']);
    expect(schema.properties.proxy_protocol_ranges).toMatchObject({ type: 'array', maxItems: 100 });
    expect(schema.properties.proxy_protocol_ranges.description).toContain('ports 80 and 443');
  });
});

test.describe('Host defaults — PROXY protocol sources at phone width', () => {
  test.use({ viewport: { width: 393, height: 852 } });

  test('the field is usable without horizontal overflow', async ({ page }) => {
    await open(page);
    await sourcesField(page).scrollIntoViewIfNeeded();
    await expect(sourcesField(page)).toBeVisible();
    const box = await sourcesField(page).boundingBox();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(393);
    const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
    expect(bodyWidth).toBeLessThanOrEqual(393 + 5);
  });
});
