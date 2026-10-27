/**
 * Host defaults → Response headers (issue #355), in the browser: the card,
 * saving it with the page's one save bar, what is refused and how the page
 * says so, what the REST API and the running Caddy get from it, and how it
 * is found (command palette, the API reference).
 *
 * What Caddy then sends is tested through real requests in
 * functional/response-headers.spec.ts.
 */
import { execFileSync } from 'node:child_process';
import { test, expect, type Page } from '@playwright/test';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
const SAVED = 'Response headers saved and applied successfully';

type Settings = { set: Record<string, string>; remove: string[] };

/** Open a page and wait until it is interactive: fields typed into before hydration do not count as changes. */
async function open(page: Page, path = '/proxy-hosts/defaults') {
  await page.goto(path);
  await page.waitForLoadState('networkidle');
}

function card(page: Page) {
  return page.getByRole('main').locator('#response-headers');
}

function setField(page: Page) {
  return card(page).getByLabel('Set', { exact: true });
}

function removeField(page: Page) {
  return card(page).getByLabel('Remove', { exact: true });
}

function saveBar(page: Page) {
  return page.getByRole('main').getByTestId('settings-save-bar');
}

async function save(page: Page) {
  await saveBar(page).getByRole('button', { name: 'Save changes' }).click();
}

async function readSettings(page: Page): Promise<Settings> {
  const res = await page.request.get(`${API}/settings/response-headers`);
  expect(res.ok(), await res.text()).toBe(true);
  return (await res.json()) as Settings;
}

async function writeSettings(page: Page, data: Partial<Settings>) {
  const res = await page.request.put(`${API}/settings/response-headers`, { headers: HEADERS, data });
  expect(res.status(), await res.text()).toBe(200);
}

/** The response operations of the first route of the running main server when it is the response headers route, or null. */
function liveRoute(): Record<string, unknown> | null {
  try {
    const out = execFileSync(
      'docker',
      ['exec', 'ingressi-caddy', 'wget', '-qO-', 'http://localhost:2019/config/apps/http/servers/ingressi/routes/0'],
      { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const route = JSON.parse(out) as { match?: unknown; handle?: Array<{ handler: string; response?: Record<string, unknown> }> } | null;
    if (!route || route.match) return null;
    const handler = route.handle?.[0];
    return handler?.handler === 'headers' ? (handler.response ?? null) : null;
  } catch {
    return null;
  }
}

test.describe.serial('Host defaults — Response headers', () => {
  let original: Settings = { set: {}, remove: [] };
  let hostId: number | null = null;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    original = await readSettings(page);
    // Caddy runs the main server only with a host.
    const res = await page.request.post(`${API}/proxy-hosts`, {
      headers: HEADERS,
      data: { name: 'Response headers settings', domains: ['resp-headers-settings.test'], upstreams: ['echo-server:8080'], sslForced: false },
    });
    expect(res.status(), await res.text()).toBe(201);
    hostId = ((await res.json()) as { id: number }).id;
    await page.close();
  });

  test.beforeEach(async ({ page }) => {
    await writeSettings(page, { set: {}, remove: [] });
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    await writeSettings(page, original);
    if (hostId !== null) await page.request.delete(`${API}/proxy-hosts/${hostId}`, { headers: HEADERS });
    await page.close();
  });

  test('Host defaults has the card, empty, with what it does', async ({ page }) => {
    await open(page);
    await expect(card(page).getByRole('heading', { level: 2, name: 'Response headers' })).toBeVisible();
    await expect(card(page)).toContainText("Set or removed on every response of every host, after the host's own headers.");
    await expect(setField(page)).toHaveValue('');
    await expect(removeField(page)).toHaveValue('');
    await expect(setField(page)).toBeEditable();
    await expect(removeField(page)).toBeEditable();
    await expect(removeField(page)).toHaveAttribute('placeholder', 'Server\nVia');
    await expect(card(page)).toContainText("Server and Via hide Caddy's own headers.");
    // It comes right after Error pages and before Trusted proxies.
    const errorPages = await page.getByRole('main').locator('#error-pages').boundingBox();
    const ours = await card(page).boundingBox();
    const trusted = await page.getByRole('main').locator('#trusted-proxies').boundingBox();
    expect(ours!.y).toBeGreaterThan(errorPages!.y);
    expect(trusted!.y).toBeGreaterThan(ours!.y);
  });

  test('saving applies the headers; the page, the REST API and Caddy read them back', async ({ page }) => {
    await open(page);
    await setField(page).fill('X-Frame-Options: DENY\n\n  Server :  web  ');
    await removeField(page).fill('Via\n\n X-Powered-By ');
    await expect(saveBar(page)).toContainText('2 unsaved changes in Host defaults');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);

    expect(await readSettings(page)).toEqual({ set: { 'X-Frame-Options': 'DENY', Server: 'web' }, remove: ['Via', 'X-Powered-By'] });
    await expect.poll(liveRoute).toEqual({
      set: { 'X-Frame-Options': ['DENY'], Server: ['web'] },
      delete: ['Via', 'X-Powered-By'],
      deferred: true,
    });

    await page.reload();
    await page.waitForLoadState('networkidle');
    await expect(setField(page)).toHaveValue('X-Frame-Options: DENY\nServer: web');
    await expect(removeField(page)).toHaveValue('Via\nX-Powered-By');
    await expect(saveBar(page)).toContainText('No unsaved changes.');
  });

  test('removing only Server and Via works without anything to set', async ({ page }) => {
    await open(page);
    await removeField(page).fill('Server\nVia');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect(await readSettings(page)).toEqual({ set: {}, remove: ['Server', 'Via'] });
    await expect.poll(liveRoute).toEqual({ delete: ['Server', 'Via'], deferred: true });
  });

  test('the save bar counts the fields as changes, and Discard puts them back', async ({ page }) => {
    await writeSettings(page, { remove: ['Server'] });
    await open(page);
    await expect(removeField(page)).toHaveValue('Server');
    await removeField(page).fill('Via');
    await expect(saveBar(page)).toContainText('1 unsaved change in Host defaults');
    await saveBar(page).getByRole('button', { name: 'Discard' }).click();
    await expect(removeField(page)).toHaveValue('Server');
    await expect(saveBar(page)).toContainText('No unsaved changes');
    expect(await readSettings(page)).toEqual({ set: {}, remove: ['Server'] });
  });

  for (const [what, set, remove, message] of [
    ['a line without a colon', 'X-Broken', '', 'Invalid response header line: X-Broken'],
    ['an invalid name', '', 'Bad Name', 'Invalid response header name: Bad Name'],
    ['Content-Length', '', 'Content-Length', 'Content-Length cannot be set or removed on every response'],
    ['Transfer-Encoding', 'Transfer-Encoding: chunked', '', 'Transfer-Encoding cannot be set or removed on every response'],
    ['a header set and removed', 'Server: web', 'server', 'Response header server is listed more than once'],
    ['a copied cookie', 'X-Echo: {http.request.cookie.session}', '', 'Response header X-Echo cannot copy request headers or cookies'],
    ['a copied request header', 'X-Echo: {http.request.header.Authorization}', '', 'Response header X-Echo cannot copy request headers or cookies'],
  ] as const) {
    test(`${what} is refused by name, nothing is saved or applied and the change stays unsaved`, async ({ page }) => {
      await writeSettings(page, { remove: ['Via'] });
      await expect.poll(liveRoute).toEqual({ delete: ['Via'], deferred: true });
      await open(page);
      if (set) await setField(page).fill(set);
      if (remove) await removeField(page).fill(remove);
      await save(page);
      await expect(saveBar(page)).toContainText(message);
      await expect(saveBar(page)).toContainText(/unsaved change/);
      expect(await readSettings(page)).toEqual({ set: {}, remove: ['Via'] });
      expect(liveRoute()).toEqual({ delete: ['Via'], deferred: true });
    });
  }

  test('fixing a refused entry and saving again works', async ({ page }) => {
    await open(page);
    await removeField(page).fill('Content-Length');
    await save(page);
    await expect(saveBar(page)).toContainText('cannot be set or removed');
    await removeField(page).fill('Server');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect(await readSettings(page)).toEqual({ set: {}, remove: ['Server'] });
  });

  test('headers set over the REST API show in the fields', async ({ page }) => {
    await writeSettings(page, { set: { 'Strict-Transport-Security': 'max-age=63072000', 'X-Served-For': '{http.request.host}' }, remove: ['Server', 'Via'] });
    await open(page);
    await expect(setField(page)).toHaveValue('Strict-Transport-Security: max-age=63072000\nX-Served-For: {http.request.host}');
    await expect(removeField(page)).toHaveValue('Server\nVia');
  });

  test('clearing both fields takes the route out of Caddy', async ({ page }) => {
    await writeSettings(page, { set: { 'X-Test': '1' }, remove: ['Via'] });
    await expect.poll(liveRoute).not.toBeNull();
    await open(page);
    await setField(page).fill('');
    await removeField(page).fill('');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect(await readSettings(page)).toEqual({ set: {}, remove: [] });
    await expect.poll(liveRoute).toBeNull();
  });

  test('saving the card keeps the other Host defaults', async ({ page }) => {
    const errorPages = await page.request.get(`${API}/settings/error-pages`);
    const before = await errorPages.json();
    await open(page);
    await removeField(page).fill('Server');
    await save(page);
    await expect(saveBar(page)).toContainText(SAVED);
    expect(await (await page.request.get(`${API}/settings/error-pages`)).json()).toEqual(before);
  });

  for (const query of ['response headers', 'server header', 'via']) {
    test(`the command palette finds the card by "${query}"`, async ({ page }) => {
      await open(page, '/settings');
      await page.keyboard.press('ControlOrMeta+k');
      const dialog = page.getByRole('dialog', { name: 'Command palette' });
      await dialog.getByRole('combobox', { name: 'Search hosts, actions, settings and documentation' }).fill(query);
      // The settings entry, not this spec's own proxy host of a similar name.
      const option = dialog.getByRole('option').filter({ hasText: 'Headers set or removed on every response' });
      await expect(option).toBeVisible();
      await option.click();
      await expect(page).toHaveURL(/\/proxy-hosts\/defaults#response-headers$/);
      await expect(removeField(page)).toBeVisible();
    });
  }

  test('the API reference documents the response-headers group', async ({ page }) => {
    const res = await page.request.get(`${API}/openapi.json`);
    expect(res.ok()).toBe(true);
    const spec = (await res.json()) as {
      paths: Record<string, Record<string, { parameters?: Array<{ name: string; schema: { enum?: string[] } }> }>>;
      components: { schemas: Record<string, { properties?: Record<string, unknown> }> };
    };
    const settingsPath = spec.paths['/api/v1/settings/{group}'];
    for (const method of ['get', 'put']) {
      const group = settingsPath[method].parameters?.find((parameter) => parameter.name === 'group');
      expect(group?.schema.enum).toContain('response-headers');
    }
    expect(Object.keys(spec.components.schemas.ResponseHeadersSettings.properties ?? {})).toEqual(['set', 'remove']);
  });
});

test.describe('Host defaults — Response headers at phone width', () => {
  test.use({ viewport: { width: 393, height: 852 } });

  test('both fields are usable without horizontal overflow', async ({ page }) => {
    await open(page);
    for (const field of [setField(page), removeField(page)]) {
      await field.scrollIntoViewIfNeeded();
      await expect(field).toBeVisible();
      const box = await field.boundingBox();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(393);
    }
    expect(await page.evaluate(() => document.body.scrollWidth)).toBeLessThanOrEqual(393 + 5);
  });
});
