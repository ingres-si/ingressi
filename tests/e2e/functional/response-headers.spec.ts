/**
 * Functional tests: Host defaults → Response headers (issue #355), through
 * the real Caddy. The setting is saved through the REST API, then real
 * requests check the headers of every kind of response the main server
 * sends: a proxied answer, an answer for an unknown host (Caddy's own and a
 * custom default response), a reverse proxy error (502, handled by the error
 * routes, with and without a custom error page) and a redirect.
 *
 * The page itself is tested in response-headers-settings.spec.ts.
 */
import { test, expect, type APIRequestContext } from '@playwright/test';
import { httpGet, waitForBody, waitForStatus, type HttpResponse } from '../../helpers/http';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };

const HEALTHY_DOMAIN = 'func-resp-headers.test';
const DEAD_DOMAIN = 'func-resp-headers-down.test';
const REDIRECT_DOMAIN = 'func-resp-headers-redirect.test';
const UNKNOWN_DOMAIN = 'func-resp-headers-unknown.test';
const DEAD_UPSTREAM = 'whoami-server:9999'; // resolves, refuses: reverse_proxy 502

type ResponseHeaders = { set?: Record<string, string>; remove?: string[] };

async function putSettings(request: APIRequestContext, group: string, data: unknown) {
  const res = await request.put(`${API}/settings/${group}`, { headers: HEADERS, data });
  expect(res.status(), await res.text()).toBe(200);
}

async function getSettings(request: APIRequestContext, group: string): Promise<Record<string, unknown>> {
  const res = await request.get(`${API}/settings/${group}`, { headers: { Origin: BASE_URL } });
  expect(res.status(), await res.text()).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

async function setResponseHeaders(request: APIRequestContext, settings: ResponseHeaders) {
  await putSettings(request, 'response-headers', settings);
}

async function createHost(request: APIRequestContext, data: Record<string, unknown>): Promise<number> {
  const res = await request.post(`${API}/proxy-hosts`, { headers: HEADERS, data: { sslForced: false, ...data } });
  expect(res.status(), await res.text()).toBe(201);
  return ((await res.json()) as { id: number }).id;
}

function header(response: HttpResponse, name: string): string | undefined {
  const value = response.headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(', ') : value;
}

/** Poll until a response for `domain` passes `check` (Caddy applies a new configuration asynchronously). */
async function waitForHeaders(domain: string, check: (response: HttpResponse) => boolean, path = '/', timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let last: HttpResponse | null = null;
  while (Date.now() < deadline) {
    try {
      last = await httpGet(domain, path);
      if (check(last)) return last;
    } catch {
      // Caddy may be between configurations.
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error(`Headers for ${domain} did not change in time (last: ${last?.status} ${JSON.stringify(last?.headers)})`);
}

const hidden = (response: HttpResponse) => header(response, 'server') === undefined && header(response, 'via') === undefined;

test.describe.serial('Response headers for every response — live Caddy', () => {
  const hostIds: number[] = [];
  let originalResponseHeaders: Record<string, unknown> = { set: {}, remove: [] };
  let originalDefaultResponse: Record<string, unknown> = { mode: 'caddy' };
  let originalErrorPages: Record<string, unknown> = { rules: [] };

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const request = page.request;
    originalResponseHeaders = await getSettings(request, 'response-headers');
    originalDefaultResponse = await getSettings(request, 'default-response');
    const errorPages = await getSettings(request, 'error-pages');
    if (Array.isArray(errorPages.rules)) originalErrorPages = errorPages;

    await setResponseHeaders(request, { set: {}, remove: [] });
    await putSettings(request, 'default-response', { mode: 'caddy' });
    await putSettings(request, 'error-pages', { rules: [] });

    hostIds.push(await createHost(request, { name: 'Response headers healthy', domains: [HEALTHY_DOMAIN], upstreams: ['echo-server:8080'] }));
    hostIds.push(await createHost(request, { name: 'Response headers down', domains: [DEAD_DOMAIN], upstreams: [DEAD_UPSTREAM] }));
    hostIds.push(await createHost(request, {
      name: 'Response headers redirect',
      domains: [REDIRECT_DOMAIN],
      upstreams: ['echo-server:8080'],
      redirects: [{ from: '/old', to: '/new', status: 301 }],
    }));
    await waitForBody(HEALTHY_DOMAIN, 'echo-ok');
    await waitForStatus(DEAD_DOMAIN, 502);
    await page.close();
  });

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage();
    const request = page.request;
    await setResponseHeaders(request, originalResponseHeaders as ResponseHeaders);
    await putSettings(request, 'default-response', originalDefaultResponse);
    await putSettings(request, 'error-pages', originalErrorPages);
    for (const id of hostIds) {
      const res = await request.delete(`${API}/proxy-hosts/${id}`, { headers: { Origin: BASE_URL } });
      expect(res.status()).toBe(200);
    }
    await page.close();
  });

  test('without the setting, Caddy names itself in Server and Via', async () => {
    const proxied = await httpGet(HEALTHY_DOMAIN);
    expect(proxied.status).toBe(200);
    expect(header(proxied, 'via')).toMatch(/Caddy/);

    const error = await httpGet(DEAD_DOMAIN);
    expect(error.status).toBe(502);
    expect(header(error, 'server')).toBe('Caddy');
  });

  test('the REST API reads an empty setting as nothing set and nothing removed', async ({ request }) => {
    expect(await getSettings(request, 'response-headers')).toEqual({ set: {}, remove: [] });
  });

  test('removing Server and Via hides them on proxied responses, and the body is unchanged', async ({ request }) => {
    await setResponseHeaders(request, { remove: ['Server', 'Via'] });
    const response = await waitForHeaders(HEALTHY_DOMAIN, hidden);
    expect(response.status).toBe(200);
    expect(response.body).toContain('echo-ok');
    expect(header(response, 'content-type')).toMatch(/text\/plain/);
  });

  test('they are hidden on reverse proxy errors too (the error routes), with the status kept', async () => {
    const response = await waitForHeaders(DEAD_DOMAIN, hidden);
    expect(response.status).toBe(502);
  });

  test('they are hidden on a custom error page for every host', async ({ request }) => {
    await putSettings(request, 'error-pages', { rules: [{ statuses: [502], body: 'RESP_HEADERS_ERROR_PAGE' }] });
    const response = await waitForHeaders(DEAD_DOMAIN, (r) => r.body.includes('RESP_HEADERS_ERROR_PAGE'));
    expect(response.status).toBe(502);
    expect(hidden(response)).toBe(true);
    await putSettings(request, 'error-pages', { rules: [] });
  });

  test("they are hidden on Caddy's own answer for an unknown host and on direct IP access", async () => {
    for (const host of [UNKNOWN_DOMAIN, '127.0.0.1']) {
      const response = await waitForHeaders(host, hidden);
      expect(response.status).toBeLessThan(500);
    }
  });

  test('they are hidden on a custom response for unknown hosts, which keeps its own headers', async ({ request }) => {
    await putSettings(request, 'default-response', {
      mode: 'respond',
      status: 404,
      body: 'RESP_HEADERS_DEFAULT',
      headers: { 'X-Default-Response': 'yes' },
    });
    const response = await waitForHeaders(UNKNOWN_DOMAIN, (r) => r.body === 'RESP_HEADERS_DEFAULT');
    expect(response.status).toBe(404);
    expect(hidden(response)).toBe(true);
    expect(header(response, 'x-default-response')).toBe('yes');
    await putSettings(request, 'default-response', { mode: 'caddy' });
  });

  test('they are hidden on redirects, which keep their Location', async () => {
    const response = await waitForHeaders(REDIRECT_DOMAIN, (r) => r.status === 301, '/old');
    expect(header(response, 'location')).toMatch(/\/new$/);
    expect(hidden(response)).toBe(true);
  });

  test('set headers reach every kind of response, with request placeholders filled in', async ({ request }) => {
    await setResponseHeaders(request, {
      set: { Server: 'web', 'X-Served-For': '{http.request.host}', 'X-Content-Type-Options': 'nosniff' },
      remove: ['Via'],
    });
    const proxied = await waitForHeaders(HEALTHY_DOMAIN, (r) => header(r, 'server') === 'web');
    expect(header(proxied, 'x-served-for')).toBe(HEALTHY_DOMAIN);
    expect(header(proxied, 'x-content-type-options')).toBe('nosniff');
    expect(header(proxied, 'via')).toBeUndefined();

    const error = await waitForHeaders(DEAD_DOMAIN, (r) => header(r, 'server') === 'web');
    expect(error.status).toBe(502);
    expect(header(error, 'x-served-for')).toBe(DEAD_DOMAIN);

    const unknown = await waitForHeaders(UNKNOWN_DOMAIN, (r) => header(r, 'server') === 'web');
    expect(header(unknown, 'x-served-for')).toBe(UNKNOWN_DOMAIN);
  });

  test('host placeholders are sent literally, never expanded', async ({ request }) => {
    await setResponseHeaders(request, { set: { 'X-Literal': '{env.HOME} {system.hostname}' } });
    const response = await waitForHeaders(HEALTHY_DOMAIN, (r) => header(r, 'x-literal') !== undefined);
    expect(header(response, 'x-literal')).toBe('{env.HOME} {system.hostname}');
  });

  test('a set value replaces one a host sets itself', async ({ request }) => {
    const id = await createHost(request, {
      name: 'Response headers own header',
      domains: ['func-resp-headers-own.test'],
      upstreams: ['echo-server:8080'],
      customPreHandlersJson: JSON.stringify([
        { handler: 'headers', response: { set: { 'X-Owned': ['host'] }, deferred: true } },
      ]),
    });
    hostIds.push(id);
    await setResponseHeaders(request, { set: { 'X-Owned': 'global' } });
    const response = await waitForHeaders('func-resp-headers-own.test', (r) => r.status === 200 && header(r, 'x-owned') !== undefined);
    expect(header(response, 'x-owned')).toBe('global');
  });

  test('clearing the setting brings Caddy\'s own headers back', async ({ request }) => {
    await setResponseHeaders(request, { set: {}, remove: [] });
    const proxied = await waitForHeaders(HEALTHY_DOMAIN, (r) => header(r, 'via') !== undefined);
    expect(header(proxied, 'via')).toMatch(/Caddy/);
    expect(header(proxied, 'x-served-for')).toBeUndefined();
    const error = await waitForHeaders(DEAD_DOMAIN, (r) => header(r, 'server') === 'Caddy');
    expect(error.status).toBe(502);
  });
});

test.describe('Response headers — what the REST API refuses', () => {
  const refused: Array<[string, unknown, RegExp]> = [
    ['an invalid header name', { remove: ['Bad Name'] }, /Invalid response header name/],
    ['a CRLF in a value (response splitting)', { set: { 'X-Test': 'a\r\nSet-Cookie: injected=1' } }, /Invalid value/],
    ['a NUL in a value', { set: { 'X-Test': 'a\u0000b' } }, /Invalid value/],
    ['Content-Length', { remove: ['Content-Length'] }, /cannot be set or removed/],
    ['Transfer-Encoding', { set: { 'Transfer-Encoding': 'chunked' } }, /cannot be set or removed/],
    ['Connection', { remove: ['connection'] }, /cannot be set or removed/],
    ['a header both set and removed', { set: { Server: 'web' }, remove: ['server'] }, /more than once/],
    ['a header removed twice', { remove: ['Via', 'VIA'] }, /more than once/],
    ['a copied request cookie', { set: { 'X-Echo': '{http.request.cookie.better-auth.session_token}' } }, /request headers or cookies/],
    ['a copied request header', { set: { 'X-Echo': '{http.request.header.Authorization}' } }, /request headers or cookies/],
    ['an unknown field', { set: {}, remove: [], extra: true }, /unknown field/],
    ['a list that is not a list', { remove: 'Server' }, /must be a list/],
    ['a value that is not a string', { set: { 'X-Test': 5 } }, /Invalid value/],
  ];

  for (const [what, data, message] of refused) {
    test(`refuses ${what} with 400 and keeps the stored setting`, async ({ request }) => {
      const before = await getSettings(request, 'response-headers');
      const res = await request.put(`${API}/settings/response-headers`, { headers: HEADERS, data });
      expect(res.status()).toBe(400);
      expect(((await res.json()) as { error: string }).error).toMatch(message);
      expect(await getSettings(request, 'response-headers')).toEqual(before);
    });
  }

  test('stores names and values trimmed, and reads them back the same', async ({ request }) => {
    const before = await getSettings(request, 'response-headers');
    await setResponseHeaders(request, { set: { ' X-Trim ': '  value  ' }, remove: [' Via '] });
    expect(await getSettings(request, 'response-headers')).toEqual({ set: { 'X-Trim': 'value' }, remove: ['Via'] });
    await setResponseHeaders(request, before as ResponseHeaders);
  });

  test('refuses writes without a session or token', async ({ playwright }) => {
    const anonymous = await playwright.request.newContext({ storageState: { cookies: [], origins: [] } });
    const res = await anonymous.put(`${API}/settings/response-headers`, { headers: HEADERS, data: { remove: ['Server'] } });
    expect(res.status()).toBe(401);
    await anonymous.dispose();
  });
});
