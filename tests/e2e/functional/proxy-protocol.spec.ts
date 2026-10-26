/**
 * Functional tests: the PROXY protocol on Caddy's ports 80 and 443
 * (Host defaults → Trusted proxies → PROXY protocol from), through the real
 * Caddy, with the headers a TCP load balancer in front of it sends.
 *
 * The test client reaches Caddy from the address of the Docker bridge. The
 * spec learns it from the X-Forwarded-For Caddy sends upstream and lists it
 * as the load balancer, so its connections may open with a PROXY header that
 * names any client.
 *
 * It checks:
 *  - without the setting, Caddy does not understand a PROXY header (as before);
 *  - from a listed source, v1 and v2 headers, IPv4 and IPv6, with or without
 *    TLVs, name the client upstream, on HTTP and on HTTPS (the header comes
 *    before the TLS handshake), for every request of a kept-alive connection
 *    and when the header arrives in pieces; LOCAL and UNKNOWN headers and
 *    connections without a header keep the source's own address; a
 *    malformed header never reaches the upstream;
 *  - from any other source a header is read and ignored: the connection
 *    works with its own address, so nobody else can claim one;
 *  - everything that reads the client address reads the header's: access
 *    list address rules, Blocked sources, geo blocking by range, rate
 *    limits, trusted proxies (a CDN in front of the balancer), the access
 *    log and analytics;
 *  - the REST API refuses sources that would let anyone set an address and
 *    stores the others normalized, and Caddy runs exactly what is stored;
 *  - clearing the list puts everything back.
 *
 * Domains: func-pp-<kind>.test
 */
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { test, expect, request as playwrightRequest, type APIRequestContext } from '@playwright/test';
import { httpGet, waitForRoute } from '../../helpers/http';
import { httpsGet } from '../../helpers/https';
import { createSelfSignedServerCertificate } from '../../helpers/certs';
import {
  forwardedFor,
  httpRequestBytes,
  proxiedHttpGet,
  proxiedHttpsGet,
  proxiedKeepAliveGets,
  proxyV1,
  proxyV1Unknown,
  proxyV2,
  proxyV2Local,
  rawExchange,
} from '../../helpers/proxy-protocol';

const BASE_URL = 'http://localhost:3000';
const API = `${BASE_URL}/api/v1`;
const HEADERS = { 'Content-Type': 'application/json', Origin: BASE_URL };
const UPSTREAM = 'whoami-server:80';
/** What traefik/whoami writes in every answer: the request reached the upstream. */
const THROUGH = 'Hostname:';

const OPEN = 'func-pp-open.test';
const TLS = 'func-pp-tls.test';
const ACL = 'func-pp-acl.test';
const RATE = 'func-pp-rate.test';

const EMPTY_GEOBLOCK = {
  enabled: false,
  block_countries: [], block_continents: [], block_asns: [], block_cidrs: [], block_ips: [],
  allow_countries: [], allow_continents: [], allow_asns: [], allow_cidrs: [], allow_ips: [],
  trusted_proxies: [], fail_closed: false,
  response_status: 403, response_body: 'Forbidden', response_headers: {}, redirect_url: '',
};

let api: APIRequestContext;
/** The address Caddy sees the test client from: the load balancer of this spec. */
let peer = '';
let original: { trustedProxies: Record<string, unknown>; geoblock: Record<string, unknown>; logging: Record<string, unknown> };
const hostIds: number[] = [];
let certificateId: number | null = null;
/** The self-signed certificate the TLS host serves: HTTPS requests trust exactly it. */
let tlsCertificatePem = '';
let accessListId: number | null = null;
const blockedEntries: number[] = [];

async function eventually(check: () => Promise<void> | void, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await check();
      return;
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

/** The listener wrappers of the main server in the running Caddy (null when it has none). */
function liveListenerWrappers(): Array<Record<string, unknown>> | null {
  try {
    const out = execFileSync(
      'docker',
      ['exec', 'ingressi-caddy', 'wget', '-qO-', 'http://localhost:2019/config/apps/http/servers/ingressi/listener_wrappers'],
      { encoding: 'utf-8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return JSON.parse(out) as Array<Record<string, unknown>> | null;
  } catch {
    return null;
  }
}

/** The JSON access log lines Caddy wrote for `uri`. */
function accessLogLines(uri: string): Array<{ request: Record<string, unknown> }> {
  try {
    const out = execFileSync('docker', ['exec', 'ingressi-caddy', 'grep', '-F', `"uri":"${uri}"`, '/logs/access.log'], {
      encoding: 'utf-8',
      timeout: 10_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return out.split('\n').filter(Boolean).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

async function readGroup(group: string): Promise<Record<string, unknown> | null> {
  const res = await api.get(`${API}/settings/${group}`);
  expect(res.ok(), await res.text()).toBe(true);
  const body = (await res.json()) as Record<string, unknown> | null;
  return body && Object.keys(body).length > 0 ? body : null;
}

async function putGroup(group: string, data: unknown): Promise<void> {
  const res = await api.put(`${API}/settings/${group}`, { headers: HEADERS, data });
  expect(res.status(), await res.text()).toBe(200);
}

/** Lists `sources` as PROXY protocol sources (keeping the other trusted proxy settings) and waits until Caddy runs them. */
async function listSources(sources: string[], extra: Record<string, unknown> = {}): Promise<void> {
  await putGroup('trusted-proxies', { ranges: [], ...extra, proxy_protocol_ranges: sources });
  await eventually(() => {
    const allow = (liveListenerWrappers()?.[0]?.allow ?? []) as string[];
    expect(allow.length, 'Caddy runs the listed sources').toBe(sources.length);
  });
}

async function createHost(name: string, domain: string, extra: Record<string, unknown> = {}): Promise<number> {
  const res = await api.post(`${API}/proxy-hosts`, {
    headers: HEADERS,
    data: { name, domains: [domain], upstreams: [UPSTREAM], sslForced: false, ...extra },
  });
  expect(res.status(), await res.text()).toBe(201);
  const id = ((await res.json()) as { id: number }).id;
  hostIds.push(id);
  return id;
}

/** The client address the upstream was given for a request with `header` (null: no header). */
async function clientOf(header: Buffer | null, domain = OPEN, path = '/'): Promise<string | null> {
  const res = await proxiedHttpGet(domain, header, path);
  expect(res.status, res.body.slice(0, 300)).toBe(200);
  expect(res.body).toContain(THROUGH);
  return forwardedFor(res.body);
}

test.describe.serial('PROXY protocol on ports 80 and 443', () => {
  test.beforeAll(async () => {
    test.setTimeout(180_000);
    api = await playwrightRequest.newContext({ storageState: resolve(__dirname, '../../.auth/admin.json') });
    original = {
      // Unset, a group reads as nothing: put back as its empty form, which the route accepts.
      trustedProxies: (await readGroup('trusted-proxies')) ?? { ranges: [] },
      geoblock: (await readGroup('geoblock')) ?? EMPTY_GEOBLOCK,
      logging: (await readGroup('logging')) ?? { enabled: false, format: 'json' },
    };
    // Start from no PROXY protocol, whatever an earlier run left.
    await putGroup('trusted-proxies', { ranges: [] });

    await createHost('PROXY protocol open', OPEN);
    const cert = createSelfSignedServerCertificate(TLS, [TLS]);
    tlsCertificatePem = cert.certificatePem;
    const certRes = await api.post(`${API}/certificates`, {
      headers: HEADERS,
      data: { name: 'PROXY protocol TLS', type: 'imported', domainNames: [TLS], autoRenew: false, certificatePem: cert.certificatePem, privateKeyPem: cert.privateKeyPem },
    });
    expect(certRes.status(), await certRes.text()).toBe(201);
    certificateId = ((await certRes.json()) as { id: number }).id;
    await createHost('PROXY protocol TLS', TLS, { certificateId });

    const list = await api.post(`${API}/access-lists`, {
      headers: HEADERS,
      data: { name: 'PROXY protocol allow list', defaultAction: 'deny', denyStatus: 451, denyBody: 'pp-denied' },
    });
    expect(list.status(), await list.text()).toBe(201);
    accessListId = ((await list.json()) as { id: number }).id;
    const rules = await api.put(`${API}/access-lists/${accessListId}/rules`, {
      headers: HEADERS,
      data: { rules: [{ action: 'allow', kind: 'ip', values: ['203.0.113.7', '2001:db8::7'] }] },
    });
    expect(rules.status(), await rules.text()).toBe(200);
    await createHost('PROXY protocol access list', ACL, { accessListId });

    await createHost('PROXY protocol rate limit', RATE, {
      rateLimit: { mode: 'override', rules: [{ path: '/limited/*', events: 2, window: '1m' }] },
    });

    await waitForRoute(OPEN);
    await eventually(async () => {
      peer = forwardedFor((await httpGet(OPEN)).body) ?? '';
      expect(peer, 'the upstream shows the address Caddy sees the client from').toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    });
    await eventually(async () => expect((await httpGet(ACL)).status).toBe(451));
    await eventually(async () => expect((await httpsGet(TLS)).status).toBe(200));
  });

  test.afterAll(async () => {
    const cleanup = await playwrightRequest.newContext({ storageState: resolve(__dirname, '../../.auth/admin.json') });
    // Never leave the client address read differently for the specs that follow.
    for (const [group, value] of [['trusted-proxies', original.trustedProxies], ['geoblock', original.geoblock], ['logging', original.logging]] as const) {
      const res = await cleanup.put(`${API}/settings/${group}`, { headers: HEADERS, data: value });
      expect(res.ok(), `${group}: ${await res.text()}`).toBe(true);
    }
    for (const id of blockedEntries) await cleanup.delete(`${API}/access-lists/blocked-sources/entries/${id}`, { headers: HEADERS });
    for (const id of hostIds) await cleanup.delete(`${API}/proxy-hosts/${id}`, { headers: HEADERS });
    if (accessListId !== null) await cleanup.delete(`${API}/access-lists/${accessListId}`, { headers: HEADERS });
    if (certificateId !== null) await cleanup.delete(`${API}/certificates/${certificateId}`, { headers: HEADERS });
    await cleanup.dispose();
    await api?.dispose();
  });

  // ── Before: no sources listed ─────────────────────────────────────────

  test('the client reaches Caddy from a private address', () => {
    expect(peer).toMatch(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/);
  });

  test('without sources, Caddy runs no listener wrappers and does not understand a PROXY header', async () => {
    expect(liveListenerWrappers()).toBeNull();
    const v1 = await proxiedHttpGet(OPEN, proxyV1('203.0.113.7'));
    expect(v1.status).toBe(400);
    expect(v1.body).not.toContain(THROUGH);
    // A v2 header is binary: Caddy answers 400 or closes the connection, and never forwards it.
    const v2 = await rawExchange([proxyV2('203.0.113.7'), httpRequestBytes(OPEN)]);
    expect(v2.raw).not.toContain(THROUGH);
    expect(v2.raw).not.toMatch(/^HTTP\/1\.1 200/);
    // Plain requests work as always.
    expect(await clientOf(null)).toBe(peer);
  });

  // ── The REST API ──────────────────────────────────────────────────────

  test('the REST API refuses sources that would let anyone set an address, and changes nothing', async () => {
    for (const [value, message] of [
      [['0.0.0.0/0'], /"0\.0\.0\.0\/0" matches every address/],
      [['192.168.1.1', '::/0'], /"::\/0" matches every address/],
      [['private_ranges'], /"private_ranges" is not accepted here/],
      [['firewall.lan'], /"firewall\.lan" is not an IP address or a CIDR range/],
      [['10.0.0.0/33'], /is not an IP address or a CIDR range/],
      ['192.168.1.1', /proxy_protocol_ranges must be an array/],
      [[42], /\[0\] must be a string/],
      [Array.from({ length: 101 }, (_, index) => `10.0.${index}.1`), /at most 100 entries/],
    ] as const) {
      const res = await api.put(`${API}/settings/trusted-proxies`, { headers: HEADERS, data: { ranges: [], proxy_protocol_ranges: value } });
      expect(res.status(), JSON.stringify(value).slice(0, 80)).toBe(400);
      const error = String(((await res.json()) as { error: string }).error);
      expect(error).toContain('trusted-proxies.proxy_protocol_ranges');
      expect(error).toMatch(message);
    }
    expect((await readGroup('trusted-proxies'))?.proxy_protocol_ranges).toBeUndefined();
    expect(liveListenerWrappers()).toBeNull();
  });

  test('the REST API stores sources normalized, and Caddy runs exactly them as CIDR ranges', async () => {
    await putGroup('trusted-proxies', { ranges: [], proxy_protocol_ranges: ['192.168.77.1/24', ' 10.9.9.9 ', '10.9.9.9/32', '2001:DB8::1'] });
    expect((await readGroup('trusted-proxies'))?.proxy_protocol_ranges).toEqual(['192.168.77.0/24', '10.9.9.9', '2001:db8::1']);
    await eventually(() => {
      const wrappers = liveListenerWrappers();
      expect(wrappers?.map((wrapper) => wrapper.wrapper)).toEqual(['proxy_protocol', 'tls']);
      expect(wrappers?.[0].allow).toEqual(['192.168.77.0/24', '10.9.9.9/32', '2001:db8::1/128']);
      expect(String(wrappers?.[0].fallback_policy).toLowerCase()).toBe('ignore');
    });
  });

  test('sources that do not include the client: a PROXY header is read and ignored, the connection is its own', async () => {
    // 192.168.77.0/24, 10.9.9.9 and 2001:db8::1 are listed; the test client is not among them.
    expect(await clientOf(proxyV1('203.0.113.7'))).toBe(peer);
    expect(await clientOf(proxyV2('203.0.113.7'))).toBe(peer);
    expect(await clientOf(proxyV2('2001:db8::7'))).toBe(peer);
    expect(await clientOf(null)).toBe(peer);
  });

  test('sources that do not include the client: the header cannot open an access list', async () => {
    for (const header of [proxyV1('203.0.113.7'), proxyV2('203.0.113.7'), proxyV2('2001:db8::7')]) {
      const res = await proxiedHttpGet(ACL, header);
      expect(res.status).toBe(451);
      expect(res.body).toBe('pp-denied');
    }
  });

  test('sources that do not include the client: an HTTPS connection ignores the header too', async () => {
    const res = await proxiedHttpsGet(TLS, proxyV2('203.0.113.7', { destinationPort: 443 }), tlsCertificatePem);
    expect(res.status).toBe(200);
    expect(forwardedFor(res.body)).toBe(peer);
  });

  // ── The client listed as the load balancer ────────────────────────────

  test('listing the client makes Caddy read PROXY headers from it, before TLS', async () => {
    await listSources([peer]);
    expect((await readGroup('trusted-proxies'))?.proxy_protocol_ranges).toEqual([peer]);
    const wrappers = liveListenerWrappers()!;
    expect(wrappers).toHaveLength(2);
    expect(wrappers[0]).toMatchObject({ wrapper: 'proxy_protocol', allow: [`${peer}/32`] });
    expect(wrappers[1]).toEqual({ wrapper: 'tls' });
    await eventually(async () => expect(await clientOf(proxyV1('203.0.113.7'))).toBe('203.0.113.7'));
  });

  test('a v1 header with an IPv4 client names the client upstream', async () => {
    expect(await clientOf(proxyV1('203.0.113.7'))).toBe('203.0.113.7');
    expect(await clientOf(proxyV1('198.51.100.200', { sourcePort: 65535, destinationPort: 8080 }))).toBe('198.51.100.200');
  });

  test('a v1 header with an IPv6 client names the client upstream', async () => {
    expect(await clientOf(proxyV1('2001:db8::7'))).toBe('2001:db8::7');
  });

  test('a v2 header with an IPv4 client names the client upstream', async () => {
    expect(await clientOf(proxyV2('198.51.100.23'))).toBe('198.51.100.23');
  });

  test('a v2 header with an IPv6 client names the client upstream', async () => {
    expect(await clientOf(proxyV2('2001:db8:abcd::42'))).toBe('2001:db8:abcd::42');
  });

  test('a v2 header with TLVs (as cloud load balancers send) names the client upstream', async () => {
    const header = proxyV2('192.0.2.150', {
      tlvs: [
        [0x04, Buffer.alloc(3)], // PP2_TYPE_NOOP
        [0x05, Buffer.from('conn-0042')], // PP2_TYPE_UNIQUE_ID
        [0xea, Buffer.concat([Buffer.from([0x01]), Buffer.from('vpce-0123456789abcdef0')])], // AWS VPC endpoint ID
      ],
    });
    expect(await clientOf(header)).toBe('192.0.2.150');
  });

  test('every path and query of the host gets the header address', async () => {
    expect(await clientOf(proxyV1('203.0.113.8'), OPEN, '/deep/path?x=1&y=2')).toBe('203.0.113.8');
  });

  test('a connection from the listed source without a header keeps working, as itself', async () => {
    expect(await clientOf(null)).toBe(peer);
    const plain = await httpGet(OPEN, '/without-header');
    expect(plain.status).toBe(200);
    expect(forwardedFor(plain.body)).toBe(peer);
  });

  test('a v2 LOCAL header (a balancer health check) keeps the source address', async () => {
    expect(await clientOf(proxyV2Local())).toBe(peer);
  });

  test('a v1 UNKNOWN header keeps the source address', async () => {
    expect(await clientOf(proxyV1Unknown())).toBe(peer);
  });

  test('every request on a kept-alive connection comes from the address of its header', async () => {
    const responses = await proxiedKeepAliveGets(OPEN, proxyV1('203.0.113.9'), ['/one', '/two', '/three']);
    expect(responses.map((res) => res.status)).toEqual([200, 200, 200]);
    expect(responses.map((res) => forwardedFor(res.body))).toEqual(['203.0.113.9', '203.0.113.9', '203.0.113.9']);
  });

  test('a v2 header that arrives in pieces is read whole', async () => {
    const v2 = proxyV2('203.0.113.11');
    const split = await rawExchange([v2.subarray(0, 5), v2.subarray(5, 14), v2.subarray(14), httpRequestBytes(OPEN)]);
    expect(split.raw).toMatch(/^HTTP\/1\.1 200/);
    expect(forwardedFor(split.raw)).toBe('203.0.113.11');
  });

  test('a v1 header that arrives in pieces is dropped, as the specification allows, and never reaches the upstream', async () => {
    // "The sender must always ensure that the header is sent at once"; a
    // receiver may drop a partial one, which also defeats slow headers.
    const v1 = proxyV1('203.0.113.10');
    const split = await rawExchange([v1.subarray(0, 9), v1.subarray(9, 20), v1.subarray(20), httpRequestBytes(OPEN)]);
    expect(split.closed).toBe(true);
    expect(split.raw).not.toContain(THROUGH);
    expect(await clientOf(proxyV1('203.0.113.10'))).toBe('203.0.113.10');
  });

  test('the header and the request in one packet work too', async () => {
    const together = await rawExchange([Buffer.concat([proxyV2('203.0.113.12'), httpRequestBytes(OPEN, '/together')])]);
    expect(together.raw).toMatch(/^HTTP\/1\.1 200/);
    expect(forwardedFor(together.raw)).toBe('203.0.113.12');
  });

  test('a malformed header from the listed source never reaches the upstream', async () => {
    for (const bad of [
      'PROXY TCP4 999.0.0.1 192.0.2.80 41234 80\r\n',
      'PROXY TCP4 203.0.113.7 192.0.2.80 99999 80\r\n',
      'PROXY TCP6 203.0.113.7 192.0.2.80 41234 80\r\n',
      'PROXY TCP4 203.0.113.7\r\n',
      `PROXY TCP4 203.0.113.7 192.0.2.80 41234 80 ${'x'.repeat(120)}\r\n`,
    ]) {
      const res = await rawExchange([Buffer.from(bad, 'latin1'), httpRequestBytes(OPEN)]);
      expect(res.raw, bad).not.toContain(THROUGH);
      expect(res.raw, bad).not.toMatch(/^HTTP\/1\.1 200/);
    }
    // The connections after it are unaffected.
    expect(await clientOf(proxyV1('203.0.113.7'))).toBe('203.0.113.7');
  });

  test('HTTPS: a v1 or v2 header before the TLS handshake names the client', async () => {
    const v2 = await proxiedHttpsGet(TLS, proxyV2('203.0.113.44', { destinationPort: 443 }), tlsCertificatePem);
    expect(v2.status).toBe(200);
    expect(v2.body).toContain(THROUGH);
    expect(forwardedFor(v2.body)).toBe('203.0.113.44');
    expect(v2.body).toMatch(/^X-Forwarded-Proto: https$/im);

    const v1 = await proxiedHttpsGet(TLS, proxyV1('2001:db8::44', { destinationPort: 443 }), tlsCertificatePem);
    expect(v1.status).toBe(200);
    expect(forwardedFor(v1.body)).toBe('2001:db8::44');
  });

  test('HTTPS from the listed source without a header keeps working, as itself', async () => {
    const res = await httpsGet(TLS);
    expect(res.status).toBe(200);
    expect(forwardedFor(res.body)).toBe(peer);
    expect(forwardedFor((await proxiedHttpsGet(TLS, proxyV2Local(), tlsCertificatePem)).body)).toBe(peer);
  });

  // ── What reads the client address ─────────────────────────────────────

  test('access list address rules match the address the header names', async () => {
    const allowed = await proxiedHttpGet(ACL, proxyV1('203.0.113.7'));
    expect(allowed.status).toBe(200);
    expect(forwardedFor(allowed.body)).toBe('203.0.113.7');
    expect((await proxiedHttpGet(ACL, proxyV2('2001:db8::7'))).status).toBe(200);

    for (const header of [proxyV1('203.0.113.8'), proxyV2('2001:db8::8'), null]) {
      const denied = await proxiedHttpGet(ACL, header);
      expect(denied.status).toBe(451);
      expect(denied.body).toBe('pp-denied');
    }
  });

  test('Blocked sources block the address the header names, and only it', async () => {
    const block = await api.post(`${API}/access-lists/blocked-sources/entries`, {
      headers: HEADERS,
      data: { address: '203.0.113.66', reason: 'PROXY protocol e2e', expiresInSeconds: 300 },
    });
    expect(block.status(), await block.text()).toBe(201);
    const entry = ((await block.json()) as { id: number }).id;
    blockedEntries.push(entry);

    await eventually(async () => expect((await proxiedHttpGet(OPEN, proxyV1('203.0.113.66'))).status).toBe(403));
    expect((await proxiedHttpGet(OPEN, proxyV2('203.0.113.66'))).status).toBe(403);
    expect(await clientOf(proxyV1('203.0.113.67'))).toBe('203.0.113.67');
    expect(await clientOf(null)).toBe(peer);

    const unblock = await api.delete(`${API}/access-lists/blocked-sources/entries/${entry}`, { headers: HEADERS });
    expect(unblock.status()).toBe(200);
    blockedEntries.splice(blockedEntries.indexOf(entry), 1);
    await eventually(async () => expect(await clientOf(proxyV1('203.0.113.66'))).toBe('203.0.113.66'));
  });

  test('geo blocking by address range uses the address the header names', async () => {
    await putGroup('geoblock', { ...EMPTY_GEOBLOCK, enabled: true, block_cidrs: ['203.0.113.128/25'], response_status: 403, response_body: 'pp-geo-blocked' });
    await eventually(async () => expect((await proxiedHttpGet(OPEN, proxyV1('203.0.113.200'))).status).toBe(403));
    const blocked = await proxiedHttpGet(OPEN, proxyV2('203.0.113.201'));
    expect(blocked.status).toBe(403);
    expect(blocked.body).toBe('pp-geo-blocked');
    expect(await clientOf(proxyV1('203.0.113.5'))).toBe('203.0.113.5');
    expect(await clientOf(null)).toBe(peer);
    await putGroup('geoblock', original.geoblock);
    await eventually(async () => expect(await clientOf(proxyV1('203.0.113.200'))).toBe('203.0.113.200'));
  });

  test('rate limits count each client the header names on its own', async () => {
    const statuses = async (header: Buffer | null, count: number) => {
      const result: number[] = [];
      for (let i = 0; i < count; i++) result.push((await proxiedHttpGet(RATE, header, `/limited/${i}`)).status);
      return result;
    };
    expect(await statuses(proxyV1('203.0.113.50'), 3)).toEqual([200, 200, 429]);
    // Another client behind the same balancer has a counter of its own.
    expect(await statuses(proxyV2('203.0.113.51'), 2)).toEqual([200, 200]);
    expect(await statuses(proxyV2('2001:db8:50::1'), 2)).toEqual([200, 200]);
    // And the balancer's own connections too.
    expect(await statuses(null, 2)).toEqual([200, 200]);
    expect(await statuses(proxyV1('203.0.113.50'), 1)).toEqual([429]);
  });

  test('a client cannot set its address with X-Forwarded-For through the balancer', async () => {
    const res = await proxiedHttpGet(OPEN, proxyV1('203.0.113.7'), '/', { 'X-Forwarded-For': '192.0.2.99' });
    expect(res.status).toBe(200);
    expect(forwardedFor(res.body)).toBe('203.0.113.7');
    // Listing the balancer among Trusted ranges changes nothing: the client is the header's address.
    await listSources([peer], { ranges: [peer] });
    const again = await proxiedHttpGet(OPEN, proxyV1('203.0.113.7'), '/', { 'X-Forwarded-For': '192.0.2.99' });
    expect(forwardedFor(again.body)).toBe('203.0.113.7');
  });

  test('Trusted ranges apply to the address the header names: a CDN in front of the balancer', async () => {
    await listSources([peer], { ranges: ['203.0.113.0/24'] });
    await eventually(async () => {
      const res = await proxiedHttpGet(OPEN, proxyV1('203.0.113.7'), '/', { 'X-Forwarded-For': '192.0.2.99' });
      expect(forwardedFor(res.body)).toBe('192.0.2.99, 203.0.113.7');
    });
    // The access list then sees the visitor behind the CDN.
    const viaCdn = await proxiedHttpGet(ACL, proxyV1('203.0.113.20'), '/', { 'X-Forwarded-For': '203.0.113.7' });
    expect(viaCdn.status).toBe(200);
    const deniedViaCdn = await proxiedHttpGet(ACL, proxyV1('203.0.113.20'), '/', { 'X-Forwarded-For': '198.51.100.1' });
    expect(deniedViaCdn.status).toBe(451);
    // A client outside the CDN's range still cannot set an address with the header.
    const direct = await proxiedHttpGet(OPEN, proxyV1('198.51.100.9'), '/', { 'X-Forwarded-For': '192.0.2.99' });
    expect(forwardedFor(direct.body)).toBe('198.51.100.9');
    await listSources([peer]);
  });

  test('the access log records the address the header names', async () => {
    await putGroup('logging', { enabled: true, format: 'json' });
    const uri = `/pp-log-${randomUUID()}`;
    await eventually(async () => {
      expect(await clientOf(proxyV1('203.0.113.77'), OPEN, uri)).toBe('203.0.113.77');
      const lines = accessLogLines(uri);
      expect(lines.length).toBeGreaterThan(0);
      const request = lines[lines.length - 1].request;
      expect(request.remote_ip).toBe('203.0.113.77');
      expect(request.client_ip).toBe('203.0.113.77');
      expect(request.remote_port).toBe('41234');
    });
  });

  test('analytics show the address the header names', async () => {
    test.setTimeout(180_000);
    const analytics = await api.get(`${API}/analytics/requests?range=1h&limit=1`);
    test.skip(!analytics.ok() || ((await analytics.json()) as { status?: string }).status !== 'ok', 'analytics are off in this stack');
    await putGroup('logging', { enabled: true, format: 'json' });
    const path = `/pp-analytics-${randomUUID()}`;
    expect(await clientOf(proxyV2('203.0.113.78'), OPEN, path)).toBe('203.0.113.78');
    const filters = encodeURIComponent(JSON.stringify([{ dim: 'host', op: 'is', value: OPEN }]));
    await expect
      .poll(
        async () => {
          const res = await api.get(`${API}/analytics/requests?range=1h&limit=100&filters=${filters}`);
          const rows = ((await res.json()) as { requests?: Array<{ path: string; ip: string }> }).requests ?? [];
          return rows.find((row) => row.path === path)?.ip ?? null;
        },
        { timeout: 120_000, intervals: [3_000] }
      )
      .toBe('203.0.113.78');
  });

  // ── Off again ─────────────────────────────────────────────────────────

  test('a source no longer listed cannot set addresses: its headers are ignored', async () => {
    await listSources(['198.51.100.0/24']);
    await eventually(async () => expect(await clientOf(proxyV1('203.0.113.7'))).toBe(peer));
    expect(await clientOf(proxyV2('203.0.113.7'))).toBe(peer);
    expect((await proxiedHttpGet(ACL, proxyV1('203.0.113.7'))).status).toBe(451);
  });

  test('clearing the list removes the listener wrappers, and a PROXY header is not understood again', async () => {
    await putGroup('trusted-proxies', { ranges: [] });
    expect((await readGroup('trusted-proxies'))?.proxy_protocol_ranges).toBeUndefined();
    await eventually(() => expect(liveListenerWrappers()).toBeNull());
    await eventually(async () => expect((await proxiedHttpGet(OPEN, proxyV1('203.0.113.7'))).status).toBe(400));
    expect(await clientOf(null)).toBe(peer);
    expect((await httpsGet(TLS)).status).toBe(200);
  });

  test('an empty list is the same as none', async () => {
    await putGroup('trusted-proxies', { ranges: [], proxy_protocol_ranges: [] });
    expect((await readGroup('trusted-proxies'))?.proxy_protocol_ranges).toEqual([]);
    expect(liveListenerWrappers()).toBeNull();
    expect((await proxiedHttpGet(OPEN, proxyV1('203.0.113.7'))).status).toBe(400);
  });
});
