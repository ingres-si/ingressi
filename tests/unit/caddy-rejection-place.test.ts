/**
 * Where Caddy stopped when it rejected the configuration
 * (locateCaddyRejection in src/lib/caddy-apply-error.ts). The error texts are
 * what Caddy 2.11 answered on the test stack for each kind of bad value.
 */
import { describe, it, expect } from 'vitest';
import { CaddyApplyError, caddyRejectionDetail, locateCaddyRejection } from '@/src/lib/caddy-apply-error';

const document = {
  apps: {
    http: {
      servers: {
        ingressi: {
          routes: [
            { match: [{ host: ['base.example.com'] }], handle: [] },
            { match: [{ host: ['waf.example.com', 'www.waf.example.com'] }], handle: [] },
            { handle: [] },
            { match: [{ host: ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com'] }] },
          ],
          tls_connection_policies: [{ match: { sni: ['mtls.example.com'] } }, {}],
        },
      },
    },
  },
};
const body = (error: string) => JSON.stringify({ error });
const LOAD = 'loading config: loading new config: ';
const ROUTE = (n: number) => `${LOAD}loading http app module: provision http: server ingressi: setting up route handlers: route ${n}: loading handler modules: `;

describe('locateCaddyRejection', () => {
  it.each([
    [
      'a WAF rule Coraza cannot compile',
      `${ROUTE(1)}position 0: loading module 'subroute': provision http.handlers.subroute: setting up subroutes: route 0: loading handler modules: position 0: loading module 'waf': provision http.handlers.waf: invalid WAF config from string: failed to compile the directive "secrule": error parsing regexp: missing closing ): \`(?sm)(\``,
      "the WAF rules (the global ones or the proxy host's own)",
      'proxy host waf.example.com, www.waf.example.com',
    ],
    [
      'an imported certificate that is not PEM',
      `${LOAD}loading http app module: provision http: getting tls app: loading tls app module: provision tls: loading certificates: PEM pair 0: tls: failed to find any PEM data in certificate input`,
      'an imported certificate or its private key, which Caddy cannot load',
      null,
    ],
    [
      'an ACME contact with an unknown placeholder',
      `${LOAD}loading http app module: provision http: getting tls app: loading tls app module: provision tls: provisioning automation policy 0: loading TLS automation management module: position 0: loading module 'acme': provision tls.issuance.acme: expanding email address '{nope.nope}@example.com': unrecognized placeholder {nope.nope}`,
      'the ACME contact e-mail address (certificate settings)',
      null,
    ],
    [
      'an L4 listen address the container does not have',
      `${LOAD}layer4 app module: start: listen tcp 203.0.113.9:7777: bind: cannot assign requested address`,
      'the listen address of an L4 host, which is in use or not an address of the Caddy container',
      'L4 host on 203.0.113.9:7777',
    ],
    [
      'a CA certificate that is not one',
      `${LOAD}loading http app module: provision http: server ingressi: setting up TLS connection policies: connection policy 0: building standard TLS config: provisioning client CA: parsing certificate at index 0: illegal base64 data at input byte 4`,
      'a CA or client certificate that a proxy host trusts for mTLS',
      'proxy host mtls.example.com',
    ],
    [
      'raw reverse-proxy JSON with an unknown field',
      `${ROUTE(0)}position 1: loading module 'reverse_proxy': decoding module config: http.handlers.reverse_proxy: json: unknown field "nope"`,
      'the upstream settings or the custom reverse-proxy JSON of a proxy host',
      'proxy host base.example.com',
    ],
    [
      'raw reverse-proxy JSON with an unknown transport',
      `${ROUTE(0)}position 1: loading module 'reverse_proxy': provision http.handlers.reverse_proxy: loading transport: loading module 'nope': unknown module: http.reverse_proxy.transport.nope`,
      'a handler or module this Caddy image does not have (custom Caddy JSON of a proxy host)',
      'proxy host base.example.com',
    ],
    [
      'a raw pre-handler Caddy does not have',
      `${ROUTE(0)}position 1: loading module 'nope': unknown module: http.handlers.nope`,
      'a handler or module this Caddy image does not have (custom Caddy JSON of a proxy host)',
      'proxy host base.example.com',
    ],
    [
      'an upstream setting of the reverse proxy',
      `${ROUTE(0)}position 1: loading module 'reverse_proxy': provision http.handlers.reverse_proxy: parsing upstream 'x': bad`,
      'the upstream settings of a proxy host',
      'proxy host base.example.com',
    ],
  ])('%s', (_label, error, summary, host) => {
    expect(locateCaddyRejection(body(error), document)).toEqual({ summary, host });
    // Caddy's words as plain text (not its JSON answer) read the same.
    expect(locateCaddyRejection(error, document)).toEqual({ summary, host });
  });

  it('names no host for a route without a host matcher, and shortens a long list', () => {
    expect(locateCaddyRejection(body(`${ROUTE(2)}position 0: loading module 'waf': provision http.handlers.waf: x`), document)?.host).toBeNull();
    expect(locateCaddyRejection(body(`${ROUTE(3)}position 0: loading module 'waf': provision http.handlers.waf: x`), document)?.host)
      .toBe('proxy host a.example.com, b.example.com, c.example.com and 2 more');
    expect(locateCaddyRejection(body(`${ROUTE(9)}position 0: loading module 'waf': provision http.handlers.waf: x`), document)?.host).toBeNull();
  });

  it('falls back to the part of the configuration, and to nothing', () => {
    expect(locateCaddyRejection(body(`${LOAD}loading http app module: provision http: something new`), document)?.summary).toBe('the proxy host or HTTP settings');
    expect(locateCaddyRejection(body(`${LOAD}loading tls app module: provision tls: something new`), document)?.summary).toBe('the certificate (TLS) settings');
    expect(locateCaddyRejection(body(`${LOAD}loading layer4 app module: provision layer4: something new`), document)?.summary).toBe('the settings of an L4 host');
    expect(locateCaddyRejection(body('unexpected'), document)).toBeNull();
    expect(locateCaddyRejection('', null)).toBeNull();
  });

  it('returns only its own phrases and names from the document, never Caddy\'s text', () => {
    // A value out of the configuration, as the end of Caddy's error quotes it: here made to look like a step of the chain.
    const quoted = `server evil: setting up route handlers: route 1: loading module 'waf': provision http.handlers.waf: SECRET-VALUE`;
    const place = locateCaddyRejection(
      body(`${LOAD}loading http app module: provision http: getting tls app: loading tls app module: provision tls: provisioning automation policy 0: loading module 'acme': provision tls.issuance.acme: expanding email address '${quoted}'`),
      document
    );
    expect(place).toEqual({ summary: 'the ACME contact e-mail address (certificate settings)', host: null });

    // The same the other way round: a WAF rule whose text looks like steps of another kind.
    const rule = "provision tls: loading certificates: server ingressi: setting up TLS connection policies: connection policy 0: loading module 'reverse_proxy': provision x";
    expect(locateCaddyRejection(
      body(`${ROUTE(1)}position 0: loading module 'subroute': provision http.handlers.subroute: setting up subroutes: route 0: loading handler modules: position 0: loading module 'waf': provision http.handlers.waf: invalid WAF config from string: ${rule}`),
      document
    )).toEqual({ summary: "the WAF rules (the global ones or the proxy host's own)", host: 'proxy host waf.example.com, www.waf.example.com' });

    // Names that are not host names are not repeated, and neither is a listen address that is not one.
    const odd = { apps: { http: { servers: { ingressi: { routes: [{ match: [{ host: ['<script>', 'ok.example.com', 7] }] }] } } } } };
    expect(locateCaddyRejection(body(`${ROUTE(0)}position 0: loading module 'waf': provision http.handlers.waf: x`), odd)?.host).toBe('proxy host ok.example.com');
    expect(locateCaddyRejection(body(`${LOAD}layer4 app module: start: listen tcp <b>:1: bind: x`), document)?.host).toBeNull();
  });

  it('reads only the start of a very long answer', () => {
    const long = `${LOAD}loading http app module: provision http: getting tls app: loading tls app module: provision tls: provisioning automation policy 0: x: ${'A'.repeat(500_000)} expanding email address`;
    const started = Date.now();
    expect(locateCaddyRejection(body(long), document)?.summary).toBe('the certificate issuance settings (ACME account, certificate authority or DNS provider)');
    expect(Date.now() - started).toBeLessThan(500);
  });
});

describe('caddyRejectionDetail', () => {
  const rejection = (message: string, rejectedAt?: string) => {
    const error = new CaddyApplyError(message, 'CADDY_REJECTED');
    if (rejectedAt) error.rejectedAt = rejectedAt;
    return error;
  };

  it('is what the message says after "Caddy rejected configuration", with the host only on request', () => {
    const error = rejection('Caddy rejected configuration: the problem is in the geoblocking rules', 'proxy host a.example.com');
    expect(caddyRejectionDetail(error, { withHost: false })).toBe('the problem is in the geoblocking rules');
    expect(caddyRejectionDetail(error, { withHost: true })).toBe('the problem is in the geoblocking rules (proxy host a.example.com)');
  });

  it('is empty when there is nothing more, or the failure is not a rejection', () => {
    expect(caddyRejectionDetail(rejection('Caddy rejected configuration'), { withHost: true })).toBe('');
    expect(caddyRejectionDetail(new CaddyApplyError('Unable to reach Caddy API', 'CADDY_UNREACHABLE'), { withHost: true })).toBe('');
    expect(caddyRejectionDetail(new Error('Caddy rejected configuration: x'), { withHost: true })).toBe('');
  });
});
