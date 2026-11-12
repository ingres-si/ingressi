/**
 * Validators for the free-form Caddy-bound scalar fields a proxy-host / L4
 * write can set (durations, DNS resolver addresses, geoblock lists, trusted
 * proxies). A malformed value would make Caddy reject the whole document and
 * block every later apply, so these reject the write with a 400 instead.
 */
import { describe, it, expect } from 'vitest';
import {
  assertCaddyDuration,
  assertIpOrCidr,
  assertResolverAddress,
  validateProxyHostCaddyScalars,
  validateL4CaddyScalars,
} from '../../src/lib/caddy-input-validation';
import { ApiValidationError } from '../../src/lib/api-errors';

describe('assertCaddyDuration', () => {
  it.each(['10s', '500ms', '1m30s', '2h', '1d', '0', '1.5s', '.5s', '1.s', '100us', '250µs', '250μs', '5ns', undefined, null, ''])(
    'accepts %s', (v) => expect(() => assertCaddyDuration(v as string, 'd')).not.toThrow()
  );
  it.each(['notaduration', 'banana', '10', '10sec', '1 s', 's', '-', '10x', '{env.X}', '.s', '99999999999999999999h', '300y', 5 as unknown as string])(
    'rejects %s', (v) => expect(() => assertCaddyDuration(v, 'd')).toThrow(ApiValidationError)
  );
});

describe('assertIpOrCidr', () => {
  it.each(['10.0.0.0/8', '192.168.1.1', '::1', '2001:db8::/32', '1.2.3.4/32'])(
    'accepts %s', (v) => expect(() => assertIpOrCidr(v, 'c')).not.toThrow()
  );
  // Go's parsers are stricter than Node's: no empty, padded or non-decimal prefix, no IPv6 zone.
  it.each(['not-a-cidr', '10.0.0.0/33', '999.1.1.1', '10.0.0.0/-1', 'private_ranges', '10.0.0.0/', '10.0.0.0/1e1', '10.0.0.0/0x8',
    '10.0.0.0/ 8', '10.0.0.0/08', '10.0.0.0/+8', '10.0.0.0/8.0', 'fe80::1%eth0', 'fe80::1%eth0/64', ' 10.0.0.1', '', 7 as unknown as string])(
    'rejects %s (without the keyword)', (v) => expect(() => assertIpOrCidr(v, 'c')).toThrow(ApiValidationError)
  );
  it('allows private_ranges only when permitted', () => {
    expect(() => assertIpOrCidr('private_ranges', 'c', true)).not.toThrow();
  });
});

describe('assertResolverAddress', () => {
  it.each(['1.1.1.1', '8.8.8.8:53', '[2606:4700:4700::1111]:53', 'udp/1.1.1.1:53', 'tcp/9.9.9.9:53', 'dns.example.com:53'])(
    'accepts %s', (v) => expect(() => assertResolverAddress(v, 'r')).not.toThrow()
  );
  it.each(['unix//run/x.sock', '169.254.169.254:{env.P}', 'fd/3', '1.1.1.1/foo', '{http.request.header.r}', 'a:b:c',
    '1.1.1.1:99999', '1.1.1.1:0', '[::1]:99999', '[::1]:abc', '[::1]:1-5', '[::1]junk', 'a b:53', '1.1.1.1:53-54'])(
    'rejects %s', (v) => expect(() => assertResolverAddress(v, 'r')).toThrow(ApiValidationError)
  );
});

describe('validateProxyHostCaddyScalars', () => {
  it('rejects a bad load-balancer duration', () => {
    expect(() => validateProxyHostCaddyScalars({ loadBalancer: { tryDuration: 'banana' } })).toThrow(/tryDuration/);
  });
  it('rejects a bad health-check interval on a location rule', () => {
    expect(() => validateProxyHostCaddyScalars({
      locationRules: [{ loadBalancer: { activeHealthCheck: { interval: 'soon' } } }],
    })).toThrow(/interval/);
  });
  it('rejects a malformed per-host geoblock CIDR', () => {
    expect(() => validateProxyHostCaddyScalars({ geoblock: { block_cidrs: ['not-a-cidr'] } as unknown })).toThrow(/block_cidrs/);
  });
  it('rejects a unix-socket DNS resolver', () => {
    expect(() => validateProxyHostCaddyScalars({ dnsResolver: { resolvers: ['unix//x.sock'] } })).toThrow(/dnsResolver/);
  });
  it('rejects a malformed forward-auth trusted proxy', () => {
    expect(() => validateProxyHostCaddyScalars({ forwardAuth: { trustedProxies: ['garbage'] } })).toThrow(/trustedProxies/);
  });
  it('accepts valid values, including private_ranges and real durations/resolvers', () => {
    expect(() => validateProxyHostCaddyScalars({
      loadBalancer: { tryDuration: '5s', activeHealthCheck: { interval: '10s', timeout: '2s' } },
      dnsResolver: { resolvers: ['1.1.1.1', 'tcp/8.8.8.8:53'], timeout: '5s' },
      geoblock: { block_cidrs: ['10.0.0.0/8'], block_asns: [64512] } as unknown,
      authentik: { trustedProxies: ['private_ranges', '172.16.0.0/12'] },
    })).not.toThrow();
  });
});

describe('geoblock rules', () => {
  const geo = (g: object) => () => validateProxyHostCaddyScalars({ geoblock: g as unknown });
  it.each([
    ['an address in block_cidrs', { block_cidrs: ['1.2.3.4'] }],
    ['a range in block_ips', { block_ips: ['10.0.0.0/8'] }],
    ['a padded range', { block_cidrs: [' 10.0.0.0/8 '] }],
    ['an empty entry', { allow_cidrs: [''] }],
    ['a number in a list', { block_cidrs: [123] }],
    ['a string in place of a list', { block_cidrs: 'garbage' }],
    ['an IPv6 zone', { allow_ips: ['fe80::1%eth0'] }],
    ['AS number 0', { block_asns: [0] }],
    ['an AS number above 32 bits', { allow_asns: [1e30] }],
    ['a fractional AS number', { block_asns: [1.5] }],
    ['AS numbers that are not a list', { block_asns: 64512 }],
    ['a lowercase country', { block_countries: ['us'] }],
    ['a three-letter country', { allow_countries: ['ZZZ'] }],
    ['an unknown continent', { block_continents: ['XX'] }],
    ['a bad trusted proxy', { trusted_proxies: ['garbage'] }],
    ['a redirect that is not a URL', { redirect_url: 'not a url' }],
    ['a redirect with a broken escape', { redirect_url: '/blocked%zz' }],
    ['a status out of range', { response_status: 99999 }],
    ['a fractional status', { response_status: 403.5 }],
    ['a header value that is not text', { response_headers: { 'X-A': 1 } }],
    ['a list in place of the rules', ['x']],
  ])('refuses %s', (_what, g) => expect(geo(g)).toThrow(ApiValidationError));

  it('accepts what the dashboard form sends', () => {
    expect(geo({
      enabled: true,
      block_countries: ['CN', 'RU'], block_continents: ['AF'], block_asns: [64512], block_cidrs: ['10.0.0.0/8', '2001:db8::/32'], block_ips: ['1.2.3.4', '::1'],
      allow_countries: [], allow_continents: [], allow_asns: [], allow_cidrs: [], allow_ips: [],
      trusted_proxies: ['private_ranges', '172.16.0.0/12', '192.0.2.1'], fail_closed: false,
      response_status: 403, response_body: 'Forbidden', response_headers: { 'X-Blocked': '1' }, redirect_url: '',
    })).not.toThrow();
    expect(geo({ redirect_url: 'https://example.com/blocked?x=1' })).not.toThrow();
    expect(geo({ redirect_url: '/blocked' })).not.toThrow();
  });
});

describe('load balancer and health-check values', () => {
  const lb = (l: object) => () => validateProxyHostCaddyScalars({ loadBalancer: l as never });
  it.each([
    ['a fractional health-check port', { activeHealthCheck: { port: 1.5 } }],
    ['a health-check port above 65535', { activeHealthCheck: { port: 70000 } }],
    ['a fractional expected status', { activeHealthCheck: { status: 200.5 } }],
    ['a health-check URI with a broken escape', { activeHealthCheck: { uri: '/%zz' } }],
    ['a health-check URI that is not a path', { activeHealthCheck: { uri: 'health check' } }],
    ['an expected body that does not compile', { activeHealthCheck: { body: '(' } }],
    ['an expected body with a lookahead', { activeHealthCheck: { body: 'a(?=b)' } }],
    ['an expected body with a backreference', { activeHealthCheck: { body: '(a)\\1' } }],
    ['a repeat count above 1000', { activeHealthCheck: { body: 'a{2000}' } }],
    ['fractional retries', { retries: 1.5 }],
    ['fractional max fails', { passiveHealthCheck: { maxFails: 1.5 } }],
    ['a fractional unhealthy status', { passiveHealthCheck: { unhealthyStatus: [500.5] } }],
    ['a number as a duration', { tryDuration: 5 }],
  ])('refuses %s', (_what, l) => expect(lb(l)).toThrow(ApiValidationError));

  it('accepts whole numbers, a path and Go regular expressions', () => {
    expect(lb({
      retries: 3,
      activeHealthCheck: { uri: '/health?full=1', port: 8080, status: 200, body: '(?i)ok|(?P<state>up)\\z' },
      passiveHealthCheck: { maxFails: 0, unhealthyStatus: [500, 502] },
    })).not.toThrow();
  });

  it('checks location rules the same way', () => {
    expect(() => validateProxyHostCaddyScalars({ locationRules: [{ loadBalancer: { activeHealthCheck: { port: 1.5 } } as never }] })).toThrow(ApiValidationError);
  });
});

describe('validateL4CaddyScalars', () => {
  it('rejects a bad L4 load-balancer duration', () => {
    expect(() => validateL4CaddyScalars({ loadBalancer: { tryDuration: 'nope' } })).toThrow(ApiValidationError);
  });
  it('accepts valid L4 scalars', () => {
    expect(() => validateL4CaddyScalars({ loadBalancer: { tryDuration: '5s' }, geoblock: { block_ips: ['1.2.3.4'] } as unknown })).not.toThrow();
  });
});
