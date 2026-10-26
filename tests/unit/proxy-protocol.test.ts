/**
 * PROXY protocol on the HTTP/HTTPS listeners (src/lib/proxy-protocol.ts):
 * which sources may be listed, how they are stored, and the listener
 * wrappers the main server gets from them.
 */
import { describe, expect, it } from 'vitest';
import {
  MAX_PROXY_PROTOCOL_RANGES,
  buildProxyProtocolListenerWrappers,
  normalizeProxyProtocolRange,
  normalizeProxyProtocolRanges,
  readProxyProtocolRanges,
} from '../../src/lib/proxy-protocol';

describe('normalizeProxyProtocolRange', () => {
  it('keeps addresses and stores ranges as their network address', () => {
    expect(normalizeProxyProtocolRange('192.168.1.1')).toEqual({ value: '192.168.1.1' });
    expect(normalizeProxyProtocolRange(' 10.0.0.0/8 ')).toEqual({ value: '10.0.0.0/8' });
    expect(normalizeProxyProtocolRange('192.168.1.1/24')).toEqual({ value: '192.168.1.0/24' });
    expect(normalizeProxyProtocolRange('192.168.1.1/32')).toEqual({ value: '192.168.1.1' });
  });

  it('accepts IPv6 addresses and ranges, in their short form', () => {
    expect(normalizeProxyProtocolRange('2001:0db8:0000:0000:0000:0000:0000:0001')).toEqual({ value: '2001:db8::1' });
    expect(normalizeProxyProtocolRange('2001:db8::1234/64')).toEqual({ value: '2001:db8::/64' });
    expect(normalizeProxyProtocolRange('::1')).toEqual({ value: '::1' });
  });

  it('refuses ranges that match every address', () => {
    for (const all of ['0.0.0.0/0', '::/0', '10.1.2.3/0']) {
      const result = normalizeProxyProtocolRange(all);
      expect(result).toHaveProperty('error');
      expect((result as { error: string }).error).toMatch(/matches every address/);
    }
  });

  it('refuses private_ranges, in any case', () => {
    for (const shorthand of ['private_ranges', 'PRIVATE_RANGES', ' Private_Ranges ']) {
      const result = normalizeProxyProtocolRange(shorthand);
      expect((result as { error: string }).error).toMatch(/private_ranges" is not accepted here/);
    }
  });

  it('refuses what is not an address', () => {
    for (const bad of ['firewall.lan', '10.0.0.256', '10.0.0.0/33', '2001:db8::/129', '10.0.0.0/', '/24', '1.2.3.4/8/9', '{http.request.host}', '']) {
      const result = normalizeProxyProtocolRange(bad);
      expect((result as { error: string }).error, bad).toMatch(/is not an IP address or a CIDR range/);
    }
  });

  it('shortens a long entry in the message', () => {
    const result = normalizeProxyProtocolRange('x'.repeat(200)) as { error: string };
    expect(result.error).toContain('...');
    expect(result.error.length).toBeLessThan(120);
  });
});

describe('normalizeProxyProtocolRanges', () => {
  it('reads nothing as an empty list', () => {
    expect(normalizeProxyProtocolRanges(undefined)).toEqual({ values: [] });
    expect(normalizeProxyProtocolRanges(null)).toEqual({ values: [] });
    expect(normalizeProxyProtocolRanges('')).toEqual({ values: [] });
    expect(normalizeProxyProtocolRanges([])).toEqual({ values: [] });
  });

  it('splits form text on newlines, commas and spaces, dropping blanks and duplicates', () => {
    expect(normalizeProxyProtocolRanges('192.168.1.1\n10.0.10.0/24, 10.0.10.7/24  192.168.1.1\r\n\n')).toEqual({
      values: ['192.168.1.1', '10.0.10.0/24'],
    });
  });

  it('normalizes an array of strings, keeping the order of first appearance', () => {
    expect(normalizeProxyProtocolRanges(['10.0.0.9/8', '  ', '192.0.2.10', '10.0.0.0/8'])).toEqual({
      values: ['10.0.0.0/8', '192.0.2.10'],
    });
  });

  it('names the first bad entry', () => {
    expect(normalizeProxyProtocolRanges(['10.0.0.1', 'nope', '0.0.0.0/0'])).toEqual({
      error: '"nope" is not an IP address or a CIDR range',
    });
    expect(normalizeProxyProtocolRanges('10.0.0.1\n::/0')).toEqual({
      error: '"::/0" matches every address, so any client could set its own address',
    });
  });

  it('refuses values that are not a list of strings', () => {
    expect(normalizeProxyProtocolRanges(42)).toEqual({ error: 'must be a list of IP addresses or CIDR ranges' });
    expect(normalizeProxyProtocolRanges({ 0: '10.0.0.1' })).toEqual({ error: 'must be a list of IP addresses or CIDR ranges' });
    expect(normalizeProxyProtocolRanges(['10.0.0.1', 7])).toEqual({ error: '[1] must be a string' });
  });

  it(`holds at most ${MAX_PROXY_PROTOCOL_RANGES} entries`, () => {
    const exactly = Array.from({ length: MAX_PROXY_PROTOCOL_RANGES }, (_, index) => `10.0.${index}.1`);
    expect(normalizeProxyProtocolRanges(exactly)).toEqual({ values: exactly });
    expect(normalizeProxyProtocolRanges([...exactly, '10.1.0.1'])).toEqual({ error: `can hold at most ${MAX_PROXY_PROTOCOL_RANGES} entries` });
    // Duplicates do not count.
    expect(normalizeProxyProtocolRanges([...exactly, ...exactly])).toEqual({ values: exactly });
    // A list far too long is refused before every entry is parsed.
    expect(normalizeProxyProtocolRanges(Array.from({ length: 5_000 }, () => '10.0.0.1'))).toEqual({
      error: `can hold at most ${MAX_PROXY_PROTOCOL_RANGES} entries`,
    });
  });
});

describe('readProxyProtocolRanges', () => {
  it('turns stored entries into CIDR ranges Caddy can parse', () => {
    expect(readProxyProtocolRanges(['192.168.1.1', '10.0.10.0/24', '2001:db8::1', '2001:db8::/48'])).toEqual([
      '192.168.1.1/32',
      '10.0.10.0/24',
      '2001:db8::1/128',
      '2001:db8::/48',
    ]);
  });

  it('drops what does not parse, what matches everything and private_ranges, so a bad value widens nothing', () => {
    expect(readProxyProtocolRanges(['nope', '0.0.0.0/0', 'private_ranges', 7, null, '192.0.2.1', '::/0'])).toEqual(['192.0.2.1/32']);
  });

  it('deduplicates entries that mean the same range', () => {
    expect(readProxyProtocolRanges(['192.0.2.1', '192.0.2.1/32', '10.1.1.1/8', '10.0.0.0/8'])).toEqual(['192.0.2.1/32', '10.0.0.0/8']);
  });

  it('reads anything but an array as nothing', () => {
    expect(readProxyProtocolRanges(undefined)).toEqual([]);
    expect(readProxyProtocolRanges('192.0.2.1')).toEqual([]);
    expect(readProxyProtocolRanges({ ranges: ['192.0.2.1'] })).toEqual([]);
  });

  it(`keeps at most ${MAX_PROXY_PROTOCOL_RANGES} ranges`, () => {
    const many = Array.from({ length: 150 }, (_, index) => `10.0.${index}.1`);
    expect(readProxyProtocolRanges(many)).toHaveLength(MAX_PROXY_PROTOCOL_RANGES);
  });
});

describe('buildProxyProtocolListenerWrappers', () => {
  it('emits nothing without sources', () => {
    expect(buildProxyProtocolListenerWrappers(undefined)).toEqual({});
    expect(buildProxyProtocolListenerWrappers([])).toEqual({});
    expect(buildProxyProtocolListenerWrappers(['nope', '0.0.0.0/0'])).toEqual({});
  });

  it('reads the PROXY header from the listed sources, before TLS', () => {
    expect(buildProxyProtocolListenerWrappers(['192.168.1.1', '2001:db8::/64'])).toEqual({
      listener_wrappers: [
        { wrapper: 'proxy_protocol', allow: ['192.168.1.1/32', '2001:db8::/64'], fallback_policy: 'ignore' },
        { wrapper: 'tls' },
      ],
    });
  });

  it('puts the tls wrapper last, so Caddy does not put TLS in front of the PROXY header', () => {
    const wrappers = buildProxyProtocolListenerWrappers(['10.0.0.1']).listener_wrappers!;
    expect(wrappers.map((wrapper) => wrapper.wrapper)).toEqual(['proxy_protocol', 'tls']);
  });

  it('ignores headers from every other client instead of trusting them', () => {
    const [proxyProtocol] = buildProxyProtocolListenerWrappers(['10.0.0.1']).listener_wrappers!;
    expect(proxyProtocol.fallback_policy).toBe('ignore');
    expect(proxyProtocol).not.toHaveProperty('deny');
  });
});
