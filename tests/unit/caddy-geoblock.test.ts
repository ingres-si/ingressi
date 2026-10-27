import { describe, it, expect, vi } from 'vitest';

vi.unmock('@/src/lib/caddy');

import { buildBlockerHandler, resolveEffectiveGeoBlock, withDefaultGeoBlockTrustedProxies } from '@/src/lib/caddy';
import type { GeoBlockSettings } from '@/src/lib/settings';

const globalGeoBlock: GeoBlockSettings = {
  enabled: true,
  block_countries: ['CN'],
  block_continents: [],
  block_asns: [],
  block_cidrs: [],
  block_ips: [],
  allow_countries: [],
  allow_continents: [],
  allow_asns: [],
  allow_cidrs: [],
  allow_ips: [],
  trusted_proxies: [],
  fail_closed: false,
  response_status: 403,
  response_body: 'Forbidden anyway!',
  response_headers: {},
  redirect_url: '',
};

describe('resolveEffectiveGeoBlock', () => {
  it('keeps global response settings when host geoblock is disabled in merge mode', () => {
    const result = resolveEffectiveGeoBlock(globalGeoBlock, {
      geoblock_mode: 'merge',
      geoblock: {
        enabled: false,
        block_countries: [],
        block_continents: [],
        block_asns: [],
        block_cidrs: [],
        block_ips: [],
        allow_countries: [],
        allow_continents: [],
        allow_asns: [],
        allow_cidrs: [],
        allow_ips: [],
        trusted_proxies: [],
        fail_closed: false,
        response_status: 403,
        response_body: 'Forbidden',
        response_headers: {},
        redirect_url: '',
      },
    });

    expect(result).toEqual(globalGeoBlock);
    expect(buildBlockerHandler(result!).response_body).toBe('Forbidden anyway!');
  });

  it('still lets enabled host config override global response settings in merge mode', () => {
    const result = resolveEffectiveGeoBlock(globalGeoBlock, {
      geoblock_mode: 'merge',
      geoblock: {
        ...globalGeoBlock,
        enabled: true,
        response_body: 'Blocked by host',
      },
    });

    expect(result?.response_body).toBe('Blocked by host');
    expect(buildBlockerHandler(result!).response_body).toBe('Blocked by host');
  });

  it('merges the global rules into an enabled host config in merge mode', () => {
    const result = resolveEffectiveGeoBlock(globalGeoBlock, {
      geoblock_mode: 'merge',
      geoblock: { ...globalGeoBlock, block_countries: ['RU'], response_body: 'Forbidden' },
    });

    expect(result?.block_countries).toEqual(['CN', 'RU']);
  });

  it('keeps the saved rules of a disabled global config out of an enabled host in merge mode', () => {
    const disabledGlobal: GeoBlockSettings = {
      ...globalGeoBlock,
      enabled: false,
      block_countries: ['CN', 'RU'],
      block_cidrs: ['0.0.0.0/0'],
      trusted_proxies: ['10.0.0.1'],
      response_headers: { 'X-Global': '1' },
    };
    const hostGeoBlock: GeoBlockSettings = { ...globalGeoBlock, block_countries: ['KP'], response_body: 'Forbidden' };
    const result = resolveEffectiveGeoBlock(disabledGlobal, { geoblock_mode: 'merge', geoblock: hostGeoBlock });

    expect(result).toEqual(hostGeoBlock);
    const handler = buildBlockerHandler(result!);
    expect(handler.block_countries).toEqual(['KP']);
    expect(handler.block_cidrs).toBeUndefined();
    expect(handler.trusted_proxies).toBeUndefined();
    expect(handler.response_headers).toBeUndefined();
  });

  it('applies no geo blocking when the global config is disabled and the host has none', () => {
    const disabledGlobal = { ...globalGeoBlock, enabled: false };
    expect(resolveEffectiveGeoBlock(disabledGlobal, { geoblock_mode: 'merge', geoblock: null })).toBeNull();
    expect(resolveEffectiveGeoBlock(disabledGlobal, { geoblock_mode: 'merge', geoblock: { ...globalGeoBlock, enabled: false } })).toBeNull();
  });

  it('ignores the global rules for a disabled host config in override mode', () => {
    expect(resolveEffectiveGeoBlock(globalGeoBlock, { geoblock_mode: 'override', geoblock: { ...globalGeoBlock, enabled: false } })).toBeNull();
  });
});

describe('withDefaultGeoBlockTrustedProxies', () => {
  it('uses the ranges when the config lists no trusted proxies', () => {
    expect(withDefaultGeoBlockTrustedProxies(globalGeoBlock, ['172.21.0.1/32'])?.trusted_proxies).toEqual(['172.21.0.1/32']);
  });

  it('leaves a config that lists its own trusted proxies untouched', () => {
    const config = { ...globalGeoBlock, trusted_proxies: ['10.9.9.9/32'] };
    expect(withDefaultGeoBlockTrustedProxies(config, ['172.21.0.1/32'])).toBe(config);
  });

  it('leaves the config as it is without ranges, and passes null through', () => {
    expect(withDefaultGeoBlockTrustedProxies(globalGeoBlock, [])).toBe(globalGeoBlock);
    expect(withDefaultGeoBlockTrustedProxies(globalGeoBlock, undefined)).toBe(globalGeoBlock);
    expect(withDefaultGeoBlockTrustedProxies(null, ['172.21.0.1/32'])).toBeNull();
  });
});
