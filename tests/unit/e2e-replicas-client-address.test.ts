import { describe, it, expect } from 'vitest';
import { clientAddress } from '../helpers/replicas';

describe('replicas e2e clientAddress', () => {
  it('never repeats an address within a run, so two tests cannot share a sign-in limit', () => {
    const addresses = Array.from({ length: 762 }, () => clientAddress());
    expect(new Set(addresses).size).toBe(762);
  });

  it('only hands out documentation-range addresses', () => {
    for (let i = 0; i < 50; i++) expect(clientAddress()).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.([1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/);
  });
});
