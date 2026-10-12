import { describe, expect, it } from 'vitest';
import { describeClickHouseFailure } from '@/src/lib/clickhouse/failure';

/** A network error as Node and Bun raise it: the code on the error itself. */
function networkError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

describe('describeClickHouseFailure', () => {
  it('points at the container log when the host name does not resolve', () => {
    for (const code of ['ENOTFOUND', 'EAI_AGAIN']) {
      const failure = describeClickHouseFailure(networkError(code, `getaddrinfo ${code} clickhouse`));
      expect(failure.label).toBe('Host name not found');
      expect(failure.note).toContain('docker compose logs clickhouse');
      expect(failure.note).toContain('CLICKHOUSE_URL');
    }
  });

  it('says the connection was refused, also when the code sits on the cause', () => {
    expect(describeClickHouseFailure(networkError('ECONNREFUSED', 'connect ECONNREFUSED 172.18.0.4:8123')).label).toBe('Connection refused');
    expect(describeClickHouseFailure(new Error('fetch failed', { cause: networkError('FailedToOpenSocket', 'Was there a typo in the url or port?') })).label).toBe('Connection refused');
  });

  it('keeps the generic status for any other error', () => {
    for (const error of [new Error('Code: 516. Authentication failed'), networkError('ECONNRESET', 'socket hang up'), 'boom', null]) {
      expect(describeClickHouseFailure(error)).toEqual({ label: 'Not reachable from the dashboard', note: null });
    }
  });
});
