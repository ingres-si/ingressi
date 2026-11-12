/**
 * The replicas stack (tests/docker-compose.test.replicas.yml): two dashboard
 * replicas on one PostgreSQL, and a third node the third-replica spec starts.
 */
import { execFileSync } from 'node:child_process';
import { composeArgs, composeEnv } from './e2e-stack';

export type Replica = {
  /** INGRESSI_NODE_ID. */
  nodeId: string;
  /** The compose service. */
  service: string;
  container: string;
  url: string;
};

export const REPLICA_A: Replica = { nodeId: 'replica-a', service: 'web', container: 'ingressi-web', url: 'http://localhost:3000' };
export const REPLICA_B: Replica = { nodeId: 'replica-b', service: 'web-b', container: 'ingressi-web-b', url: 'http://localhost:3010' };
/** A new node (profile third-replica). */
export const REPLICA_C: Replica = { nodeId: 'replica-c', service: 'web-c', container: 'ingressi-web-c', url: 'http://localhost:3011' };

export const REPLICAS = [REPLICA_A, REPLICA_B] as const;

/** Every replica's BASE_URL: the address behind the load balancer, so the Origin every replica trusts. */
export const PUBLIC_ORIGIN = 'http://localhost:3000';

export const ADMIN = { username: 'testadmin', password: 'TestPassword2026!' };

export function replicaCompose(args: string[], options: { timeoutMs?: number } = {}): string {
  return execFileSync('docker', [...composeArgs('replicas'), ...args], {
    cwd: process.cwd(),
    env: composeEnv('replicas'),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: options.timeoutMs ?? 300_000,
  });
}

export function containerLogs(container: string, since: Date): string {
  try {
    return execFileSync('docker', ['logs', '--since', since.toISOString(), container], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (error) {
    const failed = error as { stdout?: string; stderr?: string };
    return `${failed.stdout ?? ''}${failed.stderr ?? ''}`;
  }
}

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The status of GET /api/health on a replica (0 when it does not answer). */
export async function healthStatus(replica: Replica, scope?: 'leader' | 'live' | 'request-path'): Promise<number> {
  try {
    const response = await fetch(`${replica.url}/api/health${scope ? `?scope=${scope}` : ''}`, {
      signal: AbortSignal.timeout(5_000),
      cache: 'no-store',
    });
    return response.status;
  } catch {
    return 0;
  }
}

/** Polls until `check` returns a value that is not null or undefined; throws with `what` after `timeoutMs`. */
export async function eventually<T>(what: string, check: () => Promise<T | null | undefined>, timeoutMs = 30_000, intervalMs = 250): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  for (;;) {
    try {
      const value = await check();
      if (value !== null && value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    if (Date.now() >= deadline) {
      throw new Error(`${what} did not happen within ${timeoutMs} ms${lastError ? ` (last error: ${String(lastError)})` : ''}`);
    }
    await sleep(intervalMs);
  }
}

export async function waitForHealthy(replica: Replica, timeoutMs = 180_000): Promise<void> {
  await eventually(`${replica.nodeId} answering /api/health with 200`, async () => ((await healthStatus(replica)) === 200 ? true : null), timeoutMs, 1_000);
}

/** The replica that answers /api/health?scope=leader with 200, once exactly one does. */
export async function soleLeader(replicas: readonly Replica[] = REPLICAS, timeoutMs = 30_000): Promise<Replica> {
  return await eventually(
    'exactly one leader',
    async () => {
      const statuses = await Promise.all(replicas.map((replica) => healthStatus(replica, 'leader')));
      const leaders = replicas.filter((_, index) => statuses[index] === 200);
      return leaders.length === 1 && statuses.every((status) => status === 200 || status === 503) ? leaders[0] : null;
    },
    timeoutMs,
    500
  );
}

export type ClusterNodesView = {
  enabled: boolean;
  nodeId: string | null;
  role: string | null;
  leaderNodeId: string | null;
  liveReplicas: number;
  refusal: string | null;
  nodes: Array<{ id: string; status: string; leader: boolean; thisNode: boolean; version: string; schemaVersion: string }>;
};

/** The documentation ranges (RFC 5737): 3 x 254 addresses that are never a real client. */
const CLIENT_ADDRESS_POOL = ['192.0.2', '198.51.100', '203.0.113'].flatMap((prefix) => Array.from({ length: 254 }, (_, i) => `${prefix}.${i + 1}`));
let clientAddressCursor = Math.floor(Math.random() * CLIENT_ADDRESS_POOL.length);

/**
 * A client address of its own, so per-client limits of one test never touch
 * another. Better Auth allows 3 sign-ins per 10 seconds per address, so two tests
 * that drew the same address within that window made the second one fail with a
 * 429. Addresses are handed out in turn, from a random start: none repeats until
 * the whole pool (762) is used.
 */
export function clientAddress(): string {
  const address = CLIENT_ADDRESS_POOL[clientAddressCursor % CLIENT_ADDRESS_POOL.length];
  clientAddressCursor += 1;
  return address;
}
