/**
 * Failover (ee/docs/high-availability.md, "Leader election"): the leader
 * stops, the other replica takes the lead within seconds and the background
 * jobs run there; Caddy keeps reaching a dashboard for forward auth; the
 * stopped replica comes back as a follower.
 */
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { caddyAdminGet } from '../../helpers/live-caddy';
import { httpGet, waitForStatus } from '../../helpers/http';
import {
  REPLICAS,
  containerLogs,
  eventually,
  healthStatus,
  replicaCompose,
  soleLeader,
  waitForHealthy,
  type ClusterNodesView,
  type Replica,
} from '../../helpers/replicas';

const CADDY = 'ingressi-caddy';
const DOMAIN = 'replica-failover.test';

/** Caddy's live configuration, or null while its admin API does not answer. */
function liveCaddyConfig(): string | null {
  try {
    // Read the shared Caddy admin socket through a replica that is up: during
    // failover the leader (and its web container) is stopped, so default to the
    // follower, which always survives the assertions that read the config.
    return caddyAdminGet('/config/', follower?.container ?? 'ingressi-web');
  } catch {
    return null;
  }
}

let token = '';
let hostId: number | null = null;
let leader: Replica;
let follower: Replica;
let stoppedAt: Date;

const bearer = () => ({ Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' });

test.describe.serial('Two replicas: failover', () => {
  test('setup: a host behind Ingressi forward auth', async ({ request }) => {
    leader = await soleLeader();
    follower = REPLICAS.find((replica) => replica !== leader)!;
    // A session-authenticated API change must come from the replica's own origin (checkSameOrigin).
    const created = await request.post(`${follower.url}/api/v1/tokens`, {
      headers: { Origin: follower.url },
      data: { name: `replicas-failover-${Date.now()}` },
    });
    expect(created.status(), await created.text()).toBe(201);
    token = ((await created.json()) as { raw_token: string }).raw_token;

    const host = await request.post(`${follower.url}/api/v1/proxy-hosts`, {
      headers: bearer(),
      data: {
        name: 'Replica failover host',
        domains: [DOMAIN],
        upstreams: ['echo-server:8080'],
        sslForced: false,
        ingressiForwardAuth: { enabled: true },
      },
    });
    expect(host.status(), await host.text()).toBe(201);
    hostId = ((await host.json()) as { id: number }).id;
    // Caddy asks a dashboard and gets the portal redirect.
    await waitForStatus(DOMAIN, 302, 30_000);
  });

  test('Caddy sends forward auth to both replicas, with health checks (DASHBOARD_UPSTREAMS)', async () => {
    const config = JSON.parse(liveCaddyConfig() ?? 'null') as unknown;
    const verify: Array<{ upstreams?: Array<{ dial: string }>; health_checks?: { active?: { uri?: string } } }> = [];
    const visit = (node: unknown): void => {
      if (Array.isArray(node)) return node.forEach(visit);
      if (!node || typeof node !== 'object') return;
      const record = node as Record<string, unknown>;
      const rewrite = record.rewrite as { uri?: string } | undefined;
      if (record.handler === 'reverse_proxy' && rewrite?.uri === '/api/forward-auth/verify') verify.push(record as never);
      Object.values(record).forEach(visit);
    };
    visit(config);
    expect(verify.length).toBeGreaterThan(0);
    for (const handler of verify) {
      expect(handler.upstreams?.map((upstream) => upstream.dial).sort()).toEqual(['web-b:3000', 'web:3000']);
      expect(handler.health_checks?.active?.uri).toBe('/api/health');
    }
  });

  test('stopping the leader moves the lead to the other replica within seconds', async ({ request }) => {
    stoppedAt = new Date();
    replicaCompose(['stop', leader.service]);
    const stopped = Date.now();
    await eventually(`${follower.nodeId} taking the lead`, async () => ((await healthStatus(follower, 'leader')) === 200 ? true : null), 20_000, 250);
    const handover = Date.now() - stopped;
    console.log(`[replicas] ${follower.nodeId} led ${handover} ms after ${leader.nodeId} stopped`);
    expect(handover).toBeLessThan(15_000);

    await expect
      .poll(async () => {
        const view = (await (await request.get(`${follower.url}/api/v1/cluster/nodes`, { headers: bearer() })).json()) as ClusterNodesView;
        return {
          leader: view.leaderNodeId,
          live: view.liveReplicas,
          old: view.nodes.find((node) => node.id === leader.nodeId)?.status,
        };
      }, { timeout: 15_000 })
      .toEqual({ leader: follower.nodeId, live: 1, old: 'stopped' });
  });

  test('the new leader records the takeover and runs the background jobs', async ({ request }) => {
    await expect
      .poll(async () => {
        const response = await request.get(`${follower.url}/api/v1/audit-log?action=ha_leader_started&per_page=20&from=${encodeURIComponent(stoppedAt.toISOString())}`, { headers: bearer() });
        const { events } = (await response.json()) as { events: Array<{ summary: string | null }> };
        return events.map((event) => event.summary);
      }, { timeout: 15_000 })
      .toContain(`Replica ${follower.nodeId} became the leader of the PostgreSQL replicas and runs the background jobs`);

    // The Caddy monitor now runs on the new leader: Caddy restarted without
    // its autosave comes back with the image's default configuration, and
    // the monitor applies the dashboard's configuration again.
    const baseline = liveCaddyConfig();
    expect(baseline).toContain(DOMAIN);
    execFileSync('docker', ['exec', CADDY, 'rm', '-f', '/config/caddy/autosave.json']);
    execFileSync('docker', ['restart', CADDY]);
    await eventually('Caddy answering after the restart', async () => liveCaddyConfig(), 60_000, 500);
    await eventually('the new leader restoring the Caddy configuration', async () => (liveCaddyConfig()?.includes(DOMAIN) ? true : null), 120_000, 1_000);
    expect(containerLogs(follower.container, stoppedAt)).toContain('[CaddyMonitor] Configuration reapplied successfully');
  });

  test('Caddy reaches the remaining replica for forward auth', async () => {
    await waitForStatus(DOMAIN, 302, 30_000);
    const response = await httpGet(DOMAIN, '/after-failover');
    expect(response.status).toBe(302);
    expect(String(response.headers.location)).toContain('/portal?rd=');
  });

  test('the stopped replica comes back as a follower', async ({ request }) => {
    replicaCompose(['start', leader.service]);
    await waitForHealthy(leader);
    // The lead stays where it is.
    expect((await soleLeader()).nodeId).toBe(follower.nodeId);
    expect(await healthStatus(leader, 'leader')).toBe(503);
    await expect
      .poll(async () => {
        const view = (await (await request.get(`${leader.url}/api/v1/cluster/nodes`, { headers: bearer() })).json()) as ClusterNodesView;
        return { leader: view.leaderNodeId, live: view.liveReplicas, role: view.role };
      }, { timeout: 30_000 })
      .toEqual({ leader: follower.nodeId, live: 2, role: 'follower' });
  });

  test.afterAll(async ({ playwright }) => {
    // Both replicas run again whatever happened above.
    for (const replica of REPLICAS) {
      if ((await healthStatus(replica, 'live')) !== 200) replicaCompose(['start', replica.service]);
    }
    if (hostId === null) return;
    const client = await playwright.request.newContext();
    try {
      for (const replica of REPLICAS) {
        const response = await client.delete(`${replica.url}/api/v1/proxy-hosts/${hostId}`, { headers: bearer() });
        if (response.status() < 500) break;
      }
    } finally {
      await client.dispose();
    }
  });
});
