/**
 * Functional tests: L4 port manager sidecar (regression #117).
 *
 * Verifies that:
 * 1. Triggering "Apply Ports" successfully runs docker compose and reaches "applied"
 * 2. After restarting the l4-port-manager container the sidecar auto-applies the
 *    override file on startup without failing.
 *
 * The bug in #117: NETWORKS: 0 in the docker-socket-proxy blocked the
 * GET /networks/{id} call that docker compose makes when recreating the caddy
 * container. The compose command returned non-zero, the sidecar wrote "failed",
 * and the UI showed an error after every Docker restart.
 *
 * Must run after l4-proxy-routing.spec.ts (alphabetically "l4-sidecar" > "l4-proxy")
 * so that L4 proxy hosts exist and an override file is present on the shared volume.
 */
import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { waitForTcpEcho, tcpSend } from '../../helpers/tcp';

// Container name as defined in docker-compose.yml
const L4_CONTAINER = 'ingressi-l4-ports';

// Port created by l4-proxy-routing.spec.ts — must match that file
const TCP_PORT = 15432;

const BASE_URL = 'http://localhost:3000';
const ENV = { ...process.env, CLICKHOUSE_PASSWORD: 'test-clickhouse-password-2026' };

// requireApiAdmin → requireApiUser performs a same-origin CSRF check for mutating
// requests authenticated via session cookie.  page.request.post() doesn't send an
// Origin header by default, so we must add it explicitly.
const SESSION_HEADERS = { Origin: BASE_URL };

type L4StatusResponse = {
  status: {
    state: string;
    appliedAt?: string;
    message?: string;
    error?: string;
  };
};

async function fetchL4Status(page: Page): Promise<L4StatusResponse> {
  const res = await page.request.get('/api/l4-ports');
  expect(res.ok()).toBe(true);
  return res.json();
}

/**
 * Poll /api/l4-ports until the state is "applied" or "failed".
 *
 * Pass `newerThan` (ISO timestamp string) when you need to confirm a *new*
 * apply completed — e.g. after a container restart where the previous status
 * file already shows "applied".  Uses lexicographic comparison which works
 * correctly for ISO-8601 timestamps.
 */
async function waitForL4Terminal(
  page: Page,
  timeoutMs: number,
  newerThan?: string,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { status } = await fetchL4Status(page);
    const state = status?.state as string;
    const appliedAt = status?.appliedAt ?? '';

    const isTerminal = state === 'applied' || state === 'failed';
    const isFresh = !newerThan || appliedAt > newerThan;

    if (isTerminal && isFresh) return state;
    await page.waitForTimeout(2_000);
  }
  throw new Error(`l4-port-manager did not reach a terminal state within ${timeoutMs}ms`);
}

test.describe.serial('L4 Port Manager Sidecar', () => {
  test('apply ports reaches "applied" state', async ({ page }) => {
    // waitForL4Terminal polls for up to 90 s; the global 60 s timeout would
    // fire first without this override.
    test.setTimeout(180_000);

    // Trigger a fresh apply via the API (writes a new trigger file with a new
    // timestamp, so the sidecar will process it even if ports haven't changed).
    const res = await page.request.post('/api/l4-ports', { headers: SESSION_HEADERS });
    expect(res.ok(), `POST /api/l4-ports failed: ${await res.text()}`).toBe(true);

    const state = await waitForL4Terminal(page, 90_000);
    expect(
      state,
      'Expected "applied" but got "failed". Run: docker logs ingressi-l4-ports',
    ).toBe('applied');
  });

  test('TCP traffic works after explicit apply', async () => {
    await waitForTcpEcho('127.0.0.1', TCP_PORT, 30_000);
    const res = await tcpSend('127.0.0.1', TCP_PORT, 'sidecar-apply-check\n');
    expect(res.connected).toBe(true);
    expect(res.data).toContain('sidecar-apply-check');
  });

  test('auto-applies on sidecar container restart — regression #117', async ({ page }) => {
    // Container restart + do_apply + caddy health-check can take ~60 s total;
    // waitForL4Terminal polls for up to 90 s.  Override to avoid the 60 s global cap.
    test.setTimeout(180_000);

    // Record the current appliedAt so we can detect when a *new* apply finishes.
    // The sidecar uses second-level timestamp precision, so sleep 1.5 s first to
    // guarantee the new timestamp will be strictly greater.
    const { status: before } = await fetchL4Status(page);
    const prevAppliedAt = before?.appliedAt ?? '';
    await page.waitForTimeout(1_500);

    // Restart the sidecar container.  On startup it finds the override file and
    // calls `docker compose up --force-recreate caddy`.  With NETWORKS: 0 in the
    // docker-socket-proxy this always failed because docker compose needs
    // GET /networks/{id} to inspect caddy-network before reconnecting the container.
    // The fix adds NETWORKS: 1 so the network inspection succeeds.
    execFileSync('docker', ['restart', L4_CONTAINER], {
      stdio: 'inherit',
      cwd: process.cwd(),
      env: ENV,
    });

    // Wait for the sidecar to restart, run do_apply, and write a fresh status.
    // Caddy health-check has a 10 s start_period so allow up to 90 s total.
    const state = await waitForL4Terminal(page, 90_000, prevAppliedAt);
    expect(
      state,
      'Sidecar returned "failed" after restart. ' +
      'Likely cause: docker-socket-proxy is missing NETWORKS: 1. ' +
      'Run: docker logs ingressi-l4-ports',
    ).toBe('applied');
  });

  test('TCP traffic still works after sidecar restart and auto-apply', async () => {
    // Caddy was briefly recreated during the restart apply; waitForTcpEcho
    // retries until it proxies again.
    await waitForTcpEcho('127.0.0.1', TCP_PORT, 30_000);
    const res = await tcpSend('127.0.0.1', TCP_PORT, 'after-restart-check\n');
    expect(res.connected).toBe(true);
    expect(res.data).toContain('after-restart-check');
  });

  // ---------------------------------------------------------------------------
  // Regression (production incident 2026-09-13): a failed `docker compose up`
  // aborted the sidecar under `set -e` leaving a stale .l4-apply.lock. The old
  // startup guard skipped the restore whenever it saw a fresh lock, so every
  // subsequent restart came up WITHOUT the L4 ports bound and LiveKit voice
  // traffic silently broke. The fix: the sidecar waits out a fresh lock, takes
  // over a stale one, and always re-applies at startup.
  // ---------------------------------------------------------------------------
  test('recovers from a crashed apply (stale lock) on startup — regression 2026-09-13', async ({ page }) => {
    test.setTimeout(240_000);

    const { status: before } = await fetchL4Status(page);
    const prevAppliedAt = before?.appliedAt ?? '';
    await page.waitForTimeout(1_500);

    // Simulate a crashed apply: plant a stale lock (old timestamp AND old
    // mtime — the script reads the timestamp content) plus a stuck "applying"
    // status, exactly as the aborted script left them in production. The lock
    // lives on the shared data volume, writable from the web container at
    // /app/data (the sidecar sees the same files at /data).
    const staleTs = Math.floor(Date.now() / 1000) - 3600;
    // Plant the files as root (-u root): a crashed apply left them owned by the
    // sidecar user (root) on the shared volume, so the web user (uid 10001)
    // cannot overwrite l4-ports.status — writing as root mirrors production.
    execFileSync(
      'docker',
      [
        'exec', '-u', 'root', 'ingressi-web', 'sh', '-c',
        `echo ${staleTs} > /app/data/.l4-apply.lock && ` +
        `printf '{"state":"applying","message":"Recreating caddy container with updated ports...","appliedAt":"2020-01-01T00:00:00.000Z"}' > /app/data/l4-ports.status`,
      ],
      { stdio: 'inherit', cwd: process.cwd(), env: ENV },
    );

    // Restart the sidecar. With the old guard it would have skipped the
    // restore forever ("already in progress, skipping...") and the status
    // would have stayed stuck on the planted "applying". With the fix it must
    // take over, re-apply, and reach a fresh terminal state.
    execFileSync('docker', ['restart', L4_CONTAINER], { stdio: 'inherit', cwd: process.cwd(), env: ENV });

    const state = await waitForL4Terminal(page, 120_000, prevAppliedAt);
    expect(
      state,
      'Sidecar did not recover from the planted stale lock. ' +
        'Check: docker logs ingressi-l4-ports',
    ).toBe('applied');

    // The lock must be gone after the recovered apply
    const lockGone = execFileSync(
      'docker',
      ['exec', 'ingressi-web', 'sh', '-c', 'test -f /app/data/.l4-apply.lock && echo present || echo absent'],
      { cwd: process.cwd(), env: ENV },
    ).toString().trim();
    expect(lockGone).toBe('absent');
  });

  test('L4 traffic works after recovery from crashed apply', async () => {
    await waitForTcpEcho('127.0.0.1', TCP_PORT, 30_000);
    const res = await tcpSend('127.0.0.1', TCP_PORT, 'crash-recovery-check\n');
    expect(res.connected).toBe(true);
    expect(res.data).toContain('crash-recovery-check');
  });
});
