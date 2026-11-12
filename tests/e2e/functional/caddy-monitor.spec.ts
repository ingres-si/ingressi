/**
 * Functional tests: CaddyMonitor configuration-drift recovery.
 *
 * The monitor must re-push Ingressi's configuration whenever Caddy is no longer
 * serving it — container recreated/restarted without a usable autosave
 * (wiped config volume, recreated container before the first config push)
 * or restarted onto the image's default Caddyfile.
 *
 * Regression guard: detection used to compare against an "empty config"
 * sentinel, but Caddy's admin API serves an ETag for every config (including
 * an empty one), so the sentinel was unreachable and no re-push ever happened
 * after the l4-port-manager recreated the caddy container. Detection is now
 * content-based (live config hash vs the hash recorded after the last
 * successful apply); these tests pin that behaviour from the outside.
 */
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { caddyAdminGet } from '../../helpers/live-caddy';
import { createHash } from 'node:crypto';
import { createProxyHost } from '../../helpers/proxy-api';

const CADDY = 'ingressi-caddy';
const WEB = 'ingressi-web';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Fetch Caddy's live admin config from inside the caddy container; null if unreachable. */
function fetchLiveConfig(): string | null {
  try {
    return caddyAdminGet('/config/');
  } catch {
    return null;
  }
}

function hashOf(config: string | null): string | null {
  return config === null ? null : createHash('sha256').update(config).digest('hex');
}

/** Web container log lines mentioning the monitor, since the given instant. */
function monitorLogsSince(since: Date): string {
  const logs = execFileSync(
    'docker',
    ['logs', '--since', since.toISOString(), WEB],
    { encoding: 'utf-8', maxBuffer: 32 * 1024 * 1024 },
  );
  return logs
    .split('\n')
    .filter((line) => line.includes('CaddyMonitor'))
    .join('\n');
}

test.describe.serial('CaddyMonitor drift recovery', () => {
  let baselineConfig: string;

  test('setup: seed a proxy host so the applied config differs from the image default', async ({ page }) => {
    await createProxyHost(page, {
      name: 'Caddy Monitor Test',
      domain: 'caddy-monitor.test',
      upstream: 'echo-server:8080',
    });

    // Snapshot the applied configuration once the new route is live. This is
    // the baseline the monitor must be able to restore. Seeding guarantees
    // the baseline differs from the image's default Caddyfile even on a
    // completely fresh database.
    for (let i = 0; i < 20; i++) {
      const config = fetchLiveConfig();
      if (config !== null && config.includes('caddy-monitor.test')) {
        baselineConfig = config;
        break;
      }
      await sleep(1_000);
    }
    expect(baselineConfig, 'seeded proxy host never appeared in the live caddy config').toBeTruthy();
    expect(baselineConfig).toContain('caddy-monitor.test');
  });

  test('reapplies the applied config after caddy restarts without usable autosave', async () => {
    test.setTimeout(150_000);

    // Delete the autosave so `caddy --resume` cannot restore the applied
    // config on boot — the container must come back with the image's default
    // Caddyfile, exactly like a recreated container with a wiped config volume.
    execFileSync('docker', ['exec', CADDY, 'rm', '-f', '/config/caddy/autosave.json']);
    const restartedAt = new Date();
    execFileSync('docker', ['restart', CADDY]);

    // Caddy comes back serving something other than the applied config.
    let firstConfig: string | null = null;
    for (let i = 0; i < 60; i++) {
      firstConfig = fetchLiveConfig();
      if (firstConfig !== null) break;
      await sleep(500);
    }
    expect(firstConfig, 'caddy admin API did not come back within 30s of the restart').not.toBeNull();
    expect(
      firstConfig,
      'caddy resumed the applied config despite the deleted autosave — test would be vacuous',
    ).not.toBe(baselineConfig);

    // The monitor must notice the drift and re-push the applied config.
    let restored = false;
    for (let i = 0; i < 75; i++) {
      if (fetchLiveConfig() === baselineConfig) {
        restored = true;
        break;
      }
      await sleep(1_000);
    }
    expect(
      restored,
      'CaddyMonitor did not restore the applied config within 75s of the restart — drift detection is broken (see src/lib/caddy-monitor.ts)',
    ).toBe(true);

    // It must then stay stable: no reapply loop.
    await sleep(12_000);
    expect(fetchLiveConfig()).toBe(baselineConfig);
    const detections = monitorLogsSince(restartedAt).match(/drift detected/g)?.length ?? 0;
    expect(detections, 'CaddyMonitor detected drift repeatedly — possible reapply loop').toBeLessThanOrEqual(2);
  });

  test('does not reapply when caddy resumes the identical config after restart', async () => {
    test.setTimeout(120_000);

    // After the previous test the live config is the applied one and the
    // autosave holds the same content, so a restart must resume it untouched.
    expect(hashOf(fetchLiveConfig())).toBe(hashOf(baselineConfig));

    const restartedAt = new Date();
    execFileSync('docker', ['restart', CADDY]);

    let config: string | null = null;
    for (let i = 0; i < 60; i++) {
      config = fetchLiveConfig();
      if (config !== null) break;
      await sleep(500);
    }
    expect(config, 'caddy admin API did not come back within 30s of the restart').not.toBeNull();
    expect(config, 'caddy did not resume the identical config — autosave is not working').toBe(baselineConfig);

    // Observe a few monitor ticks: no drift, no reapply, config untouched.
    await sleep(25_000);
    expect(fetchLiveConfig()).toBe(baselineConfig);
    const logs = monitorLogsSince(restartedAt);
    expect(
      logs,
      'CaddyMonitor triggered a reapply even though caddy resumed the identical config — false positive',
    ).not.toContain('drift detected');
  });
});
