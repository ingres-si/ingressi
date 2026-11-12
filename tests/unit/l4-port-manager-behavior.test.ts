/**
 * Behavioral tests for the L4 port manager sidecar entrypoint script.
 *
 * These EXECUTE docker/l4-port-manager/entrypoint.sh against a fake `docker`
 * binary. The static analysis in l4-port-manager-entrypoint.test.ts checks
 * that the script *contains* the right commands; these tests check that the
 * script *behaves* correctly when docker compose fails — the exact production
 * incident (2026-09-13) where a failed compose call aborted the script under
 * `set -e`, leaving a stale .l4-apply.lock whose freshness guard made every
 * subsequent startup skip the port restore. Caddy then came back up without
 * the L4 ports bound and LiveKit media traffic silently broke.
 *
 * Invariants covered here:
 * 1. A failed `docker compose up` must NOT kill the script — the poll loop
 *    must survive and a later trigger must still be processed.
 * 2. A failed apply must write status state "failed" (with error) — never
 *    leave "applying" stuck forever.
 * 3. A failed apply must NOT leave the .l4-apply.lock behind.
 * 4. A stale apply lock at startup must be taken over (re-applied), not
 *    skipped — a crashed apply must never permanently suppress the restore.
 * 5. A fresh apply lock at startup waits for the in-progress apply, then
 *    re-applies if the lock never clears.
 * 6. A successful apply writes status "applied".
 * 7. At startup, a caddy container that already runs with every port of the
 *    override is not recreated (an update of the sidecar alone must not restart
 *    caddy, and must not race an image updater that is recreating it); one that
 *    lacks a port is.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const SCRIPT_PATH = resolve(join(__dirname, '../../docker/l4-port-manager/entrypoint.sh'));

let workDir: string;
let dataDir: string;
let composeDir: string;
let fakeBinDir: string;
let fakeDockerLogPath: string;
let child: ChildProcess | null = null;
let output = '';

function setupEnv(): void {
  workDir = mkdtempSync(join(tmpdir(), 'l4-sidecar-test-'));
  dataDir = join(workDir, 'data');
  composeDir = join(workDir, 'compose');
  fakeBinDir = join(workDir, 'bin');
  fakeDockerLogPath = join(workDir, 'docker.log');
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(composeDir, { recursive: true });
  mkdirSync(fakeBinDir, { recursive: true });
  writeFileSync(join(composeDir, 'docker-compose.yml'), 'services: {}\n');
  writeFileSync(
    join(dataDir, 'docker-compose.l4-ports.yml'),
    'services:\n  caddy:\n    ports: ["1234:1234"]\n',
  );
  writeFileSync(fakeDockerLogPath, '');
}

/**
 * Write a fake `docker` binary. `compose up` exits with composeUpExit;
 * project-label inspection returns a fixed project name; health checks
 * ("inspect") report healthy.
 */
function writeFakeDocker(composeUpExit: number, composeUpSeconds = 0.2): void {
  writeFileSync(
    join(fakeBinDir, 'docker'),
    `#!/bin/sh
echo "$@" >> "${fakeDockerLogPath}"
if echo "$@" | grep -q -- "--force-recreate caddy"; then
  sleep ${composeUpSeconds}
  exit ${composeUpExit}
fi
if echo "$@" | grep -q "compose.project"; then
  echo "fake-project"
  exit 0
fi
if echo "$@" | grep -q "inspect"; then
  echo "healthy"
  exit 0
fi
exit 0
`,
    { mode: 0o755 },
  );
}

/** A fake `docker` whose caddy container runs and publishes `bindings` (e.g. "1234/tcp 80/tcp"). */
function writeFakeDockerRunning(bindings: string): void {
  writeFileSync(
    join(fakeBinDir, 'docker'),
    `#!/bin/sh
echo "$@" >> "${fakeDockerLogPath}"
if echo "$@" | grep -q -- "--force-recreate caddy"; then
  sleep 0.2
  exit 0
fi
if echo "$@" | grep -q "compose.project"; then
  echo "fake-project"
  exit 0
fi
if echo "$@" | grep -q "State.Running"; then
  echo "true"
  exit 0
fi
if echo "$@" | grep -q "PortBindings"; then
  echo "${bindings} "
  exit 0
fi
if echo "$@" | grep -q "inspect"; then
  echo "healthy"
  exit 0
fi
exit 0
`,
    { mode: 0o755 },
  );
}

/**
 * A fake `docker` where no container has CADDY_CONTAINER_NAME: the caddy service of the
 * sidecar's compose project is "custom-caddy" (an override's container_name), running with `bindings`.
 */
function writeFakeDockerCaddyByLabel(bindings: string): void {
  writeFileSync(
    join(fakeBinDir, 'docker'),
    `#!/bin/sh
echo "$@" >> "${fakeDockerLogPath}"
if echo "$@" | grep -q -- "--force-recreate caddy"; then
  sleep 0.2
  exit 0
fi
if echo "$@" | grep -q -- "fake-caddy"; then
  exit 1
fi
if [ "$1" = "ps" ]; then
  echo "$@" | grep -q "com.docker.compose.service=caddy" && echo "custom-caddy"
  exit 0
fi
if echo "$@" | grep -q "compose.project"; then
  echo "fake-project"
  exit 0
fi
if echo "$@" | grep -q "State.Running"; then
  echo "$@" | grep -q "custom-caddy" && echo "true"
  exit 0
fi
if echo "$@" | grep -q "PortBindings"; then
  echo "${bindings} "
  exit 0
fi
if echo "$@" | grep -q "inspect"; then
  echo "healthy"
  exit 0
fi
exit 0
`,
    { mode: 0o755 },
  );
}

function fakeDockerLog(): string[] {
  return readFileSync(fakeDockerLogPath, 'utf-8')
    .split('\n')
    .filter(Boolean);
}

function composeUpInvocations(): number {
  return fakeDockerLog().filter((l) => l.includes(' --force-recreate caddy')).length;
}

function statusFilePath(): string {
  return join(dataDir, 'l4-ports.status');
}

function readStatus(): { state: string; message?: string; error?: string; appliedAt?: string } | null {
  if (!existsSync(statusFilePath())) return null;
  try {
    return JSON.parse(readFileSync(statusFilePath(), 'utf-8'));
  } catch {
    return null;
  }
}

function startSidecar(): ChildProcess {
  return spawn('/bin/sh', [SCRIPT_PATH], {
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      COMPOSE_DIR: composeDir,
      CADDY_CONTAINER_NAME: 'fake-caddy',
      POLL_INTERVAL: '1',
      COMPOSE_SKIP_OVERRIDE: '1',
      APPLY_LOCK_MAX_AGE: '2',
      // The fake docker never reports a running caddy unless a test says so: don't wait for it.
      CADDY_STARTUP_WAIT: '0',
      PATH: `${fakeBinDir}:${process.env.PATH}`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function captureOutput(): void {
  child!.stdout?.on('data', (d) => (output += String(d)));
  child!.stderr?.on('data', (d) => (output += String(d)));
}

function triggerApply(): void {
  writeFileSync(
    join(dataDir, 'l4-ports.trigger'),
    JSON.stringify({ triggeredAt: new Date().toISOString(), hash: String(Date.now()), ports: ['1234:1234'] }),
  );
}

async function waitUntil(fn: () => boolean, timeoutMs = 10_000, intervalMs = 100): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`condition not met within ${timeoutMs}ms. Output so far:\n${output}`);
}

function killChild(): void {
  if (child) {
    child.kill('SIGKILL');
    child = null;
  }
}

describe('L4 port manager entrypoint behavior (executes the real script)', () => {
  beforeEach(() => {
    setupEnv();
    output = '';
  });

  afterEach(() => {
    killChild();
  });

  it('survives a failed compose up: writes "failed" status, keeps the poll loop alive, and processes later triggers', { timeout: 20_000 }, async () => {
    writeFakeDocker(1); // compose up always fails

    child = startSidecar();
    captureOutput();

    // Startup apply fails — status must become "failed" (not stuck "applying")
    await waitUntil(() => readStatus()?.state === 'failed', 10_000);
    expect(readStatus()?.state).toBe('failed');
    expect(readStatus()?.error).toBeTruthy();

    // The apply lock must be cleared after the failed apply (happens right
    // after the "failed" status is written, so poll for it)
    await waitUntil(() => !existsSync(join(dataDir, '.l4-apply.lock')), 10_000);

    // The script must still be alive (poll loop survived the failure)
    await new Promise((r) => setTimeout(r, 1500));
    expect(child?.exitCode).toBeNull();
    expect(child?.signalCode).toBeNull();

    // A later trigger change must still be processed
    const before = composeUpInvocations();
    triggerApply();
    await waitUntil(() => composeUpInvocations() > before, 10_000);
  });

  it('removes the apply lock after a failed apply so the next startup can restore ports', { timeout: 20_000 }, async () => {
    writeFakeDocker(1);
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'failed', 10_000);
    await waitUntil(() => !existsSync(join(dataDir, '.l4-apply.lock')), 10_000);
  });

  it('takes over a STALE apply lock at startup and re-applies (the production bug)', { timeout: 20_000 }, async () => {
    // Simulate a crashed apply: lock file left behind, written an hour ago.
    writeFakeDocker(0);
    writeFileSync(join(dataDir, '.l4-apply.lock'), String(Math.floor(Date.now() / 1000) - 3600));
    const old = new Date(Date.now() - 3_600_000);
    utimesSync(join(dataDir, '.l4-apply.lock'), old, old);

    child = startSidecar();
    captureOutput();

    // The script must NOT skip — it must run the apply and succeed.
    await waitUntil(() => composeUpInvocations() >= 1, 10_000);
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
    expect(output).toContain('taking over and re-applying');
  });

  it('waits out a FRESH apply lock, then applies anyway (never skips permanently)', async () => {
    writeFakeDocker(0);
    // Lock written "just now" — simulates an in-progress apply
    writeFileSync(join(dataDir, '.l4-apply.lock'), String(Math.floor(Date.now() / 1000)));

    child = startSidecar();
    captureOutput();

    await waitUntil(() => composeUpInvocations() >= 1, 15_000);
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
    expect(output).toContain('recent apply lock found');
    // The script writes the "applied" status before it removes the lock, so
    // wait for the removal instead of asserting the instant "applied" appears.
    await waitUntil(() => !existsSync(join(dataDir, '.l4-apply.lock')), 5_000);
  }, 20_000);

  it('writes "applied" status when compose succeeds', { timeout: 20_000 }, async () => {
    writeFakeDocker(0);
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
    expect(readStatus()?.message).toContain('healthy');
  });

  it('re-applies when the trigger file changes after a successful startup', { timeout: 20_000 }, async () => {
    writeFakeDocker(0);
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
    const before = composeUpInvocations();

    triggerApply();
    await waitUntil(() => composeUpInvocations() > before, 10_000);
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
  });

  it('applies a trigger written while the startup apply is running', { timeout: 30_000 }, async () => {
    // The override changes while compose is recreating caddy: that apply may not
    // have seen it, so the trigger must survive it and be applied by the poll loop.
    writeFakeDocker(0, 2);
    child = startSidecar();
    captureOutput();
    await waitUntil(() => composeUpInvocations() === 1, 10_000);
    triggerApply();
    await waitUntil(() => composeUpInvocations() === 2, 15_000);
    await waitUntil(() => readStatus()?.state === 'applied' && !existsSync(join(dataDir, 'l4-ports.trigger')), 10_000);
    // Applied once, and the trigger is gone: nothing left to apply again.
    await new Promise((r) => setTimeout(r, 2500));
    expect(composeUpInvocations()).toBe(2);
  });

  it('applies a trigger written while the apply of an earlier trigger is running', { timeout: 30_000 }, async () => {
    writeFakeDocker(0, 2);
    writeFileSync(join(dataDir, 'docker-compose.l4-ports.yml'), 'services: {}\n');
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'applied' && output.includes('Watching'), 15_000);
    const startup = composeUpInvocations();

    triggerApply();
    await waitUntil(() => composeUpInvocations() === startup + 1, 10_000);
    // A second, different trigger while the first is being applied.
    writeFileSync(join(dataDir, 'l4-ports.trigger'), JSON.stringify({ triggeredAt: 'later', hash: 'second', ports: ['1234:1234', '5678:5678'] }));
    await waitUntil(() => composeUpInvocations() === startup + 2, 15_000);
    await waitUntil(() => readStatus()?.state === 'applied' && !existsSync(join(dataDir, 'l4-ports.trigger')), 10_000);
    // The answered trigger is moved aside and then deleted: wait for the deletion.
    await waitUntil(() => !existsSync(join(dataDir, 'l4-ports.trigger.done')), 5_000);
  });

  it('does not re-apply the same trigger content twice', { timeout: 20_000 }, async () => {
    writeFakeDocker(0);
    writeFileSync(join(dataDir, 'l4-ports.trigger'), '{"triggeredAt":"fixed","hash":"x","ports":[]}');
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);

    // Long poll window with no trigger change: only the startup apply should run
    await new Promise((r) => setTimeout(r, 3000));
    expect(composeUpInvocations()).toBe(1);
  });
  it('does not recreate a running caddy that already publishes every L4 port', { timeout: 20_000 }, async () => {
    writeFileSync(join(dataDir, 'docker-compose.l4-ports.yml'), 'services:\n  caddy:\n    ports:\n      - "1234:1234"\n      - "5678:5678/udp"\n');
    writeFakeDockerRunning('80/tcp 1234/tcp 443/tcp 5678/udp');
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
    // The status file is written just before the log line: wait for the line.
    await waitUntil(() => output.includes('not recreating it'), 10_000);
    await new Promise((r) => setTimeout(r, 1500));
    expect(composeUpInvocations()).toBe(0);
  });

  it('recreates a running caddy that lacks an L4 port of the override', { timeout: 20_000 }, async () => {
    writeFileSync(join(dataDir, 'docker-compose.l4-ports.yml'), 'services:\n  caddy:\n    ports:\n      - "1234:1234"\n      - "5678:5678/udp"\n');
    writeFakeDockerRunning('80/tcp 1234/tcp 443/tcp');
    child = startSidecar();
    captureOutput();
    await waitUntil(() => composeUpInvocations() === 1, 10_000);
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
  });
  it('finds caddy by its compose service when an override renames the container', { timeout: 20_000 }, async () => {
    writeFileSync(join(dataDir, 'docker-compose.l4-ports.yml'), 'services:\n  caddy:\n    ports:\n      - "1234:1234"\n');
    writeFakeDockerCaddyByLabel('80/tcp 1234/tcp');
    child = startSidecar();
    captureOutput();
    await waitUntil(() => readStatus()?.state === 'applied', 10_000);
    // The status file is written just before the log line: wait for the line.
    await waitUntil(() => output.includes('not recreating it'), 10_000);
    expect(composeUpInvocations()).toBe(0);
  });
});
