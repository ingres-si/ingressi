/**
 * Unit tests for the L4 port manager sidecar entrypoint script.
 *
 * Tests critical invariants of the shell script:
 * - Always applies the override on startup (not just on trigger change)
 * - Only recreates the caddy service (never other services)
 * - Uses --no-deps to prevent dependency cascades
 * - Auto-detects compose project name from caddy container labels
 * - Pre-loads LAST_TRIGGER to avoid double-applying on startup
 * - Writes status files in valid JSON
 * - Never includes test override files in production
 * - Supports both named-volume and bind-mount deployments (COMPOSE_HOST_DIR)
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const SCRIPT_PATH = resolve(__dirname, '../../docker/l4-port-manager/entrypoint.sh');
const script = readFileSync(SCRIPT_PATH, 'utf-8');
const lines = script.split('\n');

describe('L4 port manager entrypoint.sh', () => {
  it('applies override on startup (not only on trigger change)', () => {
    // The script must call do_apply before entering the while loop.
    // This ensures L4 ports are bound after any restart, because the main
    // compose stack starts caddy without the L4 ports override file.
    const firstApply = lines.findIndex(l => l.trim().startsWith('do_apply') || l.includes('do_apply'));
    const whileLoop = lines.findIndex(l => l.includes('while true'));
    expect(firstApply).toBeGreaterThan(-1);
    expect(whileLoop).toBeGreaterThan(-1);
    expect(firstApply).toBeLessThan(whileLoop);
  });

  it('pre-loads LAST_TRIGGER before the startup apply: no double-apply, and no trigger lost', () => {
    // LAST_TRIGGER is the trigger as it was before the startup apply, so the poll
    // loop doesn't re-apply it, and does apply one written while that apply ran.
    const lastTriggerInit = lines.findIndex(l => l.includes('LAST_TRIGGER=') && l.includes('TRIGGER_FILE'));
    const startupApply = lines.findIndex(l => l.includes('Startup: applying existing L4 port override'));
    const whileLoop = lines.findIndex(l => l.includes('while true'));
    expect(lastTriggerInit).toBeGreaterThan(-1);
    expect(startupApply).toBeGreaterThan(-1);
    expect(lastTriggerInit).toBeLessThan(startupApply);
    expect(lastTriggerInit).toBeLessThan(whileLoop);
  });

  it('deletes only the trigger an apply answered', () => {
    // An unconditional rm would delete a trigger written while the apply ran.
    expect(script).toContain('APPLY_TRIGGER=$(cat "$TRIGGER_FILE"');
    expect(script).not.toMatch(/rm -f "\$TRIGGER_FILE"\s*$/m);
    expect(script).toContain('if [ -n "$APPLY_TRIGGER" ] && mv "$TRIGGER_FILE" "$TRIGGER_FILE.done" 2>/dev/null; then');
    expect(script).toContain('mv "$TRIGGER_FILE.done" "$TRIGGER_FILE"');
  });

  it('only recreates the caddy service', () => {
    // The docker compose command should target only "caddy" — never "web" or other services
    const composeUpLines = lines.filter(line =>
      line.includes('docker compose') && line.includes('up')
    );
    expect(composeUpLines.length).toBeGreaterThan(0);
    for (const line of composeUpLines) {
      expect(line).toContain('caddy');
      expect(line).not.toMatch(/\bweb\b/);
    }
  });

  it('uses --no-deps flag to prevent dependency cascades', () => {
    const composeUpLines = lines.filter(line =>
      line.includes('docker compose') && line.includes('up')
    );
    for (const line of composeUpLines) {
      expect(line).toContain('--no-deps');
    }
  });

  it('uses --force-recreate to ensure port changes take effect', () => {
    const composeUpLines = lines.filter(line =>
      line.includes('docker compose') && line.includes('up')
    );
    for (const line of composeUpLines) {
      expect(line).toContain('--force-recreate');
    }
  });

  it('specifies project name to target the correct compose stack', () => {
    // Without -p, compose would infer the project from the mount directory name
    // ("/compose") rather than the actual running stack name, causing it to
    // create new containers instead of recreating the existing ones.
    expect(script).toMatch(/COMPOSE_ARGS=.*-p \$COMPOSE_PROJECT/);
  });

  it('auto-detects project name from caddy container labels', () => {
    expect(script).toContain('com.docker.compose.project');
    expect(script).toContain('docker inspect');
    expect(script).toContain('detect_project_name');
  });

  it('compares trigger content to avoid redundant restarts', () => {
    expect(script).toContain('LAST_TRIGGER');
    expect(script).toContain('CURRENT_TRIGGER');
    expect(script).toContain('"$CURRENT_TRIGGER" = "$LAST_TRIGGER"');
  });

  it('uses --pull never to avoid registry pulls (only recreates)', () => {
    const composeUpLines = lines.filter(line =>
      line.includes('docker compose') && line.includes('up')
    );
    for (const line of composeUpLines) {
      expect(line).toContain('--pull never');
      expect(line).not.toContain('--build');
    }
  });

  it('waits for caddy health check after recreation', () => {
    expect(script).toContain('Health');
    expect(script).toContain('healthy');
    expect(script).toContain('HEALTH_TIMEOUT');
  });

  it('writes status for both success and failure cases', () => {
    const statusWrites = lines.filter(l => l.trim().startsWith('write_status'));
    // At least: startup idle/applying, applying, applied/success, failed
    expect(statusWrites.length).toBeGreaterThanOrEqual(4);
  });

  // ---------------------------------------------------------------------------
  // Regression (production incident 2026-09-13): a failed `docker compose up`
  // aborted the script under `set -e` before the failure was logged, before a
  // "failed" status was written, and before the apply lock was removed. The
  // stale lock then made every startup skip the port restore — caddy came back
  // without the L4 ports and LiveKit media traffic silently broke.
  // ---------------------------------------------------------------------------

  it('captures the compose exit status in a way that survives `set -e` (no bare assignment + dead $?)', () => {
    // The broken pattern:
    //   COMPOSE_OUTPUT=$(docker compose ... 2>&1)
    //   COMPOSE_EXIT=$?          <- never runs; set -e aborts on failure first
    // There must be no assignment of a docker compose invocation to a variable
    // that is not inside an if/&&/|| condition.
    const bareAssignment = lines.filter(
      l => /\w+\s*=\s*\$\(docker compose/.test(l)
        && !l.trim().startsWith('#')
        // capture inside an if condition is safe — set -e does not abort there
        && !l.trim().startsWith('if ')
    );
    expect(bareAssignment, 'docker compose output must be captured inside an if condition').toHaveLength(0);
  });

  it('does not capture $? after a negated if (inverted-status gotcha)', () => {
    // `if ! cmd; then VAR=$?; fi` captures the *inverted* status (0 on failure).
    const negatedIfWithDollarQ = lines.filter(
      l => l.trim().startsWith('if ! ') && l.includes('$(')
    );
    for (const line of negatedIfWithDollarQ) {
      const lineIdx = lines.indexOf(line);
      const body = lines.slice(lineIdx, lineIdx + 5).join('\n');
      expect(body).not.toMatch(/\$\?/);
    }
  });

  it('removes the apply lock via a trap so a crashed apply cannot block future startups', () => {
    expect(script).toMatch(/trap .*rm -f "\$APPLY_LOCK"/);
    // and the lock must be cleared explicitly after do_apply completes too
    expect(script).toMatch(/rm -f "\$APPLY_LOCK"/);
  });

  it('startup waits for a fresh apply lock instead of skipping permanently', () => {
    // The old guard skipped the restore whenever the lock was <10s old, which
    // permanently suppressed port restoration after a crashed apply.
    // The fix: wait for the lock to clear (bounded), then apply unconditionally.
    expect(script).toMatch(/APPLY_LOCK_MAX_AGE/);
    expect(script).toContain('taking over and re-applying');
    // The skip must no longer exist as a permanent path
    expect(script).not.toContain('already in progress, skipping');
  });

  it('does not include test override files in production', () => {
    // Including docker-compose.test.yml would override web env vars (triggering
    // web restart) and switch to test volume names.
    expect(script).not.toContain('docker-compose.test.yml');
  });

  it('does not restart the web service or itself', () => {
    const dangerousPatterns = [
      /up.*\bweb\b/,
      /restart.*\bweb\b/,
      /up.*\bl4-port-manager\b/,
      /restart.*\bl4-port-manager\b/,
    ];
    for (const pattern of dangerousPatterns) {
      expect(script).not.toMatch(pattern);
    }
  });

  // ---------------------------------------------------------------------------
  // Deployment scenario: COMPOSE_HOST_DIR (bind-mount / cloud override)
  // ---------------------------------------------------------------------------

  it('uses --project-directory $COMPOSE_HOST_DIR when COMPOSE_HOST_DIR is set', () => {
    // Bind-mount deployments (docker-compose.override.yml replaces named volumes
    // with ./data bind mounts). Relative paths like ./geoip-data in the override
    // file must resolve against the HOST project directory, not the sidecar's
    // /compose mount. --project-directory tells the Docker daemon where to look.
    expect(script).toContain('--project-directory $COMPOSE_HOST_DIR');
    // It must be conditional — only applied when COMPOSE_HOST_DIR is non-empty
    expect(script).toMatch(/if \[ -n "\$COMPOSE_HOST_DIR" \]/);
  });

  it('does NOT unconditionally add --project-directory (named-volume deployments work without it)', () => {
    // Standard deployments (no override file) use named volumes — no host path
    // is needed. --project-directory must NOT be hardcoded outside the conditional.
    const unconditional = lines.filter(l =>
      l.includes('--project-directory') && !l.includes('COMPOSE_HOST_DIR') && !l.trim().startsWith('#')
    );
    expect(unconditional).toHaveLength(0);
  });

  it('uses --env-file from $COMPOSE_DIR (container-accessible path), not $COMPOSE_HOST_DIR', () => {
    // When --project-directory points to the host path, Docker Compose looks for
    // .env at $COMPOSE_HOST_DIR/.env which is NOT mounted inside the container.
    // We must explicitly pass --env-file $COMPOSE_DIR/.env (the container mount).
    expect(script).toContain('--env-file $COMPOSE_DIR/.env');
    // Must NOT reference the host dir for the env file
    expect(script).not.toContain('--env-file $COMPOSE_HOST_DIR');
  });

  it('always reads compose files from $COMPOSE_DIR regardless of COMPOSE_HOST_DIR', () => {
    // The sidecar mounts the project at /compose (COMPOSE_DIR). Whether or not
    // COMPOSE_HOST_DIR is set, all -f flags must reference container-accessible
    // paths under $COMPOSE_DIR, never the host path.
    const composeFileFlags = lines.filter(l =>
      l.includes('-f ') && l.includes('docker-compose')
    );
    expect(composeFileFlags.length).toBeGreaterThan(0);
    for (const line of composeFileFlags) {
      expect(line).toContain('$COMPOSE_DIR');
      expect(line).not.toContain('$COMPOSE_HOST_DIR');
    }
  });
});
