import { describe, it, expect, beforeAll } from 'vitest';
import { createRequire } from 'node:module';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import {
  copyMaplibreWorker,
  WORKER_PUBLIC_PATH,
} from '../../scripts/copy-maplibre-worker.mjs';
import { buildCsp } from '@/src/lib/csp';

/**
 * maplibre-gl v6 loads its tile worker from a separate ES module that Turbopack
 * cannot resolve at runtime, so the worker (and everything it imports) is staged
 * into public/maplibre/ at build time and pointed at explicitly via
 * setWorkerUrl(). These tests fail loudly if a maplibre-gl upgrade renames or
 * re-splits those chunks, which would otherwise only surface as a blank map.
 */

const require = createRequire(import.meta.url);
const projectRoot = resolve(__dirname, '../..');
const distDir = dirname(require.resolve('maplibre-gl/dist/maplibre-gl-worker.mjs'));
const stagedDir = join(projectRoot, 'public', 'maplibre');

describe('maplibre worker staging', () => {
  beforeAll(() => {
    // Stage from scratch so the test covers a clean build, not a stale copy.
    rmSync(stagedDir, { recursive: true, force: true });
    copyMaplibreWorker(projectRoot);
  });

  it('stages the worker entry the client asks for', () => {
    expect(WORKER_PUBLIC_PATH).toBe('/maplibre/maplibre-gl-worker.mjs');
    expect(readFileSync(join(stagedDir, 'maplibre-gl-worker.mjs'))).toEqual(
      readFileSync(join(distDir, 'maplibre-gl-worker.mjs')),
    );
  });

  it('stages every relative import the worker pulls in', () => {
    const worker = readFileSync(join(distDir, 'maplibre-gl-worker.mjs'), 'utf8');
    const deps = [...worker.matchAll(/\b(?:from|import)\s*\(?\s*['"]\.\/([^'"]+)['"]/g)].map(
      (m) => m[1],
    );

    // Guards against the import regex silently matching nothing: every other
    // dist module the worker names must be among the imports followed. Up to
    // maplibre-gl 6.12 that is maplibre-gl-shared.mjs; from 6.13 the worker is
    // self-contained and names none.
    const named = readdirSync(distDir).filter(
      (name) => name.endsWith('.mjs') && name !== 'maplibre-gl-worker.mjs' && worker.includes(name),
    );
    expect(deps).toEqual(expect.arrayContaining(named));

    for (const dep of new Set(deps)) {
      expect(
        readFileSync(join(stagedDir, dep)),
        `${dep} is imported by the worker but was not staged into public/maplibre/`,
      ).toEqual(readFileSync(join(distDir, dep)));
    }
  });

  it('is idempotent — a second run copies nothing', () => {
    expect(copyMaplibreWorker(projectRoot)).toEqual([]);
  });

  it('overwrites a staged file whose content differs but size matches', () => {
    // Regression: maplibre-gl 6.4.1 and 6.6.0 ship worker files of identical
    // byte size with different content. A size-based freshness check kept the
    // stale 6.4.1 worker next to a freshly staged 6.6.0 shared chunk — the
    // mismatched pair crashed the worker at runtime ("Class constructor ...
    // cannot be invoked without 'new'") and the map rendered as empty ocean.
    const stagedWorker = join(stagedDir, 'maplibre-gl-worker.mjs');
    const distWorker = readFileSync(join(distDir, 'maplibre-gl-worker.mjs'));
    const tampered = Buffer.from(distWorker);
    tampered[tampered.length >> 1] ^= 0xff; // flip one byte, keep the size
    expect(tampered.length).toBe(distWorker.length);
    writeFileSync(stagedWorker, tampered);

    expect(copyMaplibreWorker(projectRoot)).toContain('maplibre-gl-worker.mjs');
    expect(readFileSync(stagedWorker)).toEqual(distWorker);
  });

  it('WorldMapInner points maplibre at the staged worker', () => {
    const source = readFileSync(
      join(projectRoot, 'app', '(dashboard)', 'analytics', 'WorldMapInner.tsx'),
      'utf8',
    );
    expect(source).toContain(`setWorkerUrl('${WORKER_PUBLIC_PATH}')`);
  });

  it("CSP allows loading the worker from 'self'", () => {
    const workerSrc = buildCsp('map-worker-test')
      .split(';')
      .map((directive) => directive.trim())
      .find((directive) => directive.startsWith('worker-src '));
    expect(workerSrc).toContain("'self'");
  });
});
