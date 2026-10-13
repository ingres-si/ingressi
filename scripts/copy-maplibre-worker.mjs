/**
 * Copy maplibre-gl's tile worker (and everything it imports) into
 * `public/maplibre/` so the browser can load it from a stable, self-hosted URL.
 *
 * Why this exists
 * ---------------
 * maplibre-gl v6 stopped inlining its worker as a blob and now resolves a
 * separate `maplibre-gl-worker.mjs` at runtime from `import.meta.url`. That
 * lookup does not survive Turbopack bundling:
 *
 *   - `next dev`   → resolves to the page URL, so the HTML page is loaded as a
 *                    worker and the map renders as an empty ocean.
 *   - `next build` → resolves to the wrong dist file (the main bundle).
 *
 * Pointing maplibre at a bundler-emitted asset does not work either: up to
 * maplibre-gl 6.12 the worker is an ES module that imports
 * `./maplibre-gl-shared.mjs`, and Turbopack emits each dist file under a
 * different content-hashed name without rewriting those relative imports, so
 * the sibling import 404s. From 6.13 the worker is self-contained.
 *
 * Copying the worker's whole module graph verbatim keeps the relative imports
 * resolvable, whichever way a release splits it. `WorldMapInner.tsx` then calls
 * `setWorkerUrl()` with this path.
 *
 * Runs from next.config.mjs so it covers `next dev`, `next build` and the Docker
 * build alike, under both Node and Bun, with no extra lifecycle script wiring.
 */
import { createRequire } from 'node:module';
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const require = createRequire(import.meta.url);

export const PUBLIC_DIR = 'maplibre';
export const WORKER_ENTRY = 'maplibre-gl-worker.mjs';
/** URL the browser loads the worker from — keep in sync with WorldMapInner.tsx. */
export const WORKER_PUBLIC_PATH = `/${PUBLIC_DIR}/${WORKER_ENTRY}`;

/**
 * Relative specifiers of `from './x'`, `import './x'` and `import('./x')`, so we
 * follow the worker's chunk graph. maplibre's dist is minified, so whitespace is
 * routinely absent — up to 6.12 the worker entry opens with `}from"./maplibre-gl-shared.mjs"`.
 */
function relativeImports(source) {
  const specifiers = new Set();
  const re = /\b(?:from|import)\s*\(?\s*['"](\.[^'"]*)['"]/g;
  let match;
  while ((match = re.exec(source)) !== null) specifiers.add(match[1]);
  return specifiers;
}

/**
 * @param {string} projectRoot absolute path to the repo root
 * @returns {string[]} names of the files that were copied
 */
export function copyMaplibreWorker(projectRoot) {
  const distDir = dirname(require.resolve('maplibre-gl/dist/maplibre-gl-worker.mjs'));
  const outDir = resolve(projectRoot, 'public', PUBLIC_DIR);
  mkdirSync(outDir, { recursive: true });

  const copied = [];
  const queue = [WORKER_ENTRY];
  const seen = new Set(queue);

  while (queue.length > 0) {
    const name = queue.shift();
    const from = join(distDir, name);
    const to = join(outDir, name);

    if (!existsSync(from)) {
      throw new Error(
        `maplibre-gl worker chunk "${name}" is missing from ${distDir}; ` +
          'scripts/copy-maplibre-worker.mjs needs updating for this maplibre-gl version.',
      );
    }

    // Compare content, not size: maplibre-gl 6.4.1 and 6.6.0 ship worker files
    // of identical size but different content, so a size-based check kept a
    // stale 6.4.1 worker next to a freshly upgraded 6.6.0 shared chunk. The
    // mismatched pair crashes the worker with "Class constructor ... cannot be
    // invoked without 'new'" and renders the map as empty ocean.
    const source = readFileSync(from);
    let upToDate;
    try {
      upToDate = source.equals(readFileSync(to));
    } catch {
      upToDate = false; // not staged yet
    }
    if (!upToDate) {
      copyFileSync(from, to);
      copied.push(name);
    }

    for (const specifier of relativeImports(source.toString('utf8'))) {
      const dep = specifier.replace(/^\.\//, '');
      if (dep.includes('/')) {
        throw new Error(
          `maplibre-gl worker imports "${specifier}" from a subdirectory; ` +
            'scripts/copy-maplibre-worker.mjs needs updating.',
        );
      }
      if (!seen.has(dep)) {
        seen.add(dep);
        queue.push(dep);
      }
    }
  }

  return copied;
}
