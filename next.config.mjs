import { createRequire } from 'module';
import { execSync } from 'node:child_process';
import { copyMaplibreWorker } from './scripts/copy-maplibre-worker.mjs';

// Application version shown in the web UI and OpenAPI spec (issue #259).
// Resolution order:
//   1. APP_VERSION build arg -- set by CI to a release git tag (e.g. 1.2.3)
//      for tagged releases.
//   2. The git commit SHA -- used for non-release builds (branch/PR/dev) so the
//      UI shows an identifiable build reference instead of a stale
//      package.json placeholder like 1.0.0.
//   3. The version declared in package.json.
//   4. 'unknown'.
const require = createRequire(import.meta.url);
const { version: pkgVersion } = require('./package.json');

function getGitCommit() {
  try {
    const sha = execSync('git rev-parse --short HEAD', {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    }).trim();
    return sha || null;
  } catch {
    // Not a git checkout (e.g. Docker build context excludes .git).
    return null;
  }
}

function resolveAppVersion() {
  const fromArg = String(process.env.APP_VERSION || '').trim().replace(/^v/, '');
  if (fromArg) return fromArg;
  const commit = getGitCommit();
  if (commit) return commit;
  return pkgVersion || 'unknown';
}

const APP_VERSION = resolveAppVersion();

// When building under Node.js (not Bun), redirect bun:sqlite to a better-sqlite3 shim
// so `next build` works locally without Bun installed.
const isBun = typeof globalThis.Bun !== 'undefined';

// maplibre-gl v6 loads its tile worker from a separate file that Turbopack cannot
// resolve correctly; stage it under public/ so it is served from a stable URL.
// See scripts/copy-maplibre-worker.mjs for the full explanation.
copyMaplibreWorker(import.meta.dirname);

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Inlined into client and server bundles at build time; referenced via
  // src/lib/app-version.ts. Values in the `env` key do not need a
  // NEXT_PUBLIC_ prefix to be inlined, but the prefix keeps intent explicit.
  env: {
    NEXT_PUBLIC_APP_VERSION: APP_VERSION,
  },
  // pg (PostgreSQL, src/lib/db/postgres.ts) is loaded from node_modules at
  // run time rather than bundled, like the SQLite drivers.
  serverExternalPackages: isBun ? ['bun:sqlite', 'pg'] : ['better-sqlite3', 'pg'],
  ...(!isBun && {
    turbopack: {
      resolveAlias: {
        'bun:sqlite': './tests/helpers/bun-sqlite-compat.ts',
        'drizzle-orm/bun-sqlite/migrator': 'drizzle-orm/better-sqlite3/migrator',
        'drizzle-orm/bun-sqlite': 'drizzle-orm/better-sqlite3',
      },
    },
  }),
  experimental: {
    serverActions: {
      bodySizeLimit: '2mb'
    }
  },
  output: 'standalone',
  poweredByHeader: false,
  // The proxy host form became a page: the old deep links /proxy-hosts?create=1
  // (with an optional &domain=, which is passed along) and ?edit=<id> (at
  // Routing, where the form started) open it.
  async redirects() {
    return [
      {
        source: '/proxy-hosts',
        has: [{ type: 'query', key: 'create', value: '1' }],
        destination: '/proxy-hosts/new',
        permanent: false,
      },
      {
        source: '/proxy-hosts',
        has: [{ type: 'query', key: 'edit', value: '(?<id>\\d{1,15})' }],
        destination: '/proxy-hosts/:id/edit?section=routing',
        permanent: false,
      },
    ];
  },
  // The MCP endpoints' discovery documents live at fixed well-known URIs
  // (RFC 8414 and RFC 9728). Serving them through rewrites keeps the App
  // Router's route list free of dot-directories; the handlers are under
  // app/api/oauth/well-known/.
  async rewrites() {
    return [
      {
        source: '/.well-known/oauth-protected-resource',
        destination: '/api/oauth/well-known/protected-resource',
      },
      {
        // The path-specific form for the MCP endpoint (RFC 9728 §3.1).
        source: '/.well-known/oauth-protected-resource/api/mcp',
        destination: '/api/oauth/well-known/protected-resource',
      },
      {
        source: '/.well-known/oauth-authorization-server',
        destination: '/api/oauth/well-known/authorization-server',
      },
    ];
  },
  // Security headers (CSP, etc.) are set per-request in proxy.ts middleware
  // with a unique nonce, so they are NOT defined here as static headers.
};

export default nextConfig;
