/**
 * What the running Caddy serves, read from its admin API. The admin API is on
 * a unix socket (CADDY_ADMIN_SOCKET) by default, so the read goes through a
 * container that has the socket (the web container) rather than the caddy
 * container's wget, which cannot speak to a unix socket. Falls back to the TCP
 * admin port when the stack is configured that way.
 */
import { execFileSync } from 'node:child_process';

const CADDY = 'ingressi-caddy';

// Runs in the web container: GET an admin API path over the socket (or TCP) and
// print the body. The path is inlined, not passed as an argv — the web image's
// `node` is a bun shim, and `bun -e <script> <arg>` does not populate argv.
function reader(path: string): string {
  return [
    "const http=require('http');",
    "const s=process.env.CADDY_ADMIN_SOCKET;",
    `const p=${JSON.stringify(path)};`,
    "const u=new URL(process.env.CADDY_API_URL||'http://localhost:2019');",
    "const o=s?{socketPath:s,path:p,headers:{Host:'localhost'}}:{host:u.hostname,port:u.port,path:p};",
    "http.get(o,r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>process.stdout.write(d));}).on('error',e=>{process.stderr.write(''+e);process.exit(1);});",
  ].join('');
}

/**
 * GET a path from Caddy's admin API (e.g. "/config/..."), read through the web
 * container that shares the socket. Returns the raw body, or throws on failure.
 * `webContainer` selects which instance's admin to read (default the primary).
 */
export function caddyAdminGet(path: string, webContainer = 'ingressi-web'): string {
  return execFileSync('docker', ['exec', webContainer, 'node', '-e', reader(path)], {
    encoding: 'utf-8',
    timeout: 10_000,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
}

export type Policy = {
  subjects?: string[];
  issuers?: { challenges?: { dns?: { provider?: { name?: string } } } }[];
};

/** Caddy's live TLS automation policies; null if unreachable. */
export function fetchLivePolicies(): Policy[] | null {
  try {
    return JSON.parse(caddyAdminGet('/config/apps/tls/automation/policies')) as Policy[] | null;
  } catch {
    return null;
  }
}

/** The DNS provider name Caddy uses for `domain`, or null when no policy lists it. */
export function liveProviderFor(domain: string): string | null {
  const policy = fetchLivePolicies()?.find((p) => p.subjects?.includes(domain));
  if (!policy) return null;
  return policy.issuers?.[0]?.challenges?.dns?.provider?.name ?? null;
}

// Re-exported so specs that still name the caddy container keep a single source.
export { CADDY };
