/**
 * Reads Caddy's reverse-proxy upstream pool from the admin API
 * (GET /reverse_proxy/upstreams).
 *
 * What Caddy reports (checked against Caddy 2.11): for every upstream of an
 * HTTP reverse_proxy handler, its dial address, the requests in flight
 * (`num_requests`) and `fails`, the failures counted by *passive* health checks
 * within their `fail_duration`. Caddy only counts failures when a host has
 * passive health checks with a non-zero fail duration. The result of *active*
 * health checks is not exposed by the admin API, and caddy-l4 (TCP/UDP)
 * upstreams are not part of this pool.
 */
import http from "node:http";
import https from "node:https";
import { config } from "@/src/lib/config";

export type CaddyUpstream = { address: string; numRequests: number; fails: number };

const TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** Plain node:http request: native fetch sends Sec-Fetch-* headers that trip Caddy's origin checks. */
function getJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const request = lib.request(
      {
        ...(config.caddyAdminSocket
          ? { socketPath: config.caddyAdminSocket, headers: { Host: "localhost" } }
          : { hostname: parsed.hostname, port: parsed.port }),
        path: parsed.pathname + parsed.search,
        method: "GET",
        timeout: TIMEOUT_MS,
      },
      (response) => {
        let size = 0;
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            request.destroy(new Error("Caddy admin response too large"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if ((response.statusCode ?? 0) < 200 || (response.statusCode ?? 0) >= 300) {
            reject(new Error(`Caddy admin API answered with HTTP ${response.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            reject(new Error("Caddy admin API returned invalid JSON"));
          }
        });
      }
    );
    request.on("timeout", () => request.destroy(new Error("Caddy admin API timed out")));
    request.on("error", reject);
    request.end();
  });
}

export function parseCaddyUpstreams(value: unknown): CaddyUpstream[] {
  if (!Array.isArray(value)) throw new Error("Unexpected /reverse_proxy/upstreams response");
  const upstreams: CaddyUpstream[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const { address, num_requests: numRequests, fails } = item as Record<string, unknown>;
    if (typeof address !== "string" || address.length === 0 || address.length > 512) continue;
    upstreams.push({
      address,
      numRequests: typeof numRequests === "number" && Number.isFinite(numRequests) ? numRequests : 0,
      fails: typeof fails === "number" && Number.isFinite(fails) ? fails : 0,
    });
  }
  return upstreams;
}

/** Throws when Caddy cannot be reached; callers treat that as "unknown", not as healthy. */
export async function fetchCaddyUpstreams(): Promise<CaddyUpstream[]> {
  return parseCaddyUpstreams(await getJson(`${config.caddyApiUrl}/reverse_proxy/upstreams`));
}
