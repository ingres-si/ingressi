/**
 * The PROXY protocol on Caddy's HTTP and HTTPS listeners (ports 80 and 443),
 * set under Host defaults → Trusted proxies.
 *
 * A TCP load balancer in front of Caddy (HAProxy in TCP mode, a cloud network
 * load balancer, OPNsense or another Caddy with layer4) hides the client:
 * every connection comes from the balancer. With the PROXY protocol the
 * balancer opens each connection with a header naming the client, and Caddy
 * takes that address for the connection, so whatever reads the client address
 * (access lists, geo blocking, rate limits, the WAF, analytics, the addresses
 * that skip sign-in) sees the visitor.
 *
 * Only the listed sources may send the header. From them it is optional, so a
 * client that connects directly still works; from any other address a header
 * is read and its address ignored, so nobody else can claim an address. A
 * range that matches every address is refused, and so is private_ranges: the
 * list names the balancers, not a network.
 *
 * Pure: no database and no Node built-ins.
 */
import { PRIVATE_RANGES_VALUE, parseIpRange } from "./access-list-rules";

export const MAX_PROXY_PROTOCOL_RANGES = 100;

/** The text of an entry as an error message may show it. */
function shown(text: string): string {
  return text.length > 64 ? `${text.slice(0, 61)}...` : text;
}

/** One entry, normalized (a range is stored as its network address), or what is wrong with it. */
export function normalizeProxyProtocolRange(raw: string): { value: string } | { error: string } {
  const text = raw.trim();
  if (text.toLowerCase() === PRIVATE_RANGES_VALUE) {
    return { error: `"${PRIVATE_RANGES_VALUE}" is not accepted here; list the addresses of the load balancers` };
  }
  const range = parseIpRange(text);
  if (!range) return { error: `"${shown(text)}" is not an IP address or a CIDR range` };
  if (range.prefix === 0) return { error: `"${shown(text)}" matches every address, so any client could set its own address` };
  return { value: range.text };
}

/**
 * The entries of a request (an array of strings) or a form (one string
 * separated by commas, spaces or newlines), normalized and deduplicated, or
 * the first thing wrong with them.
 */
export function normalizeProxyProtocolRanges(input: unknown): { values: string[] } | { error: string } {
  if (input === undefined || input === null) return { values: [] };
  const items: unknown = typeof input === "string" ? input.split(/[\s,]+/) : input;
  if (!Array.isArray(items)) return { error: "must be a list of IP addresses or CIDR ranges" };
  if (items.length > MAX_PROXY_PROTOCOL_RANGES * 10) return { error: `can hold at most ${MAX_PROXY_PROTOCOL_RANGES} entries` };
  const values: string[] = [];
  const seen = new Set<string>();
  for (const [index, item] of items.entries()) {
    if (typeof item !== "string") return { error: `[${index}] must be a string` };
    if (!item.trim()) continue;
    const result = normalizeProxyProtocolRange(item);
    if ("error" in result) return { error: result.error };
    if (seen.has(result.value)) continue;
    seen.add(result.value);
    values.push(result.value);
  }
  if (values.length > MAX_PROXY_PROTOCOL_RANGES) return { error: `can hold at most ${MAX_PROXY_PROTOCOL_RANGES} entries` };
  return { values };
}

/** What storage holds, for use: the valid entries as CIDR ranges (Caddy parses each as a prefix); the rest are dropped. */
export function readProxyProtocolRanges(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const ranges: string[] = [];
  for (const item of input) {
    if (typeof item !== "string") continue;
    const result = normalizeProxyProtocolRange(item);
    if ("error" in result) continue;
    const range = result.value.includes("/") ? result.value : `${result.value}/${result.value.includes(":") ? 128 : 32}`;
    if (!ranges.includes(range)) ranges.push(range);
    if (ranges.length >= MAX_PROXY_PROTOCOL_RANGES) break;
  }
  return ranges;
}

/**
 * The listener wrappers of the main HTTP server (`servers.ingressi`), or
 * nothing when no source is listed.
 *
 * The PROXY header comes before the TLS handshake, so the `tls` wrapper is
 * listed after it: Caddy puts TLS first when a server's wrappers leave it out.
 * `fallback_policy` is spelled out (it is Caddy's default) because it is what
 * keeps other clients from setting an address.
 */
export function buildProxyProtocolListenerWrappers(ranges: unknown): { listener_wrappers?: Record<string, unknown>[] } {
  const allow = readProxyProtocolRanges(ranges);
  if (allow.length === 0) return {};
  return {
    listener_wrappers: [{ wrapper: "proxy_protocol", allow, fallback_policy: "ignore" }, { wrapper: "tls" }],
  };
}
