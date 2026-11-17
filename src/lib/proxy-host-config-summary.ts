/**
 * A host's configuration in a few plain lines, one per section of the host
 * editor (routing, security, access, certificate, headers, advanced), for
 * the host's page. Pure: the caller passes the host and what it resolved
 * (the effective WAF mode, rate limit rules and geo blocking, the access
 * list's name, the certificate).
 */
import type { ProxyHost } from "./models/proxy-hosts";
import type { HostCertificate, ProtectionInput } from "./proxy-host-view";
import { RENEWAL_LABELS } from "./proxy-host-view";
import { hostModeOf } from "./waf-host-mode";

export const HOST_EDITOR_SECTIONS = ["routing", "security", "access", "certificate", "headers", "advanced"] as const;
export type HostEditorSection = (typeof HOST_EDITOR_SECTIONS)[number];

export const HOST_EDITOR_SECTION_LABELS: Record<HostEditorSection, string> = {
  routing: "Routing",
  security: "Security",
  access: "Access",
  certificate: "Certificate",
  headers: "Headers",
  advanced: "Advanced",
};

export type HostConfigSummary = { section: HostEditorSection; title: string; summary: string };

const POLICY_LABELS: Record<string, string> = {
  random: "random",
  round_robin: "round robin",
  least_conn: "least connections",
  ip_hash: "client IP hash",
  first: "first available",
  header: "header hash",
  cookie: "cookie",
  uri_hash: "URI hash",
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;

/** "28 Dec 2026" (UTC). */
export function dayText(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()}`;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function schemeOf(upstream: string): "https" | "http" | null {
  const value = upstream.trim().toLowerCase();
  if (value.startsWith("https://")) return "https";
  if (value.startsWith("http://")) return "http";
  return null;
}

function routing(host: ProxyHost): string {
  const parts: string[] = [];
  const schemes = host.upstreams.map(schemeOf);
  const tls = schemes.filter((scheme) => scheme === "https").length;
  const upstreams = plural(host.upstreams.length, "upstream");
  parts.push(tls === host.upstreams.length && tls > 0 ? `${upstreams} over HTTPS` : tls > 0 ? `${upstreams}, ${tls} over HTTPS` : upstreams);
  const lb = host.loadBalancer?.enabled ? host.loadBalancer : null;
  if (lb && host.upstreams.length > 1) parts.push(`${POLICY_LABELS[lb.policy] ?? lb.policy} load balancing`);
  const checks = lb && (lb.activeHealthCheck?.enabled || lb.passiveHealthCheck?.enabled);
  parts.push(checks ? "health checks on" : "no health checks");
  parts.push(host.allowWebsocket ? "WebSockets on" : "WebSockets off");
  if (host.locationRules.length > 0) parts.push(plural(host.locationRules.length, "path route"));
  return parts.join(" · ");
}

function security(input: ProtectionInput, host: ProxyHost): string {
  const parts: string[] = [];
  const inherits = hostModeOf(host.waf) === "inherit";
  const waf =
    input.wafMode === "block" ? "WAF blocks" : input.wafMode === "detection_only" ? "WAF detection only" : "WAF off";
  parts.push(inherits && input.wafMode !== "off" ? `${waf} (global settings)` : waf);
  parts.push(input.rateLimit.rules > 0 ? plural(input.rateLimit.rules, "rate limit rule") : "no rate limit");
  if (input.geo) parts.push(input.geo.fromGlobal ? "global geo blocking" : "geo blocking");
  return parts.join(" · ");
}

function access(input: ProtectionInput, host: ProxyHost): string {
  const parts: string[] = [];
  if (input.sso) parts.push("sign-in with dashboard accounts");
  if (input.authentik) parts.push("sign-in through Authentik");
  if (input.forwardAuth) parts.push(input.forwardAuth === "authelia" ? "sign-in through Authelia" : "forward auth");
  if (input.accessList) parts.push(input.accessList.name ? `access list "${input.accessList.name}"` : "an access list");
  if (input.mtls) parts.push("client certificate required");
  if ((host.pathAccessLists?.length ?? 0) > 0) parts.push(plural(host.pathAccessLists.length, "path access list"));
  if (host.pathBlocks.length > 0) parts.push(plural(host.pathBlocks.length, "blocked path"));
  if (parts.length === 0) return "Public: anyone who reaches the domain gets through";
  const text = parts.join(" · ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function certificate(cert: HostCertificate, host: ProxyHost): string {
  const parts: string[] = [];
  if (!cert.visible) {
    parts.push(cert.automatic ? "Obtained automatically" : "A chosen certificate");
  } else if (cert.kind === "imported") {
    parts.push(cert.name ? `Imported "${cert.name}"` : "Imported");
    if (cert.validTo) parts.push(`expires ${dayText(cert.validTo)}`);
    if (cert.renewal === "replace_soon" || cert.renewal === "expired") parts.push(RENEWAL_LABELS[cert.renewal]);
  } else {
    parts.push(cert.issuer ?? "ACME");
    parts.push(cert.renewal === "scheduled" ? "renews automatically" : RENEWAL_LABELS[cert.renewal]);
    if (cert.validTo) parts.push(`expires ${dayText(cert.validTo)}`);
  }
  parts.push(host.sslForced ? "HTTP redirects to HTTPS" : "HTTP not redirected");
  return parts.join(" · ");
}

function headers(host: ProxyHost): string {
  const parts: string[] = [];
  parts.push(host.hstsEnabled ? (host.hstsSubdomains ? "HSTS on, with subdomains" : "HSTS on") : "HSTS off");
  parts.push(host.preserveHostHeader ? "Host header passed through" : "Host header set to the upstream");
  return parts.join(" · ");
}

function advanced(host: ProxyHost): string | null {
  const parts: string[] = [];
  if (host.redirects.length > 0) parts.push(plural(host.redirects.length, "redirect"));
  if (host.rewrite || host.pathRewrites.length > 0) parts.push("path rewrites");
  if (host.errorPages.length > 0) parts.push(plural(host.errorPages.length, "custom error page"));
  if (host.upstreamDnsResolution?.enabled) parts.push("upstream DNS pinning");
  if (host.customReverseProxyJson || host.customPreHandlersJson) parts.push("custom Caddy JSON");
  if (parts.length === 0) return null;
  const text = parts.join(" · ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** One line per editor section; Advanced only when something there is set. */
export function hostConfigSummaries(host: ProxyHost, input: ProtectionInput, cert: HostCertificate): HostConfigSummary[] {
  const rows: HostConfigSummary[] = [
    { section: "routing", title: "Routing", summary: routing(host) },
    { section: "security", title: "Security", summary: security(input, host) },
    { section: "access", title: "Access", summary: access(input, host) },
    { section: "certificate", title: "Certificate", summary: certificate(cert, host) },
    { section: "headers", title: "Headers", summary: headers(host) },
  ];
  const extra = advanced(host);
  if (extra) rows.push({ section: "advanced", title: "Advanced", summary: extra });
  return rows;
}
