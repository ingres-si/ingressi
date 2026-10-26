/**
 * Where each setting lives. The settings have pages of their own next to
 * what they configure (Certificate settings, Host defaults, Geo blocking…);
 * this catalog lists every section of those pages for the command palette
 * (src/lib/search.ts) and forwards the links of the old Settings page
 * (`/settings?section=<id>` and `/settings#<id>`) to the page that holds the
 * section now. Pure data, safe for the client.
 */
import type { Permission } from "./permissions";

export type SettingsSection = {
  /** The id the old Settings page used (`/settings?section=<id>`). */
  id: string;
  name: string;
  desc: string;
  /** Other words people search for. */
  keywords: readonly string[];
  /** The page that holds it, by its name in the navigation. */
  page: string;
  /** The page, with the section's anchor when it is not at the top. */
  href: string;
  /** Needed on top of settings:read to see the section (the page shows a notice otherwise); Backups needs only this. */
  permission?: Permission;
};

export const SETTINGS_SECTIONS: readonly SettingsSection[] = [
  {
    id: "general",
    name: "General",
    desc: "Primary domain and dashboard address",
    keywords: ["primary domain", "base url", "dashboard address", "domain"],
    page: "Settings",
    href: "/settings",
  },
  {
    id: "acme",
    name: "Certificate authority",
    desc: "Let's Encrypt or your own ACME directory, and the contact e-mail",
    keywords: ["acme", "lets encrypt", "certificate authority", "directory", "step-ca", "internal ca", "pem", "contact email", "tls"],
    page: "Certificate settings",
    href: "/certificates/settings",
  },
  {
    id: "dns-providers",
    name: "DNS-01 providers",
    desc: "Provider credentials for wildcard certificates",
    keywords: ["dns", "dns providers", "acme", "dns-01", "cloudflare", "route53", "hetzner", "wildcard", "challenge"],
    page: "Certificate settings",
    href: "/certificates/settings#dns-providers",
  },
  {
    id: "dns-resolvers",
    name: "DNS-01 resolvers",
    desc: "Your own resolvers for the DNS-01 check",
    keywords: ["dns", "dns resolvers", "resolver", "nameserver", "propagation"],
    page: "Certificate settings",
    href: "/certificates/settings#dns-resolvers",
  },
  {
    id: "certificate-storage",
    name: "Certificate storage",
    desc: "Local, or shared Redis or Valkey for several Caddy nodes",
    keywords: ["redis", "valkey", "storage", "high availability", "cluster"],
    page: "Certificate settings",
    href: "/certificates/settings#certificate-storage",
    permission: "high_availability:read",
  },
  {
    id: "default-response",
    name: "Requests for unknown hosts",
    desc: "The answer when no proxy host matches",
    keywords: ["default response", "unknown host", "catch-all", "direct ip", "fallback", "404", "redirect", "abort", "444"],
    page: "Host defaults",
    href: "/proxy-hosts/defaults#default-response",
  },
  {
    id: "error-pages",
    name: "Error pages",
    desc: "Fallback error pages for every host",
    keywords: ["error", "404", "502", "503", "504", "custom page", "html"],
    page: "Host defaults",
    href: "/proxy-hosts/defaults#error-pages",
  },
  {
    id: "trusted-proxies",
    name: "Trusted proxies",
    desc: "The real client address behind a load balancer or CDN",
    keywords: ["proxy", "cloudflare", "real ip", "x-forwarded-for", "client ip", "cidr", "strict", "private_ranges", "proxy protocol", "load balancer", "haproxy"],
    page: "Host defaults",
    href: "/proxy-hosts/defaults#trusted-proxies",
  },
  {
    id: "upstream-dns",
    name: "Upstream DNS pinning",
    desc: "Resolve upstream hostnames when the configuration is applied",
    keywords: ["upstream", "dns", "pinning", "resolve", "ipv4", "ipv6", "address family"],
    page: "Host defaults",
    href: "/proxy-hosts/defaults#upstream-dns",
  },
  {
    id: "forward-auth",
    name: "Forward auth defaults",
    desc: "Authentik and Authelia defaults for new proxy hosts",
    keywords: ["authentik", "authelia", "forward auth", "outpost", "sso"],
    page: "Host defaults",
    href: "/proxy-hosts/defaults#forward-auth",
  },
  {
    id: "geoblock",
    name: "Geo blocking",
    desc: "Default country rules and the GeoLite2 databases",
    keywords: ["geo", "geoblock", "geoblocking", "country", "block", "geoip", "geolite2", "maxmind", "asn", "geoipupdate"],
    page: "Geo blocking",
    href: "/geo-blocking",
  },
  {
    id: "rate-limit",
    name: "Rate limiting",
    desc: "Default request limits, and clients never limited",
    keywords: ["rate", "limit", "429", "throttle", "requests per minute", "exempt"],
    page: "Rate limiting",
    href: "/rate-limiting",
  },
  {
    id: "oauth",
    name: "OAuth providers",
    desc: "OpenID Connect providers for dashboard sign-in",
    keywords: ["oauth", "oidc", "openid", "sso", "sign-in", "provider", "callback"],
    page: "OAuth providers",
    href: "/oauth-providers",
    permission: "sso:read",
  },
  {
    id: "analytics",
    name: "Traffic analytics",
    desc: "ClickHouse status and retention",
    keywords: ["analytics", "clickhouse", "retention"],
    page: "Analytics settings",
    href: "/analytics/settings",
  },
  {
    id: "logging",
    name: "Access log",
    desc: "The HTTP access log of proxied requests",
    keywords: ["log", "access log", "logging", "json"],
    page: "Analytics settings",
    href: "/analytics/settings#logging",
  },
  {
    id: "metrics",
    name: "Prometheus metrics",
    desc: "The metrics endpoint on its own port",
    keywords: ["metrics", "prometheus", "monitoring", "port"],
    page: "Analytics settings",
    href: "/analytics/settings#metrics",
  },
  {
    id: "sync",
    name: "Instance sync",
    desc: "Standalone, master or replica, and the replicas of a master",
    keywords: ["instance mode", "master", "replica", "slave", "instances", "sync token", "pull", "push", "nodes", "key pin"],
    page: "Instance sync",
    href: "/instances",
    permission: "instances:read",
  },
  {
    id: "high-availability",
    name: "Dashboard cluster",
    desc: "Leader and standbys, or PostgreSQL replicas",
    keywords: [
      "high availability", "ha", "cluster", "leader", "standby", "failover", "lease", "litestream", "replication",
      "postgresql", "postgres", "replicas", "nodes", "heartbeat",
    ],
    page: "High availability",
    href: "/high-availability",
    permission: "high_availability:read",
  },
  {
    id: "shared-state",
    name: "Shared state",
    desc: "Forward-auth sessions and API balances in Redis or Valkey",
    keywords: ["redis", "valkey", "high availability", "sessions", "balances", "standby", "leader", "shared state"],
    page: "High availability",
    href: "/high-availability#shared-state",
    permission: "high_availability:read",
  },
  {
    id: "backups",
    name: "Backups",
    desc: "Scheduled, encrypted backups to your S3-compatible storage",
    keywords: ["backup", "s3", "restore", "schedule", "retention", "passphrase", "bucket"],
    page: "Backups",
    href: "/backups",
    permission: "backups:read",
  },
];

/**
 * Old Settings ids that are not sections of their own: a card of a section,
 * a link that never matched a section, and the groups of the old page.
 */
const OTHER_OLD_IDS: Readonly<Record<string, string>> = {
  authentik: "/proxy-hosts/defaults#authentik",
  "instance-sync": "/instances",
  branding: "/branding",
  system: "/settings",
  networking: "/proxy-hosts/defaults#trusted-proxies",
  security: "/geo-blocking",
  observability: "/analytics/settings",
  appearance: "/branding",
};

/** Every page that holds settings, for revalidating them after a change. */
export const SETTINGS_PAGES: readonly string[] = [
  ...new Set(SETTINGS_SECTIONS.map((section) => section.href.split("#")[0])),
];

/** A section by its id. */
export function findSettingsSection(id: string): SettingsSection | undefined {
  return SETTINGS_SECTIONS.find((section) => section.id === id);
}

/**
 * Where an id of the old Settings page (`?section=`, `?group=` or `#`) points
 * now; null for ids it never had.
 */
export function settingsSectionHref(id: string): string | null {
  const key = id.trim().toLowerCase();
  if (!key) return null;
  return findSettingsSection(key)?.href ?? OTHER_OLD_IDS[key] ?? null;
}
