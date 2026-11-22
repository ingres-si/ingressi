/**
 * The dashboard's navigation: the sidebar's groups and entries, and every
 * page each entry stands for. Pure data and functions, safe for the client
 * (the sidebar) and the server (the command palette's search).
 *
 * Each page is listed with the permission its page guard checks (null for
 * pages every signed-in user may open); tests/unit/permission-call-sites
 * keeps the two in step. An entry is shown when its user may open one of its
 * pages, and it links to the first of them the user may open, so a role
 * that can read groups but not users still reaches the groups page.
 */
import type { Permission } from "./permissions";

/** The counters the sidebar shows next to entries (see src/lib/nav-summary.ts). */
export type NavBadgeKey = "alertsFiring" | "certificatesExpiring" | "approvalsPending" | "reviewsDue";

export type NavPage = {
  href: string;
  /** The page's own name, for the command palette and breadcrumbs. */
  label: string;
  /** Shown to users holding this permission; null for every signed-in user. */
  permission: Permission | null;
  /** Shown only while the entry's badge is up (the reviewer's own reviews). */
  onlyWithBadge?: boolean;
};

export type NavEntryKey =
  | "overview"
  | "proxy-hosts"
  | "l4-hosts"
  | "certificates"
  | "access-lists"
  | "analytics"
  | "security"
  | "alerts"
  | "audit-log"
  | "users"
  | "sign-in"
  | "access-reviews"
  | "approvals"
  | "history"
  | "compliance"
  | "fleet"
  | "high-availability"
  | "monetization"
  | "settings"
  | "mcp"
  | "branding"
  | "profile"
  | "api-docs";

export type NavEntry = {
  key: NavEntryKey;
  label: string;
  /** The first page the user may open is the entry's link; every page marks it current. */
  pages: readonly NavPage[];
  badge?: NavBadgeKey;
};

export type NavGroup = {
  /** Null for the first group (Overview), which has no heading. */
  title: string | null;
  entries: readonly NavEntry[];
};

export const NAV_GROUPS: readonly NavGroup[] = [
  {
    title: null,
    entries: [{ key: "overview", label: "Overview", pages: [{ href: "/", label: "Overview", permission: null }] }],
  },
  {
    title: "Traffic",
    entries: [
      {
        key: "proxy-hosts",
        label: "Proxy hosts",
        pages: [
          { href: "/proxy-hosts", label: "Proxy hosts", permission: "proxy_hosts:read" },
          { href: "/proxy-hosts/defaults", label: "Host defaults", permission: "settings:read" },
        ],
      },
      { key: "l4-hosts", label: "L4 hosts", pages: [{ href: "/l4-proxy-hosts", label: "L4 hosts", permission: "l4_proxy_hosts:read" }] },
      {
        key: "certificates",
        label: "Certificates",
        pages: [
          { href: "/certificates", label: "Certificates", permission: "certificates:read" },
          { href: "/certificates/settings", label: "Certificate settings", permission: "settings:read" },
        ],
        badge: "certificatesExpiring",
      },
      { key: "access-lists", label: "Access lists", pages: [{ href: "/access-lists", label: "Access lists", permission: "access_lists:read" }] },
    ],
  },
  {
    title: "Observe",
    entries: [
      {
        key: "analytics",
        label: "Analytics",
        pages: [
          { href: "/analytics", label: "Analytics", permission: "analytics:read" },
          { href: "/analytics/settings", label: "Analytics settings", permission: "settings:read" },
        ],
      },
      {
        key: "security",
        label: "Security events",
        pages: [
          { href: "/security", label: "Security events", permission: "waf:read" },
          { href: "/waf", label: "WAF settings", permission: "waf:read" },
          { href: "/geo-blocking", label: "Geo blocking", permission: "settings:read" },
          { href: "/rate-limiting", label: "Rate limiting", permission: "settings:read" },
        ],
      },
      { key: "alerts", label: "Alerts", pages: [{ href: "/alerts", label: "Alerts", permission: "alerts:read" }], badge: "alertsFiring" },
      {
        key: "audit-log",
        label: "Audit log",
        pages: [
          { href: "/audit-log", label: "Audit log", permission: "audit_log:read" },
          { href: "/audit-log/streaming", label: "Audit streaming", permission: "audit_streaming:read" },
        ],
      },
    ],
  },
  {
    title: "Users and sign-in",
    entries: [
      {
        key: "users",
        label: "Users and groups",
        pages: [
          { href: "/users", label: "Users", permission: "users:read" },
          { href: "/groups", label: "Groups", permission: "groups:read" },
        ],
      },
      {
        key: "sign-in",
        label: "Sign-in and directories",
        pages: [
          { href: "/sign-in", label: "Sign-in and directories", permission: "sso:read" },
          { href: "/sso", label: "Single sign-on", permission: "sso:read" },
          { href: "/oauth-providers", label: "OAuth providers", permission: "settings:read" },
          { href: "/saml", label: "SAML", permission: "sso:read" },
          { href: "/ldap", label: "LDAP directories", permission: "ldap:read" },
          { href: "/scim", label: "SCIM provisioning", permission: "scim:read" },
        ],
      },
      {
        key: "access-reviews",
        label: "Access reviews",
        pages: [
          { href: "/access-reviews", label: "Access reviews", permission: "access_reviews:read" },
          { href: "/my-reviews", label: "My reviews", permission: null, onlyWithBadge: true },
        ],
        badge: "reviewsDue",
      },
    ],
  },
  {
    title: "Govern",
    entries: [
      { key: "approvals", label: "Approvals", pages: [{ href: "/approvals", label: "Approvals", permission: "approvals:read" }], badge: "approvalsPending" },
      {
        key: "history",
        label: "Change history",
        pages: [
          { href: "/history", label: "Change history", permission: "config_history:read" },
          { href: "/backups", label: "Backups", permission: "backups:read" },
        ],
      },
      { key: "compliance", label: "Compliance", pages: [{ href: "/compliance", label: "Compliance", permission: "compliance:read" }] },
    ],
  },
  {
    title: "Platform",
    entries: [
      {
        key: "fleet",
        label: "Fleet",
        pages: [
          { href: "/fleet", label: "Fleet", permission: "fleet:read" },
          { href: "/instances", label: "Instance sync", permission: "settings:read" },
        ],
      },
      {
        key: "high-availability",
        label: "High availability",
        pages: [{ href: "/high-availability", label: "High availability", permission: "settings:read" }],
      },
      { key: "monetization", label: "API monetization", pages: [{ href: "/api-monetization", label: "API monetization", permission: "monetization:read" }] },
    ],
  },
];

/** Under the groups, above the user menu. */
export const NAV_FOOTER: readonly NavEntry[] = [
  {
    key: "settings",
    label: "Settings",
    pages: [
      { href: "/settings", label: "Settings", permission: "settings:read" },
      { href: "/settings/ai", label: "AI settings", permission: "ai:read" },
    ],
  },
  {
    key: "mcp",
    label: "MCP server",
    pages: [{ href: "/mcp", label: "MCP server", permission: "settings:read" }],
  },
  { key: "branding", label: "Branding", pages: [{ href: "/branding", label: "Branding", permission: "branding:read" }] },
];

/** The user menu's pages. */
export const NAV_ACCOUNT: readonly NavEntry[] = [
  { key: "profile", label: "Profile", pages: [{ href: "/profile", label: "Profile", permission: null }] },
  { key: "api-docs", label: "API reference", pages: [{ href: "/api-docs", label: "API reference", permission: "api_docs:read" }] },
];

const ALL_ENTRIES: readonly NavEntry[] = [...NAV_GROUPS.flatMap((group) => group.entries), ...NAV_FOOTER, ...NAV_ACCOUNT];

/** Every dashboard page the navigation reaches, once each, in navigation order. */
export const NAV_PAGES: readonly (NavPage & { entry: NavEntryKey })[] = ALL_ENTRIES.flatMap((entry) =>
  entry.pages.map((page) => ({ ...page, entry: entry.key }))
);

export type NavViewer = {
  /** Permissions the user holds (listHeldPermissions); every one for administrators. */
  permissions?: readonly string[];
  isAdmin?: boolean;
};

/** A badge as the sidebar shows it: short text, its tone, and the sentence screen readers hear. */
export type NavBadge = { text: string; tone: "neutral" | "warn"; label: string };

/** Badge values by key; a key that is absent or null shows nothing. */
export type NavBadges = Partial<Record<NavBadgeKey, NavBadge | null>>;

/** Whether `viewer` may open `page` (and, for onlyWithBadge pages, whether the badge is up). */
export function canOpenPage(viewer: NavViewer, page: NavPage, badgeUp = false): boolean {
  if (page.onlyWithBadge && !badgeUp) return false;
  if (page.permission === null) return true;
  if (viewer.isAdmin) return true;
  return (viewer.permissions ?? []).includes(page.permission);
}

export type VisibleNavEntry = NavEntry & {
  /** Where the entry links: its first page the viewer may open. */
  href: string;
  /** The pages the viewer may open. */
  openPages: readonly NavPage[];
};

/** The entry with its link for `viewer`, or null when they may open none of its pages. */
export function visibleEntry(viewer: NavViewer, entry: NavEntry, badges: NavBadges = {}): VisibleNavEntry | null {
  const badgeUp = entry.badge ? Boolean(badges[entry.badge]) : false;
  const openPages = entry.pages.filter((page) => canOpenPage(viewer, page, badgeUp));
  if (openPages.length === 0) return null;
  return { ...entry, href: openPages[0].href, openPages };
}

/** The sidebar groups for `viewer`: entries they may open, groups left empty dropped. */
export function visibleNavGroups(viewer: NavViewer, badges: NavBadges = {}): { title: string | null; entries: VisibleNavEntry[] }[] {
  return NAV_GROUPS.map((group) => ({
    title: group.title,
    entries: group.entries.flatMap((entry) => visibleEntry(viewer, entry, badges) ?? []),
  })).filter((group) => group.entries.length > 0);
}

export function visibleEntries(viewer: NavViewer, entries: readonly NavEntry[], badges: NavBadges = {}): VisibleNavEntry[] {
  return entries.flatMap((entry) => visibleEntry(viewer, entry, badges) ?? []);
}

/** Every page `viewer` may open, in navigation order (the command palette's "Go to" results). */
export function visibleNavPages(viewer: NavViewer): (NavPage & { entry: NavEntryKey })[] {
  return NAV_PAGES.filter((page) => canOpenPage(viewer, page));
}

/** The entry `pathname` belongs to: the one with the longest page path that matches. */
export function currentEntryKey(pathname: string): NavEntryKey | null {
  let best: { key: NavEntryKey; length: number } | null = null;
  for (const page of NAV_PAGES) {
    const matches = page.href === "/" ? pathname === "/" : pathname === page.href || pathname.startsWith(`${page.href}/`);
    if (matches && (!best || page.href.length > best.length)) best = { key: page.entry, length: page.href.length };
  }
  return best?.key ?? null;
}
