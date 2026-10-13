/**
 * The proxy hosts list and a host's page as the dashboard shows them: what
 * protects a host, its certificate, what needs attention, and the search,
 * filters and sort of the list. Pure functions and types, with no server
 * imports, so client components use them too; the server side that fills
 * them in is src/lib/proxy-host-insights.ts.
 */
import type { CertificateKind, RenewalState } from "./certificate-renewal";
import type { WafEffectiveMode } from "./waf-host-mode";
import {
  PROXY_HOST_SORT_KEYS,
  type ProxyHostSortKey,
  type SortDirection,
} from "./list-sort-preferences";

// ── Protections ─────────────────────────────────────────────────────────

/** The protection filter of the list; "none" matches hosts without any protection. */
export const PROTECTION_FILTERS = [
  "waf_block",
  "waf_detect",
  "waf_off",
  "sign_in",
  "rate_limit",
  "geo",
  "access_list",
  "mtls",
  "none",
] as const;
export type ProtectionFilter = (typeof PROTECTION_FILTERS)[number];

export const PROTECTION_FILTER_LABELS: Record<ProtectionFilter, string> = {
  waf_block: "WAF blocking",
  waf_detect: "WAF detection only",
  waf_off: "WAF off",
  sign_in: "Sign-in required",
  rate_limit: "Rate limiting",
  geo: "Geo blocking",
  access_list: "Access list",
  mtls: "Client certificates",
  none: "No protection",
};

export function isProtectionFilter(value: unknown): value is ProtectionFilter {
  return typeof value === "string" && (PROTECTION_FILTERS as readonly string[]).includes(value);
}

/** The dot colours of ProtectionPill (src/components/ui/ProtectionPill.tsx). */
export type ProtectionPillKind = "waf" | "sso" | "rate-limit" | "geo" | "mtls" | "access-list" | "forward-auth";

export type HostProtection = {
  /** What it is, for the filter. */
  key: Exclude<ProtectionFilter, "waf_off" | "none">;
  kind: ProtectionPillKind;
  /** Short pill text, e.g. "WAF · Block". */
  label: string;
  /** The detail behind the label. */
  title: string;
};

/** What protects a host once its own settings and the global ones are combined. */
export type ProtectionInput = {
  wafMode: WafEffectiveMode;
  /** Built-in sign-in (forward auth to the dashboard's own accounts). */
  sso: boolean;
  authentik: boolean;
  /** Generic forward auth: its provider ("authelia", "custom"). */
  forwardAuth: string | null;
  /** Rate limiting rules that apply to the host. */
  rateLimit: { rules: number; first: { events: number; window: string } | null };
  /** Effective geo blocking, or null when none applies. */
  geo: { blockCountries: string[]; allowCountries: string[]; blockContinents: string[]; other: number; fromGlobal: boolean } | null;
  /** The host's access list (its name when the reader may see it). */
  accessList: { name: string | null } | null;
  mtls: boolean;
};

function listShort(values: readonly string[], max = 3): string {
  return values.length <= max ? values.join(", ") : `${values.length}`;
}

function geoLabel(geo: NonNullable<ProtectionInput["geo"]>): { label: string; title: string } {
  const source = geo.fromGlobal ? " (global rules)" : "";
  if (geo.blockCountries.length > 0) {
    const n = geo.blockCountries.length;
    const label = n <= 3 ? `Geo · blocks ${geo.blockCountries.join(", ")}` : `Geo · blocks ${n} countries`;
    return { label, title: `Blocks requests from ${geo.blockCountries.join(", ")}${source}` };
  }
  if (geo.blockContinents.length > 0) {
    return {
      label: `Geo · blocks ${listShort(geo.blockContinents)}${geo.blockContinents.length > 3 ? " continents" : ""}`,
      title: `Blocks requests from the continents ${geo.blockContinents.join(", ")}${source}`,
    };
  }
  if (geo.allowCountries.length > 0) {
    return {
      label: geo.allowCountries.length <= 3 ? `Geo · allows ${geo.allowCountries.join(", ")}` : `Geo · allows ${geo.allowCountries.length} countries`,
      title: `Always allows ${geo.allowCountries.join(", ")}${source}`,
    };
  }
  return { label: "Geo", title: `Geo blocking by network or address${source}` };
}

/** The pills of a host, in the order the list shows them. */
export function protectionsOf(input: ProtectionInput): HostProtection[] {
  const pills: HostProtection[] = [];
  if (input.wafMode === "block") {
    pills.push({ key: "waf_block", kind: "waf", label: "WAF · Block", title: "The WAF blocks requests that match its rules" });
  } else if (input.wafMode === "detection_only") {
    pills.push({ key: "waf_detect", kind: "waf", label: "WAF · Detect only", title: "The WAF logs requests that match its rules without blocking them" });
  }
  if (input.sso) pills.push({ key: "sign_in", kind: "sso", label: "SSO", title: "Visitors sign in with their dashboard account" });
  if (input.authentik) pills.push({ key: "sign_in", kind: "forward-auth", label: "Authentik", title: "Visitors sign in through Authentik" });
  if (input.forwardAuth) {
    const authelia = input.forwardAuth === "authelia";
    pills.push({
      key: "sign_in",
      kind: "forward-auth",
      label: authelia ? "Forward auth · Authelia" : "Forward auth",
      title: authelia ? "Visitors sign in through Authelia" : "Requests are checked by a forward-auth server",
    });
  }
  if (input.accessList) {
    pills.push({
      key: "access_list",
      kind: "access-list",
      label: input.accessList.name ? `Access list · ${input.accessList.name}` : "Access list",
      title: input.accessList.name ? `Access list "${input.accessList.name}"` : "An access list applies",
    });
  }
  if (input.mtls) pills.push({ key: "mtls", kind: "mtls", label: "mTLS", title: "Clients need a trusted client certificate" });
  if (input.rateLimit.rules > 0) {
    const first = input.rateLimit.first;
    pills.push({
      key: "rate_limit",
      kind: "rate-limit",
      label: input.rateLimit.rules === 1 && first ? `Rate limit · ${first.events}/${first.window}` : `Rate limit · ${input.rateLimit.rules} rules`,
      title: `${input.rateLimit.rules} rate limiting ${input.rateLimit.rules === 1 ? "rule applies" : "rules apply"}`,
    });
  }
  if (input.geo) {
    const { label, title } = geoLabel(input.geo);
    pills.push({ key: "geo", kind: "geo", label, title });
  }
  return pills;
}

// ── Certificates ────────────────────────────────────────────────────────

/** A host's certificate as the list shows it. */
export type HostCertificate =
  /** The reader may not read certificates: only how the host gets one. */
  | { visible: false; automatic: boolean }
  | {
      visible: true;
      kind: CertificateKind;
      /** The certificate's name (imported and managed entries). */
      name: string | null;
      daysLeft: number | null;
      validTo: string | null;
      issuer: string | null;
      renewal: RenewalState;
      /** Imported or managed certificate entry, for a link to it. */
      certificateId: number | null;
    };

export type CertificateTone = "ok" | "warn" | "bad" | "off";

/** How urgent a certificate looks: red when expired or failing, amber in its renewal window. */
export function certificateTone(certificate: HostCertificate): CertificateTone {
  if (!certificate.visible) return "off";
  switch (certificate.renewal) {
    case "expired":
    case "overdue":
      return "bad";
    case "due":
    case "replace_soon":
      return "warn";
    case "inactive":
    case "unknown":
      return "off";
    default:
      return certificate.daysLeft !== null && certificate.daysLeft <= 30 ? "warn" : "ok";
  }
}

export const RENEWAL_LABELS: Record<RenewalState, string> = {
  scheduled: "renews automatically",
  due: "renewing now",
  overdue: "renewal failing",
  expired: "expired",
  manual: "replaced by hand",
  replace_soon: "replace soon",
  unknown: "not read yet",
  inactive: "host disabled",
};

// ── Attention ───────────────────────────────────────────────────────────

export type AttentionTone = "bad" | "warn";

/** Something about a host that needs a look, most severe first in HostListRow.attention. */
export type HostAttention =
  | {
      kind: "error_burst";
      tone: AttentionTone;
      /** The most frequent 5xx status of the burst (0 when unknown). */
      status: number;
      count: number;
      /** Requests in the burst's minutes, 5xx included. */
      requests: number;
      /** Unix seconds of the first and last 5xx. */
      start: number;
      end: number;
      ongoing: boolean;
      method: string;
      path: string;
    }
  | { kind: "error_rate"; tone: AttentionTone; rate: number; errors: number; requests: number }
  | { kind: "mitigation_spike"; tone: AttentionTone; count: number; baseline: number; factor: number | null; outcome: string }
  | { kind: "certificate"; tone: AttentionTone; state: RenewalState; daysLeft: number | null };

/** A 5xx share at or above this over 24 hours (with at least HIGH_ERROR_RATE_MIN_REQUESTS requests) needs attention. */
export const HIGH_ERROR_RATE = 0.05;
export const HIGH_ERROR_RATE_MIN_REQUESTS = 20;

export type TimeFormatter = (unixMs: number) => string;

const STATUS_TEXT: Record<number, string> = {
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};

/** "502 Bad Gateway", or the bare code. */
export function statusText(status: number): string {
  return STATUS_TEXT[status] ? `${status} ${STATUS_TEXT[status]}` : String(status);
}

function percentText(rate: number): string {
  const percent = rate * 100;
  return `${percent < 1 ? percent.toFixed(2) : percent.toFixed(1)}%`;
}

/** The status column's text for one attention item, e.g. "501 burst at 09:02". */
export function attentionLabel(item: HostAttention, time: TimeFormatter): string {
  switch (item.kind) {
    case "error_burst": {
      const what = item.status > 0 ? `${item.status} burst` : "5xx burst";
      return item.ongoing ? `${what} since ${time(item.start * 1000)}` : `${what} at ${time(item.start * 1000)}`;
    }
    case "error_rate":
      return `5xx at ${percentText(item.rate)}`;
    case "mitigation_spike":
      return item.factor !== null ? `Blocked traffic ${Math.round(item.factor)}× usual` : "Blocked traffic spike";
    case "certificate":
      if (item.state === "expired") return "Certificate expired";
      if (item.state === "overdue") return "Certificate renewal failing";
      return item.daysLeft !== null ? `Certificate expires in ${item.daysLeft} ${item.daysLeft === 1 ? "day" : "days"}` : "Certificate expires soon";
  }
}

const TONE_RANK: Record<AttentionTone, number> = { bad: 0, warn: 1 };

export function sortAttention(items: HostAttention[]): HostAttention[] {
  return [...items].sort((a, b) => TONE_RANK[a.tone] - TONE_RANK[b.tone]);
}

/** The certificate states that need someone to act (Caddy renewing on schedule does not). */
export function certificateAttention(certificate: HostCertificate): HostAttention | null {
  if (!certificate.visible) return null;
  const { renewal, daysLeft } = certificate;
  if (renewal === "expired" || renewal === "overdue") return { kind: "certificate", tone: "bad", state: renewal, daysLeft };
  if (renewal === "replace_soon") return { kind: "certificate", tone: daysLeft !== null && daysLeft < 7 ? "bad" : "warn", state: renewal, daysLeft };
  return null;
}

// ── Rows ────────────────────────────────────────────────────────────────

export type HostTraffic = {
  requests: number;
  errors5xx: number;
  /** 0 to 1. */
  errorRate5xx: number;
  mitigated: number;
  bytes: number;
};

export type HostState = "healthy" | "attention" | "pending" | "disabled";

/** One proxy host as the list shows it. */
export type HostListRow = {
  id: number;
  name: string;
  domains: string[];
  upstreams: string[];
  enabled: boolean;
  tags: string[];
  createdAt: string;
  state: HostState;
  /** Most severe first; empty when nothing needs attention (always empty for disabled hosts). */
  attention: HostAttention[];
  /** A change to the host waiting for approval (ee/approvals). */
  pendingChangeRequestId: number | null;
  /** Requests in the last 24 hours; null when the reader may not read analytics. */
  traffic: HostTraffic | null;
  wafMode: WafEffectiveMode;
  protections: HostProtection[];
  certificate: HostCertificate;
};

/** Disabled first wins, then what needs attention, then a change waiting for approval. */
export function hostState(enabled: boolean, attention: readonly HostAttention[], pendingChangeRequestId: number | null): HostState {
  if (!enabled) return "disabled";
  if (attention.length > 0) return "attention";
  if (pendingChangeRequestId !== null) return "pending";
  return "healthy";
}

// ── Search, filters and sort ────────────────────────────────────────────

export const STATUS_FILTERS = ["all", "attention", "disabled"] as const;
export type StatusFilter = (typeof STATUS_FILTERS)[number];

export const SORT_KEYS = PROXY_HOST_SORT_KEYS;
export type SortKey = ProxyHostSortKey;
export type SortDir = SortDirection;

/** Sort keys of the earlier list, still accepted in links. */
const LEGACY_SORT_KEYS: Record<string, SortKey> = {
  domains: "host",
  upstreams: "host",
  enabled: "status",
  createdAt: "created",
};

export const DEFAULT_SORT_DIR: Record<SortKey, SortDir> = {
  requests: "desc",
  host: "asc",
  name: "asc",
  status: "asc",
  errors: "desc",
  created: "desc",
};

export const SORT_LABELS: Record<SortKey, string> = {
  requests: "requests in 24 hours",
  host: "host name",
  name: "name",
  status: "status",
  errors: "5xx rate",
  created: "date added",
};

/** How the list is laid out: one run of hosts, or a section per tag. */
export const GROUP_BYS = ["none", "tag"] as const;
export type GroupBy = (typeof GROUP_BYS)[number];

export type HostListQuery = {
  search: string;
  status: StatusFilter;
  protection: ProtectionFilter | null;
  tags: string[];
  sortBy: SortKey;
  sortDir: SortDir;
  groupBy: GroupBy;
  page: number;
};

type RawParams = Record<string, string | string[] | undefined>;

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * The list's query from the page's search parameters. Sorting by requests
 * needs analytics; without it the list sorts by host name.
 */
export function parseHostListQuery(
  params: RawParams,
  analytics: boolean,
  preferredSort: { key: SortKey; dir: SortDir } | null = null
): HostListQuery {
  const search = (first(params.search) ?? "").trim().slice(0, 200);
  const statusParam = first(params.status);
  const status: StatusFilter = statusParam === "attention" || statusParam === "disabled" ? statusParam : "all";
  const protectionParam = first(params.protection);
  const protection = isProtectionFilter(protectionParam) ? protectionParam : null;
  const rawTags = params.tag;
  const tags = [...new Set((Array.isArray(rawTags) ? rawTags : rawTags ? [rawTags] : []).map((tag) => tag.trim().toLowerCase()).filter(Boolean))].slice(0, 20);
  const sortParam = first(params.sortBy) ?? "";
  const dirParam = first(params.sortDir);
  const usePreference = sortParam === "" && dirParam === undefined && preferredSort !== null;
  const preferredKey =
    usePreference &&
    preferredSort &&
    (analytics || (preferredSort.key !== "requests" && preferredSort.key !== "errors"))
      ? preferredSort.key
      : null;
  let sortBy: SortKey = (SORT_KEYS as readonly string[]).includes(sortParam)
    ? (sortParam as SortKey)
    : LEGACY_SORT_KEYS[sortParam] ?? preferredKey ?? (analytics ? "requests" : "host");
  if (!analytics && (sortBy === "requests" || sortBy === "errors")) sortBy = "host";
  const sortDir: SortDir =
    dirParam === "asc" || dirParam === "desc"
      ? dirParam
      : preferredKey === sortBy && preferredSort
        ? preferredSort.dir
        : DEFAULT_SORT_DIR[sortBy];
  const page = Math.max(1, Math.min(100_000, parseInt(first(params.page) ?? "1", 10) || 1));
  const groupBy: GroupBy = first(params.group) === "tag" ? "tag" : "none";
  return { search, status, protection, tags, sortBy, sortDir, groupBy, page };
}

/** Name, domains, upstreams and tags, case-insensitively. */
export function matchesHostSearch(row: Pick<HostListRow, "name" | "domains" | "upstreams" | "tags">, search: string): boolean {
  const needle = search.trim().toLowerCase();
  if (!needle) return true;
  return (
    row.name.toLowerCase().includes(needle) ||
    row.domains.some((domain) => domain.toLowerCase().includes(needle)) ||
    row.upstreams.some((upstream) => upstream.toLowerCase().includes(needle)) ||
    row.tags.some((tag) => tag.includes(needle))
  );
}

export function matchesProtection(row: Pick<HostListRow, "protections" | "wafMode">, filter: ProtectionFilter | null): boolean {
  if (filter === null) return true;
  if (filter === "waf_off") return row.wafMode === "off";
  if (filter === "none") return row.protections.length === 0;
  return row.protections.some((protection) => protection.key === filter);
}

/** Hosts carrying any of `tags`. */
export function matchesTags(row: Pick<HostListRow, "tags">, tags: readonly string[]): boolean {
  return tags.length === 0 || row.tags.some((tag) => tags.includes(tag));
}

export function matchesStatus(row: Pick<HostListRow, "state">, status: StatusFilter): boolean {
  if (status === "attention") return row.state === "attention";
  if (status === "disabled") return row.state === "disabled";
  return true;
}

const STATE_RANK: Record<HostState, number> = { attention: 0, pending: 1, healthy: 2, disabled: 3 };

function stateRank(row: HostListRow): number {
  // Within "attention", red before amber.
  return STATE_RANK[row.state] * 2 + (row.state === "attention" && row.attention[0]?.tone === "warn" ? 1 : 0);
}

export function primaryDomain(row: Pick<HostListRow, "domains" | "name">): string {
  return row.domains[0] ?? row.name;
}

/**
 * The section a host belongs to when the list is grouped by tag: the first of
 * its tags that the tag filter selected (all of its tags when none is), which
 * is the alphabetically first as tags are stored sorted. Null without tags.
 */
export function hostGroupOf(row: Pick<HostListRow, "tags">, filterTags: readonly string[] = []): string | null {
  const candidates = filterTags.length > 0 ? row.tags.filter((tag) => filterTags.includes(tag)) : row.tags;
  return candidates[0] ?? null;
}

/**
 * Sorts the list. Grouped by tag, the sections come first in alphabetical
 * order (hosts without a tag last) and `sortBy` orders the hosts inside each.
 */
export function sortHostRows(
  rows: readonly HostListRow[],
  sortBy: SortKey,
  sortDir: SortDir,
  groupBy: GroupBy = "none",
  filterTags: readonly string[] = []
): HostListRow[] {
  const byHost = (a: HostListRow, b: HostListRow) => primaryDomain(a).localeCompare(primaryDomain(b)) || a.id - b.id;
  const compare: Record<SortKey, (a: HostListRow, b: HostListRow) => number> = {
    requests: (a, b) => (a.traffic?.requests ?? 0) - (b.traffic?.requests ?? 0),
    errors: (a, b) => (a.traffic?.errorRate5xx ?? 0) - (b.traffic?.errorRate5xx ?? 0),
    status: (a, b) => stateRank(a) - stateRank(b),
    created: (a, b) => a.createdAt.localeCompare(b.createdAt),
    host: byHost,
    name: (a, b) => a.name.localeCompare(b.name),
  };
  const sign = sortDir === "asc" ? 1 : -1;
  const byGroup = (a: HostListRow, b: HostListRow) => {
    if (groupBy !== "tag") return 0;
    const ga = hostGroupOf(a, filterTags);
    const gb = hostGroupOf(b, filterTags);
    if (ga === gb) return 0;
    if (ga === null) return 1;
    if (gb === null) return -1;
    return ga < gb ? -1 : 1;
  };
  return [...rows].sort((a, b) => byGroup(a, b) || sign * compare[sortBy](a, b) || byHost(a, b));
}
