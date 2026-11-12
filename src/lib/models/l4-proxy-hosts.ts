import { appDb, nowIso, toIso } from "../db";
import { applyCaddyConfig } from "../caddy";
import { CaddyApplyError } from "../caddy-apply-error";
import { RESERVED_L4_PORTS } from "../l4-reserved-ports";
import { dialAddressPort } from "../caddy-utils";
import { validateL4CaddyScalars } from "../caddy-input-validation";
import { ApiValidationError } from "../api-errors";
import { logAuditEvent } from "../audit";
import { l4ProxyHosts } from "../db/schema";
import { and, eq, count, or, type SQL } from "drizzle-orm";
import { brandName } from "@/ee/white-label/store";
import { normalizeTags, parseStoredTags, serializeTags } from "../host-tags";
import { tagsMatchAny } from "../host-tag-filter";
import { assertHostCreateApproved, assertHostDeleteApproved, assertHostUpdateApproved } from "@/ee/approvals/guard";
import { asc, containsText, desc, first } from "@/src/lib/db/ops";
import { applyOrUndo, caddyAcceptedLastApply } from "../rejected-apply";

export type L4Protocol = "tcp" | "udp";
export type L4MatcherType = "none" | "tls_sni" | "http_host" | "proxy_protocol";
export type L4ProxyProtocolVersion = "v1" | "v2";

export type L4LoadBalancingPolicy = "random" | "round_robin" | "least_conn" | "ip_hash" | "first";

export type L4LoadBalancerActiveHealthCheck = {
  enabled: boolean;
  port: number | null;
  interval: string | null;
  timeout: string | null;
};

export type L4LoadBalancerPassiveHealthCheck = {
  enabled: boolean;
  failDuration: string | null;
  maxFails: number | null;
};

export type L4LoadBalancerConfig = {
  enabled: boolean;
  policy: L4LoadBalancingPolicy;
  tryDuration: string | null;
  tryInterval: string | null;
  activeHealthCheck: L4LoadBalancerActiveHealthCheck | null;
  passiveHealthCheck: L4LoadBalancerPassiveHealthCheck | null;
};

export type L4DnsResolverConfig = {
  enabled: boolean;
  resolvers: string[];
  fallbacks: string[];
  timeout: string | null;
};

export type L4UpstreamDnsResolutionConfig = {
  enabled: boolean | null;
  family: "ipv6" | "ipv4" | "both" | null;
};

type L4LoadBalancerActiveHealthCheckMeta = {
  enabled?: boolean;
  port?: number;
  interval?: string;
  timeout?: string;
};

type L4LoadBalancerPassiveHealthCheckMeta = {
  enabled?: boolean;
  fail_duration?: string;
  max_fails?: number;
};

type L4LoadBalancerMeta = {
  enabled?: boolean;
  policy?: string;
  try_duration?: string;
  try_interval?: string;
  active_health_check?: L4LoadBalancerActiveHealthCheckMeta;
  passive_health_check?: L4LoadBalancerPassiveHealthCheckMeta;
};

type L4DnsResolverMeta = {
  enabled?: boolean;
  resolvers?: string[];
  fallbacks?: string[];
  timeout?: string;
};

type L4UpstreamDnsResolutionMeta = {
  enabled?: boolean;
  family?: string;
};

export type L4GeoBlockConfig = {
  enabled: boolean;
  block_countries: string[];
  block_continents: string[];
  block_asns: number[];
  block_cidrs: string[];
  block_ips: string[];
  allow_countries: string[];
  allow_continents: string[];
  allow_asns: number[];
  allow_cidrs: string[];
  allow_ips: string[];
};

export type L4GeoBlockMode = "merge" | "override";

export type L4ProxyHostMeta = {
  load_balancer?: L4LoadBalancerMeta;
  dns_resolver?: L4DnsResolverMeta;
  upstream_dns_resolution?: L4UpstreamDnsResolutionMeta;
  geoblock?: L4GeoBlockConfig;
  geoblock_mode?: L4GeoBlockMode;
};

const VALID_L4_LB_POLICIES: L4LoadBalancingPolicy[] = ["random", "round_robin", "least_conn", "ip_hash", "first"];
const VALID_L4_UPSTREAM_DNS_FAMILIES: L4UpstreamDnsResolutionConfig["family"][] = ["ipv6", "ipv4", "both"];

export type L4ProxyHost = {
  id: number;
  name: string;
  protocol: L4Protocol;
  listenAddress: string;
  upstreams: string[];
  matcherType: L4MatcherType;
  matcherValue: string[];
  tlsTermination: boolean;
  proxyProtocolVersion: L4ProxyProtocolVersion | null;
  proxyProtocolReceive: boolean;
  enabled: boolean;
  meta: L4ProxyHostMeta | null;
  loadBalancer: L4LoadBalancerConfig | null;
  dnsResolver: L4DnsResolverConfig | null;
  upstreamDnsResolution: L4UpstreamDnsResolutionConfig | null;
  geoblock: L4GeoBlockConfig | null;
  geoblockMode: L4GeoBlockMode;
  /** Free-form tags (src/lib/host-tags.ts); a custom role can be scoped to them. */
  tags: string[];
  createdAt: string;
  updatedAt: string;
};

export type L4ProxyHostInput = {
  name: string;
  protocol: L4Protocol;
  listenAddress: string;
  upstreams: string[];
  matcherType?: L4MatcherType;
  matcherValue?: string[];
  tlsTermination?: boolean;
  proxyProtocolVersion?: L4ProxyProtocolVersion | null;
  proxyProtocolReceive?: boolean;
  enabled?: boolean;
  meta?: L4ProxyHostMeta | null;
  loadBalancer?: Partial<L4LoadBalancerConfig> | null;
  dnsResolver?: Partial<L4DnsResolverConfig> | null;
  upstreamDnsResolution?: Partial<L4UpstreamDnsResolutionConfig> | null;
  geoblock?: L4GeoBlockConfig | null;
  geoblockMode?: L4GeoBlockMode;
  /** Free-form tags; an array of strings (or a comma-separated string). */
  tags?: string[] | null;
};

const VALID_PROTOCOLS: L4Protocol[] = ["tcp", "udp"];
const VALID_MATCHER_TYPES: L4MatcherType[] = ["none", "tls_sni", "http_host", "proxy_protocol"];
const VALID_PROXY_PROTOCOL_VERSIONS: L4ProxyProtocolVersion[] = ["v1", "v2"];

function safeJsonParse<T>(value: string | null, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function normalizeMetaValue(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function hydrateL4LoadBalancer(meta: L4LoadBalancerMeta | undefined): L4LoadBalancerConfig | null {
  if (!meta) return null;

  const enabled = Boolean(meta.enabled);
  const policy: L4LoadBalancingPolicy =
    meta.policy && VALID_L4_LB_POLICIES.includes(meta.policy as L4LoadBalancingPolicy)
      ? (meta.policy as L4LoadBalancingPolicy)
      : "random";

  const tryDuration = normalizeMetaValue(meta.try_duration ?? null);
  const tryInterval = normalizeMetaValue(meta.try_interval ?? null);

  let activeHealthCheck: L4LoadBalancerActiveHealthCheck | null = null;
  if (meta.active_health_check) {
    activeHealthCheck = {
      enabled: Boolean(meta.active_health_check.enabled),
      port:
        typeof meta.active_health_check.port === "number" &&
        Number.isFinite(meta.active_health_check.port) &&
        meta.active_health_check.port > 0
          ? meta.active_health_check.port
          : null,
      interval: normalizeMetaValue(meta.active_health_check.interval ?? null),
      timeout: normalizeMetaValue(meta.active_health_check.timeout ?? null),
    };
  }

  let passiveHealthCheck: L4LoadBalancerPassiveHealthCheck | null = null;
  if (meta.passive_health_check) {
    passiveHealthCheck = {
      enabled: Boolean(meta.passive_health_check.enabled),
      failDuration: normalizeMetaValue(meta.passive_health_check.fail_duration ?? null),
      maxFails:
        typeof meta.passive_health_check.max_fails === "number" &&
        Number.isFinite(meta.passive_health_check.max_fails) &&
        meta.passive_health_check.max_fails >= 0
          ? meta.passive_health_check.max_fails
          : null,
    };
  }

  return {
    enabled,
    policy,
    tryDuration,
    tryInterval,
    activeHealthCheck,
    passiveHealthCheck,
  };
}

function dehydrateL4LoadBalancer(config: Partial<L4LoadBalancerConfig> | null): L4LoadBalancerMeta | undefined {
  if (!config) return undefined;

  const meta: L4LoadBalancerMeta = {
    enabled: Boolean(config.enabled),
  };

  if (config.policy) {
    meta.policy = config.policy;
  }
  if (config.tryDuration) {
    meta.try_duration = config.tryDuration;
  }
  if (config.tryInterval) {
    meta.try_interval = config.tryInterval;
  }

  if (config.activeHealthCheck) {
    const ahc: L4LoadBalancerActiveHealthCheckMeta = {
      enabled: config.activeHealthCheck.enabled,
    };
    if (config.activeHealthCheck.port !== null && config.activeHealthCheck.port !== undefined) {
      ahc.port = config.activeHealthCheck.port;
    }
    if (config.activeHealthCheck.interval) {
      ahc.interval = config.activeHealthCheck.interval;
    }
    if (config.activeHealthCheck.timeout) {
      ahc.timeout = config.activeHealthCheck.timeout;
    }
    meta.active_health_check = ahc;
  }

  if (config.passiveHealthCheck) {
    const phc: L4LoadBalancerPassiveHealthCheckMeta = {
      enabled: config.passiveHealthCheck.enabled,
    };
    if (config.passiveHealthCheck.failDuration) {
      phc.fail_duration = config.passiveHealthCheck.failDuration;
    }
    if (config.passiveHealthCheck.maxFails !== null && config.passiveHealthCheck.maxFails !== undefined) {
      phc.max_fails = config.passiveHealthCheck.maxFails;
    }
    meta.passive_health_check = phc;
  }

  return meta;
}

function hydrateL4DnsResolver(meta: L4DnsResolverMeta | undefined): L4DnsResolverConfig | null {
  if (!meta) return null;

  const enabled = Boolean(meta.enabled);

  const resolvers = Array.isArray(meta.resolvers)
    ? meta.resolvers.map((r) => (typeof r === "string" ? r.trim() : "")).filter((r) => r.length > 0)
    : [];

  const fallbacks = Array.isArray(meta.fallbacks)
    ? meta.fallbacks.map((r) => (typeof r === "string" ? r.trim() : "")).filter((r) => r.length > 0)
    : [];

  const timeout = normalizeMetaValue(meta.timeout ?? null);

  return {
    enabled,
    resolvers,
    fallbacks,
    timeout,
  };
}

function dehydrateL4DnsResolver(config: Partial<L4DnsResolverConfig> | null): L4DnsResolverMeta | undefined {
  if (!config) return undefined;

  const meta: L4DnsResolverMeta = {
    enabled: Boolean(config.enabled),
  };

  if (config.resolvers && config.resolvers.length > 0) {
    meta.resolvers = [...config.resolvers];
  }
  if (config.fallbacks && config.fallbacks.length > 0) {
    meta.fallbacks = [...config.fallbacks];
  }
  if (config.timeout) {
    meta.timeout = config.timeout;
  }

  return meta;
}

function hydrateL4UpstreamDnsResolution(meta: L4UpstreamDnsResolutionMeta | undefined): L4UpstreamDnsResolutionConfig | null {
  if (!meta) return null;

  const enabled = meta.enabled === undefined ? null : Boolean(meta.enabled);
  const family =
    meta.family && VALID_L4_UPSTREAM_DNS_FAMILIES.includes(meta.family as L4UpstreamDnsResolutionConfig["family"])
      ? (meta.family as L4UpstreamDnsResolutionConfig["family"])
      : null;

  return {
    enabled,
    family,
  };
}

function dehydrateL4UpstreamDnsResolution(
  config: Partial<L4UpstreamDnsResolutionConfig> | null
): L4UpstreamDnsResolutionMeta | undefined {
  if (!config) return undefined;

  const meta: L4UpstreamDnsResolutionMeta = {};
  if (config.enabled !== null && config.enabled !== undefined) {
    meta.enabled = Boolean(config.enabled);
  }
  if (config.family && VALID_L4_UPSTREAM_DNS_FAMILIES.includes(config.family)) {
    meta.family = config.family;
  }

  return Object.keys(meta).length > 0 ? meta : undefined;
}

type L4ProxyHostRow = typeof l4ProxyHosts.$inferSelect;

function parseL4ProxyHost(row: L4ProxyHostRow): L4ProxyHost {
  const meta = safeJsonParse<L4ProxyHostMeta>(row.meta, {});
  return {
    id: row.id,
    name: row.name,
    protocol: row.protocol as L4Protocol,
    listenAddress: row.listenAddress,
    upstreams: safeJsonParse<string[]>(row.upstreams, []),
    matcherType: (row.matcherType as L4MatcherType) || "none",
    matcherValue: safeJsonParse<string[]>(row.matcherValue, []),
    tlsTermination: row.tlsTermination,
    proxyProtocolVersion: row.proxyProtocolVersion as L4ProxyProtocolVersion | null,
    proxyProtocolReceive: row.proxyProtocolReceive,
    enabled: row.enabled,
    meta: Object.keys(meta).length > 0 ? meta : null,
    loadBalancer: hydrateL4LoadBalancer(meta.load_balancer),
    dnsResolver: hydrateL4DnsResolver(meta.dns_resolver),
    upstreamDnsResolution: hydrateL4UpstreamDnsResolution(meta.upstream_dns_resolution),
    geoblock: meta.geoblock?.enabled ? meta.geoblock : null,
    geoblockMode: meta.geoblock_mode ?? "merge",
    tags: parseStoredTags(row.tags),
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!,
  };
}

// Reserved ports (80/443/2019) are defined in ./l4-reserved-ports — kept
// re-exported here for API surface convenience.
export {
  RESERVED_L4_PORTS,
  extractL4ListenPort,
  isReservedL4Port,
} from "../l4-reserved-ports";

function validateL4Input(input: L4ProxyHostInput | Partial<L4ProxyHostInput>, isCreate: boolean) {
  if (isCreate) {
    if (!input.name?.trim()) {
      throw new ApiValidationError("Name is required");
    }
    if (!input.protocol || !VALID_PROTOCOLS.includes(input.protocol)) {
      throw new ApiValidationError("Protocol must be 'tcp' or 'udp'");
    }
    if (!input.listenAddress?.trim()) {
      throw new ApiValidationError("Listen address is required");
    }
    if (!input.upstreams || input.upstreams.length === 0) {
      throw new ApiValidationError("At least one upstream must be specified");
    }
  }

  if (input.listenAddress !== undefined) {
    const addr = input.listenAddress.trim();
    // Must be :PORT or HOST:PORT
    const portMatch = addr.match(/:(\d+)$/);
    if (!portMatch) {
      throw new ApiValidationError("Listen address must be in format ':PORT' or 'HOST:PORT'");
    }
    const port = parseInt(portMatch[1], 10);
    if (port < 1 || port > 65535) {
      throw new ApiValidationError("Port must be between 1 and 65535");
    }
    if ((RESERVED_L4_PORTS as readonly number[]).includes(port)) {
      throw new ApiValidationError(
        `Port ${port} is reserved for ${brandName()}'s own Caddy listeners (HTTP 80/443, admin API 2019) and cannot be used for L4 proxy hosts. Choose a different port.`
      );
    }
  }

  if (input.protocol !== undefined && !VALID_PROTOCOLS.includes(input.protocol)) {
    throw new ApiValidationError("Protocol must be 'tcp' or 'udp'");
  }

  if (input.matcherType !== undefined && !VALID_MATCHER_TYPES.includes(input.matcherType)) {
    throw new ApiValidationError(`Matcher type must be one of: ${VALID_MATCHER_TYPES.join(", ")}`);
  }

  if (input.matcherType === "tls_sni" || input.matcherType === "http_host") {
    if (!input.matcherValue || input.matcherValue.length === 0) {
      throw new ApiValidationError("Matcher value is required for TLS SNI and HTTP Host matchers");
    }
  }

  if (input.tlsTermination && input.protocol === "udp") {
    throw new ApiValidationError("TLS termination is only supported with TCP protocol");
  }

  if (input.proxyProtocolVersion !== undefined && input.proxyProtocolVersion !== null) {
    if (!VALID_PROXY_PROTOCOL_VERSIONS.includes(input.proxyProtocolVersion)) {
      throw new ApiValidationError("Proxy protocol version must be 'v1' or 'v2'");
    }
  }

  if (input.upstreams) {
    for (const upstream of input.upstreams) {
      if (!upstream.includes(":")) {
        throw new ApiValidationError(`Upstream '${upstream}' must be in 'host:port' format`);
      }
      // Caddy's layer4 app checks upstream ports when it loads the
      // configuration: a bad one would make every later apply fail.
      // Placeholders are left to Caddy (only administrators may use them).
      const port = dialAddressPort(upstream);
      if (!upstream.includes("{") && (port === null || !/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535)) {
        throw new ApiValidationError(`Upstream '${upstream}' must end in a port between 1 and 65535`);
      }
    }
  }

  validateL4CaddyScalars(input);
  // A raw meta object is stored as given: check what it holds the same way.
  if (input.meta !== undefined && input.meta !== null) {
    if (typeof input.meta !== "object" || Array.isArray(input.meta)) {
      throw new ApiValidationError("meta must be an object");
    }
    validateL4CaddyScalars({
      loadBalancer: hydrateL4LoadBalancer(input.meta.load_balancer),
      geoblock: input.meta.geoblock,
    });
  }
}

/** The L4 hosts a tag scope covers: null for every host (see proxyHostScopeCondition). */
export function l4ProxyHostScopeCondition(scopeTags: readonly string[] | null | undefined): SQL | undefined {
  return scopeTags ? tagsMatchAny(l4ProxyHosts.tags, scopeTags) : undefined;
}

function l4SearchCondition(search?: string): SQL | undefined {
  return search
    ? or(
        containsText(l4ProxyHosts.name, search),
        containsText(l4ProxyHosts.listenAddress, search),
        containsText(l4ProxyHosts.upstreams, search),
        containsText(l4ProxyHosts.tags, search)
      )
    : undefined;
}

export async function listL4ProxyHosts(scopeTags?: readonly string[] | null): Promise<L4ProxyHost[]> {
  const hosts = await appDb
    .select()
    .from(l4ProxyHosts)
    .where(l4ProxyHostScopeCondition(scopeTags))
    .orderBy(desc(l4ProxyHosts.createdAt), desc(l4ProxyHosts.id));
  return hosts.map(parseL4ProxyHost);
}

export async function countL4ProxyHosts(search?: string, scopeTags?: readonly string[] | null): Promise<number> {
  const where = and(l4SearchCondition(search), l4ProxyHostScopeCondition(scopeTags));
  const [row] = await appDb.select({ value: count() }).from(l4ProxyHosts).where(where);
  return row?.value ?? 0;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const L4_SORT_COLUMNS: Record<string, any> = {
  name: l4ProxyHosts.name,
  protocol: l4ProxyHosts.protocol,
  listenAddress: l4ProxyHosts.listenAddress,
  upstreams: l4ProxyHosts.upstreams,
  enabled: l4ProxyHosts.enabled,
  createdAt: l4ProxyHosts.createdAt,
};

export async function listL4ProxyHostsPaginated(
  limit: number,
  offset: number,
  search?: string,
  sortBy?: string,
  sortDir?: "asc" | "desc",
  scopeTags?: readonly string[] | null
): Promise<L4ProxyHost[]> {
  const where = and(l4SearchCondition(search), l4ProxyHostScopeCondition(scopeTags));
  const col = (sortBy && L4_SORT_COLUMNS[sortBy]) || l4ProxyHosts.createdAt;
  const dir = sortDir === "asc" ? asc : desc;
  const hosts = await appDb
    .select()
    .from(l4ProxyHosts)
    .where(where)
    // The id last, so that every page is the same on every database.
    .orderBy(dir(col), dir(l4ProxyHosts.id))
    .limit(limit)
    .offset(offset);
  return hosts.map(parseL4ProxyHost);
}

export async function createL4ProxyHost(input: L4ProxyHostInput, actorUserId: number) {
  validateL4Input(input, true);
  const tags = normalizeTags(input.tags);
  // Change approvals (ee): a host a policy protects is only created through an approved change request.
  await assertHostCreateApproved("l4_proxy_host", input.name, tags);
  const acceptedBefore = await caddyAcceptedLastApply();

  const now = nowIso();
  const [record] = await appDb
    .insert(l4ProxyHosts)
    .values({
      name: input.name.trim(),
      protocol: input.protocol,
      listenAddress: input.listenAddress.trim(),
      upstreams: JSON.stringify(Array.from(new Set(input.upstreams.map((u) => u.trim())))),
      matcherType: input.matcherType ?? "none",
      matcherValue: input.matcherValue ? JSON.stringify(input.matcherValue.map((v) => v.trim()).filter(Boolean)) : null,
      tlsTermination: input.tlsTermination ?? false,
      proxyProtocolVersion: input.proxyProtocolVersion ?? null,
      proxyProtocolReceive: input.proxyProtocolReceive ?? false,
      ownerUserId: actorUserId,
      meta: (() => {
        const meta: L4ProxyHostMeta = { ...(input.meta ?? {}) };
        if (input.loadBalancer) meta.load_balancer = dehydrateL4LoadBalancer(input.loadBalancer);
        if (input.dnsResolver) meta.dns_resolver = dehydrateL4DnsResolver(input.dnsResolver);
        if (input.upstreamDnsResolution) meta.upstream_dns_resolution = dehydrateL4UpstreamDnsResolution(input.upstreamDnsResolution);
        if (input.geoblock) meta.geoblock = input.geoblock;
        if (input.geoblockMode && input.geoblockMode !== "merge") meta.geoblock_mode = input.geoblockMode;
        return Object.keys(meta).length > 0 ? JSON.stringify(meta) : null;
      })(),
      enabled: input.enabled ?? true,
      tags: serializeTags(tags),
      createdAt: now,
      updatedAt: now,
    })
    .returning();

  if (!record) {
    throw new Error("Failed to create L4 proxy host");
  }

  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "l4_proxy_host",
    entityId: record.id,
    summary: `Created L4 proxy host ${input.name}`,
    data: input,
  });

  try {
    await applyOrUndo({
      actorUserId,
      acceptedBefore,
      what: "L4 host",
      // A host Caddy rejects is not kept (see rejected-apply.ts).
      undo: async () => {
        await appDb.delete(l4ProxyHosts).where(eq(l4ProxyHosts.id, record.id));
        await logAuditEvent({
          userId: actorUserId,
          action: "delete",
          entityType: "l4_proxy_host",
          entityId: record.id,
          summary: `Removed L4 proxy host ${input.name} again: Caddy rejected the configuration with it`,
        });
      },
    });
  } catch (error) {
    // The host is stored: say which one, so the caller can tell it was saved but is not live yet.
    if (error instanceof CaddyApplyError) error.l4ProxyHostId = record.id;
    throw error;
  }
  return (await getL4ProxyHost(record.id))!;
}

export async function getL4ProxyHost(id: number): Promise<L4ProxyHost | null> {
  const host = await appDb.query.l4ProxyHosts.findFirst({
    where: (table, { eq }) => eq(table.id, id),
  });
  return host ? parseL4ProxyHost(host) : null;
}

export async function updateL4ProxyHost(id: number, input: Partial<L4ProxyHostInput>, actorUserId: number) {
  const existing = await getL4ProxyHost(id);
  if (!existing) {
    throw new Error("L4 proxy host not found");
  }
  await assertHostUpdateApproved("l4_proxy_host", existing, input);

  // For validation, merge with existing to check cross-field constraints
  const merged = {
    protocol: input.protocol ?? existing.protocol,
    tlsTermination: input.tlsTermination ?? existing.tlsTermination,
    matcherType: input.matcherType ?? existing.matcherType,
    matcherValue: input.matcherValue ?? existing.matcherValue,
  };
  if (merged.tlsTermination && merged.protocol === "udp") {
    throw new Error("TLS termination is only supported with TCP protocol");
  }
  if ((merged.matcherType === "tls_sni" || merged.matcherType === "http_host") && merged.matcherValue.length === 0) {
    throw new Error("Matcher value is required for TLS SNI and HTTP Host matchers");
  }

  validateL4Input(input, false);
  const tags = input.tags !== undefined ? normalizeTags(input.tags) : undefined;
  // What is put back if Caddy rejects the configuration with this change.
  const acceptedBefore = await caddyAcceptedLastApply();
  const previousRow = await first(appDb.select().from(l4ProxyHosts).where(eq(l4ProxyHosts.id, id)).limit(1));

  const now = nowIso();
  await appDb
    .update(l4ProxyHosts)
    .set({
      ...(tags !== undefined ? { tags: serializeTags(tags) } : {}),
      ...(input.name !== undefined ? { name: input.name.trim() } : {}),
      ...(input.protocol !== undefined ? { protocol: input.protocol } : {}),
      ...(input.listenAddress !== undefined ? { listenAddress: input.listenAddress.trim() } : {}),
      ...(input.upstreams !== undefined
        ? { upstreams: JSON.stringify(Array.from(new Set(input.upstreams.map((u) => u.trim())))) }
        : {}),
      ...(input.matcherType !== undefined ? { matcherType: input.matcherType } : {}),
      ...(input.matcherValue !== undefined
        ? { matcherValue: JSON.stringify(input.matcherValue.map((v) => v.trim()).filter(Boolean)) }
        : {}),
      ...(input.tlsTermination !== undefined ? { tlsTermination: input.tlsTermination } : {}),
      ...(input.proxyProtocolVersion !== undefined ? { proxyProtocolVersion: input.proxyProtocolVersion } : {}),
      ...(input.proxyProtocolReceive !== undefined ? { proxyProtocolReceive: input.proxyProtocolReceive } : {}),
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
      ...(() => {
        const hasMetaChanges =
          input.meta !== undefined ||
          input.loadBalancer !== undefined ||
          input.dnsResolver !== undefined ||
          input.upstreamDnsResolution !== undefined ||
          input.geoblock !== undefined ||
          input.geoblockMode !== undefined;
        if (!hasMetaChanges) return {};

        // Start from existing meta
        const existingMeta: L4ProxyHostMeta = {
          ...(existing.loadBalancer ? { load_balancer: dehydrateL4LoadBalancer(existing.loadBalancer) } : {}),
          ...(existing.dnsResolver ? { dns_resolver: dehydrateL4DnsResolver(existing.dnsResolver) } : {}),
          ...(existing.upstreamDnsResolution ? { upstream_dns_resolution: dehydrateL4UpstreamDnsResolution(existing.upstreamDnsResolution) } : {}),
          ...(existing.geoblock ? { geoblock: existing.geoblock } : {}),
          ...(existing.geoblockMode !== "merge" ? { geoblock_mode: existing.geoblockMode } : {}),
        };

        // Apply direct meta override if provided
        const meta: L4ProxyHostMeta = input.meta !== undefined ? { ...(input.meta ?? {}) } : { ...existingMeta };

        // Apply structured field overrides
        if (input.loadBalancer !== undefined) {
          const lb = dehydrateL4LoadBalancer(input.loadBalancer);
          if (lb) {
            meta.load_balancer = lb;
          } else {
            delete meta.load_balancer;
          }
        }
        if (input.dnsResolver !== undefined) {
          const dr = dehydrateL4DnsResolver(input.dnsResolver);
          if (dr) {
            meta.dns_resolver = dr;
          } else {
            delete meta.dns_resolver;
          }
        }
        if (input.upstreamDnsResolution !== undefined) {
          const udr = dehydrateL4UpstreamDnsResolution(input.upstreamDnsResolution);
          if (udr) {
            meta.upstream_dns_resolution = udr;
          } else {
            delete meta.upstream_dns_resolution;
          }
        }
        if (input.geoblock !== undefined) {
          if (input.geoblock) {
            meta.geoblock = input.geoblock;
          } else {
            delete meta.geoblock;
          }
        }
        if (input.geoblockMode !== undefined) {
          if (input.geoblockMode !== "merge") {
            meta.geoblock_mode = input.geoblockMode;
          } else {
            delete meta.geoblock_mode;
          }
        }

        return { meta: Object.keys(meta).length > 0 ? JSON.stringify(meta) : null };
      })(),
      updatedAt: now,
    })
    .where(eq(l4ProxyHosts.id, id));

  await logAuditEvent({
    userId: actorUserId,
    action: "update",
    entityType: "l4_proxy_host",
    entityId: id,
    summary: `Updated L4 proxy host ${input.name ?? existing.name}`,
    data: input,
  });

  await applyOrUndo({
    actorUserId,
    acceptedBefore,
    what: "L4 host",
    undo: async () => {
      if (!previousRow) return;
      const { id: _id, ...columns } = previousRow;
      void _id;
      await appDb.update(l4ProxyHosts).set(columns).where(eq(l4ProxyHosts.id, id));
      await logAuditEvent({
        userId: actorUserId,
        action: "update",
        entityType: "l4_proxy_host",
        entityId: id,
        summary: `Undid the update of L4 proxy host ${existing.name}: Caddy rejected the configuration with it`,
      });
    },
  });
  return (await getL4ProxyHost(id))!;
}

export async function deleteL4ProxyHost(id: number, actorUserId: number) {
  const existing = await getL4ProxyHost(id);
  if (!existing) {
    throw new Error("L4 proxy host not found");
  }
  await assertHostDeleteApproved("l4_proxy_host", existing);

  await appDb.delete(l4ProxyHosts).where(eq(l4ProxyHosts.id, id));
  await logAuditEvent({
    userId: actorUserId,
    action: "delete",
    entityType: "l4_proxy_host",
    entityId: id,
    summary: `Deleted L4 proxy host ${existing.name}`,
  });
  await applyCaddyConfig();
}
