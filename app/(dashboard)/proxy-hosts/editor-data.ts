/**
 * The data of the host editor pages (/proxy-hosts/new and
 * the tabs of /proxy-hosts/[id]): the host, the pickers its role may use and the
 * context the review shows. Every list is reduced to the fields the editor
 * needs; nothing secret (PEM, keys, password hashes) reaches the client.
 */
import { queryHostWafRules } from "@/src/lib/analytics/security";
import { resolveRange } from "@/src/lib/analytics/range";
import { isAnalyticsEnabled } from "@/src/lib/clickhouse/client";
import { listProxyHosts, type ProxyHost } from "@/src/lib/models/proxy-hosts";
import { listCertificates, type Certificate } from "@/src/lib/models/certificates";
import { listCaCertificates } from "@/src/lib/models/ca-certificates";
import { getBlockedSourcesList, listAccessLists } from "@/src/lib/models/access-lists";
import { listMtlsRoles } from "@/src/lib/models/mtls-roles";
import { listIssuedClientCertificates } from "@/src/lib/models/issued-client-certificates";
import { listUsers } from "@/src/lib/models/user";
import { listGroups } from "@/src/lib/models/groups";
import { getForwardAuthAccessForHost } from "@/src/lib/models/forward-auth";
import { listWafExclusions } from "@/src/lib/models/waf-exclusions";
import { getWafRuleMessages } from "@/src/lib/models/waf-events";
import { queryAuditEvents } from "@/src/lib/models/audit";
import {
  getAuthentikSettings,
  getDnsProviderSettings,
  getForwardAuthSettings,
  getGeoBlockSettings,
  getRateLimitSettings,
  getTrustedProxiesSettings,
  getWafSettings,
  type TrustedProxiesSettings,
} from "@/src/lib/settings";
import { resolveWafTuning } from "@/src/lib/waf-tuning";
import { parsePemInfo } from "@/src/lib/certificate-overview";
import { getProviderDefinition } from "@/src/lib/dns-providers";
import { buildDnsProviderChoices } from "@/src/lib/dns-provider-choice";
import { getManagedCertificateExpiry } from "@/src/lib/managed-certificates";
import { certificateIdsInScope } from "@/src/lib/access-scope";
import { can, scopeTagsFor, type Access } from "@/src/lib/permissions";
import { getHostApprovalContext } from "@/ee/approvals/requests";
import type {
  EditorAccessList,
  EditorCertificate,
  HostEditorData,
  ServedCertificate,
} from "@/src/components/proxy-hosts/editor/types";

/** How long the page waits for Caddy's served certificate (cached for an hour once read). */
const SERVED_CERTIFICATE_WAIT_MS = 800;

/** A certificate as the editor's picker shows it: name, kind, the names it covers and, for imported ones, its expiry. */
export function toEditorCertificate(certificate: Certificate): EditorCertificate {
  const pem = certificate.type === "imported" && certificate.certificatePem ? parsePemInfo(certificate.certificatePem) : null;
  return {
    id: certificate.id,
    name: certificate.name,
    type: certificate.type,
    domains: [...certificate.domainNames],
    expiresAt: pem?.validTo ?? null,
    issuer: pem?.issuer ?? null,
    provider: certificate.type === "managed" && typeof certificate.providerOptions?.provider === "string" ? certificate.providerOptions.provider : null,
  };
}

/**
 * What Caddy serves for the host's saved certificate choice: for the host's
 * names when Caddy manages them (automatic), for the entry's names when the
 * host uses a managed certificate. Imported certificates are read from their PEM.
 */
async function servedCertificate(host: ProxyHost | null, certificates: Certificate[]): Promise<ServedCertificate | null> {
  if (!host) return null;
  let names: string[];
  if (host.certificateId === null) names = host.domains;
  else {
    const chosen = certificates.find((certificate) => certificate.id === host.certificateId);
    if (chosen?.type !== "managed") return null;
    names = chosen.domainNames;
  }
  if (names.length === 0) return null;
  try {
    const found = await getManagedCertificateExpiry(names.slice(0, 20), { waitMs: SERVED_CERTIFICATE_WAIT_MS });
    const entries = [...found.values()];
    if (entries.length === 0) return null;
    const soonest = entries.reduce((a, b) => (a.validTo <= b.validTo ? a : b));
    return { domains: entries.map((entry) => entry.domain), issuer: soonest.issuer, keyType: soonest.keyType, validTo: soonest.validTo };
  } catch {
    return null;
  }
}

/** How Caddy works out the client address, as far as the sign-in bypass depends on it. */
function clientAddressOf(settings: TrustedProxiesSettings | null): HostEditorData["clientAddress"] {
  const proxiesTrusted = (settings?.ranges ?? []).some((range) => range.trim().length > 0);
  const headers = (settings?.client_ip_headers ?? []).map((header) => header.trim().toLowerCase()).filter(Boolean);
  const readsForwardedFor = headers.length === 0 || headers.includes("x-forwarded-for");
  return { proxiesTrusted, forwardedForForgeable: proxiesTrusted && readsForwardedFor && !settings?.strict };
}

/** What the pickers may list: everything for administrators, otherwise what the role can read plus what the visible hosts use. */
async function pickerVisibility(access: Access, visibleHosts: ProxyHost[]) {
  if (access.isAdmin) return { certificate: () => true, accessList: () => true, trustAnchors: true };
  const usedCertificates = new Set(visibleHosts.map((host) => host.certificateId).filter((id): id is number => id !== null));
  const usedAccessLists = new Set(visibleHosts.map((host) => host.accessListId).filter((id): id is number => id !== null));
  const readable = can(access, "certificates:read") ? await certificateIdsInScope(access) : new Set<number>();
  const allAccessLists = can(access, "access_lists:read");
  return {
    certificate: (id: number) => usedCertificates.has(id) || readable === null || readable.has(id),
    accessList: (id: number) => allAccessLists || usedAccessLists.has(id),
    trustAnchors: can(access, "certificates:read") && scopeTagsFor(access, "certificates") === null,
  };
}

async function lastSaved(access: Access, host: ProxyHost | null): Promise<HostEditorData["lastSaved"]> {
  if (!host) return null;
  if (!can(access, "audit_log:read")) return { at: host.updatedAt, by: null };
  try {
    const [event] = await queryAuditEvents(
      { entityType: "proxy_host", entityId: host.id },
      { limit: 1, offset: 0 }
    );
    const by = event?.user ? event.user.name ?? null : null;
    return { at: host.updatedAt, by };
  } catch {
    return { at: host.updatedAt, by: null };
  }
}

export async function loadHostEditorData(
  access: Access,
  options: { host: ProxyHost | null; template: ProxyHost | null; initialDomain: string | null }
): Promise<HostEditorData> {
  const { host, template } = options;
  const scope = scopeTagsFor(access, "proxy_hosts");
  const canReadWaf = can(access, "waf:read");

  const [visibleHosts, certificates, accessLists, blockedSources, authentikDefaults, forwardAuthDefaults, wafSettings, rateLimit, geoblock, dns, trustedProxies] =
    await Promise.all([
      listProxyHosts(scope),
      listCertificates(),
      listAccessLists(),
      getBlockedSourcesList().catch(() => null),
      getAuthentikSettings(),
      getForwardAuthSettings(),
      getWafSettings(),
      getRateLimitSettings(),
      getGeoBlockSettings(),
      getDnsProviderSettings(),
      getTrustedProxiesSettings().catch(() => null),
    ]);
  const picker = await pickerVisibility(access, visibleHosts);
  const canChooseUsers = can(access, "users:read");
  const canChooseGroups = can(access, "groups:read");

  // These tables may be missing before their migrations ran; the editor works without them.
  const [caCertificates, mtlsRoles, clientCertificates, users, groups] = await Promise.all([
    picker.trustAnchors ? listCaCertificates().catch(() => []) : Promise.resolve([]),
    picker.trustAnchors ? listMtlsRoles().catch(() => []) : Promise.resolve([]),
    picker.trustAnchors ? listIssuedClientCertificates().catch(() => []) : Promise.resolve([]),
    canChooseUsers ? listUsers().catch(() => []) : Promise.resolve([]),
    canChooseGroups ? listGroups().catch(() => []) : Promise.resolve([]),
  ]);

  const grants = host ? await getForwardAuthAccessForHost(host.id).catch(() => []) : [];
  const exclusions = host ? await listWafExclusions({ proxyHostId: host.id }) : [];
  const ruleIds = [...new Set([...exclusions.map((exclusion) => exclusion.ruleId), ...(template?.waf?.excluded_rule_ids ?? [])])];
  // The rules that hit this host lately: what its Security tab offers to exclude.
  const recent =
    host && canReadWaf && isAnalyticsEnabled()
      ? await queryHostWafRules({ range: resolveRange({ range: "7d" }), domains: host.domains, limit: 12 }).catch(() => null)
      : null;
  const wafRecentRules = recent && recent.status === "ok" ? recent.rules : null;
  const messages = ruleIds.length > 0 && canReadWaf ? await getWafRuleMessages(ruleIds).catch(() => ({})) : {};

  const usage = new Map<number, number>();
  for (const visible of visibleHosts) {
    if (visible.accessListId === null || visible.id === host?.id) continue;
    usage.set(visible.accessListId, (usage.get(visible.accessListId) ?? 0) + 1);
  }
  const editorAccessLists: EditorAccessList[] = accessLists
    .filter((list) => picker.accessList(list.id))
    .map((list) => ({
      id: list.id,
      name: list.name,
      description: list.description,
      rules: list.rules.length,
      members: list.entries.length,
      defaultAction: list.defaultAction === "deny" ? "deny" : "allow",
      otherHosts: usage.get(list.id) ?? 0,
    }));

  const tuning = wafSettings ? resolveWafTuning(wafSettings) : null;

  return {
    mode: host ? "edit" : "create",
    host,
    template,
    initialDomain: options.initialDomain,
    forwardAuthAccess: {
      userIds: grants.filter((entry) => entry.userId !== null).map((entry) => entry.userId!),
      groupIds: grants.filter((entry) => entry.groupId !== null).map((entry) => entry.groupId!),
    },
    certificates: certificates.filter((certificate) => picker.certificate(certificate.id)).map(toEditorCertificate),
    servedCertificate: await servedCertificate(host, certificates),
    clientAddress: clientAddressOf(trustedProxies),
    accessLists: editorAccessLists,
    blockedSourcesActive: Boolean(blockedSources && blockedSources.rules.length > 0),
    caCertificates: caCertificates.map((ca) => ({ id: ca.id, name: ca.name })),
    mtlsRoles: mtlsRoles.map((role) => ({ id: role.id, name: role.name, description: role.description, certificates: role.certificateCount })),
    clientCertificates: clientCertificates.map((cert) => ({
      id: cert.id,
      caId: cert.caCertificateId,
      commonName: cert.commonName,
      validTo: cert.validTo,
      revoked: cert.revokedAt !== null,
    })),
    users: users.map((user) => ({ id: user.id, name: user.name ?? user.username ?? user.email, detail: user.email })),
    groups: groups.map((group) => ({ id: group.id, name: group.name, description: group.description, members: group.members.length })),
    canChooseTrust: picker.trustAnchors,
    canChooseUsers,
    canChooseGroups,
    canChooseAccessLists: access.isAdmin || can(access, "access_lists:read"),
    isAdmin: access.isAdmin,
    authentikDefaults,
    forwardAuthDefaults,
    scopeTags: scope ? [...scope] : [],
    approval: await getHostApprovalContext(access),
    wafGlobal: wafSettings
      ? {
          appliesToAll: Boolean(wafSettings.enabled),
          mode: wafSettings.mode === "Off" || wafSettings.mode === "DetectionOnly" ? wafSettings.mode : "On",
          loadOwaspCrs: Boolean(wafSettings.load_owasp_crs),
          paranoiaLevel: tuning?.paranoiaLevel ?? null,
          inboundThreshold: tuning?.inboundThreshold ?? null,
        }
      : null,
    wafExclusions: exclusions.map((exclusion) => ({
      id: exclusion.id,
      ruleId: exclusion.ruleId,
      wholeHost: !exclusion.path && !exclusion.variable,
      path: exclusion.path,
      pathMatch: exclusion.pathMatch,
      variable: exclusion.variable,
      reason: exclusion.reason,
      createdBy: canReadWaf ? exclusion.createdBy?.name ?? null : null,
      createdAt: exclusion.createdAt,
    })),
    wafRuleMessages: Object.fromEntries(
      Object.entries(messages).filter((entry): entry is [string, string] => typeof entry[1] === "string")
    ) as Record<number, string>,
    canReadWaf,
    canWriteWaf: can(access, "waf:write"),
    wafRecentRules,
    rateLimitDefaults: rateLimit ? { enabled: Boolean(rateLimit.enabled), rules: rateLimit.rules.length } : null,
    geoblockGlobal: geoblock
      ? {
          enabled: Boolean(geoblock.enabled),
          blocks: [geoblock.block_countries, geoblock.block_continents, geoblock.block_asns, geoblock.block_cidrs, geoblock.block_ips].some((rules) => (rules?.length ?? 0) > 0),
        }
      : null,
    dnsProviderConfigured: Boolean(dns?.default && dns.providers[dns.default]),
    dnsChoices: buildDnsProviderChoices(dns, (name) => getProviderDefinition(name)?.displayName ?? name),
    canCreateCertificate: can(access, "certificates:write") && scopeTagsFor(access, "certificates") === null,
    lastSaved: await lastSaved(access, host),
    historyHref: host && can(access, "audit_log:read") ? `/audit-log?search=${encodeURIComponent(host.name)}` : null,
  };
}
