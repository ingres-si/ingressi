import ProxyHostsClient from "./ProxyHostsClient";
import { listProxyHosts, type ProxyHost } from "@/src/lib/models/proxy-hosts";
import { listCertificates } from "@/src/lib/models/certificates";
import { listCaCertificates } from "@/src/lib/models/ca-certificates";
import { listAccessLists } from "@/src/lib/models/access-lists";
import { getAuthentikSettings, getForwardAuthSettings } from "@/src/lib/settings";
import { listMtlsRoles } from "@/src/lib/models/mtls-roles";
import { listIssuedClientCertificates } from "@/src/lib/models/issued-client-certificates";
import { listUsers } from "@/src/lib/models/user";
import { listGroups } from "@/src/lib/models/groups";
import { getForwardAuthAccessForHost } from "@/src/lib/models/forward-auth";
import { requirePermission } from "@/src/lib/auth";
import { can, scopeTagsFor, type Access } from "@/src/lib/permissions";
import { certificateIdsInScope } from "@/src/lib/access-scope";
import { toCertificatePickerOption } from "@/src/lib/certificate-api";
import { loadHostInsights } from "@/src/lib/proxy-host-insights";
import {
  matchesHostSearch,
  matchesProtection,
  matchesStatus,
  matchesTags,
  parseHostListQuery,
  sortHostRows,
  type HostListRow,
  type StatusFilter,
} from "@/src/lib/proxy-host-view";
import { paginate } from "@/src/lib/pagination";
import { getHostApprovalContext } from "@/ee/approvals/requests";
import { getUserPreferences } from "@/src/lib/preferences";
import { parseStoredSortPreference } from "@/src/lib/list-sort-preferences";

export const metadata = { title: "Proxy hosts" };

/** How long the list waits for certificate checks not cached yet; the rest show on the next visit. */
const CERTIFICATE_WAIT_MS = 1500;

interface PageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function ProxyHostsPage({ searchParams }: PageProps) {
  const { access, user } = await requirePermission("proxy_hosts:read");
  // A tag scope limits the list (and the counts) to hosts with one of the role's tags.
  const scope = scopeTagsFor(access, "proxy_hosts");
  const [params, preferences] = await Promise.all([searchParams, getUserPreferences(Number(user.id))]);
  const query = parseHostListQuery(
    params,
    can(access, "analytics:read"),
    parseStoredSortPreference(preferences.proxyHostsSort)
  );

  const [allHosts, certificates, caCertificates, accessLists, authentikDefaults, forwardAuthDefaults] = await Promise.all([
    listProxyHosts(scope),
    listCertificates(),
    listCaCertificates(),
    listAccessLists(),
    getAuthentikSettings(),
    getForwardAuthSettings(),
  ]);
  // These are safe to fail if the RBAC migration hasn't been applied yet
  const [mtlsRoles, issuedClientCerts, allUsers, allGroups] = await Promise.all([
    listMtlsRoles().catch(() => []),
    listIssuedClientCertificates().catch(() => []),
    listUsers().catch(() => []),
    listGroups().catch(() => []),
  ]);

  // The form's pickers list only what the user's role can read, plus what the
  // hosts they can see already use (so editing a host keeps its references).
  const picker = await pickerVisibility(access, allHosts);
  const visibleAccessLists = accessLists.filter((list) => picker.accessList(list.id));

  // Hosts are filtered, counted and sorted in memory: their status, traffic
  // and protection come from several sources, not from one query.
  const { rows, analyticsStatus } = await loadHostInsights(access, allHosts, {
    accessListNames: new Map(visibleAccessLists.map((list) => [list.id, list.name])),
    certificateWaitMs: CERTIFICATE_WAIT_MS,
  });
  const filtered = rows.filter(
    (row) => matchesHostSearch(row, query.search) && matchesProtection(row, query.protection) && matchesTags(row, query.tags)
  );
  const statusCounts: Record<StatusFilter, number> = {
    all: filtered.length,
    attention: filtered.filter((row) => matchesStatus(row, "attention")).length,
    disabled: filtered.filter((row) => matchesStatus(row, "disabled")).length,
  };
  const matching = sortHostRows(filtered.filter((row) => matchesStatus(row, query.status)), query.sortBy, query.sortDir, query.groupBy, query.tags);
  const { items: pageRows, page, perPage } = paginate<HostListRow>(matching, query.page);
  const byId = new Map(allHosts.map((host) => [host.id, host]));
  const hosts = pageRows.map((row) => byId.get(row.id)!);
  // ?edit=<id> opens the edit dialog for a host the user may see, on any page of the list.
  const editParam = Array.isArray(params.edit) ? params.edit[0] : params.edit;
  const editTarget = can(access, "proxy_hosts:write") && editParam && /^\d{1,15}$/.test(editParam) ? byId.get(Number(editParam)) ?? null : null;
  const maxRequests = Math.max(0, ...filtered.map((row) => row.traffic?.requests ?? 0));
  const availableTags = [...new Set(allHosts.flatMap((host) => host.tags))].sort();

  // Build forward auth access map for hosts that have Ingressi forward auth enabled
  const faHosts = [...hosts, ...(editTarget && !hosts.includes(editTarget) ? [editTarget] : [])].filter((h) => h.ingressiForwardAuth?.enabled);
  const faAccessEntries = await Promise.all(
    faHosts.map((h) => getForwardAuthAccessForHost(h.id).catch(() => []))
  );
  const forwardAuthAccessMap: Record<number, { userIds: number[]; groupIds: number[] }> = {};
  faHosts.forEach((h, i) => {
    const entries = faAccessEntries[i];
    forwardAuthAccessMap[h.id] = {
      userIds: entries.filter((e) => e.userId !== null).map((e) => e.userId!),
      groupIds: entries.filter((e) => e.groupId !== null).map((e) => e.groupId!),
    };
  });

  const forwardAuthUsers = allUsers.map((u) => ({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
  }));
  const forwardAuthGroups = allGroups.map((g) => ({
    id: g.id,
    name: g.name,
    description: g.description,
    member_count: g.members.length,
  }));

  return (
    <ProxyHostsClient
      hosts={hosts}
      rows={pageRows}
      totalHosts={allHosts.length}
      statusCounts={statusCounts}
      maxRequests={maxRequests}
      analyticsStatus={analyticsStatus}
      availableTags={availableTags}
      query={{ ...query, page }}
      certificates={certificates.filter((cert) => picker.certificate(cert.id)).map(toCertificatePickerOption)}
      caCertificates={picker.trustAnchors ? caCertificates : []}
      accessLists={visibleAccessLists}
      authentikDefaults={authentikDefaults}
      forwardAuthDefaults={forwardAuthDefaults}
      pagination={{ total: matching.length, page, perPage }}
      mtlsRoles={picker.trustAnchors ? mtlsRoles : []}
      issuedClientCerts={picker.trustAnchors ? issuedClientCerts : []}
      forwardAuthUsers={can(access, "users:read") ? forwardAuthUsers : []}
      forwardAuthGroups={can(access, "groups:read") ? forwardAuthGroups : []}
      forwardAuthAccessMap={forwardAuthAccessMap}
      editTarget={editTarget}
      canWrite={can(access, "proxy_hosts:write")}
      scopeTags={scope ? [...scope] : []}
      approval={await getHostApprovalContext(access)}
    />
  );
}

/** What the host form may list for this user (everything for administrators). */
async function pickerVisibility(access: Access, visibleHosts: readonly ProxyHost[]) {
  if (access.isAdmin) {
    return { certificate: () => true, accessList: () => true, trustAnchors: true };
  }
  const usedCertificates = new Set(visibleHosts.map((host) => host.certificateId).filter((id): id is number => id !== null));
  const usedAccessLists = new Set(visibleHosts.map((host) => host.accessListId).filter((id): id is number => id !== null));
  const readableCertificates = can(access, "certificates:read") ? await certificateIdsInScope(access) : new Set<number>();
  const allAccessLists = can(access, "access_lists:read");
  return {
    certificate: (id: number) => usedCertificates.has(id) || readableCertificates === null || readableCertificates.has(id),
    accessList: (id: number) => allAccessLists || usedAccessLists.has(id),
    trustAnchors: can(access, "certificates:read") && scopeTagsFor(access, "certificates") === null,
  };
}
