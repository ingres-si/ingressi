/**
 * Tag scopes and the other limits on what a non-administrator may do with
 * hosts and certificates (custom roles, ee/custom-roles). Routes and server
 * actions call these after requirePermission / requireApiPermission.
 *
 * - Proxy hosts and L4 proxy hosts: a scoped role sees and changes only hosts
 *   carrying one of its tags. A host outside the scope answers 404, exactly
 *   like a missing one. A scoped write may only add or remove the role's own
 *   tags and must leave at least one of them on the host, so creating a host
 *   requires one. Domains (and L4 listening ports) that a host outside the
 *   scope already uses are refused, so a team cannot take over another team's
 *   traffic.
 * - Certificates: a scoped role sees the certificates its in-scope proxy
 *   hosts use; it may change or delete one only when every host using it is
 *   in scope, and it cannot create certificates (a new certificate is used by
 *   no host yet). CA certificates, client certificates and mTLS roles are
 *   trust anchors for every host, so they need a certificates permission
 *   without a scope.
 * - Every non-administrator (scoped or not) is refused raw Caddy JSON on proxy
 *   hosts and any address Caddy would dial on its admin API port (upstreams,
 *   location rules, the Authentik outpost, the forward-auth server), cannot
 *   add such an address to a host that carries custom Caddy JSON, needs
 *   waf:write to change a host's custom WAF directives, and may only reference a
 *   certificate, access list, CA/client certificate, mTLS role, user or group
 *   on a host if they can read it (or the host already references it).
 *
 * Administrators are never limited here.
 */
import { and, eq, isNotNull } from "drizzle-orm";
import { appDb } from "./db";
import { l4ProxyHosts, proxyHosts } from "./db/schema";
import { ApiClientError, ApiValidationError } from "./api-errors";
import { can, scopeTagsFor, tagsInScope, type Access, type ScopableArea } from "./permissions";
import { normalizeTags, parseStoredTags } from "./host-tags";
import { tagsMatchAny } from "./host-tag-filter";
import { normalizeProxyHostDomains } from "./proxy-host-domains";
import { isDomainCoveredByWildcard } from "./cert-domain-match";
import { extractL4ListenPort } from "./l4-reserved-ports";
import {
  authentikAuthDial,
  authentikOutpostDial,
  dialAddressPort,
  forwardAuthDial,
  parseUpstreamTarget,
} from "./caddy-utils";
import { getProxyHost, type MtlsConfig, type ProxyHost, type ProxyHostInput, type WafHostConfig } from "./models/proxy-hosts";
import { getL4ProxyHost, type L4ProxyHost, type L4ProxyHostInput } from "./models/l4-proxy-hosts";

/** A refusal because of the caller's role (403); the message is safe to show. */
export class ScopeError extends ApiClientError {
  constructor(message: string) {
    super(message, 403);
    this.name = "ScopeError";
  }
}

/** The Caddy admin API port. Proxying to it would hand over the whole Caddy configuration. */
const CADDY_ADMIN_PORT = 2019;

// ── Proxy hosts and L4 proxy hosts ────────────────────────────────────

/** The proxy host, or null when it is missing or outside the caller's scope. */
export async function findProxyHostInScope(access: Access, id: number): Promise<ProxyHost | null> {
  const host = Number.isSafeInteger(id) && id > 0 ? await getProxyHost(id) : null;
  return host && tagsInScope(host.tags, scopeTagsFor(access, "proxy_hosts")) ? host : null;
}

/**
 * The proxy host; throws "Proxy host not found" (404 through apiErrorResponse,
 * exactly as for a missing host) when it is missing or outside the scope.
 */
export async function getProxyHostInScope(access: Access, id: number): Promise<ProxyHost> {
  const host = await findProxyHostInScope(access, id);
  if (!host) throw new Error("Proxy host not found");
  return host;
}

/** The L4 proxy host, or null when it is missing or outside the caller's scope. */
export async function findL4ProxyHostInScope(access: Access, id: number): Promise<L4ProxyHost | null> {
  const host = Number.isSafeInteger(id) && id > 0 ? await getL4ProxyHost(id) : null;
  return host && tagsInScope(host.tags, scopeTagsFor(access, "l4_proxy_hosts")) ? host : null;
}

/** The L4 proxy host; throws "L4 proxy host not found" (404) when missing or outside the scope. */
export async function getL4ProxyHostInScope(access: Access, id: number): Promise<L4ProxyHost> {
  const host = await findL4ProxyHostInScope(access, id);
  if (!host) throw new Error("L4 proxy host not found");
  return host;
}

/**
 * The tags a host gets from a write, or undefined to leave them as they are.
 * `existing` is the host's current tags (null when creating one). Unscoped
 * callers set whatever they send. A scoped caller may only add or remove tags
 * of its scope (other tags already on the host are kept), and the host must
 * keep at least one tag of the scope.
 */
export function tagsForWrite(
  access: Access,
  area: Extract<ScopableArea, "proxy_hosts" | "l4_proxy_hosts">,
  requested: unknown,
  existing: readonly string[] | null
): string[] | undefined {
  const scope = scopeTagsFor(access, area);
  if (scope === null) return requested === undefined ? undefined : normalizeTags(requested);
  const current = existing ?? [];
  const wanted = requested === undefined ? [...current] : normalizeTags(requested);
  const foreign = wanted.filter((tag) => !scope.includes(tag) && !current.includes(tag));
  if (foreign.length > 0) {
    throw new ScopeError(`You can only add your role's tags (${scope.join(", ")}), not ${foreign.join(", ")}`);
  }
  const kept = current.filter((tag) => !scope.includes(tag));
  const result = [...new Set([...kept, ...wanted.filter((tag) => scope.includes(tag))])].sort();
  if (!result.some((tag) => scope.includes(tag))) {
    throw new ApiValidationError(`The host needs at least one of your role's tags: ${scope.join(", ")}`);
  }
  return result;
}

function domainsOverlap(a: string, b: string): boolean {
  return a === b || isDomainCoveredByWildcard(a, [b]) || isDomainCoveredByWildcard(b, [a]);
}

/**
 * Refuses domains that a proxy host outside the caller's scope serves (equal,
 * or matched through a wildcard either way). Unscoped callers are not checked.
 */
export async function assertDomainsFreeOutsideScope(
  access: Access,
  domains: readonly string[] | undefined,
  exceptHostId: number | null
): Promise<void> {
  if (domains === undefined) return;
  const scope = scopeTagsFor(access, "proxy_hosts");
  if (scope === null) return;
  const wanted = normalizeProxyHostDomains([...domains]);
  const rows = await appDb.select({ id: proxyHosts.id, domains: proxyHosts.domains, tags: proxyHosts.tags }).from(proxyHosts);
  for (const row of rows) {
    if (row.id === exceptHostId || tagsInScope(parseStoredTags(row.tags), scope)) continue;
    let taken: string[] = [];
    try {
      taken = JSON.parse(row.domains) as string[];
    } catch {
      continue;
    }
    const clash = wanted.find((domain) => taken.some((other) => domainsOverlap(domain, String(other).toLowerCase())));
    if (clash) {
      throw new ScopeError(`The domain ${clash} is served by a host outside your role's scope`);
    }
  }
}

/** Refuses an L4 listening port (per protocol) that an L4 host outside the caller's scope uses. */
export async function assertListenPortFreeOutsideScope(
  access: Access,
  protocol: string | undefined,
  listenAddress: string | undefined,
  exceptHostId: number | null
): Promise<void> {
  const scope = scopeTagsFor(access, "l4_proxy_hosts");
  if (scope === null || listenAddress === undefined || protocol === undefined) return;
  const port = extractL4ListenPort(listenAddress);
  if (port === null) return; // The model refuses it with the reason.
  const rows = await appDb
    .select({ id: l4ProxyHosts.id, protocol: l4ProxyHosts.protocol, listenAddress: l4ProxyHosts.listenAddress, tags: l4ProxyHosts.tags })
    .from(l4ProxyHosts);
  for (const row of rows) {
    if (row.id === exceptHostId || tagsInScope(parseStoredTags(row.tags), scope)) continue;
    if (row.protocol === protocol && extractL4ListenPort(row.listenAddress) === port) {
      throw new ScopeError(`Port ${port}/${protocol} is used by an L4 host outside your role's scope`);
    }
  }
}

/**
 * Refuses a dial address (as caddy.ts builds it) that could reach Caddy's
 * admin API: its port, a port that is not one plain number (Caddy takes
 * "2019-2019" as port 2019), a Caddy placeholder (filled in per request), or
 * a network-prefixed/socket target (unix//…, fd/…, tcp/…) that sidesteps the
 * port check and can reach the admin API's unix socket from inside the Caddy
 * container.
 */
function assertNoAdminApiDial(dial: string): void {
  if (dial.includes("{")) {
    throw new ScopeError("Only administrators can use Caddy placeholders in upstream addresses");
  }
  // A legitimate dial is [host]:port with no slash; a slash means a network
  // prefix or unix-socket path (a plain [host]:port never contains one).
  if (dial.includes("/")) {
    throw new ScopeError("Only administrators can use socket or network-prefixed upstream addresses");
  }
  const port = dialAddressPort(dial);
  if (port === null) return;
  if (!/^\d{1,5}$/.test(port)) {
    throw new ScopeError("Upstream ports must be a single number");
  }
  if (Number(port) === CADDY_ADMIN_PORT) {
    throw new ScopeError(`Only administrators can proxy to port ${CADDY_ADMIN_PORT} (Caddy's admin API)`);
  }
}

/**
 * The values a host already has. They are not refused again: an administrator
 * set them, and the editor sends every field back, so refusing them would
 * keep everybody else from saving any change to that host.
 */
function kept(values: readonly (string | null | undefined)[] | null | undefined): Set<string> {
  return new Set((values ?? []).filter((value): value is string => typeof value === "string").map((value) => value.trim()));
}

/**
 * An HTTP upstream as it is compared with what a host already has: the
 * address Caddy dials and whether it does so over TLS. The host editor
 * writes "backend:8080" back as "http://backend:8080", which is the same
 * upstream; two spellings that Caddy would dial differently never are.
 */
function upstreamKey(upstream: string): string {
  const target = parseUpstreamTarget(upstream);
  return `${target.scheme === "https" ? "https" : "http"} ${target.dial.trim()}`;
}

function keptUpstreams(values: readonly (string | null | undefined)[] | null | undefined): Set<string> {
  return new Set([...kept(values)].map(upstreamKey));
}

/** HTTP upstreams: Caddy dials what parseUpstreamTarget makes of them. `existing` is keptUpstreams(…). */
function assertNoAdminApiUpstream(upstreams: readonly string[] | null | undefined, existing: Set<string>): void {
  for (const upstream of upstreams ?? []) {
    if (typeof upstream === "string" && !existing.has(upstreamKey(upstream))) {
      assertNoAdminApiDial(parseUpstreamTarget(upstream).dial);
    }
  }
}

function assertNoAdminApiHealthCheck(port: unknown, existing: number | null | undefined): void {
  if (port === undefined || port === null || Number(port) !== CADDY_ADMIN_PORT || existing === CADDY_ADMIN_PORT) return;
  throw new ScopeError(`Only administrators can health-check port ${CADDY_ADMIN_PORT} (Caddy's admin API)`);
}

/** Every address a proxy host input makes Caddy dial. */
function assertNoAdminApiDials(input: Partial<ProxyHostInput>, existing: ProxyHost | null): void {
  assertNoAdminApiUpstream(input.upstreams, keptUpstreams(existing?.upstreams));
  assertNoAdminApiHealthCheck(input.loadBalancer?.activeHealthCheck?.port, existing?.loadBalancer?.activeHealthCheck?.port);
  // A location rule keeps what the rule of the same path already has.
  for (const rule of input.locationRules ?? []) {
    const path = typeof rule?.path === "string" ? rule.path.trim() : null;
    const current = (existing?.locationRules ?? []).find((candidate) => candidate.path.trim() === path);
    assertNoAdminApiUpstream(rule?.upstreams, keptUpstreams(current?.upstreams));
    assertNoAdminApiHealthCheck(rule?.loadBalancer?.activeHealthCheck?.port, current?.loadBalancer?.activeHealthCheck?.port);
  }

  const outpost = input.authentik?.outpostUpstream;
  if (typeof outpost === "string" && outpost.trim() && outpost.trim() !== existing?.authentik?.outpostUpstream?.trim()) {
    assertNoAdminApiDial(authentikOutpostDial(outpost.trim()));
    assertNoAdminApiDial(authentikAuthDial(outpost.trim()));
  }
  const authUpstream = input.forwardAuth?.authUpstream;
  if (typeof authUpstream === "string" && authUpstream.trim() && authUpstream.trim() !== existing?.forwardAuth?.authUpstream?.trim()) {
    const dial = forwardAuthDial(authUpstream.trim());
    if (dial !== null) assertNoAdminApiDial(dial);
  }
}

function sameText(a: unknown, b: string | null | undefined): boolean {
  // Anything but text (or nothing) is a change: the API takes JSON of any shape.
  if (a !== null && a !== undefined && typeof a !== "string") return false;
  return (a?.trim() || null) === (b?.trim() || null);
}

function sameIds(a: readonly number[] | undefined, b: readonly number[] | undefined): boolean {
  const left = [...new Set(a ?? [])].sort((x, y) => x - y);
  const right = [...new Set(b ?? [])].sort((x, y) => x - y);
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function mtlsReferencesChanged(next: MtlsConfig | null | undefined, previous: MtlsConfig | null | undefined): boolean {
  if (next === undefined) return false;
  return (
    !sameIds(next?.trusted_client_cert_ids, previous?.trusted_client_cert_ids) ||
    !sameIds(next?.trusted_role_ids, previous?.trusted_role_ids) ||
    !sameIds(next?.ca_certificate_ids, previous?.ca_certificate_ids)
  );
}

function addsUpstream(values: readonly unknown[] | null | undefined, existing: Set<string>): boolean {
  return (values ?? []).some((value) => typeof value !== "string" || !existing.has(upstreamKey(value)));
}

function setsAddress(value: unknown, existing: string | null | undefined): boolean {
  if (value === undefined || value === null) return false;
  if (typeof value !== "string") return true;
  return value.trim() !== "" && value.trim() !== existing?.trim();
}

/**
 * Whether a write gives the host a place to send requests that it does not
 * have yet: an upstream, an upstream of a location rule (compared with the
 * rule of the same path), the Authentik outpost or the forward-auth server.
 * Taking one away, or changing the order, is not that.
 */
function addsDestination(input: Partial<ProxyHostInput>, existing: ProxyHost): boolean {
  if (addsUpstream(input.upstreams, keptUpstreams(existing.upstreams))) return true;
  for (const rule of input.locationRules ?? []) {
    const path = typeof rule?.path === "string" ? rule.path.trim() : null;
    const current = (existing.locationRules ?? []).find((candidate) => candidate.path.trim() === path);
    if (addsUpstream(rule?.upstreams, keptUpstreams(current?.upstreams))) return true;
  }
  return (
    setsAddress(input.authentik?.outpostUpstream, existing.authentik?.outpostUpstream) ||
    setsAddress(input.forwardAuth?.authUpstream, existing.forwardAuth?.authUpstream)
  );
}

/** The host's own WAF rule text, as Coraza gets it. */
function wafDirectives(waf: WafHostConfig | null | undefined): string {
  const directives: unknown = waf?.custom_directives;
  return typeof directives === "string" ? directives.replace(/\r\n/g, "\n").trim() : directives === undefined || directives === null ? "" : "\u0000";
}

/**
 * Checks a proxy host write by a non-administrator: no raw Caddy JSON, no
 * upstream on the admin API port, no new destination for a host that carries
 * custom Caddy JSON (addsDestination), WAF rule text only with waf:write, and only references
 * the caller can read (or that the host already has). `existing` is null
 * when creating.
 */
export async function assertProxyHostWriteAllowed(
  access: Access,
  input: Partial<ProxyHostInput>,
  existing: ProxyHost | null
): Promise<void> {
  if (access.isAdmin) return;
  if (
    (input.customReverseProxyJson !== undefined && !sameText(input.customReverseProxyJson, existing?.customReverseProxyJson)) ||
    (input.customPreHandlersJson !== undefined && !sameText(input.customPreHandlersJson, existing?.customPreHandlersJson))
  ) {
    throw new ScopeError("Only administrators can set custom Caddy JSON on a proxy host");
  }
  assertNoAdminApiDials(input, existing);
  // Custom Caddy JSON can hold what only Caddy can read ({env.…} and {file.…}
  // placeholders in request headers, a client certificate for the upstream):
  // whoever chooses where the requests go receives it.
  if (
    existing &&
    (existing.customReverseProxyJson?.trim() || existing.customPreHandlersJson?.trim()) &&
    addsDestination(input, existing)
  ) {
    throw new ScopeError(
      "Only administrators can add a destination (an upstream, a location rule's upstream, the Authentik outpost " +
        "or the forward-auth server) to a proxy host with custom Caddy JSON"
    );
  }
  // WAF rules written as text are WAF configuration: they can switch the engine,
  // the audit log and the body limits of the host, whatever its WAF mode says.
  if (
    input.waf !== undefined &&
    wafDirectives(input.waf) !== wafDirectives(existing?.waf) &&
    !can(access, "waf:write")
  ) {
    throw new ScopeError("Changing a proxy host's custom WAF directives needs the waf:write permission");
  }

  const certificateId = input.certificateId;
  if (certificateId !== undefined && certificateId !== null && certificateId !== existing?.certificateId) {
    const visible = can(access, "certificates:read") && (await certificateVisible(access, certificateId));
    if (!visible) throw new ScopeError("You cannot use this certificate");
  }
  const accessListId = input.accessListId;
  if (accessListId !== undefined && accessListId !== null && accessListId !== existing?.accessListId) {
    if (!can(access, "access_lists:read")) throw new ScopeError("Using an access list needs the access_lists:read permission");
  }
  if (mtlsReferencesChanged(input.mtls, existing?.mtls)) {
    if (!can(access, "certificates:read") || scopeTagsFor(access, "certificates") !== null) {
      throw new ScopeError("Changing trusted client certificates needs certificate permissions without a tag scope");
    }
  }
}

/**
 * Checks mTLS access-rule references (mTLS roles and client certificates) set
 * by a non-administrator: changing them needs certificate permissions without
 * a tag scope, like the trust anchors themselves.
 */
export function assertMtlsRuleReferencesAllowed(
  access: Access,
  next: { allowedRoleIds?: readonly number[]; allowedCertIds?: readonly number[] },
  current: { allowedRoleIds: readonly number[]; allowedCertIds: readonly number[] } | null
): void {
  if (access.isAdmin) return;
  const changed =
    (next.allowedRoleIds !== undefined && !sameIds(next.allowedRoleIds, current?.allowedRoleIds ?? [])) ||
    (next.allowedCertIds !== undefined && !sameIds(next.allowedCertIds, current?.allowedCertIds ?? []));
  if (changed && (!can(access, "certificates:read") || scopeTagsFor(access, "certificates") !== null)) {
    throw new ScopeError("Choosing mTLS roles or client certificates needs certificate permissions without a tag scope");
  }
}

/** Checks forward-auth access (users and groups allowed through a host) set by a non-administrator. */
export async function assertForwardAuthAccessAllowed(
  access: Access,
  next: { userIds?: readonly number[]; groupIds?: readonly number[] },
  current: { userIds: readonly number[]; groupIds: readonly number[] }
): Promise<void> {
  if (access.isAdmin) return;
  if (next.userIds !== undefined && !sameIds(next.userIds, current.userIds) && !can(access, "users:read")) {
    throw new ScopeError("Choosing users for forward auth needs the users:read permission");
  }
  if (next.groupIds !== undefined && !sameIds(next.groupIds, current.groupIds) && !can(access, "groups:read")) {
    throw new ScopeError("Choosing groups for forward auth needs the groups:read permission");
  }
}

/**
 * Checks an L4 host write by a non-administrator: nothing that reaches
 * Caddy's admin API, and only plain addresses. `existing` is the host being
 * updated (null or left out when creating): what it already has is kept.
 */
export function assertL4WriteAllowed(access: Access, input: Partial<L4ProxyHostInput>, existing: L4ProxyHost | null = null): void {
  if (access.isAdmin) return;
  // The raw meta object carries the same settings as the fields checked below, unchecked.
  if (input.meta !== undefined && input.meta !== null) {
    throw new ScopeError("Only administrators can set the raw meta object of an L4 host");
  }
  // The layer4 proxy dials L4 upstreams as written.
  const upstreams = kept(existing?.upstreams);
  for (const upstream of input.upstreams ?? []) {
    if (typeof upstream === "string" && !upstreams.has(upstream.trim())) assertNoAdminApiDial(upstream);
  }
  // The listen address is a plain [host]:port: no network prefix (unix/, fd/) and no placeholder.
  if (
    typeof input.listenAddress === "string" &&
    input.listenAddress.trim() !== existing?.listenAddress.trim() &&
    !L4_LISTEN_ADDRESS.test(input.listenAddress.trim())
  ) {
    throw new ScopeError("Only administrators can use a listen address other than [host]:port");
  }
  // Caddy expands placeholders in SNI and Host matcher values.
  const matchers = kept(existing?.matcherValue);
  if (
    Array.isArray(input.matcherValue) &&
    input.matcherValue.some((value) => typeof value === "string" && value.includes("{") && !matchers.has(value.trim()))
  ) {
    throw new ScopeError("Only administrators can use Caddy placeholders in matcher values");
  }
  // An active health check dials its own port, like the HTTP path.
  assertNoAdminApiHealthCheck(input.loadBalancer?.activeHealthCheck?.port, existing?.loadBalancer?.activeHealthCheck?.port);
}

const L4_LISTEN_ADDRESS = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]*):\d{1,5}$/;

// ── Settings ──────────────────────────────────────────────────────────

/**
 * The settings groups whose text Caddy expands placeholders in when it loads
 * the configuration: the ACME contact and directory, and DNS provider
 * credentials. {env.…} and {file.…} there read the Caddy container's
 * environment and files (its saved configuration holds every secret) and
 * send them to the address the same settings name.
 */
const PLACEHOLDER_SETTINGS_GROUPS: ReadonlySet<string> = new Set(["general", "acme", "cloudflare", "dns-provider"]);

function hasPlaceholder(value: unknown): boolean {
  if (typeof value === "string") return value.includes("{");
  if (Array.isArray(value)) return value.some(hasPlaceholder);
  if (value && typeof value === "object") return Object.values(value).some(hasPlaceholder);
  return false;
}

/** Checks a settings write by a non-administrator: no Caddy placeholder in the groups Caddy expands them in. */
export function assertSettingsWriteAllowed(access: Access, group: string, value: unknown): void {
  if (access.isAdmin || !PLACEHOLDER_SETTINGS_GROUPS.has(group)) return;
  if (hasPlaceholder(value)) {
    throw new ScopeError("Only administrators can use Caddy placeholders in these settings");
  }
}

// ── Certificates ──────────────────────────────────────────────────────

/** Ids of the certificates the caller's tag scope covers, or null for all of them. */
export async function certificateIdsInScope(access: Access): Promise<Set<number> | null> {
  const scope = scopeTagsFor(access, "certificates");
  if (scope === null) return null;
  const rows = await appDb
    .select({ certificateId: proxyHosts.certificateId })
    .from(proxyHosts)
    .where(and(isNotNull(proxyHosts.certificateId), tagsMatchAny(proxyHosts.tags, scope)));
  return new Set(rows.map((row) => row.certificateId!));
}

async function certificateVisible(access: Access, certificateId: number): Promise<boolean> {
  const ids = await certificateIdsInScope(access);
  return ids === null || ids.has(certificateId);
}

/** 404 unless the certificate is in the caller's scope. */
export async function assertCertificateReadable(access: Access, certificateId: number): Promise<void> {
  if (!(await certificateVisible(access, certificateId))) {
    throw new Error("Certificate not found");
  }
}

/**
 * Refuses changing or deleting a certificate unless every proxy host using it
 * is in the caller's scope (404 when none is, like a missing certificate).
 */
export async function assertCertificateWritable(access: Access, certificateId: number): Promise<void> {
  const scope = scopeTagsFor(access, "certificates");
  if (scope === null) return;
  const rows = await appDb
    .select({ tags: proxyHosts.tags })
    .from(proxyHosts)
    .where(eq(proxyHosts.certificateId, certificateId));
  const inScope = rows.filter((row) => tagsInScope(parseStoredTags(row.tags), scope)).length;
  if (inScope === 0) throw new Error("Certificate not found");
  if (inScope < rows.length) {
    throw new ScopeError("This certificate is also used by hosts outside your role's scope");
  }
}

/** Refuses creating a certificate under a tag scope: a new certificate belongs to no host yet. */
export function assertCanCreateCertificate(access: Access): void {
  if (scopeTagsFor(access, "certificates") !== null) {
    throw new ScopeError("A role with a tag scope cannot create certificates; ask an administrator");
  }
}

/**
 * CA certificates, client certificates and mTLS roles serve every host, so a
 * certificates permission limited by a tag scope does not reach them.
 */
export function assertUnscopedCertificates(access: Access): void {
  if (scopeTagsFor(access, "certificates") !== null) {
    throw new ScopeError(
      "CA certificates, client certificates and mTLS roles need certificate permissions without a tag scope"
    );
  }
}
