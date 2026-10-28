// SPDX-License-Identifier: Elastic-2.0
import { appDb } from "@/src/lib/db";
import { accessLists, certificates, forwardAuthAccess, l4ProxyHosts, monetizationHosts, users } from "@/src/lib/db/schema";
import { getGeoBlockSettings, getWafSettings, type GeoBlockSettings, type WafSettings } from "@/src/lib/settings";
import { listProxyHosts, type ProxyHost } from "@/src/lib/models/proxy-hosts";
import { resolveEffectiveWaf } from "@/src/lib/caddy-waf";
import { isDomainCoveredByCert } from "@/src/lib/cert-domain-match";
import { listMfaAccountSummaries } from "@/src/lib/mfa";
import { listCustomRoleViews } from "@/ee/custom-roles/store";
import { HOST_EXPR, num, str, timeFilter } from "@/ee/ai/clickhouse";
import {
  clean,
  columns,
  finding,
  keyValueSection,
  parseStringArray,
  percent,
  section,
  sortFindings,
  summaryItem,
  userLabel,
  type BuildContext,
  type BuiltReport,
} from "./shared";
import type { ReportCell, ReportFinding } from "../types";
import { asc } from "@/src/lib/db/ops";

const MAX_REQUEST_HOSTS = 5000;

export type WafState = { mode: "blocking" | "detection only" | "off"; crs: boolean; source: string; customRules: boolean };

/** How the WAF protects one host: its effective mode, where the settings come from, whether it has rules. */
export function wafState(global: WafSettings | null, host: ProxyHost): WafState {
  const effective = resolveEffectiveWaf(global, host.waf);
  const override = host.waf?.waf_mode === "override";
  if (!effective || effective.mode === "Off") {
    const source = !effective
      ? host.waf?.enabled === false ? "turned off for this host" : "not enabled"
      : override || host.waf?.mode === "Off" ? "engine set to Off for this host" : "engine set to Off";
    return { mode: "off", crs: false, source, customRules: false };
  }
  const hostHasOwn = Boolean(host.waf && (host.waf.enabled !== undefined || host.waf.mode !== undefined || host.waf.load_owasp_crs !== undefined));
  return {
    mode: effective.mode === "DetectionOnly" ? "detection only" : "blocking",
    crs: effective.load_owasp_crs === true,
    source: override ? "host (override)" : hostHasOwn ? (global?.enabled ? "global + host" : "host") : "global",
    customRules: Boolean(effective.custom_directives && effective.custom_directives.trim()),
  };
}

function ruleCount(config: GeoBlockSettings, kind: "block" | "allow"): number {
  const keys = kind === "block"
    ? (["block_countries", "block_continents", "block_asns", "block_cidrs", "block_ips"] as const)
    : (["allow_countries", "allow_continents", "allow_asns", "allow_cidrs", "allow_ips"] as const);
  return keys.reduce((sum, key) => sum + (Array.isArray(config[key]) ? config[key].length : 0), 0);
}

/**
 * Whether geo blocking applies to the host, mirroring resolveEffectiveGeoBlock
 * in src/lib/caddy.ts: an override uses the host's settings only; otherwise an
 * enabled host or global configuration applies (merged when both are enabled).
 * Allow rules only make exceptions to block rules, so without block rules
 * nothing is blocked.
 */
export function geoBlockState(global: GeoBlockSettings | null, host: Pick<ProxyHost, "geoblock" | "geoblockMode">): { enabled: boolean; source: string; blockRules: number; allowRules: number } {
  const hostConfig = host.geoblock;
  const off = (source: string) => ({ enabled: false, source, blockRules: 0, allowRules: 0 });
  const applied = (source: string, configs: GeoBlockSettings[]) => {
    const blockRules = configs.reduce((sum, config) => sum + ruleCount(config, "block"), 0);
    const allowRules = configs.reduce((sum, config) => sum + ruleCount(config, "allow"), 0);
    return blockRules > 0 ? { enabled: true, source, blockRules, allowRules } : { enabled: false, source: "no block rules", blockRules, allowRules };
  };
  if (!hostConfig?.enabled && !global?.enabled) return off("not enabled");
  if (hostConfig && host.geoblockMode === "override") {
    return hostConfig.enabled ? applied("host (override)", [hostConfig]) : off("turned off for this host");
  }
  if (hostConfig?.enabled && global?.enabled) return applied("global + host", [global, hostConfig]);
  if (hostConfig?.enabled) return applied("host", [hostConfig]);
  return applied("global", [global!]);
}

function pathLimited(protectedPaths: string[] | null | undefined, excludedPaths: string[] | null | undefined): boolean {
  return (protectedPaths?.length ?? 0) > 0 || (excludedPaths?.length ?? 0) > 0;
}

/** WAF events per request host in the period, or null without analytics. */
async function wafActivity(context: BuildContext, notes: string[]): Promise<Map<string, { blocked: number; detected: number }> | null> {
  if (!context.analytics.analyticsEnabled()) {
    notes.push("ClickHouse analytics is not configured, so WAF activity per host is not included.");
    return null;
  }
  try {
    const rows = await context.analytics.query<{ h: string; blocked: string; detected: string }>(
      `SELECT ${HOST_EXPR} AS h, countIf(blocked) AS blocked, countIf(NOT blocked) AS detected
       FROM waf_events WHERE ${timeFilter()} GROUP BY h ORDER BY blocked DESC LIMIT {p_limit:UInt32}`,
      {
        p_from: Math.floor(context.period.from.getTime() / 1000),
        p_to: Math.floor(context.period.to.getTime() / 1000),
        p_limit: MAX_REQUEST_HOSTS,
      }
    );
    return new Map(rows.map((row) => [str(row.h, 253), { blocked: num(row.blocked), detected: num(row.detected) }]));
  } catch {
    notes.push("ClickHouse could not be queried, so WAF activity per host is not included.");
    return null;
  }
}

export async function buildProtectionCoverage(context: BuildContext): Promise<BuiltReport> {
  const notes: string[] = [];
  const [globalWaf, globalGeo, hosts] = await Promise.all([getWafSettings(), getGeoBlockSettings(), listProxyHosts()]);
  const activity = await wafActivity(context, notes);
  const listNames = new Map((await appDb.select({ id: accessLists.id, name: accessLists.name }).from(accessLists)).map((row) => [row.id, clean(row.name, 100)]));
  const certs = new Map((await appDb.select({ id: certificates.id, name: certificates.name, type: certificates.type }).from(certificates)).map((row) => [row.id, row]));
  const grants = new Map<number, { users: number; groups: number }>();
  for (const grant of await appDb.select().from(forwardAuthAccess)) {
    const entry = grants.get(grant.proxyHostId) ?? { users: 0, groups: 0 };
    if (grant.userId !== null) entry.users += 1;
    if (grant.groupId !== null) entry.groups += 1;
    grants.set(grant.proxyHostId, entry);
  }
  const monetized = new Set((await appDb.select().from(monetizationHosts)).filter((row) => row.enabled).map((row) => row.proxyHostId));

  const findings: ReportFinding[] = [];
  const counts = { enabled: 0, wafBlocking: 0, wafDetection: 0, wafOff: 0, geo: 0, authenticated: 0, noRedirect: 0, noHsts: 0, upstreamUnverified: 0 };
  const sorted = [...hosts].sort((a, b) => a.name.localeCompare(b.name) || a.id - b.id);
  const hostRows: Record<string, ReportCell>[] = sorted.map((host) => {
    const label = `Proxy host "${clean(host.name, 120)}"`;
    const subject = `proxy_host:${host.id}`;
    const waf = wafState(globalWaf, host);
    const geo = geoBlockState(globalGeo, host);
    const authentication: string[] = [];
    let partial = false;
    const skippedFor: string[] = [];
    if (host.accessListId !== null) authentication.push(`access list: ${listNames.get(host.accessListId) ?? `#${host.accessListId}`}`);
    if (host.ingressiForwardAuth?.enabled) {
      const grant = grants.get(host.id) ?? { users: 0, groups: 0 };
      authentication.push(`built-in forward auth (${grant.users} user(s), ${grant.groups} group(s) allowed)`);
      partial ||= pathLimited(host.ingressiForwardAuth.protected_paths, host.ingressiForwardAuth.excluded_paths);
      skippedFor.push(...(host.ingressiForwardAuth.bypass_sources ?? []));
    }
    if (host.forwardAuth?.enabled) {
      authentication.push(`forward auth: ${host.forwardAuth.provider}`);
      partial ||= pathLimited(host.forwardAuth.protectedPaths, host.forwardAuth.excludedPaths);
      skippedFor.push(...host.forwardAuth.bypassSources);
    }
    if (host.authentik?.enabled) {
      authentication.push("Authentik");
      partial ||= pathLimited(host.authentik.protectedPaths, host.authentik.excludedPaths);
      skippedFor.push(...host.authentik.bypassSources);
    }
    if (host.mtls?.enabled) {
      const trusted = (host.mtls.trusted_client_cert_ids?.length ?? 0) + (host.mtls.trusted_role_ids?.length ?? 0) + (host.mtls.ca_certificate_ids?.length ?? 0);
      authentication.push(`mTLS client certificates (${trusted} trusted certificate(s), role(s) or CA(s))`);
      partial ||= pathLimited(host.mtls.protected_paths, host.mtls.excluded_paths);
    }
    if (monetized.has(host.id)) authentication.push("API keys (API monetization)");
    const httpsUpstream = host.upstreams.some((upstream) => /^https:\/\//i.test(upstream.trim()));
    const cert = host.certificateId !== null ? certs.get(host.certificateId) : undefined;
    const certificate = host.certificateId === null ? "automatic (ACME)" : cert ? `${cert.type === "imported" ? "imported" : "managed"}: ${clean(cert.name, 120)}` : `#${host.certificateId}`;
    const requestHosts = host.domains.map((domain) => domain.toLowerCase());
    let blocked: number | null = null;
    let detected: number | null = null;
    if (activity) {
      blocked = 0;
      detected = 0;
      for (const [requestHost, value] of activity) {
        if (isDomainCoveredByCert(requestHost, requestHosts)) {
          blocked += value.blocked;
          detected += value.detected;
        }
      }
    }

    const flags: string[] = [];
    if (host.enabled) {
      counts.enabled += 1;
      if (waf.mode === "blocking") counts.wafBlocking += 1;
      else if (waf.mode === "detection only") counts.wafDetection += 1;
      else counts.wafOff += 1;
      if (geo.enabled) counts.geo += 1;
      if (authentication.length > 0) counts.authenticated += 1;
      if (waf.mode === "off") {
        flags.push("waf_off");
        findings.push(finding("medium", "waf_off", subject, `${label} is not protected by the WAF (${waf.source}).`));
      } else if (waf.mode === "detection only") {
        flags.push("waf_detection_only");
        findings.push(finding("low", "waf_detection_only", subject, `${label} has the WAF in detection-only mode: matching requests are logged, not blocked.`));
      }
      if (waf.mode !== "off" && !waf.crs && !waf.customRules) {
        flags.push("waf_without_rules");
        findings.push(finding("low", "waf_without_rules", subject, `${label} has the WAF on without the OWASP Core Rule Set or custom rules.`));
      }
      if (!host.sslForced) {
        counts.noRedirect += 1;
        flags.push("https_redirect_off");
        findings.push(finding("medium", "https_redirect_off", subject, `${label} also answers over plain HTTP (no redirect to HTTPS).`));
      }
      if (!host.hstsEnabled) {
        counts.noHsts += 1;
        flags.push("hsts_off");
        findings.push(finding("low", "hsts_off", subject, `${label} does not send HSTS.`));
      }
      if (httpsUpstream && host.skipHttpsHostnameValidation) {
        counts.upstreamUnverified += 1;
        flags.push("upstream_tls_unverified");
        findings.push(finding("medium", "upstream_tls_unverified", subject, `${label} does not verify the TLS certificate of its HTTPS upstream.`));
      }
    }

    return {
      id: host.id,
      name: clean(host.name, 120),
      domains: host.domains.map((domain) => clean(domain, 253)),
      enabled: host.enabled,
      tags: host.tags.map((tag) => clean(tag, 40)),
      waf: waf.mode,
      wafSource: waf.source,
      owaspCrs: waf.crs,
      geoBlocking: geo.enabled,
      geoBlockingSource: geo.source,
      authentication: authentication.length > 0 ? authentication : ["none"],
      authenticationLimitedToPaths: partial,
      signInSkippedForAddresses: skippedFor.map((address) => clean(address, 64)),
      certificate,
      httpsRedirect: host.sslForced,
      hsts: host.hstsEnabled ? (host.hstsSubdomains ? "on, including subdomains" : "on") : "off",
      upstreamTlsVerification: httpsUpstream ? (host.skipHttpsHostnameValidation ? "skipped" : "verified") : "no HTTPS upstream",
      wafBlockedInPeriod: blocked,
      wafDetectedInPeriod: detected,
      flags,
    };
  });

  const l4Rows = (await appDb
    .select()
    .from(l4ProxyHosts)
    .orderBy(asc(l4ProxyHosts.name), asc(l4ProxyHosts.id)))
    .map((host) => ({
      id: host.id,
      name: clean(host.name, 120),
      protocol: clean(host.protocol, 10),
      listenAddress: clean(host.listenAddress, 100),
      matcher: host.matcherType === "none" ? "none" : `${clean(host.matcherType, 20)}: ${clean(host.matcherValue ?? "", 200)}`,
      tlsTermination: host.tlsTermination,
      upstreams: parseStringArray(host.upstreams).map((upstream) => clean(upstream, 200)),
      enabled: host.enabled,
      tags: parseStringArray(host.tags).map((tag) => clean(tag, 40)),
    }));

  // MFA coverage of dashboard users.
  const mfa = await listMfaAccountSummaries(context.now);
  const userStatus = new Map((await appDb.select({ id: users.id, status: users.status, customRoleId: users.customRoleId, name: users.name, email: users.email, username: users.username }).from(users)).map((row) => [row.id, row]));
  const adminLevelRoles = new Set((await listCustomRoleViews(appDb)).filter((role) => role.adminLevel).map((role) => role.id));
  const active = mfa.filter((summary) => userStatus.get(summary.id)?.status === "active");
  const isAdmin = (summary: (typeof mfa)[number]) => {
    const row = userStatus.get(summary.id);
    return (summary.role === "admin" && row?.customRoleId === null) || (row?.customRoleId != null && adminLevelRoles.has(row.customRoleId));
  };
  const admins = active.filter(isAdmin);
  const adminsWithout = admins.filter((summary) => !summary.enabled);
  if (adminsWithout.length > 0) {
    findings.push(
      finding(
        "high",
        "admins_without_mfa",
        "users",
        `${adminsWithout.length} active administrator(s) without MFA: ${adminsWithout.map((summary) => userLabel(userStatus.get(summary.id) ?? null, summary.id)).join(", ")}.`
      )
    );
  }

  const enabledHosts = counts.enabled;
  return {
    summary: [
      summaryItem("proxyHosts", "Proxy hosts", hosts.length),
      summaryItem("enabledProxyHosts", "Enabled proxy hosts", enabledHosts),
      summaryItem("wafBlocking", "Enabled hosts with the WAF blocking", counts.wafBlocking),
      summaryItem("wafBlockingPercent", "WAF blocking coverage (%)", percent(counts.wafBlocking, enabledHosts)),
      summaryItem("wafDetectionOnly", "Enabled hosts with the WAF in detection-only mode", counts.wafDetection),
      summaryItem("wafOff", "Enabled hosts without the WAF", counts.wafOff),
      summaryItem("geoBlocking", "Enabled hosts with geo blocking", counts.geo),
      summaryItem("authenticated", "Enabled hosts with authentication in front (access list, forward auth, mTLS or API keys)", counts.authenticated),
      summaryItem("httpsRedirectOff", "Enabled hosts without an HTTPS redirect", counts.noRedirect),
      summaryItem("hstsOff", "Enabled hosts without HSTS", counts.noHsts),
      summaryItem("upstreamTlsUnverified", "Enabled hosts not verifying their HTTPS upstream", counts.upstreamUnverified),
      summaryItem("l4Hosts", "L4 proxy hosts", l4Rows.length),
      summaryItem("activeUsers", "Active dashboard users", active.length),
      summaryItem("mfaCoveragePercent", "MFA coverage of active users (%)", percent(active.filter((summary) => summary.enabled).length, active.length)),
      summaryItem("adminMfaCoveragePercent", "MFA coverage of active administrators (%)", percent(admins.length - adminsWithout.length, admins.length)),
    ],
    findings: sortFindings(findings),
    sections: [
      section(
        "proxy_hosts",
        "Proxy hosts",
        "Effective settings of each HTTP proxy host, combining the global WAF and geo-blocking settings with the host's own. Hosts without authentication in front can be meant to be public.",
        columns([
          ["id", "Id"],
          ["name", "Name"],
          ["domains", "Domains"],
          ["enabled", "Enabled"],
          ["tags", "Tags"],
          ["waf", "WAF"],
          ["wafSource", "WAF settings from"],
          ["owaspCrs", "OWASP CRS"],
          ["geoBlocking", "Geo blocking"],
          ["geoBlockingSource", "Geo blocking from"],
          ["authentication", "Authentication in front"],
          ["authenticationLimitedToPaths", "Authentication limited to some paths"],
          ["signInSkippedForAddresses", "Sign-in skipped for these addresses"],
          ["certificate", "Certificate"],
          ["httpsRedirect", "HTTPS redirect"],
          ["hsts", "HSTS"],
          ["upstreamTlsVerification", "Upstream TLS verification"],
          ["wafBlockedInPeriod", "WAF blocked in period"],
          ["wafDetectedInPeriod", "WAF detected (not blocked) in period"],
          ["flags", "Flags"],
        ]),
        hostRows
      ),
      section(
        "l4_hosts",
        "L4 proxy hosts",
        "TCP/UDP proxy hosts. The WAF, access lists and forward auth work at HTTP level and do not apply to them.",
        columns([
          ["id", "Id"],
          ["name", "Name"],
          ["protocol", "Protocol"],
          ["listenAddress", "Listen address"],
          ["matcher", "Matcher"],
          ["tlsTermination", "TLS termination"],
          ["upstreams", "Upstreams"],
          ["enabled", "Enabled"],
          ["tags", "Tags"],
        ]),
        l4Rows
      ),
      keyValueSection("global", "Global protection settings", "As of generation time.", [
        ["WAF", globalWaf?.enabled ? (globalWaf.mode === "On" ? "on (blocking)" : globalWaf.mode === "DetectionOnly" ? "detection only" : "off") : "off"],
        ["WAF: OWASP Core Rule Set", globalWaf?.enabled ? globalWaf.load_owasp_crs === true : null],
        ["WAF: excluded rules", globalWaf?.enabled ? globalWaf.excluded_rule_ids?.length ?? 0 : null],
        ["Geo blocking", globalGeo?.enabled === true],
        ["Geo blocking: block rules", globalGeo?.enabled ? ruleCount(globalGeo, "block") : null],
        ["Geo blocking: allow rules", globalGeo?.enabled ? ruleCount(globalGeo, "allow") : null],
        ["Geo blocking: fail closed when the client address is unknown", globalGeo?.enabled ? globalGeo.fail_closed === true : null],
      ]),
      keyValueSection("mfa", "MFA coverage of dashboard users", null, [
        ["Active users", active.length],
        ["Active users with MFA", active.filter((summary) => summary.enabled).length],
        ["Active administrators", admins.length],
        ["Active administrators with MFA", admins.length - adminsWithout.length],
        ["Active administrators without MFA", adminsWithout.map((summary) => userLabel(userStatus.get(summary.id) ?? null, summary.id))],
      ]),
    ],
    notes: [
      ...notes,
      "Coverage is read from the configuration; it shows what is set up, not whether the upstream applications are secure.",
      "Disabled hosts are listed but not counted or flagged.",
    ],
  };
}
