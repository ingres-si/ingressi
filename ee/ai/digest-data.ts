// SPDX-License-Identifier: Elastic-2.0
/**
 * The facts of the daily security digest, aggregated from ClickHouse (when
 * analytics is configured) and the dashboard's own database. Only counts,
 * host names, request paths without query strings, rule ids and messages,
 * countries and autonomous systems: never log lines, client addresses or
 * request contents.
 */
import { and, count, eq, gte, isNotNull, lte, notInArray } from "drizzle-orm";
import { appDb } from "@/src/lib/db";
import { alertEvents, auditEvents, proxyHosts, users } from "@/src/lib/db/schema";
import { evaluateCertExpiring } from "@/ee/alerting/evaluators";
import { openAsnLookup, type AsnLookup } from "./asn";
import {
  HOST_EXPR,
  PATH_EXPR,
  analyticsAvailable,
  defaultAnalyticsQuery,
  num,
  str,
  timeFilter,
  type AnalyticsQuery,
  type QueryParams,
} from "./clickhouse";
import { desc } from "@/src/lib/db/ops";

const HOUR_MS = 60 * 60 * 1000;
export const DIGEST_PERIOD_HOURS = 24;
export const DIGEST_BASELINE_DAYS = 7;
export const DIGEST_CERT_DAYS = 14;
const TOP = 5;
const MAX_LISTED_CHANGES = 10;
const MAX_LISTED_ALERTS = 10;
const MAX_ACCESS_LIST_DOMAINS = 200;
const ATTACK_SOURCE_IPS = 500;
const RECENT_IPS = 1000;
const BASELINE_IPS = 20_000;
const MAX_NEW_ASN_CANDIDATES = 20;
const MAX_NETWORK_CHECKS = 40;

/**
 * Audit actions that record sign-ins, tests, exports and other events that do
 * not change the configuration; the digest leaves them out of "configuration
 * changes".
 */
export const NON_CHANGE_AUDIT_ACTIONS = [
  "login_success",
  "signin_existing",
  "auto_link",
  "account_linked",
  "require_manual_link",
  "create_new",
  "oauth_link_rate_limited",
  "oauth_link_password_failed",
  "sso_enforced_sign_in_refused",
  "forward_auth_login",
  "forward_auth_login_failed",
  "forward_auth_access_denied",
  "config_exported",
  "config_snapshot_created",
  "audit_log_exported",
  "audit_log_verified",
  "audit_sink_test",
  "audit_sink_tested",
  "alert_channel_tested",
  "ai_provider_tested",
  "certificate_storage_tested",
  "ha_leader_started",
  // PostgreSQL replicas joining or refused (src/lib/cluster-nodes.ts): the deployment, not the configuration.
  "ha_replica_joined",
  "ha_replica_refused",
  "ai_digest_previewed",
  "ai_digest_sent",
  // Asking an analytics question (ee/ai/questions) reads traffic; it changes nothing.
  "analytics_question_asked",
  // Compliance reports and incident drafts (ee/compliance) record reading and drafting.
  "compliance_report_generated",
  "compliance_report_deleted",
  "compliance_incident_created",
  "compliance_incident_updated",
  "compliance_incident_drafted",
  "compliance_incident_facts_refreshed",
  "compliance_incident_deleted",
];

export type TrafficFacts = {
  requests: number;
  uniqueClients: number;
  blocked: { total: number; waf: number; geo: number; accessList: number };
  /** WAF matches that did not block (detection-only mode, or below the anomaly threshold). */
  wafDetectedNotBlocked: number;
  topAttackedHosts: { host: string; events: number }[];
  topAttackedPaths: { host: string; path: string; events: number }[];
  topWafRules: { ruleId: number; message: string | null; events: number }[];
  topSourceCountries: { country: string; events: number }[];
  /** null when the GeoLite2-ASN database is not available. */
  topSourceNetworks: { asn: number; organization: string; events: number }[] | null;
  /** null when there is no earlier traffic to compare with. */
  newCountries: { country: string; requests: number }[] | null;
  newNetworks: { asn: number; organization: string; requests: number }[] | null;
};

export type DigestFacts = {
  period: { from: string; to: string; hours: number };
  analytics: { status: "ok" | "disabled" | "error"; note: string | null };
  traffic: TrafficFacts | null;
  certificates: {
    withinDays: number;
    /** Availability/validation findings have no inferred expiry countdown. */
    attention?: { kind: string; name: string; state: string; message: string }[];
    expiring: { kind: string; name: string; expiresAt: string; daysLeft: number; expired: boolean }[];
  };
  configChanges: { total: number; recent: { at: string; actor: string; summary: string }[] };
  alerts: { fired: number; resolved: number; recent: { at: string; severity: string; title: string }[] };
  notes: string[];
};

export type DigestDataDependencies = {
  analyticsEnabled: () => boolean;
  query: AnalyticsQuery;
  asnLookup: () => Promise<AsnLookup | null>;
};

const defaultDependencies: DigestDataDependencies = {
  analyticsEnabled: analyticsAvailable,
  query: defaultAnalyticsQuery,
  asnLookup: () => openAsnLookup(),
};

function seconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

function parseJsonArray(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

/** Domains of proxy hosts protected by an access list (basic auth). */
async function accessListDomains(): Promise<string[]> {
  const rows = await appDb.select({ domains: proxyHosts.domains }).from(proxyHosts).where(isNotNull(proxyHosts.accessListId));
  const domains = new Set<string>();
  for (const row of rows) for (const domain of parseJsonArray(row.domains)) domains.add(domain.toLowerCase());
  return [...domains].slice(0, MAX_ACCESS_LIST_DOMAINS);
}

/** countIf() expression for 401 answers on access-list hosts (exact or wildcard domains), with its parameters. */
function accessListCondition(domains: string[]): { sql: string; params: QueryParams } {
  if (domains.length === 0) return { sql: "0", params: {} };
  const params: QueryParams = {};
  const exact: string[] = [];
  const wildcard: string[] = [];
  domains.forEach((domain, index) => {
    if (domain.startsWith("*.")) {
      params[`alw_${index}`] = domain.slice(1);
      wildcard.push(`endsWith(${HOST_EXPR}, {alw_${index}:String})`);
    } else {
      params[`al_${index}`] = domain;
      exact.push(`{al_${index}:String}`);
    }
  });
  const hostMatch = [exact.length ? `${HOST_EXPR} IN (${exact.join(", ")})` : null, ...wildcard].filter(Boolean).join(" OR ");
  return { sql: `countIf(status = 401 AND (${hostMatch}))`, params };
}

async function collectTraffic(
  deps: DigestDataDependencies,
  from: Date,
  to: Date,
  notes: string[]
): Promise<TrafficFacts> {
  const q = deps.query;
  const tp = { p_from: seconds(from), p_to: seconds(to) };
  const access = accessListCondition(await accessListDomains());

  const [trafficRows, wafRows, hostRows, pathRows, ruleRows, countryRows] = await Promise.all([
    q<{ requests: string; clients: string; geo_blocked: string; access_denied: string }>(
      `SELECT count() AS requests, uniq(client_ip) AS clients, countIf(is_blocked) AS geo_blocked, ${access.sql} AS access_denied
       FROM traffic_events WHERE ${timeFilter()}`,
      { ...tp, ...access.params }
    ),
    q<{ waf_blocked: string; waf_detected: string }>(
      `SELECT countIf(blocked) AS waf_blocked, countIf(NOT blocked) AS waf_detected FROM waf_events WHERE ${timeFilter()}`,
      tp
    ),
    q<{ host: string; events: string }>(
      `SELECT h AS host, sum(c) AS events FROM (
         SELECT ${HOST_EXPR} AS h, count() AS c FROM waf_events WHERE ${timeFilter()} GROUP BY h
         UNION ALL
         SELECT ${HOST_EXPR} AS h, count() AS c FROM traffic_events WHERE ${timeFilter()} AND is_blocked GROUP BY h
       ) WHERE h != '' GROUP BY h ORDER BY events DESC LIMIT {p_limit:UInt32}`,
      { ...tp, p_limit: TOP }
    ),
    q<{ h: string; p: string; events: string }>(
      `SELECT ${HOST_EXPR} AS h, ${PATH_EXPR} AS p, count() AS events
       FROM waf_events WHERE ${timeFilter()}
       GROUP BY h, p ORDER BY events DESC LIMIT {p_limit:UInt32}`,
      { ...tp, p_limit: TOP }
    ),
    q<{ rule_id: string | number; message: string | null; events: string }>(
      `SELECT rule_id, any(rule_message) AS message, count() AS events
       FROM waf_events WHERE ${timeFilter()} AND rule_id IS NOT NULL
       GROUP BY rule_id ORDER BY events DESC LIMIT {p_limit:UInt32}`,
      { ...tp, p_limit: TOP }
    ),
    q<{ country: string; events: string }>(
      `SELECT country, sum(c) AS events FROM (
         SELECT ifNull(country_code, '') AS country, count() AS c FROM waf_events WHERE ${timeFilter()} GROUP BY country
         UNION ALL
         SELECT ifNull(country_code, '') AS country, count() AS c FROM traffic_events WHERE ${timeFilter()} AND is_blocked GROUP BY country
       ) WHERE country != '' GROUP BY country ORDER BY events DESC LIMIT {p_limit:UInt32}`,
      { ...tp, p_limit: TOP }
    ),
  ]);

  const traffic = trafficRows[0];
  const waf = wafRows[0];
  const blocked = {
    waf: num(waf?.waf_blocked),
    geo: num(traffic?.geo_blocked),
    accessList: num(traffic?.access_denied),
  };
  const facts: TrafficFacts = {
    requests: num(traffic?.requests),
    uniqueClients: num(traffic?.clients),
    blocked: { total: blocked.waf + blocked.geo + blocked.accessList, ...blocked },
    wafDetectedNotBlocked: num(waf?.waf_detected),
    topAttackedHosts: hostRows.map((row) => ({ host: str(row.host, 253), events: num(row.events) })).filter((row) => row.host),
    topAttackedPaths: pathRows.map((row) => ({ host: str(row.h, 253), path: str(row.p) || "/", events: num(row.events) })),
    topWafRules: ruleRows.map((row) => ({ ruleId: num(row.rule_id), message: row.message ? str(row.message) : null, events: num(row.events) })),
    topSourceCountries: countryRows.map((row) => ({ country: str(row.country, 8), events: num(row.events) })).filter((row) => row.country),
    topSourceNetworks: null,
    newCountries: null,
    newNetworks: null,
  };

  const asnLookup: AsnLookup | null = await deps.asnLookup().catch(() => null);
  if (!asnLookup) notes.push("Autonomous systems are not shown: the GeoLite2-ASN database is not available.");

  if (asnLookup) {
    try {
      const sources = await q<{ ip: string; events: string }>(
        `SELECT ip, sum(c) AS events FROM (
           SELECT client_ip AS ip, count() AS c FROM waf_events WHERE ${timeFilter()} GROUP BY ip
           UNION ALL
           SELECT client_ip AS ip, count() AS c FROM traffic_events WHERE ${timeFilter()} AND is_blocked GROUP BY ip
         ) WHERE ip != '' GROUP BY ip ORDER BY events DESC LIMIT {p_limit:UInt32}`,
        { ...tp, p_limit: ATTACK_SOURCE_IPS }
      );
      facts.topSourceNetworks = aggregateByAsn(sources.map((row) => ({ ip: row.ip, count: num(row.events) })), asnLookup)
        .slice(0, TOP)
        .map(({ asn, organization, count: events }) => ({ asn, organization, events }));
    } catch {
      notes.push("Attack sources by autonomous system could not be computed.");
    }
  }

  await collectNewSources(deps, from, to, asnLookup, facts, notes);
  return facts;
}

type AsnCount = { asn: number; organization: string; count: number; networks: Set<string> };

/** Sums per-address counts by autonomous system, largest first. */
export function aggregateByAsn(rows: { ip: string; count: number }[], lookup: AsnLookup): AsnCount[] {
  const byAsn = new Map<number, AsnCount>();
  for (const row of rows) {
    const info = lookup(row.ip);
    if (!info) continue;
    const entry = byAsn.get(info.asn) ?? { asn: info.asn, organization: str(info.organization, 120), count: 0, networks: new Set<string>() };
    entry.count += row.count;
    entry.networks.add(info.network);
    byAsn.set(info.asn, entry);
  }
  return [...byAsn.values()].sort((a, b) => b.count - a.count || a.asn - b.asn);
}

/** Countries and autonomous systems seen in the last 24 hours but not in the 7 days before. */
async function collectNewSources(
  deps: DigestDataDependencies,
  from: Date,
  to: Date,
  asnLookup: AsnLookup | null,
  facts: TrafficFacts,
  notes: string[]
): Promise<void> {
  const q = deps.query;
  const since = new Date(from.getTime() - DIGEST_BASELINE_DAYS * 24 * HOUR_MS);
  const window = { p_since: seconds(since), p_from: seconds(from), p_to: seconds(to) };
  try {
    const [baseline] = await q<{ earlier: string; first_ts: string }>(
      `SELECT count() AS earlier, toUInt32(min(ts)) AS first_ts FROM traffic_events
       WHERE ts >= toDateTime({p_since:UInt32}) AND ts < toDateTime({p_from:UInt32})`,
      window
    );
    if (num(baseline?.earlier) === 0) {
      notes.push("New countries and networks are not shown: no traffic was recorded in the 7 days before.");
      return;
    }
    const firstTs = num(baseline?.first_ts);
    const daysCovered = Math.floor((seconds(from) - firstTs) / 86400);
    if (firstTs > 0 && daysCovered < DIGEST_BASELINE_DAYS - 1) {
      notes.push(`New countries and networks are compared with ${Math.max(daysCovered, 1)} day(s) of earlier traffic only.`);
    }

    const countries = await q<{ country: string; recent: string }>(
      `SELECT country_code AS country, countIf(ts >= toDateTime({p_from:UInt32})) AS recent, countIf(ts < toDateTime({p_from:UInt32})) AS earlier
       FROM traffic_events
       WHERE ts >= toDateTime({p_since:UInt32}) AND ts <= toDateTime({p_to:UInt32}) AND country_code IS NOT NULL AND country_code != ''
       GROUP BY country HAVING recent > 0 AND earlier = 0 ORDER BY recent DESC LIMIT 20`,
      window
    );
    facts.newCountries = countries.map((row) => ({ country: str(row.country, 8), requests: num(row.recent) })).filter((row) => row.country);

    if (!asnLookup) return;
    const [recent, earlier] = await Promise.all([
      q<{ ip: string; requests: string }>(
        `SELECT client_ip AS ip, count() AS requests FROM traffic_events
         WHERE ${timeFilter()} AND client_ip != '' GROUP BY ip ORDER BY requests DESC LIMIT {p_limit:UInt32}`,
        { ...window, p_limit: RECENT_IPS }
      ),
      q<{ ip: string }>(
        `SELECT client_ip AS ip FROM traffic_events
         WHERE ts >= toDateTime({p_since:UInt32}) AND ts < toDateTime({p_from:UInt32}) AND client_ip != ''
         GROUP BY ip ORDER BY count() DESC LIMIT {p_limit:UInt32}`,
        { ...window, p_limit: BASELINE_IPS }
      ),
    ]);
    const known = new Set<number>();
    for (const row of earlier) {
      const info = asnLookup(row.ip);
      if (info) known.add(info.asn);
    }
    const candidates = aggregateByAsn(recent.map((row) => ({ ip: row.ip, count: num(row.requests) })), asnLookup)
      .filter((entry) => !known.has(entry.asn))
      .slice(0, MAX_NEW_ASN_CANDIDATES);
    // The busiest earlier addresses are a sample: confirm that none of the
    // candidates' networks sent anything in the earlier period.
    const networks: { key: string; asn: number; cidr: string }[] = [];
    for (const candidate of candidates) {
      for (const cidr of candidate.networks) {
        if (networks.length >= MAX_NETWORK_CHECKS) break;
        networks.push({ key: `n_${networks.length}`, asn: candidate.asn, cidr });
      }
    }
    const seenBefore = new Set<number>();
    if (networks.length > 0) {
      const [row] = await q<Record<string, string>>(
        `SELECT ${networks.map((network) => `countIf(isIPAddressInRange(client_ip, {${network.key}:String})) AS ${network.key}`).join(", ")}
         FROM traffic_events WHERE ts >= toDateTime({p_since:UInt32}) AND ts < toDateTime({p_from:UInt32})`,
        { ...window, ...Object.fromEntries(networks.map((network) => [network.key, network.cidr])) }
      );
      for (const network of networks) {
        if (num(row?.[network.key]) > 0) seenBefore.add(network.asn);
      }
    }
    const checked = new Set(networks.map((network) => network.asn));
    facts.newNetworks = candidates
      .filter((entry) => checked.has(entry.asn) && !seenBefore.has(entry.asn))
      .slice(0, 10)
      .map(({ asn, organization, count: requests }) => ({ asn, organization, requests }));
  } catch {
    notes.push("New countries and networks could not be computed.");
  }
}

async function collectCertificates(now: Date): Promise<DigestFacts["certificates"]> {
  const evaluation = await evaluateCertExpiring({ days: DIGEST_CERT_DAYS, includeClientCertificates: true, includeManagedCertificates: true }, now);
  const expiring: DigestFacts["certificates"]["expiring"] = [];
  const attention: NonNullable<DigestFacts["certificates"]["attention"]> = [];
  if (evaluation.status !== "ok") {
    attention.push({ kind: "Certificate status", name: "", state: "unknown", message: "Certificate status could not be checked." });
  } else for (const finding of evaluation.findings) {
    const kind = String(finding.facts.certificateKind ?? "Certificate");
    const name = str(String(finding.facts.name ?? finding.facts.domain ?? ""), 120);
    const raw = finding.facts.expiresAt;
    const expiry = typeof raw === "string" && raw.trim() ? Date.parse(raw) : NaN;
    const state = typeof finding.facts.state === "string" ? finding.facts.state : "unknown";
    // No usable expiry, or a certificate that is not the one asked for: a
    // finding about availability, never a countdown. Findings past the expiry
    // window (a renewal that is overdue but not yet close to expiry) too.
    if (
      !Number.isFinite(expiry) ||
      state === "missing" ||
      state === "mismatch" ||
      expiry > now.getTime() + DIGEST_CERT_DAYS * 24 * HOUR_MS
    ) {
      attention.push({ kind, name, state, message: str(finding.message, 1000) });
      continue;
    }
    // The actual date is authoritative, including managed certificates whose
    // findings do not carry an `expired` flag. Null never becomes zero days.
    const daysLeft = Math.floor((expiry - now.getTime()) / (24 * HOUR_MS));
    expiring.push({ kind, name, expiresAt: new Date(expiry).toISOString(), daysLeft, expired: expiry <= now.getTime() });
  }
  expiring.sort((a, b) => a.expiresAt.localeCompare(b.expiresAt));
  return { withinDays: DIGEST_CERT_DAYS, expiring, attention };
}

async function collectConfigChanges(from: Date, to: Date): Promise<DigestFacts["configChanges"]> {
  const where = and(
    gte(auditEvents.createdAt, from.toISOString()),
    lte(auditEvents.createdAt, to.toISOString()),
    notInArray(auditEvents.action, NON_CHANGE_AUDIT_ACTIONS)
  );
  const [rows, [{ value: total }]] = await Promise.all([
    appDb
      .select({
        createdAt: auditEvents.createdAt,
        summary: auditEvents.summary,
        action: auditEvents.action,
        entityType: auditEvents.entityType,
        userId: auditEvents.userId,
        username: users.username,
        name: users.name,
      })
      .from(auditEvents)
      .leftJoin(users, eq(users.id, auditEvents.userId))
      .where(where)
      .orderBy(desc(auditEvents.createdAt), desc(auditEvents.id))
      .limit(MAX_LISTED_CHANGES),
    appDb.select({ value: count() }).from(auditEvents).where(where),
  ]);
  return {
    total,
    recent: rows.map((row) => ({
      at: row.createdAt,
      actor: str(row.username || row.name || (row.userId ? `user ${row.userId}` : "system"), 80),
      summary: str(row.summary || `${row.action} ${row.entityType}`, 300),
    })),
  };
}

async function collectAlerts(from: Date, to: Date): Promise<DigestFacts["alerts"]> {
  const inPeriod = and(gte(alertEvents.createdAt, from.toISOString()), lte(alertEvents.createdAt, to.toISOString()));
  const [firing, [{ value: fired }], [{ value: resolved }]] = await Promise.all([
    appDb
      .select({ createdAt: alertEvents.createdAt, severity: alertEvents.severity, title: alertEvents.title })
      .from(alertEvents)
      .where(and(inPeriod, eq(alertEvents.status, "firing")))
      .orderBy(desc(alertEvents.createdAt), desc(alertEvents.id))
      .limit(MAX_LISTED_ALERTS),
    appDb.select({ value: count() }).from(alertEvents).where(and(inPeriod, eq(alertEvents.status, "firing"))),
    appDb.select({ value: count() }).from(alertEvents).where(and(inPeriod, eq(alertEvents.status, "resolved"))),
  ]);
  return {
    fired,
    resolved,
    recent: firing.map((row) => ({ at: row.createdAt, severity: str(row.severity, 16), title: str(row.title, 300) })),
  };
}

/** Collects every section of the digest for the 24 hours up to `now`. */
export async function collectDigestFacts(
  now: Date = new Date(),
  dependencies: Partial<DigestDataDependencies> = {}
): Promise<DigestFacts> {
  const deps: DigestDataDependencies = { ...defaultDependencies, ...dependencies };
  const to = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const from = new Date(to.getTime() - DIGEST_PERIOD_HOURS * HOUR_MS);
  const notes: string[] = [];

  let analytics: DigestFacts["analytics"];
  let traffic: TrafficFacts | null = null;
  if (!deps.analyticsEnabled()) {
    analytics = {
      status: "disabled",
      note: "ClickHouse analytics is not configured, so traffic, blocked-request and attack figures are not included.",
    };
  } else {
    try {
      traffic = await collectTraffic(deps, from, to, notes);
      analytics = { status: "ok", note: null };
    } catch {
      analytics = {
        status: "error",
        note: "ClickHouse could not be queried, so traffic, blocked-request and attack figures are not included.",
      };
    }
  }

  const [certificates, configChanges, alerts] = await Promise.all([
    collectCertificates(now),
    collectConfigChanges(from, to),
    collectAlerts(from, to),
  ]);

  return {
    period: { from: from.toISOString(), to: to.toISOString(), hours: DIGEST_PERIOD_HOURS },
    analytics,
    traffic,
    certificates,
    configChanges,
    alerts,
    notes,
  };
}
