/**
 * Caddy JSON for access list rules (src/lib/access-list-rules.ts).
 *
 * A list compiles to one `subroute` handler whose routes enforce "the first
 * matching rule decides" with plain matchers:
 *
 *  - An allow rule emits nothing itself. It is remembered, and every later
 *    deny (and the default deny) excludes the clients it allows: address
 *    allows through a `not` matcher, country, continent and AS number allows
 *    as the allow lists of the caddy-blocker handler that denies.
 *  - A deny rule by address or network matches with Caddy's `client_ip`
 *    matcher (server-level trusted proxies applied) or, when no trusted
 *    proxies are configured, `remote_ip`. It answers with a static response,
 *    or, when an earlier rule allows countries, continents or AS numbers,
 *    with a caddy-blocker handler that blocks everyone those allows do not
 *    cover.
 *  - A deny rule by country, continent or AS number uses the caddy-blocker
 *    handler (GeoLite2 lookups), with the earlier non-address allows as its
 *    allow lists.
 *  - A default action of deny is a last route that denies whoever no earlier
 *    allow covers.
 *
 * Consecutive deny rules of the same family share one route: they exclude
 * the same allows, so the result is the same. Static denials add the list to
 * the access log (log_append, ACCESS_LIST_LOG_FIELD) so analytics counts them
 * as blocked; caddy-blocker logs its own blocks.
 *
 * Pure: the caller passes the rules (expired ones already left out) and the
 * trusted-proxy context.
 */
import { escapeHostPlaceholders, expandPrivateRanges } from "./caddy-utils";
import {
  ACCESS_LIST_LOG_FIELD,
  DEFAULT_DENY_BODY,
  DEFAULT_DENY_STATUS,
  type AccessListDefaultAction,
  type AccessListRuleAction,
  type AccessListRuleKind,
} from "./access-list-rules";

type CaddyHandler = Record<string, unknown>;
type CaddyRoute = Record<string, unknown>;

export const GEOIP_COUNTRY_DB = "/usr/share/GeoIP/GeoLite2-Country.mmdb";
export const GEOIP_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";
/** Value of ACCESS_LIST_LOG_FIELD for the global Blocked sources list. */
export const BLOCKED_SOURCES_LOG_VALUE = "blocked_sources";

const EVERY_ADDRESS = ["0.0.0.0/0", "::/0"];

export type CompiledAccessListRule = {
  action: AccessListRuleAction;
  kind: AccessListRuleKind;
  values: readonly string[];
};

export type CompiledAccessList = {
  /** Written to the access log for static denials: the list id, or BLOCKED_SOURCES_LOG_VALUE. */
  logValue: string;
  rules: readonly CompiledAccessListRule[];
  defaultAction: AccessListDefaultAction;
  denyStatus: number;
  denyBody: string | null;
  denyRedirectUrl: string | null;
  failClosed: boolean;
};

export type AccessListCaddyContext = {
  /** Server-level trusted proxy ranges, normalized (private_ranges expanded). */
  trustedProxies: readonly string[];
};

/** The address matcher: client_ip when trusted proxies are configured, else remote_ip. */
export function addressMatcherName(context: AccessListCaddyContext): "client_ip" | "remote_ip" {
  return context.trustedProxies.length > 0 ? "client_ip" : "remote_ip";
}

function addressMatch(context: AccessListCaddyContext, ranges: readonly string[]): Record<string, unknown> {
  return { [addressMatcherName(context)]: { ranges: [...ranges] } };
}

function addressRanges(values: readonly string[]): string[] {
  return Array.from(new Set(expandPrivateRanges([...values])));
}

type GeoSets = { countries: string[]; continents: string[]; asns: number[] };

function emptyGeo(): GeoSets {
  return { countries: [], continents: [], asns: [] };
}

function geoIsEmpty(geo: GeoSets): boolean {
  return geo.countries.length === 0 && geo.continents.length === 0 && geo.asns.length === 0;
}

function addGeo(geo: GeoSets, kind: AccessListRuleKind, values: readonly string[]): void {
  const push = <T>(target: T[], items: T[]) => {
    for (const item of items) if (!target.includes(item)) target.push(item);
  };
  if (kind === "country") push(geo.countries, [...values]);
  else if (kind === "continent") push(geo.continents, [...values]);
  else if (kind === "asn") push(geo.asns, values.map(Number));
}

function denyHandlers(list: CompiledAccessList): CaddyHandler[] {
  const response: CaddyHandler = list.denyRedirectUrl
    ? {
        handler: "static_response",
        status_code: 302,
        headers: { Location: [escapeHostPlaceholders(list.denyRedirectUrl)] },
      }
    : {
        handler: "static_response",
        status_code: list.denyStatus || DEFAULT_DENY_STATUS,
        body: escapeHostPlaceholders(list.denyBody ?? DEFAULT_DENY_BODY),
      };
  return [{ handler: "log_append", key: ACCESS_LIST_LOG_FIELD, value: list.logValue }, response];
}

function blockerHandler(
  list: CompiledAccessList,
  context: AccessListCaddyContext,
  options: { allow: GeoSets; block?: GeoSets; blockEveryone?: boolean; failClosed?: boolean }
): CaddyHandler {
  const handler: CaddyHandler = { handler: "blocker", geoip_db: GEOIP_COUNTRY_DB, asn_db: GEOIP_ASN_DB };
  const block = options.block ?? emptyGeo();
  if (block.countries.length) handler.block_countries = [...block.countries];
  if (block.continents.length) handler.block_continents = [...block.continents];
  if (block.asns.length) handler.block_asns = [...block.asns];
  if (options.blockEveryone) handler.block_cidrs = [...EVERY_ADDRESS];
  if (options.allow.countries.length) handler.allow_countries = [...options.allow.countries];
  if (options.allow.continents.length) handler.allow_continents = [...options.allow.continents];
  if (options.allow.asns.length) handler.allow_asns = [...options.allow.asns];
  if (context.trustedProxies.length > 0) handler.trusted_proxies = [...context.trustedProxies];
  if (options.failClosed) handler.fail_closed = true;
  if (list.denyRedirectUrl) {
    handler.redirect_url = list.denyRedirectUrl;
  } else {
    handler.response_status = list.denyStatus || DEFAULT_DENY_STATUS;
    handler.response_body = list.denyBody ?? DEFAULT_DENY_BODY;
  }
  return handler;
}

function copyGeo(geo: GeoSets): GeoSets {
  return { countries: [...geo.countries], continents: [...geo.continents], asns: [...geo.asns] };
}

/** Matches the clients of the list's allow address rules; null when it has none. */
export function allowedAddressMatcher(list: CompiledAccessList, context: AccessListCaddyContext): Record<string, unknown> | null {
  const ranges = addressRanges(
    list.rules.filter((rule) => rule.action === "allow" && rule.kind === "ip").flatMap((rule) => rule.values)
  );
  return ranges.length > 0 ? addressMatch(context, ranges) : null;
}

/** The routes of a list's subroute, in order; empty when the list lets everyone through. */
export function buildAccessListRoutes(list: CompiledAccessList, context: AccessListCaddyContext): CaddyRoute[] {
  const routes: CaddyRoute[] = [];
  const allowedAddresses: string[] = [];
  const allowedGeo = emptyGeo();
  const excludeAllowedAddresses = (): Record<string, unknown> =>
    allowedAddresses.length > 0 ? { not: [addressMatch(context, allowedAddresses)] } : {};

  // Group consecutive rules of one action and family ("address" or "geo"):
  // a run of denies shares its exclusions, so it compiles to one route.
  type Run = { action: AccessListRuleAction; family: "address" | "geo"; rules: CompiledAccessListRule[] };
  const runs: Run[] = [];
  for (const rule of list.rules) {
    if (rule.values.length === 0) continue;
    const family = rule.kind === "ip" ? "address" : "geo";
    const last = runs[runs.length - 1];
    if (last && last.action === rule.action && last.family === family) last.rules.push(rule);
    else runs.push({ action: rule.action, family, rules: [rule] });
  }

  for (const run of runs) {
    if (run.action === "allow") {
      for (const rule of run.rules) {
        if (rule.kind === "ip") {
          for (const range of addressRanges(rule.values)) if (!allowedAddresses.includes(range)) allowedAddresses.push(range);
        } else {
          addGeo(allowedGeo, rule.kind, rule.values);
        }
      }
      continue;
    }

    if (run.family === "address") {
      const ranges = addressRanges(run.rules.flatMap((rule) => rule.values));
      const match = { ...addressMatch(context, ranges), ...excludeAllowedAddresses() };
      // The address matched; with country/ASN allows before it, only the
      // blocker can exempt those clients. An address it cannot attribute
      // (indeterminate behind a trusted proxy) is denied: the rule matched.
      const handle = geoIsEmpty(allowedGeo)
        ? denyHandlers(list)
        : [blockerHandler(list, context, { allow: copyGeo(allowedGeo), blockEveryone: true, failClosed: true })];
      routes.push({ match: [match], handle });
      continue;
    }

    const block = emptyGeo();
    for (const rule of run.rules) addGeo(block, rule.kind, rule.values);
    const route: CaddyRoute = { handle: [blockerHandler(list, context, { allow: copyGeo(allowedGeo), block })] };
    if (allowedAddresses.length > 0) route.match = [excludeAllowedAddresses()];
    routes.push(route);
  }

  if (list.defaultAction === "deny") {
    const route: CaddyRoute = {
      // Unmatched means denied, including a client whose address cannot be
      // worked out: an allow that cannot be checked does not let it in.
      handle: geoIsEmpty(allowedGeo)
        ? denyHandlers(list)
        : [blockerHandler(list, context, { allow: copyGeo(allowedGeo), blockEveryone: true, failClosed: true })],
    };
    if (allowedAddresses.length > 0) route.match = [excludeAllowedAddresses()];
    routes.push(route);
  }

  // "Block when the client address is unknown": a blocker without rules
  // first, which only blocks when it cannot work out the client behind a
  // trusted proxy. Without trusted proxies the address is always known.
  if (routes.length > 0 && list.failClosed && context.trustedProxies.length > 0) {
    routes.unshift({ handle: [blockerHandler(list, context, { allow: emptyGeo(), failClosed: true })] });
  }

  return routes;
}

/** The list as one handler (a subroute), or null when it lets every request through. */
export function buildAccessListHandler(list: CompiledAccessList, context: AccessListCaddyContext): CaddyHandler | null {
  const routes = buildAccessListRoutes(list, context);
  return routes.length > 0 ? { handler: "subroute", routes } : null;
}

/** Name of the named route that holds a list's rules (invoked from each host using it). */
export function accessListRouteName(listId: number): string {
  return `ingressi_acl_${listId}`;
}
