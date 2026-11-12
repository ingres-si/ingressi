/**
 * The host editor's change list: each group of settings the editor tracks,
 * with the section it lives in, a label, how it reads in the review (one line
 * per setting) and how to undo it. Pure functions over HostForm.
 */
import { diffLines, type DiffLine } from "@/components/ui/diff";
import { RATE_LIMIT_KEY_LABELS } from "@/lib/rate-limit-rules";
import { addressList, canonical, effectiveGrants, LB_POLICIES, serializeUpstreams, splitList, type HostForm, type LbForm } from "./model";

export const SECTIONS = ["routing", "security", "access", "certificate", "headers", "advanced"] as const;
export type SectionId = (typeof SECTIONS)[number];

export const SECTION_LABELS: Record<SectionId, string> = {
  routing: "Routing",
  security: "Security",
  access: "Access",
  certificate: "Certificate",
  headers: "Headers",
  advanced: "Advanced",
};

export function isSectionId(value: string): value is SectionId {
  return (SECTIONS as readonly string[]).includes(value);
}

/** Names of the things a form refers to by id. */
export type ChangeLookup = {
  certificate: (id: number) => string;
  accessList: (id: number) => string;
  user: (id: number) => string;
  group: (id: number) => string;
  role: (id: number) => string;
  clientCertificate: (id: number) => string;
  ca: (id: number) => string;
  globalWafMode: string;
};

type Kind = "value" | "list" | "text";

export type ChangeGroup = {
  id: string;
  section: SectionId;
  label: string;
  /** The field to focus when the review's "Show" is used. */
  focus: string;
  kind: Kind;
  /** Compared to tell whether the group changed. */
  value: (form: HostForm) => unknown;
  /** How it reads: one line (value), one line per item (list) or the text itself (text). */
  lines: (form: HostForm, lookup: ChangeLookup) => string[];
  /** The form with this group put back as it was. */
  restore: (form: HostForm, saved: HostForm) => HostForm;
};

const onOff = (value: boolean) => (value ? "On" : "Off");
const orNone = (value: string) => (value.trim() ? value.trim() : "Not set");

function keys<K extends keyof HostForm>(...names: K[]) {
  return (form: HostForm, saved: HostForm): HostForm => {
    const next = { ...form };
    for (const name of names) next[name] = saved[name];
    return next;
  };
}

function lbLines(lb: LbForm, prefix = ""): string[] {
  if (!lb.enabled) return [`${prefix}Caddy default: random, no health checks`];
  const policy = LB_POLICIES.find((entry) => entry.value === lb.policy)?.label ?? lb.policy;
  const lines = [`${prefix}Policy: ${policy}`];
  if (lb.policy === "header") lines.push(`${prefix}Header to hash: ${orNone(lb.headerField)}`);
  if (lb.policy === "cookie") {
    lines.push(`${prefix}Cookie name: ${orNone(lb.cookieName)}`);
    lines.push(`${prefix}Cookie signing secret: ${lb.cookieSecret ? `set (${lb.cookieSecret.length} characters)` : "not set"}`);
  }
  if (lb.tryDuration) lines.push(`${prefix}Keep trying for: ${lb.tryDuration}`);
  if (lb.tryInterval) lines.push(`${prefix}Wait between tries: ${lb.tryInterval}`);
  if (lb.retries) lines.push(`${prefix}Max retries: ${lb.retries}`);
  if (lb.active.enabled) {
    const a = lb.active;
    lines.push(
      `${prefix}Active health checks: ${[a.uri || "/", a.port && `port ${a.port}`, a.interval && `every ${a.interval}`, a.timeout && `timeout ${a.timeout}`, a.status && `expects ${a.status}`, a.body && `body "${a.body}"`].filter(Boolean).join(", ")}`
    );
  } else {
    lines.push(`${prefix}Active health checks: off`);
  }
  if (lb.passive.enabled) {
    const p = lb.passive;
    lines.push(
      `${prefix}Passive health checks: ${[p.maxFails && `${p.maxFails} failures`, p.failDuration && `within ${p.failDuration}`, p.unhealthyStatus && `statuses ${p.unhealthyStatus}`, p.unhealthyLatency && `slower than ${p.unhealthyLatency}`].filter(Boolean).join(", ") || "on"}`
    );
  } else {
    lines.push(`${prefix}Passive health checks: off`);
  }
  return lines;
}

const WAF_MODE_LABELS = { inherit: "Global mode", off: "Off", detection_only: "Detect only", block: "Block" } as const;
const BODY_ACTION_LABELS = { inherit: "Global default", Reject: "Reject with 413", ProcessPartial: "Inspect the first part, pass the rest" } as const;
const SIGN_IN_LABELS = { none: "None", ingressi: "Built-in sign-in", authentik: "Authentik", generic: "Authelia or custom" } as const;

function geoLines(form: HostForm): string[] {
  const g = form.geoblock;
  if (!g.enabled && g.mode === "merge") {
    const lines = ["Off"];
    return lines;
  }
  const list = (label: string, values: string[]) => (values.length > 0 ? [`${label}: ${values.join(", ")}`] : []);
  return [
    g.enabled ? "On" : "Off",
    g.mode === "override" ? "Overrides the global rules" : "Merges with the global rules",
    ...list("Block countries", g.blockCountries),
    ...list("Block continents", g.blockContinents),
    ...list("Block ASNs", g.blockAsns),
    ...list("Block ranges", g.blockCidrs),
    ...list("Block addresses", g.blockIps),
    ...list("Allow countries", g.allowCountries),
    ...list("Allow continents", g.allowContinents),
    ...list("Allow ASNs", g.allowAsns),
    ...list("Allow ranges", g.allowCidrs),
    ...list("Allow addresses", g.allowIps),
    ...list("Trusted proxies", g.trustedProxies),
    ...(g.failClosed ? ["Blocks requests whose address is unknown"] : []),
    g.redirectUrl.trim() ? `Blocked clients are redirected to ${g.redirectUrl.trim()}` : `Blocked clients get ${g.responseStatus} "${g.responseBody}"`,
    ...g.headers.filter((row) => row.name.trim()).map((row) => `Response header ${row.name.trim()}: ${row.value.trim()}`),
  ];
}

function signInValue(form: HostForm): unknown {
  switch (form.signIn) {
    case "authentik":
      return { signIn: form.signIn, authentik: { ...form.authentik, bypassSources: addressList(form.authentik.bypassSources) } };
    case "generic":
      return { signIn: form.signIn, forwardAuth: { ...form.forwardAuth, bypassSources: addressList(form.forwardAuth.bypassSources) } };
    case "ingressi":
      return {
        signIn: form.signIn,
        protectedPaths: splitList(form.ingressi.protectedPaths),
        excludedPaths: splitList(form.ingressi.excludedPaths),
        bypassSources: addressList(form.ingressi.bypassSources),
      };
    default:
      return { signIn: "none" };
  }
}

function pathsLine(label: string, value: string): string[] {
  const list = splitList(value);
  return list.length > 0 ? [`${label}: ${list.join(", ")}`] : [];
}

function sourcesLine(value: string): string[] {
  const list = addressList(value);
  return list.length > 0 ? [`Skip sign-in from: ${list.join(", ")}`] : [];
}

function signInLines(form: HostForm): string[] {
  const lines: string[] = [SIGN_IN_LABELS[form.signIn]];
  if (form.signIn === "authentik") {
    const a = form.authentik;
    lines.push(
      `Outpost domain: ${orNone(a.outpostDomain)}`,
      `Outpost upstream: ${orNone(a.outpostUpstream)}`,
      `Auth endpoint: ${orNone(a.authEndpoint)}`,
      `Headers copied: ${splitList(a.copyHeaders).join(", ") || "None"}`,
      `Trusted proxies: ${splitList(a.trustedProxies).join(", ") || "None"}`,
      `Sets the outpost's Host header: ${a.setHostHeader ? "yes" : "no"}`,
      ...pathsLine("Only these paths", a.protectedPaths),
      ...pathsLine("Never these paths", a.excludedPaths),
      ...sourcesLine(a.bypassSources)
    );
  } else if (form.signIn === "generic") {
    const f = form.forwardAuth;
    lines.push(
      `Preset: ${f.provider === "authelia" ? "Authelia" : "Custom"}`,
      `Auth server: ${orNone(f.authUpstream)}`,
      `Auth endpoint: ${orNone(f.authEndpoint)}`,
      `Headers copied: ${splitList(f.copyHeaders).join(", ") || "None"}`,
      `Trusted proxies: ${splitList(f.trustedProxies).join(", ") || "None"}`,
      `401 for API clients: ${f.apiSplit ? "yes" : "no"}`,
      ...pathsLine("Skip sign-in with header", f.apiBypassHeaders),
      ...pathsLine("Only these paths", f.protectedPaths),
      ...pathsLine("Never these paths", f.excludedPaths),
      ...sourcesLine(f.bypassSources)
    );
  } else if (form.signIn === "ingressi") {
    lines.push(
      ...pathsLine("Only these paths", form.ingressi.protectedPaths),
      ...pathsLine("Never these paths", form.ingressi.excludedPaths),
      ...sourcesLine(form.ingressi.bypassSources)
    );
  }
  return lines;
}

function wafLines(form: HostForm, lookup: ChangeLookup): string[] {
  const w = form.waf;
  const mode = w.mode === "inherit" ? `Global mode (${lookup.globalWafMode})` : WAF_MODE_LABELS[w.mode];
  if (w.mode === "off") return [`Mode: ${mode}`];
  return [
    `Mode: ${mode}`,
    `Rules: ${w.rules === "override" ? "Override global" : "Merge with global"}`,
    `OWASP Core Rule Set: ${w.loadCrs ? "loaded" : "not loaded"}`,
    `Max request body: ${w.bodyLimit ? `${w.bodyLimit} MiB` : "global default"}`,
    `Buffered in memory: ${w.bodyMemory ? `${w.bodyMemory} MiB` : "global default"}`,
    `Larger bodies: ${BODY_ACTION_LABELS[w.bodyAction]}`,
  ];
}

function mtlsLines(form: HostForm, lookup: ChangeLookup): string[] {
  const m = form.mtls;
  if (!m.enabled) return ["Off"];
  return [
    "Required",
    ...(m.trustMode === "ca"
      ? m.caIds.map((id) => `Any certificate signed by ${lookup.ca(id)}`)
      : [
          ...m.roleIds.map((id) => `Role ${lookup.role(id)}`),
          ...m.certIds.map((id) => `Certificate ${lookup.clientCertificate(id)}`),
        ]),
    ...pathsLine("Only these paths", m.protectedPaths),
    ...pathsLine("Never these paths", m.excludedPaths),
  ];
}

function rateLimitLines(form: HostForm): string[] {
  const r = form.rateLimit;
  const mode = !r.enabled ? "Global defaults only" : r.mode === "override" ? "Override global" : "Merge with global";
  return [
    `Mode: ${mode}`,
    ...r.rules.map((rule) => {
      const by = rule.by === "header" ? `header ${rule.header.trim() || "(none)"}` : RATE_LIMIT_KEY_LABELS[rule.by].toLowerCase();
      const unit = { s: "second", m: "minute", h: "hour" }[rule.windowUnit];
      const window = rule.windowValue === "1" ? unit : `${rule.windowValue} ${unit}s`;
      return `${rule.methods.length > 0 ? rule.methods.join(" ") : "Any method"} ${rule.path.trim() || "*"} · ${rule.events} per ${window} · per ${by}`;
    }),
  ];
}

function dnsLines(form: HostForm): string[] {
  const d = form.dnsResolver;
  if (!d.enabled) return ["System resolvers"];
  return [
    `Resolvers: ${splitList(d.resolvers).join(", ") || "None"}`,
    ...(splitList(d.fallbacks).length > 0 ? [`Fallbacks: ${splitList(d.fallbacks).join(", ")}`] : []),
    ...(d.timeout.trim() ? [`Timeout: ${d.timeout.trim()}`] : []),
  ];
}

const PINNING_MODES = { inherit: "Inherit global", enabled: "Enabled", disabled: "Disabled" } as const;
const PINNING_FAMILIES = { inherit: "Inherit global", both: "Both, IPv6 first", ipv6: "IPv6 only", ipv4: "IPv4 only" } as const;

export function changeGroups(mode: "create" | "edit"): ChangeGroup[] {
  const nameSection: SectionId = mode === "create" ? "routing" : "advanced";
  return [
    { id: "enabled", section: "routing", label: "Host enabled", focus: "f-enabled", kind: "value", value: (f) => f.enabled, lines: (f) => [f.enabled ? "Enabled" : "Disabled"], restore: keys("enabled") },
    { id: "name", section: nameSection, label: "Name", focus: "f-name", kind: "value", value: (f) => f.name.trim(), lines: (f) => [orNone(f.name)], restore: keys("name") },
    { id: "tags", section: nameSection, label: "Tags", focus: "f-tags", kind: "list", value: (f) => f.tags, lines: (f) => f.tags, restore: keys("tags") },
    { id: "domains", section: "routing", label: "Domains", focus: "f-domains", kind: "list", value: (f) => f.domains, lines: (f) => f.domains, restore: keys("domains") },
    {
      id: "upstreams",
      section: "routing",
      label: "Upstreams",
      focus: "f-up-0",
      kind: "list",
      value: (f) => serializeUpstreams(f.upstreams),
      lines: (f) => serializeUpstreams(f.upstreams),
      restore: keys("upstreams"),
    },
    { id: "lb", section: "routing", label: "Load balancing", focus: "f-lb-enabled", kind: "list", value: (f) => (f.lb.enabled ? f.lb : false), lines: (f) => lbLines(f.lb), restore: keys("lb") },
    { id: "allowWebsocket", section: "routing", label: "WebSockets", focus: "f-ws", kind: "value", value: (f) => f.allowWebsocket, lines: (f) => [onOff(f.allowWebsocket)], restore: keys("allowWebsocket") },
    {
      id: "preserveHostHeader",
      section: "routing",
      label: "Preserve Host header",
      focus: "f-preserve-host",
      kind: "value",
      value: (f) => f.preserveHostHeader,
      lines: (f) => [onOff(f.preserveHostHeader)],
      restore: keys("preserveHostHeader"),
    },
    {
      id: "skipHttpsHostnameValidation",
      section: "routing",
      label: "Skip upstream certificate check",
      focus: "f-skip-verify",
      kind: "value",
      value: (f) => f.skipHttpsHostnameValidation,
      lines: (f) => [onOff(f.skipHttpsHostnameValidation)],
      restore: keys("skipHttpsHostnameValidation"),
    },
    {
      id: "locationRules",
      section: "routing",
      label: "Path-based routes",
      focus: "f-routes",
      kind: "list",
      value: (f) => f.locationRules.map((rule) => ({ path: rule.path.trim(), upstreams: serializeUpstreams(rule.upstreams), lb: rule.lb.enabled ? rule.lb : false })),
      lines: (f) =>
        f.locationRules.flatMap((rule) => [
          `${rule.path.trim() || "(no path)"} → ${serializeUpstreams(rule.upstreams).join(", ") || "(no upstream)"}`,
          ...(rule.lb.enabled ? lbLines(rule.lb, `${rule.path.trim()} · `) : []),
        ]),
      restore: keys("locationRules"),
    },
    { id: "waf", section: "security", label: "Web application firewall", focus: "f-waf-mode", kind: "list", value: (f) => f.waf, lines: wafLines, restore: keys("waf") },
    {
      id: "wafDirectives",
      section: "security",
      label: "Custom SecLang directives",
      focus: "f-waf-directives",
      kind: "text",
      value: (f) => f.wafDirectives.trim(),
      lines: (f) => (f.wafDirectives.trim() ? f.wafDirectives.trim().split("\n") : []),
      restore: keys("wafDirectives"),
    },
    {
      id: "wafExcluded",
      section: "security",
      label: "Rule exclusions",
      focus: "f-waf-exclude",
      kind: "list",
      value: (f) => [...f.wafExcluded].sort((a, b) => a - b),
      lines: (f) => f.wafExcluded.map((id) => `Rule ${id} excluded on this host`),
      restore: keys("wafExcluded"),
    },
    { id: "rateLimit", section: "security", label: "Rate limiting", focus: "f-rl-mode", kind: "list", value: (f) => f.rateLimit, lines: rateLimitLines, restore: keys("rateLimit") },
    {
      id: "accessListId",
      section: "access",
      label: "Access list",
      focus: "f-access-list",
      kind: "value",
      value: (f) => f.accessListId,
      lines: (f, lookup) => [f.accessListId === null ? "None" : lookup.accessList(f.accessListId)],
      restore: keys("accessListId"),
    },
    { id: "geoblock", section: "security", label: "Geo blocking", focus: "f-geo-enabled", kind: "list", value: (f) => f.geoblock, lines: geoLines, restore: keys("geoblock") },
    {
      id: "signIn",
      section: "access",
      label: "Sign-in",
      focus: "f-sign-in",
      kind: "list",
      value: signInValue,
      lines: signInLines,
      restore: (form, saved) => ({
        ...form,
        signIn: saved.signIn,
        authentik: saved.authentik,
        forwardAuth: saved.forwardAuth,
        ingressi: {
          ...form.ingressi,
          protectedPaths: saved.ingressi.protectedPaths,
          excludedPaths: saved.ingressi.excludedPaths,
          bypassSources: saved.ingressi.bypassSources,
        },
      }),
    },
    {
      id: "grants",
      section: "access",
      label: "Who may sign in",
      focus: "f-sign-in-who",
      kind: "list",
      value: effectiveGrants,
      lines: (f, lookup) => {
        const grants = effectiveGrants(f);
        return [...grants.groupIds.map((id) => `Group ${lookup.group(id)}`), ...grants.userIds.map((id) => `User ${lookup.user(id)}`)];
      },
      restore: (form, saved) => ({ ...form, ingressi: { ...form.ingressi, userIds: saved.ingressi.userIds, groupIds: saved.ingressi.groupIds } }),
    },
    { id: "mtls", section: "access", label: "Client certificates (mTLS)", focus: "f-mtls", kind: "list", value: (f) => (f.mtls.enabled ? f.mtls : false), lines: mtlsLines, restore: keys("mtls") },
    {
      id: "pathBlocks",
      section: "access",
      label: "Blocked paths",
      focus: "f-blocks",
      kind: "list",
      value: (f) => f.pathBlocks.map(({ path, status, body }) => ({ path: path.trim(), status, body })),
      lines: (f) => f.pathBlocks.map((rule) => `${rule.path.trim() || "(no path)"} → ${rule.status}${rule.body ? ` "${rule.body}"` : ""}`),
      restore: keys("pathBlocks"),
    },
    {
      id: "pathAllows",
      section: "access",
      label: "Paths that bypass blocks",
      focus: "f-allows",
      kind: "list",
      value: (f) => f.pathAllows.map((rule) => rule.path.trim()),
      lines: (f) => f.pathAllows.map((rule) => rule.path.trim() || "(no path)"),
      restore: keys("pathAllows"),
    },
    {
      id: "certificateId",
      section: "certificate",
      label: "Certificate",
      focus: "f-certificate",
      kind: "value",
      value: (f) => f.certificateId,
      lines: (f, lookup) => [f.certificateId === null ? "Managed by Caddy (automatic)" : lookup.certificate(f.certificateId)],
      restore: keys("certificateId"),
    },
    { id: "sslForced", section: "certificate", label: "Redirect HTTP to HTTPS", focus: "f-force-https", kind: "value", value: (f) => f.sslForced, lines: (f) => [onOff(f.sslForced)], restore: keys("sslForced") },
    { id: "hstsEnabled", section: "headers", label: "HSTS header", focus: "f-hsts", kind: "value", value: (f) => f.hstsEnabled, lines: (f) => [onOff(f.hstsEnabled)], restore: keys("hstsEnabled") },
    {
      id: "hstsSubdomains",
      section: "headers",
      label: "HSTS includes subdomains",
      focus: "f-hsts-sub",
      kind: "value",
      value: (f) => f.hstsSubdomains,
      lines: (f) => [onOff(f.hstsSubdomains)],
      restore: keys("hstsSubdomains"),
    },
    {
      id: "redirects",
      section: "advanced",
      label: "Redirects",
      focus: "f-redirects",
      kind: "list",
      value: (f) => f.redirects.map(({ from, to, status }) => ({ from: from.trim(), to: to.trim(), status })),
      lines: (f) => f.redirects.map((rule) => `${rule.from.trim() || "(no path)"} → ${rule.to.trim() || "(no target)"} · ${rule.status}`),
      restore: keys("redirects"),
    },
    {
      id: "rewritePrefix",
      section: "advanced",
      label: "Path prefix for the upstream",
      focus: "f-rewrite-prefix",
      kind: "value",
      value: (f) => f.rewritePrefix.trim(),
      lines: (f) => [orNone(f.rewritePrefix)],
      restore: keys("rewritePrefix"),
    },
    {
      id: "pathRewrites",
      section: "advanced",
      label: "Path rewrites",
      focus: "f-rewrites",
      kind: "list",
      value: (f) => f.pathRewrites.map(({ from, to }) => ({ from: from.trim(), to: to.trim() })),
      lines: (f) => f.pathRewrites.map((rule) => `${rule.from.trim() || "(no path)"} → ${rule.to.trim() || "(no target)"}`),
      restore: keys("pathRewrites"),
    },
    {
      id: "errorPages",
      section: "advanced",
      label: "Error pages",
      focus: "f-error-pages",
      kind: "list",
      value: (f) => f.errorPages.map(({ statuses, body, contentType }) => ({ statuses: statuses.trim(), body, contentType: contentType.trim() })),
      lines: (f) =>
        f.errorPages.map((rule) => {
          const body = rule.body.replace(/\s+/g, " ").trim();
          return `${rule.statuses.trim() || "Every error"} · ${body.length > 60 ? `${body.slice(0, 57)}…` : body}${rule.contentType.trim() ? ` · ${rule.contentType.trim()}` : ""}`;
        }),
      restore: keys("errorPages"),
    },
    { id: "dnsResolver", section: "advanced", label: "DNS resolvers", focus: "f-dns-enabled", kind: "list", value: (f) => (f.dnsResolver.enabled ? f.dnsResolver : false), lines: dnsLines, restore: keys("dnsResolver") },
    {
      id: "upstreamDns",
      section: "advanced",
      label: "Upstream DNS pinning",
      focus: "f-dns-pin",
      kind: "list",
      value: (f) => f.upstreamDns,
      lines: (f) => [`Pinning: ${PINNING_MODES[f.upstreamDns.mode]}`, `Address family: ${PINNING_FAMILIES[f.upstreamDns.family]}`],
      restore: keys("upstreamDns"),
    },
    {
      id: "customPreHandlersJson",
      section: "advanced",
      label: "Handlers before the proxy",
      focus: "f-pre-handlers",
      kind: "text",
      value: (f) => f.customPreHandlersJson.trim(),
      lines: (f) => (f.customPreHandlersJson.trim() ? f.customPreHandlersJson.trim().split("\n") : []),
      restore: keys("customPreHandlersJson"),
    },
    {
      id: "customReverseProxyJson",
      section: "advanced",
      label: "Merged into reverse_proxy",
      focus: "f-reverse-proxy",
      kind: "text",
      value: (f) => f.customReverseProxyJson.trim(),
      lines: (f) => (f.customReverseProxyJson.trim() ? f.customReverseProxyJson.trim().split("\n") : []),
      restore: keys("customReverseProxyJson"),
    },
  ];
}

export type FormChange = {
  group: ChangeGroup;
  /** The lines DiffView shows. */
  diff: DiffLine[];
};

function listDiff(before: string[], after: string[]): DiffLine[] {
  const removed = before.filter((line) => !after.includes(line));
  const added = after.filter((line) => !before.includes(line));
  return [...removed.map((text): DiffLine => ({ type: "remove", text })), ...added.map((text): DiffLine => ({ type: "add", text }))];
}

/** What differs between the saved form and the current one, in section order. */
export function formChanges(saved: HostForm, current: HostForm, lookup: ChangeLookup, groups: ChangeGroup[]): FormChange[] {
  const changes: FormChange[] = [];
  for (const group of groups) {
    if (canonical(group.value(saved)) === canonical(group.value(current))) continue;
    const before = group.lines(saved, lookup);
    const after = group.lines(current, lookup);
    let diff: DiffLine[];
    if (group.kind === "text") diff = diffLines(before, after);
    else if (group.kind === "value") diff = [{ type: "remove", text: before[0] ?? "Not set" }, { type: "add", text: after[0] ?? "Not set" }];
    else diff = listDiff(before, after);
    if (!diff.some((line) => line.type !== "context")) {
      // A change the lines cannot show (a secret, or the same text twice).
      diff = [{ type: "add", text: `${group.label} changed` }];
    }
    changes.push({ group, diff });
  }
  return changes.sort((a, b) => SECTIONS.indexOf(a.group.section) - SECTIONS.indexOf(b.group.section));
}
