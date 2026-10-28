/**
 * What the host editor pages (/proxy-hosts/new, and the tabs of /proxy-hosts/[id]) pass
 * to the editor. Plain data only: every list is an allowlisted view built by
 * the page (no PEM, keys, password hashes or e-mail addresses beyond what the
 * user's role may read).
 */
import type { ProxyHost } from "@/lib/models/proxy-hosts";
import type { AuthentikSettings, ForwardAuthSettings } from "@/lib/settings";
import type { HostApprovalContext } from "@/ee/approvals/types";
import type { DnsProviderChoices } from "@/src/lib/dns-provider-choice";

export type EditorCertificate = {
  id: number;
  name: string;
  /** "imported" (PEM uploaded) or "managed" (a certificate entry Caddy obtains with its own settings). */
  type: string;
  domains: string[];
  /** When the certificate expires, for imported certificates (read from the PEM). */
  expiresAt: string | null;
  issuer: string | null;
  /** Managed certificates: the DNS provider it is set to (a name under Certificate settings), null for the default. */
  provider: string | null;
};

/** The certificate Caddy serves today for the host's saved choice: automatic, or a managed entry. */
export type ServedCertificate = {
  domains: string[];
  issuer: string | null;
  keyType: string | null;
  validTo: string;
};

export type EditorAccessList = {
  id: number;
  name: string;
  description: string | null;
  rules: number;
  members: number;
  defaultAction: "allow" | "deny";
  /** Other hosts the user can see that use the list. */
  otherHosts: number;
};

export type EditorUser = { id: number; name: string; detail: string | null };
export type EditorGroup = { id: number; name: string; description: string | null; members: number };
export type EditorCa = { id: number; name: string };
export type EditorMtlsRole = { id: number; name: string; description: string | null; certificates: number };
export type EditorClientCertificate = { id: number; caId: number; commonName: string; validTo: string; revoked: boolean };

/** One of the host's WAF rule exclusions (src/lib/models/waf-exclusions.ts). */
export type EditorWafExclusion = {
  id: number;
  ruleId: number;
  /** No path and no variable: mirrored in the host's excluded rule list, editable here. */
  wholeHost: boolean;
  path: string | null;
  pathMatch: "exact" | "prefix" | null;
  variable: string | null;
  reason: string;
  createdBy: string | null;
  createdAt: string;
};

export type EditorWafGlobal = {
  /** The global WAF applies to every host. */
  appliesToAll: boolean;
  mode: "Off" | "On" | "DetectionOnly";
  loadOwaspCrs: boolean;
  paranoiaLevel: number | null;
  inboundThreshold: number | null;
};

export type HostEditorData = {
  mode: "create" | "edit";
  /** The host being edited (edit) or null. */
  host: ProxyHost | null;
  /** The host a new one copies (create from ?from=), or null. */
  template: ProxyHost | null;
  /** The first domain of a new host (?domain=). */
  initialDomain: string | null;
  /** Users and groups the host's built-in forward auth lets in. */
  forwardAuthAccess: { userIds: number[]; groupIds: number[] };
  certificates: EditorCertificate[];
  servedCertificate: ServedCertificate | null;
  /** How Caddy works out the client address, for the checks that match it (sign-in bypass). */
  clientAddress: {
    /** Trusted proxies are set, so the address comes from the headers behind them. */
    proxiesTrusted: boolean;
    /** The address comes from X-Forwarded-For read left to right, which a client can forge through a proxy that appends to it. */
    forwardedForForgeable: boolean;
  };
  accessLists: EditorAccessList[];
  /** The global Blocked sources list has rules: they apply to every host. */
  blockedSourcesActive: boolean;
  caCertificates: EditorCa[];
  mtlsRoles: EditorMtlsRole[];
  clientCertificates: EditorClientCertificate[];
  users: EditorUser[];
  groups: EditorGroup[];
  /** The role may choose client certificates and mTLS roles (certificates:read without a tag scope). */
  canChooseTrust: boolean;
  canChooseUsers: boolean;
  canChooseGroups: boolean;
  canChooseAccessLists: boolean;
  /** Custom Caddy JSON is for administrators only. */
  isAdmin: boolean;
  authentikDefaults: AuthentikSettings | null;
  forwardAuthDefaults: ForwardAuthSettings | null;
  /** The tags the user's role is limited to, if any. */
  scopeTags: string[];
  approval: HostApprovalContext | null;
  wafGlobal: EditorWafGlobal | null;
  wafExclusions: EditorWafExclusion[];
  /** CRS rule messages seen in WAF events, by rule id. */
  wafRuleMessages: Record<number, string>;
  canReadWaf: boolean;
  /**
   * The WAF rules that matched this host's requests in the last 7 days, most
   * frequent first (waf:read and analytics on); null when unknown.
   */
  wafRecentRules?: { ruleId: number; message: string | null; events: number; blocked: number; topPath: string | null }[] | null;
  /** The user may add, change and remove WAF exclusions (waf:write). */
  canWriteWaf?: boolean;
  rateLimitDefaults: { enabled: boolean; rules: number } | null;
  /** The global geo blocking rules: whether they are on, and whether they have any block rules. */
  geoblockGlobal: { enabled: boolean; blocks: boolean } | null;
  /** A default DNS provider exists, so Caddy can obtain wildcard certificates. */
  dnsProviderConfigured: boolean;
  /** The DNS providers under Certificate settings, for the certificate section. */
  dnsChoices: DnsProviderChoices;
  /** The user may create a certificate (certificates:write without a tag scope). */
  canCreateCertificate: boolean;
  lastSaved: { at: string; by: string | null } | null;
  historyHref: string | null;
};
