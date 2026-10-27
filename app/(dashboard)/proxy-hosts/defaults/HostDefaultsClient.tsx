"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionCard } from "@/components/ui/SectionCard";
import { Textarea } from "@/components/ui/textarea";
import { ErrorPagesFields } from "@/components/proxy-hosts/ErrorPagesFields";
import type {
  AuthentikSettings,
  DefaultResponseSettings,
  ErrorPagesSettings,
  ForwardAuthSettings,
  ResponseHeadersSettings,
  TrustedProxiesSettings,
  UpstreamDnsResolutionSettings,
} from "@/lib/settings";
import { cn } from "@/lib/utils";
import {
  updateAuthentikSettingsAction,
  updateDefaultResponseSettingsAction,
  updateErrorPagesSettingsAction,
  updateForwardAuthSettingsAction,
  updateResponseHeadersSettingsAction,
  updateTrustedProxiesSettingsAction,
  updateUpstreamDnsResolutionSettingsAction,
} from "../../settings/actions";
import { useUnsavedWarning } from "../../settings/use-unsaved-warning";
import { ChoiceField, OverrideRow, SettingRow, SettingRows, SettingsForm, SettingsGroupForms, ToggleField } from "@/src/components/settings/settings-form";

export type HostDefaultsProps = {
  defaultResponse: DefaultResponseSettings | null;
  errorPages: ErrorPagesSettings | null;
  responseHeaders: ResponseHeadersSettings | null;
  trustedProxies: TrustedProxiesSettings | null;
  upstreamDnsResolution: UpstreamDnsResolutionSettings | null;
  authentik: AuthentikSettings | null;
  forwardAuth: ForwardAuthSettings | null;
  isSlave: boolean;
  /** On a replica: the settings it overrides instead of following its master. */
  overrides: {
    defaultResponse: boolean;
    responseHeaders: boolean;
    trustedProxies: boolean;
    upstreamDnsResolution: boolean;
    authentik: boolean;
    forwardAuth: boolean;
  };
  /** settings:write */
  canSave: boolean;
  /** proxy_hosts:read, for the breadcrumb's link. */
  canOpenProxyHosts: boolean;
};

/** Host defaults: what every proxy host gets unless it sets its own, and what new hosts start with. */
export default function HostDefaultsClient(props: HostDefaultsProps) {
  const { isSlave, overrides, canSave, canOpenProxyHosts } = props;
  const onDirtyChange = useUnsavedWarning();
  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        className="mb-0"
        breadcrumb={["Traffic", canOpenProxyHosts ? { label: "Proxy hosts", href: "/proxy-hosts" } : "Proxy hosts", "Defaults"]}
        title="Host defaults"
        description="For every proxy host. A host's own settings win."
      />
      <SettingsGroupForms name="Host defaults" canSave={canSave} onDirtyChange={onDirtyChange}>
        <DefaultResponseCard defaultResponse={props.defaultResponse} isSlave={isSlave} override={overrides.defaultResponse} />
        <SectionCard id="error-pages" className="scroll-mt-20 md:scroll-mt-4" title="Error pages" headingLevel={2} divided={false}>
          <SettingsForm action={updateErrorPagesSettingsAction} order={1} className="border-t border-line px-5 py-4">
            <ErrorPagesFields initialData={props.errorPages?.rules ?? []} />
          </SettingsForm>
        </SectionCard>
        <ResponseHeadersCard responseHeaders={props.responseHeaders} isSlave={isSlave} override={overrides.responseHeaders} />
        <TrustedProxiesCard trustedProxies={props.trustedProxies} isSlave={isSlave} override={overrides.trustedProxies} />
        <UpstreamDnsCard upstreamDnsResolution={props.upstreamDnsResolution} isSlave={isSlave} override={overrides.upstreamDnsResolution} />
        <ForwardAuthCards
          authentik={props.authentik}
          forwardAuth={props.forwardAuth}
          isSlave={isSlave}
          overrides={{ authentik: overrides.authentik, forwardAuth: overrides.forwardAuth }}
        />
      </SettingsGroupForms>
    </div>
  );
}

// ─── Requests for unknown hosts ─────────────────────────────────────────────

type Mode = DefaultResponseSettings["mode"];

const ANSWERS: readonly { value: Mode; label: string; description: string }[] = [
  { value: "caddy", label: "Caddy default", description: "No custom answer." },
  { value: "respond", label: "Custom response", description: "Your status, body and headers." },
  { value: "redirect", label: "Redirect", description: "To another address." },
  { value: "abort", label: "Close the connection", description: "No response at all, like nginx 444." },
];

const REDIRECT_STATUSES = ["301", "302", "303", "307", "308"] as const;
type RedirectStatus = (typeof REDIRECT_STATUSES)[number];

function DefaultResponseCard({
  defaultResponse,
  isSlave,
  override: initialOverride,
}: {
  defaultResponse: DefaultResponseSettings | null;
  isSlave: boolean;
  override: boolean;
}) {
  const [override, setOverride] = useState(initialOverride);
  const [mode, setMode] = useState<Mode>(defaultResponse?.mode ?? "caddy");
  const [redirectStatus, setRedirectStatus] = useState<RedirectStatus>(() => {
    const stored = defaultResponse?.mode === "redirect" ? String(defaultResponse.status ?? 302) : "302";
    return (REDIRECT_STATUSES as readonly string[]).includes(stored) ? (stored as RedirectStatus) : "302";
  });
  const disabled = isSlave && !override;
  const initialHeaders = Object.entries(defaultResponse?.headers ?? {})
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n");

  return (
    <SectionCard id="default-response" className="scroll-mt-20 md:scroll-mt-4" title="Requests for unknown hosts" headingLevel={2} divided={false}>
      <SettingsForm action={updateDefaultResponseSettingsAction} order={0}>
        <SettingRows>
          {isSlave && <OverrideRow id="default-response-override" checked={override} onCheckedChange={setOverride} />}
          <SettingRow label="Answer with" labelId="settings-answer-with">
            <div role="radiogroup" aria-labelledby="settings-answer-with" className="grid w-full grid-cols-[repeat(auto-fit,minmax(min(230px,100%),1fr))] gap-2">
              {ANSWERS.map((answer) => {
                const checked = mode === answer.value;
                return (
                  <label
                    key={answer.value}
                    className={cn(
                      "flex cursor-pointer items-start gap-2.5 rounded-[10px] border px-3 py-2.5 transition-colors",
                      checked ? "border-brand bg-brand-tint" : "border-line hover:bg-panel2",
                      disabled && "cursor-not-allowed opacity-60"
                    )}
                  >
                    <input
                      type="radio"
                      name="mode"
                      value={answer.value}
                      checked={checked}
                      onChange={() => setMode(answer.value)}
                      disabled={disabled}
                      className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--brand-fill)]"
                    />
                    <span className="flex flex-col gap-0.5">
                      <span className="font-medium">{answer.label}</span>
                      <span className="text-xs leading-4 text-soft">{answer.description}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </SettingRow>

          {mode === "respond" && (
            <>
              <SettingRow label="Status code" htmlFor="settings-default-status">
                <Input
                  key="default-response-status"
                  id="settings-default-status"
                  name="status"
                  type="number"
                  min={200}
                  max={599}
                  defaultValue={defaultResponse?.mode === "respond" ? defaultResponse.status ?? 404 : 404}
                  required
                  disabled={disabled}
                  className="num w-[120px]"
                />
              </SettingRow>
              <SettingRow
                label="Response body"
                htmlFor="settings-default-body"
                hint="Placeholders such as {http.request.host} are filled in."
              >
                <Textarea
                  id="settings-default-body"
                  name="body"
                  defaultValue={defaultResponse?.mode === "respond" ? defaultResponse.body ?? "" : ""}
                  rows={3}
                  disabled={disabled}
                  placeholder="Not found"
                  className="num min-h-0"
                />
              </SettingRow>
            </>
          )}

          {mode === "redirect" && (
            <>
              <SettingRow label="Redirect status" labelId="settings-redirect-status" hint="307 and 308 keep the request method.">
                <ChoiceField
                  name="status"
                  label="Redirect status"
                  value={redirectStatus}
                  onChange={setRedirectStatus}
                  options={REDIRECT_STATUSES.map((status) => ({ value: status, label: status }))}
                  disabled={disabled}
                />
              </SettingRow>
              <SettingRow label="Redirect to" htmlFor="settings-redirect-url" hint="{http.request.uri} keeps the path and query.">
                <Input
                  id="settings-redirect-url"
                  name="redirectUrl"
                  defaultValue={defaultResponse?.mode === "redirect" ? defaultResponse.redirectUrl ?? "" : ""}
                  required
                  disabled={disabled}
                  placeholder="https://example.com{http.request.uri}"
                  className="num"
                />
              </SettingRow>
            </>
          )}

          {(mode === "respond" || mode === "redirect") && (
            <SettingRow label="Response headers" htmlFor="settings-default-headers" hint="Name: value, one per line.">
              <Textarea
                key={`default-response-headers-${mode}`}
                id="settings-default-headers"
                name="headers"
                defaultValue={
                  defaultResponse?.mode === mode ? initialHeaders : mode === "respond" ? "Content-Type: text/plain; charset=utf-8" : ""
                }
                rows={2}
                disabled={disabled}
                placeholder={"Content-Type: text/html; charset=utf-8\nCache-Control: no-store"}
                className="num min-h-0"
              />
            </SettingRow>
          )}
        </SettingRows>
      </SettingsForm>
    </SectionCard>
  );
}

// ─── Response headers ───────────────────────────────────────────────────────

function ResponseHeadersCard({
  responseHeaders,
  isSlave,
  override: initialOverride,
}: {
  responseHeaders: ResponseHeadersSettings | null;
  isSlave: boolean;
  override: boolean;
}) {
  const [override, setOverride] = useState(initialOverride);
  const disabled = isSlave && !override;
  return (
    <SectionCard
      id="response-headers"
      className="scroll-mt-20 md:scroll-mt-4"
      title="Response headers"
      description="Set or removed on every response of every host, after the host's own headers."
      descriptionPlacement="below"
      headingLevel={2}
      divided={false}
    >
      <SettingsForm action={updateResponseHeadersSettingsAction} order={6}>
        <SettingRows>
          {isSlave && <OverrideRow id="response-headers-override" checked={override} onCheckedChange={setOverride} />}
          <SettingRow
            label="Set"
            htmlFor="settings-response-headers-set"
            hint="Name: value, one per line. Replaces the value the upstream or Caddy sent."
          >
            <Textarea
              id="settings-response-headers-set"
              name="set"
              defaultValue={Object.entries(responseHeaders?.set ?? {})
                .map(([name, value]) => `${name}: ${value}`)
                .join("\n")}
              disabled={disabled}
              rows={2}
              placeholder={"Server: web\nX-Content-Type-Options: nosniff"}
              className="num min-h-0"
            />
          </SettingRow>
          <SettingRow
            label="Remove"
            htmlFor="settings-response-headers-remove"
            hint="Header names, one per line. Server and Via hide Caddy's own headers."
          >
            <Textarea
              id="settings-response-headers-remove"
              name="remove"
              defaultValue={(responseHeaders?.remove ?? []).join("\n")}
              disabled={disabled}
              rows={2}
              placeholder={"Server\nVia"}
              className="num min-h-0"
            />
          </SettingRow>
        </SettingRows>
      </SettingsForm>
    </SectionCard>
  );
}

// ─── Trusted proxies ────────────────────────────────────────────────────────

function TrustedProxiesCard({
  trustedProxies,
  isSlave,
  override: initialOverride,
}: {
  trustedProxies: TrustedProxiesSettings | null;
  isSlave: boolean;
  override: boolean;
}) {
  const [override, setOverride] = useState(initialOverride);
  const disabled = isSlave && !override;
  return (
    <SectionCard
      id="trusted-proxies"
      className="scroll-mt-20 md:scroll-mt-4"
      title="Trusted proxies"
      description="Load balancers or CDNs in front of Caddy that pass on the client address."
      descriptionPlacement="below"
      headingLevel={2}
      divided={false}
    >
      <SettingsForm action={updateTrustedProxiesSettingsAction} order={2}>
        <SettingRows>
          {isSlave && <OverrideRow id="trusted-proxies-override" checked={override} onCheckedChange={setOverride} />}
          <SettingRow
            label="Trusted ranges"
            htmlFor="settings-trusted-ranges"
            hint="Addresses or CIDR ranges, one per line. private_ranges covers every private network."
          >
            <Textarea
              id="settings-trusted-ranges"
              name="ranges"
              defaultValue={(trustedProxies?.ranges ?? []).join("\n")}
              disabled={disabled}
              rows={2}
              placeholder={"private_ranges\n172.21.0.1/32"}
              className="num min-h-0"
            />
          </SettingRow>
          <SettingRow
            label="Client address headers"
            htmlFor="settings-client-ip-headers"
            hint="One per line. Empty means X-Forwarded-For; Cloudflare sends Cf-Connecting-Ip."
          >
            <Textarea
              id="settings-client-ip-headers"
              name="clientIpHeaders"
              defaultValue={(trustedProxies?.client_ip_headers ?? []).join("\n")}
              disabled={disabled}
              rows={1}
              placeholder="X-Forwarded-For"
              className="num min-h-0"
            />
          </SettingRow>
          <SettingRow label="Strict mode">
            <ToggleField
              id="trusted-proxies-strict"
              name="strict"
              label="Accept these headers only from trusted proxies"
              defaultChecked={trustedProxies?.strict ?? false}
              disabled={disabled}
            />
          </SettingRow>
          <SettingRow label="Geo blocking" hint="Trusted proxies set on geo blocking itself win.">
            <ToggleField
              id="trusted-proxies-geoblock"
              name="defaultGeoblock"
              label="Use these ranges for geo blocking too"
              defaultChecked={trustedProxies?.default_geoblock ?? false}
              disabled={disabled}
            />
          </SettingRow>
          <SettingRow
            label="PROXY protocol from"
            htmlFor="settings-proxy-protocol-ranges"
            hint="TCP load balancers that send a PROXY header (v1 or v2) to ports 80 and 443. Addresses or CIDR ranges, one per line; other clients connect as before."
          >
            <Textarea
              id="settings-proxy-protocol-ranges"
              name="proxyProtocolRanges"
              defaultValue={(trustedProxies?.proxy_protocol_ranges ?? []).join("\n")}
              disabled={disabled}
              rows={2}
              placeholder={"192.168.1.1\n10.0.10.0/24"}
              className="num min-h-0"
            />
          </SettingRow>
        </SettingRows>
      </SettingsForm>
    </SectionCard>
  );
}

// ─── Upstream DNS pinning ───────────────────────────────────────────────────

type Family = UpstreamDnsResolutionSettings["family"];

function UpstreamDnsCard({
  upstreamDnsResolution,
  isSlave,
  override: initialOverride,
}: {
  upstreamDnsResolution: UpstreamDnsResolutionSettings | null;
  isSlave: boolean;
  override: boolean;
}) {
  const [override, setOverride] = useState(initialOverride);
  const [family, setFamily] = useState<Family>(upstreamDnsResolution?.family ?? "both");
  const disabled = isSlave && !override;
  return (
    <SectionCard id="upstream-dns" className="scroll-mt-20 md:scroll-mt-4" title="Upstream DNS pinning" headingLevel={2} divided={false}>
      <SettingsForm action={updateUpstreamDnsResolutionSettingsAction} order={3}>
        <SettingRows>
          {isSlave && <OverrideRow id="udns-override" checked={override} onCheckedChange={setOverride} />}
          <SettingRow label="Pin upstream addresses">
            <ToggleField
              id="udns-enabled"
              name="enabled"
              label="Resolve upstream hostnames when applying"
              defaultChecked={upstreamDnsResolution?.enabled ?? false}
              disabled={disabled}
            />
          </SettingRow>
          <SettingRow label="Address family" labelId="settings-udns-family">
            <ChoiceField
              name="family"
              label="Address family"
              value={family}
              onChange={setFamily}
              disabled={disabled}
              options={[
                { value: "both", label: "Both, prefer IPv6" },
                { value: "ipv4", label: "IPv4 only" },
                { value: "ipv6", label: "IPv6 only" },
              ]}
            />
          </SettingRow>
        </SettingRows>
      </SettingsForm>
    </SectionCard>
  );
}

// ─── Forward auth ───────────────────────────────────────────────────────────

function ForwardAuthCards({
  authentik,
  forwardAuth,
  isSlave,
  overrides,
}: {
  authentik: AuthentikSettings | null;
  forwardAuth: ForwardAuthSettings | null;
  isSlave: boolean;
  overrides: { authentik: boolean; forwardAuth: boolean };
}) {
  const [authentikOverride, setAuthentikOverride] = useState(overrides.authentik);
  const [forwardAuthOverride, setForwardAuthOverride] = useState(overrides.forwardAuth);
  const [preset, setPreset] = useState<ForwardAuthSettings["provider"]>(forwardAuth?.provider ?? "authelia");
  const authentikDisabled = isSlave && !authentikOverride;
  const forwardAuthDisabled = isSlave && !forwardAuthOverride;
  return (
    <div id="forward-auth" className="flex scroll-mt-20 md:scroll-mt-4 flex-col gap-4">
      <SectionCard
        id="authentik"
        className="scroll-mt-20 md:scroll-mt-4"
        title="Authentik"
        description="Filled in when you turn on Authentik for a new host."
        descriptionPlacement="below"
        headingLevel={2}
        divided={false}
      >
        <SettingsForm action={updateAuthentikSettingsAction} order={4}>
          <SettingRows>
            {isSlave && <OverrideRow id="authentik-override" checked={authentikOverride} onCheckedChange={setAuthentikOverride} />}
            <SettingRow label="Outpost domain" htmlFor="settings-authentik-domain">
              <Input
                id="settings-authentik-domain"
                name="outpostDomain"
                placeholder="outpost.goauthentik.io"
                defaultValue={authentik?.outpostDomain ?? ""}
                required
                disabled={authentikDisabled}
                className="num"
              />
            </SettingRow>
            <SettingRow label="Outpost upstream" htmlFor="settings-authentik-upstream">
              <Input
                id="settings-authentik-upstream"
                name="outpostUpstream"
                placeholder="http://authentik-server:9000"
                defaultValue={authentik?.outpostUpstream ?? ""}
                required
                disabled={authentikDisabled}
                className="num"
              />
            </SettingRow>
            <SettingRow label="Auth endpoint" htmlFor="settings-authentik-endpoint">
              <Input
                id="settings-authentik-endpoint"
                name="authEndpoint"
                placeholder="/outpost.goauthentik.io/auth/caddy"
                defaultValue={authentik?.authEndpoint ?? ""}
                disabled={authentikDisabled}
                className="num"
              />
            </SettingRow>
          </SettingRows>
        </SettingsForm>
      </SectionCard>
      <SectionCard
        id="generic-forward-auth"
        className="scroll-mt-20 md:scroll-mt-4"
        title="Generic forward auth"
        description="Filled in when you turn on Authelia or another forward auth server for a new host."
        descriptionPlacement="below"
        headingLevel={2}
        divided={false}
      >
        <SettingsForm action={updateForwardAuthSettingsAction} order={5}>
          <SettingRows>
            {isSlave && (
              <OverrideRow id="forward-auth-override" checked={forwardAuthOverride} onCheckedChange={setForwardAuthOverride} />
            )}
            <SettingRow label="Provider preset" labelId="settings-forward-auth-preset">
              <ChoiceField
                name="provider"
                label="Provider preset"
                value={preset}
                onChange={setPreset}
                disabled={forwardAuthDisabled}
                options={[
                  { value: "authelia", label: "Authelia" },
                  { value: "custom", label: "Custom" },
                ]}
              />
            </SettingRow>
            <SettingRow label="Auth server URL" htmlFor="settings-forward-auth-upstream">
              <Input
                id="settings-forward-auth-upstream"
                name="authUpstream"
                placeholder="http://authelia:9091"
                defaultValue={forwardAuth?.authUpstream ?? ""}
                required
                disabled={forwardAuthDisabled}
                className="num"
              />
            </SettingRow>
            <SettingRow
              label="Auth endpoint"
              htmlFor="settings-forward-auth-endpoint"
              hint="Optional. Blank means /api/authz/forward-auth for Authelia."
            >
              <Input
                id="settings-forward-auth-endpoint"
                name="authEndpoint"
                placeholder="/api/authz/forward-auth"
                defaultValue={forwardAuth?.authEndpoint ?? ""}
                disabled={forwardAuthDisabled}
                className="num"
              />
            </SettingRow>
          </SettingRows>
        </SettingsForm>
      </SectionCard>
    </div>
  );
}
