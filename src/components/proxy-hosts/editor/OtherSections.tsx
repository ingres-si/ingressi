"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { StatusDot } from "@/components/ui/StatusDot";
import { AddButton, EditorCard, Field, FieldError, RemoveButton, TextField, ToggleRow, useEditor, useFieldProps } from "./fields";
import { NativeSelect, SelectField } from "./controls";
import { NameAndTagsCard } from "./RoutingSection";
import { REDIRECT_STATUSES, rowKey, type RedirectStatus } from "./model";
import { ManagedCertificateSheet } from "@/components/certificates/ManagedCertificateSheet";
import { describeChallenge, effectiveChallenge } from "@/src/lib/dns-provider-choice";

const DAY_MS = 24 * 60 * 60 * 1000;

function formatDay(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

function daysLeft(iso: string): number {
  return Math.floor((new Date(iso).getTime() - Date.now()) / DAY_MS);
}

/** Whether `domain` is one of `names`, directly or through a wildcard one label deep. */
function covered(domain: string, names: readonly string[]): boolean {
  const lower = domain.toLowerCase();
  return names.some((name) => {
    const candidate = name.toLowerCase();
    if (candidate === lower) return true;
    if (!candidate.startsWith("*.")) return false;
    const rest = lower.split(".").slice(1).join(".");
    return rest === candidate.slice(2) && !lower.startsWith("*.");
  });
}

function InfoCell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="text-xs text-soft">{label}</span>
      {children}
    </div>
  );
}

export function CertificateSection() {
  const { form, update, data, certificateSaved } = useEditor();
  // The sheet that creates a managed certificate with another DNS provider, or edits the chosen one.
  const [sheet, setSheet] = useState<"new" | "edit" | null>(null);
  const chosen = form.certificateId === null ? null : data.certificates.find((certificate) => certificate.id === form.certificateId) ?? null;
  // Caddy's reading is of the saved choice: a changed, unsaved selection has none yet.
  const served = data.host !== null && form.certificateId === data.host.certificateId ? data.servedCertificate : null;
  const uncovered = chosen ? form.domains.filter((domain) => !covered(domain, chosen.domains)) : [];
  const managed = chosen?.type === "managed" ? chosen : null;
  const managedReading = managed ? served : null;
  const expiresAt = chosen?.expiresAt ?? managedReading?.validTo ?? null;
  // Imported certificates are not obtained: only automatic hosts and managed entries have a challenge.
  const obtainedWith = chosen && !managed ? null : describeChallenge(effectiveChallenge(data.dnsChoices, managed?.provider ?? null));
  const otherProvider = data.dnsChoices.providers.find((provider) => provider.name !== data.dnsChoices.defaultProvider);
  return (
    <EditorCard
      id="certificate"
      title="Certificate"
      was="certificateId"
      actions={
        <Link href="/certificates" className="text-[13px] text-brand underline-offset-4 hover:underline">
          All certificates
        </Link>
      }
    >
      <SelectField
        id="f-certificate"
        label="Certificate"
        className="max-w-xl"
        value={form.certificateId === null ? "" : String(form.certificateId)}
        onChange={(value) => update((f) => ({ ...f, certificateId: value ? Number(value) : null }))}
      >
        <option value="">Managed by Caddy (automatic)</option>
        {data.certificates.map((certificate) => (
          <option key={certificate.id} value={certificate.id}>
            {certificate.name} · {certificate.type === "imported" ? "imported" : "managed"}
          </option>
        ))}
      </SelectField>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(170px,100%),1fr))] gap-3 rounded-xl border border-line bg-panel2 px-4 py-3.5 text-[13px]">
        {chosen ? (
          <>
            <InfoCell label="Covers">
              {chosen.domains.length > 0 ? chosen.domains.map((domain) => <span key={domain} className="num">{domain}</span>) : <span className="text-soft">No names recorded</span>}
            </InfoCell>
            <InfoCell label="Issuer">
              <span>{chosen.issuer ?? managedReading?.issuer ?? (chosen.type === "imported" ? "Unknown" : "Obtained by Caddy")}</span>
              {managedReading?.keyType && <span className="text-xs text-soft">{managedReading.keyType}</span>}
            </InfoCell>
            <InfoCell label="Expires">
              {expiresAt ? (
                <>
                  <span>{formatDay(expiresAt)}</span>
                  <span className={cn("num text-xs", daysLeft(expiresAt) < 14 ? "text-warn" : "text-soft")}>{daysLeft(expiresAt)} days</span>
                </>
              ) : (
                <span className="text-soft">Not known here</span>
              )}
            </InfoCell>
            <InfoCell label="Renewal">
              {chosen.type === "imported" ? <StatusDot tone="warn" label="Manual: import a new one before it expires" /> : <StatusDot tone="ok" label="Automatic" />}
            </InfoCell>
            {obtainedWith && (
              <InfoCell label="Obtained with">
                <span data-testid="certificate-challenge">{obtainedWith}</span>
              </InfoCell>
            )}
          </>
        ) : served && form.certificateId === null ? (
          <>
            <InfoCell label="Covers">
              {served.domains.map((domain) => (
                <span key={domain} className="num">
                  {domain}
                </span>
              ))}
            </InfoCell>
            <InfoCell label="Issuer">
              <span>{served.issuer ?? "Unknown"}</span>
              {served.keyType && <span className="text-xs text-soft">{served.keyType}</span>}
            </InfoCell>
            <InfoCell label="Expires">
              <span>{formatDay(served.validTo)}</span>
              <span className="num text-xs text-soft">{daysLeft(served.validTo)} days</span>
            </InfoCell>
            <InfoCell label="Renewal">
              <StatusDot tone="ok" label="Automatic" />
            </InfoCell>
            <InfoCell label="Obtained with">
              <span data-testid="certificate-challenge">{obtainedWith}</span>
            </InfoCell>
          </>
        ) : (
          <>
            <InfoCell label="Obtained with">
              <span data-testid="certificate-challenge">{obtainedWith}</span>
            </InfoCell>
            <p className="m-0 text-[13px] text-muted-foreground">Obtained and renewed automatically once the host is saved.</p>
          </>
        )}
      </div>
      {data.canCreateCertificate && ((!chosen && otherProvider) || managed) && (
        <div className="flex flex-wrap gap-2">
          {!chosen && otherProvider && (
            <Button type="button" variant="outline" size="sm" onClick={() => setSheet("new")}>
              Use a different DNS provider
            </Button>
          )}
          {managed && (
            <Button type="button" variant="outline" size="sm" onClick={() => setSheet("edit")}>
              Edit certificate
            </Button>
          )}
        </div>
      )}
      {sheet && (
        <ManagedCertificateSheet
          open
          cert={sheet === "edit" && managed ? { id: managed.id, name: managed.name, domains: managed.domains, provider: managed.provider } : null}
          choices={data.dnsChoices}
          initial={{ name: form.domains[0] ?? "", domains: form.domains, provider: otherProvider?.name ?? null }}
          onClose={() => setSheet(null)}
          onSaved={(saved) =>
            certificateSaved(
              { id: saved.id, name: saved.name, type: "managed", domains: saved.domains, expiresAt: null, issuer: null, provider: saved.provider },
              sheet === "new"
            )
          }
        />
      )}
      {uncovered.length > 0 && (
        <p className="m-0 text-xs text-warn">
          The certificate does not name {uncovered.join(", ")}: browsers will warn on {uncovered.length === 1 ? "that domain" : "those domains"}.
        </p>
      )}
      <div className="border-t border-line">
        <ToggleRow
          id="f-force-https"
          label="Redirect HTTP to HTTPS"
          was="sslForced"
          checked={form.sslForced}
          onChange={(sslForced) => update((f) => ({ ...f, sslForced }))}
          className="pb-0"
        />
      </div>
    </EditorCard>
  );
}

export function HeadersSection() {
  const { form, update } = useEditor();
  return (
    <>
      <EditorCard id="hsts" title="Strict Transport Security">
        <div className="-mt-2 divide-y divide-line">
          <ToggleRow
            id="f-hsts"
            label="Send the HSTS header"
            was="hstsEnabled"
            description="Browsers then use only HTTPS for two years: hard to undo."
            checked={form.hstsEnabled}
            onChange={(hstsEnabled) => update((f) => ({ ...f, hstsEnabled }))}
          />
          <ToggleRow
            id="f-hsts-sub"
            label="Include subdomains"
            was="hstsSubdomains"
            description={form.hstsEnabled ? "Every name under these domains must then serve HTTPS." : undefined}
            checked={form.hstsSubdomains}
            onChange={(hstsSubdomains) => update((f) => ({ ...f, hstsSubdomains }))}
          />
        </div>
      </EditorCard>
      <EditorCard id="response-headers" title="Other headers">
        <p className="-mt-2 m-0 text-[13px] text-muted-foreground">
          Set them in{" "}
          <a href="#advanced" className="text-brand underline-offset-4 hover:underline">
            Advanced, Raw Caddy JSON
          </a>
          .
        </p>
      </EditorCard>
    </>
  );
}

function RedirectRow({ index }: { index: number }) {
  const { form, update } = useEditor();
  const row = form.redirects[index];
  const fromProps = useFieldProps(`f-rd-${index}-from`);
  const toProps = useFieldProps(`f-rd-${index}-to`);
  const set = (patch: Partial<typeof row>) => update((f) => ({ ...f, redirects: f.redirects.map((current) => (current.key === row.key ? { ...current, ...patch } : current)) }));
  return (
    <li className="flex flex-col gap-1 border-t border-line px-5 py-3">
      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_84px_32px] items-center gap-2">
        <Input {...fromProps} aria-label={`Redirect ${index + 1} from path`} value={row.from} placeholder="/docs" className="num" onChange={(event) => set({ from: event.target.value })} />
        <Input {...toProps} aria-label={`Redirect ${index + 1} to`} value={row.to} placeholder="https://example.com/docs" className="num" onChange={(event) => set({ to: event.target.value })} />
        <NativeSelect aria-label={`Redirect ${index + 1} status`} value={String(row.status)} className="num" onChange={(event) => set({ status: Number(event.target.value) as RedirectStatus })}>
          {REDIRECT_STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </NativeSelect>
        <RemoveButton label={`Remove redirect ${row.from || index + 1}`} onClick={() => update((f) => ({ ...f, redirects: f.redirects.filter((current) => current.key !== row.key) }))} />
      </div>
      <FieldError id={`f-rd-${index}-from`} />
      <FieldError id={`f-rd-${index}-to`} />
    </li>
  );
}

function RewriteRow({ index }: { index: number }) {
  const { form, update } = useEditor();
  const row = form.pathRewrites[index];
  const fromProps = useFieldProps(`f-rw-${index}-from`);
  const toProps = useFieldProps(`f-rw-${index}-to`);
  const set = (patch: Partial<typeof row>) => update((f) => ({ ...f, pathRewrites: f.pathRewrites.map((current) => (current.key === row.key ? { ...current, ...patch } : current)) }));
  return (
    <li className="flex flex-col gap-1">
      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_32px] items-center gap-2">
        <Input {...fromProps} aria-label={`Rewrite ${index + 1} from path`} value={row.from} placeholder="/secretpath" className="num" onChange={(event) => set({ from: event.target.value })} />
        <Input {...toProps} aria-label={`Rewrite ${index + 1} to path`} value={row.to} placeholder="/dns-query" className="num" onChange={(event) => set({ to: event.target.value })} />
        <RemoveButton label={`Remove rewrite ${row.from || index + 1}`} onClick={() => update((f) => ({ ...f, pathRewrites: f.pathRewrites.filter((current) => current.key !== row.key) }))} />
      </div>
      <FieldError id={`f-rw-${index}-from`} />
      <FieldError id={`f-rw-${index}-to`} />
    </li>
  );
}

function ErrorPageRow({ index }: { index: number }) {
  const { form, update } = useEditor();
  const row = form.errorPages[index];
  const statusesProps = useFieldProps(`f-ep-${index}-statuses`);
  const bodyProps = useFieldProps(`f-ep-${index}-body`);
  const set = (patch: Partial<typeof row>) => update((f) => ({ ...f, errorPages: f.errorPages.map((current) => (current.key === row.key ? { ...current, ...patch } : current)) }));
  return (
    <li className="flex flex-col gap-2 border-t border-line px-5 py-3">
      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_32px] items-center gap-2">
        <Input {...statusesProps} aria-label={`Error page ${index + 1} status codes`} value={row.statuses} placeholder="502, 503, 504 (blank: every error)" className="num" onChange={(event) => set({ statuses: event.target.value })} />
        <Input aria-label={`Error page ${index + 1} content type`} value={row.contentType} placeholder="text/html; charset=utf-8" className="num" onChange={(event) => set({ contentType: event.target.value })} />
        <RemoveButton label={`Remove error page ${index + 1}`} onClick={() => update((f) => ({ ...f, errorPages: f.errorPages.filter((current) => current.key !== row.key) }))} />
      </div>
      <FieldError id={`f-ep-${index}-statuses`} />
      <Textarea {...bodyProps} aria-label={`Error page ${index + 1} body`} value={row.body} rows={3} className="num min-h-[72px] text-xs" onChange={(event) => set({ body: event.target.value })} />
      <FieldError id={`f-ep-${index}-body`} />
    </li>
  );
}

function JsonField({ id, label, value, onChange, placeholder, disabled }: { id: string; label: string; value: string; onChange: (value: string) => void; placeholder: string; disabled: boolean }) {
  const props = useFieldProps(id);
  return (
    <Field id={id} label={label} was={id === "f-pre-handlers" ? "customPreHandlersJson" : "customReverseProxyJson"}>
      <Textarea {...props} value={value} rows={5} spellCheck={false} disabled={disabled} placeholder={placeholder} className="num min-h-[110px] text-xs leading-[18px]" onChange={(event) => onChange(event.target.value)} />
    </Field>
  );
}

export function AdvancedSection() {
  const { form, update, data } = useEditor();
  return (
    <>
      {data.mode === "edit" && <NameAndTagsCard />}
      <EditorCard
        id="f-redirects"
        title="Redirects and rewrites"
        was="redirects"
        actions={<AddButton onClick={() => update((f) => ({ ...f, redirects: [...f.redirects, { key: rowKey("rd"), from: "", to: "", status: 301 }] }))}>Add redirect</AddButton>}
        flush
      >
        {form.redirects.length === 0 ? (
          <p className="m-0 px-5 py-3.5 text-[13px] text-muted-foreground">No redirects.</p>
        ) : (
          <ul className="m-0 list-none p-0 [&>li:first-child]:border-t-0">
            {form.redirects.map((row, index) => (
              <RedirectRow key={row.key} index={index} />
            ))}
          </ul>
        )}
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(260px,100%),1fr))] gap-x-5 gap-y-3 border-t border-line px-5 pb-4 pt-3">
          <TextField
            id="f-rewrite-prefix"
            name="rewritePathPrefix"
            label="Path prefix for the upstream"
            was="rewritePrefix"
            value={form.rewritePrefix}
            onChange={(rewritePrefix) => update((f) => ({ ...f, rewritePrefix }))}
            placeholder="None"
            hint="Added in front of every path."
            mono
          />
          <div id="f-rewrites" tabIndex={-1} className="flex min-w-0 flex-col gap-1.5">
            <span className="text-[13px] font-medium">Path rewrites</span>
            {form.pathRewrites.length > 0 && (
              <ul className="m-0 flex list-none flex-col gap-2 p-0">
                {form.pathRewrites.map((row, index) => (
                  <RewriteRow key={row.key} index={index} />
                ))}
              </ul>
            )}
            <div>
              <AddButton onClick={() => update((f) => ({ ...f, pathRewrites: [...f.pathRewrites, { key: rowKey("rw"), from: "", to: "" }] }))}>Add rewrite</AddButton>
            </div>
          </div>
        </div>
      </EditorCard>

      <EditorCard
        id="f-error-pages"
        title="Error pages"
        was="errorPages"
        actions={
          <AddButton
            onClick={() =>
              update((f) => ({
                ...f,
                errorPages: [...f.errorPages, { key: rowKey("ep"), statuses: "502, 503, 504", body: "<h1>Service temporarily unavailable</h1>", contentType: "" }],
              }))
            }
          >
            Add error page
          </AddButton>
        }
        flush
      >
        {form.errorPages.length === 0 ? (
          <p className="m-0 px-5 py-3.5 text-[13px] text-muted-foreground">No error pages.</p>
        ) : (
          <ul className="m-0 list-none p-0 [&>li:first-child]:border-t-0">
            {form.errorPages.map((row, index) => (
              <ErrorPageRow key={row.key} index={index} />
            ))}
          </ul>
        )}
      </EditorCard>

      <EditorCard id="name-resolution" title="Upstream name resolution">
        <div className="-mt-2 border-b border-line">
          <ToggleRow
            id="f-dns-enabled"
            label="Own DNS resolvers"
            was="dnsResolver"
            checked={form.dnsResolver.enabled}
            onChange={(enabled) => update((f) => ({ ...f, dnsResolver: { ...f.dnsResolver, enabled } }))}
          />
        </div>
        {form.dnsResolver.enabled && (
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(220px,100%),1fr))] gap-x-4 gap-y-3">
            <TextField
              id="f-dns-resolvers"
              name="dnsResolvers"
              label="Resolvers"
              value={form.dnsResolver.resolvers}
              onChange={(resolvers) => update((f) => ({ ...f, dnsResolver: { ...f.dnsResolver, resolvers } }))}
              placeholder="1.1.1.1, 9.9.9.9"
              hint="Comma separated."
              mono
            />
            <TextField
              id="f-dns-fallbacks"
              name="dnsFallbacks"
              label="Fallbacks, optional"
              value={form.dnsResolver.fallbacks}
              onChange={(fallbacks) => update((f) => ({ ...f, dnsResolver: { ...f.dnsResolver, fallbacks } }))}
              placeholder="8.8.8.8"
              mono
            />
            <TextField
              id="f-dns-timeout"
              name="dnsTimeout"
              label="Timeout"
              value={form.dnsResolver.timeout}
              onChange={(timeout) => update((f) => ({ ...f, dnsResolver: { ...f.dnsResolver, timeout } }))}
              placeholder="5s"
              mono
            />
          </div>
        )}
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(220px,100%),1fr))] gap-x-4 gap-y-3">
          <SelectField
            id="f-dns-pin"
            label="Upstream DNS pinning"
            was="upstreamDns"
            value={form.upstreamDns.mode}
            onChange={(mode) => update((f) => ({ ...f, upstreamDns: { ...f.upstreamDns, mode: mode as typeof f.upstreamDns.mode } }))}
          >
            <option value="inherit">Inherit global</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </SelectField>
          <SelectField
            id="f-dns-family"
            label="Address family"
            value={form.upstreamDns.family}
            onChange={(family) => update((f) => ({ ...f, upstreamDns: { ...f.upstreamDns, family: family as typeof f.upstreamDns.family } }))}
          >
            <option value="inherit">Inherit global</option>
            <option value="both">Both, IPv6 first</option>
            <option value="ipv6">IPv6 only</option>
            <option value="ipv4">IPv4 only</option>
          </SelectField>
        </div>
      </EditorCard>

      <EditorCard
        id="raw-json"
        title="Raw Caddy JSON"
        description={
          data.isAdmin
            ? undefined
            : data.host?.customPreHandlersJson || data.host?.customReverseProxyJson
              ? "Only administrators can change custom Caddy JSON. This host has some, so only administrators can add an upstream or another destination to it."
              : "Only administrators can change custom Caddy JSON."
        }
      >
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(300px,100%),1fr))] gap-x-5 gap-y-3">
          <JsonField
            id="f-pre-handlers"
            label="Handlers before the proxy"
            value={form.customPreHandlersJson}
            onChange={(customPreHandlersJson) => update((f) => ({ ...f, customPreHandlersJson }))}
            placeholder='[{"handler": "headers", …}]'
            disabled={!data.isAdmin}
          />
          <JsonField
            id="f-reverse-proxy"
            label="Merged into reverse_proxy"
            value={form.customReverseProxyJson}
            onChange={(customReverseProxyJson) => update((f) => ({ ...f, customReverseProxyJson }))}
            placeholder='{"headers": {"request": {…}}}'
            disabled={!data.isAdmin}
          />
        </div>
      </EditorCard>
    </>
  );
}
