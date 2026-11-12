"use client";

import Link from "next/link";
import { Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useBranding } from "@/ee/white-label/ui/BrandingProvider";
import { AddButton, EditorCard, FieldError, RemoveButton, TextField, ToggleRow, WasHint, useEditor, useFieldProps } from "./fields";
import { NativeSelect, SegmentedField, SelectField } from "./controls";
import { MtlsAccessRules } from "./MtlsAccessRules";
import { AUTHELIA_ENDPOINT, AUTHELIA_HEADERS, PATH_BLOCK_STATUSES, addressList, rowKey, type GenericAuthForm, type SignIn } from "./model";
import { touchesPrivateNetworks } from "@/src/lib/sign-in-bypass";
import type { PathBlockStatusCode } from "@/lib/models/proxy-hosts";

function AccessListCard() {
  const { form, update, data } = useEditor();
  const selected = data.accessLists.find((list) => list.id === form.accessListId) ?? null;
  const describe = () => {
    if (!selected) return null;
    const parts = [
      selected.description,
      `${selected.rules} ${selected.rules === 1 ? "rule" : "rules"}, ${selected.members} basic-auth ${selected.members === 1 ? "member" : "members"}; everything else is ${selected.defaultAction === "deny" ? "denied" : "let through"}.`,
      selected.otherHosts > 0 ? `Also on ${selected.otherHosts} other ${selected.otherHosts === 1 ? "host" : "hosts"}.` : null,
    ];
    return parts.filter(Boolean).join(" ");
  };
  return (
    <EditorCard
      id="access-list"
      title="Access list"
      was="accessListId"
      actions={
        data.canChooseAccessLists ? (
          <Link href={selected ? `/access-lists/${selected.id}` : "/access-lists"} className="text-[13px] text-brand underline-offset-4 hover:underline">
            {selected ? "Open list" : "Manage access lists"}
          </Link>
        ) : undefined
      }
    >
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(260px,100%),1fr))] items-start gap-x-5 gap-y-3">
        <SelectField
          id="f-access-list"
          label="Access list"
          value={form.accessListId === null ? "" : String(form.accessListId)}
          onChange={(value) => update((f) => ({ ...f, accessListId: value ? Number(value) : null }))}
          disabled={!data.canChooseAccessLists}
          hint={data.canChooseAccessLists ? undefined : "Choosing an access list needs the access_lists:read permission."}
        >
          <option value="">None, public</option>
          {data.accessLists.map((list) => (
            <option key={list.id} value={list.id}>
              {list.name}
            </option>
          ))}
        </SelectField>
        {selected && <p className="m-0 text-[13px] text-muted-foreground sm:pt-7">{describe()}</p>}
      </div>
      {data.blockedSourcesActive && (
        <div className="flex items-center gap-2.5 rounded-lg bg-panel2 px-3 py-2.5 text-[13px] text-muted-foreground">
          <Info aria-hidden="true" className="h-4 w-4 shrink-0 text-soft" />
          <span>
            <span className="text-foreground">Blocked sources</span> apply to this host too.
          </span>
        </div>
      )}
    </EditorCard>
  );
}

/** What to tell about the address check, or null when nothing is worth saying. */
function bypassWarning(entries: string[], address: { proxiesTrusted: boolean; forwardedForForgeable: boolean }): string | null {
  if (address.forwardedForForgeable) {
    return "A proxy that adds to X-Forwarded-For instead of replacing it lets a visitor forge the address: turn on strict parsing under Trusted proxies, or use the header the proxy sets itself.";
  }
  if (!address.proxiesTrusted && touchesPrivateNetworks(entries)) {
    return "Matches the address that connects to Caddy. Behind a proxy, a CDN or Docker's port proxy that is theirs, not the visitor's, and everyone would skip sign-in: set Trusted proxies and test from outside.";
  }
  return null;
}

/** The paths a check covers or skips and, for the sign-in providers (not client certificates), the addresses that skip it. */
function PathsFields({ prefix, protectedPaths, excludedPaths, bypassSources, onChange, names }: {
  prefix: string;
  protectedPaths: string;
  excludedPaths: string;
  bypassSources?: string;
  onChange: (patch: { protectedPaths?: string; excludedPaths?: string; bypassSources?: string }) => void;
  names?: { protectedPaths: string; excludedPaths: string; bypassSources?: string };
}) {
  const { data } = useEditor();
  const entries = addressList(bypassSources ?? "");
  const warning = entries.length === 0 ? null : bypassWarning(entries, data.clientAddress);
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(240px,100%),1fr))] gap-x-4 gap-y-3">
      <TextField
        id={`${prefix}-protected`}
        name={names?.protectedPaths}
        label="Only these paths, optional"
        value={protectedPaths}
        onChange={(value) => onChange({ protectedPaths: value })}
        placeholder="/admin/*, /internal/*"
        hint="Blank: the whole host."
        mono
      />
      <TextField
        id={`${prefix}-excluded`}
        name={names?.excludedPaths}
        label="Never these paths, optional"
        value={excludedPaths}
        onChange={(value) => onChange({ excludedPaths: value })}
        placeholder="/health, /public/*"
        hint="Ignored when only some paths are protected."
        mono
      />
      {bypassSources !== undefined && (
        <TextField
          id={`${prefix}-sources`}
          name={names?.bypassSources}
          label="Skip sign-in from, optional"
          value={bypassSources}
          onChange={(value) => onChange({ bypassSources: value })}
          placeholder="192.168.1.0/24, 10.0.0.5"
          hint="Addresses and networks that reach the host without signing in."
          mono
        />
      )}
      {warning && <p className="col-span-full m-0 text-xs text-warn">{warning}</p>}
    </div>
  );
}

function IngressiSignIn() {
  const { form, update, data } = useEditor();
  const ingressi = form.ingressi;
  const set = (patch: Partial<typeof ingressi>) => update((f) => ({ ...f, ingressi: { ...f.ingressi, ...patch } }));
  const toggle = (list: number[], id: number) => (list.includes(id) ? list.filter((value) => value !== id) : [...list, id].sort((a, b) => a - b));
  const nobody = ingressi.userIds.length === 0 && ingressi.groupIds.length === 0;
  return (
    <div className="flex flex-col gap-3.5">
      <fieldset id="f-sign-in-who" tabIndex={-1} className="m-0 flex flex-col gap-2 border-0 p-0">
        <legend className="mb-1 flex flex-wrap items-center gap-2 text-[13px] font-medium">
          Who may sign in
          <WasHint group="grants" />
        </legend>
        {!data.canChooseGroups && !data.canChooseUsers ? (
          <p className="m-0 text-[13px] text-muted-foreground">
            Choosing users and groups needs the users:read or groups:read permission. {nobody ? "Nobody is chosen today." : `${ingressi.userIds.length + ingressi.groupIds.length} chosen today.`}
          </p>
        ) : (
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(260px,100%),1fr))] gap-3">
            {data.canChooseGroups && (
              <div className="flex flex-col gap-1">
                <span className="text-xs text-soft">Groups</span>
                {data.groups.length === 0 ? (
                  <span className="text-[13px] text-muted-foreground">No groups yet.</span>
                ) : (
                  <ul className="m-0 max-h-52 list-none overflow-y-auto rounded-lg border border-line p-0">
                    {data.groups.map((group) => (
                      <li key={group.id} className="border-b border-line last:border-b-0">
                        <label className="flex cursor-pointer items-center gap-2.5 px-3 py-2 text-[13px] hover:bg-panel2">
                          <Checkbox checked={ingressi.groupIds.includes(group.id)} onCheckedChange={() => set({ groupIds: toggle(ingressi.groupIds, group.id) })} />
                          <span className="min-w-0 flex-1">
                            {group.name}
                            {group.description && <span className="ml-1.5 text-xs text-soft">{group.description}</span>}
                          </span>
                          <span className="num text-xs text-soft">{group.members}</span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            {data.canChooseUsers && (
              <div className="flex flex-col gap-1">
                <span className="text-xs text-soft">Users</span>
                {data.users.length === 0 ? (
                  <span className="text-[13px] text-muted-foreground">No users.</span>
                ) : (
                  <ul className="m-0 max-h-52 list-none overflow-y-auto rounded-lg border border-line p-0">
                    {data.users.map((user) => (
                      <li key={user.id} className="border-b border-line last:border-b-0">
                        <label className="flex cursor-pointer items-center gap-2.5 px-3 py-2 text-[13px] hover:bg-panel2">
                          <Checkbox checked={ingressi.userIds.includes(user.id)} onCheckedChange={() => set({ userIds: toggle(ingressi.userIds, user.id) })} />
                          <span className="min-w-0 flex-1 truncate">
                            {user.name}
                            {user.detail && user.detail !== user.name && <span className="ml-1.5 text-xs text-soft">{user.detail}</span>}
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}
        {nobody && (data.canChooseGroups || data.canChooseUsers) && <p className="m-0 text-xs text-warn">Nobody is chosen yet, so nobody can sign in to this host.</p>}
        <p className="m-0 text-xs text-muted-foreground">People signed in to the dashboard through an identity provider get in without signing in again; everyone else signs in at the portal.</p>
        <FieldError id="f-sign-in-who" />
      </fieldset>
      <PathsFields prefix="f-fi" protectedPaths={ingressi.protectedPaths} excludedPaths={ingressi.excludedPaths} bypassSources={ingressi.bypassSources} onChange={set} />
    </div>
  );
}

function AuthentikSignIn() {
  const { form, update } = useEditor();
  const a = form.authentik;
  const set = (patch: Partial<typeof a>) => update((f) => ({ ...f, authentik: { ...f.authentik, ...patch } }));
  return (
    <div className="flex flex-col gap-3.5">
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(240px,100%),1fr))] gap-x-4 gap-y-3">
        <TextField id="f-ak-domain" name="authentikOutpostDomain" label="Outpost domain" value={a.outpostDomain} onChange={(outpostDomain) => set({ outpostDomain })} placeholder="outpost.goauthentik.io" mono />
        <TextField id="f-ak-upstream" name="authentikOutpostUpstream" label="Outpost upstream" value={a.outpostUpstream} onChange={(outpostUpstream) => set({ outpostUpstream })} placeholder="http://authentik-server:9000" mono />
        <TextField
          id="f-ak-endpoint"
          name="authentikAuthEndpoint"
          label="Auth endpoint, optional"
          value={a.authEndpoint}
          onChange={(authEndpoint) => set({ authEndpoint })}
          placeholder="/outpost.goauthentik.io/auth/caddy"
          mono
        />
        <TextField id="f-ak-headers" label="Headers copied to the upstream" value={a.copyHeaders} onChange={(copyHeaders) => set({ copyHeaders })} hint="Comma separated." mono />
        <TextField id="f-ak-proxies" label="Trusted proxies" value={a.trustedProxies} onChange={(trustedProxies) => set({ trustedProxies })} placeholder="private_ranges" mono />
      </div>
      <PathsFields prefix="f-ak" protectedPaths={a.protectedPaths} excludedPaths={a.excludedPaths} bypassSources={a.bypassSources} onChange={set} />
      <ToggleRow
        id="f-ak-host-header"
        className="py-0"
        label="Send the outpost domain as its Host header"
        description="Keep on unless the outpost is reached by address."
        checked={a.setHostHeader}
        onChange={(setHostHeader) => set({ setHostHeader })}
      />
    </div>
  );
}

function GenericSignIn() {
  const { form, update } = useEditor();
  const f = form.forwardAuth;
  const set = (patch: Partial<GenericAuthForm>) => update((current) => ({ ...current, forwardAuth: { ...current.forwardAuth, ...patch } }));
  const applyPreset = (provider: GenericAuthForm["provider"]) => {
    const preset = provider === "authelia";
    const otherEndpoint = preset ? "" : AUTHELIA_ENDPOINT;
    const otherHeaders = preset ? "" : AUTHELIA_HEADERS.join(", ");
    // Only replace blanks or the other preset's defaults; never custom values.
    set({
      provider,
      authEndpoint: !f.authEndpoint.trim() || f.authEndpoint === otherEndpoint ? (preset ? AUTHELIA_ENDPOINT : "") : f.authEndpoint,
      copyHeaders: !f.copyHeaders.trim() || f.copyHeaders === otherHeaders ? (preset ? AUTHELIA_HEADERS.join(", ") : "") : f.copyHeaders,
    });
  };
  return (
    <div className="flex flex-col gap-3.5">
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(240px,100%),1fr))] gap-x-4 gap-y-3">
        <SelectField id="f-fa-preset" label="Preset" value={f.provider} onChange={(value) => applyPreset(value as GenericAuthForm["provider"])}>
          <option value="authelia">Authelia</option>
          <option value="custom">Custom forward auth</option>
        </SelectField>
        <TextField id="f-fa-upstream" name="forwardAuthUpstream" label="Auth server" value={f.authUpstream} onChange={(authUpstream) => set({ authUpstream })} placeholder="http://authelia:9091" hint="Its address, without a path." mono />
        <TextField
          id="f-fa-endpoint"
          name="forwardAuthEndpoint"
          label="Auth endpoint"
          value={f.authEndpoint}
          onChange={(authEndpoint) => set({ authEndpoint })}
          placeholder={AUTHELIA_ENDPOINT}
          hint="Authelia takes the portal address as ?authelia_url=."
          mono
        />
        <TextField id="f-fa-headers" label="Headers copied to the upstream" value={f.copyHeaders} onChange={(copyHeaders) => set({ copyHeaders })} hint="Comma separated." mono />
        <TextField id="f-fa-proxies" label="Trusted proxies" value={f.trustedProxies} onChange={(trustedProxies) => set({ trustedProxies })} placeholder="private_ranges" mono />
        <TextField
          id="f-fa-bypass"
          name="forwardAuthApiBypassHeaders"
          label="Skip sign-in when a request has"
          value={f.apiBypassHeaders}
          onChange={(apiBypassHeaders) => set({ apiBypassHeaders })}
          placeholder="X-Api-Key, Authorization"
          hint="The upstream then checks these itself."
          mono
        />
      </div>
      <div className="rounded-xl border border-line px-4">
        <ToggleRow
          id="f-fa-api-split"
          label="401 for API clients"
          description="API clients and WebSocket handshakes get 401 instead of a redirect."
          checked={f.apiSplit}
          onChange={(apiSplit) => set({ apiSplit })}
        />
      </div>
      <PathsFields prefix="f-fa" protectedPaths={f.protectedPaths} excludedPaths={f.excludedPaths} bypassSources={f.bypassSources} onChange={set} />
    </div>
  );
}

function SignInCard() {
  const { form, update } = useEditor();
  const { productName } = useBranding();
  const options: { value: SignIn; label: string }[] = [
    { value: "none", label: "None" },
    { value: "ingressi", label: `${productName} sign-in` },
    { value: "authentik", label: "Authentik" },
    { value: "generic", label: "Authelia or custom" },
  ];
  return (
    <EditorCard id="sign-in" title="Sign-in in front of the host" was="signIn">
      <SegmentedField id="f-sign-in" label="Provider" value={form.signIn} onChange={(signIn) => update((f) => ({ ...f, signIn }))} options={options} />
      {form.signIn === "ingressi" && <IngressiSignIn />}
      {form.signIn === "authentik" && <AuthentikSignIn />}
      {form.signIn === "generic" && <GenericSignIn />}
    </EditorCard>
  );
}

function MtlsCard() {
  const { form, update, data } = useEditor();
  const m = form.mtls;
  const set = (patch: Partial<typeof m>) => update((f) => ({ ...f, mtls: { ...f.mtls, ...patch } }));
  const toggle = (list: number[], id: number) => (list.includes(id) ? list.filter((value) => value !== id) : [...list, id]);
  const knownCas = new Set(data.caCertificates.map((ca) => ca.id));
  const active = data.clientCertificates.filter((certificate) => !certificate.revoked && knownCas.has(certificate.caId));
  const byCa = new Map<number, typeof active>();
  for (const certificate of active) byCa.set(certificate.caId, [...(byCa.get(certificate.caId) ?? []), certificate]);
  return (
    <EditorCard
      id="f-mtls"
      title="Client certificates (mTLS)"
      was="mtls"
      description={m.enabled ? "Clients without a trusted certificate cannot connect at all." : undefined}
      actions={
        <span className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px]">
          {data.canChooseTrust && m.enabled && (
            <Link href="/certificates" className="text-brand underline-offset-4 hover:underline">
              Roles and client certificates
            </Link>
          )}
          <span className="flex items-center gap-2">
            <span id="f-mtls-enabled-label">Require client certificates</span>
            <Switch id="f-mtls-enabled" aria-labelledby="f-mtls-enabled-label" checked={m.enabled} onCheckedChange={(enabled) => set({ enabled })} disabled={!data.canChooseTrust && !m.enabled} />
          </span>
        </span>
      }
    >
      {!data.canChooseTrust && (
        <p className="m-0 text-[13px] text-muted-foreground">Choosing roles and client certificates needs certificate permissions without a tag scope.</p>
      )}
      {m.enabled && (
        <>
          {data.canChooseTrust && (
            <SegmentedField
              id="f-mtls-mode"
              label="Trust"
              value={m.trustMode}
              onChange={(trustMode) => set({ trustMode })}
              options={[
                { value: "identity", label: "Roles and certificates" },
                { value: "ca", label: "Certificate authority" },
              ]}
              hint={
                m.trustMode === "ca"
                  ? "Any client certificate signed by a chosen authority gets in, with no need to list each one. Use it for an authority you import, such as Cloudflare's origin pull CA."
                  : "Only the chosen roles and certificates get in. Certificates must come from an authority generated here."
              }
            />
          )}
          {data.canChooseTrust && m.trustMode === "ca" && (
            <div className="flex flex-col gap-1">
              <span className="text-[13px] font-medium">Trusted certificate authorities</span>
              {data.caCertificates.length === 0 ? (
                <span className="text-[13px] text-muted-foreground">No certificate authorities yet. Import one under Certificates.</span>
              ) : (
                <ul id="f-mtls-cas" className="m-0 list-none rounded-lg border border-line p-0">
                  {data.caCertificates.map((ca) => (
                    <li key={ca.id} className="border-b border-line last:border-b-0">
                      <label className="flex cursor-pointer items-center gap-2.5 px-3 py-2 text-[13px] hover:bg-panel2">
                        <Checkbox checked={m.caIds.includes(ca.id)} onCheckedChange={() => set({ caIds: toggle(m.caIds, ca.id) })} />
                        <span className="min-w-0 flex-1">{ca.name}</span>
                        <span className="text-xs text-soft">{ca.issuesHere ? "Issues certificates here" : "Accepts everything it signs"}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              )}
              {m.caIds.some((id) => data.caCertificates.find((ca) => ca.id === id && ca.issuesHere)) && (
                <p className="m-0 text-xs leading-4 text-soft">
                  For an authority that issues certificates here, only its client certificates that are not revoked get in, and a revoked one is refused at once. For the others, everything the authority signs gets in, and a single certificate cannot be revoked.
                </p>
              )}
            </div>
          )}
          {data.canChooseTrust && m.trustMode === "identity" && (
            <div className="grid grid-cols-[repeat(auto-fit,minmax(min(260px,100%),1fr))] gap-3">
              <div className="flex flex-col gap-1">
                <span className="text-[13px] font-medium">Trusted roles</span>
                {data.mtlsRoles.length === 0 ? (
                  <span className="text-[13px] text-muted-foreground">No roles yet.</span>
                ) : (
                  <ul className="m-0 list-none rounded-lg border border-line p-0">
                    {data.mtlsRoles.map((role) => (
                      <li key={role.id} className="border-b border-line last:border-b-0">
                        <label className="flex cursor-pointer items-center gap-2.5 px-3 py-2 text-[13px] hover:bg-panel2">
                          <Checkbox checked={m.roleIds.includes(role.id)} onCheckedChange={() => set({ roleIds: toggle(m.roleIds, role.id) })} />
                          <span className="min-w-0 flex-1">{role.name}</span>
                          <span className="num text-xs text-soft">
                            {role.certificates} {role.certificates === 1 ? "certificate" : "certificates"}
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-[13px] font-medium">Trusted certificates</span>
                {active.length === 0 ? (
                  <span className="text-[13px] text-muted-foreground">No client certificates issued yet.</span>
                ) : (
                  <ul className="m-0 flex max-h-72 list-none flex-col gap-2 overflow-y-auto p-0">
                    {[...byCa.entries()].map(([caId, certificates]) => {
                      const ca = data.caCertificates.find((entry) => entry.id === caId);
                      const all = certificates.every((certificate) => m.certIds.includes(certificate.id));
                      const some = certificates.some((certificate) => m.certIds.includes(certificate.id));
                      const ids = certificates.map((certificate) => certificate.id);
                      return (
                        <li key={caId} className="rounded-lg border border-line">
                          <label className="flex cursor-pointer items-center gap-2.5 border-b border-line px-3 py-2 text-xs font-semibold text-muted-foreground hover:bg-panel2">
                            <Checkbox
                              checked={all ? true : some ? "indeterminate" : false}
                              onCheckedChange={() => set({ certIds: all ? m.certIds.filter((id) => !ids.includes(id)) : [...new Set([...m.certIds, ...ids])] })}
                            />
                            <span className="flex-1">{ca?.name ?? `CA #${caId}`}</span>
                            <span className="num font-normal">
                              {certificates.filter((certificate) => m.certIds.includes(certificate.id)).length}/{certificates.length}
                            </span>
                          </label>
                          <ul className="m-0 list-none p-0">
                            {certificates.map((certificate) => (
                              <li key={certificate.id}>
                                <label className="flex cursor-pointer items-center gap-2.5 py-1.5 pl-7 pr-3 text-[13px] hover:bg-panel2">
                                  <Checkbox checked={m.certIds.includes(certificate.id)} onCheckedChange={() => set({ certIds: toggle(m.certIds, certificate.id) })} />
                                  <span className="min-w-0 flex-1">{certificate.commonName}</span>
                                  <span className="text-xs text-soft">expires {new Date(certificate.validTo).toLocaleDateString("en-GB")}</span>
                                </label>
                              </li>
                            ))}
                          </ul>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </div>
          )}
          <FieldError id="f-mtls" />
          <PathsFields
            prefix="f-mtls-paths"
            protectedPaths={m.protectedPaths}
            excludedPaths={m.excludedPaths}
            onChange={set}
            names={{ protectedPaths: "mtlsProtectedPaths", excludedPaths: "mtlsExcludedPaths" }}
          />
          {data.mode === "edit" && data.host && data.canChooseTrust && m.trustMode === "identity" && <MtlsAccessRules hostId={data.host.id} roles={data.mtlsRoles} certificates={active} />}
        </>
      )}
    </EditorCard>
  );
}

function BlockedPathsCard() {
  const { form, update } = useEditor();
  const setBlocks = (recipe: (rows: typeof form.pathBlocks) => typeof form.pathBlocks) => update((f) => ({ ...f, pathBlocks: recipe(f.pathBlocks) }));
  const setAllows = (recipe: (rows: typeof form.pathAllows) => typeof form.pathAllows) => update((f) => ({ ...f, pathAllows: recipe(f.pathAllows) }));
  return (
    <EditorCard
      id="f-blocks"
      title="Blocked paths"
      was="pathBlocks"
      actions={<AddButton onClick={() => setBlocks((rows) => [...rows, { key: rowKey("pb"), path: "", status: 403, body: "Forbidden" }])}>Add blocked path</AddButton>}
      flush
    >
      {form.pathBlocks.length === 0 ? (
        <p className="m-0 px-5 py-3.5 text-[13px] text-muted-foreground">No blocked paths.</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {form.pathBlocks.map((row, index) => (
            <BlockRow
              key={row.key}
              index={index}
              row={row}
              onChange={(next) => setBlocks((rows) => rows.map((current) => (current.key === row.key ? next : current)))}
              onRemove={() => setBlocks((rows) => rows.filter((current) => current.key !== row.key))}
            />
          ))}
        </ul>
      )}
      <div id="f-allows" tabIndex={-1} className="flex flex-col gap-2 border-t border-line px-5 pb-4 pt-3.5">
        <span className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
          Paths that bypass the blocks
          <WasHint group="pathAllows" />
        </span>
        <span className="text-xs text-soft">Allow /secret and block /* to expose only /secret.</span>
        {form.pathAllows.map((row, index) => (
          <AllowRow
            key={row.key}
            index={index}
            value={row.path}
            onChange={(path) => setAllows((rows) => rows.map((current) => (current.key === row.key ? { ...current, path } : current)))}
            onRemove={() => setAllows((rows) => rows.filter((current) => current.key !== row.key))}
          />
        ))}
        <div>
          <AddButton onClick={() => setAllows((rows) => [...rows, { key: rowKey("pa"), path: "" }])}>Add path</AddButton>
        </div>
      </div>
    </EditorCard>
  );
}

function BlockRow({ row, index, onChange, onRemove }: { row: { key: string; path: string; status: PathBlockStatusCode; body: string }; index: number; onChange: (row: { key: string; path: string; status: PathBlockStatusCode; body: string }) => void; onRemove: () => void }) {
  const pathProps = useFieldProps(`f-pb-${index}-path`);
  return (
    <li className={cn("flex flex-col gap-1 border-line px-5 py-3", index > 0 && "border-t")}>
      <div className="grid grid-cols-[minmax(0,1fr)_96px_32px] items-center gap-2 sm:grid-cols-[minmax(0,1fr)_96px_minmax(0,1fr)_32px]">
        <Input {...pathProps} aria-label={`Blocked path ${index + 1}`} value={row.path} placeholder="/metrics" className="num" onChange={(event) => onChange({ ...row, path: event.target.value })} />
        <NativeSelect aria-label={`Status for blocked path ${index + 1}`} value={String(row.status)} className="num" onChange={(event) => onChange({ ...row, status: Number(event.target.value) as PathBlockStatusCode })}>
          {PATH_BLOCK_STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </NativeSelect>
        <Input aria-label={`Body for blocked path ${index + 1}`} value={row.body} placeholder="Empty body" className="col-span-2 row-start-2 sm:col-span-1 sm:row-start-auto" onChange={(event) => onChange({ ...row, body: event.target.value })} />
        <span className="col-start-3 row-start-1 sm:col-start-auto">
          <RemoveButton label={`Remove blocked path ${row.path || index + 1}`} onClick={onRemove} />
        </span>
      </div>
      <FieldError id={`f-pb-${index}-path`} />
    </li>
  );
}

function AllowRow({ value, index, onChange, onRemove }: { value: string; index: number; onChange: (value: string) => void; onRemove: () => void }) {
  const props = useFieldProps(`f-pa-${index}-path`);
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <Input {...props} aria-label={`Bypass path ${index + 1}`} value={value} placeholder="/secret" className="num max-w-sm" onChange={(event) => onChange(event.target.value)} />
        <RemoveButton label={`Remove bypass path ${value || index + 1}`} onClick={onRemove} />
      </div>
      <FieldError id={`f-pa-${index}-path`} />
    </div>
  );
}

export function AccessSection() {
  return (
    <>
      <AccessListCard />
      <SignInCard />
      <MtlsCard />
      <BlockedPathsCard />
    </>
  );
}
