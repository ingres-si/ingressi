"use client";

import { useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { COUNTRIES } from "../countries";
import { AddButton, ChipInput, EditorCard, FieldError, RemoveButton, TextField, ToggleRow, useEditor } from "./fields";
import { SegmentedField } from "./controls";
import { rowKey, type GeoForm } from "./model";

const CONTINENTS = [
  { code: "AF", name: "Africa" },
  { code: "AN", name: "Antarctica" },
  { code: "AS", name: "Asia" },
  { code: "EU", name: "Europe" },
  { code: "NA", name: "North America" },
  { code: "OC", name: "Oceania" },
  { code: "SA", name: "South America" },
];

const RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

function GeoIpStatus() {
  const [status, setStatus] = useState<{ country: boolean; asn: boolean } | null | "loading">("loading");
  useEffect(() => {
    let alive = true;
    fetch("/api/geoip-status")
      .then((response) => (response.ok ? response.json() : null))
      .then((value) => alive && setStatus(value))
      .catch(() => alive && setStatus(null));
    return () => {
      alive = false;
    };
  }, []);
  // Said only when something is missing: then country, continent or ASN rules do nothing.
  if (status === "loading" || (status?.country && status?.asn)) return null;
  const none = !status?.country && !status?.asn;
  const text = none
    ? "GeoIP databases missing: country, continent and ASN rules do nothing"
    : !status?.country
      ? "GeoIP country database missing: country and continent rules do nothing"
      : "GeoIP ASN database missing: ASN rules do nothing";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-warn">
      <span aria-hidden="true" className={cn("h-2 w-2 rounded-full", none ? "bg-bad" : "bg-warn")} />
      {text}
    </span>
  );
}

function CountryPicker({ id, label, values, onChange }: { id: string; label: string; values: string[]; onChange: (values: string[]) => void }) {
  const [search, setSearch] = useState("");
  const selected = useMemo(() => new Set(values), [values]);
  const query = search.trim().toLowerCase();
  const matches = useMemo(
    () => COUNTRIES.filter((country) => !query || country.name.toLowerCase().includes(query) || country.code.toLowerCase().startsWith(query)),
    [query]
  );
  const toggle = (code: string) => onChange(selected.has(code) ? values.filter((value) => value !== code) : [...values, code]);
  return (
    <fieldset className="m-0 flex min-w-0 flex-col gap-2 border-0 p-0">
      <legend className="mb-1.5 text-[13px] font-medium">{label}</legend>
      {values.length > 0 && (
        <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0" aria-label={`${label} chosen`}>
          {values.map((code) => (
            <li key={code} className="inline-flex h-7 items-center gap-1 rounded-lg border border-line2 bg-panel2 pl-2 pr-0.5 text-[13px]">
              {COUNTRIES.find((country) => country.code === code)?.name ?? code}
              <span className="num text-[11px] text-soft">{code}</span>
              <button
                type="button"
                aria-label={`Remove ${COUNTRIES.find((country) => country.code === code)?.name ?? code}`}
                onClick={() => toggle(code)}
                className="grid h-6 w-6 place-items-center rounded-md text-muted-foreground hover:bg-raise hover:text-foreground"
              >
                <svg aria-hidden="true" viewBox="0 0 24 24" className="h-3 w-3 fill-none stroke-current" strokeWidth={2.4} strokeLinecap="round">
                  <path d="M6 6l12 12M18 6L6 18" />
                </svg>
              </button>
            </li>
          ))}
        </ul>
      )}
      <label htmlFor={`${id}-search`} className="sr-only">
        Search countries for {label.toLowerCase()}
      </label>
      <Input id={`${id}-search`} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search countries" className="h-8 max-w-xs" autoComplete="off" />
      <div className="max-h-48 overflow-y-auto rounded-lg border border-line">
        {matches.length === 0 ? (
          <p className="m-0 px-3 py-2 text-xs text-soft">No country matches “{search}”.</p>
        ) : (
          <ul className="m-0 list-none p-0">
            {matches.map((country) => (
              <li key={country.code} className="border-b border-line last:border-b-0">
                <label className="flex cursor-pointer items-center gap-2.5 px-3 py-1.5 text-[13px] hover:bg-panel2">
                  <Checkbox checked={selected.has(country.code)} onCheckedChange={() => toggle(country.code)} aria-label={`${country.name} (${country.code})`} />
                  <span className="flex-1">{country.name}</span>
                  <span className="num text-[11px] text-soft">{country.code}</span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </fieldset>
  );
}

function ContinentPicker({ label, values, onChange }: { label: string; values: string[]; onChange: (values: string[]) => void }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[13px] font-medium">{label}</span>
      <div role="group" aria-label={label} className="flex flex-wrap gap-1.5">
        {CONTINENTS.map((continent) => {
          const pressed = values.includes(continent.code);
          return (
            <button
              key={continent.code}
              type="button"
              aria-pressed={pressed}
              onClick={() => onChange(pressed ? values.filter((value) => value !== continent.code) : [...values, continent.code])}
              className={cn(
                "inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[13px] transition-colors",
                pressed ? "border-brand bg-brand-tint text-foreground" : "border-line2 text-muted-foreground hover:text-foreground"
              )}
            >
              {continent.name}
              <span className="num text-[11px] text-soft">{continent.code}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function RulesPanel({ kind, geo, set }: { kind: "block" | "allow"; geo: GeoForm; set: (patch: Partial<GeoForm>) => void }) {
  const block = kind === "block";
  return (
    <div className="flex flex-col gap-4">
      <CountryPicker
        id={`f-geo-${kind}-countries`}
        label={block ? "Blocked countries" : "Allowed countries"}
        values={block ? geo.blockCountries : geo.allowCountries}
        onChange={(values) => set(block ? { blockCountries: values } : { allowCountries: values })}
      />
      <ContinentPicker
        label={block ? "Blocked continents" : "Allowed continents"}
        values={block ? geo.blockContinents : geo.allowContinents}
        onChange={(values) => set(block ? { blockContinents: values } : { allowContinents: values })}
      />
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(240px,100%),1fr))] gap-x-4 gap-y-3">
        <div className="flex flex-col gap-1.5">
          <span className="text-[13px] font-medium">{block ? "Blocked ASNs" : "Allowed ASNs"}</span>
          <ChipInput
            id={`f-geo-${kind}-asns`}
            label={block ? "Add blocked ASNs" : "Add allowed ASNs"}
            values={block ? geo.blockAsns : geo.allowAsns}
            onChange={(values) => set(block ? { blockAsns: values } : { allowAsns: values })}
            normalize={(value) => value.trim().replace(/^AS/i, "").replace(/\D/g, "")}
            placeholder="13335"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <span className="text-[13px] font-medium">{block ? "Blocked ranges" : "Allowed ranges"}</span>
          <ChipInput
            id={`f-geo-${kind}-cidrs`}
            label={block ? "Add blocked ranges" : "Add allowed ranges"}
            values={block ? geo.blockCidrs : geo.allowCidrs}
            onChange={(values) => set(block ? { blockCidrs: values } : { allowCidrs: values })}
            placeholder="10.0.0.0/8"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <span className="text-[13px] font-medium">{block ? "Blocked addresses" : "Allowed addresses"}</span>
          <ChipInput
            id={`f-geo-${kind}-ips`}
            label={block ? "Add blocked addresses" : "Add allowed addresses"}
            values={block ? geo.blockIps : geo.allowIps}
            onChange={(values) => set(block ? { blockIps: values } : { allowIps: values })}
            placeholder="203.0.113.7"
          />
        </div>
      </div>
    </div>
  );
}

export function GeoBlockCard() {
  const { form, update, data, errors } = useEditor();
  const geo = form.geoblock;
  const [panel, setPanel] = useState<"block" | "allow">("block");
  const [open, setOpen] = useState(false);
  // The block response settings open by themselves when one of them has a problem.
  const advancedOpen = open || Object.keys(errors).some((id) => id === "f-geo-status" || id === "f-geo-redirect" || id.startsWith("f-geo-header-"));
  const setAdvancedOpen = (recipe: (current: boolean) => boolean) => setOpen(recipe(advancedOpen));
  const set = (patch: Partial<GeoForm>) => update((f) => ({ ...f, geoblock: { ...f.geoblock, ...patch } }));
  const blockCount = geo.blockCountries.length + geo.blockContinents.length + geo.blockAsns.length + geo.blockCidrs.length + geo.blockIps.length;
  const allowCount = geo.allowCountries.length + geo.allowContinents.length + geo.allowAsns.length + geo.allowCidrs.length + geo.allowIps.length;
  const globalOn = Boolean(data.geoblockGlobal?.enabled);
  // Allow rules only make exceptions to block rules (the global ones too when merged).
  const globalBlocks = globalOn && Boolean(data.geoblockGlobal?.blocks);
  const blocksNothing = allowCount > 0 && blockCount === 0 && (geo.mode === "override" || !globalBlocks);
  const description = geo.enabled
    ? "Allow rules win over block rules."
    : !globalOn
      ? undefined
      : geo.mode === "override"
        ? "Off for this host, and it overrides the global geo blocking rules, so none apply."
        : "Off for this host: only the global geo blocking rules apply.";
  return (
    <EditorCard
      id="geo-blocking"
      title="Geo blocking"
      was="geoblock"
      description={description}
      actions={
        <span className="flex items-center gap-2 text-[13px]">
          <span id="f-geo-enabled-label">Geo blocking for this host</span>
          <Switch id="f-geo-enabled" aria-labelledby="f-geo-enabled-label" checked={geo.enabled} onCheckedChange={(enabled) => set({ enabled })} />
        </span>
      }
    >
      {geo.enabled && (
        <>
          <div className="flex flex-wrap items-end justify-between gap-3">
            <SegmentedField
              id="f-geo-mode"
              label="Rules"
              value={geo.mode}
              onChange={(mode) => set({ mode })}
              options={[
                { value: "merge", label: "Merge with global" },
                { value: "override", label: "Override global" },
              ]}
            />
            <GeoIpStatus />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <span className="text-soft">Preset:</span>
            <button
              type="button"
              onClick={() => set({ blockCidrs: [...new Set([...geo.blockCidrs, "0.0.0.0/0"])], allowCidrs: [...new Set([...geo.allowCidrs, ...RFC1918])] })}
              className="h-7 rounded-lg border border-line2 bg-panel2 px-2.5 text-xs transition-colors hover:bg-raise"
            >
              Private networks only
            </button>
          </div>
          <SegmentedControl
            label="Rule list"
            size="sm"
            value={panel}
            onChange={setPanel}
            options={[
              { value: "block", label: `Block rules${blockCount ? ` · ${blockCount}` : ""}` },
              { value: "allow", label: `Allow rules${allowCount ? ` · ${allowCount}` : ""}` },
            ]}
          />
          <RulesPanel kind={panel} geo={geo} set={set} />
          {blocksNothing && (
            <p className="m-0 text-xs text-warn">
              Allow rules only make exceptions to block rules, so with no block rules nothing is blocked. To let only some countries in, block every continent and allow them.
            </p>
          )}
          <FieldError id="f-geo-ranges" />
          <div className="border-t border-line pt-3">
            <button
              type="button"
              aria-expanded={advancedOpen}
              aria-controls="geo-advanced"
              onClick={() => setAdvancedOpen((open) => !open)}
              className="text-[13px] font-medium text-brand underline-offset-4 hover:underline"
            >
              {advancedOpen ? "Hide" : "Show"} trusted proxies and the block response
            </button>
            <div id="geo-advanced" hidden={!advancedOpen} className="mt-3 flex flex-col gap-3.5">
              <div className="flex flex-col gap-1.5">
                <span className="text-[13px] font-medium">Trusted proxies</span>
                <ChipInput
                  id="f-geo-proxies"
                  label="Add trusted proxies"
                  values={geo.trustedProxies}
                  onChange={(trustedProxies) => set({ trustedProxies })}
                  placeholder="private_ranges"
                  hint="private_ranges covers the private networks."
                />
              </div>
              <ToggleRow
                id="f-geo-fail-closed"
                className="py-0"
                label="Block clients whose address is unknown"
                checked={geo.failClosed}
                onChange={(failClosed) => set({ failClosed })}
              />
              <div className="grid grid-cols-[repeat(auto-fit,minmax(min(200px,100%),1fr))] gap-x-4 gap-y-3">
                <TextField id="f-geo-status" name="geoblockResponseStatus" label="Status code" value={geo.responseStatus} onChange={(responseStatus) => set({ responseStatus })} inputMode="numeric" mono />
                <TextField id="f-geo-body" name="geoblockResponseBody" label="Response body" value={geo.responseBody} onChange={(responseBody) => set({ responseBody })} />
                <TextField
                  id="f-geo-redirect"
                  name="geoblockRedirectUrl"
                  label="Redirect to, optional"
                  value={geo.redirectUrl}
                  onChange={(redirectUrl) => set({ redirectUrl })}
                  placeholder="https://example.com/blocked"
                  hint="Sends a 302 there instead of the status and body."
                  mono
                />
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-[13px] font-medium">Response headers</span>
                {geo.headers.map((row, index) => (
                  <div key={row.key} className="flex flex-col gap-1">
                    <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_32px] gap-2">
                      <Input
                        id={`f-geo-header-${index}`}
                        aria-label={`Response header ${index + 1} name`}
                        value={row.name}
                        placeholder="Header"
                        className="num"
                        onChange={(event) => set({ headers: geo.headers.map((current) => (current.key === row.key ? { ...current, name: event.target.value } : current)) })}
                      />
                      <Input
                        aria-label={`Response header ${index + 1} value`}
                        value={row.value}
                        placeholder="Value"
                        className="num"
                        onChange={(event) => set({ headers: geo.headers.map((current) => (current.key === row.key ? { ...current, value: event.target.value } : current)) })}
                      />
                      <RemoveButton label={`Remove response header ${index + 1}`} onClick={() => set({ headers: geo.headers.filter((current) => current.key !== row.key) })} />
                    </div>
                    <FieldError id={`f-geo-header-${index}`} />
                  </div>
                ))}
                <div>
                  <AddButton onClick={() => set({ headers: [...geo.headers, { key: rowKey("gh"), name: "", value: "" }] })}>Add header</AddButton>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </EditorCard>
  );
}
