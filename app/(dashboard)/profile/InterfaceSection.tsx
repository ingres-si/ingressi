"use client";

import { useMemo, useState, useSyncExternalStore } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Label } from "@/components/ui/label";
import { useFormat, usePreferences } from "@/src/components/preferences/PreferencesProvider";
import {
  NUMBER_FORMATS,
  listTimeZones,
  numberFormatExample,
  type NumberFormatPreference,
  type ThemePreference,
} from "@/src/lib/preferences-shared";
import { formatNumber, formatPercent } from "@/src/lib/date-format";
import {
  parseStoredSortPreference,
  type ClientCertificateSortKey,
  type L4ProxyHostSortKey,
  type ProxyHostSortKey,
  type SortDirection,
  type StoredSortPreference,
} from "@/src/lib/list-sort-preferences";

const noSubscription = () => () => {};
let browserTimeZones: string[] | null = null;
const SERVER_TIME_ZONES = ["UTC"];

/** The browser's list of time zones (computed once); the server renders UTC only, so hydration matches. */
function useTimeZoneList(): string[] {
  return useSyncExternalStore(
    noSubscription,
    () => (browserTimeZones ??= listTimeZones()),
    () => SERVER_TIME_ZONES
  );
}

const THEME_LABELS: Array<[ThemePreference, string]> = [
  ["system", "System"],
  ["dark", "Dark"],
  ["light", "Light"],
];

type SortChoice<K extends string> = { key: K; label: string; defaultDir: SortDirection };

const PROXY_HOST_SORTS: readonly SortChoice<ProxyHostSortKey>[] = [
  { key: "host", label: "Host name", defaultDir: "asc" },
  { key: "name", label: "Name", defaultDir: "asc" },
  { key: "requests", label: "Requests", defaultDir: "desc" },
  { key: "status", label: "Status", defaultDir: "asc" },
  { key: "errors", label: "5xx rate", defaultDir: "desc" },
  { key: "created", label: "Date added", defaultDir: "desc" },
];

const L4_PROXY_HOST_SORTS: readonly SortChoice<L4ProxyHostSortKey>[] = [
  { key: "name", label: "Name", defaultDir: "asc" },
  { key: "protocol", label: "Protocol", defaultDir: "asc" },
  { key: "listenAddress", label: "Port", defaultDir: "asc" },
  { key: "upstreams", label: "Upstream", defaultDir: "asc" },
  { key: "enabled", label: "Status", defaultDir: "asc" },
  { key: "createdAt", label: "Date added", defaultDir: "desc" },
];

const CLIENT_CERTIFICATE_SORTS: readonly SortChoice<ClientCertificateSortKey>[] = [
  { key: "name", label: "Common name", defaultDir: "asc" },
  { key: "ca", label: "Issued by", defaultDir: "asc" },
  { key: "issued", label: "Issued", defaultDir: "desc" },
  { key: "expires", label: "Expires", defaultDir: "asc" },
];

function SortPreferenceControl<K extends string>({
  id,
  label,
  value,
  options,
  onPick,
  disabled = false,
}: {
  id: string;
  label: string;
  value: StoredSortPreference<K>;
  options: readonly SortChoice<K>[];
  onPick: (value: StoredSortPreference<K>) => void;
  disabled?: boolean;
}) {
  const parsed = parseStoredSortPreference(value);
  const selectedKey = parsed?.key ?? "default";
  const selectedDir = parsed?.dir ?? "default";

  const pickKey = (raw: string) => {
    if (raw === "default") {
      onPick("default");
      return;
    }
    const key = raw as K;
    const option = options.find((candidate) => candidate.key === key);
    if (!option) return;
    const dir = parsed?.key === key ? parsed.dir : option.defaultDir;
    onPick(`${key}:${dir}` as StoredSortPreference<K>);
  };

  const pickDirection = (dir: SortDirection) => {
    if (!parsed) return;
    onPick(`${parsed.key}:${dir}` as StoredSortPreference<K>);
  };

  return (
    <div className="flex min-w-0 flex-col gap-2">
      <span id={`${id}-label`} className="text-sm font-medium">{label}</span>
      <div className="flex w-full max-w-sm overflow-hidden rounded-md border border-input bg-background shadow-sm focus-within:ring-1 focus-within:ring-ring">
        <select
          id={id}
          aria-labelledby={`${id}-label`}
          value={selectedKey}
          onChange={(event) => pickKey(event.target.value)}
          disabled={disabled}
          className="h-9 min-w-0 flex-1 border-0 bg-transparent px-3 py-1 text-sm outline-none disabled:opacity-50"
        >
          <option value="default">Application default</option>
          {options.map((option) => <option key={option.key} value={option.key}>{option.label}</option>)}
        </select>
        <select
          aria-label={`${label} direction`}
          value={selectedDir}
          onChange={(event) => pickDirection(event.target.value as SortDirection)}
          disabled={disabled || !parsed}
          className="h-9 w-36 border-0 border-l border-input bg-transparent px-3 py-1 text-sm outline-none disabled:opacity-50"
        >
          <option value="default" disabled>Not applicable</option>
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
        </select>
      </div>
    </div>
  );
}

function Segmented<T extends string>({
  labelledBy,
  options,
  value,
  onPick,
  mono = false,
  disabled = false,
}: {
  labelledBy: string;
  options: Array<[T, string]>;
  value: T;
  onPick: (value: T) => void;
  mono?: boolean;
  disabled?: boolean;
}) {
  return (
    <div role="group" aria-labelledby={labelledBy} className="inline-flex w-fit rounded-lg border bg-muted/40 p-0.5">
      {options.map(([id, label]) => (
        <button
          key={id}
          type="button"
          aria-pressed={value === id}
          onClick={() => onPick(id)}
          disabled={disabled}
          className={`rounded-md px-3 py-1.5 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
            value === id ? "bg-background font-medium text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
          } ${mono ? "font-mono" : ""}`}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

/** Profile: interface preferences of the account (src/lib/preferences.ts). */
export default function InterfaceSection() {
  const { preferences, update } = usePreferences();
  const format = useFormat();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const zoneList = useTimeZoneList();
  const timeZones = useMemo(
    () => (zoneList.includes(preferences.timeZone) ? zoneList : [preferences.timeZone, ...zoneList]),
    [zoneList, preferences.timeZone]
  );

  const save = async (change: Parameters<typeof update>[0]) => {
    setError(null);
    setPending(true);
    const problem = await update(change);
    setPending(false);
    if (problem) setError(problem);
  };

  const example = `${formatNumber(61817, preferences)} requests · ${formatPercent(0.018, preferences)} blocked`;

  return (
    <section aria-labelledby="ui-title" className="flex flex-col gap-5 rounded-xl border bg-card p-6">
      <h2 id="ui-title" className="text-base font-semibold">Interface</h2>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="flex flex-col gap-2">
          <span id="ui-theme" className="text-sm font-medium">Theme</span>
          <Segmented
            labelledBy="ui-theme"
            options={THEME_LABELS}
            value={preferences.theme}
            onPick={(theme) => save({ theme })}
            disabled={pending}
          />
          <span className="text-xs text-muted-foreground">System follows your device&apos;s setting.</span>
        </div>

        <div className="flex flex-col gap-2">
          <Label htmlFor="ui-tz">Time zone</Label>
          <select
            id="ui-tz"
            value={preferences.timeZone}
            onChange={(event) => save({ timeZone: event.target.value })}
            disabled={pending}
            className="flex h-9 w-full max-w-xs rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50"
          >
            {timeZones.map((zone) => (
              <option key={zone} value={zone}>{zone}</option>
            ))}
          </select>
          <span className="text-xs text-muted-foreground">
            Now: <span className="font-mono" suppressHydrationWarning>{format.dateTime(Date.now())}</span>
          </span>
        </div>

        <div className="flex flex-col gap-2">
          <span id="ui-nf" className="text-sm font-medium">Number format</span>
          <Segmented<NumberFormatPreference>
            labelledBy="ui-nf"
            options={NUMBER_FORMATS.map((id) => [id, numberFormatExample(id)])}
            value={preferences.numberFormat}
            onPick={(numberFormat) => save({ numberFormat })}
            mono
            disabled={pending}
          />
          <span className="text-xs text-muted-foreground">
            Example: <span className="font-mono">{example}</span>
          </span>
        </div>
      </div>

      <div className="flex flex-col gap-4 border-t pt-5">
        <div className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold">Default list order</h3>
          <p className="m-0 text-xs text-muted-foreground">
            Used when these lists first open. Explicit sort parameters in a list URL take precedence.
          </p>
        </div>
        <div className="grid gap-6 lg:grid-cols-3">
          <SortPreferenceControl
            id="ui-proxy-host-sort"
            label="Proxy hosts"
            value={preferences.proxyHostsSort}
            options={PROXY_HOST_SORTS}
            onPick={(proxyHostsSort) => save({ proxyHostsSort })}
            disabled={pending}
          />
          <SortPreferenceControl
            id="ui-l4-proxy-host-sort"
            label="L4 proxy hosts"
            value={preferences.l4ProxyHostsSort}
            options={L4_PROXY_HOST_SORTS}
            onPick={(l4ProxyHostsSort) => save({ l4ProxyHostsSort })}
            disabled={pending}
          />
          <SortPreferenceControl
            id="ui-client-certificates-sort"
            label="Client certificates"
            value={preferences.clientCertificatesSort}
            options={CLIENT_CERTIFICATE_SORTS}
            onPick={(clientCertificatesSort) => save({ clientCertificatesSort })}
            disabled={pending}
          />
        </div>
      </div>
    </section>
  );
}
