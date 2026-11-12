"use client";

/** Controls shared by several sections: a native select, upstream rows and the load balancing editor. */
import type { ReactNode, SelectHTMLAttributes } from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { Field, FieldError, TextField, ToggleRow, useFieldProps, AddButton, RemoveButton, WasHint } from "./fields";
import { AS_WRITTEN, DEFAULT_PASSIVE_FAIL_DURATION, LB_POLICIES, parseUpstream, rowKey, SCHEMES, type LbForm, type Scheme, type UpstreamRow } from "./model";

/** A native select styled like the inputs: keyboard and screen-reader friendly, and the platform picker on phones. */
export function NativeSelect({ className, children, ...props }: SelectHTMLAttributes<HTMLSelectElement> & { children: ReactNode }) {
  return (
    <select
      {...props}
      className={cn(
        "h-9 w-full min-w-0 rounded-lg border border-line2 bg-panel px-2.5 text-[13px] text-foreground transition-colors hover:border-soft/60 focus-visible:border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-tint disabled:cursor-not-allowed disabled:opacity-50 aria-[invalid=true]:border-bad",
        className
      )}
    >
      {children}
    </select>
  );
}

export function SelectField({
  id,
  label,
  value,
  onChange,
  hint,
  was,
  className,
  disabled,
  children,
}: {
  id: string;
  label: ReactNode;
  value: string;
  onChange: (value: string) => void;
  hint?: ReactNode;
  was?: string;
  className?: string;
  disabled?: boolean;
  children: ReactNode;
}) {
  const props = useFieldProps(id, Boolean(hint));
  return (
    <Field id={id} label={label} hint={hint} was={was} className={className}>
      <NativeSelect {...props} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
        {children}
      </NativeSelect>
    </Field>
  );
}

function UpstreamAddress({ id, row, index, onChange }: { id: string; row: UpstreamRow; index: number; onChange: (row: UpstreamRow) => void }) {
  const props = useFieldProps(id);
  return (
    <Input
      {...props}
      aria-label={`Upstream ${index + 1} address`}
      value={row.address}
      placeholder="10.0.0.5:8080"
      autoComplete="off"
      spellCheck={false}
      className="num"
      onChange={(event) => {
        const value = event.target.value;
        // A pasted URL brings its scheme with it.
        if (/^https?:\/\//.test(value)) onChange({ ...row, ...parseUpstream(value) });
        else onChange({ ...row, address: value });
      }}
    />
  );
}

/** Upstream rows: scheme, address and a remove button; at least one row stays. */
export function UpstreamRows({
  rows,
  onChange,
  idOf,
  addLabel = "Add upstream",
}: {
  rows: UpstreamRow[];
  onChange: (rows: UpstreamRow[]) => void;
  idOf: (index: number) => string;
  addLabel?: string;
}) {
  const set = (index: number, row: UpstreamRow) => onChange(rows.map((current, i) => (i === index ? row : current)));
  return (
    <div className="flex flex-col gap-2">
      <ol className="m-0 flex list-none flex-col gap-2 p-0">
        {rows.map((row, index) => (
          <li key={row.key} className="flex flex-col gap-1">
            <div className="grid grid-cols-[96px_minmax(0,1fr)_32px] items-center gap-2">
              <NativeSelect
                aria-label={`Upstream ${index + 1} scheme`}
                value={row.scheme}
                className="num"
                onChange={(event) => set(index, { ...row, scheme: event.target.value as Scheme })}
              >
                {SCHEMES.map((scheme) => (
                  <option key={scheme} value={scheme}>
                    {scheme}
                  </option>
                ))}
                {/* Only for an upstream stored in a form the two schemes cannot express. */}
                {row.scheme === AS_WRITTEN && <option value={AS_WRITTEN}>as written</option>}
              </NativeSelect>
              <UpstreamAddress id={idOf(index)} row={row} index={index} onChange={(next) => set(index, next)} />
              {rows.length > 1 ? (
                <RemoveButton label={`Remove upstream ${index + 1}`} onClick={() => onChange(rows.filter((_, i) => i !== index))} />
              ) : (
                <span aria-hidden="true" />
              )}
            </div>
            <FieldError id={idOf(index)} />
          </li>
        ))}
      </ol>
      <div>
        <AddButton onClick={() => onChange([...rows, { key: rowKey("up"), scheme: "http://", address: "" }])}>{addLabel}</AddButton>
      </div>
    </div>
  );
}

/** Load balancing settings: policy, retries and health checks. The parent shows the on/off switch. */
export function LbFields({ lb, onChange, idPrefix }: { lb: LbForm; onChange: (lb: LbForm) => void; idPrefix: string }) {
  const set = (patch: Partial<LbForm>) => onChange({ ...lb, ...patch });
  const policy = LB_POLICIES.find((entry) => entry.value === lb.policy);
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(260px,100%),1fr))] items-start gap-x-4 gap-y-3">
        <SelectField id={`${idPrefix}-policy`} label="Policy" value={lb.policy} onChange={(value) => set({ policy: value as LbForm["policy"] })}>
          {LB_POLICIES.map((entry) => (
            <option key={entry.value} value={entry.value}>
              {entry.label}
            </option>
          ))}
        </SelectField>
        <p className="m-0 text-[13px] text-muted-foreground sm:pt-7">{policy?.description}</p>
      </div>
      {lb.policy === "header" && (
        <TextField id={`${idPrefix}-header`} label="Header to hash" value={lb.headerField} onChange={(value) => set({ headerField: value })} placeholder="X-Tenant-Id" mono className="max-w-sm" />
      )}
      {lb.policy === "cookie" && (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(220px,100%),1fr))] gap-x-4 gap-y-3">
          <TextField id={`${idPrefix}-cookie`} label="Cookie name" value={lb.cookieName} onChange={(value) => set({ cookieName: value })} placeholder="server_id" mono />
          <TextField
            id={`${idPrefix}-cookie-secret`}
            label="Signing secret, optional"
            type="password"
            value={lb.cookieSecret}
            onChange={(value) => set({ cookieSecret: value })}
            autoComplete="new-password"
          />
        </div>
      )}
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(180px,100%),1fr))] gap-x-4 gap-y-3">
        <TextField id={`${idPrefix}-try-duration`} label="Keep trying for" value={lb.tryDuration} onChange={(value) => set({ tryDuration: value })} placeholder="5s" mono />
        <TextField id={`${idPrefix}-try-interval`} label="Wait between tries" value={lb.tryInterval} onChange={(value) => set({ tryInterval: value })} placeholder="250ms" mono />
        <TextField id={`${idPrefix}-retries`} label="Max retries" value={lb.retries} onChange={(value) => set({ retries: value })} inputMode="numeric" mono />
      </div>
      <div className="border-t border-line">
        <ToggleRow
          id={`${idPrefix}-active`}
          label="Active health checks"
          description="Probe each upstream on a schedule."
          checked={lb.active.enabled}
          onChange={(enabled) => set({ active: { ...lb.active, enabled } })}
        />
        {lb.active.enabled && (
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(150px,100%),1fr))] gap-x-4 gap-y-3 pb-3">
            <TextField id={`${idPrefix}-active-uri`} label="Path" value={lb.active.uri} onChange={(uri) => set({ active: { ...lb.active, uri } })} placeholder="/health" mono />
            <TextField id={`${idPrefix}-active-port`} label="Port" value={lb.active.port} onChange={(port) => set({ active: { ...lb.active, port } })} placeholder="Upstream's" inputMode="numeric" mono />
            <TextField id={`${idPrefix}-active-interval`} label="Every" value={lb.active.interval} onChange={(interval) => set({ active: { ...lb.active, interval } })} placeholder="30s" mono />
            <TextField id={`${idPrefix}-active-timeout`} label="Timeout" value={lb.active.timeout} onChange={(timeout) => set({ active: { ...lb.active, timeout } })} placeholder="5s" mono />
            <TextField id={`${idPrefix}-active-status`} label="Expected status" value={lb.active.status} onChange={(status) => set({ active: { ...lb.active, status } })} placeholder="2xx" inputMode="numeric" mono />
            <TextField id={`${idPrefix}-active-body`} label="Expected body" value={lb.active.body} onChange={(body) => set({ active: { ...lb.active, body } })} placeholder="Any" mono />
          </div>
        )}
      </div>
      <div className="border-t border-line">
        <ToggleRow
          id={`${idPrefix}-passive`}
          label="Passive health checks"
          description="Judge each upstream by its real responses."
          checked={lb.passive.enabled}
          onChange={(enabled) =>
            set({ passive: { ...lb.passive, enabled, failDuration: enabled && !lb.passive.failDuration ? DEFAULT_PASSIVE_FAIL_DURATION : lb.passive.failDuration } })
          }
        />
        {lb.passive.enabled && (
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(150px,100%),1fr))] gap-x-4 gap-y-3 pb-1">
            <TextField id={`${idPrefix}-passive-duration`} label="Remember failures for" value={lb.passive.failDuration} onChange={(failDuration) => set({ passive: { ...lb.passive, failDuration } })} placeholder="30s" mono />
            <TextField id={`${idPrefix}-passive-max`} label="Failures before unhealthy" value={lb.passive.maxFails} onChange={(maxFails) => set({ passive: { ...lb.passive, maxFails } })} inputMode="numeric" mono />
            <TextField id={`${idPrefix}-passive-status`} label="Unhealthy status codes" value={lb.passive.unhealthyStatus} onChange={(unhealthyStatus) => set({ passive: { ...lb.passive, unhealthyStatus } })} placeholder="502, 503, 504" mono />
            <TextField id={`${idPrefix}-passive-latency`} label="Unhealthy latency" value={lb.passive.unhealthyLatency} onChange={(unhealthyLatency) => set({ passive: { ...lb.passive, unhealthyLatency } })} placeholder="Off" mono />
          </div>
        )}
      </div>
    </div>
  );
}

/** A segmented choice with a visible label above it (the group is named after the label). */
export function SegmentedField<T extends string>({
  id,
  label,
  value,
  onChange,
  options,
  was,
  hint,
}: {
  id: string;
  label: string;
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: string; disabled?: boolean }[];
  was?: string;
  hint?: ReactNode;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5" id={id} tabIndex={-1}>
      <span className="flex flex-wrap items-center gap-2 text-[13px] font-medium leading-5">
        {label}
        {was && <WasHint group={was} />}
      </span>
      <SegmentedControl label={label} value={value} onChange={onChange} options={options} size="sm" />
      {hint && <p className="m-0 text-xs leading-4 text-soft">{hint}</p>}
      <FieldError id={id} />
    </div>
  );
}

