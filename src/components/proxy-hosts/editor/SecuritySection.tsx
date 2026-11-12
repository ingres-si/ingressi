"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import Link from "next/link";
import { ChevronDown, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AppDialog } from "@/components/ui/AppDialog";
import { WafExclusionDialog, type WafExclusionDraft, type WafExclusionEditing, type WafRuleOption } from "@/app/(dashboard)/waf/WafExclusionDialog";
import { deleteWafExclusionAction } from "@/app/(dashboard)/waf/actions";
import type { EditorWafExclusion } from "./types";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { RATE_LIMIT_KEYS, RATE_LIMIT_KEY_LABELS, RATE_LIMIT_LIMITS, RATE_LIMIT_METHODS, type RateLimitKey } from "@/lib/rate-limit-rules";
import { appendQuickTemplate, HOST_TEMPLATE_ID_OFFSET, WAF_QUICK_TEMPLATES } from "@/lib/waf-quick-templates";
import type { WafHostMode } from "@/lib/waf-host-mode";
import { AddButton, EditorCard, Field, FieldError, RemoveButton, TextField, ToggleRow, WasHint, useEditor, useFieldProps } from "./fields";
import { NativeSelect, SegmentedField, SelectField } from "./controls";
import { rateLimitRow, type RateLimitRuleRow, type WafForm } from "./model";
import { GeoBlockCard } from "./GeoBlockCard";
import { ChoiceCards } from "@/components/ui/ChoiceCards";

const GLOBAL_MODE = { On: "blocking", DetectionOnly: "detection only", Off: "off" } as const;

function WafModePicker() {
  const { form, update, data } = useEditor();
  const global = data.wafGlobal;
  const globalLabel = global ? GLOBAL_MODE[global.mode] : "blocking";
  const modes: { value: WafHostMode; label: string; description?: string; dot: string }[] = [
    {
      value: "inherit",
      label: "Global mode",
      // The global settings may cover only hosts that pick a mode: then inheriting means no WAF.
      description: global?.appliesToAll === false && !data.host?.waf ? "Off: the WAF settings cover only hosts that pick a mode." : `Follows the WAF settings: ${globalLabel} now.`,
      dot: "bg-soft",
    },
    { value: "off", label: "Off", description: "Nothing on this host is inspected.", dot: "bg-soft" },
    { value: "detection_only", label: "Detect only", description: "Logs matches, blocks nothing.", dot: "bg-warn" },
    { value: "block", label: "Block", description: "Requests over the anomaly threshold get 403.", dot: "bg-waf" },
  ];
  return (
    <div className="flex flex-col gap-1.5">
      <span id="f-waf-mode-label" className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
        Mode
        <WasHint group="waf" />
      </span>
      <ChoiceCards
        id="f-waf-mode"
        labelledBy="f-waf-mode-label"
        value={form.waf.mode}
        minWidth={180}
        onChange={(mode) => update((f) => ({ ...f, waf: { ...f.waf, mode } }))}
        options={modes.map((mode) => ({ value: mode.value, label: mode.label, description: mode.description, dot: mode.dot }))}
      />
      <FieldError id="f-waf-mode" />
    </div>
  );
}

/** Security events for the host (its first plain domain), WAF events only. */
function hostEventsHref(domains: readonly string[]): string | null {
  const domain = domains.find((name) => !name.includes("*"));
  if (!domain) return null;
  return `/security?kind=waf&filters=${encodeURIComponent(JSON.stringify([{ dim: "host", op: "is", value: domain }]))}`;
}

/** The WAF settings most hosts never change: which rules, body limits and raw directives. */
function WafAdvanced() {
  const { form, update, data } = useEditor();
  const setWaf = (patch: Partial<WafForm>) => update((f) => ({ ...f, waf: { ...f.waf, ...patch } }));
  const directivesProps = useFieldProps("f-waf-directives", true);
  const [templatesOpen, setTemplatesOpen] = useState(false);
  // Open when something here is not the default, so a change is never hidden.
  const changed = form.waf.rules === "override" || !form.waf.loadCrs || Boolean(form.waf.bodyLimit || form.waf.bodyMemory) || form.waf.bodyAction !== "inherit" || Boolean(form.wafDirectives.trim());
  const [open, setOpen] = useState(changed);
  // An overriding host takes nothing from the global settings: unset values are Coraza's own.
  const defaultLabel = form.waf.rules === "override" ? "Coraza default" : "Global default";
  const summary = [
    form.waf.rules === "override" ? "own settings only" : null,
    !form.waf.loadCrs ? "Core Rule Set off" : null,
    form.waf.bodyLimit ? `body ${form.waf.bodyLimit} MiB` : null,
    form.wafDirectives.trim() ? "custom directives" : null,
  ].filter(Boolean);
  return (
    <div className="border-t border-line pt-3.5">
      <button
        type="button"
        aria-expanded={open}
        aria-controls="waf-advanced"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center gap-2 text-left"
      >
        <ChevronDown aria-hidden="true" className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", !open && "-rotate-90")} />
        <span className="font-medium">Advanced</span>
        <span className="min-w-0 truncate text-[13px] text-muted-foreground">
          {summary.length > 0 ? summary.join(" · ") : "Global rules and limits, the Core Rule Set, no custom directives"}
        </span>
      </button>
      <div id="waf-advanced" hidden={!open} className="mt-3.5 flex flex-col gap-4">
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(260px,100%),1fr))] gap-x-5 gap-y-3.5">
          <SegmentedField
            id="f-waf-rules"
            label="Global WAF settings"
            value={form.waf.rules}
            onChange={(rules) => setWaf({ rules })}
            options={[
              { value: "merge", label: "Use them too" },
              { value: "override", label: "Ignore them" },
            ]}
            hint={
              form.waf.rules === "override"
                ? "Only this host's settings: global exclusions, directives and limits do not apply."
                : "Global exclusions, directives and limits apply, plus this host's."
            }
          />
          <ToggleRow
            id="f-waf-crs"
            className="py-0"
            label="OWASP Core Rule Set"
            description="The common attack rules most hosts need."
            checked={form.waf.loadCrs}
            onChange={(loadCrs) => setWaf({ loadCrs })}
          />
        </div>
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(190px,100%),1fr))] gap-x-4 gap-y-3">
          <TextField id="f-waf-body" label="Max request body, MiB" value={form.waf.bodyLimit} onChange={(bodyLimit) => setWaf({ bodyLimit })} placeholder={defaultLabel} inputMode="numeric" mono />
          <TextField id="f-waf-memory" label="Buffered in memory, MiB" value={form.waf.bodyMemory} onChange={(bodyMemory) => setWaf({ bodyMemory })} placeholder={defaultLabel} inputMode="numeric" mono />
          <SelectField id="f-waf-action" label="Larger bodies" value={form.waf.bodyAction} onChange={(value) => setWaf({ bodyAction: value as WafForm["bodyAction"] })}>
            <option value="inherit">{defaultLabel}</option>
            <option value="Reject">Reject with 413</option>
            <option value="ProcessPartial">Inspect the first part, pass the rest</option>
          </SelectField>
        </div>
        <p className="-mt-2 m-0 text-xs text-soft">With the Core Rule Set the WAF reads at most 12.5 MiB of a body unless you raise it, up to 1024 MiB.</p>
        <Field
          id="f-waf-directives"
          label="Custom SecLang directives"
          was="wafDirectives"
          hint={
            data.canWriteWaf
              ? `Added after the Core Rule Set. Use rule ids from ${9000 + HOST_TEMPLATE_ID_OFFSET} up for your own rules.`
              : "Changing custom directives needs the waf:write permission."
          }
        >
          <Textarea
            {...directivesProps}
            disabled={!data.canWriteWaf}
            value={form.wafDirectives}
            onChange={(event) => update((f) => ({ ...f, wafDirectives: event.target.value }))}
            rows={3}
            spellCheck={false}
            placeholder={'SecRule REQUEST_URI "@beginsWith /internal" "id:9101,deny,status:403,log"'}
            className="num min-h-[72px] text-xs leading-[18px]"
          />
        </Field>
        <div hidden={!data.canWriteWaf}>
          <button
            type="button"
            aria-expanded={templatesOpen}
            aria-controls="waf-templates"
            onClick={() => setTemplatesOpen((value) => !value)}
            className="inline-flex items-center gap-1 text-[13px] text-muted-foreground hover:text-foreground"
          >
            Quick templates
            <ChevronDown aria-hidden="true" className={cn("h-4 w-4 transition-transform", templatesOpen && "rotate-180")} />
          </button>
          <div id="waf-templates" hidden={!templatesOpen} className="mt-2">
            <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0">
              {WAF_QUICK_TEMPLATES.map((template) => (
                <li key={template.label}>
                  <button
                    type="button"
                    onClick={() => update((f) => ({ ...f, wafDirectives: appendQuickTemplate(f.wafDirectives, template, HOST_TEMPLATE_ID_OFFSET) }))}
                    className="rounded-lg border border-line2 bg-panel2 px-2.5 py-1 text-xs transition-colors hover:bg-raise"
                  >
                    Add: {template.label}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

function WafCard() {
  const { form, data } = useEditor();
  const eventsHref = data.canReadWaf && data.host ? hostEventsHref(data.host.domains) : null;
  return (
    <EditorCard
      id="waf"
      title="Web application firewall"
      actions={
        <span className="flex flex-wrap gap-3 text-[13px]">
          {eventsHref && (
            <Link href={eventsHref} className="text-brand underline-offset-4 hover:underline">
              Security events for this host
            </Link>
          )}
          {data.canReadWaf && (
            <Link href="/waf" className="text-brand underline-offset-4 hover:underline">
              WAF settings
            </Link>
          )}
        </span>
      }
    >
      <WafModePicker />
      {form.waf.mode !== "off" && <WafAdvanced />}
    </EditorCard>
  );
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

/** Where an exclusion applies: every request, a path, a variable. */
function exclusionWhere(exclusion: Pick<EditorWafExclusion, "path" | "pathMatch" | "variable">): string {
  const parts = [
    exclusion.path ? `${exclusion.pathMatch === "prefix" ? "Paths under" : "Path"} ${exclusion.path}` : null,
    exclusion.variable ? `${exclusion.path ? "variable" : "Variable"} ${exclusion.variable}` : null,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : "Every request";
}

/**
 * A new host's excluded rules (a copy brings its source's): a list of rule
 * ids saved with the host, since exclusion records need the host to exist.
 */
function NewHostExclusions() {
  const { form, update, data, touch } = useEditor();
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = () => {
    const id = Number(draft.trim());
    if (!Number.isInteger(id) || id < 1 || id > 2_147_483_647) {
      setError("Enter a rule id, such as 920540.");
      return;
    }
    setError(null);
    setDraft("");
    if (!form.wafExcluded.includes(id)) update((f) => ({ ...f, wafExcluded: [...f.wafExcluded, id].sort((x, y) => x - y) }));
  };
  return (
    <EditorCard id="f-waf-exclusions" title="Rule exclusions" was="wafExcluded" description="Rules skipped on every request to this host. Exclusions for one path or variable can be added once the host exists.">
      {form.wafExcluded.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
          {form.wafExcluded.map((ruleId) => (
            <li key={ruleId} className="flex items-center gap-2 text-[13px]">
              <span className="num rounded bg-raise px-1.5 text-xs leading-[18px] text-muted-foreground">{ruleId}</span>
              <span className="min-w-0 flex-1 truncate">{data.wafRuleMessages[ruleId] ?? "Core Rule Set rule"}</span>
              <RemoveButton label={`Remove exclusion of rule ${ruleId}`} onClick={() => update((f) => ({ ...f, wafExcluded: f.wafExcluded.filter((id) => id !== ruleId) }))} />
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="f-waf-exclude" className="sr-only">
          Rule id to exclude
        </label>
        <Input
          id="f-waf-exclude"
          value={draft}
          inputMode="numeric"
          placeholder="Rule id, e.g. 920540"
          aria-invalid={error ? true : undefined}
          className="num h-8 w-[200px]"
          onChange={(event) => setDraft(event.target.value)}
          onBlur={() => touch("f-waf-exclude")}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
        />
        <button type="button" onClick={add} className="h-8 rounded-lg border border-line2 bg-panel2 px-3 text-[13px] transition-colors hover:bg-raise">
          Exclude rule
        </button>
      </div>
      {error && <p className="m-0 text-xs text-bad">{error}</p>}
    </EditorCard>
  );
}

/**
 * The host's rule exclusions, managed in place: each with where it applies,
 * changed or removed right here (saved at once, like on the WAF settings
 * page), and the rules that matched this host lately, each one click away
 * from an exclusion narrowed to this host.
 */
function ExclusionsCard() {
  const { data } = useEditor();
  const router = useRouter();
  const host = data.host!;
  const canWrite = Boolean(data.canWriteWaf);
  const [dialog, setDialog] = useState<{ key: number; initial: WafExclusionDraft; editing?: WafExclusionEditing } | null>(null);
  const [removing, setRemoving] = useState<EditorWafExclusion | null>(null);
  const [pending, startTransition] = useTransition();
  const messageOf = (ruleId: number) => data.wafRuleMessages[ruleId] ?? data.wafRecentRules?.find((rule) => rule.ruleId === ruleId)?.message ?? null;
  const wholeHostRules = new Set(data.wafExclusions.filter((exclusion) => exclusion.wholeHost).map((exclusion) => exclusion.ruleId));
  const recent = (data.wafRecentRules ?? []).filter((rule) => !wholeHostRules.has(rule.ruleId)).slice(0, 6);
  const ruleOptions: WafRuleOption[] = data.wafRecentRules ?? [];
  const reasonFor = (ruleId: number) => `False positive on ${host.domains[0] ?? host.name}${messageOf(ruleId) ? ` (${messageOf(ruleId)})` : ""}`.slice(0, 500);

  const openAdd = (ruleId?: number) =>
    setDialog((current) => ({
      key: (current?.key ?? 0) + 1,
      initial: { ruleId: ruleId ? String(ruleId) : "", scope: String(host.id), path: "", pathMatch: "prefix", variable: "", reason: ruleId ? reasonFor(ruleId) : "" },
    }));
  const openEdit = (exclusion: EditorWafExclusion) =>
    setDialog((current) => ({
      key: (current?.key ?? 0) + 1,
      initial: {
        ruleId: String(exclusion.ruleId),
        scope: String(host.id),
        path: exclusion.path ?? "",
        pathMatch: exclusion.pathMatch ?? "prefix",
        variable: exclusion.variable ?? "",
        reason: exclusion.reason,
      },
      editing: { id: exclusion.id, ruleId: exclusion.ruleId, message: messageOf(exclusion.ruleId), scopeLabel: host.name },
    }));

  function remove(exclusion: EditorWafExclusion) {
    startTransition(async () => {
      const result = await deleteWafExclusionAction(exclusion.id);
      if (result.ok) toast.success(`Rule ${exclusion.ruleId} is checked again on ${host.name}`);
      else toast.error(result.error);
      setRemoving(null);
      router.refresh();
    });
  }

  return (
    <EditorCard
      id="f-waf-exclusions"
      title="Rule exclusions"
      description="Rules this host skips. Changes here apply right away."
      flush
      actions={
        canWrite ? (
          <Button type="button" variant="secondary" size="sm" onClick={() => openAdd()}>
            <Plus aria-hidden="true" />
            Add exclusion
          </Button>
        ) : undefined
      }
    >
      {data.wafExclusions.length === 0 ? (
        <p className="m-0 px-5 py-3.5 text-[13px] text-muted-foreground">No rule is excluded on this host.</p>
      ) : (
        <ul className="m-0 list-none p-0" aria-label="Excluded rules">
          {data.wafExclusions.map((exclusion) => (
            <li key={exclusion.id} className="flex flex-wrap items-start gap-x-4 gap-y-1 border-b border-line px-5 py-3 last:border-b-0">
              <div className="flex min-w-0 flex-[1_1_360px] flex-col gap-0.5">
                <span className="text-[13px]">
                  <span className="num text-muted-foreground">{exclusion.ruleId}</span> {messageOf(exclusion.ruleId) ?? "Core Rule Set rule"}
                </span>
                <span className="num text-xs text-muted-foreground [overflow-wrap:anywhere]">{exclusionWhere(exclusion)}</span>
                {exclusion.reason && <span className="text-xs text-soft [overflow-wrap:anywhere]">{exclusion.reason}</span>}
              </div>
              <span className="pt-0.5 text-xs text-soft">{[exclusion.createdBy, formatDate(exclusion.createdAt)].filter(Boolean).join(" · ")}</span>
              {canWrite && (
                <span className="flex gap-1">
                  <Button type="button" variant="ghost" size="sm" onClick={() => openEdit(exclusion)} aria-label={`Change the exclusion of rule ${exclusion.ruleId}`}>
                    Change
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setRemoving(exclusion)} aria-label={`Remove the exclusion of rule ${exclusion.ruleId}`}>
                    Remove
                  </Button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      {recent.length > 0 && (
        <div className="border-t border-line px-5 pb-4 pt-3">
          <h4 className="m-0 mb-2 text-[13px] font-semibold text-muted-foreground">Matched this host in the last 7 days</h4>
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
            {recent.map((rule) => (
              <li key={rule.ruleId} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                <span className="min-w-0 flex-[1_1_320px] truncate">
                  <span className="num text-muted-foreground">{rule.ruleId}</span> {rule.message ?? "Core Rule Set rule"}
                </span>
                <span className="num text-xs text-soft">
                  {rule.events} match{rule.events === 1 ? "" : "es"}
                  {rule.blocked > 0 ? `, ${rule.blocked} blocked` : ""}
                  {rule.topPath ? ` · mostly ${rule.topPath}` : ""}
                </span>
                {canWrite && (
                  <Button type="button" variant="ghost" size="sm" onClick={() => openAdd(rule.ruleId)} aria-label={`Exclude rule ${rule.ruleId}`}>
                    Exclude…
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {dialog && (
        <WafExclusionDialog
          key={dialog.key}
          open
          onOpenChange={(open) => !open && setDialog(null)}
          hosts={[]}
          initial={dialog.initial}
          editing={dialog.editing}
          fixedScope={host.name}
          rules={ruleOptions}
          description="Skip one rule on this host: on every request, or only on a path or variable."
          onCreated={() => router.refresh()}
        />
      )}
      <AppDialog
        open={removing !== null}
        onClose={() => !pending && setRemoving(null)}
        title={removing ? `Remove the exclusion of rule ${removing.ruleId}?` : ""}
        submitLabel="Remove"
        isSubmitting={pending}
        onSubmit={() => removing && remove(removing)}
      >
        <p className="m-0 text-[13px] text-muted-foreground">
          {removing ? `The rule checks ${exclusionWhere(removing).toLowerCase()} on ${host.name} again, right away.` : ""}
        </p>
      </AppDialog>
    </EditorCard>
  );
}

const UNIT_LABELS = { s: "seconds", m: "minutes", h: "hours" } as const;

function RateLimitRuleEditor({ rule, index, onChange, onRemove }: { rule: RateLimitRuleRow; index: number; onChange: (rule: RateLimitRuleRow) => void; onRemove: () => void }) {
  const eventsProps = useFieldProps(`f-rl-${index}-events`);
  const windowProps = useFieldProps(`f-rl-${index}-window`);
  const title = `Rule ${index + 1}`;
  return (
    <li className="flex flex-col gap-3 border-t border-line px-5 py-3.5" aria-label={title} data-testid="rate-limit-rule">
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(200px,100%),1fr))] items-start gap-x-4 gap-y-3">
        <TextField id={`f-rl-${index}-path`} label="Path" value={rule.path} onChange={(path) => onChange({ ...rule, path })} placeholder="Every path, or /login, /api/*" mono />
        <SelectField id={`f-rl-${index}-key`} label="Counted by" value={rule.by} onChange={(value) => onChange({ ...rule, by: value as RateLimitKey })}>
          {RATE_LIMIT_KEYS.map((key) => (
            <option key={key} value={key}>
              {RATE_LIMIT_KEY_LABELS[key]}
            </option>
          ))}
        </SelectField>
        {rule.by === "header" && (
          <TextField id={`f-rl-${index}-header`} label="Header" value={rule.header} onChange={(header) => onChange({ ...rule, header })} placeholder="X-Api-Key" mono />
        )}
      </div>
      <div className="flex flex-wrap items-end gap-x-3 gap-y-2">
        <div className="flex flex-col gap-1.5">
          <label htmlFor={`f-rl-${index}-events`} className="text-[13px] font-medium">
            Requests
          </label>
          <Input {...eventsProps} value={rule.events} inputMode="numeric" className="num w-24" onChange={(event) => onChange({ ...rule, events: event.target.value })} />
        </div>
        <span className="pb-2 text-[13px] text-muted-foreground">per</span>
        <div className="flex flex-col gap-1.5">
          <label htmlFor={`f-rl-${index}-window`} className="text-[13px] font-medium">
            Window
          </label>
          <span className="flex gap-2">
            <Input {...windowProps} value={rule.windowValue} inputMode="numeric" className="num w-20" onChange={(event) => onChange({ ...rule, windowValue: event.target.value })} />
            <NativeSelect aria-label={`${title} window unit`} value={rule.windowUnit} className="w-[110px]" onChange={(event) => onChange({ ...rule, windowUnit: event.target.value as RateLimitRuleRow["windowUnit"] })}>
              {(Object.keys(UNIT_LABELS) as RateLimitRuleRow["windowUnit"][]).map((unit) => (
                <option key={unit} value={unit}>
                  {UNIT_LABELS[unit]}
                </option>
              ))}
            </NativeSelect>
          </span>
        </div>
        <span className="ml-auto">
          <RemoveButton label={`Remove rate limit rule ${index + 1}`} onClick={onRemove} />
        </span>
      </div>
      <FieldError id={`f-rl-${index}-events`} />
      <FieldError id={`f-rl-${index}-window`} />
      <div className="flex flex-wrap items-center gap-1" role="group" aria-label={`${title} methods`}>
        {RATE_LIMIT_METHODS.map((method) => {
          const active = rule.methods.includes(method);
          return (
            <button
              key={method}
              type="button"
              aria-pressed={active}
              onClick={() => onChange({ ...rule, methods: active ? rule.methods.filter((m) => m !== method) : [...rule.methods, method] })}
              className={cn(
                "num rounded-md border px-2 py-0.5 text-[11px] transition-colors",
                active ? "border-brand bg-brand-tint text-foreground" : "border-line2 text-muted-foreground hover:text-foreground"
              )}
            >
              {method}
            </button>
          );
        })}
        <span className="ml-1 text-xs text-soft">{rule.methods.length === 0 ? "Every method" : ""}</span>
      </div>
    </li>
  );
}

function RateLimitCard() {
  const { form, update, data } = useEditor();
  const rate = form.rateLimit;
  const mode = rate.enabled ? rate.mode : "off";
  const defaults = data.rateLimitDefaults;
  const globalRules = defaults?.enabled ? defaults.rules : 0;
  // What is easy to get wrong: "Off" still applies the global defaults, and an override without rules limits nothing.
  const note =
    mode === "off"
      ? globalRules > 0
        ? `The ${globalRules === 1 ? "global rule applies" : `${globalRules} global rules apply`}; this host adds none.`
        : "No global rules are set, so nothing is limited."
      : mode === "override"
        ? "Only these rules apply; with none, nothing is limited."
        : undefined;
  const userKeyWithoutSignIn = form.signIn !== "ingressi" && rate.rules.some((rule) => rule.by === "forward_auth_user");
  const setRules = (recipe: (rules: RateLimitRuleRow[]) => RateLimitRuleRow[]) => update((f) => ({ ...f, rateLimit: { ...f.rateLimit, rules: recipe(f.rateLimit.rules) } }));
  return (
    <EditorCard id="rate-limiting" title="Rate limiting" was="rateLimit" description={note} flush={mode !== "off"}>
      <div className={cn(mode !== "off" && "px-5 pb-4 pt-3")}>
        <SegmentedField
          id="f-rl-mode"
          label="Limits"
          value={mode}
          onChange={(value) =>
            update((f) => ({
              ...f,
              rateLimit: value === "off" ? { ...f.rateLimit, enabled: false } : { ...f.rateLimit, enabled: true, mode: value },
            }))
          }
          options={[
            { value: "off", label: "Global limits" },
            { value: "merge", label: "Global and this host's" },
            { value: "override", label: "This host's only" },
          ]}
        />
      </div>
      {mode !== "off" && (
        <>
          {rate.rules.length > 0 && (
            <ol className="m-0 list-none p-0">
              {rate.rules.map((rule, index) => (
                <RateLimitRuleEditor
                  key={rule.key}
                  rule={rule}
                  index={index}
                  onChange={(next) => setRules((rules) => rules.map((current) => (current.key === rule.key ? next : current)))}
                  onRemove={() => setRules((rules) => rules.filter((current) => current.key !== rule.key))}
                />
              ))}
            </ol>
          )}
          <div className="flex flex-wrap items-center gap-x-3.5 gap-y-2 border-t border-line px-5 pb-4 pt-3">
            <AddButton onClick={() => setRules((rules) => [...rules, rateLimitRow()])} disabled={rate.rules.length >= RATE_LIMIT_LIMITS.maxRules}>
              Add rule
            </AddButton>
            {userKeyWithoutSignIn && (
              <span className="text-xs text-warn">Counting by signed-in user needs the built-in sign-in on this host; until then it counts by client IP.</span>
            )}
          </div>
        </>
      )}
    </EditorCard>
  );
}

export function SecuritySection() {
  const { data } = useEditor();
  return (
    <>
      <WafCard />
      {data.host ? <ExclusionsCard /> : <NewHostExclusions />}
      <RateLimitCard />
      <GeoBlockCard />
    </>
  );
}
