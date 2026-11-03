"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowDown, ArrowUp, Check, Copy, KeyRound, Pencil, Plus, Undo2, X } from "lucide-react";
import { toast } from "sonner";
import type { AccessList, AccessListUsage } from "@/lib/models/access-lists";
import type { ListStats } from "@/lib/access-list-stats";
import {
  ACCESS_LIST_RULE_KINDS,
  continentName,
  countryName,
  normalizeMemberInput,
  ruleKindLabel,
  ruleValuesText,
  type AccessListRuleAction,
  type AccessListRuleKind,
} from "@/lib/access-list-rules";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionCard } from "@/components/ui/SectionCard";
import { Banner } from "@/components/ui/Banner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  draftFromList,
  draftRuleError,
  draftToSave,
  generatePassword,
  isDraftDirty,
  moveRule,
  newDraftMember,
  newDraftRule,
  parseDraftValues,
  type AccessListDraft,
  type DraftMember,
  type DraftRule,
} from "./access-list-draft";
import { describeAccessList, listWarning } from "./access-list-view";
import { ACCESS_LISTS_HREF } from "./AccessListsHeader";
import { KIND_OPTIONS, fmtDateTime, fmtDay, fromLocalInput, toLocalInput } from "./rule-format";
import { DeleteAccessListDialog } from "./AccessListDialogs";
import { saveAccessListAction } from "./actions";

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

function ruleLabel(rule: DraftRule): string {
  const values = parseDraftValues(rule.kind, rule.valuesText).values;
  return `${rule.action === "allow" ? "Allow" : "Deny"} ${ruleKindLabel(rule.kind, values).toLowerCase()} ${values.join(", ") || "(empty)"}`;
}

function ActionLabel({ action }: { action: AccessListRuleAction }) {
  const allow = action === "allow";
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] font-semibold", allow ? "text-ok" : "text-bad")}>
      <span className={cn("h-2 w-2 rounded-full", allow ? "bg-ok" : "bg-bad")} aria-hidden="true" />
      {allow ? "Allow" : "Deny"}
    </span>
  );
}

function RuleEditFields({ rule, onChange }: { rule: DraftRule; onChange: (rule: DraftRule) => void }) {
  const parsed = parseDraftValues(rule.kind, rule.valuesText);
  const option = KIND_OPTIONS[rule.kind];
  const idBase = `rule-${rule.key}`;
  return (
    <div className="grid gap-3 pt-1">
      <div className="grid gap-3 sm:grid-cols-[140px_minmax(0,1fr)]">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idBase}-action`} className="text-[13px]">Action</Label>
          <Select value={rule.action} onValueChange={(value) => onChange({ ...rule, action: value as AccessListRuleAction })}>
            <SelectTrigger id={`${idBase}-action`} className="h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="allow">Allow</SelectItem>
              <SelectItem value="deny">Deny</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idBase}-kind`} className="text-[13px]">Match by</Label>
          <Select value={rule.kind} onValueChange={(value) => onChange({ ...rule, kind: value as AccessListRuleKind })}>
            <SelectTrigger id={`${idBase}-kind`} className="h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ACCESS_LIST_RULE_KINDS.map((kind) => (
                <SelectItem key={kind} value={kind}>{KIND_OPTIONS[kind].label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`${idBase}-values`} className="text-[13px]">Values</Label>
        <Input
          id={`${idBase}-values`}
          className="h-9 font-mono text-[13px]"
          value={rule.valuesText}
          placeholder={option.placeholder}
          autoFocus={rule.isNew}
          onChange={(event) => onChange({ ...rule, valuesText: event.target.value })}
          aria-describedby={`${idBase}-values-hint`}
          aria-invalid={parsed.errors.length > 0}
        />
        <span id={`${idBase}-values-hint`} className={cn("text-xs", parsed.errors.length > 0 ? "text-destructive" : "text-muted-foreground")}>
          {parsed.errors.length > 0 ? parsed.errors[0] : option.hint}
        </span>
        {(rule.kind === "country" || rule.kind === "continent") && parsed.values.length > 0 && (
          <span className="flex flex-wrap gap-1.5">
            {parsed.values.map((value) => (
              <span key={value} className="rounded-md bg-muted px-1.5 py-0.5 text-xs">
                <span className="font-mono">{value}</span> {rule.kind === "country" ? countryName(value) : continentName(value)}
              </span>
            ))}
          </span>
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_220px]">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idBase}-note`} className="text-[13px]">
            Note <span className="font-normal text-muted-foreground">(optional)</span>
          </Label>
          <Input
            id={`${idBase}-note`}
            className="h-9 text-[13px]"
            value={rule.note}
            maxLength={500}
            onChange={(event) => onChange({ ...rule, note: event.target.value })}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idBase}-expires`} className="text-[13px]">
            Expires <span className="font-normal text-muted-foreground">(optional)</span>
          </Label>
          <Input
            id={`${idBase}-expires`}
            type="datetime-local"
            className="h-9 text-[13px]"
            value={toLocalInput(rule.expiresAt)}
            onChange={(event) => onChange({ ...rule, expiresAt: fromLocalInput(event.target.value) })}
          />
        </div>
      </div>
    </div>
  );
}

function RuleRow({
  rule,
  index,
  count,
  editing,
  canWrite,
  onEdit,
  onDone,
  onChange,
  onMove,
  onRemove,
}: {
  rule: DraftRule;
  index: number;
  count: number;
  editing: boolean;
  canWrite: boolean;
  onEdit: () => void;
  onDone: () => void;
  onChange: (rule: DraftRule) => void;
  onMove: (delta: -1 | 1) => void;
  onRemove: () => void;
}) {
  const label = ruleLabel(rule);
  const values = parseDraftValues(rule.kind, rule.valuesText).values;
  const expired = rule.expiresAt !== "" && new Date(rule.expiresAt).getTime() <= Date.now();
  const note = [
    rule.note,
    rule.expiresAt ? (expired ? "Expired" : `Expires ${fmtDateTime(rule.expiresAt)}`) : "",
    rule.isNew ? "Not saved yet" : "",
  ].filter(Boolean).join(" · ");
  return (
    <li
      className={cn(
        "grid grid-cols-[22px_64px_minmax(0,1fr)] items-center gap-x-2.5 gap-y-1 border-b border-line py-2.5 pl-3 pr-2 sm:grid-cols-[22px_64px_minmax(0,1fr)_auto]",
        rule.isNew && "bg-brand-tint"
      )}
      data-testid="access-list-rule"
    >
      <span className="num text-xs text-muted-foreground">{index + 1}</span>
      <ActionLabel action={rule.action} />
      <span className="flex min-w-0 flex-col gap-px">
        <span className="flex min-w-0 items-baseline gap-2">
          <span className="flex-none text-xs text-muted-foreground">{ruleKindLabel(rule.kind, values)}</span>
          <span className={cn("min-w-0 font-mono text-[13px] [overflow-wrap:anywhere]", values.length === 0 && "text-muted-foreground")}>
            {values.length > 0 ? ruleValuesText(rule.kind, values) : "No values yet"}
          </span>
        </span>
        {note && <span className={cn("text-xs", expired ? "text-warn" : "text-muted-foreground")}>{note}</span>}
      </span>
      {canWrite && (
        <span className="col-start-3 flex justify-end sm:col-start-auto">
          <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`${editing ? "Done editing" : "Edit"}: ${label}`} onClick={editing ? onDone : onEdit}>
            {editing ? <Check className="h-3.5 w-3.5" /> : <Pencil className="h-3.5 w-3.5" />}
          </Button>
          <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`Move up: ${label}`} disabled={index === 0} onClick={() => onMove(-1)}>
            <ArrowUp className="h-3.5 w-3.5" />
          </Button>
          <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`Move down: ${label}`} disabled={index === count - 1} onClick={() => onMove(1)}>
            <ArrowDown className="h-3.5 w-3.5" />
          </Button>
          <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`Remove rule: ${label}`} onClick={onRemove}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </span>
      )}
      {editing && (
        <div className="col-span-full border-t border-line pt-2">
          <RuleEditFields rule={rule} onChange={onChange} />
        </div>
      )}
    </li>
  );
}

function MemberRow({
  member,
  canWrite,
  onChange,
  onRemove,
}: {
  member: DraftMember;
  canWrite: boolean;
  onChange: (member: DraftMember) => void;
  onRemove: () => void;
}) {
  const shownPassword = member.id === null ? member.password : member.newPassword;
  const status = member.removed
    ? "Removed when you save"
    : member.id === null
      ? "Not saved yet"
      : member.newPassword
        ? "New password when you save"
        : member.createdAt
          ? `Added ${fmtDay(member.createdAt)}`
          : "";
  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success("Password copied");
    } catch {
      toast.error("Could not copy the password");
    }
  };
  return (
    <li className="flex flex-wrap items-center gap-2.5 border-b border-line py-2 pl-3 pr-2 last:border-b-0" data-testid="access-list-member">
      <span className={cn("min-w-0 flex-1 font-mono text-[13px]", member.removed && "text-muted-foreground line-through")}>{member.username}</span>
      {shownPassword && !member.removed && (
        <span className="flex items-center gap-1">
          <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{shownPassword}</code>
          <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`Copy the password of ${member.username}`} onClick={() => copy(shownPassword)}>
            <Copy className="h-3.5 w-3.5" />
          </Button>
        </span>
      )}
      <span className="text-xs text-muted-foreground">{status}</span>
      {canWrite && (
        <span className="flex">
          {member.id !== null && !member.removed && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              aria-label={`New password for ${member.username}`}
              title="New password"
              onClick={() => onChange({ ...member, newPassword: generatePassword() })}
            >
              <KeyRound className="h-3.5 w-3.5" />
            </Button>
          )}
          {member.removed ? (
            <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`Keep ${member.username}`} onClick={() => onChange({ ...member, removed: false })}>
              <Undo2 className="h-3.5 w-3.5" />
            </Button>
          ) : (
            <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label={`Remove ${member.username}`} onClick={onRemove}>
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </span>
      )}
    </li>
  );
}

/** The access list page: its rules in order, what everyone else gets, basic-auth users, the denied response and where it is used. */
export function AccessListEditor({
  list,
  usage,
  listStats,
  statsAvailable,
  canWrite,
  trustedProxiesConfigured,
}: {
  list: AccessList;
  usage: AccessListUsage[];
  listStats: ListStats | null;
  statsAvailable: boolean;
  canWrite: boolean;
  trustedProxiesConfigured: boolean;
}) {
  const router = useRouter();
  // The version the draft started from: the server's, or the one a save here answered with.
  const [base, setBase] = useState<AccessList>(list);
  const saved = useMemo(() => draftFromList(base), [base]);
  const [draft, setDraft] = useState<AccessListDraft>(saved);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [newMember, setNewMember] = useState({ username: "", password: "" });
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const resetOnRefresh = useRef(false);
  const leaving = useRef(false);

  const dirty = isDraftDirty(draft, saved);

  // A newer version from the server replaces the base; the draft follows when it has no changes of its own.
  useEffect(() => {
    if (list.updatedAt <= base.updatedAt) return;
    setBase(list);
    if (resetOnRefresh.current || !isDraftDirty(draft, saved)) {
      resetOnRefresh.current = false;
      setDraft(draftFromList(list));
      setEditingKey(null);
    }
    // Only a new server version matters here, not every draft change.
  }, [list]);

  // Leaving with unsaved changes asks first: a reload or another site, and links inside the dashboard.
  useEffect(() => {
    if (!dirty) return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      if (!leaving.current) event.preventDefault();
    };
    const onClick = (event: MouseEvent) => {
      if (leaving.current || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
      const anchor = (event.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
      if (!anchor || anchor.target === "_blank") return;
      const url = new URL(anchor.href, window.location.href);
      if (url.origin !== window.location.origin || url.pathname === window.location.pathname) return;
      if (!window.confirm("Leave without saving your changes to this list?")) {
        event.preventDefault();
        event.stopPropagation();
      }
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    document.addEventListener("click", onClick, true);
    return () => {
      window.removeEventListener("beforeunload", onBeforeUnload);
      document.removeEventListener("click", onClick, true);
    };
  }, [dirty]);

  const activeMembers = draft.members.filter((member) => !member.removed);
  const summaryInput = {
    rules: draft.rules.map((rule) => ({ action: rule.action, kind: rule.kind, values: parseDraftValues(rule.kind, rule.valuesText).values, expiresAt: rule.expiresAt || null })),
    defaultAction: draft.defaultAction,
    memberCount: activeMembers.length,
  };
  const summary = describeAccessList(summaryInput);
  const warning = listWarning(summaryInput);
  const hostCount = usage.length;
  const showNewPasswords = draft.members.some((member) => !member.removed && (member.id === null ? member.password : member.newPassword));

  const setRules = (rules: DraftRule[]) => setDraft((current) => ({ ...current, rules }));
  const setMembers = (members: DraftMember[]) => setDraft((current) => ({ ...current, members }));

  const finishEditing = (rule: DraftRule) => {
    const error = draftRuleError(rule);
    if (error) {
      toast.error(error);
      return;
    }
    setEditingKey(null);
  };

  const addRule = () => {
    // A list that denies everyone else is extended with allows, one that lets everyone in with denies.
    const rule = newDraftRule(draft.defaultAction === "deny" ? "allow" : "deny", "ip");
    setRules([...draft.rules, rule]);
    setEditingKey(rule.key);
  };

  const addMember = () => {
    try {
      const member = normalizeMemberInput({ username: newMember.username, password: newMember.password });
      if (draft.members.some((existing) => existing.username === member.username && !existing.removed)) {
        toast.error(`The list already has a user named ${member.username}`);
        return;
      }
      setMembers([...draft.members, newDraftMember(member.username, member.password)]);
      setNewMember({ username: "", password: "" });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Check the username and password");
    }
  };

  const validate = (): string | null => {
    if (!draft.name.trim()) return "Give the list a name";
    for (const rule of draft.rules) {
      const error = draftRuleError(rule);
      if (error) return `Rule ${draft.rules.indexOf(rule) + 1}: ${error}`;
    }
    const status = Number(draft.denyStatus.trim());
    if (!draft.denyRedirectUrl.trim() && (!Number.isInteger(status) || status < 400 || status > 599)) {
      return "The status of a denied request must be from 400 to 599";
    }
    return null;
  };

  const save = async () => {
    const problem = validate();
    if (problem) {
      toast.error(problem);
      return;
    }
    setSaving(true);
    try {
      const result = await saveAccessListAction(base.id, draftToSave(draft, { system: false, expectedUpdatedAt: base.updatedAt }));
      if (!result.ok) {
        toast.error(result.error);
        if (result.saved) {
          resetOnRefresh.current = true;
          router.refresh();
        }
        return;
      }
      setBase(result.value);
      setDraft(draftFromList(result.value));
      setEditingKey(null);
      toast.success(`Saved ${result.value.name}`);
      router.refresh();
    } finally {
      setSaving(false);
    }
  };

  const discard = () => {
    setDraft(saved);
    setEditingKey(null);
    setNewMember({ username: "", password: "" });
  };

  const name = draft.name.trim() || base.name;

  return (
    <div className={cn("flex min-w-0 flex-col gap-4", canWrite && "pb-28")}>
      <PageHeader
        className="mb-0"
        breadcrumb={["Traffic", { label: "Access lists", href: ACCESS_LISTS_HREF }, name]}
        title={<span className="[overflow-wrap:anywhere]">{name}</span>}
        description={<span data-testid="access-list-summary">{summary}</span>}
        actions={
          canWrite && (
            <Button type="button" variant="danger" onClick={() => setConfirmDelete(true)}>
              Delete list
            </Button>
          )
        }
      />

      {!canWrite && (
        <Banner tone="neutral" title="Changing access lists needs the access_lists:write permission." />
      )}

      <div className="grid min-w-0 items-start gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="flex min-w-0 flex-col gap-4">
          <SectionCard
            id="rules"
            title="Rules"
            count={draft.rules.length || null}
            description="Checked from the top. The first rule that matches decides."
            descriptionPlacement="below"
            divided={false}
            actions={
              canWrite && (
                <Button type="button" variant="outline" size="sm" onClick={addRule}>
                  <Plus /> Add rule
                </Button>
              )
            }
          >
            <div className="flex flex-col gap-3 px-[18px] pb-[18px]">
              <div className="overflow-hidden rounded-[10px] border border-line">
                {draft.rules.length > 0 && (
                  <ol aria-label="Rules">
                    {draft.rules.map((rule, index) => (
                      <RuleRow
                        key={rule.key}
                        rule={rule}
                        index={index}
                        count={draft.rules.length}
                        editing={editingKey === rule.key}
                        canWrite={canWrite}
                        onEdit={() => setEditingKey(rule.key)}
                        onDone={() => finishEditing(rule)}
                        onChange={(next) => setRules(draft.rules.map((item) => (item.key === rule.key ? next : item)))}
                        onMove={(delta) => setRules(moveRule(draft.rules, index, delta))}
                        onRemove={() => {
                          setRules(draft.rules.filter((item) => item.key !== rule.key));
                          if (editingKey === rule.key) setEditingKey(null);
                        }}
                      />
                    ))}
                  </ol>
                )}
                <div className="grid grid-cols-[22px_minmax(0,1fr)_auto] items-center gap-2.5 bg-panel2 py-2.5 pl-3 pr-2" data-testid="access-list-everyone-else">
                  <span className="text-xs text-muted-foreground" aria-hidden="true">∗</span>
                  {canWrite ? (
                    <Label htmlFor="access-list-everyone-else" className="text-[13px] font-semibold">
                      Everyone else
                    </Label>
                  ) : (
                    <span className="text-[13px] font-semibold">Everyone else</span>
                  )}
                  {canWrite ? (
                    <Select value={draft.defaultAction} onValueChange={(value) => setDraft({ ...draft, defaultAction: value === "deny" ? "deny" : "allow" })}>
                      <SelectTrigger id="access-list-everyone-else" className="h-8 w-[120px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="allow">Allow</SelectItem>
                        <SelectItem value="deny">Deny</SelectItem>
                      </SelectContent>
                    </Select>
                  ) : (
                    <span className="pr-2">
                      <ActionLabel action={draft.defaultAction} />
                    </span>
                  )}
                </div>
              </div>
              {warning === "denies_everyone" && (
                <Banner tone="warn" title={hostCount > 0 ? `Every request to its ${plural(hostCount, "host")} is denied.` : "Every request is denied."}>
                  Add an allow rule, or set Everyone else to Allow.
                </Banner>
              )}
              {warning === "allow_rules_unused" && (
                <Banner tone="warn" title="The allow rules change nothing.">
                  Everyone else is allowed too. Set Everyone else to Deny to let in only what they allow.
                </Banner>
              )}
            </div>
          </SectionCard>

          <SectionCard
            id="users"
            title="Basic auth"
            count={activeMembers.length || null}
            description={
              activeMembers.length > 0
                ? "Visitors the rules let in then sign in as one of these users."
                : "Add users to make visitors sign in after the rules let them in."
            }
            descriptionPlacement="below"
            divided={false}
          >
            <div className="flex flex-col gap-3 px-[18px] pb-[18px]">
              {draft.members.length > 0 && (
                <ul aria-label="Users" className="flex flex-col overflow-hidden rounded-[10px] border border-line">
                  {draft.members.map((member) => (
                    <MemberRow
                      key={member.key}
                      member={member}
                      canWrite={canWrite}
                      onChange={(next) => setMembers(draft.members.map((item) => (item.key === member.key ? next : item)))}
                      onRemove={() =>
                        setMembers(
                          member.id === null
                            ? draft.members.filter((item) => item.key !== member.key)
                            : draft.members.map((item) => (item.key === member.key ? { ...item, removed: true } : item))
                        )
                      }
                    />
                  ))}
                </ul>
              )}
              {showNewPasswords && (
                <p className="m-0 text-xs text-warn">Copy new passwords before you save: they are not shown again.</p>
              )}
              {canWrite && (
                <div className="grid grid-cols-1 items-end gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto_auto]">
                  <div className="flex min-w-0 flex-col gap-1.5">
                    <Label htmlFor="access-list-member-username" className="text-[13px]">Username</Label>
                    <Input
                      id="access-list-member-username"
                      className="h-9 font-mono text-[13px]"
                      value={newMember.username}
                      autoComplete="off"
                      onChange={(event) => setNewMember({ ...newMember, username: event.target.value })}
                    />
                  </div>
                  <div className="flex min-w-0 flex-col gap-1.5">
                    <Label htmlFor="access-list-member-password" className="text-[13px]">Password</Label>
                    <Input
                      id="access-list-member-password"
                      className="h-9 font-mono text-[13px]"
                      value={newMember.password}
                      autoComplete="new-password"
                      onChange={(event) => setNewMember({ ...newMember, password: event.target.value })}
                    />
                  </div>
                  <Button type="button" variant="outline" className="h-9" onClick={() => setNewMember({ ...newMember, password: generatePassword() })}>
                    Generate
                  </Button>
                  <Button type="button" variant="outline" className="h-9" disabled={!newMember.username.trim() || !newMember.password} onClick={addMember}>
                    Add user
                  </Button>
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard id="denied" title="Denied requests" divided={false}>
            <div className="flex flex-col gap-3 px-[18px] pb-[18px]">
              <div className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 gap-y-2.5">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="access-list-status" className="text-[13px]">Status</Label>
                  <Input
                    id="access-list-status"
                    inputMode="numeric"
                    className="h-9 font-mono text-[13px]"
                    value={draft.denyStatus}
                    disabled={!canWrite || draft.denyRedirectUrl.trim() !== ""}
                    onChange={(event) => setDraft({ ...draft, denyStatus: event.target.value })}
                  />
                </div>
                <div className="flex min-w-0 flex-col gap-1.5">
                  <Label htmlFor="access-list-body" className="text-[13px]">Body</Label>
                  <Input
                    id="access-list-body"
                    className="h-9 text-[13px]"
                    value={draft.denyBody}
                    placeholder="Forbidden"
                    maxLength={4096}
                    disabled={!canWrite || draft.denyRedirectUrl.trim() !== ""}
                    onChange={(event) => setDraft({ ...draft, denyBody: event.target.value })}
                  />
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="access-list-redirect" className="text-[13px]">
                  Or redirect to <span className="font-normal text-muted-foreground">(optional)</span>
                </Label>
                <Input
                  id="access-list-redirect"
                  className="h-9 font-mono text-[13px]"
                  value={draft.denyRedirectUrl}
                  placeholder="https://example.com/not-available"
                  disabled={!canWrite}
                  onChange={(event) => setDraft({ ...draft, denyRedirectUrl: event.target.value })}
                />
              </div>
              <div className="flex items-start gap-3.5 pt-1">
                <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <Label htmlFor="access-list-skip-auth" className="text-[13px]">Skip Basic Auth for allowed addresses</Label>
                  <span className="text-xs text-muted-foreground">Clients that match an Allow address rule are not asked for a username and password. Everyone else still is.</span>
                </span>
                <Switch
                  id="access-list-skip-auth"
                  checked={draft.skipAuthForAllowed}
                  disabled={!canWrite}
                  onCheckedChange={(checked) => setDraft({ ...draft, skipAuthForAllowed: checked })}
                />
              </div>
              {(trustedProxiesConfigured || draft.failClosed) && (
                <div className="flex items-start gap-3.5 pt-1">
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <Label htmlFor="access-list-fail-closed" className="text-[13px]">Deny when the client address is unknown</Label>
                    <span className="text-xs text-muted-foreground">A trusted proxy sent no usable X-Forwarded-For. Off lets these requests through.</span>
                  </span>
                  <Switch
                    id="access-list-fail-closed"
                    checked={draft.failClosed}
                    disabled={!canWrite}
                    onCheckedChange={(checked) => setDraft({ ...draft, failClosed: checked })}
                  />
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard title="Name and description" divided={false}>
            <div className="grid grid-cols-[repeat(auto-fit,minmax(min(220px,100%),1fr))] gap-x-3.5 gap-y-2.5 px-[18px] pb-[18px]">
              <div className="flex min-w-0 flex-col gap-1.5">
                <Label htmlFor="access-list-name" className="text-[13px]">Name</Label>
                <Input
                  id="access-list-name"
                  className="h-9 text-[13px]"
                  value={draft.name}
                  maxLength={200}
                  disabled={!canWrite}
                  onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                />
              </div>
              <div className="flex min-w-0 flex-col gap-1.5">
                <Label htmlFor="access-list-description" className="text-[13px]">Description</Label>
                <Input
                  id="access-list-description"
                  className="h-9 text-[13px]"
                  value={draft.description}
                  maxLength={1000}
                  disabled={!canWrite}
                  onChange={(event) => setDraft({ ...draft, description: event.target.value })}
                />
              </div>
            </div>
          </SectionCard>
        </div>

        <SectionCard id="used-by" title="Used by" count={hostCount || null} description={statsAvailable && hostCount > 0 ? "Stopped in 24 h" : undefined}>
          {hostCount === 0 ? (
            <p className="m-0 px-[18px] py-4 text-[13px] text-muted-foreground">
              No host uses this list. Choose it in a proxy host&apos;s Access settings.
            </p>
          ) : (
            <ul aria-label="Hosts using this list" className="flex flex-col">
              {usage.map((host) => {
                const hostStats = listStats?.hosts[host.id];
                const domain = host.domains[0] ?? host.name;
                const failed = activeMembers.length > 0 ? hostStats?.failedSignIns ?? 0 : 0;
                return (
                  <li key={host.id} className="flex items-start gap-2.5 border-b border-line px-[18px] py-2.5 last:border-b-0">
                    <span className="flex min-w-0 flex-1 flex-col gap-px">
                      <Link href={`/proxy-hosts/${host.id}`} className="num text-[13px] text-foreground underline-offset-4 hover:underline [overflow-wrap:anywhere]">
                        {domain}
                      </Link>
                      {(host.name !== domain || host.domains.length > 1 || !host.enabled) && (
                        <span className="text-xs text-muted-foreground">
                          {[host.name !== domain ? host.name : "", host.domains.length > 1 ? `+${host.domains.length - 1} domains` : "", host.enabled ? "" : "Disabled"]
                            .filter(Boolean)
                            .join(" · ")}
                        </span>
                      )}
                    </span>
                    {statsAvailable && (
                      <span className="flex flex-col items-end">
                        <span className="num text-[13px]">{(hostStats?.stopped ?? 0).toLocaleString("en-US")}</span>
                        {failed > 0 && <span className="text-xs text-muted-foreground">{plural(failed, "failed sign-in")}</span>}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </SectionCard>
      </div>

      {canWrite && (
        <div className="fixed inset-x-3 bottom-[calc(68px_+_env(safe-area-inset-bottom))] z-30 md:bottom-4 md:left-[calc(15.5rem_+_max(2rem,_(100vw_-_15.5rem_-_1600px)_/_2_+_2rem))] md:right-[max(2rem,_calc((100vw_-_15.5rem_-_1600px)_/_2_+_2rem))]">
          <div
            data-testid="access-list-save-bar"
            className={cn("flex flex-wrap items-center gap-x-3.5 gap-y-2.5 rounded-2xl border bg-panel px-4 py-3 shadow-overlay", dirty ? "border-line2" : "border-line")}
          >
            <span className="flex min-w-0 flex-[1_1_220px] items-center gap-2.5" role="status">
              <span aria-hidden="true" className={cn("h-2 w-2 shrink-0 rounded-full", dirty ? "bg-brand" : "bg-ok")} />
              <span className="flex min-w-0 flex-col">
                <span className="font-semibold">{dirty ? "Unsaved changes" : "No unsaved changes"}</span>
                {dirty && hostCount > 0 && <span className="text-[13px] text-soft">Applies to {plural(hostCount, "host")}.</span>}
              </span>
            </span>
            <span className="flex gap-2">
              <Button type="button" variant="ghost" disabled={!dirty || saving} onClick={discard}>
                Discard
              </Button>
              <Button type="button" disabled={!dirty || saving} onClick={save}>
                {saving ? "Saving" : "Save list"}
              </Button>
            </span>
          </div>
        </div>
      )}

      <DeleteAccessListDialog
        list={confirmDelete ? { id: base.id, name: base.name } : null}
        hostCount={hostCount}
        onClose={() => setConfirmDelete(false)}
        onDeleted={() => {
          leaving.current = true;
          router.push(ACCESS_LISTS_HREF);
          router.refresh();
        }}
      />
    </div>
  );
}
