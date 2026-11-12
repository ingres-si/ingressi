"use client";

/**
 * The sectioned host editor: tabs for Routing, Security, Access,
 * Certificate, Headers and Advanced (each linkable as #routing …), the
 * settings of the chosen tab, and a bar at the bottom that counts unsaved
 * changes against the saved host and opens a review of exactly what will
 * change, the approval policy that applies and the impact, before the change
 * is saved or submitted.
 *
 * On a host's page (`workspace`) the same tab bar also holds the page's
 * Overview and History, so looking at a host and changing it happen on one
 * page: switching tabs never leaves it, unsaved changes survive the switch,
 * and the bar shows up only once something changed. /proxy-hosts/new uses it
 * on its own.
 */
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { CheckCircle2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { Banner } from "@/components/ui/Banner";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/PageHeader";
import { Switch } from "@/components/ui/switch";
import { policiesCovering } from "@/ee/approvals/match";
import { previewProxyHostEditorAction, saveProxyHostEditorAction } from "@/app/(dashboard)/proxy-hosts/editor-actions";
import { changeGroups, formChanges, isSectionId, SECTION_LABELS, SECTIONS, type ChangeLookup, type FormChange, type SectionId } from "./changes";
import { EditorProvider, type EditorContextValue } from "./fields";
import { TabAnchor } from "./TabAnchor";
import { useLeaveGuard } from "@/src/components/hosts/useLeaveGuard";
import { HEALTH_CHECKS_TARGET } from "@/app/(dashboard)/proxy-hosts/links";
import { buildPayload, copyHostForm, hostToForm, LB_POLICIES, newHostForm, payloadIsEmpty, serializeUpstreams, withHealthChecksOn, type HostForm } from "./model";
import { fieldOfServerError, validateForm, type FieldErrors } from "./validate";
import { ReviewPanel, type PreviewState } from "./ReviewPanel";
import { RoutingSection } from "./RoutingSection";
import { SecuritySection } from "./SecuritySection";
import { AccessSection } from "./AccessSection";
import { AdvancedSection, CertificateSection, HeadersSection } from "./OtherSections";
import type { EditorCertificate, HostEditorData } from "./types";

/** Cards that can be linked to directly (#waf), and the section they are in. */
const CARD_SECTIONS: Record<string, SectionId> = {
  domains: "routing",
  upstreams: "routing",
  "load-balancing": "routing",
  protocols: "routing",
  "f-routes": "routing",
  waf: "security",
  "f-waf-exclusions": "security",
  "rate-limiting": "security",
  "access-list": "access",
  "geo-blocking": "security",
  "sign-in": "access",
  "f-mtls": "access",
  "f-blocks": "access",
  hsts: "headers",
  "f-redirects": "advanced",
  "f-error-pages": "advanced",
  "name-resolution": "advanced",
  "raw-json": "advanced",
};

const WAF_LABELS = { inherit: "global mode", off: "off", detection_only: "detect only", block: "block" } as const;
const GLOBAL_WAF = { On: "blocking", DetectionOnly: "detection only", Off: "off" } as const;

const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

function sectionSummary(section: SectionId, form: HostForm, data: HostEditorData): string {
  switch (section) {
    case "routing": {
      const upstreams = serializeUpstreams(form.upstreams).length;
      const policy = form.lb.enabled ? LB_POLICIES.find((entry) => entry.value === form.lb.policy)?.label.toLowerCase() : "random";
      return `${plural(form.domains.length, "domain")} · ${plural(upstreams, "upstream")} · ${policy}`;
    }
    case "security": {
      const rate = form.rateLimit.enabled ? plural(form.rateLimit.rules.length, "rate limit") : "no own rate limits";
      return `WAF ${WAF_LABELS[form.waf.mode]} · ${rate}${form.geoblock.enabled ? " · geo blocking" : ""}`;
    }
    case "access": {
      const parts = [
        form.accessListId !== null ? data.accessLists.find((list) => list.id === form.accessListId)?.name ?? "Access list" : null,
        form.signIn === "authentik" ? "Authentik" : form.signIn === "generic" ? "Forward auth" : form.signIn === "ingressi" ? "Sign-in" : null,
        form.mtls.enabled ? "mTLS" : null,
        form.pathBlocks.length > 0 ? plural(form.pathBlocks.length, "blocked path") : null,
      ].filter(Boolean);
      return parts.length > 0 ? parts.join(" · ") : "Public";
    }
    case "certificate": {
      // Caddy's reading is of the saved choice: a changed, unsaved selection has none yet.
      const served = data.host !== null && form.certificateId === data.host.certificateId ? data.servedCertificate : null;
      const left = served ? ` · ${Math.max(0, Math.floor((new Date(served.validTo).getTime() - Date.now()) / 86_400_000))} days left` : "";
      if (form.certificateId === null) return `Managed by Caddy${left}`;
      const chosen = data.certificates.find((certificate) => certificate.id === form.certificateId);
      return `${chosen?.name ?? "Chosen certificate"}${chosen?.type === "managed" ? left : ""}`;
    }
    case "headers":
      return `HSTS ${form.hstsEnabled ? "on" : "off"}`;
    case "advanced": {
      const parts = [
        form.redirects.length > 0 ? plural(form.redirects.length, "redirect") : null,
        form.pathRewrites.length > 0 || form.rewritePrefix.trim() ? "rewrites" : null,
        form.errorPages.length > 0 ? plural(form.errorPages.length, "error page") : null,
        form.dnsResolver.enabled ? "own resolvers" : null,
        form.customPreHandlersJson.trim() || form.customReverseProxyJson.trim() ? "raw JSON" : null,
      ].filter(Boolean);
      return parts.length > 0 ? parts.join(" · ") : "Nothing extra";
    }
  }
}

/** A tab of a host's page: its overview, a section of the editor, or its history. */
export type WorkspaceTab = "overview" | SectionId | "history";

/** What a host's page puts around the editor. */
export type HostWorkspace = {
  /** The page header, with the tab bar to put under it. */
  header: (tabs: ReactNode) => ReactNode;
  overview: ReactNode;
  /** The host's changes; null without audit_log:read (no History tab). */
  history: ReactNode | null;
  historyCount: number | null;
};

type Done =
  | { kind: "saved"; title: string; text: string; href: string; link: string }
  | { kind: "submitted"; title: string; text: string; href: string; link: string };

function initialForm(data: HostEditorData): HostForm {
  const context = {
    authentikDefaults: data.authentikDefaults,
    forwardAuthDefaults: data.forwardAuthDefaults,
    forwardAuthAccess: data.forwardAuthAccess,
    globalCrs: data.wafGlobal?.loadOwaspCrs,
  };
  if (data.host) return hostToForm(data.host, context);
  if (data.template) {
    const form = copyHostForm(
      data.template,
      { canSetCustomJson: data.isAdmin, canChooseTrust: data.canChooseTrust, canSetWafDirectives: Boolean(data.canWriteWaf) },
      context
    );
    if (data.initialDomain) form.domains = [data.initialDomain];
    return form;
  }
  return newHostForm({ initialDomain: data.initialDomain, scopeTags: data.scopeTags }, context);
}

const noSubscription = () => () => {};

export function HostEditor({ data: pageData, workspace }: { data: HostEditorData; workspace?: HostWorkspace }) {
  const router = useRouter();
  // Certificates created or changed from the certificate section, which the page's list does not have yet.
  const [certificateEdits, setCertificateEdits] = useState<EditorCertificate[]>([]);
  const data = useMemo<HostEditorData>(
    () =>
      certificateEdits.length === 0
        ? pageData
        : {
            ...pageData,
            certificates: [
              ...pageData.certificates.map((certificate) => certificateEdits.find((edit) => edit.id === certificate.id) ?? certificate),
              ...certificateEdits.filter((edit) => !pageData.certificates.some((certificate) => certificate.id === edit.id)),
            ],
          },
    [pageData, certificateEdits]
  );
  // False in the server render and during hydration, true once React owns
  // the fields: text typed into them before that is reset by hydration.
  const hydrated = useSyncExternalStore(noSubscription, () => true, () => false);
  const creating = data.mode === "create";
  const base = data.host ?? data.template;
  const [saved, setSaved] = useState<HostForm>(() => initialForm(data));
  const [form, setForm] = useState<HostForm>(saved);
  // The tab shown: a host's page opens on its overview, the editor on its own on Routing.
  const [view, setView] = useState<WorkspaceTab>(workspace ? "overview" : "routing");
  const section: SectionId = isSectionId(view) ? view : "routing";
  const setSection = setView;
  const [touched, setTouched] = useState<ReadonlySet<string>>(() => new Set());
  const [showAllErrors, setShowAllErrors] = useState(false);
  const [serverErrors, setServerErrors] = useState<FieldErrors>({});
  const [reviewOpen, setReviewOpen] = useState(false);
  const [preview, setPreview] = useState<PreviewState>({ status: "loading" });
  const [note, setNote] = useState("");
  const [emergency, setEmergency] = useState(false);
  const [emergencyReason, setEmergencyReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [done, setDone] = useState<Done | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const pendingFocus = useRef<string | null>(null);
  // Bumped to focus pendingFocus after the next render, even when the section stays the same.
  const [focusTick, setFocusTick] = useState(0);
  const sectionHeading = useRef<HTMLHeadingElement>(null);
  const reviewButton = useRef<HTMLButtonElement>(null);
  const previewRun = useRef(0);

  const groups = useMemo(() => changeGroups(data.mode), [data.mode]);
  const lookup = useMemo<ChangeLookup>(
    () => ({
      certificate: (id) => data.certificates.find((certificate) => certificate.id === id)?.name ?? `Certificate #${id}`,
      accessList: (id) => data.accessLists.find((list) => list.id === id)?.name ?? `Access list #${id}`,
      user: (id) => data.users.find((user) => user.id === id)?.name ?? `#${id}`,
      group: (id) => data.groups.find((group) => group.id === id)?.name ?? `#${id}`,
      role: (id) => data.mtlsRoles.find((role) => role.id === id)?.name ?? `#${id}`,
      clientCertificate: (id) => data.clientCertificates.find((certificate) => certificate.id === id)?.commonName ?? `#${id}`,
      ca: (id) => data.caCertificates.find((ca) => ca.id === id)?.name ?? `CA #${id}`,
      globalWafMode: data.wafGlobal ? GLOBAL_WAF[data.wafGlobal.mode] : "blocking",
    }),
    [data]
  );

  const changes = useMemo(() => formChanges(saved, form, lookup, groups), [saved, form, lookup, groups]);
  const payload = useMemo(() => buildPayload(form, saved, base, creating), [form, saved, base, creating]);
  const dirty = creating || !payloadIsEmpty(payload);
  const nameSection: SectionId = creating ? "routing" : "advanced";
  const validation = useMemo(
    () => validateForm(form, { nameSection, dnsProviderConfigured: data.dnsProviderConfigured, canChooseTrust: data.canChooseTrust }),
    [form, nameSection, data.dnsProviderConfigured, data.canChooseTrust]
  );
  const visibleErrors = useMemo(() => {
    const out: FieldErrors = { ...serverErrors };
    for (const [id, error] of Object.entries(validation)) {
      if (showAllErrors || touched.has(id) || (id.startsWith("f-up-") && touched.has("f-up-0"))) out[id] = error;
    }
    return out;
  }, [serverErrors, validation, showAllErrors, touched]);
  const errorCount = Object.keys(validation).length + Object.keys(serverErrors).length;

  // Policies that cover this host (before and after a tag change), for the header and the bar.
  const covering = useMemo(() => {
    if (!data.approval || data.approval.policies.length === 0) return [];
    const tags = [...new Set([...saved.tags, ...form.tags])];
    return policiesCovering(data.approval.policies, "proxy_host", tags, [creating ? "create" : "update"]);
  }, [data.approval, saved.tags, form.tags, creating]);

  const update = useCallback((recipe: (current: HostForm) => HostForm) => {
    setForm((current) => recipe(current));
    setDone(null);
    setSubmitError(null);
    setServerErrors({});
  }, []);

  const certificateSaved = useCallback(
    (certificate: EditorCertificate, choose: boolean) => {
      setCertificateEdits((edits) => [...edits.filter((edit) => edit.id !== certificate.id), certificate]);
      if (choose) update((current) => ({ ...current, certificateId: certificate.id }));
    },
    [update]
  );
  const touch = useCallback((id: string) => {
    setTouched((current) => (current.has(id) ? current : new Set([...current, id])));
  }, []);

  const wasOf = useCallback(
    (groupId: string) => {
      const change = changes.find((entry) => entry.group.id === groupId);
      if (!change || creating || change.group.kind !== "value") return null;
      return change.group.lines(saved, lookup)[0] ?? null;
    },
    [changes, creating, saved, lookup]
  );

  // Sections are linkable: #routing, #security … (or a card id inside one), and ?section=routing ….
  const selectFromHash = useCallback(() => {
    const hash = decodeURIComponent(window.location.hash.replace(/^#/, "")) || new URLSearchParams(window.location.search).get("section") || "";
    if (!hash) {
      if (workspace) setView("overview");
      return;
    }
    if (workspace && (hash === "overview" || (hash === "history" && workspace.history))) {
      setView(hash);
      return;
    }
    if (hash === HEALTH_CHECKS_TARGET) {
      // "Turn on health checks" on the host's page: they are turned on here as an unsaved change to review.
      update(withHealthChecksOn);
      setSection("routing");
      // Once: a reload shows Routing as it is then.
      window.history.replaceState(window.history.state, "", "#routing");
      pendingFocus.current = "f-lb-passive";
      setFocusTick((tick) => tick + 1);
      return;
    }
    if (isSectionId(hash)) {
      setSection(hash);
      return;
    }
    const owner = CARD_SECTIONS[hash];
    if (owner) {
      setSection(owner);
      pendingFocus.current = hash;
      setFocusTick((tick) => tick + 1);
    }
  }, [update, workspace]);

  useEffect(() => {
    selectFromHash();
    window.addEventListener("hashchange", selectFromHash);
    return () => window.removeEventListener("hashchange", selectFromHash);
  }, [selectFromHash]);

  // Drop the old deep links' leftovers (?create=1, ?edit=<id>) and ?section= (now the #anchor) from the address bar.
  useEffect(() => {
    const url = new URL(window.location.href);
    const section = url.searchParams.get("section");
    if (!["create", "edit", "section"].some((key) => url.searchParams.has(key))) return;
    for (const key of ["create", "edit", "section"]) url.searchParams.delete(key);
    if (section && !url.hash && (isSectionId(section) || CARD_SECTIONS[section])) url.hash = section;
    window.history.replaceState(window.history.state, "", url.toString());
  }, []);

  // Focus the field a "Show" or an error link points at, once its section has rendered. A field the
  // same update reveals (#health-checks) is not there on the first pass: it stays pending until it is.
  useEffect(() => {
    const id = pendingFocus.current;
    if (!id) return;
    const target = document.getElementById(id);
    if (!target) return;
    pendingFocus.current = null;
    target.scrollIntoView({ block: "center", behavior: "smooth" });
    target.focus({ preventScroll: true });
  }, [section, focusTick]);

  const goToSection = useCallback((next: WorkspaceTab, focusId?: string) => {
    setSection(next);
    // The overview is the page itself: no anchor.
    const url = new URL(window.location.href);
    url.hash = next === "overview" ? "" : next;
    window.history.replaceState(window.history.state, "", url.toString());
    pendingFocus.current = focusId ?? null;
    if (focusId) setFocusTick((tick) => tick + 1);
    else requestAnimationFrame(() => sectionHeading.current?.focus());
  }, []);

  // Leaving with unsaved changes asks first.
  useLeaveGuard(dirty && !done && !(creating && changes.length === 0));

  // The review's preview: re-run whenever what would be sent changes while it is open.
  const payloadKey = JSON.stringify(payload);
  useEffect(() => {
    if (!reviewOpen) return;
    const run = ++previewRun.current;
    setPreview({ status: "loading" });
    previewProxyHostEditorAction(data.host?.id ?? null, payload)
      .then((result) => {
        if (run !== previewRun.current) return;
        if (result.status === "ok") setPreview({ status: "ready", preview: result.preview });
        else setPreview({ status: "error", message: result.message });
      })
      .catch(() => run === previewRun.current && setPreview({ status: "error", message: "The change could not be checked: the server did not answer." }));
    // payloadKey stands for payload: the preview re-runs only when what would be sent changes.
  }, [reviewOpen, payloadKey, data.host?.id]);

  const firstError = useCallback((): { id: string; section: SectionId } | null => {
    const entries = Object.entries({ ...validation, ...serverErrors });
    if (entries.length === 0) return null;
    entries.sort(([, a], [, b]) => SECTIONS.indexOf(a.section) - SECTIONS.indexOf(b.section));
    return { id: entries[0][0], section: entries[0][1].section };
  }, [validation, serverErrors]);

  const openReview = useCallback(() => {
    if (Object.keys(validation).length > 0) {
      setShowAllErrors(true);
      const first = firstError();
      setAnnouncement(`Fix ${plural(Object.keys(validation).length, "problem")} before saving.`);
      if (first) goToSection(first.section, first.id);
      return;
    }
    setSubmitError(null);
    setReviewOpen(true);
  }, [validation, firstError, goToSection]);

  const closeReview = useCallback(() => {
    setReviewOpen(false);
    requestAnimationFrame(() => reviewButton.current?.focus());
  }, []);

  // Ctrl/Cmd+S opens the review.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        if (dirty && !reviewOpen) openReview();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [dirty, reviewOpen, openReview]);

  async function submit() {
    setSubmitting(true);
    setSubmitError(null);
    const result = await saveProxyHostEditorAction(data.host?.id ?? null, {
      ...payload,
      ...(emergency ? { emergencyReason: emergencyReason.trim() } : note.trim() ? { note: note.trim() } : {}),
    }).catch(() => ({ status: "error" as const, message: "The server did not answer. Nothing was saved." }));
    setSubmitting(false);
    if (result.status === "error") {
      const field = fieldOfServerError(result.message, nameSection);
      if (field) {
        setServerErrors({ [field.id]: { message: result.message, section: field.section } });
        setReviewOpen(false);
        setAnnouncement(`Not saved: ${result.message}`);
        goToSection(field.section, field.id);
      } else {
        setSubmitError(result.message);
      }
      return;
    }
    setReviewOpen(false);
    setEmergency(false);
    setEmergencyReason("");
    setNote("");
    if (result.status === "saved") {
      if (creating) {
        setAnnouncement(result.message);
        setSaved(form);
        router.push(`/proxy-hosts/${result.hostId}`);
        return;
      }
      setSaved(form);
      setDone({ kind: "saved", title: "Saved", text: result.message, href: `/proxy-hosts/${result.hostId}`, link: "Open host" });
      setAnnouncement(result.message);
      router.refresh();
      return;
    }
    if (result.requestStatus === "applied") {
      if (!creating) setSaved(form);
      setDone({
        kind: "saved",
        title: "Applied as an emergency change",
        text: "The audit log records your reason.",
        href: "/audit-log",
        link: "Open the audit log",
      });
      setAnnouncement("Applied as an emergency change.");
      router.refresh();
      return;
    }
    setDone({ kind: "submitted", title: "Change request submitted for approval", text: result.message, href: "/approvals", link: "Open in Approvals" });
    setAnnouncement(result.message);
  }

  const context: EditorContextValue = { form, saved, data, lookup, update, certificateSaved, errors: visibleErrors, touch, wasOf };
  const hostName = data.host?.name ?? (form.name.trim() || "the new host");
  const perSection = new Map<SectionId, number>();
  for (const change of changes) perSection.set(change.group.section, (perSection.get(change.group.section) ?? 0) + 1);
  const errorsPerSection = new Map<SectionId, number>();
  for (const error of Object.values(visibleErrors)) errorsPerSection.set(error.section, (errorsPerSection.get(error.section) ?? 0) + 1);

  const ready = preview.status === "ready" ? preview.preview : null;
  const submitLabel = emergency
    ? "Apply now as an emergency change"
    : ready?.approval.required
      ? "Submit for approval"
      : creating
        ? "Create host"
        : "Save changes";
  const closeHref = data.host ? `/proxy-hosts/${data.host.id}` : "/proxy-hosts";

  const sections: Record<SectionId, ReactNode> = {
    routing: <RoutingSection />,
    security: <SecuritySection />,
    access: <AccessSection />,
    certificate: <CertificateSection />,
    headers: <HeadersSection />,
    advanced: <AdvancedSection />,
  };

  const count = changes.length;
  const barTitle = creating ? (count > 0 ? `New host · ${plural(count, "setting")} set` : "New host") : count === 0 ? "No unsaved changes" : plural(count, "unsaved change");
  // Said only when saving does not apply the change at once.
  const barText = covering.length > 0 && (creating || count > 0) ? (creating ? "Creating it sends a change request for approval." : "Saving sends them for approval.") : null;

  const tabBar = (
    <nav aria-label={workspace ? "Host sections" : "Host settings"} data-host-tabs="" data-hydrated={hydrated ? "true" : undefined}>
      <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-line">
        {workspace && (
          <TabAnchor id="overview" current={view === "overview"} onSelect={() => goToSection("overview")}>
            Overview
          </TabAnchor>
        )}
        {SECTIONS.map((id) => {
          const changed = perSection.get(id) ?? 0;
          const problems = errorsPerSection.get(id) ?? 0;
          return (
            <TabAnchor key={id} id={id} current={view === id} onSelect={() => goToSection(id)} title={sectionSummary(id, form, data)}>
              {SECTION_LABELS[id]}
              {problems > 0 ? (
                <span className="num rounded-full bg-bad-tint px-1.5 text-[11px] font-semibold leading-[18px] text-bad">
                  {problems}
                  <span className="sr-only"> {problems === 1 ? "problem" : "problems"}</span>
                </span>
              ) : changed > 0 ? (
                <span className="num rounded-full bg-brand-tint px-1.5 text-[11px] font-semibold leading-[18px] text-brand">
                  {changed}
                  <span className="sr-only"> unsaved {changed === 1 ? "change" : "changes"}</span>
                </span>
              ) : null}
            </TabAnchor>
          );
        })}
        {workspace?.history && (
          <TabAnchor id="history" current={view === "history"} onSelect={() => goToSection("history")}>
            History
            {workspace.historyCount !== null && workspace.historyCount > 0 && (
              <span className="num rounded-full bg-raise px-1.5 text-[11px] leading-[18px] text-muted-foreground">{workspace.historyCount}</span>
            )}
          </TabAnchor>
        )}
      </div>
    </nav>
  );

  // On a host's page the bar is there only while something is unsaved, being reviewed or just saved.
  const showBar = !workspace || count > 0 || dirty || reviewOpen || done !== null;

  return (
    <EditorProvider value={context}>
      <div className={cn("flex flex-col gap-5", showBar && "pb-36 md:pb-28")}>
        {workspace ? (
          workspace.header(tabBar)
        ) : (
          <PageHeader
            className="mb-0"
            breadcrumb={["Traffic", { label: "Proxy hosts", href: "/proxy-hosts" }, "New host"]}
            title={data.template ? `Copy of ${data.template.name}` : "New proxy host"}
            actions={
              <>
                <span className="flex h-[38px] items-center gap-2.5 rounded-[10px] border border-line bg-panel px-3 text-[13px]">
                  <span id="f-enabled-label" className="font-semibold">
                    {form.enabled ? "Enabled" : "Disabled"}
                  </span>
                  <Switch id="f-enabled" aria-label="Host enabled" checked={form.enabled} onCheckedChange={(enabled) => update((f) => ({ ...f, enabled }))} />
                </span>
                <Button asChild variant="outline" className="h-[38px]">
                  <Link href={closeHref}>
                    Cancel
                  </Link>
                </Button>
              </>
            }
          >
            {(covering.length > 0 || form.tags.length > 0) && (
              <div className="flex flex-wrap items-center gap-2">
                {covering.length > 0 && (
                  <span className="inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full border border-line2 px-2.5 text-xs text-muted-foreground">
                    <ShieldCheck aria-hidden="true" className="h-3.5 w-3.5 text-warn" />
                    {covering[0].name}
                    {covering.length > 1 ? ` and ${covering.length - 1} more` : ""} {covering.length > 1 ? "policies" : "policy"} · changes need approval
                  </span>
                )}
                {form.tags.map((tag) => (
                  <span key={tag} className="num rounded bg-raise px-1.5 text-[11px] leading-[18px] text-muted-foreground">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            {tabBar}
          </PageHeader>
        )}

        {data.template && (
          <Banner tone="info" title={`A copy of ${data.template.name}.`}>
            Change the domains before creating it: two hosts cannot serve the same name.
            {!data.isAdmin && (data.template.customPreHandlersJson || data.template.customReverseProxyJson) ? " Custom Caddy JSON was not copied: only administrators set it." : ""}
            {!data.canWriteWaf && data.template.waf?.custom_directives?.trim() ? " Custom WAF directives were not copied: they need the waf:write permission." : ""}
            {!data.canChooseTrust && data.template.mtls?.enabled ? " Client certificate settings were not copied: your role cannot choose them." : ""}
          </Banner>
        )}

        {workspace && covering.length > 0 && isSectionId(view) && (
          <Banner tone="info" icon={null} title={`Changes to this host need approval (${covering.map((policy) => policy.name).join(", ")}).`}>
            Saving sends them as a change request.
          </Banner>
        )}

        {view === "overview" && workspace ? (
          workspace.overview
        ) : view === "history" && workspace?.history ? (
          workspace.history
        ) : (
          <div className="flex min-w-0 flex-col gap-5" id="host-editor-section" role="tabpanel">
            <h2 ref={sectionHeading} tabIndex={-1} className="sr-only">
              {SECTION_LABELS[section]}
            </h2>
            {sections[section]}
          </div>
        )}
      </div>

      <p role="status" aria-live="polite" className="sr-only">
        {announcement}
      </p>

      {showBar && (
      <div className="fixed inset-x-3 bottom-[calc(68px_+_env(safe-area-inset-bottom))] z-30 flex flex-col gap-2 md:bottom-4 md:left-[calc(15.5rem_+_max(2rem,_(100vw_-_15.5rem_-_1600px)_/_2_+_2rem))] md:right-[max(2rem,_calc((100vw_-_15.5rem_-_1600px)_/_2_+_2rem))]">
        {reviewOpen && (
          <ReviewPanel
            title={creating ? `Review the new host ${hostName}` : `Review ${plural(count, "change")} to ${hostName}`}
            changes={changes}
            creating={creating}
            preview={preview}
            note={note}
            onNote={setNote}
            emergency={emergency}
            onEmergency={setEmergency}
            emergencyReason={emergencyReason}
            onEmergencyReason={setEmergencyReason}
            submitError={submitError}
            submitting={submitting}
            submitLabel={submitLabel}
            onSubmit={submit}
            onClose={closeReview}
            onShow={(change: FormChange) => {
              setReviewOpen(false);
              goToSection(change.group.section, change.group.focus);
            }}
            onUndo={(change: FormChange) => setForm((current) => change.group.restore(current, saved))}
            hostLabel={hostName}
            policiesExist={Boolean(data.approval && data.approval.policies.length > 0)}
          />
        )}
        <div
          data-testid="host-editor-bar"
          data-hydrated={hydrated ? "true" : undefined}
          className={cn("flex flex-wrap items-center gap-x-3.5 gap-y-2.5 rounded-2xl border bg-panel px-4 py-3 shadow-overlay", count > 0 || creating ? "border-line2" : "border-line")}
        >
          {done ? (
            <>
              <span className="flex min-w-0 flex-[1_1_320px] items-start gap-2.5">
                <CheckCircle2 aria-hidden="true" className={cn("mt-px h-[18px] w-[18px] shrink-0", done.kind === "saved" ? "text-ok" : "text-warn")} />
                <span className="flex flex-col gap-0.5">
                  <span className="font-semibold">{done.title}</span>
                  <span className="text-[13px] text-muted-foreground">{done.text}</span>
                </span>
              </span>
              <span className="flex flex-wrap gap-2">
                <Button type="button" variant="ghost" onClick={() => setDone(null)}>
                  Keep editing
                </Button>
                {workspace && done.kind === "saved" && done.href.startsWith("/proxy-hosts/") ? (
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => {
                      setDone(null);
                      goToSection("overview");
                    }}
                  >
                    Show overview
                  </Button>
                ) : (
                  <Button asChild variant="secondary">
                    <Link href={done.href}>{done.link}</Link>
                  </Button>
                )}
              </span>
            </>
          ) : (
            <>
              <span className="flex min-w-0 flex-[1_1_260px] items-center gap-2.5">
                <span aria-hidden="true" className={cn("h-2 w-2 shrink-0 rounded-full", errorCount > 0 && showAllErrors ? "bg-bad" : count > 0 || creating ? "bg-brand" : "bg-ok")} />
                <span className="flex min-w-0 flex-col">
                  <span className="font-semibold">{barTitle}</span>
                  {(barText || (showAllErrors && errorCount > 0)) && (
                    <span className="text-[13px] text-soft">
                      {showAllErrors && errorCount > 0 ? (
                        <button
                          type="button"
                          className="text-bad underline-offset-4 hover:underline"
                          onClick={() => {
                            const first = firstError();
                            if (first) goToSection(first.section, first.id);
                          }}
                        >
                          {plural(errorCount, "problem")} to fix before saving. Show the first
                        </button>
                      ) : (
                        barText
                      )}
                    </span>
                  )}
                </span>
              </span>
              <span className="flex flex-wrap gap-2">
                {!creating && (
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={count === 0 && payloadIsEmpty(payload)}
                    onClick={() => {
                      setForm(saved);
                      setServerErrors({});
                      setShowAllErrors(false);
                      setReviewOpen(false);
                      setAnnouncement("Changes discarded.");
                    }}
                  >
                    Discard
                  </Button>
                )}
                <Button
                  ref={reviewButton}
                  type="button"
                  variant="secondary"
                  aria-expanded={reviewOpen}
                  disabled={!dirty}
                  onClick={() => (reviewOpen ? closeReview() : openReview())}
                >
                  {creating ? "Review" : "Review changes"}
                </Button>
                {!reviewOpen && (
                  <Button type="button" disabled={!dirty} onClick={openReview}>
                    {creating ? "Create host" : "Save"}
                  </Button>
                )}
              </span>
            </>
          )}
        </div>
      </div>
      )}
    </EditorProvider>
  );
}
