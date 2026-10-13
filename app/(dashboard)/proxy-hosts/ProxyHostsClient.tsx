"use client";

import { Fragment, useEffect, useMemo, useRef, useState, useTransition, type ReactNode } from "react";
import Link from "next/link";
import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronDown, MoreHorizontal, Plus, Server } from "lucide-react";
import { toast } from "sonner";
import type { AccessList } from "@/lib/models/access-lists";
import type { CertificatePickerOption } from "@/lib/certificate-api";
import type { ProxyHost } from "@/lib/models/proxy-hosts";
import type { CaCertificate } from "@/lib/models/ca-certificates";
import type { AuthentikSettings, ForwardAuthSettings } from "@/lib/settings";
import type { MtlsRole } from "@/lib/models/mtls-roles";
import type { IssuedClientCertificate } from "@/lib/models/issued-client-certificates";
import type { AnalyticsStatus } from "@/src/lib/analytics/run";
import {
  DEFAULT_SORT_DIR,
  HIGH_ERROR_RATE,
  PROTECTION_FILTERS,
  PROTECTION_FILTER_LABELS,
  hostGroupOf,
  primaryDomain,
  type HostListQuery,
  type HostListRow,
  type SortKey,
  type StatusFilter,
} from "@/src/lib/proxy-host-view";
import type { HostApprovalContext } from "@/ee/approvals/types";
import { toggleProxyHostAction } from "./actions";
import { bulkProxyHostsAction, type BulkOperation } from "./bulk-actions";
import { NEW_HOST_HREF, hostEditorHref, hostHref } from "./links";
import { CertificateSummary, HostStatus, ProtectionPills, TagChips } from "./host-parts";
import { PageHeader } from "@/components/ui/PageHeader";
import { ListSearchField } from "@/components/ui/ListSearchField";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { EmptyState } from "@/components/ui/EmptyState";
import { Banner } from "@/components/ui/Banner";
import { Pagination, useUrlPage } from "@/components/ui/Pagination";
import { AppDialog } from "@/components/ui/AppDialog";
import { formatCount, formatPercent } from "@/components/ui/chart-format";
import { CreateHostDialog, EditHostDialog, DeleteHostDialog } from "@/components/proxy-hosts/HostDialogs";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

type ForwardAuthUser = { id: number; email: string; name: string | null; role: string };
type ForwardAuthGroup = { id: number; name: string; description: string | null; member_count: number };
type ForwardAuthAccessMap = Record<number, { userIds: number[]; groupIds: number[] }>;

type Props = {
  /** The hosts on this page, for the host dialogs (same order as `rows`). */
  hosts: ProxyHost[];
  /** The hosts on this page as the list shows them. */
  rows: HostListRow[];
  /** Every host the user may see, before filters. */
  totalHosts: number;
  /** Hosts per status for the search, protection and tag filters. */
  statusCounts: Record<StatusFilter, number>;
  /** Busiest host's requests among the filtered ones, for the share bars. */
  maxRequests: number;
  /** null without analytics:read; "disabled" without ClickHouse. */
  analyticsStatus: AnalyticsStatus | null;
  availableTags: string[];
  query: HostListQuery;
  certificates: CertificatePickerOption[];
  accessLists: AccessList[];
  caCertificates: CaCertificate[];
  authentikDefaults: AuthentikSettings | null;
  forwardAuthDefaults?: ForwardAuthSettings | null;
  pagination: { total: number; page: number; perPage: number };
  mtlsRoles?: MtlsRole[];
  issuedClientCerts?: IssuedClientCertificate[];
  forwardAuthUsers?: ForwardAuthUser[];
  forwardAuthGroups?: ForwardAuthGroup[];
  forwardAuthAccessMap?: ForwardAuthAccessMap;
  /** A host to open in the edit dialog (?edit=<id>), if the user may see it. */
  editTarget?: ProxyHost | null;
  /** The user may create, change and delete hosts (proxy_hosts:write); true when omitted. */
  canWrite?: boolean;
  /** The tags the user's role is limited to, if any. */
  scopeTags?: string[];
  /** Change approval policies (ee/approvals), so the dialogs can say a host is protected. */
  approval?: HostApprovalContext | null;
};

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

function SortButton({ label, sortKey, query, onSort }: { label: string; sortKey: SortKey; query: HostListQuery; onSort: (key: SortKey) => void }) {
  const active = query.sortBy === sortKey;
  const Icon = active ? (query.sortDir === "asc" ? ArrowUp : ArrowDown) : ArrowUpDown;
  return (
    <button type="button" onClick={() => onSort(sortKey)} className="inline-flex items-center gap-1 rounded hover:text-foreground">
      {label}
      <Icon aria-hidden="true" className={cn("h-3.5 w-3.5", !active && "opacity-50")} />
    </button>
  );
}

function SortHeader({
  label,
  sortKey,
  alsoSortKey,
  alsoLabel,
  query,
  onSort,
  className,
}: {
  label: string;
  sortKey: SortKey;
  /** A second sort offered in the same column, e.g. the host's name next to its domain. */
  alsoSortKey?: SortKey;
  alsoLabel?: string;
  query: HostListQuery;
  onSort: (key: SortKey) => void;
  className?: string;
}) {
  const active = query.sortBy === sortKey || (alsoSortKey !== undefined && query.sortBy === alsoSortKey);
  return (
    <th
      scope="col"
      aria-sort={active ? (query.sortDir === "asc" ? "ascending" : "descending") : "none"}
      className={cn("border-b border-line px-2.5 py-2 font-medium", className)}
    >
      <span className="inline-flex items-center gap-3">
        <SortButton label={label} sortKey={sortKey} query={query} onSort={onSort} />
        {alsoSortKey && alsoLabel && <SortButton label={alsoLabel} sortKey={alsoSortKey} query={query} onSort={onSort} />}
      </span>
    </th>
  );
}

function GroupHeading({ group }: { group: string | null }) {
  return group === null ? <span>No tag</span> : <span className="num">{group}</span>;
}

function PlainHeader({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <th scope="col" className={cn("border-b border-line px-2.5 py-2 font-medium", className)}>
      {children}
    </th>
  );
}

function RequestsBar({ requests, max }: { requests: number; max: number }) {
  const width = max > 0 ? Math.max(requests > 0 ? 2 : 0, Math.round((requests / max) * 1000) / 10) : 0;
  return (
    <span className="flex items-center gap-2.5">
      <span aria-hidden="true" className="h-1.5 w-[88px] shrink-0 overflow-hidden rounded-[3px] bg-raise">
        <span className="block h-full bg-served" style={{ width: `${width}%` }} />
      </span>
      <span className="num">{formatCount(requests)}</span>
    </span>
  );
}

function ErrorRate({ row }: { row: HostListRow }) {
  if (!row.traffic || row.traffic.requests === 0) return <span className="text-soft">–</span>;
  const rate = row.traffic.errorRate5xx;
  return (
    <span
      className={cn("num", rate >= HIGH_ERROR_RATE ? "font-semibold text-bad" : rate >= 0.01 ? "text-warn" : undefined)}
      title={`${formatCount(row.traffic.errors5xx)} of ${formatCount(row.traffic.requests)} requests`}
    >
      {formatPercent(rate)}
    </span>
  );
}

function HostName({ row }: { row: HostListRow }) {
  const domain = primaryDomain(row);
  const more = row.domains.length - 1;
  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      <span className="min-w-0">
        <Link href={hostHref(row.id)} className="font-semibold text-foreground underline-offset-4 hover:underline [overflow-wrap:anywhere]">
          {domain}
        </Link>
        {more > 0 && <span className="ml-1 text-xs text-soft">+ {more === 1 ? row.domains[1] : `${more} more`}</span>}
      </span>
      <span className="flex flex-wrap items-center gap-x-1.5 text-xs text-soft">
        {row.name !== domain && (
          <>
            <span className="text-muted-foreground">{row.name}</span>
            <span aria-hidden="true">·</span>
          </>
        )}
        {/* One line: a long upstream is cut, its full address in the tooltip. */}
        <span className="num max-w-[300px] truncate" title={row.upstreams.join("\n")}>
          {row.upstreams[0]}
          {row.upstreams.length > 1 && ` +${row.upstreams.length - 1}`}
        </span>
      </span>
    </span>
  );
}

export default function ProxyHostsClient({
  hosts,
  rows,
  totalHosts,
  statusCounts,
  maxRequests,
  analyticsStatus,
  availableTags,
  query,
  certificates,
  accessLists,
  caCertificates,
  authentikDefaults,
  pagination,
  mtlsRoles,
  issuedClientCerts,
  forwardAuthUsers,
  forwardAuthGroups,
  forwardAuthAccessMap,
  forwardAuthDefaults,
  editTarget = null,
  canWrite = true,
  scopeTags = [],
  approval = null,
}: Props) {
  const [createOpen, setCreateOpen] = useState(false);
  const [duplicateHost, setDuplicateHost] = useState<ProxyHost | null>(null);
  const [editHost, setEditHost] = useState<ProxyHost | null>(null);
  const [deleteHost, setDeleteHost] = useState<ProxyHost | null>(null);
  // Counter forces CreateHostDialog to remount on each open, resetting useFormState
  const [dialogKey, setDialogKey] = useState(0);
  const [searchTerm, setSearchTerm] = useState(query.search);
  const [selected, setSelected] = useState<ReadonlySet<number>>(() => new Set());
  const [tagOpen, setTagOpen] = useState(false);
  const [tagValue, setTagValue] = useState("");
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [bulkPending, startBulk] = useTransition();

  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { hrefFor } = useUrlPage();
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showTraffic = analyticsStatus !== null && analyticsStatus !== "disabled";

  // The Tags column only when some host has tags.

  const showTags = availableTags.length > 0 || rows.some((row) => row.tags.length > 0);
  // Host, Status, Protection, Certificate and the actions, plus the optional columns.
  const columnCount = (canWrite ? 1 : 0) + 5 + (showTraffic ? 2 : 0) + (showTags ? 1 : 0);
  const hostById = useMemo(() => new Map(hosts.map((host) => [host.id, host])), [hosts]);

  useEffect(() => {
    setSearchTerm(query.search);
  }, [query.search]);

  // Keep only selected hosts that are still on the page.
  useEffect(() => {
    setSelected((current) => {
      const onPage = new Set(rows.map((row) => row.id));
      const kept = [...current].filter((id) => onPage.has(id));
      return kept.length === current.size ? current : new Set(kept);
    });
  }, [rows]);

  // Deep links (the command palette): ?create=1 opens the create form, with
  // &domain= as its first domain, and ?edit=<id> the edit form. The
  // parameters are then removed so a reload does not reopen them.
  const [initialDomain, setInitialDomain] = useState<string | null>(null);
  useEffect(() => {
    const create = searchParams.get("create") === "1";
    const edit = searchParams.get("edit");
    if (!create && !edit) return;
    if (create && canWrite) {
      setDuplicateHost(null);
      setInitialDomain(searchParams.get("domain")?.trim().slice(0, 253) || null);
      setDialogKey((k) => k + 1);
      setCreateOpen(true);
    } else if (edit && canWrite && editTarget && String(editTarget.id) === edit) {
      setEditHost(editTarget);
    }
    const params = new URLSearchParams(searchParams.toString());
    params.delete("create");
    params.delete("domain");
    params.delete("edit");
    const rest = params.toString();
    router.replace(rest ? `${pathname}?${rest}` : pathname, { scroll: false });
  }, [searchParams, canWrite, editTarget, pathname, router]);

  /** Changes the filters or the sort, back on page 1. */
  function pushParams(update: (params: URLSearchParams) => void) {
    const params = new URLSearchParams(searchParams.toString());
    update(params);
    params.delete("page");
    const rest = params.toString();
    router.push(rest ? `${pathname}?${rest}` : pathname);
  }

  // Typing replaces the address instead of adding a history entry per word, keeps the scroll
  // position, and shows a spinner in the field until the list has caught up.
  const [searching, startSearch] = useTransition();
  function handleSearchChange(value: string) {
    setSearchTerm(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const params = new URLSearchParams(searchParams.toString());
      if (value.trim()) params.set("search", value.trim());
      else params.delete("search");
      params.delete("page");
      const rest = params.toString();
      startSearch(() => router.replace(rest ? `${pathname}?${rest}` : pathname, { scroll: false }));
    }, 250);
  }

  function handleStatusChange(value: StatusFilter) {
    pushParams((params) => {
      if (value === "all") params.delete("status");
      else params.set("status", value);
    });
  }

  function handleProtectionChange(value: string) {
    pushParams((params) => {
      if (value === "any") params.delete("protection");
      else params.set("protection", value);
    });
  }

  function toggleTag(tag: string) {
    const next = query.tags.includes(tag) ? query.tags.filter((t) => t !== tag) : [...query.tags, tag];
    pushParams((params) => {
      params.delete("tag");
      for (const t of next) params.append("tag", t);
    });
  }

  function handleSort(key: SortKey) {
    const dir = query.sortBy === key ? (query.sortDir === "asc" ? "desc" : "asc") : DEFAULT_SORT_DIR[key];
    pushParams((params) => {
      params.set("sortBy", key);
      params.set("sortDir", dir);
    });
  }

  function toggleGrouping() {
    pushParams((params) => {
      if (query.groupBy === "tag") params.delete("group");
      else params.set("group", "tag");
    });
  }

  /** The heading to show above a row: the first of the page, and wherever the section changes. */
  const groupHeadings = useMemo(() => {
    if (query.groupBy !== "tag") return new Map<number, string | null>();
    const headings = new Map<number, string | null>();
    let previous: string | null | undefined;
    for (const row of rows) {
      const group = hostGroupOf(row, query.tags);
      if (group !== previous) headings.set(row.id, group);
      previous = group;
    }
    return headings;
  }, [rows, query.groupBy, query.tags]);

  function clearFilters() {
    setSearchTerm("");
    pushParams((params) => {
      for (const key of ["search", "status", "protection", "tag"]) params.delete(key);
    });
  }

  const handleToggleEnabled = async (id: number, enabled: boolean) => {
    const result = await toggleProxyHostAction(id, enabled);
    // A protected host is not toggled at once: the change waits for approval (ee/approvals).
    if (result.status === "error") toast.error(result.message ?? "Failed to toggle proxy host");
    else if (result.changeRequest) toast.info(result.message ?? "Submitted for approval", { duration: 10000 });
    else toast.success(result.message ?? (enabled ? "Proxy host enabled." : "Proxy host disabled."));
    router.refresh();
  };

  const openDuplicate = (host: ProxyHost) => {
    setDuplicateHost(host);
    setDialogKey((k) => k + 1);
    setCreateOpen(true);
  };

  // ── Selection and bulk actions ──
  const selectedRows = rows.filter((row) => selected.has(row.id));
  const allSelected = rows.length > 0 && selectedRows.length === rows.length;
  const someSelected = selectedRows.length > 0 && !allSelected;

  function toggleRow(id: number, checked: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleAll(checked: boolean) {
    setSelected(checked ? new Set(rows.map((row) => row.id)) : new Set());
  }

  function runBulk(operation: BulkOperation) {
    const ids = selectedRows.map((row) => row.id);
    startBulk(async () => {
      try {
        const result = await bulkProxyHostsAction(ids, operation);
        if (result.ok) toast.success(result.message);
        else toast.error(result.message, { duration: 10000 });
        if (result.changed + result.submitted + result.unchanged > 0) {
          setSelected(new Set());
          setTagOpen(false);
          setTagValue("");
        }
      } catch (error) {
        toast.error(error instanceof Error ? error.message : "The bulk action failed.");
      }
      setBulkDeleteOpen(false);
      router.refresh();
    });
  }

  const actionsMenu = (row: HostListRow) => {
    const host = hostById.get(row.id);
    const domain = primaryDomain(row);
    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`More actions for ${domain}`}>
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem asChild>
            <Link href={hostHref(row.id)}>Open</Link>
          </DropdownMenuItem>
          {canWrite && host && (
            <>
              <DropdownMenuItem asChild>
                <Link href={hostEditorHref(row.id)}>Edit</Link>
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => openDuplicate(host)}>Duplicate</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => handleToggleEnabled(row.id, !row.enabled)}>{row.enabled ? "Disable" : "Enable"}</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-bad focus:text-bad" onSelect={() => setDeleteHost(host)}>
                Delete
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    );
  };

  const filtering = Boolean(query.search) || query.status !== "all" || query.protection !== null || query.tags.length > 0;
  const { total, page, perPage } = pagination;
  const anyEnabled = selectedRows.some((row) => row.enabled);
  const anyDisabled = selectedRows.some((row) => !row.enabled);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        className="mb-0"
        breadcrumb={["Traffic", "Proxy hosts"]}
        title="Proxy hosts"
        count={totalHosts}
        actions={
          canWrite && (
            <Button asChild>
              <Link href={NEW_HOST_HREF}>
                <Plus />
                New proxy host
              </Link>
            </Button>
          )
        }
      />

      {analyticsStatus === "unavailable" && (
        <Banner tone="warn" title="Traffic could not be read.">
          ClickHouse did not answer.
        </Banner>
      )}

      {totalHosts === 0 ? (
        <section aria-label="Proxy hosts" className="rounded-2xl border border-line bg-panel">
          <EmptyState
            icon={Server}
            title="No proxy hosts yet"
            action={
              canWrite ? (
                <Button asChild>
                  <Link href={NEW_HOST_HREF}>
                    <Plus />
                    New proxy host
                  </Link>
                </Button>
              ) : undefined
            }
          />
        </section>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2.5">
            <ListSearchField
              className="flex-[1_1_280px]"
              value={searchTerm}
              onChange={handleSearchChange}
              placeholder="Domain, upstream or tag"
              label="Filter hosts"
              pending={searching}
            />
            <SegmentedControl<StatusFilter>
              label="Status"
              value={query.status}
              onChange={handleStatusChange}
              options={[
                { value: "all", label: <>All <span className="num text-muted-foreground">{statusCounts.all}</span></> },
                {
                  value: "attention",
                  label: (
                    <>
                      Needs attention <span className={cn("num", statusCounts.attention > 0 ? "text-warn" : "text-muted-foreground")}>{statusCounts.attention}</span>
                    </>
                  ),
                },
                { value: "disabled", label: <>Disabled <span className="num text-muted-foreground">{statusCounts.disabled}</span></> },
              ]}
            />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="h-[38px]">
                  {query.protection ? `Protection: ${PROTECTION_FILTER_LABELS[query.protection]}` : "Protection"}
                  <ChevronDown aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-56">
                <DropdownMenuLabel>Protection</DropdownMenuLabel>
                <DropdownMenuRadioGroup value={query.protection ?? "any"} onValueChange={handleProtectionChange}>
                  <DropdownMenuRadioItem value="any">Any</DropdownMenuRadioItem>
                  {PROTECTION_FILTERS.map((filter) => (
                    <DropdownMenuRadioItem key={filter} value={filter}>
                      {PROTECTION_FILTER_LABELS[filter]}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="h-[38px]" disabled={availableTags.length === 0}>
                  {query.tags.length > 0 ? `Tags: ${query.tags.length}` : "Tags"}
                  <ChevronDown aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="max-h-80 w-56 overflow-y-auto">
                <DropdownMenuLabel>Hosts with any of these tags</DropdownMenuLabel>
                {availableTags.map((tag) => (
                  <DropdownMenuCheckboxItem
                    key={tag}
                    checked={query.tags.includes(tag)}
                    onCheckedChange={() => toggleTag(tag)}
                    onSelect={(event) => event.preventDefault()}
                    className="num"
                  >
                    {tag}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              variant="outline"
              className="h-[38px]"
              aria-pressed={query.groupBy === "tag"}
              disabled={availableTags.length === 0}
              title="Show the hosts in a section per tag"
              onClick={toggleGrouping}
            >
              {query.groupBy === "tag" ? "Grouped by tag" : "Group by tag"}
            </Button>
            {filtering && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            )}
          </div>

          <section aria-label="Proxy hosts" className="min-w-0 overflow-hidden rounded-2xl border border-line bg-panel">
            {canWrite && selectedRows.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 border-b border-line bg-brand-tint px-[18px] py-2.5">
                <span className="mr-2 font-semibold" aria-live="polite">
                  {plural(selectedRows.length, "host")} selected
                </span>
                <Button variant="outline" size="sm" disabled={bulkPending} onClick={() => runBulk({ type: "waf_block" })}>
                  Turn on WAF blocking
                </Button>
                <Popover open={tagOpen} onOpenChange={setTagOpen}>
                  <PopoverTrigger asChild>
                    <Button variant="outline" size="sm" disabled={bulkPending}>
                      Add tag
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent align="start" className="w-72">
                    <form
                      className="flex flex-col gap-2"
                      onSubmit={(event) => {
                        event.preventDefault();
                        if (tagValue.trim()) runBulk({ type: "add_tag", tag: tagValue.trim() });
                      }}
                    >
                      <Label htmlFor="bulk-tag">Tag</Label>
                      <Input
                        id="bulk-tag"
                        value={tagValue}
                        onChange={(event) => setTagValue(event.target.value)}
                        list="bulk-tag-suggestions"
                        placeholder={scopeTags[0] ?? "production"}
                        autoCapitalize="none"
                        autoComplete="off"
                        spellCheck={false}
                      />
                      <datalist id="bulk-tag-suggestions">
                        {(scopeTags.length > 0 ? scopeTags : availableTags).map((tag) => (
                          <option key={tag} value={tag} />
                        ))}
                      </datalist>
                      {scopeTags.length > 0 && <p className="text-xs text-soft">Your role can add {scopeTags.join(", ")}.</p>}
                      <Button type="submit" size="sm" disabled={!tagValue.trim() || bulkPending}>
                        Add to {plural(selectedRows.length, "host")}
                      </Button>
                    </form>
                  </PopoverContent>
                </Popover>
                {anyDisabled && (
                  <Button variant="outline" size="sm" disabled={bulkPending} onClick={() => runBulk({ type: "enable" })}>
                    Enable
                  </Button>
                )}
                {anyEnabled && (
                  <Button variant="outline" size="sm" disabled={bulkPending} onClick={() => runBulk({ type: "disable" })}>
                    Disable
                  </Button>
                )}
                <Button variant="danger" size="sm" disabled={bulkPending} onClick={() => setBulkDeleteOpen(true)}>
                  Delete
                </Button>
                <Button variant="ghost" size="sm" className="ml-auto" onClick={() => setSelected(new Set())}>
                  Clear selection
                </Button>
              </div>
            )}

            {rows.length === 0 ? (
              <EmptyState
                compact
                icon={null}
                title="No proxy host matches these filters"
                action={
                  <Button variant="secondary" size="sm" onClick={clearFilters}>
                    Clear filters
                  </Button>
                }
              />
            ) : (
              <>
                <div className="hidden overflow-x-auto md:block">
                  <table className="w-full min-w-[1080px] border-collapse text-[13px]">
                    <thead>
                      <tr className="text-left text-xs text-soft">
                        {canWrite && (
                          <th scope="col" className="w-5 border-b border-line py-2 pl-[18px] pr-2">
                            <Checkbox
                              aria-label="Select every host on this page"
                              checked={allSelected ? true : someSelected ? "indeterminate" : false}
                              onCheckedChange={(checked) => toggleAll(checked === true)}
                            />
                          </th>
                        )}
                        <SortHeader label="Host" sortKey="host" alsoLabel="Name" alsoSortKey="name" query={query} onSort={handleSort} className={cn(!canWrite && "pl-[18px]")} />
                        <SortHeader label="Status" sortKey="status" query={query} onSort={handleSort} />
                        {showTraffic && <SortHeader label="Requests, 24h" sortKey="requests" query={query} onSort={handleSort} />}
                        {showTraffic && <SortHeader label="5xx" sortKey="errors" query={query} onSort={handleSort} className="text-right" />}
                        <PlainHeader>Protection</PlainHeader>
                        <PlainHeader>Certificate</PlainHeader>
                        {showTags && <PlainHeader>Tags</PlainHeader>}
                        <th scope="col" className="border-b border-line py-2 pl-1.5 pr-[18px]">
                          <span className="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((row) => {
                        const isSelected = selected.has(row.id);
                        return (
                          <Fragment key={row.id}>
                          {groupHeadings.has(row.id) && (
                            <tr className="bg-panel2">
                              <th scope="colgroup" colSpan={columnCount} className="border-b border-line px-[18px] py-1.5 text-left text-xs font-medium text-muted-foreground">
                                <GroupHeading group={groupHeadings.get(row.id) ?? null} />
                              </th>
                            </tr>
                          )}
                          <tr
                            className={cn(
                              "border-b border-line align-top last:border-b-0 hover:bg-panel2",
                              isSelected && "bg-brand-tint hover:bg-brand-tint",
                              !row.enabled && "text-muted-foreground"
                            )}
                          >
                            {canWrite && (
                              <td className="w-5 py-3 pl-[18px] pr-2">
                                <Checkbox
                                  aria-label={`Select ${primaryDomain(row)}`}
                                  checked={isSelected}
                                  onCheckedChange={(checked) => toggleRow(row.id, checked === true)}
                                />
                              </td>
                            )}
                            <td className={cn("px-2.5 py-3", !canWrite && "pl-[18px]")}>
                              <HostName row={row} />
                            </td>
                            <td className="px-2.5 py-3">
                              <HostStatus row={row} />
                            </td>
                            {showTraffic && (
                              <td className="px-2.5 py-3">
                                <RequestsBar requests={row.traffic?.requests ?? 0} max={maxRequests} />
                              </td>
                            )}
                            {showTraffic && (
                              <td className="px-2.5 py-3 text-right">
                                <ErrorRate row={row} />
                              </td>
                            )}
                            <td className="px-2.5 py-3">
                              <ProtectionPills protections={row.protections} />
                            </td>
                            <td className="whitespace-nowrap px-2.5 py-3">
                              <CertificateSummary certificate={row.certificate} />
                            </td>
                            {showTags && (
                              <td className="px-2.5 py-3">
                                <TagChips tags={row.tags} onSelect={(tag) => !query.tags.includes(tag) && toggleTag(tag)} />
                              </td>
                            )}
                            <td className="py-2.5 pl-1.5 pr-[18px] text-right">{actionsMenu(row)}</td>
                          </tr>
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <ul className="flex flex-col md:hidden" aria-label="Proxy hosts">
                  {rows.map((row) => (
                    <Fragment key={row.id}>
                    {groupHeadings.has(row.id) && (
                      <li role="presentation" className="border-b border-line bg-panel2 px-4 py-1.5 text-xs font-medium text-muted-foreground">
                        <GroupHeading group={groupHeadings.get(row.id) ?? null} />
                      </li>
                    )}
                    <li
                      className={cn(
                        "flex items-start gap-3 border-b border-line px-4 py-3.5 last:border-b-0",
                        selected.has(row.id) && "bg-brand-tint"
                      )}
                    >
                      {canWrite && (
                        <Checkbox
                          className="mt-0.5"
                          aria-label={`Select ${primaryDomain(row)}`}
                          checked={selected.has(row.id)}
                          onCheckedChange={(checked) => toggleRow(row.id, checked === true)}
                        />
                      )}
                      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                        <HostName row={row} />
                        <HostStatus row={row} />
                        {showTraffic && row.traffic && (
                          <span className="text-xs text-soft">
                            <span className="num text-muted-foreground">{formatCount(row.traffic.requests)}</span> requests in 24 hours ·{" "}
                            <ErrorRate row={row} /> 5xx
                          </span>
                        )}
                        <ProtectionPills protections={row.protections} />
                        {row.tags.length > 0 && <TagChips tags={row.tags} />}
                      </div>
                      <div className="shrink-0">{actionsMenu(row)}</div>
                    </li>
                    </Fragment>
                  ))}
                </ul>
              </>
            )}

            <Pagination
              page={page}
              perPage={perPage}
              total={total}
              noun="hosts"
              label="Pages of hosts"
              hrefFor={hrefFor}
              className="border-t border-line px-[18px] py-3"
            />
          </section>
        </>
      )}

      <CreateHostDialog
        key={dialogKey}
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          setTimeout(() => {
            setDuplicateHost(null);
            setInitialDomain(null);
          }, 200);
          router.refresh();
        }}
        initialData={duplicateHost}
        initialDomain={initialDomain}
        certificates={certificates}
        accessLists={accessLists}
        authentikDefaults={authentikDefaults}
        forwardAuthDefaults={forwardAuthDefaults}
        caCertificates={caCertificates}
        mtlsRoles={mtlsRoles ?? []}
        issuedClientCerts={issuedClientCerts ?? []}
        forwardAuthUsers={forwardAuthUsers ?? []}
        forwardAuthGroups={forwardAuthGroups ?? []}
        scopeTags={scopeTags}
        approval={approval}
      />

      {editHost && (
        <EditHostDialog
          open={!!editHost}
          host={editHost}
          onClose={() => {
            setEditHost(null);
            router.refresh();
          }}
          certificates={certificates}
          accessLists={accessLists}
          authentikDefaults={authentikDefaults}
          forwardAuthDefaults={forwardAuthDefaults}
          caCertificates={caCertificates}
          mtlsRoles={mtlsRoles ?? []}
          issuedClientCerts={issuedClientCerts ?? []}
          forwardAuthUsers={forwardAuthUsers ?? []}
          forwardAuthGroups={forwardAuthGroups ?? []}
          forwardAuthAccess={forwardAuthAccessMap?.[editHost.id] ?? null}
          scopeTags={scopeTags}
          approval={approval}
        />
      )}

      {deleteHost && (
        <DeleteHostDialog
          open={!!deleteHost}
          host={deleteHost}
          onClose={() => {
            setDeleteHost(null);
            router.refresh();
          }}
          approval={approval}
        />
      )}

      <AppDialog
        open={bulkDeleteOpen}
        onClose={() => setBulkDeleteOpen(false)}
        title={`Delete ${plural(selectedRows.length, "proxy host")}`}
        maxWidth="md"
        submitLabel="Delete"
        isSubmitting={bulkPending}
        onSubmit={() => runBulk({ type: "delete" })}
      >
        <div className="flex flex-col gap-3 text-sm">
          <p>These hosts stop serving their domains:</p>
          <ul className="flex max-h-48 flex-col gap-1 overflow-y-auto rounded-lg border border-line bg-panel2 px-3 py-2">
            {selectedRows.map((row) => (
              <li key={row.id} className="num [overflow-wrap:anywhere]">
                {primaryDomain(row)}
                {row.name !== primaryDomain(row) && <span className="ml-1.5 font-sans text-soft">{row.name}</span>}
              </li>
            ))}
          </ul>
          {approval && approval.policies.length > 0 && (
            <p className="text-muted-foreground">Hosts a change approval policy protects get a change request instead.</p>
          )}
          <p className="font-medium text-bad">This cannot be undone.</p>
        </div>
      </AppDialog>
    </div>
  );
}
