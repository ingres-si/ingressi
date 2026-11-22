"use client";

import { Fragment, type ReactNode, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import {
  ArrowLeftRight, Bell, ChartColumn, ChevronsUpDown, CircleCheck, ClipboardCheck, Coins,
  Ellipsis, FileCheck2, FileJson2, History, KeyRound, Layers, LayoutGrid, LockKeyhole, LogOut, Menu, Network, Palette,
  Plug, ScrollText, Search, Server, ShieldAlert, ShieldCheck, SlidersHorizontal, UserRound, Users, type LucideIcon,
} from "lucide-react";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuRadioGroup,
  DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { formatAppVersion } from "@/src/lib/app-version";
import {
  NAV_ACCOUNT, NAV_FOOTER, currentEntryKey, visibleEntries, visibleNavGroups,
  type NavBadge, type NavEntryKey, type VisibleNavEntry,
} from "@/src/lib/navigation";
import type { NavEnvironment, NavSummary } from "@/src/lib/nav-summary";
import { useBranding } from "@/ee/white-label/ui/BrandingProvider";
import { BrandLogo, hasLogo, PoweredBy, SupportLinks } from "@/ee/white-label/ui/BrandParts";
import { CommandPaletteProvider, useCommandPalette } from "@/components/command-palette/CommandPalette";

type User = {
  id: string;
  name?: string | null;
  email?: string | null;
  image?: string | null;
  role?: string;
  /** Permissions the user holds (src/lib/permissions.ts); every one for administrators. */
  permissions?: readonly string[];
  /** The built-in admin role. */
  isAdmin?: boolean;
};

const EMPTY_SUMMARY: NavSummary = { badges: {}, environment: null };

const ICONS: Record<NavEntryKey, LucideIcon> = {
  overview: LayoutGrid,
  "proxy-hosts": ArrowLeftRight,
  "l4-hosts": Server,
  certificates: ShieldCheck,
  "access-lists": KeyRound,
  analytics: ChartColumn,
  security: ShieldAlert,
  alerts: Bell,
  "audit-log": ScrollText,
  users: Users,
  "sign-in": LockKeyhole,
  "access-reviews": ClipboardCheck,
  approvals: CircleCheck,
  history: History,
  compliance: FileCheck2,
  fleet: Network,
  "high-availability": Layers,
  monetization: Coins,
  settings: SlidersHorizontal,
  mcp: Plug,
  branding: Palette,
  profile: UserRound,
  "api-docs": FileJson2,
};

/** The phone's bottom navigation: these entries when the user may open them, then More. */
const BOTTOM_TABS: { key: NavEntryKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "proxy-hosts", label: "Hosts" },
  { key: "analytics", label: "Analytics" },
  { key: "security", label: "Security" },
];

function initials(name: string): string {
  const parts = name.trim().split(/[\s._@-]+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : name.trim().slice(0, 2);
  return letters.toUpperCase() || "U";
}

function NavBadgeView({ badge, plain }: { badge: NavBadge; plain?: boolean }) {
  if (plain) {
    return (
      <span className="shrink-0 text-xs text-soft">
        <span aria-hidden="true">{badge.text}</span>
        <span className="sr-only">{badge.label}</span>
      </span>
    );
  }
  return (
    <span
      className={cn(
        "num shrink-0 rounded-full px-1.5 text-[11px] font-semibold leading-[18px]",
        badge.tone === "warn" ? "bg-warn-tint text-warn" : "bg-raise text-muted-foreground",
      )}
    >
      <span aria-hidden="true">{badge.text}</span>
      <span className="sr-only">{badge.label}</span>
    </span>
  );
}

function NavLink({
  entry,
  current,
  badge,
  plainBadge,
  onNavigate,
}: {
  entry: VisibleNavEntry;
  current: boolean;
  badge?: NavBadge | null;
  plainBadge?: boolean;
  onNavigate?: () => void;
}) {
  const Icon = ICONS[entry.key];
  return (
    <Link
      href={entry.href}
      onClick={onNavigate}
      // With its pages listed under it, the entry is the current section and a page link is the current page.
      aria-current={current ? (entry.openPages.length > 1 ? "true" : "page") : undefined}
      className={cn(
        "flex h-[34px] items-center gap-2.5 rounded-md px-2.5 text-sm transition-colors max-md:h-11",
        current
          ? "bg-brand-tint font-semibold text-foreground"
          : "font-medium text-muted-foreground hover:bg-raise hover:text-foreground",
      )}
    >
      <Icon className="h-[18px] w-[18px] shrink-0" strokeWidth={1.8} aria-hidden="true" />
      <span className="min-w-0 flex-1 truncate">{entry.label}</span>
      {badge && <NavBadgeView badge={badge} plain={plainBadge} />}
    </Link>
  );
}

/** The page of `pages` that `pathname` is on: the longest matching path. */
function currentPage(pathname: string, pages: readonly { href: string }[]): string | null {
  let best: string | null = null;
  for (const { href } of pages) {
    const matches = href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
    if (matches && (!best || href.length > best.length)) best = href;
  }
  return best;
}

/**
 * The pages an entry stands for, under it while it is current (Settings and
 * Branding, Users and Groups, the sign-in pages), so every page stays one
 * click away whatever the page itself shows.
 */
function SubLinks({ entry, pathname, onNavigate }: { entry: VisibleNavEntry; pathname: string; onNavigate?: () => void }) {
  if (entry.openPages.length < 2) return null;
  const active = currentPage(pathname, entry.openPages);
  return (
    <ul aria-label={entry.label} className="mb-1 ml-[19px] flex flex-col gap-0.5 border-l border-line pl-2">
      {entry.openPages.map((page) => (
        <li key={page.href}>
          <Link
            href={page.href}
            onClick={onNavigate}
            aria-current={active === page.href ? "page" : undefined}
            className={cn(
              "flex h-[30px] items-center rounded-md px-2.5 text-[13px] transition-colors max-md:h-11",
              active === page.href
                ? "font-semibold text-foreground"
                : "text-muted-foreground hover:bg-raise hover:text-foreground",
            )}
          >
            <span className="truncate">{page.label}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function BrandRow() {
  const branding = useBranding();
  return (
    <div className="flex items-center gap-2 px-2 py-1">
      {hasLogo(branding) ? (
        <BrandLogo branding={branding} className="h-7 w-auto max-w-[96px] shrink-0" />
      ) : (
        <span aria-hidden="true" className="grid h-7 w-7 shrink-0 place-items-center rounded-[7px] bg-primary text-primary-foreground">
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
            <path d="M11 8v3M11 17v3M22 8v12M6 14h12M15 11l3 3-3 3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
      )}
      <span className="min-w-0 truncate text-[17px] font-bold tracking-[-0.01em]">{branding.productName}</span>
    </div>
  );
}

function EnvironmentSwitcher({ environment, compact }: { environment: NavEnvironment; compact?: boolean }) {
  const label = `Environment: ${environment.name}, ${environment.note}. Switch environment`;
  const dot = <span aria-hidden="true" className={cn("h-2 w-2 shrink-0 rounded-full", environment.tone === "warn" ? "bg-warn" : "bg-ok")} />;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={label}
        className={cn(
          "flex items-center gap-2.5 rounded-lg border border-line bg-panel2 text-left transition-colors hover:bg-raise",
          compact ? "h-11 px-3" : "w-full px-2.5 py-2",
        )}
        data-testid="environment-switcher"
      >
        {dot}
        {compact ? (
          <span className="max-w-[9rem] truncate font-semibold">{environment.name}</span>
        ) : (
          <span className="flex min-w-0 flex-1 flex-col">
            <span className="truncate font-semibold">{environment.name}</span>
            <span className="truncate text-xs text-muted-foreground">{environment.note}</span>
          </span>
        )}
        <ChevronsUpDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel>{environment.name} · {environment.note}</DropdownMenuLabel>
        {environment.environments.length > 0 && <DropdownMenuSeparator />}
        {environment.environments.map((group) => (
          <DropdownMenuItem key={group.id} asChild>
            <Link href={`/fleet#environment-${group.id}`}>
              <span aria-hidden="true" className={cn("h-2 w-2 shrink-0 rounded-full", group.attention > 0 ? "bg-warn" : "bg-ok")} />
              <span className="min-w-0 flex-1 truncate">{group.name}</span>
              <span className="num text-xs text-soft">
                {group.nodes} {group.nodes === 1 ? "node" : "nodes"}
                {group.attention > 0 ? ` · ${group.attention} need attention` : ""}
              </span>
            </Link>
          </DropdownMenuItem>
        ))}
        {(environment.links.fleet || environment.links.sync) && <DropdownMenuSeparator />}
        {environment.links.fleet && (
          <DropdownMenuItem asChild>
            <Link href="/fleet">Open fleet management</Link>
          </DropdownMenuItem>
        )}
        {environment.links.sync && (
          <DropdownMenuItem asChild>
            <Link href="/instances">{environment.mode === "standalone" ? "Set up instance sync" : "Instance sync settings"}</Link>
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function SearchButton({ onOpen }: { onOpen: () => void }) {
  const [shortcut, setShortcut] = useState("⌘K");
  useEffect(() => {
    if (!/mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent)) setShortcut("Ctrl K");
  }, []);
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex h-9 w-full items-center gap-2 rounded-md border border-line px-2.5 text-left text-muted-foreground transition-colors hover:bg-raise hover:text-foreground max-md:h-11"
      aria-keyshortcuts="Meta+K Control+K"
    >
      <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
      <span className="min-w-0 flex-1 truncate">Search or jump to…</span>
      <kbd className="shrink-0 rounded border border-line2 px-1.5 text-[11px] leading-[18px] text-muted-foreground">{shortcut}</kbd>
    </button>
  );
}

function UserMenu({ user, apiDocs }: { user: User; apiDocs: VisibleNavEntry | null }) {
  const { theme, setTheme } = useTheme();
  const logoutForm = useRef<HTMLFormElement>(null);
  const name = user.name || user.email || "Account";
  return (
    <>
      <form ref={logoutForm} action="/api/auth/logout" method="POST" className="hidden" aria-hidden="true" />
      <DropdownMenu>
        <DropdownMenuTrigger
          aria-label={`Your account: ${name}`}
          className="mt-1.5 flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors hover:bg-raise"
          data-testid="account-menu"
        >
          {user.image ? (
            <img src={user.image} alt="" className="h-[30px] w-[30px] shrink-0 rounded-full object-cover" />
          ) : (
            <span aria-hidden="true" className="grid h-[30px] w-[30px] shrink-0 place-items-center rounded-full bg-raise text-xs font-semibold">
              {initials(name)}
            </span>
          )}
          <span className="flex min-w-0 flex-1 flex-col">
            <span className="truncate font-semibold">{user.name ?? "Administrator"}</span>
            {user.email && <span className="truncate text-xs text-muted-foreground">{user.email}</span>}
          </span>
          <ChevronsUpDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent side="top" align="start" className="w-(--radix-dropdown-menu-trigger-width) min-w-56">
          <DropdownMenuItem asChild>
            <Link href="/profile">
              <UserRound aria-hidden="true" />
              Profile
            </Link>
          </DropdownMenuItem>
          {apiDocs && (
            <DropdownMenuItem asChild>
              <Link href={apiDocs.href}>
                <FileJson2 aria-hidden="true" />
                API reference
              </Link>
            </DropdownMenuItem>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuLabel>Theme</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={theme ?? "dark"} onValueChange={setTheme}>
            <DropdownMenuRadioItem value="dark">Dark</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="light">Light</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="system">Same as the system</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => logoutForm.current?.requestSubmit()}>
            <LogOut aria-hidden="true" />
            Sign out
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className="num font-normal" title="Application version">{formatAppVersion()}</DropdownMenuLabel>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}

function NavContent({
  pathname,
  user,
  summary,
  onNavigate,
}: {
  pathname: string;
  user: User;
  summary: NavSummary;
  onNavigate?: () => void;
}) {
  const branding = useBranding();
  const palette = useCommandPalette();
  const groups = visibleNavGroups(user, summary.badges);
  const footer = visibleEntries(user, NAV_FOOTER, summary.badges);
  const [apiDocs = null] = visibleEntries(user, NAV_ACCOUNT.filter((entry) => entry.key === "api-docs"));
  const current = currentEntryKey(pathname);

  return (
    <div className="flex h-full flex-col gap-3.5 px-3 py-4">
      <BrandRow />
      {summary.environment && <EnvironmentSwitcher environment={summary.environment} />}
      <SearchButton onOpen={() => { onNavigate?.(); palette.open(); }} />

      <nav aria-label="Main navigation" className="-mx-1 flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto px-1">
        {groups.map((group) => (
          <div key={group.title ?? "start"} role="group" aria-label={group.title ?? undefined} className="flex flex-col gap-0.5">
            {group.title && (
              <div aria-hidden="true" className="px-2.5 pb-1 text-[11px] font-semibold uppercase tracking-[0.06em] text-soft">{group.title}</div>
            )}
            {group.entries.map((entry) => (
              <Fragment key={entry.key}>
                <NavLink
                  entry={entry}
                  current={current === entry.key}
                  badge={entry.badge ? summary.badges[entry.badge] : null}
                  onNavigate={onNavigate}
                />
                {current === entry.key && <SubLinks entry={entry} pathname={pathname} onNavigate={onNavigate} />}
              </Fragment>
            ))}
          </div>
        ))}
      </nav>

      <div className="flex flex-col gap-0.5 border-t border-line pt-3">
        {footer.map((entry) => (
          <Fragment key={entry.key}>
            <NavLink
              entry={entry}
              current={current === entry.key}
              badge={entry.badge ? summary.badges[entry.badge] : null}
              plainBadge
              onNavigate={onNavigate}
            />
            {current === entry.key && <SubLinks entry={entry} pathname={pathname} onNavigate={onNavigate} />}
          </Fragment>
        ))}
        <UserMenu user={user} apiDocs={apiDocs} />
        <SupportLinks branding={branding} className="justify-start px-2.5 pt-1" />
        <PoweredBy branding={branding} className="pt-1" />
      </div>
    </div>
  );
}

function BottomNav({ user, summary, pathname, onMore }: { user: User; summary: NavSummary; pathname: string; onMore: () => void }) {
  const entries = new Map(visibleNavGroups(user, summary.badges).flatMap((group) => group.entries).map((entry) => [entry.key, entry]));
  const current = currentEntryKey(pathname);
  const tabs = BOTTOM_TABS.flatMap((tab) => {
    const entry = entries.get(tab.key);
    return entry ? [{ ...tab, href: entry.href }] : [];
  });
  const onTab = tabs.some((tab) => tab.key === current);
  const item = (active: boolean) =>
    cn(
      "flex min-h-[52px] flex-col items-center justify-center gap-0.5 rounded-lg text-[11px] leading-[14px]",
      active ? "font-semibold text-foreground" : "font-medium text-muted-foreground",
    );
  const pill = (active: boolean) => cn("grid h-7 w-[52px] place-items-center rounded-full", active && "bg-brand-tint");
  return (
    <nav
      aria-label="Main"
      className="fixed inset-x-0 bottom-0 z-40 grid gap-0.5 border-t border-line bg-panel px-1 pt-1 pb-[calc(4px+env(safe-area-inset-bottom))] md:hidden"
      style={{ gridTemplateColumns: `repeat(${tabs.length + 1}, minmax(0, 1fr))` }}
    >
      {tabs.map((tab) => {
        const Icon = ICONS[tab.key];
        const active = current === tab.key;
        return (
          <Link key={tab.key} href={tab.href} aria-current={active ? "page" : undefined} className={item(active)}>
            <span className={pill(active)}>
              <Icon className="h-[22px] w-[22px]" strokeWidth={1.8} aria-hidden="true" />
            </span>
            {tab.label}
          </Link>
        );
      })}
      <button type="button" onClick={onMore} className={item(!onTab && current !== null)} aria-haspopup="dialog">
        <span className={pill(!onTab && current !== null)}>
          <Ellipsis className="h-[22px] w-[22px]" strokeWidth={1.8} aria-hidden="true" />
        </span>
        More
      </button>
    </nav>
  );
}

function currentLabel(pathname: string, user: User, summary: NavSummary): string {
  const key = currentEntryKey(pathname);
  if (!key) return "";
  const all = [
    ...visibleNavGroups(user, summary.badges).flatMap((group) => group.entries),
    ...visibleEntries(user, NAV_FOOTER, summary.badges),
    ...visibleEntries(user, NAV_ACCOUNT),
  ];
  return all.find((entry) => entry.key === key)?.label ?? "";
}

function Shell({
  user,
  summary,
  children,
}: { user: User; summary: NavSummary; children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();
  const branding = useBranding();
  const title = currentLabel(pathname, user, summary) || branding.productName;

  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-62 flex-col border-r border-line bg-panel md:flex">
        <NavContent
          pathname={pathname}
          user={user}
          summary={summary}
        />
      </aside>

      <header className="fixed inset-x-0 top-0 z-40 flex h-14 items-center gap-1 border-b border-line bg-panel px-2 pt-[env(safe-area-inset-top)] md:hidden">
        <button
          type="button"
          aria-label="Open navigation"
          onClick={() => setMobileOpen(true)}
          className="grid h-11 w-11 shrink-0 place-items-center rounded-lg transition-colors hover:bg-raise"
        >
          <Menu className="h-[22px] w-[22px]" aria-hidden="true" />
        </button>
        <span className="min-w-0 flex-1 truncate text-[17px] font-semibold tracking-[-0.01em]" data-testid="mobile-title">
          {title}
          <span className="sr-only"> · {branding.productName}</span>
        </span>
        {summary.environment && <EnvironmentSwitcher environment={summary.environment} compact />}
      </header>

      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-[288px] max-w-[85vw] border-r p-0 sm:max-w-[288px]">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <NavContent
            pathname={pathname}
            user={user}
            summary={summary}
            onNavigate={() => setMobileOpen(false)}
          />
        </SheetContent>
      </Sheet>

      {/* overflow-x: clip, not hidden: hidden would make main a scroll container and break position: sticky inside pages. */}
      <main className="mt-14 min-w-0 flex-1 overflow-x-clip pb-24 md:ml-62 md:mt-0 md:pb-0">
        <div className="mx-auto max-w-[1600px] px-4 py-4 md:px-8 md:pt-6 md:pb-14">{children}</div>
      </main>

      <BottomNav user={user} summary={summary} pathname={pathname} onMore={() => setMobileOpen(true)} />
    </div>
  );
}

export default function DashboardLayoutClient({
  user,
  children,
  summary = EMPTY_SUMMARY,
}: { user: User; children: ReactNode; summary?: NavSummary }) {
  return (
    <CommandPaletteProvider userId={user.id}>
      <Shell user={user} summary={summary}>
        {children}
      </Shell>
    </CommandPaletteProvider>
  );
}
