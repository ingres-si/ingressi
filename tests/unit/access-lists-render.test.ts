/**
 * Server-side render of the Access lists pages: the list of lists (what each
 * list does, where it is used, the 24-hour counts, the Blocked sources tab,
 * pages), a list's page (rules then Everyone else, warnings, read-only) and
 * the Blocked sources tab.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const nav = vi.hoisted(() => ({ search: '' }));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/access-lists',
  useSearchParams: () => new URLSearchParams(nav.search),
}));
vi.mock('@/app/(dashboard)/access-lists/actions', () => ({
  createAccessListAction: vi.fn(),
  saveAccessListAction: vi.fn(),
  deleteAccessListAction: vi.fn(),
  saveBlockedSourcesAction: vi.fn(),
  blockSourceAction: vi.fn(),
  unblockSourceAction: vi.fn(),
}));

import AccessListsClient from '@/app/(dashboard)/access-lists/AccessListsClient';
import BlockedSourcesClient from '@/app/(dashboard)/access-lists/BlockedSourcesClient';
import { AccessListEditor } from '@/app/(dashboard)/access-lists/AccessListEditor';
import type { AccessList, AccessListRule, AccessListUsage } from '@/src/lib/models/access-lists';
import { emptyAccessListStats, type AccessListStats } from '@/src/lib/access-list-stats';

const STAMP = '2026-10-01T10:00:00.000Z';

function rule(id: number, action: 'allow' | 'deny', kind: AccessListRule['kind'], values: string[], note: string | null = null): AccessListRule {
  return { id, position: id, action, kind, values, note, expiresAt: null, expired: false, createdAt: STAMP, updatedAt: STAMP };
}

function list(id: number, name: string, overrides: Partial<AccessList> = {}): AccessList {
  return {
    id,
    name,
    description: null,
    entries: [],
    rules: [],
    defaultAction: 'allow',
    denyStatus: 403,
    denyBody: null,
    denyRedirectUrl: null,
    failClosed: false,
    skipAuthForAllowed: false,
    system: null,
    createdAt: STAMP,
    updatedAt: STAMP,
    ...overrides,
  };
}

const office = list(1, 'Office and VPN', {
  description: 'Staff networks only',
  defaultAction: 'deny',
  rules: [rule(1, 'allow', 'ip', ['203.0.113.0/26']), rule(2, 'allow', 'ip', ['private_ranges'])],
  entries: [{ id: 5, username: 'alice', createdAt: STAMP }] as AccessList['entries'],
});
const scanners = list(2, 'Block scanners', { rules: [rule(3, 'deny', 'country', ['CN', 'RU'])] });
const hosts: AccessListUsage[] = [
  { id: 11, name: 'Grafana', domains: ['grafana.example.com'], enabled: true },
  { id: 12, name: 'Wiki', domains: ['wiki.example.com'], enabled: true },
  { id: 13, name: 'Git', domains: ['git.example.com'], enabled: false },
];

function stats(available: boolean): AccessListStats {
  const base = emptyAccessListStats([{ id: 1, basicAuth: true, hosts: hosts.map((host) => ({ id: host.id, domains: host.domains })) }], available);
  if (available) {
    base.lists[1] = { stopped: 1234, failedSignIns: 7, hosts: { 11: { stopped: 1200, failedSignIns: 7 }, 12: { stopped: 34, failedSignIns: 0 } } };
  }
  return base;
}

function renderList(props: Partial<Parameters<typeof AccessListsClient>[0]> = {}) {
  return renderToStaticMarkup(
    createElement(AccessListsClient, {
      lists: [office, scanners],
      usage: { 1: hosts },
      stats: stats(true),
      blockedCount: 4,
      canWrite: true,
      ...props,
    })
  );
}

describe('Access lists: the list of lists', () => {
  it('says what each list does, where it is used and what it stopped', () => {
    nav.search = '';
    const html = renderList();
    expect(html).toContain('New access list');
    for (const column of ['Name', 'What it does', 'Used by', 'Stopped, 24 h']) expect(html).toContain(`>${column}</th>`);
    expect(html).toContain('Allows only 203.0.113.0/26 and private networks · basic auth for 1 user');
    expect(html).toContain('Denies CN and RU');
    expect(html).toContain('href="/access-lists/1"');
    expect(html).toContain('href="/proxy-hosts/11"');
    expect(html).toContain('+1 more');
    expect(html).toContain('1,234');
    expect(html).toContain('7 failed sign-ins');
    expect(html).toContain('Not used');
    // The tabs: this one and the global Blocked sources list.
    expect(html).toContain('aria-label="Access list sections"');
    expect(html).toMatch(/href="\/access-lists\?tab=blocked-sources"[^>]*>Blocked sources/);
  });

  it('leaves out the counts without analytics and the actions when read-only', () => {
    const html = renderList({ stats: stats(false), canWrite: false });
    expect(html).not.toContain('Stopped, 24 h');
    expect(html).not.toContain('New access list');
    expect(html).not.toContain('More actions for');
  });

  it('pages a long list and keeps the search', () => {
    const many = Array.from({ length: 30 }, (_, index) => list(100 + index, `Team ${String(index + 1).padStart(2, '0')}`));
    nav.search = 'page=2';
    const html = renderList({ lists: many, usage: {} });
    expect(html).toContain('Team 26');
    expect(html).not.toContain('Team 25<');
    expect(html).toContain('aria-label="Pages of access lists"');
    nav.search = 'q=team%2001';
    const searched = renderList({ lists: many, usage: {} });
    expect(searched).toContain('Team 01');
    expect(searched).not.toContain('Team 02');
    expect(searched).not.toContain('Pages of access lists');
    nav.search = '';
  });

  it('shows one line and the action when there are no lists', () => {
    const html = renderList({ lists: [], usage: {} });
    expect(html).toContain('No access lists yet');
    expect(html).toContain('New access list');
  });
});

describe('Access lists: a list', () => {
  function renderEditor(target: AccessList, props: Partial<Parameters<typeof AccessListEditor>[0]> = {}) {
    return renderToStaticMarkup(
      createElement(AccessListEditor, {
        list: target,
        usage: hosts,
        listStats: stats(true).lists[1],
        statsAvailable: true,
        canWrite: true,
        trustedProxiesConfigured: false,
        ...props,
      })
    );
  }

  it('shows the rules in order, then everyone else, with the summary and the hosts', () => {
    const html = renderEditor(office);
    expect(html).toContain('Allows only 203.0.113.0/26 and private networks · basic auth for 1 user');
    expect(html).toContain('Checked from the top. The first rule that matches decides.');
    const rules = [...html.matchAll(/data-testid="access-list-rule"/g)].map((match) => match.index ?? 0);
    expect(rules).toHaveLength(2);
    expect(Math.max(...rules)).toBeLessThan(html.indexOf('data-testid="access-list-everyone-else"'));
    expect(html).toContain('Basic auth');
    expect(html).toContain('alice');
    expect(html).toContain('Denied requests');
    expect(html).toContain('href="/proxy-hosts/11"');
    expect(html).toContain('1,200');
    expect(html).toContain('Save list');
    expect(html).toContain('Delete list');
    // Only behind trusted proxies.
    expect(html).not.toContain('Deny when the client address is unknown');
    expect(renderEditor(office, { trustedProxiesConfigured: true })).toContain('Deny when the client address is unknown');
  });

  it('warns about a list that denies everyone', () => {
    const html = renderEditor(list(3, 'Locked', { defaultAction: 'deny' }));
    expect(html).toContain('Denies everyone');
    expect(html).toContain('Every request to its 3 hosts is denied.');
  });

  it('is read-only without access_lists:write', () => {
    const html = renderEditor(office, { canWrite: false });
    expect(html).toContain('Changing access lists needs the access_lists:write permission.');
    expect(html).not.toContain('Save list');
    expect(html).not.toContain('Add rule');
    expect(html).not.toContain('Delete list');
  });
});

describe('Access lists: Blocked sources', () => {
  const blocked = list(9, 'Blocked sources', {
    system: 'blocked_sources',
    rules: [rule(20, 'deny', 'ip', ['198.51.100.19'], 'Scanner'), rule(21, 'deny', 'country', ['KP'])],
  });

  it('lists the entries with their reason, and the denied response', () => {
    const html = renderToStaticMarkup(
      createElement(BlockedSourcesClient, { list: blocked, stopped: 42, listCount: 2, canWrite: true, trustedProxiesConfigured: false })
    );
    expect(html).toContain('Denied on every host before anything else');
    expect(html).toContain('>42<');
    expect(html).toContain('198.51.100.19');
    expect(html).toContain('Scanner');
    expect(html).toContain('KP · North Korea');
    expect(html).toContain('Block a source');
    expect(html).toContain('403 · Forbidden');
    expect(html).toMatch(/href="\/access-lists\?tab=blocked-sources"[^>]*aria-current="page"|aria-current="page"[^>]*href="\/access-lists\?tab=blocked-sources"/);
  });

  it('shows one line when nothing is blocked, and no actions when read-only', () => {
    const html = renderToStaticMarkup(
      createElement(BlockedSourcesClient, { list: { ...blocked, rules: [] }, stopped: null, listCount: 2, canWrite: false, trustedProxiesConfigured: false })
    );
    expect(html).toContain('Nothing is blocked');
    expect(html).not.toContain('Block a source');
    expect(html).not.toContain('requests stopped');
  });
});
