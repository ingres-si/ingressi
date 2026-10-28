/**
 * Compliance reports (ee/compliance): the contents of each report against a
 * seeded install, findings, the SHA-256 of the canonical JSON and its
 * stability, the integrity check against the audit log, CSV and JSON
 * exports, reading, downloading and deleting stored reports, validation,
 * and that no secret ever appears in a report.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import * as schema from '../../src/lib/db/schema';
import { API_TOKEN_HASH, SECRETS, pemKeyOfTestCertificates, seedCompliance, type Seed } from '../helpers/compliance';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));

vi.mock('../../src/lib/api-auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/api-auth')>();
  return { ...actual, requireApiPermission: vi.fn((request: unknown) => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireApiAdmin(request))), requireApiAdmin: vi.fn() };
});

import { requireApiAdmin } from '../../src/lib/api-auth';
import { logAuditEvent } from '../../src/lib/audit';
import { insertAuditEvent } from '../../src/lib/audit-chain';
import { ADMIN_LEVEL_PERMISSIONS, PERMISSION_AREAS, isAdminLevel } from '../../src/lib/permissions';
import { canonicalJson, sha256Hex } from '../../ee/compliance/canonical';
import { buildReportDocument, csvSections, generateReport, getReport, reportCsv, reportJson } from '../../ee/compliance/reports';
import type { AnalyticsDependencies } from '../../ee/compliance/reports/shared';
import type { ComplianceReportDocument, ReportSection, ReportType, StoredReportDetail } from '../../ee/compliance/types';
import * as reportsRoute from '../../app/api/v1/compliance/reports/route';
import * as reportRoute from '../../app/api/v1/compliance/reports/[id]/route';
import * as exportRoute from '../../app/api/v1/compliance/reports/[id]/export/route';
import * as controlsRoute from '../../app/api/v1/compliance/controls/route';
import { first as dbFirst } from '@/src/lib/db/ops';

const NOW = new Date('2026-09-30T12:00:00.000Z');
let seed: Seed;

function req(method: string, path: string, body?: unknown): NextRequest {
  const init: { method: string; headers: Record<string, string>; body?: string } = { method, headers: {} };
  if (body !== undefined) {
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
    init.headers['content-type'] = 'application/json';
  }
  return new NextRequest(`http://localhost${path}`, init);
}
const params = (id: string | number) => ({ params: Promise.resolve({ id: String(id) }) });

const noAnalytics: AnalyticsDependencies = { analyticsEnabled: () => false, query: async () => [] };
const fixed = (overrides: Record<string, unknown> = {}) => ({ now: () => NOW, analytics: noAnalytics, uuid: () => '00000000-0000-4000-8000-000000000001', ...overrides });

async function build(type: ReportType, analytics: AnalyticsDependencies = noAnalytics): Promise<ComplianceReportDocument> {
  return buildReportDocument(
    { type, from: new Date('2026-09-01T00:00:00.000Z'), to: NOW },
    { userId: seed.adminId, name: 'Alice Admin', email: 'admin@example.com' },
    fixed({ analytics })
  );
}

function sectionOf(document: ComplianceReportDocument, key: string): ReportSection {
  const found = document.sections.find((item) => item.key === key);
  if (!found) throw new Error(`no section ${key}`);
  return found;
}

function rowOf(section: ReportSection, column: string, value: unknown) {
  const row = section.rows.find((candidate) => candidate[column] === value);
  if (!row) throw new Error(`no row with ${column}=${String(value)} in ${section.key}`);
  return row;
}

function codes(document: ComplianceReportDocument): string[] {
  return document.findings.map((item) => `${item.code}@${item.subject}`);
}

beforeEach(async () => {
  ctx.db = createTestDb();
  vi.clearAllMocks();
  seed = await seedCompliance(ctx.db, NOW);
  vi.mocked(requireApiAdmin).mockResolvedValue({ userId: seed.adminId, role: 'admin', authMethod: 'bearer' });
});

describe('access review', () => {
  it('lists every user with role, permissions, scope, MFA, sign-in, identities, tokens and groups', async () => {
    const document = await build('access_review');
    const users = sectionOf(document, 'users');
    expect(users.rows).toHaveLength(5);

    const alice = rowOf(users, 'email', 'admin@example.com');
    expect(alice).toMatchObject({ role: 'admin', administrator: true, permissions: ['all'], mfa: 'enrolled', passwordSignIn: true, apiTokens: 2, flags: [] });
    expect(alice.lastSignInAt).toBe('2026-09-28T12:00:00.000Z');

    const erin = rowOf(users, 'email', 'erin@example.com');
    expect(erin).toMatchObject({
      role: 'custom: Team A',
      administrator: false,
      permissions: ['proxy_hosts:read', 'proxy_hosts:write'],
      scopeTags: ['team-a'],
      ssoIdentities: ['Corporate IdP'],
      forwardAuthGroups: ['Operators'],
      passwordSignIn: false,
    });
    // A dashboard session counts as a sign-in.
    expect(erin.lastSignInAt).toBe('2026-09-28T12:00:00.000Z');

    expect(rowOf(users, 'email', 'dave@example.com')).toMatchObject({ status: 'disabled', flags: [] });

    const groups = sectionOf(document, 'forward_auth_groups');
    expect(rowOf(groups, 'name', 'Operators')).toMatchObject({ memberCount: 1, hosts: ['Admin panel'] });
    expect(rowOf(sectionOf(document, 'custom_roles'), 'name', 'Team A')).toMatchObject({ users: 1, administratorLevel: false });
  });

  it('flags administrators without MFA, inactive accounts and unused or expired tokens', async () => {
    const document = await build('access_review');
    expect(codes(document)).toEqual(expect.arrayContaining([
      `admin_without_mfa@user:${seed.adminNoMfaId}`,
      `inactive_90_days@user:${seed.inactiveId}`,
      `token_unused_90_days@api_token:${seed.unusedTokenId}`,
      `token_expired@api_token:${seed.expiredTokenId}`,
    ]));
    expect(codes(document)).not.toContain(`admin_without_mfa@user:${seed.adminId}`);
    expect(codes(document)).not.toContain(`token_unused_90_days@api_token:${seed.usedTokenId}`);
    // A disabled account is never flagged as inactive; a new one is not either.
    expect(codes(document).filter((code) => code.startsWith('inactive_90_days'))).toEqual([`inactive_90_days@user:${seed.inactiveId}`]);
    expect(document.findings[0].severity).toBe('high');

    const summary = Object.fromEntries(document.summary.map((item) => [item.key, item.value]));
    expect(summary).toMatchObject({ users: 5, activeUsers: 4, administrators: 2, administratorsWithoutMfa: 1, inactiveUsers: 1, apiTokens: 3, apiTokensUnused: 1, apiTokensExpired: 1 });
    expect(summary.mfaCoveragePercent).toBe(25);
  });

  it('counts an administrator-level custom role as an administrator', async () => {
    const t = NOW.toISOString();
    const role = (await dbFirst(ctx.db.insert(schema.customRoles).values({ name: 'Security', permissions: JSON.stringify(['sso:read', 'sso:write']), scopeTags: '[]', createdAt: t, updatedAt: t }).returning()))!;
    const user = (await dbFirst(ctx.db.insert(schema.users).values({ email: 'frank@example.com', name: 'Frank', role: 'viewer', customRoleId: role.id, status: 'active', createdAt: t, updatedAt: t }).returning()))!;
    const document = await build('access_review');
    expect(codes(document)).toContain(`admin_without_mfa@user:${user.id}`);
  });

  it('lists access changes of the period but not sign-ins', async () => {
    await ctx.db.insert(schema.auditEvents).values([
      { userId: seed.adminId, action: 'update', entityType: 'user', entityId: seed.customId, summary: 'Changed role of erin', createdAt: '2026-09-10T10:00:00.000Z' },
      { userId: seed.adminId, action: 'mfa_verification_failed', entityType: 'user', summary: 'Wrong code', createdAt: '2026-09-11T10:00:00.000Z' },
      { userId: seed.adminId, action: 'update', entityType: 'user', summary: 'Before the period', createdAt: '2026-08-01T10:00:00.000Z' },
    ]);
    const changes = sectionOf(await build('access_review'), 'access_changes');
    expect(changes.rows.map((row) => row.summary)).toEqual(['Changed role of erin']);
  });
});

describe('change log', () => {
  it('groups the period by area and actor and verifies the hash chain', async () => {
    await insertAuditEvent({ userId: seed.adminId, action: 'create', entityType: 'proxy_host', entityId: 1, summary: 'Created proxy host App' });
    await insertAuditEvent({ userId: seed.adminId, action: 'update', entityType: 'certificate', entityId: 1, summary: 'Updated certificate' });
    await insertAuditEvent({ userId: null, action: 'login_success', entityType: 'session', summary: 'Signed in' });
    const document = await buildReportDocument(
      { type: 'change_log', from: new Date(Date.now() - 60_000), to: new Date(Date.now() + 60_000) },
      { userId: seed.adminId, name: 'Alice Admin', email: 'admin@example.com' },
      { analytics: noAnalytics }
    );
    const summary = Object.fromEntries(document.summary.map((item) => [item.key, item.value]));
    expect(summary).toMatchObject({ events: 3, changes: 2, signIns: 1, chainVerified: true, unchainedEventsInPeriod: 0 });
    const areas = sectionOf(document, 'by_area').rows.map((row) => row.area);
    expect(areas).toEqual(expect.arrayContaining(['Proxy hosts', 'Certificates and mTLS', 'Sign-in']));
    const actors = sectionOf(document, 'by_actor');
    expect(rowOf(actors, 'userId', seed.adminId)).toMatchObject({ events: 2, changes: 2 });
    expect(rowOf(actors, 'userId', null)).toMatchObject({ actor: 'System or deleted account', signIns: 1 });
    const integrity = Object.fromEntries(sectionOf(document, 'integrity').rows.map((row) => [row.item, row.value]));
    expect(integrity.Result).toBe('intact');
    expect(document.findings.filter((item) => item.severity === 'high')).toEqual([]);
  });

  it('reports a broken chain as a high finding', async () => {
    const first = await insertAuditEvent({ userId: seed.adminId, action: 'create', entityType: 'proxy_host', summary: 'Created' });
    await insertAuditEvent({ userId: seed.adminId, action: 'delete', entityType: 'proxy_host', summary: 'Deleted' });
    await ctx.db.update(schema.auditEvents).set({ summary: 'Rewritten history' }).where(eq(schema.auditEvents.id, first));
    const document = await buildReportDocument(
      { type: 'change_log', from: new Date(Date.now() - 60_000), to: new Date(Date.now() + 60_000) },
      { userId: seed.adminId, name: null, email: null },
      { analytics: noAnalytics }
    );
    expect(codes(document)).toContain(`audit_chain_broken@audit_event:${first}`);
    expect(document.findings[0]).toMatchObject({ severity: 'high', code: 'audit_chain_broken' });
  });

  it('notes events in the period that predate the hash chain', async () => {
    const document = await build('change_log');
    // The seeded sign-ins were inserted without hashes.
    expect(codes(document)).toContain('audit_events_unchained@audit_log');
  });
});

describe('certificate inventory', () => {
  it('describes imported, managed and automatic certificates, CAs and client certificates', async () => {
    const document = await build('certificate_inventory');
    const server = sectionOf(document, 'server_certificates');
    const app = rowOf(server, 'name', 'App certificate');
    expect(app).toMatchObject({ kind: 'imported', keyType: 'RSA 1024', status: 'valid', privateKeyStored: true });
    expect(app.subject).toContain('CN=app.example.com');
    expect(app.issuer).toContain('O=Example Test CA');
    expect(app.names).toEqual(['app.example.com', '*.app.example.com']);
    expect(app.usedBy).toEqual(['App (app.example.com)']);
    expect(String(app.fingerprintSha256)).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

    expect(rowOf(server, 'name', 'Old certificate')).toMatchObject({ status: 'expired', usedBy: [] });
    expect(rowOf(server, 'name', 'Managed wildcard')).toMatchObject({ kind: 'managed (ACME)', issuer: "Let's Encrypt (ACME)", renewal: 'automatic, DNS-01 (cloudflare)' });
    expect(rowOf(server, 'name', 'Host "Legacy"')).toMatchObject({ kind: 'automatic HTTPS (ACME)', names: ['legacy.example.com'] });
    // Caddy requests nothing for a disabled host, or for a managed certificate no host uses.
    expect(server.rows.find((row) => row.name === 'Host "Shop"')).toBeUndefined();
    expect(codes(document)).toContain(`certificate_unused@certificate:${seed.managedCertId}`);

    const ca = rowOf(sectionOf(document, 'ca_certificates'), 'name', 'Client CA');
    expect(ca).toMatchObject({ status: 'expiring', canIssue: true, issuedActive: 1, issuedRevoked: 1 });
    expect(rowOf(sectionOf(document, 'client_certificates'), 'commonName', 'stolen-phone')).toMatchObject({ status: 'revoked' });

    expect(codes(document)).toEqual(expect.arrayContaining([
      `certificate_expired@certificate:${seed.expiredCertId}`,
      `ca_certificate_expiring@ca_certificate:${seed.caId}`,
      `certificate_unused@certificate:${seed.expiredCertId}`,
    ]));
    // An expired certificate no host uses is not high.
    expect(document.findings.find((item) => item.code === 'certificate_expired')?.severity).toBe('medium');
  });

  it('names a custom ACME CA by host only', async () => {
    await ctx.db.insert(schema.settings).values({ key: 'acme', value: JSON.stringify({ caUrl: 'https://acme.example.test/directory?token=x' }), updatedAt: NOW.toISOString() });
    const document = await build('certificate_inventory');
    expect(rowOf(sectionOf(document, 'server_certificates'), 'name', 'Managed wildcard').issuer).toBe('Custom ACME CA (acme.example.test)');
    expect(JSON.stringify(document)).not.toContain('token=x');
  });
});

describe('protection coverage', () => {
  it('shows WAF, authentication, geo blocking, TLS and MFA coverage per host', async () => {
    await ctx.db.insert(schema.settings).values({ key: 'waf', value: JSON.stringify({ enabled: true, mode: 'DetectionOnly', load_owasp_crs: true, custom_directives: '' }), updatedAt: NOW.toISOString() });
    const document = await build('protection_coverage');
    const hosts = sectionOf(document, 'proxy_hosts');
    expect(rowOf(hosts, 'name', 'App')).toMatchObject({ waf: 'blocking', wafSource: 'host (override)', owaspCrs: true, authentication: ['none'], httpsRedirect: true, hsts: 'on', flags: [] });
    expect(rowOf(hosts, 'name', 'Legacy')).toMatchObject({
      waf: 'detection only',
      wafSource: 'global',
      httpsRedirect: false,
      hsts: 'off',
      upstreamTlsVerification: 'skipped',
      flags: ['waf_detection_only', 'https_redirect_off', 'hsts_off', 'upstream_tls_unverified'],
    });
    const admin = rowOf(hosts, 'name', 'Admin panel');
    expect(admin).toMatchObject({ waf: 'off', wafSource: 'engine set to Off for this host', geoBlocking: true, geoBlockingSource: 'host (override)' });
    expect(admin.authentication).toEqual([
      'access list: Staff',
      'built-in forward auth (0 user(s), 1 group(s) allowed)',
      'mTLS client certificates (1 trusted certificate(s), role(s) or CA(s))',
    ]);
    // Disabled hosts are listed but not flagged.
    expect(rowOf(hosts, 'name', 'Shop')).toMatchObject({ enabled: false, flags: [] });

    expect(codes(document)).toEqual(expect.arrayContaining([
      `waf_off@proxy_host:${seed.hostAuthId}`,
      `waf_detection_only@proxy_host:${seed.hostOpenId}`,
      `https_redirect_off@proxy_host:${seed.hostOpenId}`,
      `upstream_tls_unverified@proxy_host:${seed.hostOpenId}`,
      'admins_without_mfa@users',
    ]));
    const summary = Object.fromEntries(document.summary.map((item) => [item.key, item.value]));
    expect(summary).toMatchObject({ proxyHosts: 4, enabledProxyHosts: 3, wafBlocking: 1, wafDetectionOnly: 1, wafOff: 1, authenticated: 1, adminMfaCoveragePercent: 50 });
    expect(document.notes.join(' ')).toContain('ClickHouse analytics is not configured');
  });

  it('counts geo blocking only where something is blocked, leaving a disabled global config out of merged hosts', async () => {
    const geo = (patch: Record<string, unknown>) => ({
      enabled: true, block_countries: [], block_continents: [], block_asns: [], block_cidrs: [], block_ips: [],
      allow_countries: [], allow_continents: [], allow_asns: [], allow_cidrs: [], allow_ips: [],
      trusted_proxies: [], fail_closed: false, response_status: 403, response_body: 'Forbidden', response_headers: {}, redirect_url: '',
      ...patch,
    });
    const setHostGeo = async (id: number, geoblock: object, mode: 'merge' | 'override') => {
      const [row] = await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, id));
      const meta = { ...JSON.parse(row.meta as string), geoblock, geoblock_mode: mode };
      await ctx.db.update(schema.proxyHosts).set({ meta: JSON.stringify(meta) }).where(eq(schema.proxyHosts.id, id));
    };
    const geoOf = (document: ComplianceReportDocument, name: string) => {
      const { geoBlocking, geoBlockingSource } = rowOf(sectionOf(document, 'proxy_hosts'), 'name', name);
      return { geoBlocking, geoBlockingSource };
    };
    // Admin panel: allow rules alone (override). App: its own block rules, merged. Legacy: no geo blocking of its own.
    await setHostGeo(seed.hostAuthId, geo({ allow_countries: ['AT'] }), 'override');
    await setHostGeo(seed.hostWafId, geo({ block_countries: ['CN'] }), 'merge');

    // The global rules are saved but turned off: no host uses them.
    await ctx.db.insert(schema.settings).values({ key: 'geoblock', value: JSON.stringify(geo({ enabled: false, block_countries: ['RU'] })), updatedAt: NOW.toISOString() });
    let document = await build('protection_coverage');
    expect(geoOf(document, 'Admin panel')).toEqual({ geoBlocking: false, geoBlockingSource: 'no block rules' });
    expect(geoOf(document, 'App')).toEqual({ geoBlocking: true, geoBlockingSource: 'host' });
    expect(geoOf(document, 'Legacy')).toEqual({ geoBlocking: false, geoBlockingSource: 'not enabled' });
    expect(document.summary.find((item) => item.key === 'geoBlocking')?.value).toBe(1);

    // Turned on, they apply to every host that does not override them.
    await ctx.db.update(schema.settings).set({ value: JSON.stringify(geo({ block_countries: ['RU'] })) }).where(eq(schema.settings.key, 'geoblock'));
    document = await build('protection_coverage');
    expect(geoOf(document, 'Admin panel')).toEqual({ geoBlocking: false, geoBlockingSource: 'no block rules' });
    expect(geoOf(document, 'App')).toEqual({ geoBlocking: true, geoBlockingSource: 'global + host' });
    expect(geoOf(document, 'Legacy')).toEqual({ geoBlocking: true, geoBlockingSource: 'global' });
    expect(document.summary.find((item) => item.key === 'geoBlocking')?.value).toBe(2);
  });

  it('lists the addresses that skip sign-in, apart from the paths a sign-in is limited to', async () => {
    const [row] = await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, seed.hostAuthId));
    const meta = JSON.parse(row.meta as string);
    meta.cpm_forward_auth.bypass_sources = ['192.168.1.0/24', 'private_ranges', '0.0.0.0/0', 'nonsense'];
    await ctx.db.update(schema.proxyHosts).set({ meta: JSON.stringify(meta) }).where(eq(schema.proxyHosts.id, seed.hostAuthId));

    const hosts = sectionOf(await build('protection_coverage'), 'proxy_hosts');
    // Only what the sign-in would accept from storage, and not counted as a limit to some paths.
    expect(rowOf(hosts, 'name', 'Admin panel')).toMatchObject({ signInSkippedForAddresses: ['192.168.1.0/24', 'private_ranges'], authenticationLimitedToPaths: false });
    expect(rowOf(hosts, 'name', 'App')).toMatchObject({ signInSkippedForAddresses: [] });
    expect(JSON.stringify(hosts.columns)).toContain('Sign-in skipped for these addresses');
  });

  it('adds WAF activity per host from aggregated ClickHouse figures', async () => {
    const queries: string[] = [];
    const analytics: AnalyticsDependencies = {
      analyticsEnabled: () => true,
      query: async <T,>(query: string) => {
        queries.push(query);
        return [{ h: 'app.example.com', blocked: '12', detected: '3' }, { h: 'legacy.example.com', blocked: '0', detected: '7' }] as T[];
      },
    };
    const hosts = sectionOf(await build('protection_coverage', analytics), 'proxy_hosts');
    expect(rowOf(hosts, 'name', 'App')).toMatchObject({ wafBlockedInPeriod: 12, wafDetectedInPeriod: 3 });
    expect(rowOf(hosts, 'name', 'Legacy')).toMatchObject({ wafBlockedInPeriod: 0, wafDetectedInPeriod: 7 });
    expect(queries.join('\n')).not.toMatch(/client_ip|raw_data/);
  });
});

describe('integrity', () => {
  it('stores the canonical JSON with its SHA-256 and records the hash in the audit log', async () => {
    const { detail } = await generateReport({ type: 'access_review', from: '2026-09-01', to: '2026-09-30' }, seed.adminId, fixed());
    const row = (await dbFirst(ctx.db.select().from(schema.complianceReports).where(eq(schema.complianceReports.id, detail.id)).limit(1)))!;
    expect(row.content).toBe(canonicalJson(JSON.parse(row.content)));
    expect(row.sha256).toBe(sha256Hex(row.content));
    expect(detail.sha256).toBe(row.sha256);
    expect(detail.document.generatedBy).toEqual({ userId: seed.adminId, name: 'Alice Admin', email: 'admin@example.com' });
    expect(detail.document.product.name).toBe('Ingressi');
    expect(detail.document.period).toEqual({ from: '2026-09-01T00:00:00.000Z', to: '2026-09-30T12:00:00.000Z' });
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      action: 'compliance_report_generated',
      entityType: 'compliance_report',
      entityId: detail.id,
      userId: seed.adminId,
      data: expect.objectContaining({ sha256: row.sha256, type: 'access_review', reportId: detail.reportId }),
    }));
  });

  it('gives the same hash for the same data and a different one when anything changes', async () => {
    const a = canonicalJson(await build('access_review'));
    const b = canonicalJson(await build('access_review'));
    expect(sha256Hex(a)).toBe(sha256Hex(b));
    await ctx.db.update(schema.users).set({ name: 'Bob Renamed' }).where(eq(schema.users.id, seed.adminNoMfaId));
    expect(sha256Hex(canonicalJson(await build('access_review')))).not.toBe(sha256Hex(a));
  });

  it('lets anyone recompute the hash of a downloaded JSON report', async () => {
    const { detail } = await generateReport({ type: 'certificate_inventory' }, seed.adminId, fixed());
    const downloaded = JSON.parse(reportJson(detail));
    expect(downloaded.integrity).toMatchObject({ algorithm: 'SHA-256', sha256: detail.sha256 });
    delete downloaded.integrity;
    expect(sha256Hex(canonicalJson(downloaded))).toBe(detail.sha256);
  });

  it('checks the stored content against the audit log', async () => {
    const actual = await vi.importActual<typeof import('../../src/lib/audit')>('../../src/lib/audit');
    vi.mocked(logAuditEvent).mockImplementation(actual.logAuditEvent);
    const { detail } = await generateReport({ type: 'protection_coverage' }, seed.adminId, fixed());
    let read = await getReport(detail.id);
    expect(read.integrity).toMatchObject({ contentMatches: true, auditEvent: { sha256Matches: true } });

    // Changing the stored report without its hash, or both, is detected.
    const tampered = read.document;
    tampered.summary[0].value = 999;
    await ctx.db.update(schema.complianceReports).set({ content: canonicalJson(tampered) }).where(eq(schema.complianceReports.id, detail.id));
    read = await getReport(detail.id);
    expect(read.integrity.contentMatches).toBe(false);
    const content = canonicalJson(tampered);
    await ctx.db.update(schema.complianceReports).set({ sha256: sha256Hex(content) }).where(eq(schema.complianceReports.id, detail.id));
    read = await getReport(detail.id);
    expect(read.integrity).toMatchObject({ contentMatches: true, auditEvent: { sha256Matches: false } });
  });
});

describe('secrets', () => {
  it('never puts a secret into any report, JSON export or CSV table', async () => {
    const outputs: string[] = [];
    for (const type of ['access_review', 'change_log', 'certificate_inventory', 'protection_coverage'] as const) {
      const { detail } = await generateReport({ type }, seed.adminId, fixed({ uuid: () => crypto.randomUUID() }));
      outputs.push((await dbFirst(ctx.db.select().from(schema.complianceReports).where(eq(schema.complianceReports.id, detail.id)).limit(1)))!.content);
      outputs.push(reportJson(detail));
      for (const key of csvSections(detail.document)) outputs.push(reportCsv(detail, key).body);
    }
    const everything = outputs.join('\n');
    for (const secret of [...Object.values(SECRETS), API_TOKEN_HASH, pemKeyOfTestCertificates()]) {
      expect(everything).not.toContain(secret);
    }
    expect(everything).not.toMatch(/BEGIN (RSA |EC )?PRIVATE KEY/);
    expect(everything).not.toMatch(/BEGIN CERTIFICATE/);
    // Encrypted values are not copied either.
    for (const row of await ctx.db.select().from(schema.certificates)) {
      if (row.privateKeyPem) expect(everything).not.toContain(row.privateKeyPem);
    }
  });
});

describe('CSV', () => {
  it('exports any table and neutralises spreadsheet formulas', async () => {
    await ctx.db.update(schema.users).set({ name: '=HYPERLINK("https://example.com","x")' }).where(eq(schema.users.id, seed.inactiveId));
    const { detail } = await generateReport({ type: 'access_review' }, seed.adminId, fixed());
    const users = reportCsv(detail, null);
    expect(users.section).toBe('users');
    expect(users.body.split('\r\n')[0]).toContain('E-mail');
    expect(users.body).toContain(`"'=HYPERLINK(""https://example.com"",""x"")"`);
    expect(reportCsv(detail, 'summary').body).toContain(detail.sha256);
    expect(reportCsv(detail, 'findings').body).toContain('admin_without_mfa');
    expect(() => reportCsv(detail, 'nope')).toThrow(/section must be one of/);
  });
});

describe('REST API', () => {
  it('generates a report and answers 201 with the report', async () => {
    const response = await reportsRoute.POST(req('POST', '/api/v1/compliance/reports', { type: 'change_log', from: '2026-01-01T00:00:00Z' }));
    expect(response.status).toBe(201);
    const body: StoredReportDetail = await response.json();
    expect(response.headers.get('location')).toBe(`/api/v1/compliance/reports/${body.id}`);
    expect(body.document.type).toBe('change_log');
    expect(body.integrity.contentMatches).toBe(true);

    const list = await (await reportsRoute.GET(req('GET', '/api/v1/compliance/reports?type=change_log'))).json();
    expect(list.total).toBe(1);
    expect(list.reports[0]).not.toHaveProperty('document');
    expect(list.reports[0].sha256).toBe(body.sha256);
  });

  it('answers CSV when asked and on export, with the hash in the headers', async () => {
    const response = await reportsRoute.POST(req('POST', '/x', { type: 'access_review', format: 'csv' }));
    expect(response.status).toBe(201);
    expect(response.headers.get('content-type')).toContain('text/csv');
    expect(response.headers.get('content-disposition')).toMatch(/attachment; filename="access-review-.*-users\.csv"/);
    const id = Number(response.headers.get('location')!.split('/').pop());
    const exported = await exportRoute.GET(req('GET', `/api/v1/compliance/reports/${id}/export?format=csv&section=api_tokens`), params(id));
    expect(exported.status).toBe(200);
    expect(await exported.text()).toContain('forgotten script');
    const json = await exportRoute.GET(req('GET', `/api/v1/compliance/reports/${id}/export`), params(id));
    expect(json.headers.get('x-report-sha256')).toMatch(/^[0-9a-f]{64}$/);
    expect((await json.json()).integrity.sha256).toBe(json.headers.get('x-report-sha256'));
  });

  it('validates the request', async () => {
    const cases: [unknown, RegExp][] = [
      [{ type: 'everything' }, /type must be one of/],
      [{ type: 'access_review', from: '2026-09-10', to: '2026-09-01' }, /from must be before to/],
      [{ type: 'access_review', from: '2024-01-01', to: '2026-01-01' }, /at most 366 days/],
      [{ type: 'access_review', from: '2026-09-01T10:00' }, /time zone/],
      [{ type: 'access_review', format: 'pdf' }, /format must be json or csv/],
      [{ type: 'access_review', extra: 1 }, /Unknown field "extra"/],
      ['not json', /Request body must be JSON/],
    ];
    for (const [body, message] of cases) {
      const response = await reportsRoute.POST(req('POST', '/x', body));
      expect(response.status, JSON.stringify(body)).toBe(400);
      expect((await response.json()).error).toMatch(message);
    }
    expect((await reportRoute.GET(req('GET', '/x'), params('abc'))).status).toBe(404);
    expect((await reportRoute.GET(req('GET', '/x'), params(999))).status).toBe(404);
    expect((await exportRoute.GET(req('GET', '/x?format=xml'), params(1))).status).toBe(400);
  });

  it('caps the period at now', async () => {
    const response = await reportsRoute.POST(req('POST', '/x', { type: 'access_review', from: '2026-09-01', to: '2099-01-01' }));
    expect(response.status).toBe(201);
    const body: StoredReportDetail = await response.json();
    expect(Date.parse(body.period.to)).toBeLessThanOrEqual(Date.now());
  });

  it('returns the control mapping', async () => {
    const body = await (await controlsRoute.GET(req('GET', '/api/v1/compliance/controls'))).json();
    expect(Object.keys(body.mapping)).toEqual(['access_review', 'change_log', 'certificate_inventory', 'protection_coverage', 'traffic_questions', 'incident_notification']);
    expect(body.statement).toMatch(/does not by itself show compliance/);
  });
});

describe('stored reports', () => {
  it('reads, downloads and deletes stored reports', async () => {
    const created: StoredReportDetail = await (await reportsRoute.POST(req('POST', '/x', { type: 'access_review' }))).json();
    expect((await reportsRoute.GET(req('GET', '/x'))).status).toBe(200);
    expect((await reportRoute.GET(req('GET', '/x'), params(created.id))).status).toBe(200);
    expect((await exportRoute.GET(req('GET', '/x?format=csv'), params(created.id))).status).toBe(200);
    expect((await controlsRoute.GET(req('GET', '/x'))).status).toBe(200);
    const deleted = await reportRoute.DELETE(req('DELETE', '/x'), params(created.id));
    expect(deleted.status).toBe(204);
    expect(await ctx.db.select().from(schema.complianceReports)).toHaveLength(0);
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'compliance_report_deleted', data: expect.objectContaining({ sha256: created.sha256 }) }));
  });
});

describe('permissions', () => {
  it('has an instance-wide compliance area that is not administrator-level', () => {
    expect(PERMISSION_AREAS.compliance).toMatchObject({ actions: ['read', 'write'], instanceWide: true });
    expect(ADMIN_LEVEL_PERMISSIONS).not.toContain('compliance:write');
    expect(isAdminLevel(['compliance:read', 'compliance:write'])).toBe(false);
  });

  it('refuses callers without the permission', async () => {
    const { ApiAuthError } = await import('../../src/lib/api-auth');
    vi.mocked(requireApiAdmin).mockRejectedValue(new ApiAuthError('Administrator privileges required', 403));
    for (const response of [
      await reportsRoute.GET(req('GET', '/x')),
      await reportsRoute.POST(req('POST', '/x', { type: 'access_review' })),
      await reportRoute.GET(req('GET', '/x'), params(1)),
      await reportRoute.DELETE(req('DELETE', '/x'), params(1)),
      await exportRoute.GET(req('GET', '/x'), params(1)),
    ]) {
      expect(response.status).toBe(403);
    }
    expect(await ctx.db.select().from(schema.complianceReports)).toHaveLength(0);
  });
});
