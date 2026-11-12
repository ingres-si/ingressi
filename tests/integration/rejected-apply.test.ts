/**
 * A host change Caddy rejects is taken back (src/lib/rejected-apply.ts): kept,
 * it would make every later apply fail for every host. The one change that
 * stays is an administrator's while Caddy was already refusing the
 * configuration, so a configuration broken in several places can be repaired
 * step by step.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});
// Like the real one, the mock leaves the apply to the batch inside a change batch.
vi.mock('../../src/lib/caddy', async () => {
  const { deferCaddyApplyToBatch } = await import('../../src/lib/change-batch');
  const { noteCaddyApplyFailure } = await import('../../src/lib/apply-observer');
  const push = vi.fn();
  return {
    pushToCaddy: push,
    applyCaddyConfig: vi.fn(async () => {
      if (deferCaddyApplyToBatch()) return;
      try {
        await push();
      } catch (error) {
        noteCaddyApplyFailure(error);
        throw error;
      }
    }),
  };
});
vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

import * as caddy from '../../src/lib/caddy';
import { runAsChangeBatch } from '../../src/lib/change-batch';
import { applyBatchOrUndo, caddyAcceptedLastApply } from '../../src/lib/rejected-apply';
import { undoSettingsCaddyRejects } from '../../src/lib/settings-rollback';
import { getSetting, setSetting } from '../../src/lib/settings';
import { createCertificate, updateCertificate } from '../../src/lib/models/certificates';
import { createCaCertificate, updateCaCertificate } from '../../src/lib/models/ca-certificates';
import { CaddyApplyError } from '../../src/lib/caddy-apply-error';
import { recordCaddyApplyResult, resetCaddyApplyStatusForTests } from '../../src/lib/caddy-apply-status';
import { ApiConflictError, ApiValidationError } from '../../src/lib/api-errors';
import { createProxyHost, updateProxyHost, type ProxyHostInput } from '../../src/lib/models/proxy-hosts';
import { createL4ProxyHost, updateL4ProxyHost, type L4ProxyHostInput } from '../../src/lib/models/l4-proxy-hosts';
import * as schema from '../../src/lib/db/schema';
import { createExternalCa, createSelfSignedServerCertificate, issueExternalClientCertificate, testCa, testServerCertificate } from '../helpers/certs';
import { createIssuedClientCertificate } from '../../src/lib/models/issued-client-certificates';
import { X509Certificate } from 'node:crypto';

const ADMIN = 1;
const OPERATOR = 2;
// What Caddy answers to a push; applyCaddyConfig itself keeps its batch behaviour.
const apply = (caddy as unknown as { pushToCaddy: ReturnType<typeof vi.fn> }).pushToCaddy;
const applyCaddyConfig = caddy.applyCaddyConfig;
const rejected = () => new CaddyApplyError('Caddy rejected configuration', 'CADDY_REJECTED');

const host = (extra: Partial<ProxyHostInput> = {}): ProxyHostInput => ({
  name: 'App', domains: ['app.example.com'], upstreams: ['backend:8080'], sslForced: false, ...extra,
} as ProxyHostInput);
const l4 = (extra: Partial<L4ProxyHostInput> = {}): L4ProxyHostInput => ({
  name: 'Db', protocol: 'tcp', listenAddress: ':5432', upstreams: ['db:5432'], ...extra,
});

async function caddyAccepts() {
  await recordCaddyApplyResult({ ok: true });
}
async function caddyAlreadyRefuses() {
  await recordCaddyApplyResult({ ok: false, code: 'CADDY_REJECTED', message: 'Caddy rejected configuration' });
}

beforeEach(async () => {
  apply.mockReset();
  apply.mockResolvedValue(undefined);
  await ctx.db.delete(schema.wafRuleExclusions);
  await ctx.db.delete(schema.certificates);
  await ctx.db.delete(schema.caCertificates);
  await ctx.db.delete(schema.settings);
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.l4ProxyHosts);
  await ctx.db.delete(schema.users);
  const now = new Date().toISOString();
  await ctx.db.insert(schema.users).values([
    { id: ADMIN, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials', subject: 'a', status: 'active', createdAt: now, updatedAt: now },
    { id: OPERATOR, email: 'op@example.com', name: 'Operator', role: 'user', provider: 'credentials', subject: 'b', status: 'active', createdAt: now, updatedAt: now },
  ]);
  await resetCaddyApplyStatusForTests();
  await caddyAccepts();
});

describe('a proxy host Caddy rejects', () => {
  it('is not kept when created, and the previous configuration is applied again', async () => {
    apply.mockRejectedValueOnce(rejected());
    await expect(createProxyHost(host(), OPERATOR)).rejects.toThrow(ApiValidationError);
    expect(await ctx.db.select().from(schema.proxyHosts)).toEqual([]);
    expect(apply).toHaveBeenCalledTimes(2);
  });

  it('says the host was not saved', async () => {
    apply.mockRejectedValueOnce(rejected());
    await expect(createProxyHost(host(), ADMIN)).rejects.toThrow(/Caddy did not accept the configuration with this change, so the proxy host was not saved/);
  });

  it('goes back to what it was when updated, WAF exclusions included', async () => {
    const created = await createProxyHost(host({ waf: { enabled: true, mode: 'On', excluded_rule_ids: [942100] } as never }), ADMIN);
    const rowBefore = await ctx.db.select().from(schema.proxyHosts);
    const exclusionsBefore = await ctx.db.select().from(schema.wafRuleExclusions);
    expect(exclusionsBefore).toHaveLength(1);

    apply.mockRejectedValueOnce(rejected());
    await expect(updateProxyHost(created.id, {
      name: 'Renamed', upstreams: ['other:9000'], waf: { enabled: true, mode: 'On', excluded_rule_ids: [941100, 920350] } as never,
    }, OPERATOR)).rejects.toThrow(ApiValidationError);

    expect(await ctx.db.select().from(schema.proxyHosts)).toEqual(rowBefore);
    expect(await ctx.db.select().from(schema.wafRuleExclusions)).toEqual(exclusionsBefore);
  });

  it('stays stored when Caddy could not be reached', async () => {
    apply.mockRejectedValueOnce(new CaddyApplyError('Unable to reach Caddy API', 'CADDY_UNREACHABLE'));
    const error = await createProxyHost(host(), OPERATOR).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CaddyApplyError);
    expect(await ctx.db.select().from(schema.proxyHosts)).toHaveLength(1);
    expect((error as CaddyApplyError).proxyHostId).toBeTypeOf('number');
  });
});

describe('where Caddy stopped', () => {
  // What applyCaddyConfig throws when Caddy's answer leads to a setting and a host (locateCaddyRejection).
  const located = () => {
    const error = new CaddyApplyError('Caddy rejected configuration: the problem is in the WAF rules', 'CADDY_REJECTED');
    error.rejectedAt = 'proxy host other.example.com';
    return error;
  };

  it('names the setting to the writer, and the host only to an administrator', async () => {
    apply.mockRejectedValueOnce(located());
    const forOperator = await createProxyHost(host(), OPERATOR).catch((e: Error) => e.message);
    expect(forOperator).toBe('Caddy did not accept the configuration with this change, so the proxy host was not saved: the problem is in the WAF rules');

    apply.mockRejectedValueOnce(located());
    const forAdmin = await createProxyHost(host(), ADMIN).catch((e: Error) => e.message);
    expect(forAdmin).toBe('Caddy did not accept the configuration with this change, so the proxy host was not saved: the problem is in the WAF rules (proxy host other.example.com)');
  });

  it('says nothing more when Caddy\'s answer led nowhere', async () => {
    apply.mockRejectedValueOnce(rejected());
    const message = await createProxyHost(host(), OPERATOR).catch((e: Error) => e.message);
    expect(message).toBe('Caddy did not accept the configuration with this change, so the proxy host was not saved');
  });

  it('tells an administrator who keeps a change in a broken configuration which host it is', async () => {
    await caddyAlreadyRefuses();
    apply.mockRejectedValueOnce(located());
    const error = await createProxyHost(host(), ADMIN).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CaddyApplyError);
    expect((error as Error).message).toBe('Caddy rejected configuration: the problem is in the WAF rules (proxy host other.example.com)');
    expect(await ctx.db.select().from(schema.proxyHosts)).toHaveLength(1);
  });

  it('gives settings writers the setting and the host', async () => {
    await setSetting('geoblock', { enabled: false });
    const result = await undoSettingsCaddyRejects(async () => {
      await setSetting('geoblock', { enabled: true });
      await applyCaddyConfig().catch(() => undefined);
      return { success: true, message: 'saved' };
    }, (message) => ({ success: false, message }));
    expect(result).toEqual({ success: true, message: 'saved' });

    apply.mockRejectedValueOnce(located());
    const refused = await undoSettingsCaddyRejects(async () => {
      await setSetting('geoblock', { enabled: true, block_cidrs: ['x'] });
      await applyCaddyConfig().catch(() => undefined);
      return { success: true, message: 'saved' };
    }, (message) => ({ success: false, message }));
    expect(refused).toEqual({
      success: false,
      message: 'Caddy did not accept these settings, so they were not saved: the problem is in the WAF rules (proxy host other.example.com)',
    });
  });
});

describe('while Caddy already refuses the configuration', () => {
  beforeEach(caddyAlreadyRefuses);

  it("an administrator's change stays stored, so the configuration can be repaired step by step", async () => {
    apply.mockRejectedValue(rejected());
    const error = await createProxyHost(host(), ADMIN).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CaddyApplyError);
    expect(await ctx.db.select().from(schema.proxyHosts)).toHaveLength(1);
  });

  it("anybody else's change is taken back", async () => {
    apply.mockRejectedValue(rejected());
    await expect(createProxyHost(host(), OPERATOR)).rejects.toThrow(ApiConflictError);
    expect(await ctx.db.select().from(schema.proxyHosts)).toEqual([]);
  });

  it('a change Caddy takes is stored as usual', async () => {
    await expect(createProxyHost(host(), OPERATOR)).resolves.toBeTruthy();
    expect(await ctx.db.select().from(schema.proxyHosts)).toHaveLength(1);
  });
});

describe('an L4 host Caddy rejects', () => {
  it('is not kept when created', async () => {
    apply.mockRejectedValueOnce(rejected());
    await expect(createL4ProxyHost(l4(), OPERATOR)).rejects.toThrow(/L4 host was not saved/);
    expect(await ctx.db.select().from(schema.l4ProxyHosts)).toEqual([]);
    expect(apply).toHaveBeenCalledTimes(2);
  });

  it('goes back to what it was when updated', async () => {
    const created = await createL4ProxyHost(l4(), ADMIN);
    const before = await ctx.db.select().from(schema.l4ProxyHosts);
    apply.mockRejectedValueOnce(rejected());
    await expect(updateL4ProxyHost(created.id, { listenAddress: '203.0.113.7:9000', upstreams: ['other:1'] }, OPERATOR))
      .rejects.toThrow(ApiValidationError);
    expect(await ctx.db.select().from(schema.l4ProxyHosts)).toEqual(before);
  });

  it("stays stored for an administrator while Caddy already refuses the configuration", async () => {
    await caddyAlreadyRefuses();
    apply.mockRejectedValue(rejected());
    const error = await createL4ProxyHost(l4(), ADMIN).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CaddyApplyError);
    expect((error as CaddyApplyError).l4ProxyHostId).toBeTypeOf('number');
    expect(await ctx.db.select().from(schema.l4ProxyHosts)).toHaveLength(1);
  });
});

describe('a bulk change (change batch) Caddy rejects', () => {
  it('is taken back as a whole: the apply at the end of the batch has the undo of every host in it', async () => {
    const first = await createProxyHost(host({ name: 'One', domains: ['one.example.com'], enabled: false }), ADMIN);
    const second = await createProxyHost(host({ name: 'Two', domains: ['two.example.com'], enabled: false }), ADMIN);
    const before = await ctx.db.select().from(schema.proxyHosts);
    apply.mockClear();

    const acceptedBefore = await caddyAcceptedLastApply();
    const { applyRequested, undo } = await runAsChangeBatch(async () => {
      await updateProxyHost(first.id, { enabled: true }, OPERATOR);
      await updateProxyHost(second.id, { enabled: true }, OPERATOR);
    });
    expect(applyRequested).toBe(true);
    expect(apply).not.toHaveBeenCalled();

    apply.mockRejectedValueOnce(rejected());
    const failure = await applyBatchOrUndo({ actorUserId: OPERATOR, acceptedBefore, undo });
    expect(failure).toEqual({ undone: true, message: expect.stringMatching(/the changes were not saved/) });
    expect(await ctx.db.select().from(schema.proxyHosts)).toEqual(before);
    expect(apply).toHaveBeenCalledTimes(2);
  });

  it('answers null when Caddy takes the batch', async () => {
    const created = await createProxyHost(host({ enabled: false }), ADMIN);
    const acceptedBefore = await caddyAcceptedLastApply();
    const { undo } = await runAsChangeBatch(async () => void (await updateProxyHost(created.id, { enabled: true }, OPERATOR)));
    expect(await applyBatchOrUndo({ actorUserId: OPERATOR, acceptedBefore, undo })).toBeNull();
    expect((await ctx.db.select().from(schema.proxyHosts))[0].enabled).toBe(true);
  });

  it('claims nothing was taken back when the batch has nothing to take back (deletions)', async () => {
    apply.mockRejectedValueOnce(rejected());
    expect(await applyBatchOrUndo({ actorUserId: OPERATOR, acceptedBefore: true, undo: null })).toEqual({ undone: false, message: 'Caddy rejected configuration' });
  });
});

describe('a certificate Caddy rejects', () => {
  // Real PEM: what is not PEM never gets as far as Caddy (pem-validation.ts). Caddy is stricter than
  // that check in places (it refuses some certificates Node reads), which is what these cases stand for.
  const imported = (extra: object = {}) => ({ name: 'Imported', type: 'imported' as const, domainNames: ['a.example.com'], ...testServerCertificate(), ...extra });
  const otherPair = () => createSelfSignedServerCertificate('other.example.com', ['other.example.com']);

  it('is not kept when created', async () => {
    apply.mockRejectedValueOnce(rejected());
    await expect(createCertificate(imported(), OPERATOR)).rejects.toThrow(/certificate was not saved/);
    expect(await ctx.db.select().from(schema.certificates)).toEqual([]);
  });

  it('goes back to what it was when updated', async () => {
    const created = await createCertificate(imported(), ADMIN);
    const before = await ctx.db.select().from(schema.certificates);
    apply.mockRejectedValueOnce(rejected());
    await expect(updateCertificate(created.id, otherPair(), OPERATOR)).rejects.toThrow(/certificate was not saved/);
    expect(await ctx.db.select().from(schema.certificates)).toEqual(before);
  });

  it('holds for CA certificates too', async () => {
    apply.mockRejectedValueOnce(rejected());
    await expect(createCaCertificate({ name: 'CA', certificatePem: testCa().certificatePem }, OPERATOR)).rejects.toThrow(/CA certificate was not saved/);
    expect(await ctx.db.select().from(schema.caCertificates)).toEqual([]);

    const created = await createCaCertificate({ name: 'CA', certificatePem: testCa().certificatePem }, ADMIN);
    const before = await ctx.db.select().from(schema.caCertificates);
    apply.mockRejectedValueOnce(rejected());
    await expect(updateCaCertificate(created.id, { certificatePem: createExternalCa('Other CA').certificatePem }, OPERATOR)).rejects.toThrow(/CA certificate was not saved/);
    expect(await ctx.db.select().from(schema.caCertificates)).toEqual(before);
  });

  it('what is not a certificate, or a key of another certificate, is refused before anything is stored or applied', async () => {
    apply.mockClear();
    await expect(createCertificate(imported({ certificatePem: 'not pem' }), OPERATOR)).rejects.toThrow(/must be PEM/);
    await expect(createCertificate(imported({ privateKeyPem: otherPair().privateKeyPem }), OPERATOR)).rejects.toThrow(/does not belong to the certificate/);
    await expect(createCaCertificate({ name: 'CA', certificatePem: 'not pem' }, OPERATOR)).rejects.toThrow(/exactly one PEM certificate/);
    expect(await ctx.db.select().from(schema.certificates)).toEqual([]);
    expect(await ctx.db.select().from(schema.caCertificates)).toEqual([]);
    expect(apply).not.toHaveBeenCalled();
  });
});

describe('a client certificate stored through the API', () => {
  let caId: number;
  const client = () => issueExternalClientCertificate(testCa(), 'device-1').certificatePem;
  const input = (certificatePem: string, extra: object = {}) => ({
    caCertificateId: caId, commonName: 'device-1', serialNumber: '01', certificatePem,
    validFrom: '2026-01-01T00:00:00Z', validTo: '2030-01-01T00:00:00Z', ...extra,
  });

  beforeEach(async () => {
    await ctx.db.delete(schema.issuedClientCertificates);
    caId = (await createCaCertificate({ name: 'Client CA', certificatePem: testCa().certificatePem }, ADMIN)).id;
  });

  it('gets the fingerprint of the certificate itself, whatever the request says', async () => {
    const pem = client();
    const real = new X509Certificate(pem).fingerprint256;
    expect((await createIssuedClientCertificate(input(pem), OPERATOR)).fingerprintSha256).toBe(real);
    // The same fingerprint in Caddy's spelling is accepted.
    await expect(createIssuedClientCertificate(input(pem, { fingerprintSha256: real.replace(/:/g, '').toLowerCase() }), OPERATOR)).resolves.toMatchObject({ fingerprintSha256: real });
    // Anything else is refused: it would end up in the expression that guards a host's mTLS access rules.
    for (const fingerprintSha256 of ["x'] || true || 'a' in ['a", '{env.SECRET}', 'AA:BB', 7]) {
      await expect(createIssuedClientCertificate(input(pem, { fingerprintSha256 }) as never, OPERATOR)).rejects.toThrow(/is not the SHA-256 fingerprint of the certificate/);
    }
    expect(await ctx.db.select().from(schema.issuedClientCertificates)).toHaveLength(2);
  });

  it('is refused when it is not one certificate, or a field is missing', async () => {
    apply.mockClear();
    await expect(createIssuedClientCertificate(input('-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----'), OPERATOR)).rejects.toThrow(/could not be read as an X\.509 certificate/);
    await expect(createIssuedClientCertificate(input('not pem'), OPERATOR)).rejects.toThrow(/The client certificate must be exactly one PEM certificate/);
    await expect(createIssuedClientCertificate(input(`${client()}\n${client()}`), OPERATOR)).rejects.toThrow(/exactly one PEM certificate/);
    await expect(createIssuedClientCertificate(input(client(), { commonName: 7 }) as never, OPERATOR)).rejects.toThrow(/commonName is required/);
    await expect(createIssuedClientCertificate(input(client(), { validTo: 'later' }), OPERATOR)).rejects.toThrow(/validTo must be a date/);
    await expect(createIssuedClientCertificate(input(client(), { caCertificateId: 'x' }) as never, OPERATOR)).rejects.toThrow(/caCertificateId must be a positive integer/);
    expect(await ctx.db.select().from(schema.issuedClientCertificates)).toEqual([]);
    expect(apply).not.toHaveBeenCalled();
  });

  it('is not kept when Caddy rejects the configuration with it', async () => {
    apply.mockRejectedValueOnce(rejected());
    await expect(createIssuedClientCertificate(input(client()), OPERATOR)).rejects.toThrow(/client certificate was not saved/);
    expect(await ctx.db.select().from(schema.issuedClientCertificates)).toEqual([]);
  });
});

describe('settings Caddy rejects (a dashboard settings action)', () => {
  const answer = (message: string) => ({ success: false, message });
  // What the settings actions do: save, apply, and answer "saved, but…" when the apply fails.
  const action = (key: string, value: unknown) => async () => {
    await setSetting(key, value);
    try {
      await applyCaddyConfig();
      return { success: true, message: 'saved' };
    } catch {
      return { success: true, message: 'Settings saved, but could not apply to Caddy' };
    }
  };

  it('are put back, and the action answers that nothing was saved', async () => {
    await setSetting('geoblock', { enabled: false, block_cidrs: [] });
    apply.mockRejectedValueOnce(rejected());
    const result = await undoSettingsCaddyRejects(action('geoblock', { enabled: true, block_cidrs: ['not-a-cidr'] }), answer);
    expect(result).toEqual({ success: false, message: expect.stringMatching(/so they were not saved/) });
    expect(await getSetting('geoblock')).toEqual({ enabled: false, block_cidrs: [] });
    expect(apply).toHaveBeenCalledTimes(2);
  });

  it('are removed again when there were none before', async () => {
    apply.mockRejectedValueOnce(rejected());
    await undoSettingsCaddyRejects(action('waf', { enabled: true, custom_directives: 'SecRule (' }), answer);
    expect(await getSetting('waf')).toBeNull();
  });

  it('stay when Caddy takes them, when it cannot be reached, and when it was refusing the configuration before', async () => {
    expect(await undoSettingsCaddyRejects(action('metrics', { enabled: true, port: 9090 }), answer)).toEqual({ success: true, message: 'saved' });

    apply.mockRejectedValueOnce(new CaddyApplyError('Unable to reach Caddy API', 'CADDY_UNREACHABLE'));
    await undoSettingsCaddyRejects(action('metrics', { enabled: true, port: 9091 }), answer);
    expect(await getSetting('metrics')).toEqual({ enabled: true, port: 9091 });

    await caddyAlreadyRefuses();
    apply.mockRejectedValueOnce(rejected());
    const kept = await undoSettingsCaddyRejects(action('metrics', { enabled: true, port: 9092 }), answer);
    expect(kept.success).toBe(true);
    expect(await getSetting('metrics')).toEqual({ enabled: true, port: 9092 });
  });
});
