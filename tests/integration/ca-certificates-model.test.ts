/**
 * Integration tests for src/lib/models/ca-certificates.ts
 *
 * Focus: deleting a CA must cascade to the client certificates it issued (and
 * their role mappings). The schema declares onDelete: "cascade", but
 * better-sqlite3 runs with PRAGMA foreign_keys OFF, so the model performs the
 * cascade explicitly. Without it, orphaned issued certs linger in the DB and
 * keep showing up as selectable in the mTLS picker.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createTestDb, type TestDb } from '../helpers/db';
import { encryptUnderOtherSecret } from '../helpers/encrypt-under-other-secret';
import {
  caCertificates,
  issuedClientCertificates,
  mtlsCertificateRoles,
  mtlsRoles,
  proxyHosts,
  users,
} from '../../src/lib/db/schema';
import { eq } from 'drizzle-orm';
import { ApiClientError, ApiConflictError } from '../../src/lib/api-errors';
import { testCa } from '../helpers/certs';

// The model refuses a CA certificate Caddy could not read, so the tests store a real one.
const CA_PEM = testCa().certificatePem;

let db: TestDb;

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => db));
vi.mock('../../src/lib/caddy', () => ({ applyCaddyConfig: vi.fn() }));
vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

let userId: number;

beforeEach(async () => {
  db = createTestDb();
  vi.clearAllMocks();
  const now = new Date().toISOString();
  const [user] = await db.insert(users).values({
    email: 'admin@test', name: 'Admin', role: 'admin',
    provider: 'credentials', subject: 'admin@test', status: 'active',
    createdAt: now, updatedAt: now,
  }).returning();
  userId = user.id;
});

const {
  CaPrivateKeyUnavailableError,
  createCaCertificate,
  deleteCaCertificate,
  getCaCertificatePrivateKey,
  listCaCertificates,
  migrateLegacyCaPrivateKeys,
  updateCaCertificate,
} = await import('../../src/lib/models/ca-certificates');

function nowIso() { return new Date().toISOString(); }

async function seedIssuedCert(caId: number, commonName: string, serial: string) {
  const now = nowIso();
  const [cert] = await db.insert(issuedClientCertificates).values({
    caCertificateId: caId, commonName, serialNumber: serial,
    fingerprintSha256: `FP:${serial}`, certificatePem: `PEM:${serial}`,
    validFrom: now, validTo: now, createdAt: now, updatedAt: now,
  }).returning();
  return cert;
}

async function seedMtlsHost(name: string, mtls: Record<string, unknown>) {
  const now = nowIso();
  const [host] = await db.insert(proxyHosts).values({
    name, domains: JSON.stringify([`${name}.local`]), upstreams: JSON.stringify(['localhost:9000']),
    meta: JSON.stringify({ mtls: { enabled: true, ...mtls } }),
    createdAt: now, updatedAt: now,
  }).returning();
  return host;
}

describe('deleteCaCertificate cascade', () => {
  it('deletes the CA and all of its issued client certificates', async () => {
    const ca = await createCaCertificate(
      { name: 'Cascade CA', certificatePem: CA_PEM },
      userId,
    );
    await seedIssuedCert(ca.id, 'alice', '001');
    await seedIssuedCert(ca.id, 'bob', '002');

    await deleteCaCertificate(ca.id, userId);

    expect(await listCaCertificates()).toHaveLength(0);
    const remaining = await db
      .select()
      .from(issuedClientCertificates)
      .where(eq(issuedClientCertificates.caCertificateId, ca.id));
    expect(remaining).toHaveLength(0);
  });

  it('removes role mappings for the deleted CA certs', async () => {
    const ca = await createCaCertificate(
      { name: 'Role Cascade CA', certificatePem: CA_PEM },
      userId,
    );
    const cert = await seedIssuedCert(ca.id, 'carol', '003');

    const now = nowIso();
    const [role] = await db.insert(mtlsRoles).values({
      name: 'admins', createdAt: now, updatedAt: now,
    }).returning();
    await db.insert(mtlsCertificateRoles).values({
      issuedClientCertificateId: cert.id, mtlsRoleId: role.id, createdAt: now,
    });

    await deleteCaCertificate(ca.id, userId);

    const mappings = await db
      .select()
      .from(mtlsCertificateRoles)
      .where(eq(mtlsCertificateRoles.issuedClientCertificateId, cert.id));
    expect(mappings).toHaveLength(0);
    // The role itself must survive — only the mapping is removed.
    const roles = await db.select().from(mtlsRoles).where(eq(mtlsRoles.id, role.id));
    expect(roles).toHaveLength(1);
  });

  it('blocks deletion when a host trusts an issued cert via trusted_client_cert_ids', async () => {
    const ca = await createCaCertificate({ name: 'In-Use CA', certificatePem: CA_PEM }, userId);
    const cert = await seedIssuedCert(ca.id, 'dave', '004');
    await seedMtlsHost('host-trusts-cert', { trusted_client_cert_ids: [cert.id] });

    const failure = deleteCaCertificate(ca.id, userId);
    await expect(failure).rejects.toBeInstanceOf(ApiConflictError);
    await expect(failure).rejects.toMatchObject({
      status: 409,
      message: expect.stringMatching(/in use by proxy host/i),
    });
    // CA and its cert must survive the blocked delete.
    expect(await listCaCertificates()).toHaveLength(1);
    const certs = await db.select().from(issuedClientCertificates).where(eq(issuedClientCertificates.id, cert.id));
    expect(certs).toHaveLength(1);
  });

  it('blocks deletion when a host trusts a role containing one of the CA certs', async () => {
    const ca = await createCaCertificate({ name: 'Role-Trusted CA', certificatePem: CA_PEM }, userId);
    const cert = await seedIssuedCert(ca.id, 'erin', '005');
    const now = nowIso();
    const [role] = await db.insert(mtlsRoles).values({ name: 'ops', createdAt: now, updatedAt: now }).returning();
    await db.insert(mtlsCertificateRoles).values({
      issuedClientCertificateId: cert.id, mtlsRoleId: role.id, createdAt: now,
    });
    await seedMtlsHost('host-trusts-role', { trusted_role_ids: [role.id] });

    await expect(deleteCaCertificate(ca.id, userId)).rejects.toThrow(/in use by proxy host/i);
  });

  it('blocks deletion via the deprecated ca_certificate_ids list (backward compat)', async () => {
    const ca = await createCaCertificate({ name: 'Legacy CA', certificatePem: CA_PEM }, userId);
    await seedMtlsHost('host-legacy', { ca_certificate_ids: [ca.id] });

    await expect(deleteCaCertificate(ca.id, userId)).rejects.toThrow(/in use by proxy host/i);
  });

  it('allows deletion when the trusting host has mTLS disabled', async () => {
    const ca = await createCaCertificate({ name: 'Disabled-mTLS CA', certificatePem: CA_PEM }, userId);
    const cert = await seedIssuedCert(ca.id, 'frank', '006');
    // seedMtlsHost merges as { enabled: true, ...mtls }, so enabled:false wins.
    await seedMtlsHost('host-mtls-off', { enabled: false, trusted_client_cert_ids: [cert.id] });

    await deleteCaCertificate(ca.id, userId);
    expect(await listCaCertificates()).toHaveLength(0);
  });

  it('allows deletion when only an unrelated CA cert is trusted', async () => {
    const target = await createCaCertificate({ name: 'Target CA', certificatePem: CA_PEM }, userId);
    const other = await createCaCertificate({ name: 'Other CA', certificatePem: CA_PEM }, userId);
    const otherCert = await seedIssuedCert(other.id, 'grace', '007');
    await seedMtlsHost('host-trusts-other', { trusted_client_cert_ids: [otherCert.id] });

    // Deleting the target CA (not referenced) must succeed.
    await deleteCaCertificate(target.id, userId);
    expect((await listCaCertificates()).map(c => c.name)).toEqual(['Other CA']);
  });

  it('leaves other CAs and their certs untouched', async () => {
    const caA = await createCaCertificate({ name: 'CA A', certificatePem: CA_PEM }, userId);
    const caB = await createCaCertificate({ name: 'CA B', certificatePem: CA_PEM }, userId);
    await seedIssuedCert(caA.id, 'a-user', '010');
    const keep = await seedIssuedCert(caB.id, 'b-user', '011');

    await deleteCaCertificate(caA.id, userId);

    const cas = await listCaCertificates();
    expect(cas.map(c => c.name)).toEqual(['CA B']);
    const survivors = await db
      .select()
      .from(issuedClientCertificates)
      .where(eq(issuedClientCertificates.caCertificateId, caB.id));
    expect(survivors.map(c => c.id)).toEqual([keep.id]);
  });
});

describe('CA private key storage', () => {
  const KEY = testCa().privateKeyPem;
  // A piece of the key's own text, which the stored value must not show.
  const KEY_TEXT = KEY.split(/\r?\n/)[1];

  it('stores the key encrypted and returns it decrypted to the signer', async () => {
    const ca = await createCaCertificate({ name: 'Enc CA', certificatePem: CA_PEM, privateKeyPem: KEY }, userId);
    const [row] = await db.select().from(caCertificates).where(eq(caCertificates.id, ca.id));
    expect(row.privateKeyPem).toMatch(/^enc:v1:/);
    expect(row.privateKeyPem).not.toContain(KEY_TEXT);
    expect(await getCaCertificatePrivateKey(ca.id)).toBe(KEY);
  });

  it('encrypts legacy plaintext keys idempotently', async () => {
    const now = nowIso();
    const [legacy] = await db.insert(caCertificates).values({
      name: 'Legacy CA', certificatePem: 'CERT', privateKeyPem: KEY, createdAt: now, updatedAt: now,
    }).returning();

    expect(await migrateLegacyCaPrivateKeys()).toBe(1);
    expect(await migrateLegacyCaPrivateKeys()).toBe(0);
    const [row] = await db.select().from(caCertificates).where(eq(caCertificates.id, legacy.id));
    expect(row.privateKeyPem).toMatch(/^enc:v1:/);
    expect(await getCaCertificatePrivateKey(legacy.id)).toBe(KEY);
  });

  async function storedKey(id: number) {
    const [row] = await db.select().from(caCertificates).where(eq(caCertificates.id, id));
    return row.privateKeyPem;
  }

  it('encrypts a key set through updateCaCertificate', async () => {
    const ca = await createCaCertificate({ name: 'Upd CA', certificatePem: CA_PEM }, userId);
    expect(await storedKey(ca.id)).toBeNull();

    const updated = await updateCaCertificate(ca.id, { privateKeyPem: `  ${KEY}\n` }, userId);

    expect(updated.hasPrivateKey).toBe(true);
    expect(await storedKey(ca.id)).toMatch(/^enc:v1:/);
    expect(await storedKey(ca.id)).not.toContain(KEY_TEXT);
    expect(await getCaCertificatePrivateKey(ca.id)).toBe(KEY);
  });

  it('keeps the stored key when an update omits privateKeyPem', async () => {
    const ca = await createCaCertificate({ name: 'Keep CA', certificatePem: CA_PEM, privateKeyPem: KEY }, userId);
    const before = await storedKey(ca.id);

    await updateCaCertificate(ca.id, { name: 'Renamed CA' }, userId);

    expect(await storedKey(ca.id)).toBe(before);
    expect(await getCaCertificatePrivateKey(ca.id)).toBe(KEY);
  });

  it.each([
    ['an empty string', ''],
    ['null', null],
  ])('clears the stored key when updated with %s', async (_label, value) => {
    const ca = await createCaCertificate({ name: 'Clear CA', certificatePem: CA_PEM, privateKeyPem: KEY }, userId);

    // The REST PUT body is untyped JSON, so null reaches the model as-is.
    const updated = await updateCaCertificate(ca.id, { privateKeyPem: value as string }, userId);

    expect(updated.hasPrivateKey).toBe(false);
    expect(await storedKey(ca.id)).toBeNull();
    expect(await getCaCertificatePrivateKey(ca.id)).toBeNull();
  });

  it('reports a key encrypted under another SESSION_SECRET as unavailable, with an actionable message', async () => {
    const now = nowIso();
    const [ca] = await db.insert(caCertificates).values({
      name: 'Rotated CA', certificatePem: 'CERT', privateKeyPem: encryptUnderOtherSecret(KEY), createdAt: now, updatedAt: now,
    }).returning();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    const failure = getCaCertificatePrivateKey(ca.id);

    await expect(failure).rejects.toBeInstanceOf(CaPrivateKeyUnavailableError);
    await expect(failure).rejects.toBeInstanceOf(ApiClientError);
    await expect(failure).rejects.toMatchObject({
      status: 409,
      message: expect.stringMatching(/cannot be decrypted with the current SESSION_SECRET.*create a new CA/),
    });
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(KEY_TEXT);
    // A key is still stored, so the CA keeps reporting one; the failure is
    // surfaced when the key is used.
    expect((await listCaCertificates()).find((c) => c.id === ca.id)?.hasPrivateKey).toBe(true);
    // The startup migration leaves the undecryptable value alone.
    expect(await migrateLegacyCaPrivateKeys()).toBe(0);
    errorSpy.mockRestore();
  });
});
