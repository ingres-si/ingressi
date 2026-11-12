import { appDb, nowIso, toIso } from "../db";
import { logAuditEvent } from "../audit";
import { applyCaddyConfig } from "../caddy";
import { caCertificates, issuedClientCertificates, mtlsCertificateRoles, proxyHosts } from "../db/schema";
import { eq, inArray } from "drizzle-orm";
import { ApiConflictError, ApiValidationError } from "../api-errors";
import { decryptSecret, encryptSecret, isEncryptedSecret } from "../secret";
import { asc, desc, first } from "@/src/lib/db/ops";
import { applyOrUndo, caddyAcceptedLastApply } from "../rejected-apply";
import { assertCaCertificatePem, assertPrivateKeyPem } from "../pem-validation";

export const CA_PRIVATE_KEY_UNAVAILABLE_MESSAGE =
  "The CA private key cannot be decrypted with the current SESSION_SECRET. " +
  "Restore the previous secret via SESSION_SECRET_PREVIOUS or create a new CA.";

/**
 * The stored CA signing key exists but cannot be decrypted, typically because
 * SESSION_SECRET changed. The message is safe to show to admins and API clients.
 */
export class CaPrivateKeyUnavailableError extends ApiConflictError {
  constructor() {
    super(CA_PRIVATE_KEY_UNAVAILABLE_MESSAGE);
    this.name = "CaPrivateKeyUnavailableError";
  }
}

function encryptCaPrivateKey(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? encryptSecret(trimmed) : null;
}

function tryParseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export type CaCertificate = {
  id: number;
  name: string;
  certificatePem: string;
  hasPrivateKey: boolean;
  createdAt: string;
  updatedAt: string;
};

export type CaCertificateInput = {
  name: string;
  certificatePem: string;
  privateKeyPem?: string;
};

type CaCertificateRow = typeof caCertificates.$inferSelect;

function parseCaCertificate(row: CaCertificateRow): CaCertificate {
  return {
    id: row.id,
    name: row.name,
    certificatePem: row.certificatePem,
    hasPrivateKey: !!row.privateKeyPem,
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!
  };
}

export async function listCaCertificates(): Promise<CaCertificate[]> {
  const rows = await appDb.select().from(caCertificates).orderBy(desc(caCertificates.createdAt), desc(caCertificates.id));
  return rows.map(parseCaCertificate);
}

/**
 * Returns the decrypted CA signing key, or null when none is stored. Throws
 * CaPrivateKeyUnavailableError when a key is stored but cannot be decrypted.
 */
export async function getCaCertificatePrivateKey(id: number): Promise<string | null> {
  const cert = await appDb.query.caCertificates.findFirst({
    where: (table, { eq }) => eq(table.id, id)
  });
  if (!cert?.privateKeyPem) return null;
  try {
    return decryptSecret(cert.privateKeyPem, `CA certificate ${id} private key`);
  } catch {
    console.error(`Failed to decrypt the private key of CA certificate ${id}; SESSION_SECRET may have changed`);
    throw new CaPrivateKeyUnavailableError();
  }
}

/**
 * Encrypt CA private keys stored in plaintext by older releases. Idempotent,
 * so a restored legacy backup is repaired on the next startup.
 */
export async function migrateLegacyCaPrivateKeys(): Promise<number> {
  const rows = await appDb
    .select({ id: caCertificates.id, privateKeyPem: caCertificates.privateKeyPem })
    .from(caCertificates);
  let migrated = 0;
  for (const row of rows) {
    if (!row.privateKeyPem || isEncryptedSecret(row.privateKeyPem)) continue;
    await appDb
      .update(caCertificates)
      .set({ privateKeyPem: encryptSecret(row.privateKeyPem) })
      .where(eq(caCertificates.id, row.id));
    migrated += 1;
  }
  return migrated;
}

export async function getCaCertificate(id: number): Promise<CaCertificate | null> {
  const cert = await appDb.query.caCertificates.findFirst({
    where: (table, { eq }) => eq(table.id, id)
  });
  return cert ? parseCaCertificate(cert) : null;
}

/**
 * Caddy rejects the whole configuration over a CA certificate it cannot
 * read, so it is checked before it is stored; a signing key must belong to it.
 */
function validateCaPem(certificatePem: unknown, privateKeyPem: unknown): void {
  const certificate = assertCaCertificatePem(certificatePem);
  if (typeof privateKeyPem === "string" ? privateKeyPem.trim() : privateKeyPem) {
    assertPrivateKeyPem(privateKeyPem, certificate, "The CA private key");
  }
}

export async function createCaCertificate(input: CaCertificateInput, actorUserId: number): Promise<CaCertificate> {
  if (typeof input.name !== "string" || !input.name.trim()) throw new ApiValidationError("name is required");
  validateCaPem(input.certificatePem, input.privateKeyPem);
  const acceptedBefore = await caddyAcceptedLastApply();
  const now = nowIso();
  const [record] = await appDb
    .insert(caCertificates)
    .values({
      name: input.name.trim(),
      certificatePem: input.certificatePem.trim(),
      privateKeyPem: encryptCaPrivateKey(input.privateKeyPem),
      createdBy: actorUserId,
      createdAt: now,
      updatedAt: now
    })
    .returning();

  if (!record) {
    throw new Error("Failed to create CA certificate");
  }

  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "ca_certificate",
    entityId: record.id,
    summary: `Created CA certificate ${input.name}`
  });
  // A CA certificate Caddy cannot load is not kept (see rejected-apply.ts).
  await applyOrUndo({
    actorUserId,
    acceptedBefore,
    what: "CA certificate",
    undo: async () => {
      await appDb.delete(caCertificates).where(eq(caCertificates.id, record.id));
      await logAuditEvent({
        userId: actorUserId,
        action: "delete",
        entityType: "ca_certificate",
        entityId: record.id,
        summary: `Removed CA certificate ${input.name} again: Caddy rejected the configuration with it`
      });
    },
  });
  return (await getCaCertificate(record.id))!;
}

export async function updateCaCertificate(id: number, input: Partial<CaCertificateInput>, actorUserId: number): Promise<CaCertificate> {
  const existing = await getCaCertificate(id);
  if (!existing) {
    throw new Error("CA certificate not found");
  }

  // A stored certificate from before this check is only checked again when it or its key changes.
  if (input.certificatePem !== undefined || (typeof input.privateKeyPem === "string" && input.privateKeyPem.trim())) {
    validateCaPem(input.certificatePem ?? existing.certificatePem, input.privateKeyPem);
  }

  // What is put back if Caddy rejects the configuration with this change.
  const acceptedBefore = await caddyAcceptedLastApply();
  const previousRow = await first(appDb.select().from(caCertificates).where(eq(caCertificates.id, id)).limit(1));

  const now = nowIso();
  await appDb
    .update(caCertificates)
    .set({
      name: input.name?.trim() ?? existing.name,
      certificatePem: input.certificatePem?.trim() ?? existing.certificatePem,
      ...(input.privateKeyPem !== undefined ? { privateKeyPem: encryptCaPrivateKey(input.privateKeyPem) } : {}),
      updatedAt: now
    })
    .where(eq(caCertificates.id, id));

  await logAuditEvent({
    userId: actorUserId,
    action: "update",
    entityType: "ca_certificate",
    entityId: id,
    summary: `Updated CA certificate ${input.name ?? existing.name}`
  });
  await applyOrUndo({
    actorUserId,
    acceptedBefore,
    what: "CA certificate",
    undo: async () => {
      if (!previousRow) return;
      const { id: _id, ...columns } = previousRow;
      void _id;
      await appDb.update(caCertificates).set(columns).where(eq(caCertificates.id, id));
      await logAuditEvent({
        userId: actorUserId,
        action: "update",
        entityType: "ca_certificate",
        entityId: id,
        summary: `Undid the update of CA certificate ${existing.name}: Caddy rejected the configuration with it`
      });
    },
  });
  return (await getCaCertificate(id))!;
}

export async function deleteCaCertificate(id: number, actorUserId: number): Promise<void> {
  // The in-use check and the deletes run in one transaction, so no host can
  // start trusting the CA's certificates in between.
  const existing = await appDb.transaction(async (tx) => {
    const existing = await tx.query.caCertificates.findFirst({
      where: (table, { eq }) => eq(table.id, id)
    });
    if (!existing) {
      throw new Error("CA certificate not found");
    }

    // Collect the issued client certificates belonging to this CA, plus any
    // mTLS roles that include them — used both to detect references below and to
    // cascade-delete afterwards.
    const issuedCerts = await tx
      .select({ id: issuedClientCertificates.id })
      .from(issuedClientCertificates)
      .where(eq(issuedClientCertificates.caCertificateId, id));
    const issuedCertIds = issuedCerts.map((c) => c.id);
    const issuedCertIdSet = new Set(issuedCertIds);

    const affectedRoleIds = new Set<number>();
    if (issuedCertIds.length > 0) {
      const roleRows = await tx
        .select({ roleId: mtlsCertificateRoles.mtlsRoleId })
        .from(mtlsCertificateRoles)
        .where(inArray(mtlsCertificateRoles.issuedClientCertificateId, issuedCertIds));
      for (const row of roleRows) affectedRoleIds.add(row.roleId);
    }

    // Check if any proxy host's mTLS config references this CA. A host is "in
    // use" if it directly trusts one of the CA's issued certs
    // (trusted_client_cert_ids), trusts a role that contains one
    // (trusted_role_ids), or uses the deprecated whole-CA trust list
    // (ca_certificate_ids). The old guard only checked the deprecated field, so
    // CAs trusted via the current per-cert/role model could be deleted out from
    // under a live host.
    const allHosts = await tx.select({ meta: proxyHosts.meta, name: proxyHosts.name }).from(proxyHosts).orderBy(asc(proxyHosts.id));
    const referencing = allHosts.filter((host) => {
      const meta = tryParseJson<{
        mtls?: {
          enabled?: boolean;
          trusted_client_cert_ids?: number[];
          trusted_role_ids?: number[];
          ca_certificate_ids?: number[];
        };
      }>(host.meta, {});
      if (!meta.mtls?.enabled) return false;
      const trustsCert = meta.mtls.trusted_client_cert_ids?.some((cid) => issuedCertIdSet.has(cid)) ?? false;
      const trustsRole = meta.mtls.trusted_role_ids?.some((rid) => affectedRoleIds.has(rid)) ?? false;
      const trustsCa = meta.mtls.ca_certificate_ids?.includes(id) ?? false;
      return trustsCert || trustsRole || trustsCa;
    });

    if (referencing.length > 0) {
      const names = referencing.map((h) => h.name).join(", ");
      throw new ApiConflictError(`CA certificate is in use by proxy host(s): ${names}`);
    }

    // Cascade-delete the CA's issued client certificates and their role
    // mappings. The schema declares onDelete: "cascade" for these foreign keys,
    // but production SQLite runs with foreign keys off and PostgreSQL has
    // none, so the cascade never fires by itself — without this, deleting a CA
    // orphans its issued certificates, which keep appearing as selectable in
    // the mTLS picker.
    if (issuedCertIds.length > 0) {
      await tx
        .delete(mtlsCertificateRoles)
        .where(inArray(mtlsCertificateRoles.issuedClientCertificateId, issuedCertIds));
      await tx
        .delete(issuedClientCertificates)
        .where(eq(issuedClientCertificates.caCertificateId, id));
    }

    await tx.delete(caCertificates).where(eq(caCertificates.id, id));
    return existing;
  });
  await logAuditEvent({
    userId: actorUserId,
    action: "delete",
    entityType: "ca_certificate",
    entityId: id,
    summary: `Deleted CA certificate ${existing.name}`
  });
  await applyCaddyConfig();
}
