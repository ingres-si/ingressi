import { appDb, nowIso, toIso } from "../db";
import { logAuditEvent } from "../audit";
import { applyCaddyConfig } from "../caddy";
import { issuedClientCertificates } from "../db/schema";
import { desc } from "@/src/lib/db/ops";
import { eq } from "drizzle-orm";
import { ApiValidationError } from "../api-errors";
import { normalizeFingerprint } from "../caddy-mtls";
import { assertCaCertificatePem } from "../pem-validation";
import { applyOrUndo, caddyAcceptedLastApply } from "../rejected-apply";

export type IssuedClientCertificate = {
  id: number;
  caCertificateId: number;
  commonName: string;
  serialNumber: string;
  fingerprintSha256: string;
  certificatePem: string;
  validFrom: string;
  validTo: string;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type IssuedClientCertificateInput = {
  caCertificateId: number;
  commonName: string;
  serialNumber: string;
  /** The certificate's own SHA-256 fingerprint; computed when left out, refused when it is another one. */
  fingerprintSha256?: string;
  certificatePem: string;
  validFrom: string;
  validTo: string;
};

type IssuedClientCertificateRow = typeof issuedClientCertificates.$inferSelect;

function parseIssuedClientCertificate(row: IssuedClientCertificateRow): IssuedClientCertificate {
  return {
    id: row.id,
    caCertificateId: row.caCertificateId,
    commonName: row.commonName,
    serialNumber: row.serialNumber,
    fingerprintSha256: row.fingerprintSha256,
    certificatePem: row.certificatePem,
    validFrom: toIso(row.validFrom)!,
    validTo: toIso(row.validTo)!,
    revokedAt: toIso(row.revokedAt),
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!
  };
}

export async function listIssuedClientCertificates(): Promise<IssuedClientCertificate[]> {
  const rows = await appDb
    .select()
    .from(issuedClientCertificates)
    .orderBy(desc(issuedClientCertificates.createdAt), desc(issuedClientCertificates.id));
  return rows.map(parseIssuedClientCertificate);
}

export async function getIssuedClientCertificate(id: number): Promise<IssuedClientCertificate | null> {
  const record = await appDb.query.issuedClientCertificates.findFirst({
    where: (table, { eq: compareEq }) => compareEq(table.id, id)
  });
  return record ? parseIssuedClientCertificate(record) : null;
}

/**
 * The input as it is stored. The certificate is checked the way Caddy reads
 * it (a host that trusts it gets it in its TLS policy, and Caddy rejects the
 * whole configuration over one it cannot parse), and the fingerprint is the
 * certificate's own: it ends up in the expressions that decide who gets
 * through a host's mTLS access rules, so it is never taken from the request.
 */
function validateIssuedClientCertificate(input: IssuedClientCertificateInput): IssuedClientCertificateInput {
  if (!Number.isSafeInteger(input?.caCertificateId) || input.caCertificateId <= 0) {
    throw new ApiValidationError("caCertificateId must be a positive integer");
  }
  for (const field of ["commonName", "serialNumber", "validFrom", "validTo"] as const) {
    if (typeof input[field] !== "string" || !input[field].trim()) {
      throw new ApiValidationError(`${field} is required`);
    }
  }
  for (const field of ["validFrom", "validTo"] as const) {
    if (Number.isNaN(Date.parse(input[field]))) throw new ApiValidationError(`${field} must be a date`);
  }
  const certificate = assertCaCertificatePem(input.certificatePem, "The client certificate");
  const fingerprint = certificate.fingerprint256;
  if (
    input.fingerprintSha256 !== undefined &&
    input.fingerprintSha256 !== null &&
    (typeof input.fingerprintSha256 !== "string" || normalizeFingerprint(input.fingerprintSha256.trim()) !== normalizeFingerprint(fingerprint))
  ) {
    throw new ApiValidationError("fingerprintSha256 is not the SHA-256 fingerprint of the certificate (leave it out to have it computed)");
  }
  return { ...input, fingerprintSha256: fingerprint };
}

export async function createIssuedClientCertificate(
  rawInput: IssuedClientCertificateInput,
  actorUserId: number
): Promise<IssuedClientCertificate> {
  const input = validateIssuedClientCertificate(rawInput);
  const acceptedBefore = await caddyAcceptedLastApply();
  const now = nowIso();
  const [record] = await appDb
    .insert(issuedClientCertificates)
    .values({
      caCertificateId: input.caCertificateId,
      commonName: input.commonName.trim(),
      serialNumber: input.serialNumber.trim(),
      fingerprintSha256: input.fingerprintSha256!,
      certificatePem: input.certificatePem.trim(),
      validFrom: input.validFrom,
      validTo: input.validTo,
      createdBy: actorUserId,
      createdAt: now,
      updatedAt: now
    })
    .returning();

  if (!record) {
    throw new Error("Failed to store issued client certificate");
  }

  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "issued_client_certificate",
    entityId: record.id,
    summary: `Issued client certificate ${input.commonName}`,
    data: {
      caCertificateId: input.caCertificateId,
      serialNumber: input.serialNumber
    }
  });
  // A client certificate Caddy cannot load is not kept (see rejected-apply.ts).
  await applyOrUndo({
    actorUserId,
    acceptedBefore,
    what: "client certificate",
    undo: async () => {
      await appDb.delete(issuedClientCertificates).where(eq(issuedClientCertificates.id, record.id));
      await logAuditEvent({
        userId: actorUserId,
        action: "delete",
        entityType: "issued_client_certificate",
        entityId: record.id,
        summary: `Removed client certificate ${input.commonName} again: Caddy rejected the configuration with it`
      });
    },
  });
  return (await getIssuedClientCertificate(record.id))!;
}

export async function revokeIssuedClientCertificate(
  id: number,
  actorUserId: number
): Promise<IssuedClientCertificate> {
  const existing = await getIssuedClientCertificate(id);
  if (!existing) {
    throw new Error("Issued client certificate not found");
  }
  if (existing.revokedAt) {
    throw new Error("Issued client certificate is already revoked");
  }

  const revokedAt = nowIso();
  await appDb
    .update(issuedClientCertificates)
    .set({
      revokedAt,
      updatedAt: revokedAt
    })
    .where(eq(issuedClientCertificates.id, id));

  await logAuditEvent({
    userId: actorUserId,
    action: "revoke",
    entityType: "issued_client_certificate",
    entityId: id,
    summary: `Revoked client certificate ${existing.commonName}`,
    data: {
      caCertificateId: existing.caCertificateId,
      serialNumber: existing.serialNumber
    }
  });
  await applyCaddyConfig();
  return (await getIssuedClientCertificate(id))!;
}
