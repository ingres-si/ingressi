import { appDb, nowIso, toIso } from "../db";
import { logAuditEvent } from "../audit";
import { applyCaddyConfig } from "../caddy";
import { certificates, proxyHosts } from "../db/schema";
import { eq } from "drizzle-orm";
import { decryptSecret, encryptSecret, isEncryptedSecret } from "../secret";
import { ApiValidationError } from "../api-errors";
import { getDnsProviderSettings } from "../settings";
import {
  normalizeCertificateProviderOptions,
  parseStoredCertificateProviderOptions,
  sanitizeStoredCertificateProviderOptions,
} from "../certificate-provider-options";
import { desc, first } from "@/src/lib/db/ops";
import { applyOrUndo, caddyAcceptedLastApply } from "../rejected-apply";
import { assertImportedCertificatePem } from "../pem-validation";

export type CertificateType = "managed" | "imported";

export type Certificate = {
  id: number;
  name: string;
  type: CertificateType;
  domainNames: string[];
  autoRenew: boolean;
  providerOptions: Record<string, unknown> | null;
  certificatePem: string | null;
  privateKeyPem: string | null;
  createdAt: string;
  updatedAt: string;
};

export type CertificateInput = {
  name: string;
  type: CertificateType;
  domainNames: string[];
  autoRenew?: boolean;
  providerOptions?: Record<string, unknown> | null;
  certificatePem?: string | null;
  privateKeyPem?: string | null;
};

type CertificateRow = typeof certificates.$inferSelect;

function parseCertificate(row: CertificateRow): Certificate {
  return {
    id: row.id,
    name: row.name,
    type: row.type as CertificateType,
    domainNames: JSON.parse(row.domainNames),
    autoRenew: row.autoRenew,
    providerOptions: parseStoredCertificateProviderOptions(row.providerOptions),
    certificatePem: row.certificatePem,
    privateKeyPem: row.privateKeyPem ? decryptSecret(row.privateKeyPem) : null,
    createdAt: toIso(row.createdAt)!,
    updatedAt: toIso(row.updatedAt)!
  };
}

export async function listCertificates(): Promise<Certificate[]> {
  const rows = await appDb
    .select()
    .from(certificates)
    .orderBy(desc(certificates.createdAt), desc(certificates.id));
  return rows.map(parseCertificate);
}

export async function getCertificate(id: number): Promise<Certificate | null> {
  const cert = await appDb.query.certificates.findFirst({
    where: (table, { eq }) => eq(table.id, id)
  });
  return cert ? parseCertificate(cert) : null;
}

/**
 * `checkPem` is false when an update leaves the certificate and key as they
 * are stored: a certificate from before this check can still be renamed.
 */
function validateCertificateInput(input: CertificateInput, checkPem = true) {
  if (!input.domainNames || input.domainNames.length === 0) {
    throw new Error("At least one domain is required for a certificate");
  }
  if (input.type === "imported") {
    if (!input.certificatePem || !input.privateKeyPem) {
      throw new Error("Imported certificates require certificate and key PEM data");
    }
    // Caddy rejects the whole configuration over a certificate it cannot load.
    if (checkPem) assertImportedCertificatePem(input.certificatePem, input.privateKeyPem);
  }
}

export async function createCertificate(input: CertificateInput, actorUserId: number) {
  validateCertificateInput(input);
  const acceptedBefore = await caddyAcceptedLastApply();
  const now = nowIso();
  const providerOptions = normalizeCertificateProviderOptions(input.providerOptions);
  const [record] = await appDb
    .insert(certificates)
    .values({
      name: input.name.trim(),
      type: input.type,
      domainNames: JSON.stringify(
        Array.from(new Set(input.domainNames.map((domain) => domain.trim().toLowerCase())))
      ),
      autoRenew: input.autoRenew ?? true,
      providerOptions: providerOptions ? JSON.stringify(providerOptions) : null,
      certificatePem: input.certificatePem ?? null,
      privateKeyPem: input.privateKeyPem ? encryptSecret(input.privateKeyPem) : null,
      createdAt: now,
      updatedAt: now,
      createdBy: actorUserId
    })
    .returning();

  if (!record) {
    throw new Error("Failed to create certificate");
  }

  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "certificate",
    entityId: record.id,
    summary: `Created certificate ${input.name}`
  });
  // A certificate Caddy cannot load is not kept (see rejected-apply.ts).
  await applyOrUndo({
    actorUserId,
    acceptedBefore,
    what: "certificate",
    undo: async () => {
      await appDb.delete(certificates).where(eq(certificates.id, record.id));
      await logAuditEvent({
        userId: actorUserId,
        action: "delete",
        entityType: "certificate",
        entityId: record.id,
        summary: `Removed certificate ${input.name} again: Caddy rejected the configuration with it`
      });
    },
  });
  return (await getCertificate(record.id))!;
}

export async function updateCertificate(id: number, input: Partial<CertificateInput>, actorUserId: number) {
  const existing = await getCertificate(id);
  if (!existing) {
    throw new Error("Certificate not found");
  }

  const merged: CertificateInput = {
    name: input.name ?? existing.name,
    type: input.type ?? existing.type,
    domainNames: input.domainNames ?? existing.domainNames,
    autoRenew: input.autoRenew ?? existing.autoRenew,
    // null clears the override (back to the default provider); only an omitted field keeps it.
    providerOptions: input.providerOptions !== undefined ? input.providerOptions : existing.providerOptions,
    certificatePem: input.certificatePem ?? existing.certificatePem,
    privateKeyPem: input.privateKeyPem ?? existing.privateKeyPem
  };

  const pemChanged =
    (input.certificatePem ?? null) !== null || (input.privateKeyPem ?? null) !== null || merged.type !== existing.type;
  validateCertificateInput(merged, pemChanged);
  // What is put back if Caddy rejects the configuration with this change.
  const acceptedBefore = await caddyAcceptedLastApply();
  const previousRow = await first(appDb.select().from(certificates).where(eq(certificates.id, id)).limit(1));

  const now = nowIso();
  const providerOptions = normalizeCertificateProviderOptions(merged.providerOptions);
  await appDb
    .update(certificates)
    .set({
      name: merged.name.trim(),
      type: merged.type,
      domainNames: JSON.stringify(Array.from(new Set(merged.domainNames))),
      autoRenew: merged.autoRenew,
      providerOptions: providerOptions ? JSON.stringify(providerOptions) : null,
      certificatePem: merged.certificatePem ?? null,
      privateKeyPem: merged.privateKeyPem ? encryptSecret(merged.privateKeyPem) : null,
      updatedAt: now
    })
    .where(eq(certificates.id, id));

  await logAuditEvent({
    userId: actorUserId,
    action: "update",
    entityType: "certificate",
    entityId: id,
    summary: `Updated certificate ${merged.name}`
  });
  await applyOrUndo({
    actorUserId,
    acceptedBefore,
    what: "certificate",
    undo: async () => {
      if (!previousRow) return;
      const { id: _id, ...columns } = previousRow;
      void _id;
      await appDb.update(certificates).set(columns).where(eq(certificates.id, id));
      await logAuditEvent({
        userId: actorUserId,
        action: "update",
        entityType: "certificate",
        entityId: id,
        summary: `Undid the update of certificate ${existing.name}: Caddy rejected the configuration with it`
      });
    },
  });
  return (await getCertificate(id))!;
}

function parseHostDomains(raw: string): string[] {
  try {
    const value = JSON.parse(raw);
    return Array.isArray(value) ? value.filter((domain): domain is string => typeof domain === "string") : [];
  } catch {
    return [];
  }
}

/**
 * Deletes a certificate. Proxy hosts that use it fall back to automatic TLS
 * (Caddy obtains a certificate for their names) in the same transaction:
 * SQLite does not enforce the schema's ON DELETE SET NULL here, so without
 * this they would keep pointing at a row that no longer exists. L4 hosts do
 * not reference certificates (they use what Caddy holds for their SNI names).
 *
 * A wildcard name can only be obtained automatically with a DNS provider
 * (DNS-01), as when a host is saved (assertWildcardIssuable): without one,
 * a certificate that a wildcard host uses cannot be deleted.
 */
export async function deleteCertificate(id: number, actorUserId: number) {
  const existing = await getCertificate(id);
  if (!existing) {
    throw new Error("Certificate not found");
  }

  const users = await appDb
    .select({ name: proxyHosts.name, domains: proxyHosts.domains })
    .from(proxyHosts)
    .where(eq(proxyHosts.certificateId, id));
  const wildcardUser = users.find((host) => parseHostDomains(host.domains).some((domain) => domain.trim().startsWith("*.")));
  if (wildcardUser) {
    const dns = await getDnsProviderSettings();
    if (!(dns?.default && dns.providers[dns.default])) {
      throw new ApiValidationError(
        `Proxy host "${wildcardUser.name}" uses this certificate for a wildcard name, which needs a DNS provider to be obtained automatically. ` +
          "Set a default DNS provider in Certificate settings, or give the host another certificate, before deleting it."
      );
    }
  }

  const now = nowIso();
  const detached = await appDb.transaction(async (tx) => {
    const hosts = await tx
      .select({ id: proxyHosts.id, name: proxyHosts.name })
      .from(proxyHosts)
      .where(eq(proxyHosts.certificateId, id));
    if (hosts.length > 0) {
      await tx.update(proxyHosts).set({ certificateId: null, updatedAt: now }).where(eq(proxyHosts.certificateId, id));
    }
    await tx.delete(certificates).where(eq(certificates.id, id));
    return hosts;
  });

  await logAuditEvent({
    userId: actorUserId,
    action: "delete",
    entityType: "certificate",
    entityId: id,
    summary:
      detached.length > 0
        ? `Deleted certificate ${existing.name}; ${detached.length === 1 ? "1 proxy host uses" : `${detached.length} proxy hosts use`} automatic TLS instead`
        : `Deleted certificate ${existing.name}`,
    data: detached.length > 0 ? { proxyHosts: detached.map((host) => ({ id: host.id, name: host.name })) } : undefined
  });
  for (const host of detached) {
    await logAuditEvent({
      userId: actorUserId,
      action: "update",
      entityType: "proxy_host",
      entityId: host.id,
      summary: `Proxy host ${host.name} uses automatic TLS: its certificate ${existing.name} was deleted`,
      data: { certificateId: { before: id, after: null } }
    });
  }
  await applyCaddyConfig();
}

/**
 * Encrypt private keys and remove arbitrary provider-option fields written by
 * older releases. The scan is idempotent and intentionally does not rely on a
 * one-time flag, so restored legacy backups are repaired on the next startup.
 */
export async function migrateLegacyCertificateStorage(): Promise<number> {
  const rows = await appDb
    .select({
      id: certificates.id,
      privateKeyPem: certificates.privateKeyPem,
      providerOptions: certificates.providerOptions,
    })
    .from(certificates);
  let migrated = 0;

  for (const row of rows) {
    const updates: Partial<Pick<CertificateRow, "privateKeyPem" | "providerOptions">> = {};
    if (row.privateKeyPem && !isEncryptedSecret(row.privateKeyPem)) {
      updates.privateKeyPem = encryptSecret(row.privateKeyPem);
    }

    const providerOptions = sanitizeStoredCertificateProviderOptions(row.providerOptions);
    if (providerOptions !== row.providerOptions) {
      updates.providerOptions = providerOptions;
    }

    if (Object.keys(updates).length === 0) continue;
    await appDb
      .update(certificates)
      .set(updates)
      .where(eq(certificates.id, row.id));
    migrated += 1;
  }

  return migrated;
}
