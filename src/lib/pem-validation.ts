/**
 * Checks certificates and private keys before they are stored, the way Caddy
 * reads them when it loads the configuration (Go's tls.X509KeyPair for an
 * imported certificate, x509.ParseCertificate for a trusted CA). A value
 * Caddy cannot read would otherwise sit in the database until a host uses
 * it, and then make Caddy reject the whole configuration.
 *
 * The messages name what is wrong and never quote the input: it can be a
 * private key.
 */
import { createPrivateKey, X509Certificate, type KeyObject } from "node:crypto";
import { ApiValidationError } from "./api-errors";

type PemBlock = { type: string; text: string; body: string };

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

function pemBlocks(pem: string): PemBlock[] {
  return [...pem.matchAll(PEM_BLOCK)].map((match) => ({ type: match[1], text: match[0], body: match[2] }));
}

function requireText(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new ApiValidationError(`${label} is required and must be PEM text`);
  }
  return value;
}

function parseCertificateBlock(block: PemBlock, label: string, position: number, total: number): X509Certificate {
  try {
    return new X509Certificate(block.text);
  } catch {
    const which = total > 1 ? `certificate ${position} of ${total} in ${label}` : label;
    throw new ApiValidationError(`${which} could not be read as an X.509 certificate`);
  }
}

/**
 * A certificate with its chain: one or more CERTIFICATE blocks, the first of
 * which is the certificate itself. Returns that first certificate.
 */
export function assertCertificateChainPem(value: unknown, label = "The certificate"): X509Certificate {
  const blocks = pemBlocks(requireText(value, label)).filter((block) => block.type === "CERTIFICATE");
  if (blocks.length === 0) {
    throw new ApiValidationError(`${label} must be PEM: it has no "-----BEGIN CERTIFICATE-----" block`);
  }
  const parsed = blocks.map((block, index) => parseCertificateBlock(block, label, index + 1, blocks.length));
  return parsed[0];
}

/** Key types Go's tls.X509KeyPair takes. */
const KEY_TYPES: ReadonlySet<string> = new Set(["rsa", "ec", "ed25519"]);

/**
 * An unencrypted private key (PKCS#1, PKCS#8 or SEC 1), which must belong to
 * `certificate` when one is given. Like Go, the first block whose type ends
 * in "PRIVATE KEY" is the key; blocks before it (EC PARAMETERS) are skipped.
 */
export function assertPrivateKeyPem(value: unknown, certificate: X509Certificate | null, label = "The private key"): KeyObject {
  const block = pemBlocks(requireText(value, label)).find(
    (candidate) => candidate.type === "PRIVATE KEY" || candidate.type.endsWith(" PRIVATE KEY")
  );
  if (!block) {
    throw new ApiValidationError(`${label} must be PEM: it has no "-----BEGIN … PRIVATE KEY-----" block`);
  }
  if (block.type === "ENCRYPTED PRIVATE KEY" || /Proc-Type:\s*4,\s*ENCRYPTED/i.test(block.body)) {
    throw new ApiValidationError(`${label} is protected with a passphrase; remove the passphrase before importing it`);
  }
  let key: KeyObject;
  try {
    key = createPrivateKey(block.text);
  } catch {
    throw new ApiValidationError(`${label} could not be read as a private key`);
  }
  if (!KEY_TYPES.has(key.asymmetricKeyType ?? "")) {
    throw new ApiValidationError(`${label} must be an RSA, ECDSA or Ed25519 key`);
  }
  if (certificate) {
    let matches: boolean;
    try {
      matches = certificate.checkPrivateKey(key);
    } catch {
      matches = false;
    }
    if (!matches) throw new ApiValidationError(`${label} does not belong to the certificate`);
  }
  return key;
}

/** An imported certificate: the chain and the key of its first certificate. */
export function assertImportedCertificatePem(certificatePem: unknown, privateKeyPem: unknown): void {
  assertPrivateKeyPem(privateKeyPem, assertCertificateChainPem(certificatePem));
}

/**
 * A CA certificate: exactly one CERTIFICATE block and nothing else, because
 * Caddy is handed that one certificate (caddy-mtls.ts) and anything around it
 * would end up inside it.
 */
export function assertCaCertificatePem(value: unknown, label = "The CA certificate"): X509Certificate {
  const text = requireText(value, label).trim();
  const blocks = pemBlocks(text);
  if (blocks.length !== 1 || blocks[0].type !== "CERTIFICATE" || blocks[0].text !== text) {
    throw new ApiValidationError(
      `${label} must be exactly one PEM certificate ("-----BEGIN CERTIFICATE-----" to "-----END CERTIFICATE-----"), with nothing before or after it`
    );
  }
  return parseCertificateBlock(blocks[0], label, 1, 1);
}
