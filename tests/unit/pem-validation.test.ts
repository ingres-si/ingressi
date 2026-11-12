/**
 * Certificates and keys are checked before they are stored
 * (src/lib/pem-validation.ts), the way Caddy reads them: what it would
 * reject the whole configuration over is refused, and everything it takes
 * (RSA, ECDSA and Ed25519 keys in PKCS#1, SEC 1 or PKCS#8, chains) passes.
 */
import { describe, it, expect } from 'vitest';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import {
  assertCaCertificatePem,
  assertCertificateChainPem,
  assertImportedCertificatePem,
  assertPrivateKeyPem,
} from '@/src/lib/pem-validation';
import { ApiValidationError } from '@/src/lib/api-errors';
import { createExternalCa, createSelfSignedServerCertificate } from '../helpers/certs';

// Throwaway pairs made with openssl for these tests only (forge, which the helpers use, makes RSA only).
const EC_CERT = `-----BEGIN CERTIFICATE-----
MIIBaDCCAQ2gAwIBAgITU9SpOmUGYOaDEXHljRUO8rJMHjAKBggqhkjOPQQDAjAZ
MRcwFQYDVQQDDA5lYy5leGFtcGxlLmNvbTAgFw0yNjExMTIwNzQxNTVaGA8yMTI2
MTAxOTA3NDE1NVowGTEXMBUGA1UEAwwOZWMuZXhhbXBsZS5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARknp9t3aNIAn33ndAITsZylRw+/MZIzUtRCjA7DUrD
GKvKUVjmqCogLS6xRghfkXGXCJLmf3JzJq7yRO1ntNmZozIwMDAdBgNVHQ4EFgQU
wvGlrPy9V7aCA9jLTyAd+nENU6IwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNJADBGAiEArSV8mNf+/HXc5UdWrqNtTVSjEibMREXsWB+9f27z82ICIQCg1HGe
NXwQMh9a7bAB6ouLilW/huXiFuCeo4y+eayPHw==
-----END CERTIFICATE-----`;
// As openssl writes it: the curve first, then the SEC 1 key.
const EC_KEY = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBeTIDTTvo6jzU962o3M7Y/J4EEmEAzxRCYfllX82H3IoAoGCCqGSM49
AwEHoUQDQgAEZJ6fbd2jSAJ9953QCE7GcpUcPvzGSM1LUQowOw1KwxirylFY5qgq
IC0usUYIX5FxlwiS5n9ycyau8kTtZ7TZmQ==
-----END EC PRIVATE KEY-----`;
const ED_CERT = `-----BEGIN CERTIFICATE-----
MIIBJzCB2qADAgECAhQOo3ajJUpK1DMBBeFCz9SAzsOhFTAFBgMrZXAwGTEXMBUG
A1UEAwwOZWQuZXhhbXBsZS5jb20wIBcNMjYxMTEyMDc0MTU1WhgPMjEyNjEwMTkw
NzQxNTVaMBkxFzAVBgNVBAMMDmVkLmV4YW1wbGUuY29tMCowBQYDK2VwAyEArmvJ
aa6NchCIbOUg2Y0gC9EsxHH6vSIBEsEjNaO8umijMjAwMB0GA1UdDgQWBBR4Cdaq
+ONJr9ECPkcNeINgtb8KpzAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBACn4UXvt
vmYHXDOTzRgf3UuBF4K3lMMCJXD65GDFlI+Z33EWO7fVbLix7S5Ab+RB2ikwv86Z
LNSz/v0VqlaT7Qk=
-----END CERTIFICATE-----`;
const ED_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBAJsGWgHkEF8fTCFTgo0whM7nv1/56IAgot3x4zktB9
-----END PRIVATE KEY-----`;

const rsa = createSelfSignedServerCertificate('rsa.example.com', ['rsa.example.com']);
const otherRsa = createSelfSignedServerCertificate('other.example.com', ['other.example.com']);
const ca = createExternalCa('PEM test CA');
const pkcs8 = (pem: string) => createPrivateKey(pem).export({ type: 'pkcs8', format: 'pem' }) as string;

function refusal(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ApiValidationError);
    return (error as Error).message;
  }
  throw new Error('expected a refusal');
}

describe('an imported certificate and its key', () => {
  it.each([
    ['RSA, PKCS#1 key', rsa.certificatePem, rsa.privateKeyPem],
    ['RSA, PKCS#8 key', rsa.certificatePem, pkcs8(rsa.privateKeyPem)],
    ['ECDSA, SEC 1 key after its EC PARAMETERS block', EC_CERT, EC_KEY],
    ['ECDSA, PKCS#8 key', EC_CERT, pkcs8(EC_KEY)],
    ['Ed25519', ED_CERT, ED_KEY],
    ['Windows line endings and text around the blocks', `subject=CN=x\r\n${rsa.certificatePem.replace(/\r?\n/g, '\r\n')}\r\n`, `\r\n${rsa.privateKeyPem}\r\n`],
    ['a chain: the certificate, then the one that signed it', `${rsa.certificatePem}\n${ca.certificatePem}`, rsa.privateKeyPem],
  ])('passes: %s', (_label, certificate, key) => {
    expect(() => assertImportedCertificatePem(certificate, key)).not.toThrow();
  });

  it('takes the first certificate of a chain as the one the key belongs to', () => {
    expect(assertCertificateChainPem(`${rsa.certificatePem}\n${ca.certificatePem}`).subject).toContain('rsa.example.com');
    expect(refusal(() => assertImportedCertificatePem(`${ca.certificatePem}\n${rsa.certificatePem}`, rsa.privateKeyPem))).toMatch(/does not belong to the certificate/);
  });

  it.each([
    ['text that is not PEM', 'not pem', rsa.privateKeyPem, /must be PEM: it has no "-----BEGIN CERTIFICATE-----" block/],
    ['a key where the certificate goes', rsa.privateKeyPem, rsa.privateKeyPem, /has no "-----BEGIN CERTIFICATE-----" block/],
    ['a certificate block with something else in it', '-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----', rsa.privateKeyPem, /could not be read as an X\.509 certificate/],
    ['a broken certificate later in the chain', `${rsa.certificatePem}\n-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----`, rsa.privateKeyPem, /certificate 2 of 2 in The certificate could not be read/],
    ['a key that is not PEM', rsa.certificatePem, 'not a key', /The private key must be PEM/],
    ['a certificate where the key goes', rsa.certificatePem, rsa.certificatePem, /The private key must be PEM/],
    ['a key block with something else in it', rsa.certificatePem, '-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----', /could not be read as a private key/],
    ['the key of another certificate', rsa.certificatePem, otherRsa.privateKeyPem, /does not belong to the certificate/],
    ['a key of another kind than the certificate', rsa.certificatePem, ED_KEY, /does not belong to the certificate/],
    ['nothing', '', '', /is required and must be PEM text/],
    ['a number', 7, rsa.privateKeyPem, /The certificate is required and must be PEM text/],
    ['an object as key', rsa.certificatePem, { pem: rsa.privateKeyPem }, /The private key is required and must be PEM text/],
  ])('refuses %s', (_label, certificate, key, message) => {
    expect(refusal(() => assertImportedCertificatePem(certificate, key))).toMatch(message);
  });

  it('refuses a key protected with a passphrase, in both forms', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const modern = privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'x' }) as string;
    const legacy = privateKey.export({ type: 'pkcs1', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'x' }) as string;
    expect(modern).toContain('ENCRYPTED PRIVATE KEY');
    expect(legacy).toContain('Proc-Type: 4,ENCRYPTED');
    for (const key of [modern, legacy]) {
      expect(refusal(() => assertPrivateKeyPem(key, null))).toMatch(/protected with a passphrase/);
    }
  });

  it('refuses a key of a kind Caddy does not load', () => {
    const { privateKey } = generateKeyPairSync('x25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    expect(refusal(() => assertPrivateKeyPem(pem, null))).toMatch(/must be an RSA, ECDSA or Ed25519 key/);
  });

  it('never repeats the input in a refusal', () => {
    const keyText = otherRsa.privateKeyPem.split(/\r?\n/)[2];
    for (const message of [
      refusal(() => assertImportedCertificatePem(rsa.certificatePem, otherRsa.privateKeyPem)),
      refusal(() => assertImportedCertificatePem(otherRsa.privateKeyPem, otherRsa.privateKeyPem)),
      refusal(() => assertImportedCertificatePem(rsa.certificatePem, otherRsa.privateKeyPem.replace('MII', 'XXX'))),
    ]) {
      expect(message).not.toContain(keyText);
      expect(message.length).toBeLessThan(200);
    }
  });
});

describe('a CA certificate', () => {
  it('is exactly one certificate', () => {
    expect(assertCaCertificatePem(ca.certificatePem).subject).toContain('PEM test CA');
    expect(() => assertCaCertificatePem(`\n  ${ca.certificatePem}\n\n`)).not.toThrow();
    expect(() => assertCaCertificatePem(EC_CERT)).not.toThrow();
  });

  it.each([
    ['two certificates', `${ca.certificatePem}\n${rsa.certificatePem}`],
    ['text before it', `subject=CN=x\n${ca.certificatePem}`],
    ['text after it', `${ca.certificatePem}\ntrailing`],
    ['a key with it', `${ca.certificatePem}\n${ca.privateKeyPem}`],
    ['text that is not PEM', 'not pem'],
    ['a key', ca.privateKeyPem],
  ])('refuses %s', (_label, value) => {
    expect(refusal(() => assertCaCertificatePem(value))).toMatch(/must be exactly one PEM certificate/);
  });

  it('refuses a certificate block that is not a certificate, and what is not text', () => {
    expect(refusal(() => assertCaCertificatePem('-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----'))).toMatch(/could not be read as an X\.509 certificate/);
    expect(refusal(() => assertCaCertificatePem(null))).toMatch(/is required and must be PEM text/);
    expect(refusal(() => assertCaCertificatePem(['x']))).toMatch(/is required and must be PEM text/);
  });

  it('takes the signing key that belongs to it, and no other', () => {
    const certificate = assertCaCertificatePem(ca.certificatePem);
    expect(() => assertPrivateKeyPem(ca.privateKeyPem, certificate, 'The CA private key')).not.toThrow();
    expect(refusal(() => assertPrivateKeyPem(rsa.privateKeyPem, certificate, 'The CA private key'))).toBe('The CA private key does not belong to the certificate');
  });
});
