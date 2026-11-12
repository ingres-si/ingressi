import { test, expect } from '@playwright/test';
import {
  createExternalCa,
  createSelfSignedServerCertificate,
  issueExternalClientCertificate,
  parsePkcs12Identity,
  type Pkcs12Identity,
} from '../../helpers/certs';
import { httpsGet, httpsGetOutcome, type ClientTlsIdentity, waitForHttpsRoute } from '../../helpers/https';
import {
  createProxyHost,
  generateCaCertificate,
  importCaCertificate,
  importCertificate,
  issueClientCertificate,
  openEditHostDialog,
  openEditorSection,
  revokeIssuedClientCertificate,
} from '../../helpers/proxy-api';

/**
 * "Certificate authority" trust mode: a host trusts every client certificate an
 * imported CA signs (Cloudflare Authenticated Origin Pulls style), no listing.
 */
const PREFIX = `func-mtls-ca-${Date.now()}`;
const SERVER_CERT_NAME = `${PREFIX}-server-cert`;
const EXTERNAL_CA_NAME = `${PREFIX}-external-ca`;
const OTHER_EXTERNAL_CA_NAME = `${PREFIX}-other-external-ca`;
const GENERATED_CA_NAME = `${PREFIX}-generated-ca`;
const BUNDLE_PASSWORD = 'TestBundlePassword2026!';
const ECHO_BODY = 'echo-ok';

const CA_DOMAIN = `${PREFIX}-ca.test`;
const GENERATED_DOMAIN = `${PREFIX}-generated.test`;
const IDENTITY_DOMAIN = `${PREFIX}-identity.test`;

const tls = (identity: Pkcs12Identity): ClientTlsIdentity => ({ cert: identity.certificatePem, key: identity.privateKeyPem });

function expectBlocked(outcome: Awaited<ReturnType<typeof httpsGetOutcome>>): void {
  if (outcome.response) {
    expect(outcome.response.status).not.toBe(200);
    return;
  }
  expect(outcome.error).toBeDefined();
}

let externalCa: ReturnType<typeof createExternalCa>;
let otherExternalCa: ReturnType<typeof createExternalCa>;
let fromExternal1: Pkcs12Identity;
let fromExternal2: Pkcs12Identity;
let expiredFromExternal: Pkcs12Identity;
let fromOther: Pkcs12Identity;
let fromGenerated: Pkcs12Identity;
let revokedGenerated: Pkcs12Identity;

test.describe.serial('mTLS trust by certificate authority', () => {
  test.setTimeout(180_000);

  test('setup: import an external CA, create a CA-trust host', async ({ page }) => {
    externalCa = createExternalCa(`${EXTERNAL_CA_NAME} Root`);
    otherExternalCa = createExternalCa(`${OTHER_EXTERNAL_CA_NAME} Root`);
    // Two certs the host has never been told about: the point of the mode.
    fromExternal1 = issueExternalClientCertificate(externalCa, `${PREFIX}-one`);
    fromExternal2 = issueExternalClientCertificate(externalCa, `${PREFIX}-two`);
    expiredFromExternal = issueExternalClientCertificate(externalCa, `${PREFIX}-expired`, { expired: true });
    fromOther = issueExternalClientCertificate(otherExternalCa, `${PREFIX}-other`);

    const domains = [CA_DOMAIN, GENERATED_DOMAIN, IDENTITY_DOMAIN];
    const server = createSelfSignedServerCertificate(CA_DOMAIN, domains);
    await importCertificate(page, { name: SERVER_CERT_NAME, domains, certificatePem: server.certificatePem, privateKeyPem: server.privateKeyPem });

    await importCaCertificate(page, { name: EXTERNAL_CA_NAME, certificatePem: externalCa.certificatePem });
    await importCaCertificate(page, { name: OTHER_EXTERNAL_CA_NAME, certificatePem: otherExternalCa.certificatePem });
    await generateCaCertificate(page, { name: GENERATED_CA_NAME, commonName: `${GENERATED_CA_NAME} Root` });
    fromGenerated = parsePkcs12Identity(
      await issueClientCertificate(page, { caName: GENERATED_CA_NAME, commonName: `${PREFIX}-generated`, exportPassword: BUNDLE_PASSWORD }),
      BUNDLE_PASSWORD
    );

    revokedGenerated = parsePkcs12Identity(
      await issueClientCertificate(page, { caName: GENERATED_CA_NAME, commonName: `${PREFIX}-generated-revoked`, exportPassword: BUNDLE_PASSWORD }),
      BUNDLE_PASSWORD
    );

    await createProxyHost(page, {
      name: `${PREFIX} CA Host`,
      domain: CA_DOMAIN,
      upstream: 'echo-server:8080',
      certificateName: SERVER_CERT_NAME,
      mtlsTrustedAuthorityNames: [EXTERNAL_CA_NAME],
    });
    await createProxyHost(page, {
      name: `${PREFIX} Generated CA Host`,
      domain: GENERATED_DOMAIN,
      upstream: 'echo-server:8080',
      certificateName: SERVER_CERT_NAME,
      mtlsTrustedAuthorityNames: [GENERATED_CA_NAME],
    });
    await createProxyHost(page, {
      name: `${PREFIX} Identity Host`,
      domain: IDENTITY_DOMAIN,
      upstream: 'echo-server:8080',
      certificateName: SERVER_CERT_NAME,
      mtlsCaNames: [GENERATED_CA_NAME],
    });

    await waitForHttpsRoute(CA_DOMAIN, tls(fromExternal1));
    await waitForHttpsRoute(GENERATED_DOMAIN, tls(fromGenerated));
    await waitForHttpsRoute(IDENTITY_DOMAIN, tls(fromGenerated));
  });

  test('accepts any certificate the trusted CA signs, including ones never listed', async () => {
    for (const identity of [fromExternal1, fromExternal2]) {
      const response = await httpsGet(CA_DOMAIN, '/', tls(identity));
      expect(response.status).toBe(200);
      expect(response.body).toContain(ECHO_BODY);
    }
  });

  test('fails the handshake without a client certificate', async () => {
    const outcome = await httpsGetOutcome(CA_DOMAIN);
    expect(outcome.response).toBeUndefined();
    expectBlocked(outcome);
  });

  test('refuses certificates from another CA, even an imported one', async () => {
    expectBlocked(await httpsGetOutcome(CA_DOMAIN, '/', tls(fromOther)));
    expectBlocked(await httpsGetOutcome(CA_DOMAIN, '/', tls(fromGenerated)));
  });

  test('refuses an expired certificate from the trusted CA', async () => {
    expectBlocked(await httpsGetOutcome(CA_DOMAIN, '/', tls(expiredFromExternal)));
  });

  test('refuses a self-signed certificate that copies the trusted CA subject', async () => {
    // Same subject name as the trusted CA, but signed with a different key.
    const imposter = createExternalCa(`${EXTERNAL_CA_NAME} Root`);
    const forged = issueExternalClientCertificate(imposter, `${PREFIX}-forged`);
    expectBlocked(await httpsGetOutcome(CA_DOMAIN, '/', tls(forged)));
  });

  test('does not let the trust leak to a host that trusts another CA', async () => {
    expectBlocked(await httpsGetOutcome(GENERATED_DOMAIN, '/', tls(fromExternal1)));
    expectBlocked(await httpsGetOutcome(IDENTITY_DOMAIN, '/', tls(fromExternal1)));
    expectBlocked(await httpsGetOutcome(CA_DOMAIN, '/', tls(fromOther)));
  });

  test('a generated CA in CA mode accepts its active certificates only on its own host', async () => {
    const ok = await httpsGet(GENERATED_DOMAIN, '/', tls(fromGenerated));
    expect(ok.status).toBe(200);
    expectBlocked(await httpsGetOutcome(GENERATED_DOMAIN));
  });

  test('a revoked certificate of a generated CA is refused in CA mode, others keep working', async ({ page }) => {
    expect((await httpsGet(GENERATED_DOMAIN, '/', tls(revokedGenerated))).status).toBe(200);
    await revokeIssuedClientCertificate(page, GENERATED_CA_NAME, `${PREFIX}-generated-revoked`);
    await waitForHttpsRoute(GENERATED_DOMAIN, tls(fromGenerated));
    expectBlocked(await httpsGetOutcome(GENERATED_DOMAIN, '/', tls(revokedGenerated)));
    expect((await httpsGet(GENERATED_DOMAIN, '/', tls(fromGenerated))).status).toBe(200);
  });

  test('role/certificate mode keeps working unchanged', async () => {
    const ok = await httpsGet(IDENTITY_DOMAIN, '/', tls(fromGenerated));
    expect(ok.status).toBe(200);
    expectBlocked(await httpsGetOutcome(IDENTITY_DOMAIN));
  });

  test('the editor shows the chosen authority and keeps it after reopening', async ({ page }) => {
    await openEditHostDialog(page, `${PREFIX} CA Host`);
    await openEditorSection(page, 'Access');
    const card = page.locator('#f-mtls');
    await expect(card.getByRole('group', { name: 'Trust' }).getByRole('button', { name: 'Certificate authority' })).toHaveAttribute('aria-pressed', 'true');
    const row = card.locator('#f-mtls-cas label').filter({ hasText: EXTERNAL_CA_NAME });
    await expect(row.getByRole('checkbox')).toBeChecked();
    await expect(row.getByText('Accepts everything it signs')).toBeVisible();
    await expect(card.locator('#f-mtls-cas label').filter({ hasText: OTHER_EXTERNAL_CA_NAME }).getByRole('checkbox')).not.toBeChecked();
    await expect(card.getByText('Trusted roles')).toHaveCount(0);
    // A CA that issues certificates here says so, and warns that revocation applies.
    await card.locator('#f-mtls-cas label').filter({ hasText: GENERATED_CA_NAME }).click();
    await expect(card.locator('#f-mtls-cas label').filter({ hasText: GENERATED_CA_NAME }).getByText('Issues certificates here')).toBeVisible();
    await expect(card.getByText('only its client certificates that are not revoked get in')).toBeVisible();
  });
});
