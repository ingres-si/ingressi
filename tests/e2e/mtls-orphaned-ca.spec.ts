import { test, expect } from '@playwright/test';
import { openCreateHostDialog, openEditorSection, setEditorSwitch } from '../helpers/proxy-api';
import { createExternalCa, issueExternalClientCertificate } from '../helpers/certs';

const API_CA = 'http://localhost:3000/api/v1/ca-certificates';
const API_CLIENT_CERTS = 'http://localhost:3000/api/v1/client-certificates';

// Real certificates: the API refuses what Caddy could not load.
const CA = createExternalCa('Orphan Test CA');
const CLIENT_PEM = issueExternalClientCertificate(CA, 'orphan-test-device').certificatePem;

/**
 * Regression: deleting a CA certificate must also remove the client
 * certificates it issued. The schema declares onDelete: "cascade", but
 * better-sqlite3 runs with PRAGMA foreign_keys OFF, so the cascade never
 * fired — orphaned issued certs kept appearing as selectable entries in the
 * Mutual TLS (mTLS) "Trusted Certificates" picker, grouped under a dangling
 * "CA #<id>" header.
 */
test.describe('mTLS — deleted CA must not remain selectable', () => {
  test('issued certs of a deleted CA disappear from the mTLS picker', async ({ page }) => {
    await page.goto('/proxy-hosts');
    const origin = new URL(page.url()).origin;

    const caName = 'Orphan Test CA';
    const certCommonName = 'orphan-test-device';

    // 1. Create a CA.
    const caResp = await page.request.post(API_CA, {
      headers: { Origin: origin },
      data: { name: caName, certificatePem: CA.certificatePem, privateKeyPem: CA.privateKeyPem },
    });
    expect(caResp.ok()).toBeTruthy();
    const ca = await caResp.json() as { id: number };

    // 2. Issue a client certificate from that CA.
    const certResp = await page.request.post(API_CLIENT_CERTS, {
      headers: { Origin: origin },
      data: {
        caCertificateId: ca.id,
        commonName: certCommonName,
        serialNumber: 'ORPHAN01',
        certificatePem: CLIENT_PEM,
        validFrom: '2026-01-01T00:00:00Z',
        validTo: '2030-01-01T00:00:00Z',
      },
    });
    expect(certResp.ok()).toBeTruthy();
    const cert = await certResp.json() as { id: number };

    let caDeleted = false;
    try {
      // 3. The issued cert is selectable in a host's mTLS picker.
      const picker = await openMtlsPicker(page);
      await expect(picker.getByText(caName)).toBeVisible({ timeout: 10000 });
      await expect(picker.getByText(certCommonName)).toBeVisible();

      // 4. Delete the CA. This must cascade to its issued certificates.
      const delResp = await page.request.delete(`${API_CA}/${ca.id}`, { headers: { Origin: origin } });
      expect(delResp.ok()).toBeTruthy();
      caDeleted = true;

      // The issued certificate must be gone from the API too (real cascade).
      const certAfter = await page.request.get(`${API_CLIENT_CERTS}/${cert.id}`);
      expect(certAfter.status()).toBe(404);

      // 5. The CA and its cert must no longer appear in the mTLS picker.
      const picker2 = await openMtlsPicker(page);
      await expect(picker2.getByText(certCommonName)).toHaveCount(0);
      await expect(picker2.getByText(caName)).toHaveCount(0);
    } finally {
      if (!caDeleted) {
        await page.request.delete(`${API_CA}/${ca.id}`, { headers: { Origin: origin } });
      }
    }
  });
});

/**
 * Opens a new host in the host editor and turns on client certificates (mTLS)
 * so the "Trusted certificates" picker is rendered. Returns the mTLS card.
 */
async function openMtlsPicker(page: import('@playwright/test').Page) {
  await openCreateHostDialog(page);
  await openEditorSection(page, 'Access');
  await setEditorSwitch(page, 'Require client certificates', true);
  const card = page.locator('#f-mtls');
  await expect(card.getByText('Trusted certificates')).toBeVisible();
  return card;
}
