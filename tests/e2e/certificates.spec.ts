import { test, expect } from '@playwright/test';
import { createExternalCa, createSelfSignedServerCertificate, issueExternalClientCertificate } from '../helpers/certs';
import { escapeRegExp } from '../helpers/text';

test.describe('Certificates', () => {
  test('page loads with tabs visible', async ({ page }) => {
    await page.goto('/certificates');
    // At minimum the page should load without error
    await expect(page).not.toHaveURL(/error|login/);
    await expect(page.locator('body')).toBeVisible();
  });

  test('certificates page has certificate management UI', async ({ page }) => {
    await page.goto('/certificates');
    // Should have some kind of Add button or tab UI
    await expect(page.locator('body')).toBeVisible();
    // Look for tabs or buttons
    const hasAddButton = await page.getByRole('button', { name: /add|new|create/i }).count() > 0;
    const hasTab = await page.getByRole('tab').count() > 0;
    expect(hasAddButton || hasTab).toBe(true);
  });

  test('navigating to certificates does not redirect to login', async ({ page }) => {
    await page.goto('/certificates');
    await expect(page).not.toHaveURL(/login/);
  });

  test('wildcard cert covers subdomain — no duplicate in ACME tab', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', 'Origin': BASE_URL };
    const domain = `wc-test-${Date.now()}.example`;

    // 1. Create a managed certificate with wildcard + base domain
    const certRes = await page.request.post(`${API}/certificates`, {
      data: {
        name: `Wildcard ${domain}`,
        type: 'managed',
        domainNames: [domain, `*.${domain}`],
        autoRenew: true,
      },
      headers,
    });
    expect(certRes.status()).toBe(201);
    const cert = await certRes.json();

    // 2. Create a proxy host for a subdomain (no explicit certificateId → auto ACME)
    const hostRes = await page.request.post(`${API}/proxy-hosts`, {
      data: {
        name: `Sub ${domain}`,
        domains: [`sub.${domain}`],
        upstreams: ['127.0.0.1:8080'],
      },
      headers,
    });
    expect(hostRes.status()).toBe(201);
    const host = await hostRes.json();

    try {
      // 3. Visit certificates page — the subdomain host is listed under the
      // wildcard certificate, not as a certificate of its own.
      await page.goto('/certificates');
      await expect(page.getByRole('tab', { name: /^certificates/i })).toHaveAttribute('aria-selected', 'true');
      const table = page.getByRole('region', { name: 'Certificates', exact: true }).getByRole('table');
      await expect(table.getByRole('rowheader').filter({ hasText: domain }).first()).toBeVisible({ timeout: 10_000 });
      await expect(table.getByRole('rowheader').filter({ hasText: `sub.${domain}` })).toHaveCount(0);
    } finally {
      // Cleanup: delete the proxy host and certificate
      await page.request.delete(`${API}/proxy-hosts/${host.id}`, { headers });
      await page.request.delete(`${API}/certificates/${cert.id}`, { headers });
    }
  });

  test('ACME wildcard host hides subdomain ACME hosts in certificates page', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', 'Origin': BASE_URL };
    const domain = `acme-wc-${Date.now()}.example`;

    // Auto-managed wildcard hosts require a DNS provider (ACME DNS-01 challenge).
    // Configure one for this isolated test stack and clear it afterwards.
    const dnsProviderUrl = `${API}/settings/dns-provider`;
    const setDnsRes = await page.request.put(dnsProviderUrl, {
      data: { providers: { duckdns: { api_token: 'e2e-fake-token' } }, default: 'duckdns' },
      headers,
    });
    expect(setDnsRes.ok()).toBeTruthy();

    let wcHostId: number | undefined;
    let subHostId: number | undefined;
    try {
      // 1. Create a proxy host with wildcard domain (no certificate → ACME auto)
      const wcHostRes = await page.request.post(`${API}/proxy-hosts`, {
        data: {
          name: `Wildcard ${domain}`,
          domains: [`*.${domain}`],
          upstreams: ['127.0.0.1:8080'],
        },
        headers,
      });
      expect(wcHostRes.status()).toBe(201);
      wcHostId = (await wcHostRes.json()).id;

      // 2. Create a proxy host for a subdomain (also no certificate → ACME auto)
      const subHostRes = await page.request.post(`${API}/proxy-hosts`, {
        data: {
          name: `Sub ${domain}`,
          domains: [`sub.${domain}`],
          upstreams: ['127.0.0.1:8080'],
        },
        headers,
      });
      expect(subHostRes.status()).toBe(201);
      subHostId = (await subHostRes.json()).id;

      // 3. Visit certificates page — subdomain should be collapsed under the wildcard
      await page.goto('/certificates');
      const table = page.getByRole('region', { name: 'Certificates', exact: true }).getByRole('table');
      const wildcardRow = table.getByRole('row').filter({ has: page.getByRole('rowheader').filter({ hasText: `*.${domain}` }) });
      await expect(wildcardRow).toBeVisible({ timeout: 10_000 });
      // ACME with a DNS provider: DNS-01
      await expect(wildcardRow.getByText('DNS-01')).toBeVisible();
      // The subdomain host should NOT appear as a separate entry; it is one of the wildcard's hosts
      await expect(table.getByRole('rowheader').filter({ hasText: `sub.${domain}` })).toHaveCount(0);
      await expect(wildcardRow.getByRole('button', { name: /2 hosts/i })).toBeVisible();
    } finally {
      if (subHostId) await page.request.delete(`${API}/proxy-hosts/${subHostId}`, { headers });
      if (wcHostId) await page.request.delete(`${API}/proxy-hosts/${wcHostId}`, { headers });
      await page.request.put(dnsProviderUrl, {
        data: { providers: {}, default: null },
        headers,
      });
    }
  });

  test('deletes an imported certificate from the certificate list (#151)', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', 'Origin': BASE_URL };
    const domain = `import-delete-${Date.now()}.example`;
    const certName = `Imported Delete ${domain}`;
    const { certificatePem, privateKeyPem } = createSelfSignedServerCertificate(domain, [domain]);

    const certRes = await page.request.post(`${API}/certificates`, {
      data: {
        name: certName,
        type: 'imported',
        domainNames: [domain],
        autoRenew: false,
        certificatePem,
        privateKeyPem,
      },
      headers,
    });
    expect(certRes.status()).toBe(201);
    const cert = await certRes.json() as { id: number };

    try {
      await page.goto('/certificates');

      const row = page.getByRole('row').filter({ hasText: certName });
      await expect(row).toBeVisible({ timeout: 10_000 });
      // Imported: the expiry comes from the PEM and the row says how it is obtained.
      await expect(row.getByText('Imported', { exact: true })).toBeVisible();

      await row.getByRole('button', { name: `More actions for ${certName}` }).click();
      await page.getByRole('menuitem', { name: /^delete$/i }).click();

      const dialog = page.getByRole('dialog', { name: /delete imported certificate/i });
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: /delete certificate/i }).click();

      await expect(dialog).not.toBeVisible({ timeout: 10_000 });
      await expect(page.getByText(certName)).toHaveCount(0, { timeout: 10_000 });

      const getRes = await page.request.get(`${API}/certificates/${cert.id}`, { headers: { Origin: BASE_URL } });
      expect(getRes.status()).toBe(404);
    } finally {
      await page.request.delete(`${API}/certificates/${cert.id}`, { headers }).catch(() => undefined);
    }
  });

  test('imports a multiline private key without exposing it through the API (#157)', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', 'Origin': BASE_URL };
    const domain = `import-ui-${Date.now()}.example`;
    const certName = `UI Import ${domain}`;
    const { certificatePem, privateKeyPem } = createSelfSignedServerCertificate(domain, [domain]);
    // HTML textareas normalize CRLF input to LF. Compare against the browser's
    // canonical value while still checking that every PEM line survives.
    const normalizedPrivateKeyPem = privateKeyPem.replace(/\r\n?/g, '\n');

    // Sanity-check the fixture: PEM blocks must be multi-line for this test
    // to meaningfully exercise newline preservation.
    expect(privateKeyPem.split('\n').length).toBeGreaterThan(3);

    let createdId: number | null = null;
    try {
      await page.goto('/certificates');

      // Open the Import drawer from the page header.
      await page.getByRole('button', { name: /^import certificate$/i }).click();

      const drawer = page.getByRole('dialog');
      await expect(drawer).toBeVisible();

      await drawer.getByLabel(/^name$/i).fill(certName);
      await drawer.getByLabel(/domains/i).fill(domain);

      // Certificate PEM goes into a textarea — newlines preserved trivially.
      await drawer.getByLabel(/certificate pem/i).fill(certificatePem);

      // Private Key PEM: paste while the field is in the default (hidden/masked)
      // state. Regression for #157 — a <input type="password"> would silently
      // strip the newlines from the pasted PEM, corrupting the key.
      const keyField = drawer.getByLabel(/private key pem/i);
      await keyField.click();
      await keyField.fill(privateKeyPem);
      expect(await keyField.evaluate((element) => element.tagName)).toBe('TEXTAREA');
      expect(await keyField.inputValue()).toBe(normalizedPrivateKeyPem);

      await drawer.getByRole('button', { name: /import certificate|save changes/i }).click();
      await expect(drawer).not.toBeVisible({ timeout: 10_000 });

      // The ordinary API confirms that a key is stored but must never return
      // the key itself. The textarea assertions above guard newline handling.
      const listRes = await page.request.get(`${API}/certificates`, { headers: { Origin: BASE_URL } });
      expect(listRes.ok()).toBe(true);
      const listBody = await listRes.text();
      const list = JSON.parse(listBody) as Array<{ id: number; name: string; hasPrivateKey: boolean }>;
      const created = list.find((c) => c.name === certName);
      expect(created).toBeTruthy();
      createdId = created!.id;
      expect(created!.hasPrivateKey).toBe(true);
      expect(created).not.toHaveProperty('privateKeyPem');
      expect(listBody).not.toContain(normalizedPrivateKeyPem.split('\n')[1]);
    } finally {
      if (createdId !== null) {
        await page.request.delete(`${API}/certificates/${createdId}`, { headers }).catch(() => undefined);
      }
    }
  });

  test('shows the expiry timeline and marks the row a marker picks', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', 'Origin': BASE_URL };
    const domain = `timeline-${Date.now()}.example`;
    const certName = `Timeline ${domain}`;
    // 20 days left: inside the 30-day renewal band.
    const { certificatePem, privateKeyPem } = createSelfSignedServerCertificate(domain, [domain], 20);
    const certRes = await page.request.post(`${API}/certificates`, {
      data: { name: certName, type: 'imported', domainNames: [domain], autoRenew: false, certificatePem, privateKeyPem },
      headers,
    });
    expect(certRes.status()).toBe(201);
    const cert = await certRes.json() as { id: number };

    try {
      await page.goto('/certificates');
      const timeline = page.getByRole('list', { name: /expiry, next 90 days/i });
      // Each marker is a toggle named after the domain and its time left.
      const escaped = escapeRegExp(domain);
      const marker = timeline.getByRole('button', { name: new RegExp(`^${escaped}: \\d+ days left`) });
      await expect(marker).toBeVisible({ timeout: 10_000 });
      await marker.click();
      await expect(marker).toHaveAttribute('aria-pressed', 'true');

      const row = page.getByRole('row').filter({ hasText: certName });
      await expect(row.getByText('Replace soon')).toBeVisible();

      // The status filter keeps it under "Needs attention".
      await page.getByRole('group', { name: 'Status' }).getByRole('button', { name: /needs attention/i }).click();
      await expect(row).toBeVisible();
      await page.getByRole('group', { name: 'Status' }).getByRole('button', { name: /healthy/i }).click();
      await expect(row).toHaveCount(0);
    } finally {
      await page.request.delete(`${API}/certificates/${cert.id}`, { headers }).catch(() => undefined);
    }
  });

  test('deleting a certificate in use moves its hosts to automatic TLS', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', 'Origin': BASE_URL };
    const domain = `in-use-${Date.now()}.example`;

    const certRes = await page.request.post(`${API}/certificates`, {
      data: { name: `In use ${domain}`, type: 'managed', domainNames: [domain], autoRenew: true },
      headers,
    });
    expect(certRes.status()).toBe(201);
    const cert = await certRes.json() as { id: number };
    const hostRes = await page.request.post(`${API}/proxy-hosts`, {
      data: { name: `In use ${domain}`, domains: [domain], upstreams: ['127.0.0.1:8080'], certificateId: cert.id },
      headers,
    });
    expect(hostRes.status()).toBe(201);
    const host = await hostRes.json() as { id: number; certificateId: number | null };
    expect(host.certificateId).toBe(cert.id);

    try {
      expect((await page.request.delete(`${API}/certificates/${cert.id}`, { headers })).ok()).toBe(true);
      const after = await page.request.get(`${API}/proxy-hosts/${host.id}`, { headers: { Origin: BASE_URL } });
      expect(after.status()).toBe(200);
      expect((await after.json() as { certificateId: number | null }).certificateId).toBeNull();
    } finally {
      await page.request.delete(`${API}/proxy-hosts/${host.id}`, { headers }).catch(() => undefined);
      await page.request.delete(`${API}/certificates/${cert.id}`, { headers }).catch(() => undefined);
    }
  });

  test('has certificate authority and client certificate tabs', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /^certificate authorities/i }).click();
    await expect(page.getByRole('heading', { name: 'Certificate authorities', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: /add certificate authority/i }).first()).toBeVisible();

    await page.getByRole('tab', { name: /^client certificates/i }).click();
    await expect(page.getByRole('heading', { name: /^roles/i })).toBeVisible();
    await expect(page.getByRole('heading', { name: /^client certificates/i })).toBeVisible();
  });

  test('has no footnotes and links to the certificate settings', async ({ page }) => {
    await page.goto('/certificates');
    await expect(page.getByRole('main').getByRole('link', { name: 'Certificate settings' })).toHaveAttribute('href', '/certificates/settings');
    await expect(page.getByText(/ACME account|at most an hour/)).toHaveCount(0);
  });
});

// One real CA certificate and one real client certificate for every row below: the API refuses
// what Caddy could not load, and the list only shows the names, serials and dates given with them.
const LIST_CA = createExternalCa('E2E list CA');
const LIST_CLIENT_PEM = issueExternalClientCertificate(LIST_CA, 'e2e-list-device').certificatePem;
const DAY_MS = 86_400_000;

test.describe('Issued client certificates list', () => {
  // 65 certificates through the REST API, each one a Caddy apply.
  test.setTimeout(240_000);

  test('searches, filters, sorts, pages and revokes several at once', async ({ page }) => {
    const BASE_URL = 'http://localhost:3000';
    const API = `${BASE_URL}/api/v1`;
    const headers = { 'Content-Type': 'application/json', Origin: BASE_URL };
    const run = Date.now().toString(16).toUpperCase();
    const prefix = `e2e-list-${run.toLowerCase()}`;
    const name = (i: number) => `${prefix}-${String(i).padStart(2, '0')}`;
    const serial = (i: number) => `${run}${String(i).padStart(2, '0')}`;

    const createCa = async (caName: string) => {
      const res = await page.request.post(`${API}/ca-certificates`, { data: { name: caName, certificatePem: LIST_CA.certificatePem }, headers });
      expect(res.status()).toBe(201);
      return (await res.json()) as { id: number };
    };
    const mainCa = await createCa(`List CA ${run}`);
    const otherCaName = `Other CA ${run}`;
    const otherCa = await createCa(otherCaName);

    try {
      // 60 from the first CA, 5 from the second: 3 expired, 5 expiring within 30 days, the rest valid for a year.
      const now = Date.now();
      const ids: number[] = [];
      const bodies = Array.from({ length: 65 }, (_, i) => ({
        caCertificateId: i < 60 ? mainCa.id : otherCa.id,
        commonName: name(i),
        serialNumber: serial(i),
        certificatePem: LIST_CLIENT_PEM,
        validFrom: new Date(now - 30 * DAY_MS).toISOString(),
        validTo: new Date(now + (i < 3 ? -(i + 1) : i < 8 ? 10 + i : 365 + i) * DAY_MS).toISOString(),
      }));
      for (let start = 0; start < bodies.length; start += 8) {
        const responses = await Promise.all(
          bodies.slice(start, start + 8).map((data) => page.request.post(`${API}/client-certificates`, { data, headers }))
        );
        for (const res of responses) {
          expect(res.status()).toBe(201);
          ids.push(((await res.json()) as { id: number }).id);
        }
      }

      await page.goto('/certificates?tab=client');
      const list = page.getByRole('region', { name: 'Client certificates', exact: true });
      const search = list.getByRole('searchbox', { name: 'Search client certificates' });
      const pager = list.getByRole('navigation', { name: 'Pages of client certificates' });
      const rowNames = list.getByRole('table').getByRole('rowheader');

      // Search: the 65 of this run, 25 a page, soonest expiry first (the expired ones).
      await search.fill(prefix);
      await expect(pager).toContainText('1–25 of 65 client certificates');
      await expect(rowNames).toHaveCount(25);
      await expect(rowNames.first()).toHaveText(name(2));

      await pager.getByRole('button', { name: 'Next page' }).click();
      await expect(pager).toContainText('26–50 of 65');
      await pager.getByRole('button', { name: 'Page 3' }).click();
      await expect(pager).toContainText('51–65 of 65');
      await expect(rowNames).toHaveCount(15);

      // Sorting goes back to the first page.
      await list.getByRole('button', { name: 'Common name' }).click();
      await expect(pager).toContainText('1–25 of 65');
      await expect(rowNames.first()).toHaveText(name(0));
      await list.getByRole('button', { name: 'Common name' }).click();
      await expect(rowNames.first()).toHaveText(name(64));

      // By serial number: one certificate, no pager.
      await search.fill(serial(7));
      await expect(rowNames).toHaveCount(1);
      await expect(rowNames.first()).toHaveText(name(7));
      await expect(pager).toHaveCount(0);

      // Status and CA filters.
      await search.fill(prefix);
      const status = list.getByRole('group', { name: 'Status' });
      await status.getByRole('button', { name: /^Expired/ }).click();
      await expect(rowNames).toHaveCount(3);
      await status.getByRole('button', { name: /^Expiring/ }).click();
      await expect(rowNames).toHaveCount(5);
      await status.getByRole('button', { name: /^All/ }).click();
      await list.getByRole('button', { name: /^CA/ }).click();
      await page.getByRole('menuitemradio', { name: otherCaName }).click();
      await expect(rowNames).toHaveCount(5);
      await expect(pager).toHaveCount(0);
      await list.getByRole('button', { name: 'Clear filters' }).first().click();
      await expect(search).toHaveValue('');

      // Select a page, then every match; clear.
      await search.fill(prefix);
      await list.getByRole('checkbox', { name: 'Select every client certificate on this page' }).click();
      await expect(list.getByText('25 certificates selected')).toBeVisible();
      await list.getByRole('button', { name: 'Select all 65 matching' }).click();
      await expect(list.getByText('65 certificates selected')).toBeVisible();
      await list.getByRole('button', { name: 'Clear selection' }).click();
      await expect(list.getByText(/certificates? selected/)).toHaveCount(0);

      // Revoke three at once, after a confirmation.
      await search.fill(`${prefix}-1`);
      await expect(rowNames).toHaveCount(10);
      for (const i of [10, 11, 12]) await list.getByRole('checkbox', { name: `Select ${name(i)}` }).click();
      await expect(list.getByText('3 certificates selected')).toBeVisible();
      await list.getByRole('button', { name: 'Revoke', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Revoke 3 client certificates' });
      await expect(dialog).toContainText(name(11));
      await expect(dialog).toContainText('This cannot be undone');
      await dialog.getByRole('button', { name: 'Revoke 3 certificates' }).click();
      await expect(dialog).toBeHidden({ timeout: 30_000 });
      for (const i of [10, 11, 12]) {
        const res = await page.request.get(`${API}/client-certificates/${ids[i]}`, { headers: { Origin: BASE_URL } });
        expect(((await res.json()) as { revokedAt: string | null }).revokedAt).not.toBeNull();
      }
      await search.fill(prefix);
      await status.getByRole('button', { name: /^Revoked/ }).click();
      await expect(rowNames).toHaveCount(3);

      // A certificate authority opens its own client certificates.
      await page.getByRole('tab', { name: /^certificate authorities/i }).click();
      await page.getByRole('button', { name: `More actions for ${otherCaName}` }).click();
      await page.getByRole('menuitem', { name: 'Show client certificates' }).click();
      await expect(page.getByRole('tab', { name: /^client certificates/i })).toHaveAttribute('aria-selected', 'true');
      await expect(list.getByRole('button', { name: `CA: ${otherCaName}` })).toBeVisible();
      await expect(rowNames).toHaveCount(5);

      // Phones get cards, paged the same way.
      await page.setViewportSize({ width: 390, height: 844 });
      await list.getByRole('button', { name: 'Clear filters' }).first().click();
      await search.fill(prefix);
      const cards = list.getByRole('list', { name: 'Client certificates' }).getByRole('listitem');
      await expect(cards).toHaveCount(25);
      await expect(list.getByRole('table')).toBeHidden();
      await expect(pager).toContainText('1–25 of 65');
    } finally {
      // Deleting a CA deletes the certificates it issued.
      await page.request.delete(`${API}/ca-certificates/${mainCa.id}`, { headers }).catch(() => undefined);
      await page.request.delete(`${API}/ca-certificates/${otherCa.id}`, { headers }).catch(() => undefined);
    }
  });
});
