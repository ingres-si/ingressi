/**
 * Higher-level helpers for creating proxy hosts and access lists
 * in functional E2E tests.
 *
 * All helpers accept a Playwright `Page` (pre-authenticated via the
 * global storageState) so they integrate cleanly with the standard
 * `page` test fixture.
 */
import { expect, type Download, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

export interface ProxyHostConfig {
  name: string;
  domain: string;
  upstream: string;        // e.g. "echo-server:8080"
  accessListName?: string; // name of an existing access list to attach
  certificateName?: string;
  mtlsCaNames?: string[];
  /** Trust every client certificate signed by these authorities (the "Certificate authority" mode). */
  mtlsTrustedAuthorityNames?: string[];
  mtlsProtectedPaths?: string[];
  mtlsExcludedPaths?: string[];
  enableWaf?: boolean;     // enable WAF with OWASP CRS in blocking mode
  wafMode?: 'merge' | 'override';
  wafLoadOwaspCrs?: boolean;
  wafCustomDirectives?: string;
}

export interface ImportedCertificateConfig {
  name: string;
  domains: string[];
  certificatePem: string;
  privateKeyPem: string;
}

export interface GeneratedCaConfig {
  name: string;
  commonName?: string;
  validityDays?: number;
}

export interface IssuedClientCertificateConfig {
  caName: string;
  commonName: string;
  exportPassword: string;
  validityDays?: number;
  compatibilityMode?: boolean;
}

async function openCertificatesTab(page: Page, tabName: RegExp): Promise<void> {
  await page.goto('/certificates');
  await page.getByRole('tab', { name: tabName }).click();
}

/** Opens the row menu of a certificate authority on the "Certificate authorities" tab. */
async function openCaRowMenu(page: Page, caName: string): Promise<void> {
  const row = page.getByRole('row').filter({ has: page.getByRole('rowheader').filter({ hasText: caName }) }).first();
  await expect(row).toBeVisible({ timeout: 10_000 });
  await row.getByRole('button', { name: `More actions for ${caName}` }).click();
}

export type EditorSection = 'Routing' | 'Security' | 'Access' | 'Certificate' | 'Headers' | 'Advanced';

/** Opens one section of the host editor (/proxy-hosts/new, /proxy-hosts/<id>/edit). */
export async function openEditorSection(page: Page, section: EditorSection): Promise<void> {
  await page.getByRole('tab', { name: new RegExp(`^${section}`) }).click();
  await expect(page.getByRole('heading', { level: 2, name: section, exact: true })).toBeAttached();
}

/**
 * Waits until React has hydrated the host editor: text typed into its fields
 * before then is reset by hydration (the Name field of a new host lost its
 * value on fast machines).
 */
async function waitForHostEditor(page: Page): Promise<void> {
  await expect(page.locator('[data-host-tabs]')).toHaveAttribute('data-hydrated', 'true', { timeout: 15_000 });
}

/** Opens the host editor for a new host. */
export async function openNewHost(page: Page, query = ''): Promise<void> {
  await page.goto(`/proxy-hosts/new${query}`);
  await waitForHostEditor(page);
}

/** Opens a section of an existing host's editor: a tab of the host's page (Routing unless given). */
export async function openHostEditor(page: Page, hostId: number, section?: EditorSection): Promise<void> {
  await page.goto(`/proxy-hosts/${hostId}#${(section ?? 'Routing').toLowerCase()}`);
  await waitForHostEditor(page);
  await expect(page.getByRole('tab', { name: new RegExp(`^${section ?? 'Routing'}`) })).toHaveAttribute('aria-selected', 'true');
}

/** Adds domains in the Domains card (one per line, or comma separated). */
export async function addDomains(page: Page, domains: string): Promise<void> {
  const input = page.getByLabel('Add domains');
  for (const domain of domains.split(/[\n,]/).map((d) => d.trim()).filter(Boolean)) {
    await input.fill(domain);
    await input.press('Enter');
  }
}

/** Fills the upstream rows of the Upstreams card, adding rows as needed. */
export async function fillUpstreams(page: Page, upstreams: string): Promise<void> {
  const list = upstreams.split('\n').map((u) => u.trim()).filter(Boolean);
  for (let i = 0; i < list.length; i++) {
    if (i > 0 && (await page.getByPlaceholder('10.0.0.5:8080').count()) <= i) {
      await page.locator('#upstreams').getByRole('button', { name: 'Add upstream' }).click();
    }
    await page.getByPlaceholder('10.0.0.5:8080').nth(i).fill(list[i]);
  }
}

/** Name, domains and upstreams of a new host (Routing section). */
export async function fillHostBasics(page: Page, config: { name: string; domain: string; upstream: string }): Promise<void> {
  await page.getByLabel('Name', { exact: true }).fill(config.name);
  await addDomains(page, config.domain);
  await fillUpstreams(page, config.upstream);
}

/** Sets a switch of the editor, named by its label, to `on`. */
export async function setEditorSwitch(page: Page, name: string | RegExp, on: boolean): Promise<void> {
  const toggle = page.getByRole('switch', { name });
  if ((await toggle.getAttribute('aria-checked')) !== String(on)) await toggle.click();
  await expect(toggle).toHaveAttribute('aria-checked', String(on));
}

/** Picks the option of a select whose text starts with `text`. */
export async function selectOptionByText(page: Page, label: string, text: string): Promise<void> {
  const select = page.getByRole('combobox', { name: label, exact: true });
  const options = await select.locator('option').allTextContents();
  const index = options.findIndex((option) => option === text || option.startsWith(`${text} ·`));
  if (index < 0) throw new Error(`No option "${text}" in ${label}: ${options.join(', ')}`);
  await select.selectOption({ index });
}

/**
 * Saves the host editor: opens the review, waits for the approval check and
 * confirms. A new host then opens its page; an existing one shows "Saved"
 * (or the change request, for a protected host).
 */
export async function saveHostEditor(page: Page, expectOutcome: 'saved' | 'submitted' = 'saved'): Promise<number | null> {
  const creating = /\/proxy-hosts\/new/.test(page.url());
  await page.getByTestId('host-editor-bar').getByRole('button', { name: creating ? 'Create host' : 'Save', exact: true }).click();
  const review = page.getByRole('region', { name: /^Review / });
  await expect(review).toBeVisible();
  const submit = review.getByRole('button', { name: /^(Create host|Save changes|Submit for approval)$/ });
  await expect(submit).toBeEnabled({ timeout: 15_000 });
  await submit.click();
  if (expectOutcome === 'submitted') {
    await expect(page.getByTestId('host-editor-bar').getByText('Change request submitted for approval')).toBeVisible({ timeout: 15_000 });
    return null;
  }
  if (creating) {
    await page.waitForURL(/\/proxy-hosts\/\d+(?:[?#].*)?$/, { timeout: 15_000 });
    return Number(new URL(page.url()).pathname.split('/').pop());
  }
  await expect(page.getByTestId('host-editor-bar').getByText('Saved', { exact: true })).toBeVisible({ timeout: 15_000 });
  return null;
}

/** The id of the proxy host named `name`, from the REST API. */
export async function proxyHostIdByName(page: Page, name: string): Promise<number> {
  const response = await page.request.get('/api/v1/proxy-hosts');
  expect(response.ok()).toBeTruthy();
  const hosts = (await response.json()) as Array<{ id: number; name: string }>;
  const host = hosts.find((candidate) => candidate.name === name);
  expect(host, `proxy host "${name}"`).toBeDefined();
  return host!.id;
}

/**
 * Opens the host editor for a new host. Named after the create dialog it
 * replaced, so specs written for either read the same.
 */
export async function openCreateHostDialog(page: Page): Promise<void> {
  await openNewHost(page);
}

/** Opens the host editor of the proxy host named `name` (it replaced the edit dialog). */
export async function openEditHostDialog(page: Page, name: string): Promise<void> {
  await openHostEditor(page, await proxyHostIdByName(page, name));
}

/**
 * The list row of the proxy host named `name`, found with the list's search
 * (the list is paged, so a new host need not be on the first page).
 */
export async function findHostRow(page: Page, name: string) {
  await page.goto(`/proxy-hosts?search=${encodeURIComponent(name)}`);
  const row = page.locator('tr', { hasText: name });
  await expect(row).toBeVisible({ timeout: 10_000 });
  return row;
}

/** Adds a blocked path in the Access section (which must be open). */
export async function addBlockedPath(page: Page, rule: { path: string; status: number; body?: string }): Promise<void> {
  const index = await page.getByLabel(/^Blocked path \d+$/).count();
  await page.locator('#f-blocks').getByRole('button', { name: 'Add blocked path' }).click();
  await page.getByLabel(`Blocked path ${index + 1}`, { exact: true }).fill(rule.path);
  await page.getByLabel(`Status for blocked path ${index + 1}`, { exact: true }).selectOption(String(rule.status));
  await page.getByLabel(`Body for blocked path ${index + 1}`, { exact: true }).fill(rule.body ?? '');
}

/** Adds a path that bypasses the blocks, in the Access section (which must be open). */
export async function addBypassPath(page: Page, path: string): Promise<void> {
  const index = await page.getByLabel(/^Bypass path \d+$/).count();
  await page.locator('#f-allows').getByRole('button', { name: 'Add path' }).click();
  await page.getByLabel(`Bypass path ${index + 1}`, { exact: true }).fill(path);
}

/** Adds a path rewrite in the Advanced section (which must be open). */
export async function addPathRewrite(page: Page, rule: { from: string; to: string }): Promise<void> {
  const index = await page.getByLabel(/^Rewrite \d+ from path$/).count();
  await page.locator('#f-redirects').getByRole('button', { name: 'Add rewrite' }).click();
  await page.getByLabel(`Rewrite ${index + 1} from path`, { exact: true }).fill(rule.from);
  await page.getByLabel(`Rewrite ${index + 1} to path`, { exact: true }).fill(rule.to);
}

/** Adds a redirect in the Advanced section (which must be open). */
export async function addRedirect(page: Page, rule: { from: string; to: string; status: 301 | 302 | 307 | 308 }): Promise<void> {
  const index = await page.getByLabel(/^Redirect \d+ from path$/).count();
  await page.locator('#f-redirects').getByRole('button', { name: 'Add redirect' }).click();
  await page.getByLabel(`Redirect ${index + 1} from path`, { exact: true }).fill(rule.from);
  await page.getByLabel(`Redirect ${index + 1} to`, { exact: true }).fill(rule.to);
  await page.getByLabel(`Redirect ${index + 1} status`, { exact: true }).selectOption(String(rule.status));
}

/**
 * Create a proxy host via the host editor.
 * "Redirect HTTP to HTTPS" is always turned off so functional tests can use plain HTTP.
 */
export async function createProxyHost(page: Page, config: ProxyHostConfig): Promise<number> {
  await openNewHost(page);
  await fillHostBasics(page, config);

  await openEditorSection(page, 'Certificate');
  if (config.certificateName) await selectOptionByText(page, 'Certificate', config.certificateName);
  await setEditorSwitch(page, 'Redirect HTTP to HTTPS', false);

  if (config.accessListName || config.mtlsCaNames?.length || config.mtlsTrustedAuthorityNames?.length) {
    await openEditorSection(page, 'Access');
    if (config.accessListName) await selectOptionByText(page, 'Access list', config.accessListName);
    if (config.mtlsTrustedAuthorityNames?.length) {
      await setEditorSwitch(page, 'Require client certificates', true);
      const mtls = page.locator('#f-mtls');
      await mtls.getByRole('group', { name: 'Trust' }).getByRole('button', { name: 'Certificate authority' }).click();
      await expect(mtls.getByText('Trusted certificate authorities')).toBeVisible({ timeout: 10_000 });
      for (const caName of config.mtlsTrustedAuthorityNames) {
        await mtls.locator('#f-mtls-cas label').filter({ hasText: caName }).first().click();
      }
    }
    if (config.mtlsCaNames?.length) {
      await setEditorSwitch(page, 'Require client certificates', true);
      const mtls = page.locator('#f-mtls');
      await expect(mtls.getByText('Trusted certificates')).toBeVisible({ timeout: 10_000 });
      // Each CA's group checkbox selects every certificate it issued.
      for (const caName of config.mtlsCaNames) {
        await mtls.locator('label').filter({ hasText: caName }).first().click();
      }
      if (config.mtlsProtectedPaths?.length) {
        await page.locator('[name="mtlsProtectedPaths"]').fill(config.mtlsProtectedPaths.join(', '));
      }
      if (config.mtlsExcludedPaths?.length) {
        await page.locator('[name="mtlsExcludedPaths"]').fill(config.mtlsExcludedPaths.join(', '));
      }
    }
  }

  if (config.enableWaf) {
    await openEditorSection(page, 'Security');
    const waf = page.locator('#waf');
    await waf.getByRole('radio', { name: /^Block\b/ }).click();
    // Global settings, the Core Rule Set and directives are under Advanced.
    const advanced = waf.getByRole('button', { name: /^Advanced/ });
    if ((await advanced.getAttribute('aria-expanded')) !== 'true') await advanced.click();
    await waf
      .getByRole('group', { name: 'Global WAF settings' })
      .getByRole('button', { name: (config.wafMode ?? 'override') === 'override' ? 'Ignore them' : 'Use them too' })
      .click();
    await setEditorSwitch(page, 'OWASP Core Rule Set', config.wafLoadOwaspCrs !== false);
    if (config.wafCustomDirectives) await page.getByLabel(/Custom SecLang directives/).fill(config.wafCustomDirectives);
  }

  const id = await saveHostEditor(page);
  return id ?? (await proxyHostIdByName(page, config.name));
}

export async function importCertificate(page: Page, config: ImportedCertificateConfig): Promise<void> {
  await openCertificatesTab(page, /^Certificates/i);
  await page.getByRole('button', { name: /^import certificate$/i }).click();
  await expect(page.getByRole('heading', { name: /^import certificate$/i })).toBeVisible();

  await page.getByRole('textbox', { name: 'Name', exact: true }).fill(config.name);
  await page.getByLabel(/domains \(one per line\)/i).fill(config.domains.join('\n'));
  await page.locator('[name="certificate_pem"]').fill(config.certificatePem);
  await page.getByRole('button', { name: /show private key/i }).click();
  await page.locator('[name="private_key_pem"]').fill(config.privateKeyPem);
  await page.getByRole('button', { name: /^import certificate$/i }).click();

  // Wait for the import sheet to close, then verify the cert appears in the table
  await expect(page.getByRole('heading', { name: /^import certificate$/i })).not.toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(500); // allow page to revalidate
  await expect(page.locator('table').getByText(config.name).first()).toBeVisible({ timeout: 10_000 });
}

export async function importCaCertificate(page: Page, config: { name: string; certificatePem: string }): Promise<void> {
  await openCertificatesTab(page, /^Certificate authorities/i);
  await page.getByRole('button', { name: /^add certificate authority$/i }).first().click();
  await expect(page.getByRole('heading', { name: /^add certificate authority$/i })).toBeVisible();
  await page.getByRole('tab', { name: /^import pem$/i }).click();
  await page.locator('#imp-name').fill(config.name);
  await page.locator('#imp-cert-pem').fill(config.certificatePem);
  await page.getByRole('button', { name: /^add certificate authority$/i }).last().click();
  await expect(page.getByRole('heading', { name: /^add certificate authority$/i })).not.toBeVisible({ timeout: 10_000 });
  await expect(page.locator('table').getByText(config.name).first()).toBeVisible({ timeout: 15_000 });
}

export async function generateCaCertificate(page: Page, config: GeneratedCaConfig): Promise<void> {
  await openCertificatesTab(page, /^Certificate authorities/i);
  await page.getByRole('button', { name: /^add certificate authority$/i }).first().click();
  await expect(page.getByRole('heading', { name: /^add certificate authority$/i })).toBeVisible();

  await page.getByRole('textbox', { name: 'Name', exact: true }).fill(config.name);
  if (config.commonName) {
    await page.getByRole('textbox', { name: 'Common name (CN)', exact: true }).fill(config.commonName);
  }
  if (config.validityDays !== undefined) {
    await page.getByRole('spinbutton', { name: 'Validity', exact: true }).fill(String(config.validityDays));
  }

  await page.getByRole('button', { name: /generate certificate authority/i }).click();
  await expect(page.getByRole('heading', { name: /^add certificate authority$/i })).not.toBeVisible({ timeout: 10_000 });
  await expect(page.locator('table').getByText(config.name).first()).toBeVisible({ timeout: 15_000 });
}

export async function issueClientCertificate(
  page: Page,
  config: IssuedClientCertificateConfig
): Promise<Buffer> {
  await openCertificatesTab(page, /^Certificate authorities/i);
  await openCaRowMenu(page, config.caName);
  await page.getByRole('menuitem', { name: /^issue client certificate$/i }).click();
  await expect(page.getByRole('dialog', { name: /issue client certificate/i })).toBeVisible();

  await page.getByRole('textbox', { name: 'Common name (CN)', exact: true }).fill(config.commonName);
  if (config.validityDays !== undefined) {
    await page.getByRole('spinbutton', { name: 'Validity', exact: true }).fill(String(config.validityDays));
  }
  await page.getByLabel(/export password/i).fill(config.exportPassword);

  const shouldBeChecked = config.compatibilityMode ?? true;
  if (!shouldBeChecked) {
    const compatibilityToggle = page.locator('input[name="compatibility_mode"]').first();
    await compatibilityToggle.click({ force: true });
  }

  await page.getByRole('button', { name: /issue certificate/i }).click();
  await expect(page.getByRole('button', { name: /download client certificate/i })).toBeVisible({ timeout: 15_000 });

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: /download client certificate/i }).click();
  const download = await downloadPromise;
  const downloadPath = await saveDownload(download);

  await page.getByRole('button', { name: /^done$/i }).click();
  await expect(page.getByRole('dialog', { name: /issue client certificate/i })).not.toBeVisible({ timeout: 10_000 });

  return readFile(downloadPath);
}

export async function revokeIssuedClientCertificate(page: Page, caName: string, commonName: string): Promise<void> {
  await openCertificatesTab(page, /^Client certificates/i);
  // The client certificate table: one row per certificate, with its CA in "Issued by".
  const row = page
    .getByRole('row')
    .filter({ has: page.getByRole('rowheader', { name: commonName, exact: true }) })
    .filter({ hasText: caName })
    .first();
  await expect(row).toBeVisible({ timeout: 10_000 });
  await row.getByRole('button', { name: `Revoke ${commonName}`, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: /revoke client certificate/i });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: /^revoke certificate$/i }).click();
  await expect(dialog).not.toBeVisible({ timeout: 15_000 });
  // A revoked certificate stays listed, without its Revoke button.
  await expect(row.getByText(/^Revoked/)).toBeVisible({ timeout: 15_000 });
  await expect(row.getByRole('button', { name: `Revoke ${commonName}`, exact: true })).toHaveCount(0);
}

async function saveDownload(download: Download): Promise<string> {
  const downloadPath = await download.path();
  if (!downloadPath) {
    throw new Error('Playwright download did not produce a local file path');
  }
  return downloadPath;
}

export interface AccessListUser {
  username: string;
  password: string;
}

/**
 * Create an access list with initial users via the browser UI.
 * Creates the list in the "New access list" dialog, then adds the basic-auth
 * users on the list's page and saves.
 */
export async function createAccessList(
  page: Page,
  name: string,
  users: AccessListUser[]
): Promise<void> {
  await page.goto('/access-lists');

  // Create the list
  await page.getByRole('button', { name: /new access list/i }).first().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible({ timeout: 5_000 });
  await dialog.getByLabel('Name', { exact: true }).fill(name);
  await dialog.getByRole('button', { name: /create list/i }).click();
  await expect(dialog).not.toBeVisible({ timeout: 10_000 });

  // The new list's page opens: add the users and save
  await expect(page).toHaveURL(/\/access-lists\/\d+$/, { timeout: 10_000 });
  await expect(page.getByRole('heading', { name, exact: true, level: 1 })).toBeVisible({ timeout: 10_000 });
  if (users.length === 0) return;
  for (const user of users) {
    await page.getByLabel('Username', { exact: true }).fill(user.username);
    await page.getByLabel('Password', { exact: true }).fill(user.password);
    await page.getByRole('button', { name: 'Add user' }).click();
  }
  const bar = page.getByTestId('access-list-save-bar');
  await bar.getByRole('button', { name: 'Save list' }).click();
  await expect(bar.getByText('No unsaved changes')).toBeVisible({ timeout: 10_000 });
}
