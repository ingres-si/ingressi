/**
 * Dashboard passkeys (Better Auth's passkey plugin as Ingressi configures it),
 * end to end over Better Auth's HTTP handler with a software authenticator:
 * adding one (session, password, user verification, who may), signing in
 * with one, the relying party pinned to BASE_URL, a password sign-in of an
 * account whose second factor is a passkey, the MFA policy, enforced SSO and
 * the MFA reset.
 *
 * Like auth-mfa.test.ts, this boots the real db module and the real
 * auth-server against the application database: a SQLite file, or in the
 * postgres project the worker's PostgreSQL database (tests/helpers/app-database.ts).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import { APP_BASE_URL, AuthBrowser, totpCode, totpSecretFromUri } from '../helpers/mfa-browser';
import { SoftAuthenticator } from '../helpers/webauthn';
import { openAppDatabase, type AppDatabase } from '../helpers/app-database';

let database: AppDatabase;

const PASSWORD = 'Correct-Horse-9!';
const WRONG = 'Wrong-Horse-9!!';
const RP_ID = new URL(APP_BASE_URL).hostname;

type App = {
  db: Awaited<typeof import('../../src/lib/db')>['default'];
  schema: typeof import('../../src/lib/db/schema');
  auth: ReturnType<Awaited<typeof import('../../src/lib/auth-server')>['getAuth']>;
  userModel: typeof import('../../src/lib/models/user');
  mfa: typeof import('../../src/lib/mfa');
  passkeys: typeof import('../../src/lib/passkeys');
  ssoStore: typeof import('../../ee/sso/enforcement-store');
  audit: typeof import('../../src/lib/audit');
};
let app: App;

beforeAll(async () => {
  database = await openAppDatabase('ingressi-passkeys-');
  process.env.BASE_URL = APP_BASE_URL;
  process.env.AUTH_RATE_LIMIT_ENABLED = 'false';
  vi.resetModules();

  const dbModule = await import('../../src/lib/db');
  const { getAuth } = await import('../../src/lib/auth-server');
  app = {
    db: dbModule.default,
    schema: await import('../../src/lib/db/schema'),
    auth: getAuth(),
    userModel: await import('../../src/lib/models/user'),
    mfa: await import('../../src/lib/mfa'),
    passkeys: await import('../../src/lib/passkeys'),
    ssoStore: await import('../../ee/sso/enforcement-store'),
    audit: await import('../../src/lib/audit'),
  };
});

afterAll(async () => {
  await database.close();
  delete process.env.AUTH_RATE_LIMIT_ENABLED;
  vi.resetModules();
});

beforeEach(async () => {
  const { eq } = await import('drizzle-orm');
  await app.ssoStore.writeSsoEnforcement(app.db, { enabled: false, breakGlassUserIds: [] });
  await app.db.delete(app.schema.settings).where(eq(app.schema.settings.key, app.mfa.MFA_POLICY_SETTING_KEY));
  vi.mocked(app.audit.logAuditEvent).mockClear();
});

let userCounter = 0;

async function createAccount(role: 'admin' | 'user' = 'user', withPassword = true): Promise<{ id: number; username: string }> {
  userCounter += 1;
  const username = `passkey-user-${userCounter}`;
  const user = await app.userModel.createUser({
    email: `${username}@example.com`,
    username,
    role,
    provider: withPassword ? 'credentials' : 'dex',
    subject: username,
    passwordHash: withPassword ? bcrypt.hashSync(PASSWORD, 4) : null,
  });
  return { id: user.id, username };
}

const browser = () => new AuthBrowser(() => app.auth.handler);

async function signedIn(username: string): Promise<AuthBrowser> {
  const b = browser();
  const res = await b.post('/sign-in/username', { username, password: PASSWORD });
  expect(res.status).toBe(200);
  expect(res.body?.twoFactorRedirect).toBeUndefined();
  return b;
}

async function getJson(b: AuthBrowser, path: string): Promise<{ status: number; body: any }> {
  const res = await b.get(path);
  let body: any;
  try {
    body = JSON.parse(res.body ?? 'null');
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

/** Adds a passkey through the Profile flow: options, the browser ceremony, then verification with the password. */
async function addPasskey(b: AuthBrowser, authenticator: SoftAuthenticator, body: Record<string, unknown> = {}) {
  const options = await getJson(b, '/passkey/generate-register-options');
  if (options.status !== 200) return { status: options.status, body: options.body, options: null };
  const response = authenticator.register(options.body);
  const res = await b.post('/passkey/verify-registration', { response, password: PASSWORD, name: 'Laptop', ...body });
  return { ...res, options: options.body };
}

async function signInWithPasskey(authenticator: SoftAuthenticator, b: AuthBrowser = browser()) {
  const options = await getJson(b, '/passkey/generate-authenticate-options');
  expect(options.status).toBe(200);
  const res = await b.post('/passkey/verify-authentication', { response: authenticator.authenticate(options.body) });
  return { ...res, browser: b };
}

const soft = (userVerified = true) => new SoftAuthenticator({ origin: APP_BASE_URL, rpId: RP_ID, userVerified });

async function sessionCount(userId: number): Promise<number> {
  const { eq } = await import('drizzle-orm');
  return (await app.db.select().from(app.schema.sessions).where(eq(app.schema.sessions.userId, userId))).length;
}

async function requireMfaForEveryone() {
  await app.db.insert(app.schema.settings).values({
    key: app.mfa.MFA_POLICY_SETTING_KEY,
    value: JSON.stringify({ scope: 'password_users', graceDays: 0, since: new Date(0).toISOString() }),
    updatedAt: new Date().toISOString(),
  });
}

describe('adding a passkey', () => {
  it('needs the password, pins the relying party to BASE_URL and turns MFA on', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    const authenticator = soft();

    const wrong = await addPasskey(b, authenticator, { password: WRONG });
    expect(wrong.status).toBe(400);
    expect(wrong.body).toMatchObject({ code: 'INVALID_PASSWORD' });
    expect(await app.passkeys.countPasskeys(account.id)).toBe(0);

    const added = await addPasskey(b, authenticator);
    expect(added.status).toBe(200);
    expect(added.options.rp).toMatchObject({ id: RP_ID });
    // The server names the credential's user (its sign-in username), not the client.
    expect(added.options.user.name).toBe(account.username);
    expect(added.options.authenticatorSelection).toMatchObject({ userVerification: 'required', residentKey: 'required' });

    const list = await app.passkeys.listPasskeys(account.id);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ name: 'Laptop', lastUsedAt: null });
    expect(JSON.stringify(list)).not.toContain('publicKey');

    const status = await app.mfa.getMfaStatus(account.id);
    expect(status).toMatchObject({ enabled: true, authenticatorApp: false, passkeys: 1 });
    expect(vi.mocked(app.audit.logAuditEvent).mock.calls.map(([event]) => event.action)).toContain('passkey_added');
  });

  it('refuses a passkey that does not verify the person', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    const res = await addPasskey(b, soft(false));
    // The passkey plugin itself requires user verification (userVerification:
    // "required" -> requireUserVerification), so a ceremony without it fails
    // verification before our afterVerification guard can name the reason.
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ code: 'FAILED_TO_VERIFY_REGISTRATION' });
    expect(await app.passkeys.countPasskeys(account.id)).toBe(0);
  });

  it('refuses a ceremony made for another origin', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    const options = await getJson(b, '/passkey/generate-register-options');
    const response = soft().register(options.body, 'https://evil.example.com');
    const res = await b.post('/passkey/verify-registration', { response, password: PASSWORD });
    expect(res.status).not.toBe(200);
    expect(await app.passkeys.countPasskeys(account.id)).toBe(0);
  });

  it('never signs anyone in while registering', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    const before = await sessionCount(account.id);
    const res = await addPasskey(b, soft(), { createSession: true });
    expect(res.status).toBe(200);
    expect(res.body.session).toBeUndefined();
    expect(await sessionCount(account.id)).toBe(before);
  });

  it('needs a session', async () => {
    const options = await getJson(browser(), '/passkey/generate-register-options');
    expect(options.status).toBe(401);
  });

  it('is refused for an account without a local password', async () => {
    const account = await createAccount('user', false);
    expect(await app.passkeys.passkeyRegistrationBlocker(account.id)).toContain('Only accounts with a password');
  });

  it('is refused while SSO is enforced, except for break-glass accounts', async () => {
    const account = await createAccount('admin');
    const b = await signedIn(account.username);
    await app.ssoStore.writeSsoEnforcement(app.db, { enabled: true, breakGlassUserIds: [] });
    const refused = await getJson(b, '/passkey/generate-register-options');
    expect(refused.status).toBe(400);
    expect(refused.body).toMatchObject({ code: 'PASSKEY_NOT_ALLOWED' });

    await app.ssoStore.writeSsoEnforcement(app.db, { enabled: true, breakGlassUserIds: [account.id] });
    expect((await addPasskey(b, soft())).status).toBe(200);
  });

  it('keeps the management endpoints of the plugin off', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    await addPasskey(b, soft());
    expect((await b.get('/passkey/list-user-passkeys')).status).toBe(404);
    expect((await b.post('/passkey/delete-passkey', { id: '1' })).status).toBe(404);
    expect((await b.post('/passkey/update-passkey', { id: '1', name: 'x' })).status).toBe(404);
    expect(await app.passkeys.countPasskeys(account.id)).toBe(1);
  });
});

describe('signing in with a passkey', () => {
  it('creates a session, records the sign-in and the use of the passkey', async () => {
    const account = await createAccount();
    const authenticator = soft();
    await addPasskey(await signedIn(account.username), authenticator);

    const res = await signInWithPasskey(authenticator);
    expect(res.status).toBe(200);
    expect(res.browser.has('session_token')).toBe(true);
    expect((await app.passkeys.listPasskeys(account.id))[0].lastUsedAt).not.toBeNull();
    const user = await app.userModel.getUserById(account.id);
    expect(user).toMatchObject({ lastSignInMethod: 'passkey', invited: false });
  });

  it('refuses an assertion without user verification', async () => {
    const account = await createAccount();
    const authenticator = soft();
    await addPasskey(await signedIn(account.username), authenticator);
    authenticator.userVerified = false;
    const before = await sessionCount(account.id);
    const res = await signInWithPasskey(authenticator);
    // Likewise the assertion fails verification in the plugin (400) rather than
    // reaching our afterVerification guard; either way no session is created.
    expect(res.status).toBe(400);
    expect(await sessionCount(account.id)).toBe(before);
  });

  it('refuses an assertion made for another origin', async () => {
    const account = await createAccount();
    const authenticator = soft();
    await addPasskey(await signedIn(account.username), authenticator);
    const b = browser();
    const options = await getJson(b, '/passkey/generate-authenticate-options');
    const res = await b.post('/passkey/verify-authentication', { response: authenticator.authenticate(options.body, 'https://evil.example.com') });
    expect(res.status).not.toBe(200);
    expect(b.has('session_token')).toBe(false);
  });

  it('refuses a disabled account', async () => {
    const account = await createAccount();
    const authenticator = soft();
    await addPasskey(await signedIn(account.username), authenticator);
    const { eq } = await import('drizzle-orm');
    await app.db.update(app.schema.users).set({ status: 'disabled' }).where(eq(app.schema.users.id, account.id));
    const res = await signInWithPasskey(authenticator);
    expect(res.status).toBe(401);
    expect(res.browser.has('session_token')).toBe(false);
  });

  it('never gets past enforced SSO, unless the account is a break-glass account', async () => {
    const account = await createAccount('admin');
    const authenticator = soft();
    await addPasskey(await signedIn(account.username), authenticator);

    await app.ssoStore.writeSsoEnforcement(app.db, { enabled: true, breakGlassUserIds: [] });
    const refused = await signInWithPasskey(authenticator);
    expect(refused.status).toBe(401);
    expect(refused.body).toMatchObject({ code: 'AUTHENTICATION_FAILED' });
    expect(refused.browser.has('session_token')).toBe(false);
    expect(vi.mocked(app.audit.logAuditEvent).mock.calls.map(([event]) => event.action)).toContain('sso_enforced_sign_in_refused');

    await app.ssoStore.writeSsoEnforcement(app.db, { enabled: true, breakGlassUserIds: [account.id] });
    const allowed = await signInWithPasskey(authenticator);
    expect(allowed.status).toBe(200);
  });
});

describe('a passkey as the second factor of password sign-in', () => {
  it('turns the password step of a passkey-only account into a passkey challenge without a session', async () => {
    const account = await createAccount();
    await addPasskey(await signedIn(account.username), soft());
    const before = await sessionCount(account.id);

    const b = browser();
    const res = await b.post('/sign-in/username', { username: account.username, password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ twoFactorRedirect: true, twoFactorMethods: ['passkey'] });
    expect(b.has('session_token')).toBe(false);
    expect(await sessionCount(account.id)).toBe(before);
  });

  it('keeps the authenticator challenge for an account with an authenticator app', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    const enable = await b.post('/two-factor/enable', { password: PASSWORD });
    const secret = totpSecretFromUri(enable.body.totpURI);
    expect((await b.post('/two-factor/verify-totp', { code: await totpCode(secret) })).status).toBe(200);
    await addPasskey(b, soft());

    const res = await browser().post('/sign-in/username', { username: account.username, password: PASSWORD });
    expect(res.body).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ['totp'] });
  });

  it('satisfies the MFA policy, and the last second factor of a covered account cannot be removed', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    await requireMfaForEveryone();
    expect((await app.mfa.getMfaStatus(account.id)).gate).toBe('required');

    await addPasskey(b, soft());
    expect((await app.mfa.getMfaStatus(account.id)).gate).toBe('none');

    const [passkey] = await app.passkeys.listPasskeys(account.id);
    await expect(app.passkeys.removePasskey(account.id, passkey.id)).rejects.toThrow(app.passkeys.LAST_SECOND_FACTOR_MESSAGE);
    expect(await app.passkeys.countPasskeys(account.id)).toBe(1);
  });

  it('lets a covered account turn off its authenticator app while it has a passkey', async () => {
    const account = await createAccount();
    const b = await signedIn(account.username);
    const enable = await b.post('/two-factor/enable', { password: PASSWORD });
    const secret = totpSecretFromUri(enable.body.totpURI);
    await b.post('/two-factor/verify-totp', { code: await totpCode(secret) });
    await requireMfaForEveryone();

    expect((await b.post('/two-factor/disable', { password: PASSWORD })).body).toMatchObject({ code: 'MFA_REQUIRED_BY_POLICY' });
    await addPasskey(b, soft());
    const off = await b.post('/two-factor/disable', { password: PASSWORD });
    expect(off.status).toBe(200);
    expect(await app.mfa.getMfaStatus(account.id)).toMatchObject({ enabled: true, authenticatorApp: false, passkeys: 1 });
  });
});

describe('the last sign-in', () => {
  it('is recorded for a password sign-in, and for one completed with a second factor', async () => {
    const account = await createAccount();
    expect(await app.userModel.getUserById(account.id)).toMatchObject({ lastSignInAt: null, invited: true });
    const b = await signedIn(account.username);
    expect(await app.userModel.getUserById(account.id)).toMatchObject({ lastSignInMethod: 'password', invited: false });

    const enable = await b.post('/two-factor/enable', { password: PASSWORD });
    const secret = totpSecretFromUri(enable.body.totpURI);
    await b.post('/two-factor/verify-totp', { code: await totpCode(secret) });
    const { eq } = await import('drizzle-orm');
    await app.db.update(app.schema.users).set({ lastSignInAt: null, lastSignInMethod: null }).where(eq(app.schema.users.id, account.id));

    const challenge = browser();
    await challenge.post('/sign-in/username', { username: account.username, password: PASSWORD });
    // The password step alone is not a sign-in.
    expect(await app.userModel.getUserById(account.id)).toMatchObject({ lastSignInAt: null });
    expect((await challenge.post('/two-factor/verify-totp', { code: await totpCode(secret, 1) })).status).toBe(200);
    expect(await app.userModel.getUserById(account.id)).toMatchObject({ lastSignInMethod: 'password' });
  });
});

describe('managing passkeys', () => {
  it('renames and removes only the account\'s own passkeys', async () => {
    const owner = await createAccount();
    const other = await createAccount();
    await addPasskey(await signedIn(owner.username), soft());
    const [passkey] = await app.passkeys.listPasskeys(owner.id);

    await expect(app.passkeys.renamePasskey(other.id, passkey.id, 'Mine now')).rejects.toThrow('Passkey not found');
    await expect(app.passkeys.removePasskey(other.id, passkey.id)).rejects.toThrow('Passkey not found');
    await expect(app.passkeys.renamePasskey(owner.id, passkey.id, '  ')).rejects.toThrow('name must not be empty');
    await expect(app.passkeys.renamePasskey(owner.id, passkey.id, 'x'.repeat(65))).rejects.toThrow('64 characters');

    expect((await app.passkeys.renamePasskey(owner.id, passkey.id, 'Security key')).name).toBe('Security key');
    await app.passkeys.removePasskey(owner.id, passkey.id);
    expect(await app.passkeys.countPasskeys(owner.id)).toBe(0);
  });

  it('are removed by an MFA reset and with the account', async () => {
    const account = await createAccount();
    const authenticator = soft();
    await addPasskey(await signedIn(account.username), authenticator);
    expect(await app.mfa.resetUserMfa(account.id)).toBe(true);
    expect(await app.passkeys.countPasskeys(account.id)).toBe(0);
    expect((await signInWithPasskey(authenticator)).status).toBe(401);

    const second = await createAccount();
    await addPasskey(await signedIn(second.username), soft());
    await app.userModel.deleteUser(second.id);
    expect(await app.passkeys.countPasskeys(second.id)).toBe(0);
  });
});
