"use client";

import { FormEvent, useState, useSyncExternalStore } from "react";
import { authClient } from "@/src/lib/auth-client";
import { ArrowRight, ChevronDown, ChevronUp, KeyRound, Lock, LogIn, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { formatAppVersion } from "@/src/lib/app-version";
import { BRAND_NAME } from "@/src/lib/brand";
import { describeMfaError, mfaApi, signInChallengeEnded } from "@/src/components/mfa/mfa-api";
import { describePasskeyError, passkeysSupported, signInWithPasskey } from "@/src/components/passkeys/passkey-api";
import { useBranding } from "@/ee/white-label/ui/BrandingProvider";
import { BrandFooter, BrandLogo, hasLogo } from "@/ee/white-label/ui/BrandParts";
import { signInWithDirectory, type SignInResult } from "@/ee/ldap/ui/sign-in-client";
import { startSamlSignIn } from "@/ee/saml/ui/sign-in-client";

/**
 * Leaves the login page once a session exists. An account the MFA policy asks
 * to set up MFA goes to the setup page first (after the grace period the
 * dashboard sends it there anyway).
 */
async function enterDashboard(next: string): Promise<void> {
  try {
    const response = await fetch("/api/v1/mfa", { credentials: "same-origin" });
    if (response.ok) {
      const status = (await response.json()) as { gate?: string };
      if (status.gate === "prompt" || status.gate === "required") {
        window.location.replace("/mfa-setup");
        return;
      }
    }
  } catch {
    // The dashboard applies the policy itself.
  }
  // Full navigation: the dashboard gets a fresh document (and CSP nonce)
  // instead of running inside the login page's document. replace() keeps
  // /login out of the history, so Back leaves the app instead of bouncing
  // through the login page.
  window.location.replace(next);
}

/** "local" is the account's own password; a number is a directory (ee/ldap). */
type SignInMethod = "local" | number;

/** The second sign-in step: a code from the authenticator app, or the account's passkey. */
type Challenge = { kind: "code" | "passkey"; username: string } | null;

type Provider = { id: string; name: string; host?: string | null };
type SamlProvider = { id: number; name: string; host?: string | null };

interface LoginClientProps {
  enabledProviders: Provider[];
  /** Enforced SSO: only break-glass accounts may use a password. */
  ssoEnforced?: boolean;
  /**
   * With SSO enforced: some break-glass account can sign in with a password.
   * Without one, no password or passkey sign-in is offered for local accounts.
   */
  breakGlassSignIn?: boolean;
  /** LDAP / Active Directory directories open for sign-in. */
  directories?: Array<{ id: number; name: string }>;
  /** Enabled SAML identity providers. */
  samlProviders?: SamlProvider[];
  /** Some account has a passkey, so passkey sign-in is offered. */
  passkeysAvailable?: boolean;
  /** An error to show on arrival, such as a SAML sign-in that did not complete. */
  initialError?: string | null;
  /** Where to go after a successful sign-in (a same-origin path), or "/". */
  next?: string;
}

function initialsOf(name: string): string {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2)).toUpperCase();
}

function Spinner() {
  return <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />;
}

/** The product mark next to the product name when no logo is set. */
function ProductMark() {
  return (
    <svg width="36" height="36" viewBox="0 0 28 28" aria-hidden="true" className="flex-none">
      <rect width="28" height="28" rx="7" className="fill-primary" />
      <path
        d="M11 8v3M11 17v3M22 8v12M6 14h12M15 11l3 3-3 3"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="text-primary-foreground"
      />
    </svg>
  );
}

const noSubscription = () => () => {};

/** Whether this browser can use passkeys; false while rendering on the server. */
function useWebAuthn(): boolean {
  return useSyncExternalStore(noSubscription, passkeysSupported, () => false);
}

export default function LoginClient({
  enabledProviders = [],
  ssoEnforced = false,
  breakGlassSignIn = true,
  directories = [],
  samlProviders = [],
  passkeysAvailable = false,
  initialError = null,
  next = "/",
}: LoginClientProps) {
  const [loginError, setLoginError] = useState<string | null>(initialError);
  const [loginPending, setLoginPending] = useState(false);
  const [oauthPending, setOauthPending] = useState<string | null>(null);
  // With SSO enforced, the password form is only for break-glass accounts (and
  // directories open under enforcement) and stays collapsed behind "Sign in
  // with a password", unless no provider is enabled to sign in with. Without a
  // break-glass account, local accounts get no password or passkey sign-in.
  const ssoFirst = ssoEnforced && enabledProviders.length + samlProviders.length > 0;
  const localSignIn = !ssoEnforced || breakGlassSignIn;
  const passwordSignIn = localSignIn || directories.length > 0;
  const [showPasswordForm, setShowPasswordForm] = useState(!ssoFirst && passwordSignIn);
  // A directory is the default when there is one; the local account stays one click away.
  const [method, setMethod] = useState<SignInMethod>(
    directories.length > 0 && (!ssoFirst || !localSignIn) ? directories[0].id : "local"
  );
  const directoryName = method === "local" ? null : directories.find((directory) => directory.id === method)?.name ?? null;
  // Second sign-in step for accounts with multi-factor authentication.
  const [challenge, setChallenge] = useState<Challenge>(null);
  const [useBackupCode, setUseBackupCode] = useState(false);
  const branding = useBranding();
  const webAuthn = useWebAuthn();
  const offerPasskey = passkeysAvailable && webAuthn && localSignIn;

  const handleSignIn = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoginError(null);
    setLoginPending(true);

    const formData = new FormData(event.currentTarget);
    const username = String(formData.get("username") ?? "").trim();
    const password = String(formData.get("password") ?? "");

    if (!username || !password) {
      setLoginError("Username and password are required.");
      setLoginPending(false);
      return;
    }

    // `signIn.username` is added at runtime by the usernameClient plugin. The plugin's
    // $InferServerPlugin types fail to merge into the client signature in some environments,
    // so we cast a stable shape here.
    type SignInUsername = (input: { username: string; password: string }) => Promise<SignInResult>;
    const signInUsername = (authClient.signIn as unknown as { username: SignInUsername }).username;
    const { data, error } = method === "local"
      ? await signInUsername({ username, password })
      : await signInWithDirectory(method, username, password);

    if (error) {
      let message: string | null = null;
      if (error.status === 429) {
        message = error.message || "Too many login attempts. Try again in a few minutes.";
      } else if (error.message) {
        message = error.message;
      }
      setLoginError(message ?? "Invalid username or password.");
      setLoginPending(false);
      return;
    }

    if (data?.twoFactorRedirect) {
      // The password was right; no session exists until the second factor is checked:
      // a code from the authenticator app, or the passkey when that is the account's only one.
      const methods = data.twoFactorMethods ?? [];
      setChallenge({ kind: methods.includes("passkey") && !methods.includes("totp") ? "passkey" : "code", username });
      setUseBackupCode(false);
      setShowPasswordForm(false);
      setLoginPending(false);
      return;
    }

    await enterDashboard(next);
  };

  const restartSignIn = (message: string | null) => {
    setChallenge(null);
    setUseBackupCode(false);
    setShowPasswordForm(true);
    setLoginError(message);
  };

  const handleVerify = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoginError(null);
    const code = String(new FormData(event.currentTarget).get("code") ?? "").trim();
    if (!code) {
      setLoginError(useBackupCode ? "Enter one of your backup codes." : "Enter the code from your authenticator app.");
      return;
    }
    setLoginPending(true);
    const result = useBackupCode ? await mfaApi.verifyBackupCode(code) : await mfaApi.verifyTotp(code);
    if (!result.ok) {
      setLoginPending(false);
      if (signInChallengeEnded(result.error)) {
        restartSignIn(describeMfaError(result.error));
        return;
      }
      setLoginError(describeMfaError(result.error));
      return;
    }
    await enterDashboard(next);
  };

  const handlePasskeySignIn = async () => {
    setLoginError(null);
    setLoginPending(true);
    const result = await signInWithPasskey();
    if (!result.ok) {
      setLoginPending(false);
      setLoginError(describePasskeyError(result.error));
      return;
    }
    await enterDashboard(next);
  };

  const handleOAuthSignIn = async (providerId: string) => {
    setLoginError(null);
    setOauthPending(providerId);
    try {
      await authClient.signIn.social({ provider: providerId, callbackURL: next });
    } catch {
      setLoginError("Failed to sign in with OAuth");
      setOauthPending(null);
    }
  };

  const handleSamlSignIn = async (providerId: number) => {
    setLoginError(null);
    setOauthPending(`saml:${providerId}`);
    const url = await startSamlSignIn(providerId, next);
    if (!url) {
      setLoginError("Failed to start single sign-on. Try again.");
      setOauthPending(null);
      return;
    }
    // A full navigation to the identity provider; it posts back to the dashboard.
    window.location.href = url;
  };

  const disabled = loginPending || !!oauthPending;
  const hasSso = enabledProviders.length + samlProviders.length > 0;
  // The first provider's host names the single sign-on in the break-glass note.
  const ssoHost = enabledProviders.find((provider) => provider.host)?.host ?? samlProviders.find((provider) => provider.host)?.host ?? null;
  // A heading set in the branding replaces "Sign in".
  const customHeading = branding.loginHeading !== branding.productName;

  const title = challenge ? "Two-step verification" : customHeading ? branding.loginHeading : "Sign in";
  // The second step says what it needs; the first needs no sentence under "Sign in".
  const subtitle = challenge?.kind === "passkey"
    ? "Finish signing in with your passkey."
    : challenge
      ? useBackupCode
        ? "Enter one of your backup codes. Each code works once."
        : "Enter the 6-digit code from your authenticator app."
      : null;

  const providerButtonClass = "h-auto min-h-12 w-full justify-start gap-3 rounded-lg px-4 py-2 text-left";

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-background px-4 pb-24 pt-12">
      <main className="flex w-full max-w-[400px] flex-col gap-6">
        <div className="flex items-center justify-center gap-3">
          {hasLogo(branding) ? (
            <BrandLogo branding={branding} className="max-h-12 w-auto max-w-[220px]" />
          ) : (
            <>
              {branding.productName === BRAND_NAME && <ProductMark />}
              <span className="text-[22px] font-bold leading-7 tracking-tight">{branding.productName}</span>
            </>
          )}
        </div>

        <section aria-labelledby="signin-title" className="flex flex-col gap-5 rounded-xl border bg-card p-7 text-card-foreground">
          <div className="flex flex-col gap-1">
            <h1 id="signin-title" className="break-words text-2xl font-semibold tracking-tight">{title}</h1>
            {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
          </div>

          {loginError && (
            <Alert variant="destructive">
              <AlertDescription>{loginError}</AlertDescription>
            </Alert>
          )}

          {challenge && (
            <div className="flex items-center gap-2.5 rounded-lg border bg-muted/40 px-3 py-2.5 text-sm">
              <span aria-hidden="true" className="grid h-7 w-7 flex-none place-items-center rounded-full bg-muted text-[11px] font-semibold text-muted-foreground">
                {initialsOf(challenge.username)}
              </span>
              <span className="min-w-0 flex-1">
                Password accepted for <span className="font-mono font-semibold">{challenge.username}</span>
              </span>
            </div>
          )}

          {challenge?.kind === "passkey" && (
            <div className="flex flex-col gap-3" data-testid="passkey-challenge">
              <Button type="button" className="h-11 w-full rounded-lg" onClick={handlePasskeySignIn} disabled={loginPending || !webAuthn}>
                {loginPending ? <Spinner /> : <KeyRound className="h-4 w-4" />}
                Use your passkey
              </Button>
              {!webAuthn && (
                <p className="text-xs text-muted-foreground">This browser cannot use passkeys. Sign in from a browser that can.</p>
              )}
              <div className="flex justify-end">
                <Button type="button" variant="ghost" size="sm" className="text-muted-foreground" onClick={() => restartSignIn(null)} disabled={loginPending}>
                  Back
                </Button>
              </div>
            </div>
          )}

          {challenge?.kind === "code" && (
            <form onSubmit={handleVerify} className="flex flex-col gap-3.5" data-testid="mfa-challenge">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="code">{useBackupCode ? "Backup code" : "Authentication code"}</Label>
                <Input
                  key={useBackupCode ? "backup" : "totp"}
                  id="code"
                  name="code"
                  required
                  autoFocus
                  autoComplete={useBackupCode ? "off" : "one-time-code"}
                  inputMode={useBackupCode ? "text" : "numeric"}
                  placeholder={useBackupCode ? "xxxxx-xxxxx" : "123456"}
                  spellCheck={false}
                  disabled={loginPending}
                  className="h-12 font-mono text-xl tracking-[0.14em]"
                />
              </div>
              <Button type="submit" className="h-11 w-full rounded-lg" disabled={loginPending}>
                {loginPending ? "Verifying…" : "Verify"}
              </Button>
              <div className="flex flex-wrap justify-between gap-2">
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  className="px-0 text-xs"
                  onClick={() => {
                    setUseBackupCode(!useBackupCode);
                    setLoginError(null);
                  }}
                  disabled={loginPending}
                >
                  {useBackupCode ? "Use the authenticator app" : "Use a backup code"}
                </Button>
                {offerPasskey && (
                  <Button type="button" variant="link" size="sm" className="px-0 text-xs" onClick={handlePasskeySignIn} disabled={loginPending}>
                    Use a passkey
                  </Button>
                )}
                <Button
                  type="button"
                  variant="link"
                  size="sm"
                  className="px-0 text-xs text-muted-foreground"
                  onClick={() => restartSignIn(null)}
                  disabled={loginPending}
                >
                  Back
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Five wrong codes end this attempt; ten in a row lock the second step for 15 minutes.
              </p>
            </form>
          )}

          {!challenge && (hasSso || offerPasskey) && (
            <div className="flex flex-col gap-2.5">
              {enabledProviders.map((provider) => {
                const isPending = oauthPending === provider.id;
                return (
                  <Button
                    key={provider.id}
                    variant={ssoFirst ? "default" : "outline"}
                    className={providerButtonClass}
                    onClick={() => handleOAuthSignIn(provider.id)}
                    disabled={disabled}
                  >
                    {isPending ? <Spinner /> : <LogIn className="h-5 w-5" />}
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-semibold">
                        {isPending ? `Signing in with ${provider.name}…` : `Continue with ${provider.name}`}
                      </span>
                      {provider.host && <span className="truncate font-mono text-xs font-normal opacity-80">{provider.host}</span>}
                    </span>
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </Button>
                );
              })}
              {samlProviders.map((provider) => {
                const isPending = oauthPending === `saml:${provider.id}`;
                return (
                  <Button
                    key={`saml-${provider.id}`}
                    variant={ssoFirst ? "default" : "outline"}
                    className={providerButtonClass}
                    onClick={() => handleSamlSignIn(provider.id)}
                    disabled={disabled}
                    data-testid="saml-sign-in"
                  >
                    {isPending ? <Spinner /> : <LogIn className="h-5 w-5" />}
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-semibold">
                        {isPending ? `Signing in with ${provider.name}…` : `Continue with ${provider.name}`}
                      </span>
                      {provider.host && <span className="truncate font-mono text-xs font-normal opacity-80">{provider.host}</span>}
                    </span>
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </Button>
                );
              })}
              {offerPasskey && (
                <Button
                  type="button"
                  variant="outline"
                  className="h-11 w-full rounded-lg"
                  onClick={handlePasskeySignIn}
                  disabled={disabled}
                  data-testid="passkey-sign-in"
                >
                  <KeyRound className="h-4 w-4" />
                  Sign in with a passkey
                </Button>
              )}
            </div>
          )}

          {!challenge && !ssoFirst && (hasSso || offerPasskey) && showPasswordForm && (
            <div className="relative" aria-hidden="true">
              <div className="border-t" />
              <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card px-2 text-xs text-muted-foreground">
                or with a password
              </span>
            </div>
          )}

          {!challenge && !hasSso && !offerPasskey && !passwordSignIn && (
            <p className="text-sm text-muted-foreground" data-testid="no-sign-in-method">
              Single sign-on is required, but no identity provider is enabled. Ask your administrator.
            </p>
          )}

          {!challenge && ssoFirst && passwordSignIn && (
            <div className="flex flex-col border-t pt-3.5">
              <button
                type="button"
                onClick={() => {
                  setShowPasswordForm(!showPasswordForm);
                  setLoginError(null);
                }}
                aria-expanded={showPasswordForm}
                aria-controls="password-form"
                disabled={disabled}
                className="-mx-2.5 flex min-h-12 items-center gap-3 rounded-lg px-2.5 py-1 text-left hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
              >
                <Lock className="h-[18px] w-[18px] flex-none text-muted-foreground" aria-hidden="true" />
                <span className="flex min-w-0 flex-1 flex-col">
                  {localSignIn ? (
                    <>
                      <span className="text-sm font-medium">Sign in with a password</span>
                      <span className="text-xs text-muted-foreground">
                        {directories.length > 0 ? "Break-glass accounts and directories that stay open" : "Break-glass accounts only"}
                      </span>
                    </>
                  ) : (
                    <span className="text-sm font-medium">
                      {directories.length === 1 ? `Sign in with ${directories[0].name}` : "Sign in with a directory"}
                    </span>
                  )}
                </span>
                {showPasswordForm
                  ? <ChevronUp className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                  : <ChevronDown className="h-4 w-4 text-muted-foreground" aria-hidden="true" />}
              </button>
            </div>
          )}

          {showPasswordForm && (
            <form onSubmit={handleSignIn} id="password-form" className="flex flex-col gap-3.5">
              {ssoEnforced && method === "local" && (
                <div role="note" className="flex items-start gap-2.5 rounded-lg bg-warn-tint px-3 py-2.5 text-[13px] leading-[18px]">
                  <TriangleAlert className="mt-px h-4 w-4 flex-none text-warn" aria-hidden="true" />
                  <span>
                    Single sign-on is required here. A password only works for a break-glass account, kept for when{" "}
                    {ssoHost ?? "the identity provider"} is down. Every sign-in is recorded in the audit log.
                  </span>
                </div>
              )}
              {directories.length + (localSignIn ? 1 : 0) > 1 && (
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="sign-in-method">Sign in with</Label>
                  <select
                    id="sign-in-method"
                    name="method"
                    className="flex h-10 w-full rounded-lg border border-input bg-background px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                    value={method === "local" ? "local" : String(method)}
                    onChange={(event) => {
                      setMethod(event.target.value === "local" ? "local" : Number(event.target.value));
                      setLoginError(null);
                    }}
                    disabled={disabled}
                  >
                    {directories.map((directory) => (
                      <option key={directory.id} value={String(directory.id)}>
                        {directory.name}
                      </option>
                    ))}
                    {localSignIn && (
                      <option value="local">{ssoEnforced ? "Break-glass account" : `${branding.productName} account`}</option>
                    )}
                  </select>
                </div>
              )}
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="username">{directoryName ? `${directoryName} username` : "Username"}</Label>
                <Input
                  id="username"
                  name="username"
                  required
                  autoComplete="username"
                  spellCheck={false}
                  autoFocus={!hasSso || ssoFirst}
                  disabled={disabled}
                  className="h-10 rounded-lg"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  required
                  autoComplete="current-password"
                  disabled={disabled}
                  className="h-10 rounded-lg"
                />
              </div>
              <Button type="submit" variant={ssoFirst ? "outline" : "default"} className="h-10 w-full rounded-lg" disabled={disabled}>
                {loginPending ? (
                  <>
                    <Spinner />
                    Signing in…
                  </>
                ) : (
                  "Sign in"
                )}
              </Button>
            </form>
          )}
        </section>

        <BrandFooter branding={branding} />
      </main>

      <footer className="absolute inset-x-0 bottom-8 flex flex-wrap items-center justify-center gap-x-3.5 gap-y-2 text-xs text-muted-foreground">
        <span title="Application version">
          {branding.productName} <span className="font-mono">{formatAppVersion()}</span>
        </span>
      </footer>
    </div>
  );
}
