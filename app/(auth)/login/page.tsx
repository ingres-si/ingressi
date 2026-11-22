import { redirect } from "next/navigation";
import { auth } from "@/src/lib/auth";
import { MFA_SETUP_PATH, mfaEnrolmentRequired } from "@/src/lib/mfa";
import { getProviderDisplayList } from "@/src/lib/models/oauth-providers";
import { oauthProviderHosts, samlProviderHosts } from "@/src/lib/login-providers";
import { anyPasskeyExists } from "@/src/lib/passkeys";
import { appDb } from "@/src/lib/db";
import { loginPageEnforcement } from "@/ee/sso/sign-in";
import { listLoginDirectories } from "@/ee/ldap/sso";
import { listLoginSamlProviders } from "@/ee/saml/store";
import LoginClient from "./LoginClient";

/** The message for a SAML sign-in that did not complete (ee/saml/plugin.ts); the reason is in the audit log. */
const SAML_ERROR_MESSAGE =
  "Single sign-on did not complete. Try again; if it keeps failing, ask your administrator to check the audit log.";

type LoginPageProps = { searchParams?: Promise<Record<string, string | string[] | undefined>> };

/** Reads that must never keep the login page from rendering. */
async function safely<T>(read: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await read();
  } catch {
    return fallback;
  }
}

/**
 * Where a completed sign-in goes: a same-origin path from the `next` query
 * parameter (the middleware adds it to protected deep links, including the
 * MCP consent page), or "/". A scheme, a host or a backslash is refused: the
 * login page must not be an open redirect.
 */
function safeNextPath(value: string | string[] | undefined): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return "/";
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f]/.test(value)) return "/";
  // A crafted next=/login would send a signed-in visitor back here forever.
  if (value === "/login" || value.startsWith("/login?") || value.startsWith("/login/")) return "/";
  return value;
}

export default async function LoginPage({ searchParams }: LoginPageProps = {}) {
  const params = (await searchParams) ?? {};
  const next = safeNextPath(params.next);
  const session = await auth();
  if (session) {
    redirect(await mfaEnrolmentRequired(Number(session.user.id)) ? MFA_SETUP_PATH : next);
  }

  const enabledProviders = await getProviderDisplayList();
  const { error } = params;
  // Where single sign-on sends the browser, shown on its button.
  const oauthHosts = await safely(oauthProviderHosts, new Map<string, string>());
  const samlHosts = await safely(samlProviderHosts, new Map<number, string>());
  const enforcement = await loginPageEnforcement(appDb);

  return (
    <LoginClient
      enabledProviders={enabledProviders.map((provider) => ({ ...provider, host: oauthHosts.get(provider.id) ?? null }))}
      ssoEnforced={enforcement.enforced}
      breakGlassSignIn={enforcement.breakGlass}
      directories={await listLoginDirectories(appDb)}
      samlProviders={(await listLoginSamlProviders(appDb)).map((provider) => ({ ...provider, host: samlHosts.get(provider.id) ?? null }))}
      // Passkey sign-in is offered once any account has a passkey.
      passkeysAvailable={await safely(async () => await anyPasskeyExists(), false)}
      initialError={error === "saml" ? SAML_ERROR_MESSAGE : null}
      next={next}
    />
  );
}
