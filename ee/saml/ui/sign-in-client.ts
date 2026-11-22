// SPDX-License-Identifier: Elastic-2.0
/** The login page's SAML sign-in, in the browser. */

/**
 * SAML sign-in (ee/saml): POST /api/auth/sign-in/saml stores the request and
 * a binding cookie, then the browser goes to the identity provider.
 */
export async function startSamlSignIn(providerId: number, callbackURL = "/"): Promise<string | null> {
  try {
    const response = await fetch("/api/auth/sign-in/saml", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ providerId, callbackURL }),
    });
    const body = (await response.json().catch(() => null)) as { url?: string; message?: string } | null;
    if (!response.ok || typeof body?.url !== "string") return null;
    return body.url;
  } catch {
    return null;
  }
}
