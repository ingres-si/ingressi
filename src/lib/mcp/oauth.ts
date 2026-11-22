/**
 * The OAuth 2.1 authorization server that protects the MCP endpoint
 * (RFC 9728 resource server, RFC 8414 metadata, RFC 7591 dynamic client
 * registration, PKCE S256, rotating refresh tokens).
 *
 * The rules this module enforces:
 *
 *  - Clients register themselves, or are pre-registered by an administrator;
 *    public clients (`token_endpoint_auth_method: "none"`) get no secret.
 *  - Redirect URIs are matched exactly, except that a loopback redirect may
 *    use another port (RFC 8252 §7.3). Registration accepts only HTTPS, or
 *    HTTP on a loopback address, and no fragments.
 *  - Every authorization code is single use, lives five minutes, and is bound
 *    to the client, the user, the redirect URI, the PKCE challenge, the
 *    scopes and the resource. Only its SHA-256 hash is stored.
 *  - Access tokens live one hour; refresh tokens 30 days and rotate on every
 *    use. Presenting an already rotated refresh token revokes the whole
 *    family, which is how a stolen token is contained.
 *  - Tokens are bound to the canonical MCP resource (config.ts), and only
 *    hashes are stored at rest.
 */
import { createHash, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { and, count, desc, eq, gt, isNotNull, isNull, lt, or } from "drizzle-orm";
import { appDb, nowIso } from "../db";
import { config } from "../config";
import { mcpOAuthClients, mcpOAuthCodes, mcpOAuthConsents, mcpOAuthTokens, users } from "../db/schema";
import { logAuditEvent } from "../audit";
import { first } from "../db/ops";
import { isPermission } from "../permissions";
import { mcpResourceUrl } from "./config";
import { parseScopeString, scopeString } from "./scopes";

export const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
/** Registered clients kept at once (a self-hosted instance, not a public service). */
export const MAX_REGISTERED_CLIENTS = 500;
const MAX_REDIRECT_URIS = 10;
const MAX_CLIENT_NAME_LENGTH = 100;
const MAX_URI_LENGTH = 2_000;
const ACCESS_TOKEN_PREFIX = "mcp_at_";
const REFRESH_TOKEN_PREFIX = "mcp_rt_";
const CLIENT_SECRET_PREFIX = "mcp_cs_";
const CLIENT_ID_PREFIX = "mcp_";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

const TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"] as const;
export type TokenEndpointAuthMethod = (typeof TOKEN_ENDPOINT_AUTH_METHODS)[number];
const GRANT_TYPES = ["authorization_code", "refresh_token"] as const;

/** An OAuth error: `error` is the RFC 6749 code the endpoint reports. */
export class OAuthError extends Error {
  readonly error: string;
  readonly status: number;
  readonly headers: Record<string, string>;

  constructor(error: string, description: string, status = 400, headers: Record<string, string> = {}) {
    super(description);
    this.name = "OAuthError";
    this.error = error;
    this.status = status;
    this.headers = { "Cache-Control": "no-store", Pragma: "no-cache", ...headers };
  }
}

export type StoredClient = typeof mcpOAuthClients.$inferSelect;

export type RegisteredClient = {
  clientId: string;
  clientSecret: string | null;
  name: string;
  redirectUris: string[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  grantTypes: string[];
  createdAt: string;
};

/**
 * The digest stored at rest for a client secret, authorization code, access
 * token or refresh token: PBKDF2-HMAC-SHA-256, keyed by SESSION_SECRET. The
 * values are 256-bit random tokens generated here, not user-chosen passwords,
 * but a database copy alone must still not let anyone test candidates
 * offline; SESSION_SECRET is the key that makes that impossible. Rotating
 * SESSION_SECRET invalidates the stored MCP grants; clients re-authorize.
 */
export function hashStoredSecret(value: string): string {
  return pbkdf2Sync(value, config.sessionSecret, 10_000, 32, "sha256").toString("hex");
}

/** Constant-time comparison of two hex digests. */
function sameDigest(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function randomToken(prefix: string, bytes = 32): string {
  return `${prefix}${randomBytes(bytes).toString("base64url")}`;
}

function isoAfter(seconds: number, from: Date = new Date()): string {
  return new Date(from.getTime() + seconds * 1000).toISOString();
}

function isFuture(iso: string, now: Date = new Date()): boolean {
  const time = Date.parse(iso);
  return Number.isFinite(time) && time > now.getTime();
}

function jsonArray(raw: string): string[] {
  try {
    const value = JSON.parse(raw);
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function loopbackHost(hostname: string): string {
  const lower = hostname.toLowerCase();
  if (lower === "[::1]") return "::1";
  return lower;
}

function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(loopbackHost(hostname));
}

/** A redirect URI this server will register and redirect to. */
export function validateRedirectUri(raw: unknown): string {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new OAuthError("invalid_redirect_uri", "redirect_uris must be a list of absolute URIs");
  }
  const value = raw.trim();
  if (value.length > MAX_URI_LENGTH) {
    throw new OAuthError("invalid_redirect_uri", "A redirect URI is too long");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OAuthError("invalid_redirect_uri", `Not an absolute URI: ${value.slice(0, 200)}`);
  }
  if (url.username || url.password) throw new OAuthError("invalid_redirect_uri", "A redirect URI cannot carry credentials");
  if (url.hash) throw new OAuthError("invalid_redirect_uri", "A redirect URI cannot carry a fragment");
  if (url.protocol === "https:") return value;
  if (url.protocol === "http:" && isLoopback(url.hostname)) return value;
  throw new OAuthError("invalid_redirect_uri", "Redirect URIs must use HTTPS, or HTTP on a loopback address");
}

/**
 * Whether a client may be sent to `requested`: exact match, or the same
 * loopback URI on a different port (a native client gets a free port at
 * callback time).
 */
export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  let a: URL;
  let b: URL;
  try {
    a = new URL(registered);
    b = new URL(requested);
  } catch {
    return false;
  }
  if (a.protocol !== "http:" || b.protocol !== "http:") return false;
  if (!isLoopback(a.hostname) || !isLoopback(b.hostname)) return false;
  if (loopbackHost(a.hostname) !== loopbackHost(b.hostname)) return false;
  if (a.username || a.password || b.username || b.password) return false;
  return a.pathname === b.pathname && a.search === b.search && a.hash === b.hash;
}

export function clientAllowsRedirect(client: Pick<StoredClient, "redirectUris">, requested: string): boolean {
  return jsonArray(client.redirectUris).some((registered) => redirectUriMatches(registered, requested));
}

/**
 * The canonical audience a request names, or the MCP endpoint when it names
 * none. Any other resource is an `invalid_target` (RFC 8707).
 */
export function resolveResource(raw: unknown): string {
  const canonical = mcpResourceUrl();
  if (raw === undefined || raw === null || raw === "") return canonical;
  if (typeof raw !== "string" || raw.length > MAX_URI_LENGTH) {
    throw new OAuthError("invalid_target", "resource must be an absolute URI");
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new OAuthError("invalid_target", "resource must be an absolute URI");
  }
  if (url.hash) throw new OAuthError("invalid_target", "resource must not contain a fragment");
  const normalized = url.toString().replace(/\/+$/, "");
  const expected = new URL(canonical).toString().replace(/\/+$/, "");
  if (normalized !== expected) {
    throw new OAuthError("invalid_target", "This authorization server only issues tokens for its MCP endpoint");
  }
  return canonical;
}

function readName(raw: unknown, fallback: string): string {
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw !== "string") throw new OAuthError("invalid_client_metadata", "client_name must be a string");
  // Control characters would end up in a consent heading.
  // eslint-disable-next-line no-control-regex
  const name = raw.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, MAX_CLIENT_NAME_LENGTH);
  return name || fallback;
}

function readOptionalUri(raw: unknown, field: string): string | null {
  if (raw === undefined || raw === null || raw === "") return null;
  if (typeof raw !== "string" || raw.length > MAX_URI_LENGTH) {
    throw new OAuthError("invalid_client_metadata", `${field} must be an absolute URI`);
  }
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("scheme");
    return raw;
  } catch {
    throw new OAuthError("invalid_client_metadata", `${field} must be an absolute http(s) URI`);
  }
}

export type ClientRegistrationInput = {
  redirect_uris?: unknown;
  token_endpoint_auth_method?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  client_name?: unknown;
  client_uri?: unknown;
  logo_uri?: unknown;
  software_id?: unknown;
  software_version?: unknown;
  scope?: unknown;
};

/**
 * RFC 7591 dynamic registration. The caller has already checked that
 * registration is open; this validates the metadata and stores the client.
 */
export async function registerClient(input: ClientRegistrationInput): Promise<RegisteredClient> {
  const rawUris = input.redirect_uris;
  if (!Array.isArray(rawUris) || rawUris.length === 0 || rawUris.length > MAX_REDIRECT_URIS) {
    throw new OAuthError(
      "invalid_redirect_uri",
      `redirect_uris must list 1 to ${MAX_REDIRECT_URIS} absolute URIs`
    );
  }
  const redirectUris = [...new Set(rawUris.map(validateRedirectUri))];

  const method = input.token_endpoint_auth_method ?? "none";
  if (typeof method !== "string" || !(TOKEN_ENDPOINT_AUTH_METHODS as readonly string[]).includes(method)) {
    throw new OAuthError(
      "invalid_client_metadata",
      `token_endpoint_auth_method must be one of ${TOKEN_ENDPOINT_AUTH_METHODS.join(", ")}`
    );
  }

  const grantTypes = input.grant_types ?? [...GRANT_TYPES];
  if (
    !Array.isArray(grantTypes) ||
    grantTypes.length === 0 ||
    grantTypes.some((value) => typeof value !== "string" || !(GRANT_TYPES as readonly string[]).includes(value)) ||
    !grantTypes.includes("authorization_code")
  ) {
    throw new OAuthError(
      "invalid_client_metadata",
      "grant_types must include authorization_code and may include refresh_token"
    );
  }

  const responseTypes = input.response_types ?? ["code"];
  if (!Array.isArray(responseTypes) || responseTypes.length !== 1 || responseTypes[0] !== "code") {
    throw new OAuthError("invalid_client_metadata", "response_types must be [\"code\"]");
  }

  if (input.scope !== undefined && input.scope !== null) {
    const scopes = typeof input.scope === "string" ? parseScopeString(input.scope) : null;
    if (!scopes || scopes.some((scope) => !(scope.startsWith("mcp.") || isPermission(scope)))) {
      throw new OAuthError("invalid_client_metadata", "scope names an unknown scope");
    }
  }

  const existing = await first(appDb
    .select({ value: count() })
    .from(mcpOAuthClients)
    .where(isNull(mcpOAuthClients.revokedAt)));
  if ((existing?.value ?? 0) >= MAX_REGISTERED_CLIENTS) {
    throw new OAuthError(
      "registration_limit_reached",
      `This instance holds at most ${MAX_REGISTERED_CLIENTS} MCP clients; an administrator can revoke unused ones.`,
      403
    );
  }

  const clientId = randomToken(CLIENT_ID_PREFIX, 18);
  const clientSecret = method === "none" ? null : randomToken(CLIENT_SECRET_PREFIX, 32);
  const now = nowIso();
  await appDb.insert(mcpOAuthClients).values({
    clientId,
    clientSecretHash: clientSecret ? hashStoredSecret(clientSecret) : null,
    name: readName(input.client_name, "MCP client"),
    redirectUris: JSON.stringify(redirectUris),
    grantTypes: JSON.stringify([...grantTypes]),
    tokenEndpointAuthMethod: method as TokenEndpointAuthMethod,
    clientUri: readOptionalUri(input.client_uri, "client_uri"),
    logoUri: readOptionalUri(input.logo_uri, "logo_uri"),
    softwareId: typeof input.software_id === "string" ? input.software_id.slice(0, 100) : null,
    softwareVersion: typeof input.software_version === "string" ? input.software_version.slice(0, 100) : null,
    createdAt: now,
    lastUsedAt: null,
    revokedAt: null,
  });

  await logAuditEvent({
    action: "mcp_client_registered",
    entityType: "mcp_client",
    entityId: null,
    summary: `MCP client registered: ${readName(input.client_name, "MCP client")}`,
    data: { clientId, tokenEndpointAuthMethod: method, redirectUris },
  });

  return {
    clientId,
    clientSecret,
    name: readName(input.client_name, "MCP client"),
    redirectUris,
    tokenEndpointAuthMethod: method as TokenEndpointAuthMethod,
    grantTypes: [...grantTypes],
    createdAt: now,
  };
}

export async function getClient(clientId: string): Promise<StoredClient | null> {
  return await first(appDb
    .select()
    .from(mcpOAuthClients)
    .where(eq(mcpOAuthClients.clientId, clientId))
    .limit(1)) ?? null;
}

/** A live client with the given id, or an `invalid_client` OAuth error (401). */
export async function requireActiveClient(clientId: string): Promise<StoredClient> {
  const client = await getClient(clientId);
  if (!client || client.revokedAt) {
    throw new OAuthError("invalid_client", "Unknown or revoked client", 401);
  }
  return client;
}

/** Checks the client's secret for the token and revocation endpoints. */
export function authenticateClientSecret(client: StoredClient, secret: string | null): void {
  if (client.tokenEndpointAuthMethod === "none") return;
  if (!secret || !client.clientSecretHash || !sameDigest(hashStoredSecret(secret), client.clientSecretHash)) {
    throw new OAuthError("invalid_client", "Client authentication failed", 401, {
      "WWW-Authenticate": 'Basic realm="ingressi-mcp", error="invalid_client"',
    });
  }
}

export function clientRedirectUris(client: StoredClient): string[] {
  return jsonArray(client.redirectUris);
}

export function clientGrantTypes(client: StoredClient): string[] {
  return jsonArray(client.grantTypes);
}

// ── Consent ───────────────────────────────────────────────────────────

export async function saveConsent(
  userId: number,
  clientId: string,
  scopes: readonly string[],
  resource: string
): Promise<void> {
  const now = nowIso();
  const value = scopeString(scopes);
  const existing = await first(appDb
    .select({ id: mcpOAuthConsents.id })
    .from(mcpOAuthConsents)
    .where(and(eq(mcpOAuthConsents.userId, userId), eq(mcpOAuthConsents.clientId, clientId)))
    .limit(1));
  if (existing) {
    await appDb
      .update(mcpOAuthConsents)
      .set({ scopes: value, resource, updatedAt: now })
      .where(eq(mcpOAuthConsents.id, existing.id));
    return;
  }
  await appDb.insert(mcpOAuthConsents).values({
    userId,
    clientId,
    scopes: value,
    resource,
    createdAt: now,
    updatedAt: now,
  });
}

// ── Authorization codes ───────────────────────────────────────────────

export type AuthorizationCodeInput = {
  clientId: string;
  userId: number;
  redirectUri: string;
  codeChallenge: string;
  scopes: readonly string[];
  resource: string;
};

export async function createAuthorizationCode(input: AuthorizationCodeInput): Promise<string> {
  const code = randomToken("mcp_ac_", 32);
  const now = new Date();
  await appDb.insert(mcpOAuthCodes).values({
    codeHash: hashStoredSecret(code),
    clientId: input.clientId,
    userId: input.userId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    scopes: scopeString(input.scopes),
    resource: input.resource,
    createdAt: now.toISOString(),
    expiresAt: isoAfter(AUTHORIZATION_CODE_TTL_SECONDS, now),
    consumedAt: null,
  });
  return code;
}

const PKCE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

function verifyPkce(verifier: string, challenge: string): boolean {
  if (!PKCE_VERIFIER.test(verifier)) return false;
  const computed = createHash("sha256").update(verifier).digest("base64url");
  return sameDigest(computed, challenge);
}

export type CodeExchangeInput = {
  code: string;
  client: StoredClient;
  redirectUri: string;
  codeVerifier: string;
  resource?: unknown;
};

export type CodeExchangeResult = {
  userId: number;
  scopes: string[];
  resource: string;
};

/**
 * Redeems an authorization code exactly once. Every binding is checked
 * before the code is consumed; the consume itself is a single conditional
 * UPDATE, so two parallel redemptions cannot both succeed.
 */
export async function exchangeAuthorizationCode(input: CodeExchangeInput): Promise<CodeExchangeResult> {
  const row = await first(appDb
    .select()
    .from(mcpOAuthCodes)
    .where(eq(mcpOAuthCodes.codeHash, hashStoredSecret(input.code)))
    .limit(1));
  if (!row) throw new OAuthError("invalid_grant", "Unknown authorization code");
  if (row.clientId !== input.client.clientId) {
    throw new OAuthError("invalid_grant", "The authorization code belongs to another client");
  }
  if (row.consumedAt) throw new OAuthError("invalid_grant", "The authorization code was already used");
  if (!isFuture(row.expiresAt)) throw new OAuthError("invalid_grant", "The authorization code expired");
  if (!redirectUriMatches(row.redirectUri, input.redirectUri)) {
    throw new OAuthError("invalid_grant", "redirect_uri does not match the authorization request");
  }
  const scopes = parseScopeString(row.scopes) ?? [];
  if (input.resource !== undefined && input.resource !== null && input.resource !== "") {
    const resource = resolveResource(input.resource);
    if (resource !== row.resource) throw new OAuthError("invalid_target", "resource does not match the authorization request");
  }
  if (!verifyPkce(input.codeVerifier, row.codeChallenge)) {
    throw new OAuthError("invalid_grant", "The PKCE code_verifier does not match the challenge");
  }

  const consumed = await appDb
    .update(mcpOAuthCodes)
    .set({ consumedAt: nowIso() })
    .where(and(eq(mcpOAuthCodes.id, row.id), isNull(mcpOAuthCodes.consumedAt)))
    .returning({ id: mcpOAuthCodes.id });
  if (consumed.length !== 1) throw new OAuthError("invalid_grant", "The authorization code was already used");

  return { userId: row.userId, scopes, resource: row.resource };
}

// ── Tokens ────────────────────────────────────────────────────────────

export type IssuedTokens = {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  refreshExpiresIn: number;
  scopes: string[];
  resource: string;
};

async function insertTokenPair(input: {
  clientId: string;
  userId: number;
  scopes: readonly string[];
  resource: string;
  familyId: string;
  now: Date;
}): Promise<IssuedTokens> {
  const accessToken = randomToken(ACCESS_TOKEN_PREFIX);
  const refreshToken = randomToken(REFRESH_TOKEN_PREFIX);
  await appDb
    .update(mcpOAuthClients)
    .set({ lastUsedAt: input.now.toISOString() })
    .where(eq(mcpOAuthClients.clientId, input.clientId));
  await appDb.insert(mcpOAuthTokens).values({
    accessTokenHash: hashStoredSecret(accessToken),
    refreshTokenHash: hashStoredSecret(refreshToken),
    clientId: input.clientId,
    userId: input.userId,
    scopes: scopeString(input.scopes),
    resource: input.resource,
    accessExpiresAt: isoAfter(ACCESS_TOKEN_TTL_SECONDS, input.now),
    refreshExpiresAt: isoAfter(REFRESH_TOKEN_TTL_SECONDS, input.now),
    familyId: input.familyId,
    createdAt: input.now.toISOString(),
    lastUsedAt: null,
    rotatedAt: null,
    revokedAt: null,
  });
  return {
    accessToken,
    refreshToken,
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
    refreshExpiresIn: REFRESH_TOKEN_TTL_SECONDS,
    scopes: [...input.scopes],
    resource: input.resource,
  };
}

export async function issueTokensForGrant(input: {
  clientId: string;
  userId: number;
  scopes: readonly string[];
  resource: string;
}): Promise<IssuedTokens> {
  const now = new Date();
  return await insertTokenPair({ ...input, familyId: randomBytes(16).toString("hex"), now });
}

export type RefreshInput = {
  refreshToken: string;
  client: StoredClient;
  scope?: unknown;
  resource?: unknown;
};

export async function rotateRefreshToken(input: RefreshInput): Promise<IssuedTokens> {
  const row = await first(appDb
    .select()
    .from(mcpOAuthTokens)
    .where(eq(mcpOAuthTokens.refreshTokenHash, hashStoredSecret(input.refreshToken)))
    .limit(1));
  if (!row) throw new OAuthError("invalid_grant", "Unknown refresh token");
  if (row.clientId !== input.client.clientId) throw new OAuthError("invalid_grant", "The refresh token belongs to another client");
  if (row.revokedAt) throw new OAuthError("invalid_grant", "The refresh token was revoked");
  if (row.rotatedAt) {
    // Reuse of a rotated token: someone else has it. Contain the damage.
    await revokeFamily(row.familyId, "refresh token reuse");
    throw new OAuthError("invalid_grant", "The refresh token was already used; the grant was revoked");
  }
  if (!isFuture(row.refreshExpiresAt)) throw new OAuthError("invalid_grant", "The refresh token expired");

  const originalScopes = parseScopeString(row.scopes) ?? [];
  let scopes = originalScopes;
  if (input.scope !== undefined && input.scope !== null && input.scope !== "") {
    if (typeof input.scope !== "string") throw new OAuthError("invalid_scope", "scope must be a space-separated string");
    const requested = parseScopeString(input.scope);
    if (!requested) throw new OAuthError("invalid_scope", "Malformed scope");
    if (!requested.every((scope) => originalScopes.includes(scope))) {
      throw new OAuthError("invalid_scope", "A refresh may narrow the granted scopes, not widen them");
    }
    scopes = requested;
  }

  let resource = row.resource;
  if (input.resource !== undefined && input.resource !== null && input.resource !== "") {
    resource = resolveResource(input.resource);
    if (resource !== row.resource) throw new OAuthError("invalid_target", "resource does not match the original grant");
  }

  const now = nowIso();
  const rotated = await appDb
    .update(mcpOAuthTokens)
    .set({ rotatedAt: now })
    .where(and(eq(mcpOAuthTokens.id, row.id), isNull(mcpOAuthTokens.rotatedAt), isNull(mcpOAuthTokens.revokedAt)))
    .returning({ id: mcpOAuthTokens.id });
  if (rotated.length !== 1) {
    await revokeFamily(row.familyId, "refresh token reuse");
    throw new OAuthError("invalid_grant", "The refresh token was already used; the grant was revoked");
  }

  return await insertTokenPair({
    clientId: row.clientId,
    userId: row.userId,
    scopes,
    resource,
    familyId: row.familyId,
    now: new Date(now),
  });
}

export async function revokeFamily(familyId: string, reason: string): Promise<void> {
  await appDb
    .update(mcpOAuthTokens)
    .set({ revokedAt: nowIso() })
    .where(and(eq(mcpOAuthTokens.familyId, familyId), isNull(mcpOAuthTokens.revokedAt)));
  await logAuditEvent({
    action: "mcp_tokens_revoked",
    entityType: "mcp_token",
    entityId: null,
    summary: `MCP grant revoked: ${reason}`,
    data: { familyId },
  });
}

/** The token row behind a bearer token, if it is live and its client is not revoked. */
export type ValidatedAccessToken = {
  tokenId: number;
  userId: number;
  clientId: string;
  clientName: string;
  scopes: string[];
  resource: string;
  expiresAt: string;
};

export async function validateAccessToken(raw: string): Promise<ValidatedAccessToken | null> {
  if (!raw.startsWith(ACCESS_TOKEN_PREFIX) || raw.length > 200) return null;
  const row = await first(appDb
    .select()
    .from(mcpOAuthTokens)
    .where(eq(mcpOAuthTokens.accessTokenHash, hashStoredSecret(raw)))
    .limit(1));
  if (!row || row.revokedAt) return null;
  if (!isFuture(row.accessExpiresAt)) return null;
  const client = await getClient(row.clientId);
  if (!client || client.revokedAt) return null;

  // "Last used" is written at most once a minute, as API tokens do.
  try {
    const last = row.lastUsedAt ? Date.parse(row.lastUsedAt) : 0;
    if (!Number.isFinite(last) || Date.now() - last > 60_000) {
      await appDb.update(mcpOAuthTokens).set({ lastUsedAt: nowIso() }).where(eq(mcpOAuthTokens.id, row.id));
    }
  } catch {
    // Bookkeeping only.
  }

  return {
    tokenId: row.id,
    userId: row.userId,
    clientId: row.clientId,
    clientName: client.name,
    scopes: parseScopeString(row.scopes) ?? [],
    resource: row.resource,
    expiresAt: row.accessExpiresAt,
  };
}

/**
 * RFC 7009 revocation. Unknown tokens are a no-op (the endpoint answers 200
 * either way); a token issued to another client is refused.
 */
export async function revokeToken(raw: string, clientId: string, actorUserId: number | null): Promise<void> {
  const tokenHash = hashStoredSecret(raw);
  const row = await first(appDb
    .select()
    .from(mcpOAuthTokens)
    .where(or(eq(mcpOAuthTokens.accessTokenHash, tokenHash), eq(mcpOAuthTokens.refreshTokenHash, tokenHash)))
    .limit(1));
  if (!row) return;
  if (row.clientId !== clientId) {
    throw new OAuthError("invalid_client", "The token belongs to another client", 401);
  }
  await revokeFamily(row.familyId, "revoked by the client");
  await logAuditEvent({
    userId: actorUserId,
    action: "mcp_token_revoked",
    entityType: "mcp_token",
    entityId: row.id,
    summary: "MCP token revoked",
  });
}

// ── Administration ────────────────────────────────────────────────────

export type McpClientSummary = {
  clientId: string;
  name: string;
  redirectUris: string[];
  tokenEndpointAuthMethod: string;
  clientUri: string | null;
  softwareId: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  activeGrants: number;
};

export async function listClients(): Promise<McpClientSummary[]> {
  const rows = await appDb.select().from(mcpOAuthClients).orderBy(desc(mcpOAuthClients.createdAt));
  const grants = await appDb
    .select({ clientId: mcpOAuthTokens.clientId, value: count() })
    .from(mcpOAuthTokens)
    .where(
      and(
        isNull(mcpOAuthTokens.revokedAt),
        isNull(mcpOAuthTokens.rotatedAt),
        gt(mcpOAuthTokens.refreshExpiresAt, nowIso())
      )
    )
    .groupBy(mcpOAuthTokens.clientId);
  const byClient = new Map(grants.map((row) => [row.clientId, row.value]));
  return rows.map((row) => ({
    clientId: row.clientId,
    name: row.name,
    redirectUris: clientRedirectUris(row),
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    clientUri: row.clientUri,
    softwareId: row.softwareId,
    createdAt: row.createdAt,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
    activeGrants: byClient.get(row.clientId) ?? 0,
  }));
}

export type McpConnection = {
  id: number;
  familyId: string;
  clientId: string;
  clientName: string;
  userId: number;
  userName: string | null;
  userEmail: string;
  scopes: string[];
  resource: string;
  createdAt: string;
  lastUsedAt: string | null;
  refreshExpiresAt: string;
};

/** One row per live grant (the newest token of each rotation family). */
export async function listConnections(): Promise<McpConnection[]> {
  const rows = await appDb
    .select({
      id: mcpOAuthTokens.id,
      familyId: mcpOAuthTokens.familyId,
      clientId: mcpOAuthTokens.clientId,
      clientName: mcpOAuthClients.name,
      userId: mcpOAuthTokens.userId,
      userName: users.name,
      userEmail: users.email,
      scopes: mcpOAuthTokens.scopes,
      resource: mcpOAuthTokens.resource,
      createdAt: mcpOAuthTokens.createdAt,
      lastUsedAt: mcpOAuthTokens.lastUsedAt,
      refreshExpiresAt: mcpOAuthTokens.refreshExpiresAt,
    })
    .from(mcpOAuthTokens)
    .innerJoin(mcpOAuthClients, eq(mcpOAuthTokens.clientId, mcpOAuthClients.clientId))
    .innerJoin(users, eq(mcpOAuthTokens.userId, users.id))
    .where(
      and(
        isNull(mcpOAuthTokens.revokedAt),
        isNull(mcpOAuthTokens.rotatedAt),
        isNotNull(mcpOAuthTokens.refreshTokenHash),
        gt(mcpOAuthTokens.refreshExpiresAt, nowIso())
      )
    )
    .orderBy(desc(mcpOAuthTokens.createdAt));
  return rows.map((row) => ({
    ...row,
    scopes: parseScopeString(row.scopes) ?? [],
  }));
}

export async function revokeConnection(id: number): Promise<boolean> {
  const row = await first(appDb
    .select({ familyId: mcpOAuthTokens.familyId })
    .from(mcpOAuthTokens)
    .where(eq(mcpOAuthTokens.id, id))
    .limit(1));
  if (!row) return false;
  await revokeFamily(row.familyId, "revoked by an administrator");
  return true;
}

/** Revokes a client and everything issued through it. */
export async function revokeClient(clientId: string): Promise<boolean> {
  const client = await getClient(clientId);
  if (!client) return false;
  const now = nowIso();
  await appDb.transaction(async (tx) => {
    await tx.update(mcpOAuthClients).set({ revokedAt: now }).where(eq(mcpOAuthClients.clientId, clientId));
    await tx
      .update(mcpOAuthTokens)
      .set({ revokedAt: now })
      .where(and(eq(mcpOAuthTokens.clientId, clientId), isNull(mcpOAuthTokens.revokedAt)));
    await tx.update(mcpOAuthCodes).set({ consumedAt: now }).where(eq(mcpOAuthCodes.clientId, clientId));
    await tx.delete(mcpOAuthConsents).where(eq(mcpOAuthConsents.clientId, clientId));
  });
  await logAuditEvent({
    action: "mcp_client_revoked",
    entityType: "mcp_client",
    entityId: null,
    summary: `MCP client revoked: ${client.name}`,
    data: { clientId },
  });
  return true;
}

/**
 * Deletes expired codes, long-dead tokens and clients revoked more than 30
 * days ago (with their rows). Called opportunistically from the token
 * endpoint; safe to run twice.
 */
export async function pruneMcpOAuthArtifacts(now: Date = new Date()): Promise<void> {
  const longAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const revokedLongAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  try {
    await appDb.delete(mcpOAuthCodes).where(lt(mcpOAuthCodes.expiresAt, longAgo));
    await appDb.delete(mcpOAuthTokens).where(lt(mcpOAuthTokens.refreshExpiresAt, longAgo));

    const staleClients = await appDb
      .select({ clientId: mcpOAuthClients.clientId })
      .from(mcpOAuthClients)
      .where(and(isNotNull(mcpOAuthClients.revokedAt), lt(mcpOAuthClients.revokedAt, revokedLongAgo)));
    for (const { clientId } of staleClients) {
      await appDb.transaction(async (tx) => {
        await tx.delete(mcpOAuthTokens).where(eq(mcpOAuthTokens.clientId, clientId));
        await tx.delete(mcpOAuthCodes).where(eq(mcpOAuthCodes.clientId, clientId));
        await tx.delete(mcpOAuthConsents).where(eq(mcpOAuthConsents.clientId, clientId));
        await tx.delete(mcpOAuthClients).where(eq(mcpOAuthClients.clientId, clientId));
      });
    }
  } catch {
    // Housekeeping only; never fail a token request over it.
  }
}

