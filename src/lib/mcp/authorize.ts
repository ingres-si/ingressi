/**
 * The authorization endpoint's rules, shared by the consent page (GET) and
 * the form that records the decision (POST). Keeping them in one place means
 * the POST re-checks everything the hidden fields claim: the client, the
 * redirect URI, PKCE, the scopes and the resource.
 */
import { type Access } from "../permissions";
import { issuerUrl, mcpResourceUrl } from "./config";
import {
  clientAllowsRedirect,
  getClient,
  resolveResource,
  type StoredClient,
} from "./oauth";
import {
  MCP_DEFAULT_SCOPE,
  parseScopeString,
  validateScopesForAccess,
} from "./scopes";

const MAX_STATE_LENGTH = 2_000;
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43,128}$/;

export type AuthorizationRequest = {
  clientId: string;
  clientName: string;
  redirectUri: string;
  state: string | null;
  scopes: string[];
  resource: string;
  codeChallenge: string;
  prompt: string[];
};

export type AuthorizationParse =
  | { ok: true; request: AuthorizationRequest }
  /** No trustworthy redirect_uri: the page answers 400 instead of redirecting. */
  | { ok: false; fatal: true; error: string; description: string }
  /** The redirect_uri is trusted; the browser returns to it with error=... */
  | {
      ok: false;
      fatal: false;
      redirectUri: string;
      state: string | null;
      error: string;
      description: string;
    };

function read(params: URLSearchParams, name: string): string | null {
  const value = params.get(name);
  return value === null || value.trim() === "" ? null : value;
}

function readPrompt(raw: string | null): string[] | null {
  if (raw === null) return [];
  const prompts = raw.trim().split(/\s+/).filter(Boolean);
  const known = new Set(["none", "consent", "login", "select_account"]);
  if (prompts.some((prompt) => !known.has(prompt))) return null;
  return [...new Set(prompts)];
}

function redirectable(
  redirectUri: string,
  state: string | null,
  error: string,
  description: string
): AuthorizationParse {
  return { ok: false, fatal: false, redirectUri, state, error, description };
}

/**
 * Validates an authorization request. `access` and `userId` are the
 * signed-in account's; the request is checked against what they hold now, so
 * a scope the account lost cannot be requested.
 */
export async function parseAuthorizationRequest(
  params: URLSearchParams,
  access: Access
): Promise<AuthorizationParse> {
  const clientId = read(params, "client_id");
  if (!clientId) {
    return { ok: false, fatal: true, error: "invalid_request", description: "client_id is required" };
  }
  const client = await getClient(clientId);
  if (!client || client.revokedAt) {
    return { ok: false, fatal: true, error: "invalid_client", description: "Unknown or revoked client" };
  }

  const redirectUri = read(params, "redirect_uri");
  if (!redirectUri || !clientAllowsRedirect(client, redirectUri)) {
    return {
      ok: false,
      fatal: true,
      error: "invalid_request",
      description: "redirect_uri is missing or is not registered for this client",
    };
  }

  const state = read(params, "state");
  if (state !== null && state.length > MAX_STATE_LENGTH) {
    return redirectable(redirectUri, null, "invalid_request", "state is too long");
  }

  if (read(params, "response_type") !== "code") {
    return redirectable(redirectUri, state, "unsupported_response_type", "Only the code response type is supported");
  }
  const responseMode = read(params, "response_mode");
  if (responseMode !== null && responseMode !== "query") {
    return redirectable(redirectUri, state, "invalid_request", "Only the query response mode is supported");
  }

  const challenge = read(params, "code_challenge");
  const challengeMethod = read(params, "code_challenge_method") ?? "plain";
  if (!challenge) {
    return redirectable(redirectUri, state, "invalid_request", "PKCE code_challenge is required");
  }
  if (challengeMethod !== "S256") {
    return redirectable(redirectUri, state, "invalid_request", "code_challenge_method must be S256");
  }
  if (!PKCE_CHALLENGE.test(challenge)) {
    return redirectable(redirectUri, state, "invalid_request", "code_challenge is malformed");
  }

  const prompt = readPrompt(read(params, "prompt"));
  if (!prompt) {
    return redirectable(redirectUri, state, "invalid_request", "prompt is not a known value");
  }

  const rawScope = read(params, "scope");
  const parsedScopes = rawScope === null ? [] : parseScopeString(rawScope);
  if (!parsedScopes) {
    return redirectable(redirectUri, state, "invalid_scope", "scope is malformed");
  }
  const scopes = parsedScopes.length > 0 ? parsedScopes : [MCP_DEFAULT_SCOPE];
  const scopeProblem = validateScopesForAccess(scopes, access);
  if (scopeProblem) {
    return redirectable(redirectUri, state, "invalid_scope", scopeProblem);
  }

  let resource: string;
  try {
    resource = resolveResource(read(params, "resource"));
  } catch (error) {
    return redirectable(
      redirectUri,
      state,
      "invalid_target",
      error instanceof Error ? error.message : "resource is not the MCP endpoint"
    );
  }
  if (resource !== mcpResourceUrl()) {
    return redirectable(redirectUri, state, "invalid_target", "resource is not the MCP endpoint");
  }

  return {
    ok: true,
    request: {
      clientId: client.clientId,
      clientName: client.name,
      redirectUri,
      state,
      scopes,
      resource,
      codeChallenge: challenge,
      prompt,
    } satisfies AuthorizationRequest,
  };
}

/** Appends an authorization result to the client's redirect URI. */
export function buildRedirect(
  redirectUri: string,
  result: {
    state: string | null;
    code?: string;
    error?: string;
    errorDescription?: string;
  }
): string {
  const url = new URL(redirectUri);
  if (result.code) url.searchParams.set("code", result.code);
  if (result.error) {
    url.searchParams.set("error", result.error);
    if (result.errorDescription) url.searchParams.set("error_description", result.errorDescription);
  }
  if (result.state !== null) url.searchParams.set("state", result.state);
  // RFC 9207: the client checks that the answer came from the issuer it
  // started with.
  url.searchParams.set("iss", issuerUrl());
  return url.toString();
}

export function authorizationErrorRedirect(parse: Extract<AuthorizationParse, { ok: false; fatal: false }>): string {
  return buildRedirect(parse.redirectUri, {
    state: parse.state,
    error: parse.error,
    errorDescription: parse.description,
  });
}

/** The client details the consent page shows. */
export function clientDisplay(client: StoredClient) {
  return {
    clientId: client.clientId,
    name: client.name,
    clientUri: client.clientUri,
    logoUri: client.logoUri,
    softwareId: client.softwareId,
    softwareVersion: client.softwareVersion,
  };
}
