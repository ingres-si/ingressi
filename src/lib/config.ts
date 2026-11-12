import { assertValidDashboardUpstreams } from "./dashboard-upstreams";
import { assertValidInstanceSyncToken } from "./instance-sync-token";

const DEV_SECRET = "dev-secret-change-in-production-12345678901234567890123456789012";
const DEFAULT_ADMIN_USERNAME = "admin";
export const DEFAULT_ADMIN_PASSWORD = "admin";
// Publicly known values: rejected at startup, and still tried as decryption
// keys (never for encryption) so data stored under them can be re-encrypted.
export const DISALLOWED_SESSION_SECRETS: ReadonlySet<string> = new Set([
  "change-me-in-production",
  "dev-secret-change-in-production-12345678901234567890123456789012",
  // Placeholders shipped in .env.example / documentation
  "your-secure-session-secret-here-min-32-chars",
]);
// Example passwords from current and earlier .env.example / README versions;
// they satisfy the complexity rules, so they must be rejected explicitly.
export const DISALLOWED_ADMIN_PASSWORDS: ReadonlySet<string> = new Set([
  "Your-Secure-P@ssw0rd-Here!",
  "YourStr0ng-P@ssw0rd123!",
  "YourStr0ng-P@ssw0rd!",
  "Your-Str0ng-P@ssw0rd!",
]);
const DEFAULT_CADDY_URL = process.env.NODE_ENV === "development" ? "http://localhost:2019" : "http://caddy:2019";
const MIN_SESSION_SECRET_LENGTH = 32;
const MIN_ADMIN_PASSWORD_LENGTH = 12;

const isProduction = process.env.NODE_ENV === "production";
const isNodeRuntime = process.env.NEXT_RUNTIME === "nodejs";
const isDevelopment = process.env.NODE_ENV === "development";
// Only enforce strict validation in actual production runtime, not during build.
// Next inlines NODE_ENV in the built app ("production" for next build,
// "development" for next dev), so there this is the same as NODE_ENV=production.
// Treating every non-development NODE_ENV as production is defense in depth for
// code that runs outside a Next bundle.
const isBuildPhase = process.env.NEXT_PHASE === "phase-production-build" || !process.env.NEXT_RUNTIME;
const isRuntimeProduction = !isDevelopment && isNodeRuntime && !isBuildPhase;

function resolveSessionSecret(): string {
  const rawSecret = process.env.SESSION_SECRET ?? null;
  const secret = rawSecret?.trim();

  // In development, allow missing secret
  if (isDevelopment && !secret) {
    return DEV_SECRET;
  }

  // In production build phase, allow temporary value
  if (isProduction && !isNodeRuntime && !secret) {
    return DEV_SECRET;
  }

  // Fail-closed on unrecognized NODE_ENV to prevent silent DEV_SECRET usage
  if (!isDevelopment && !isProduction && !secret) {
    throw new Error(
      `SESSION_SECRET is required when NODE_ENV="${process.env.NODE_ENV ?? ""}" ` +
      `(not "development" or "production"). ` +
      "Generate a secure secret with: openssl rand -base64 32"
    );
  }

  // Use provided secret or dev secret (only reachable in development)
  const finalSecret = secret || DEV_SECRET;

  // Strict validation in production runtime
  if (isRuntimeProduction) {
    if (!secret) {
      throw new Error(
        "SESSION_SECRET environment variable is required in production. " +
        "Generate a secure secret with: openssl rand -base64 32"
      );
    }
    if (DISALLOWED_SESSION_SECRETS.has(secret)) {
      throw new Error(
        "SESSION_SECRET is using a known insecure placeholder value. " +
        "Generate a secure secret with: openssl rand -base64 32. " +
        "Stored secrets encrypted under the placeholder are re-encrypted with the new secret automatically on the next start. " +
        "For any other SESSION_SECRET rotation, put the old value in SESSION_SECRET_PREVIOUS."
      );
    }
    if (secret.length < MIN_SESSION_SECRET_LENGTH) {
      throw new Error(
        `SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters long in production. ` +
        "Generate a secure secret with: openssl rand -base64 32"
      );
    }
  }

  return finalSecret;
}

function resolveAdminCredentials() {
  const rawUsername = process.env.ADMIN_USERNAME ?? null;
  const rawPassword = process.env.ADMIN_PASSWORD ?? null;
  const username = rawUsername?.trim() || DEFAULT_ADMIN_USERNAME;
  const password = rawPassword?.trim() || DEFAULT_ADMIN_PASSWORD;

  // In development, allow defaults
  if (isDevelopment) {
    if (username === DEFAULT_ADMIN_USERNAME || password === DEFAULT_ADMIN_PASSWORD) {
      console.log("Using default admin credentials for development (admin/admin)");
    }
    return { username, password };
  }

  // In production build phase, allow defaults temporarily
  if (isProduction && !isNodeRuntime) {
    return { username, password };
  }

  // Strict validation in production runtime
  if (isRuntimeProduction) {
    const errors: string[] = [];

    // Username validation - just ensure it's set
    if (!rawUsername || !username) {
      errors.push(
        "ADMIN_USERNAME must be set"
      );
    }

    // Password validation - strict requirements
    if (!rawPassword || password === DEFAULT_ADMIN_PASSWORD) {
      errors.push(
        "ADMIN_PASSWORD must be set to a custom value in production (not 'admin')"
      );
    } else if (DISALLOWED_ADMIN_PASSWORDS.has(password)) {
      errors.push(
        "ADMIN_PASSWORD is an example value from the documentation; choose your own password"
      );
    } else {
      if (password.length < MIN_ADMIN_PASSWORD_LENGTH) {
        errors.push(
          `ADMIN_PASSWORD must be at least ${MIN_ADMIN_PASSWORD_LENGTH} characters long`
        );
      }
      if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
        errors.push(
          "ADMIN_PASSWORD must include both uppercase and lowercase letters"
        );
      }
      if (!/[0-9]/.test(password)) {
        errors.push(
          "ADMIN_PASSWORD must include at least one number"
        );
      }
      if (!/[^A-Za-z0-9]/.test(password)) {
        errors.push(
          "ADMIN_PASSWORD must include at least one special character"
        );
      }
    }

    if (errors.length > 0) {
      throw new Error(
        "Admin credentials validation failed:\n" +
        errors.map(e => `  - ${e}`).join("\n") +
        "\n\nSet secure credentials using ADMIN_USERNAME and ADMIN_PASSWORD environment variables."
      );
    }
  }

  return { username, password };
}

// Lazy initialization to avoid executing during build time
let _adminCredentials: { username: string; password: string } | null = null;
let _sessionSecret: string | null = null;

function getAdminCredentials() {
  if (!_adminCredentials) {
    _adminCredentials = resolveAdminCredentials();
  }
  return _adminCredentials;
}

function getSessionSecret() {
  if (!_sessionSecret) {
    _sessionSecret = resolveSessionSecret();
  }
  return _sessionSecret;
}

/**
 * SESSION_SECRET_PREVIOUS: earlier session secrets (comma-separated) that may
 * still decrypt stored values after a rotation. They are never used to
 * encrypt. The whole value is also kept as one entry, in case a secret itself
 * contains a comma.
 */
function resolvePreviousSessionSecrets(): string[] {
  const raw = process.env.SESSION_SECRET_PREVIOUS?.trim();
  if (!raw) return [];
  const entries = [raw, ...raw.split(",").map((entry) => entry.trim())];
  return [...new Set(entries.filter(Boolean))];
}

export const config = {
  get sessionSecret() {
    return getSessionSecret();
  },
  /** Read on each access so tests can vary it. */
  get previousSessionSecrets(): string[] {
    return resolvePreviousSessionSecrets();
  },
  caddyApiUrl: process.env.CADDY_API_URL ?? DEFAULT_CADDY_URL,
  // When set, the Caddy admin API is reached over this unix socket instead of
  // a TCP port, so no admin API listens on a port that proxied traffic inside
  // the Caddy container could dial. caddyApiUrl is still used to derive the
  // Caddy service hostname (dashboard dial, managed certs). Empty → TCP.
  caddyAdminSocket: process.env.CADDY_ADMIN_SOCKET?.trim() || null,
  // Auto-recovery of the Caddy configuration on drift (restart/recreation).
  // Disable on instances that do not own the targeted Caddy (e.g. auxiliary
  // Ingressi instances sharing one Caddy in the e2e stack) — two enabled monitors
  // with different databases would endlessly fight over the configuration.
  caddyMonitorEnabled: process.env.CADDY_MONITOR_ENABLED !== "false",
  baseUrl: process.env.BASE_URL ?? "http://localhost:3000",
  get adminUsername() {
    return getAdminCredentials().username;
  },
  get adminPassword() {
    return getAdminCredentials().password;
  },
  auth: {
    allowSelfRegistration: process.env.AUTH_ALLOW_SELF_REGISTRATION === "true",
    // Separate from credential self-registration: gates whether an OAuth
    // sign-in may implicitly create a brand-new account. Defaults to closed.
    allowOauthRegistration: process.env.AUTH_ALLOW_OAUTH_REGISTRATION === "true",
    // When true, an OAuth IdP's profile claims may set a new user's role/status.
    // Defaults to false: role/status are forced to safe defaults regardless of
    // claims. Only enable if you control the IdP and want it to manage roles.
    allowOauthRoleFromClaims: process.env.AUTH_ALLOW_OAUTH_ROLE_FROM_CLAIMS === "true",
  },
  oauth: {
    enabled: process.env.OAUTH_ENABLED === "true",
    providerName: process.env.OAUTH_PROVIDER_NAME ?? "OAuth2",
    clientId: process.env.OAUTH_CLIENT_ID ?? null,
    clientSecret: process.env.OAUTH_CLIENT_SECRET ?? null,
    issuer: process.env.OAUTH_ISSUER ?? null,
    authorizationUrl: process.env.OAUTH_AUTHORIZATION_URL ?? null,
    tokenUrl: process.env.OAUTH_TOKEN_URL ?? null,
    userinfoUrl: process.env.OAUTH_USERINFO_URL ?? null,
    allowAutoLinking: process.env.OAUTH_ALLOW_AUTO_LINKING === "true",
  },
  forwardAuthInternalUrl: process.env.FORWARD_AUTH_INTERNAL_URL ?? null,
  /**
   * Non-default external ports (e.g. "8443") on which forward-auth protected
   * hosts are served. Redirect targets and callback origins on any other
   * non-default port are rejected, because Caddy matches hosts without regard
   * to the port. Read on each access so tests can vary it.
   */
  get forwardAuthAllowedPorts(): Set<string> {
    return new Set(
      (process.env.FORWARD_AUTH_ALLOWED_PORTS ?? "")
        .split(",")
        .map((port) => port.trim())
        .filter((port) => /^[1-9]\d{0,4}$/.test(port) && Number(port) <= 65535)
        .map((port) => String(Number(port)))
    );
  },
};

/**
 * Validates configuration at server startup in production.
 * Throws if production is running with insecure default values.
 * Safe to call during build - only validates when actually serving.
 */
export function validateProductionConfig() {
  if (isRuntimeProduction) {
    // Force validation by accessing the config values
    // This will throw if defaults are being used in production
    void config.sessionSecret;
    void config.adminUsername;
    void config.adminPassword;

    // An environment-configured slave cannot safely fall back to a short or
    // missing bearer credential. Validate this synchronously during startup.
    if (process.env.INSTANCE_MODE === "slave") {
      assertValidInstanceSyncToken(
        process.env.INSTANCE_SYNC_TOKEN,
        "INSTANCE_SYNC_TOKEN for slave mode"
      );
    }

    // A mistyped dashboard replica would silently drop out of the Caddy
    // configuration (src/lib/dashboard-upstreams.ts).
    assertValidDashboardUpstreams();
  }
}
