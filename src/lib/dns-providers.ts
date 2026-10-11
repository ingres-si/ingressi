import { encryptSecret, decryptSecret, isEncryptedSecret } from "./secret";

// ─── Types ───────────────────────────────────────────────────────────────────

export type DnsProviderFieldType = "string" | "password" | "duration";

export type DnsProviderField = {
  /** Key sent to Caddy config (e.g. "api_token") */
  key: string;
  /** Human-readable label */
  label: string;
  /** "password" fields are encrypted at rest; "duration" fields are validated as Caddy durations */
  type: DnsProviderFieldType;
  /** Placeholder text for the input */
  placeholder?: string;
  /** Help text shown below the input */
  description?: string;
  /** Whether the field is required */
  required: boolean;
};

export type DnsProviderDefinition = {
  /** Caddy DNS module name (e.g. "cloudflare", "route53") */
  name: string;
  /** Human-readable display name */
  displayName: string;
  /** Short description */
  description?: string;
  /** Link to caddy-dns module docs */
  docsUrl?: string;
  /** Credential fields this provider requires */
  fields: DnsProviderField[];
  /** caddy-dns Go module path (for Dockerfile reference) */
  modulePath: string;
  /**
   * Sensible DNS-challenge tuning defaults for this provider, applied when
   * the corresponding option field is left empty. Values are Caddy durations
   * (e.g. "600s", "10m").
   */
  challengeDefaults?: DnsProviderChallengeDefaults;
};

/**
 * DNS-challenge tuning defaults for slow-propagation providers. Keys map to
 * the Caddy `challenges.dns` JSON fields of the same name.
 */
export type DnsProviderChallengeDefaults = {
  propagation_delay?: string;
  propagation_timeout?: string;
};

export type DnsProviderCredentials = {
  provider: string;
  credentials: Record<string, string>;
};

/**
 * Safe representation returned by the REST settings endpoint. Credential
 * names are useful for showing which optional fields are configured, but the
 * values themselves must remain write-only.
 */
export type DnsProviderApiStatus = {
  providers: Record<string, { configuredFields: string[] }>;
  default: string | null;
};

export type LegacyCloudflareApiStatus = {
  hasApiToken: boolean;
  zoneId?: string;
  accountId?: string;
};

// ─── Registry ────────────────────────────────────────────────────────────────

/** Keys that tune the DNS challenge itself rather than the provider module. */
const CHALLENGE_OPTION_KEYS = ["propagation_delay", "propagation_timeout"] as const;

/**
 * Optional DNS-challenge tuning fields appended to every provider so that
 * slow-propagation DNS services can be worked around without editing the
 * Caddy config by hand. `defaults` pre-selects sensible values and is
 * reflected in the placeholder/help text shown in the settings UI.
 */
export function challengeOptionFields(
  defaults?: DnsProviderChallengeDefaults
): DnsProviderField[] {
  return [
    {
      key: "propagation_delay",
      label: "Propagation Delay",
      type: "duration",
      required: false,
      placeholder: defaults?.propagation_delay ?? "e.g. 60s",
      description:
        "How long to wait before starting the DNS propagation checks, e.g. 60s or 5m." +
        (defaults?.propagation_delay
          ? ` Defaults to ${defaults.propagation_delay} for this provider.`
          : ""),
    },
    {
      key: "propagation_timeout",
      label: "Propagation Timeout",
      type: "duration",
      required: false,
      placeholder: defaults?.propagation_timeout ?? "e.g. 2m",
      description:
        "Maximum time to wait for the challenge TXT record to propagate, e.g. 2m or 15m. Use -1 to disable the propagation check." +
        (defaults?.propagation_timeout
          ? ` Defaults to ${defaults.propagation_timeout} for this provider.`
          : ""),
    },
  ];
}

const BASE_DNS_PROVIDERS: DnsProviderDefinition[] = [
  {
    name: "cloudflare",
    displayName: "Cloudflare",
    description: "Cloudflare DNS API",
    docsUrl: "https://github.com/caddy-dns/cloudflare",
    modulePath: "github.com/caddy-dns/cloudflare",
    fields: [
      {
        key: "api_token",
        label: "API Token",
        type: "password",
        required: true,
        placeholder: "Cloudflare API token with Zone:DNS:Edit permission",
      },
    ],
  },
  {
    name: "route53",
    displayName: "Amazon Route 53",
    description: "AWS Route 53 DNS API (supports IAM roles when fields are empty)",
    docsUrl: "https://github.com/caddy-dns/route53",
    modulePath: "github.com/caddy-dns/route53",
    fields: [
      { key: "access_key_id", label: "Access Key ID", type: "string", required: false, placeholder: "AKIA..." },
      { key: "secret_access_key", label: "Secret Access Key", type: "password", required: false },
      { key: "region", label: "AWS Region", type: "string", required: false, placeholder: "us-east-1" },
      {
        key: "hosted_zone_id",
        label: "Hosted Zone ID",
        type: "string",
        required: false,
        placeholder: "Z1234567890",
        description: "Optional. Required only if you have multiple zones for the same domain.",
      },
    ],
  },
  {
    name: "digitalocean",
    displayName: "DigitalOcean",
    description: "DigitalOcean DNS API",
    docsUrl: "https://github.com/caddy-dns/digitalocean",
    modulePath: "github.com/caddy-dns/digitalocean",
    fields: [
      { key: "api_token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "duckdns",
    displayName: "Duck DNS",
    description: "Duck DNS dynamic DNS service",
    docsUrl: "https://github.com/caddy-dns/duckdns",
    modulePath: "github.com/caddy-dns/duckdns",
    fields: [
      { key: "api_token", label: "Token", type: "password", required: true },
    ],
  },
  {
    name: "hetzner",
    displayName: "Hetzner",
    description: "Hetzner DNS API",
    docsUrl: "https://github.com/caddy-dns/hetzner",
    modulePath: "github.com/caddy-dns/hetzner",
    fields: [
      { key: "api_token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "inwx",
    displayName: "INWX",
    description: "INWX DNS API",
    docsUrl: "https://github.com/caddy-dns/inwx",
    modulePath: "github.com/caddy-dns/inwx",
    fields: [
      { key: "username", label: "Username", type: "string", required: true },
      { key: "password", label: "Password", type: "password", required: true },
      { key: "shared_secret", label: "2FA Shared Secret", type: "password", required: false },
      { key: "endpoint_url", label: "Endpoint URL", type: "string", required: false },
    ],
  },
  {
    name: "vultr",
    displayName: "Vultr",
    description: "Vultr DNS API",
    docsUrl: "https://github.com/caddy-dns/vultr",
    modulePath: "github.com/caddy-dns/vultr",
    fields: [
      { key: "api_token", label: "API Key", type: "password", required: true },
    ],
  },
  {
    name: "porkbun",
    displayName: "Porkbun",
    description: "Porkbun DNS API",
    docsUrl: "https://github.com/caddy-dns/porkbun",
    modulePath: "github.com/caddy-dns/porkbun",
    fields: [
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "api_secret_key", label: "API Secret Key", type: "password", required: true },
    ],
  },
  {
    name: "godaddy",
    displayName: "GoDaddy",
    description: "GoDaddy DNS API",
    docsUrl: "https://github.com/caddy-dns/godaddy",
    modulePath: "github.com/caddy-dns/godaddy",
    fields: [
      {
        key: "api_token",
        label: "API Key:Secret",
        type: "password",
        required: true,
        placeholder: "key:secret",
        description: "Format: API_KEY:API_SECRET",
      },
    ],
  },
  {
    name: "namecheap",
    displayName: "Namecheap",
    description: "Namecheap DNS API",
    docsUrl: "https://github.com/caddy-dns/namecheap",
    modulePath: "github.com/caddy-dns/namecheap",
    fields: [
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "user", label: "Username", type: "string", required: true },
    ],
  },
  {
    name: "ovh",
    displayName: "OVH",
    description: "OVH DNS API",
    docsUrl: "https://github.com/caddy-dns/ovh",
    modulePath: "github.com/caddy-dns/ovh",
    fields: [
      { key: "endpoint", label: "Endpoint", type: "string", required: true, placeholder: "ovh-eu" },
      { key: "application_key", label: "Application Key", type: "string", required: true },
      { key: "application_secret", label: "Application Secret", type: "password", required: true },
      { key: "consumer_key", label: "Consumer Key", type: "password", required: true },
    ],
  },
  {
    name: "ionos",
    displayName: "IONOS",
    description: "IONOS DNS API",
    docsUrl: "https://github.com/caddy-dns/ionos",
    modulePath: "github.com/caddy-dns/ionos",
    fields: [
      { key: "auth_api_token", label: "API Token", type: "password", required: true, placeholder: "prefix.secret" },
    ],
  },
  {
    name: "linode",
    displayName: "Linode (Akamai)",
    description: "Linode/Akamai DNS API",
    docsUrl: "https://github.com/caddy-dns/linode",
    modulePath: "github.com/caddy-dns/linode",
    fields: [
      { key: "api_token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "njalla",
    displayName: "Njalla",
    description: "Njalla DNS API",
    docsUrl: "https://github.com/caddy-dns/njalla",
    modulePath: "github.com/caddy-dns/njalla",
    fields: [
      { key: "api_token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "spaceship",
    displayName: "Spaceship",
    description: "Spaceship DNS API",
    docsUrl: "https://github.com/caddy-dns/spaceship",
    modulePath: "github.com/caddy-dns/spaceship",
    fields: [
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "api_secret", label: "API Secret", type: "password", required: true },
    ],
  },
  {
    name: "desec",
    displayName: "deSEC",
    description: "deSEC DNS API",
    docsUrl: "https://github.com/caddy-dns/desec",
    modulePath: "github.com/caddy-dns/desec",
    fields: [
      { key: "token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "bunny",
    displayName: "Bunny",
    description: "Bunny DNS API",
    docsUrl: "https://github.com/caddy-dns/bunny",
    modulePath: "github.com/caddy-dns/bunny",
    fields: [
      { key: "access_key", label: "API Access Key", type: "password", required: true },
    ],
  },
  {
    name: "dynu",
    displayName: "Dynu",
    description: "Dynu DNS API",
    docsUrl: "https://github.com/caddy-dns/dynu",
    modulePath: "github.com/caddy-dns/dynu",
    fields: [
      { key: "api_token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "acmedns",
    displayName: "acme-dns",
    description: "acme-dns delegated DNS-01 validation (dedicated ACME challenge records only)",
    docsUrl: "https://github.com/caddy-dns/acmedns",
    modulePath: "github.com/caddy-dns/acmedns",
    fields: [
      { key: "username", label: "Username", type: "string", required: true },
      { key: "password", label: "Password", type: "password", required: true },
      { key: "subdomain", label: "Subdomain", type: "string", required: true },
      {
        key: "server_url",
        label: "Server URL",
        type: "string",
        required: true,
        placeholder: "https://auth.acme-dns.io",
      },
    ],
  },
  {
    name: "infomaniak",
    displayName: "Infomaniak",
    description: "Infomaniak DNS API",
    docsUrl: "https://github.com/caddy-dns/infomaniak",
    modulePath: "github.com/caddy-dns/infomaniak",
    fields: [
      { key: "api_token", label: "API Token", type: "password", required: true },
    ],
  },
  {
    name: "netcup",
    displayName: "netcup",
    description: "netcup CCP DNS API",
    docsUrl: "https://github.com/caddy-dns/netcup",
    modulePath: "github.com/caddy-dns/netcup",
    fields: [
      { key: "customer_number", label: "Customer Number", type: "string", required: true },
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "api_password", label: "API Password", type: "password", required: true },
    ],
    // netcup's DNS propagation is notoriously slow (see
    // https://github.com/caddy-dns/netcup#attention-slow-netcup-propagation-time),
    // so default to generous challenge timings. Users can override both.
    challengeDefaults: { propagation_delay: "600s", propagation_timeout: "900s" },
  },
  {
    name: "cloudns",
    displayName: "ClouDNS",
    description: "ClouDNS DNS API",
    docsUrl: "https://github.com/caddy-dns/cloudns",
    modulePath: "github.com/caddy-dns/cloudns",
    fields: [
      {
        key: "auth_id",
        label: "Auth ID",
        type: "string",
        required: false,
        placeholder: "1234",
        description: "API user ID (created under API & Resellers). Required unless a sub-user ID is provided.",
      },
      {
        key: "sub_auth_id",
        label: "Sub-user ID",
        type: "string",
        required: false,
        description: "API sub-user ID. Required unless an API user ID is provided.",
      },
      {
        key: "auth_password",
        label: "API Password",
        type: "password",
        required: true,
        description: "Password of the API user or sub-user.",
      },
    ],
  },
  {
    name: "rfc2136",
    displayName: "RFC2136 (BIND / TSIG)",
    description: "RFC 2136 Dynamic DNS updates via a TSIG key (BIND9 and compatible servers)",
    docsUrl: "https://github.com/caddy-dns/rfc2136",
    modulePath: "github.com/caddy-dns/rfc2136",
    fields: [
      {
        key: "key_name",
        label: "TSIG Key Name",
        type: "string",
        required: true,
        placeholder: "my-transfer-key",
        description: "Name of the TSIG key as defined on the DNS server (miND/domain form accepted).",
      },
      {
        key: "key_alg",
        label: "TSIG Algorithm",
        type: "string",
        required: true,
        placeholder: "hmac-sha256",
        description: "HMAC algorithm of the TSIG key, e.g. hmac-sha256, hmac-sha512, or hmac-md5.",
      },
      {
        key: "key",
        label: "TSIG Key Secret",
        type: "password",
        required: true,
        placeholder: "base64 secret",
        description: "The base64-encoded TSIG shared secret (from the key statement or `tsig-keygen`).",
      },
      {
        key: "server",
        label: "DNS Server",
        type: "string",
        required: true,
        placeholder: "1.2.3.4:53",
        description: "Authoritative DNS server address that accepts RFC 2136 dynamic updates (host:port).",
      },
    ],
  },
];

/**
 * Full provider registry. The challenge option fields (propagation delay and
 * timeout) are appended to every provider so slow-DNS workarounds are always
 * available, with per-provider defaults where they are known to help.
 */
export const DNS_PROVIDERS: DnsProviderDefinition[] = BASE_DNS_PROVIDERS.map((provider) => ({
  ...provider,
  fields: [...provider.fields, ...challengeOptionFields(provider.challengeDefaults)],
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Caddy durations follow Go duration syntax (ns/us/µs/ms/s/m/h compounds,
// plus "d" for days, handled by caddy.ParseDuration). Validation stays
// permissive about unit ordering; Caddy reports anything exotic at load time.
const DURATION_SEGMENT = String.raw`(?:\d+(?:\.\d+)?|\.\d+)(?:ns|us|µs|μs|ms|s|m|h|d)`;
const DURATION_PATTERN = new RegExp(`^-1$|^[+-]?(?:${DURATION_SEGMENT})+$`);

/**
 * Validate a Caddy duration string as accepted by the DNS challenge settings
 * ("600s", "2m", "1h30m", ...). The special value "-1" (disable propagation
 * checks) is also accepted. Unit-less numbers are rejected because Caddy
 * would silently interpret them as nanoseconds.
 */
export function isValidDnsDuration(value: string): boolean {
  return DURATION_PATTERN.test(value);
}

export function getProviderDefinition(name: string): DnsProviderDefinition | undefined {
  return DNS_PROVIDERS.find((p) => p.name === name);
}

/**
 * Reduce DNS-provider settings to non-secret metadata before crossing an API
 * response boundary. This intentionally redacts every value, including fields
 * whose registry type is not `password`, so newly-added credential fields are
 * safe by default.
 */
export function redactDnsProviderSettingsForApi(settings: {
  providers: Record<string, Record<string, string>>;
  default: string | null;
}): DnsProviderApiStatus {
  return {
    providers: Object.fromEntries(
      Object.entries(settings.providers).map(([provider, credentials]) => [
        provider,
        {
          configuredFields: Object.entries(credentials)
            .filter(([, value]) => typeof value === "string" && value.length > 0)
            .map(([key]) => key)
            .sort(),
        },
      ])
    ),
    default: settings.default,
  };
}

/** Redact the credential from the legacy single-provider settings group. */
export function redactLegacyCloudflareSettingsForApi(settings: {
  apiToken: string;
  zoneId?: string;
  accountId?: string;
}): LegacyCloudflareApiStatus {
  return {
    hasApiToken: settings.apiToken.length > 0,
    ...(settings.zoneId ? { zoneId: settings.zoneId } : {}),
    ...(settings.accountId ? { accountId: settings.accountId } : {}),
  };
}

/**
 * Encrypt password-type credential fields for storage.
 * Non-password fields, non-string values and already-encrypted values are
 * left unchanged.
 */
export function encryptProviderCredentials(
  providerName: string,
  credentials: Record<string, string>
): Record<string, string> {
  const def = getProviderDefinition(providerName);
  if (!def) return credentials;

  const result = { ...credentials };
  for (const field of def.fields) {
    const value: unknown = result[field.key];
    if (field.type === "password" && typeof value === "string" && value && !isEncryptedSecret(value)) {
      result[field.key] = encryptSecret(value);
    }
  }
  return result;
}

/**
 * Encrypt the password fields of a whole dns_provider setting value, in the
 * multi-provider format ({ providers, default }) and in the single-provider
 * format of older releases ({ provider, credentials }). Anything else is
 * returned unchanged.
 */
export function encryptDnsProviderSettingCredentials(value: unknown): unknown {
  if (!isJsonObject(value)) return value;
  // Credential maps are typed as string maps; encryptProviderCredentials
  // leaves non-string values alone.
  if (isJsonObject(value.providers)) {
    return {
      ...value,
      providers: Object.fromEntries(
        Object.entries(value.providers).map(([provider, credentials]) => [
          provider,
          isJsonObject(credentials)
            ? encryptProviderCredentials(provider, credentials as Record<string, string>)
            : credentials,
        ])
      ),
    };
  }
  if (typeof value.provider === "string" && isJsonObject(value.credentials)) {
    return {
      ...value,
      credentials: encryptProviderCredentials(value.provider, value.credentials as Record<string, string>),
    };
  }
  return value;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decrypt credentials for use in Caddy config. Every encrypted value is
 * decrypted, not only the fields this release's registry marks as password:
 * a master on another release may have encrypted a field this registry does
 * not know (a renamed field or a newer provider), and a slave stores synced
 * values encrypted exactly where the master had them encrypted.
 */
export function decryptProviderCredentials(
  providerName: string,
  credentials: Record<string, string>
): Record<string, string> {
  const result = { ...credentials };
  for (const [key, value] of Object.entries(result)) {
    if (typeof value === "string" && isEncryptedSecret(value)) {
      result[key] = decryptSecret(value, `DNS provider "${providerName}" credential "${key}"`);
    }
  }
  return result;
}

/**
 * Build the Caddy DNS challenge provider config from a provider name + credentials.
 * Returns the object to set as `issuer.challenges.dns`.
 *
 * Besides the provider module credentials, the optional challenge option
 * fields (propagation_delay / propagation_timeout) are hoisted out of the
 * credential map onto the challenge level, falling back to the provider's
 * registered defaults. `resolvers` comes from the global DNS resolver
 * settings and is passed in separately.
 */
export function buildDnsChallengeConfig(
  providerName: string,
  credentials: Record<string, string>,
  dnsResolvers: string[]
): Record<string, unknown> | null {
  const def = getProviderDefinition(providerName);
  if (!def) return null;

  const decrypted = decryptProviderCredentials(providerName, credentials);

  // Build provider config: { name: "cloudflare", api_token: "..." }.
  // Challenge option keys configure the DNS challenge itself, not the
  // provider module, so they are emitted at the challenge level below.
  const providerConfig: Record<string, string> = { name: providerName };
  for (const [key, value] of Object.entries(decrypted)) {
    if (value && !(CHALLENGE_OPTION_KEYS as readonly string[]).includes(key)) {
      providerConfig[key] = value;
    }
  }

  const dnsChallenge: Record<string, unknown> = { provider: providerConfig };
  if (dnsResolvers.length > 0) {
    dnsChallenge.resolvers = dnsResolvers;
  }

  // Challenge tuning: a stored option value wins over the provider default.
  // The "-1" disable value is emitted as a number because Caddy parses
  // duration strings with time.ParseDuration, which rejects a bare "-1".
  for (const key of CHALLENGE_OPTION_KEYS) {
    const value = decrypted[key] || def.challengeDefaults?.[key];
    if (value) {
      dnsChallenge[key] = value === "-1" ? -1 : value;
    }
  }

  return dnsChallenge;
}
