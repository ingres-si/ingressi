import { describe, expect, it } from "vitest";
import {
  DNS_PROVIDERS,
  buildDnsChallengeConfig,
  challengeOptionFields,
  decryptProviderCredentials,
  encryptProviderCredentials,
  getProviderDefinition,
  isValidDnsDuration,
  redactDnsProviderSettingsForApi,
  redactLegacyCloudflareSettingsForApi,
} from "@/src/lib/dns-providers";
import { isEncryptedSecret } from "@/src/lib/secret";

const NETCUP_CHALLENGE_DEFAULTS = { propagation_delay: "600s", propagation_timeout: "900s" };

describe("DNS provider registry", () => {
  it("redacts every credential value from API status metadata", () => {
    const status = redactDnsProviderSettingsForApi({
      providers: {
        acmedns: {
          username: "credential-username",
          password: "credential-password",
          server_url: "https://credential-host.invalid",
          empty_optional: "",
        },
      },
      default: "acmedns",
    });
    const serialized = JSON.stringify(status);

    expect(status).toEqual({
      providers: {
        acmedns: {
          configuredFields: ["password", "server_url", "username"],
        },
      },
      default: "acmedns",
    });
    expect(serialized).not.toContain("credential-username");
    expect(serialized).not.toContain("credential-password");
    expect(serialized).not.toContain("credential-host");
  });

  it("redacts the legacy Cloudflare API token while retaining identifiers", () => {
    const status = redactLegacyCloudflareSettingsForApi({
      apiToken: "legacy-token-sentinel",
      zoneId: "zone-id",
      accountId: "account-id",
    });

    expect(status).toEqual({
      hasApiToken: true,
      zoneId: "zone-id",
      accountId: "account-id",
    });
    expect(JSON.stringify(status)).not.toContain("legacy-token-sentinel");
  });

  it("registers Njalla with the Caddy module path and API token field", () => {
    const provider = getProviderDefinition("njalla");

    expect(provider).toMatchObject({
      name: "njalla",
      displayName: "Njalla",
      docsUrl: "https://github.com/caddy-dns/njalla",
      modulePath: "github.com/caddy-dns/njalla",
    });
    expect(provider?.fields).toEqual([
      {
        key: "api_token",
        label: "API Token",
        type: "password",
        required: true,
      },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("njalla");
  });

  it("encrypts, decrypts, and emits Njalla credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("njalla", {
      api_token: "njalla-token",
    });

    expect(isEncryptedSecret(encrypted.api_token)).toBe(true);
    expect(decryptProviderCredentials("njalla", encrypted)).toEqual({
      api_token: "njalla-token",
    });
    expect(buildDnsChallengeConfig("njalla", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "njalla",
        api_token: "njalla-token",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers Spaceship with the Caddy module path and API key/secret fields", () => {
    const provider = getProviderDefinition("spaceship");

    expect(provider).toMatchObject({
      name: "spaceship",
      displayName: "Spaceship",
      docsUrl: "https://github.com/caddy-dns/spaceship",
      modulePath: "github.com/caddy-dns/spaceship",
    });
    expect(provider?.fields).toEqual([
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "api_secret", label: "API Secret", type: "password", required: true },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("spaceship");
  });

  it("encrypts, decrypts, and emits Spaceship credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("spaceship", {
      api_key: "spaceship-key",
      api_secret: "spaceship-secret",
    });

    expect(isEncryptedSecret(encrypted.api_key)).toBe(true);
    expect(isEncryptedSecret(encrypted.api_secret)).toBe(true);
    expect(decryptProviderCredentials("spaceship", encrypted)).toEqual({
      api_key: "spaceship-key",
      api_secret: "spaceship-secret",
    });
    expect(buildDnsChallengeConfig("spaceship", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "spaceship",
        api_key: "spaceship-key",
        api_secret: "spaceship-secret",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers deSEC with the Caddy module path and API token field", () => {
    const provider = getProviderDefinition("desec");

    expect(provider).toMatchObject({
      name: "desec",
      displayName: "deSEC",
      docsUrl: "https://github.com/caddy-dns/desec",
      modulePath: "github.com/caddy-dns/desec",
    });
    expect(provider?.fields).toEqual([
      { key: "token", label: "API Token", type: "password", required: true },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("desec");
  });

  it("encrypts, decrypts, and emits deSEC credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("desec", {
      token: "desec-token",
    });

    expect(isEncryptedSecret(encrypted.token)).toBe(true);
    expect(decryptProviderCredentials("desec", encrypted)).toEqual({
      token: "desec-token",
    });
    expect(buildDnsChallengeConfig("desec", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "desec",
        token: "desec-token",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers Dynu with the Caddy module path and API token field", () => {
    const provider = getProviderDefinition("dynu");

    expect(provider).toMatchObject({
      name: "dynu",
      displayName: "Dynu",
      docsUrl: "https://github.com/caddy-dns/dynu",
      modulePath: "github.com/caddy-dns/dynu",
    });
    expect(provider?.fields).toEqual([
      { key: "api_token", label: "API Token", type: "password", required: true },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("dynu");
  });

  it("encrypts, decrypts, and emits Dynu credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("dynu", {
      api_token: "dynu-token",
    });

    expect(isEncryptedSecret(encrypted.api_token)).toBe(true);
    expect(decryptProviderCredentials("dynu", encrypted)).toEqual({
      api_token: "dynu-token",
    });
    expect(buildDnsChallengeConfig("dynu", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "dynu",
        api_token: "dynu-token",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers acme-dns with the Caddy module path and account fields", () => {
    const provider = getProviderDefinition("acmedns");

    expect(provider).toMatchObject({
      name: "acmedns",
      displayName: "acme-dns",
      docsUrl: "https://github.com/caddy-dns/acmedns",
      modulePath: "github.com/caddy-dns/acmedns",
    });
    expect(provider?.fields).toEqual([
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
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("acmedns");
  });

  it("encrypts, decrypts, and emits acme-dns credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("acmedns", {
      username: "acmedns-user",
      password: "acmedns-pass",
      subdomain: "acmedns-subdomain",
      server_url: "https://auth.acme-dns.io",
    });

    expect(isEncryptedSecret(encrypted.password)).toBe(true);
    expect(decryptProviderCredentials("acmedns", encrypted)).toEqual({
      username: "acmedns-user",
      password: "acmedns-pass",
      subdomain: "acmedns-subdomain",
      server_url: "https://auth.acme-dns.io",
    });
    expect(buildDnsChallengeConfig("acmedns", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "acmedns",
        username: "acmedns-user",
        password: "acmedns-pass",
        subdomain: "acmedns-subdomain",
        server_url: "https://auth.acme-dns.io",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers INWX with the Caddy module path and credential fields", () => {
    const provider = getProviderDefinition("inwx");

    expect(provider).toMatchObject({
      name: "inwx",
      displayName: "INWX",
      docsUrl: "https://github.com/caddy-dns/inwx",
      modulePath: "github.com/caddy-dns/inwx",
    });
    expect(provider?.fields).toEqual([
      { key: "username", label: "Username", type: "string", required: true },
      { key: "password", label: "Password", type: "password", required: true },
      { key: "shared_secret", label: "2FA Shared Secret", type: "password", required: false },
      { key: "endpoint_url", label: "Endpoint URL", type: "string", required: false },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("inwx");
  });

  it("registers Bunny with the Caddy module path and API access key field", () => {
    const provider = getProviderDefinition("bunny");

    expect(provider).toMatchObject({
      name: "bunny",
      displayName: "Bunny",
      docsUrl: "https://github.com/caddy-dns/bunny",
      modulePath: "github.com/caddy-dns/bunny",
    });
    expect(provider?.fields).toEqual([
      { key: "access_key", label: "API Access Key", type: "password", required: true },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("bunny");
  });

  it("encrypts, decrypts, and emits Bunny credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("bunny", { access_key: "bunny-key" });

    expect(isEncryptedSecret(encrypted.access_key)).toBe(true);
    expect(decryptProviderCredentials("bunny", encrypted)).toEqual({ access_key: "bunny-key" });
    expect(buildDnsChallengeConfig("bunny", encrypted, ["1.1.1.1"])).toEqual({
      provider: { name: "bunny", access_key: "bunny-key" },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers Infomaniak with the Caddy module path and API token field", () => {
    const provider = getProviderDefinition("infomaniak");

    expect(provider).toMatchObject({
      name: "infomaniak",
      displayName: "Infomaniak",
      docsUrl: "https://github.com/caddy-dns/infomaniak",
      modulePath: "github.com/caddy-dns/infomaniak",
    });
    expect(provider?.fields).toEqual([
      { key: "api_token", label: "API Token", type: "password", required: true },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("infomaniak");
  });

  it("encrypts, decrypts, and emits Infomaniak credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("infomaniak", {
      api_token: "infomaniak-token",
    });

    expect(isEncryptedSecret(encrypted.api_token)).toBe(true);
    expect(decryptProviderCredentials("infomaniak", encrypted)).toEqual({
      api_token: "infomaniak-token",
    });
    expect(buildDnsChallengeConfig("infomaniak", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "infomaniak",
        api_token: "infomaniak-token",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("registers netcup with the Caddy module path, customer/key/password fields, and slow-propagation defaults", () => {
    const provider = getProviderDefinition("netcup");

    expect(provider).toMatchObject({
      name: "netcup",
      displayName: "netcup",
      docsUrl: "https://github.com/caddy-dns/netcup",
      modulePath: "github.com/caddy-dns/netcup",
    });
    expect(provider?.fields).toEqual([
      { key: "customer_number", label: "Customer Number", type: "string", required: true },
      { key: "api_key", label: "API Key", type: "password", required: true },
      { key: "api_password", label: "API Password", type: "password", required: true },
      ...challengeOptionFields(NETCUP_CHALLENGE_DEFAULTS),
    ]);
    expect(provider?.challengeDefaults).toEqual(NETCUP_CHALLENGE_DEFAULTS);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("netcup");
  });

  it("encrypts, decrypts, and emits netcup credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("netcup", {
      customer_number: "123456",
      api_key: "netcup-key",
      api_password: "netcup-password",
    });

    expect(isEncryptedSecret(encrypted.api_key)).toBe(true);
    expect(isEncryptedSecret(encrypted.api_password)).toBe(true);
    expect(isEncryptedSecret(encrypted.customer_number)).toBe(false);
    expect(decryptProviderCredentials("netcup", encrypted)).toEqual({
      customer_number: "123456",
      api_key: "netcup-key",
      api_password: "netcup-password",
    });
    expect(buildDnsChallengeConfig("netcup", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "netcup",
        customer_number: "123456",
        api_key: "netcup-key",
        api_password: "netcup-password",
      },
      resolvers: ["1.1.1.1"],
      propagation_delay: "600s",
      propagation_timeout: "900s",
    });
  });

  it("registers ClouDNS with the Caddy module path and auth-id/sub-user/password fields", () => {
    const provider = getProviderDefinition("cloudns");

    expect(provider).toMatchObject({
      name: "cloudns",
      displayName: "ClouDNS",
      docsUrl: "https://github.com/caddy-dns/cloudns",
      modulePath: "github.com/caddy-dns/cloudns",
    });
    expect(provider?.fields).toEqual([
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
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("cloudns");
  });

  it("encrypts, decrypts, and emits ClouDNS credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("cloudns", {
      auth_id: "1234",
      auth_password: "cloudns-password",
    });

    expect(isEncryptedSecret(encrypted.auth_password)).toBe(true);
    expect(isEncryptedSecret(encrypted.auth_id)).toBe(false);
    expect(decryptProviderCredentials("cloudns", encrypted)).toEqual({
      auth_id: "1234",
      auth_password: "cloudns-password",
    });
    expect(buildDnsChallengeConfig("cloudns", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "cloudns",
        auth_id: "1234",
        auth_password: "cloudns-password",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("emits ClouDNS sub-user credentials when no API user ID is configured", () => {
    const encrypted = encryptProviderCredentials("cloudns", {
      sub_auth_id: "5678",
      auth_password: "cloudns-password",
    });

    expect(buildDnsChallengeConfig("cloudns", encrypted, [])).toEqual({
      provider: {
        name: "cloudns",
        sub_auth_id: "5678",
        auth_password: "cloudns-password",
      },
    });
  });

  it("registers RFC2136 with the Caddy module path and TSIG credential fields", () => {
    const provider = getProviderDefinition("rfc2136");

    expect(provider).toMatchObject({
      name: "rfc2136",
      displayName: "RFC2136 (BIND / TSIG)",
      docsUrl: "https://github.com/caddy-dns/rfc2136",
      modulePath: "github.com/caddy-dns/rfc2136",
    });
    expect(provider?.fields).toEqual([
      { key: "key_name", label: "TSIG Key Name", type: "string", required: true, placeholder: "my-transfer-key", description: "Name of the TSIG key as defined on the DNS server (miND/domain form accepted)." },
      { key: "key_alg", label: "TSIG Algorithm", type: "string", required: true, placeholder: "hmac-sha256", description: "HMAC algorithm of the TSIG key, e.g. hmac-sha256, hmac-sha512, or hmac-md5." },
      { key: "key", label: "TSIG Key Secret", type: "password", required: true, placeholder: "base64 secret", description: "The base64-encoded TSIG shared secret (from the key statement or `tsig-keygen`)." },
      { key: "server", label: "DNS Server", type: "string", required: true, placeholder: "1.2.3.4:53", description: "Authoritative DNS server address that accepts RFC 2136 dynamic updates (host:port)." },
      ...challengeOptionFields(),
    ]);
    expect(DNS_PROVIDERS.map((p) => p.name)).toContain("rfc2136");
  });

  it("encrypts, decrypts, and emits RFC2136 credentials for Caddy DNS challenges", () => {
    const encrypted = encryptProviderCredentials("rfc2136", {
      key_name: "transfer-key",
      key_alg: "hmac-sha256",
      key: "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4=",
      server: "1.2.3.4:53",
    });

    expect(isEncryptedSecret(encrypted.key)).toBe(true);
    expect(isEncryptedSecret(encrypted.key_name)).toBe(false);
    expect(isEncryptedSecret(encrypted.key_alg)).toBe(false);
    expect(isEncryptedSecret(encrypted.server)).toBe(false);
    expect(decryptProviderCredentials("rfc2136", encrypted)).toEqual({
      key_name: "transfer-key",
      key_alg: "hmac-sha256",
      key: "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4=",
      server: "1.2.3.4:53",
    });
    expect(buildDnsChallengeConfig("rfc2136", encrypted, ["1.1.1.1"])).toEqual({
      provider: {
        name: "rfc2136",
        key_name: "transfer-key",
        key_alg: "hmac-sha256",
        key: "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4=",
        server: "1.2.3.4:53",
      },
      resolvers: ["1.1.1.1"],
    });
  });

  it("applies netcup propagation defaults and keeps them out of the provider module config", () => {
    const challenge = buildDnsChallengeConfig(
      "netcup",
      { customer_number: "123456", api_key: "netcup-key", api_password: "netcup-password" },
      []
    );

    expect(challenge).toEqual({
      provider: {
        name: "netcup",
        customer_number: "123456",
        api_key: "netcup-key",
        api_password: "netcup-password",
      },
      propagation_delay: "600s",
      propagation_timeout: "900s",
    });
  });

  it("lets stored propagation settings override the provider defaults", () => {
    const challenge = buildDnsChallengeConfig(
      "netcup",
      { propagation_delay: "300s", propagation_timeout: "-1" },
      []
    );

    expect(challenge).toMatchObject({
      propagation_delay: "300s",
      // "-1" (disable propagation checks) is emitted as a Caddy duration number
      propagation_timeout: -1,
    });
  });

  it("emits propagation settings for providers without registered defaults", () => {
    const challenge = buildDnsChallengeConfig(
      "njalla",
      { api_token: "njalla-token", propagation_delay: "120s", propagation_timeout: "15m" },
      ["1.1.1.1"]
    );

    expect(challenge).toEqual({
      provider: { name: "njalla", api_token: "njalla-token" },
      resolvers: ["1.1.1.1"],
      propagation_delay: "120s",
      propagation_timeout: "15m",
    });
  });

  it("validates Caddy duration strings for the challenge option fields", () => {
    expect(isValidDnsDuration("600s")).toBe(true);
    expect(isValidDnsDuration("2m")).toBe(true);
    expect(isValidDnsDuration("1h30m")).toBe(true);
    expect(isValidDnsDuration("1.5h")).toBe(true);
    expect(isValidDnsDuration("2d")).toBe(true);
    expect(isValidDnsDuration("-1")).toBe(true);
    expect(isValidDnsDuration("")).toBe(false);
    expect(isValidDnsDuration("600")).toBe(false);
    expect(isValidDnsDuration("900 sec")).toBe(false);
    expect(isValidDnsDuration("soon")).toBe(false);
  });
});
