import { describe, expect, it } from "vitest";
import {
  SettingsValidationError,
  validateSettingsGroup,
} from "@/src/lib/settings-validation";

const geoblock = {
  enabled: true,
  block_countries: ["CN"],
  block_continents: [],
  block_asns: [],
  block_cidrs: ["10.0.0.0/8"],
  block_ips: [],
  allow_countries: ["FI"],
  allow_continents: ["EU"],
  allow_asns: [64512],
  allow_cidrs: [],
  allow_ips: ["192.0.2.1"],
  trusted_proxies: ["private_ranges"],
  fail_closed: false,
  response_status: 403,
  response_body: "Forbidden",
  response_headers: { "Content-Type": "text/plain" },
  redirect_url: "",
};

const validGroups: Record<string, Record<string, unknown>> = {
  general: { primaryDomain: "example.com", acmeEmail: "admin@example.com" },
  acme: { caUrl: "https://ca.example.com/acme/directory" },
  cloudflare: { apiToken: "secret", zoneId: "zone" },
  authentik: { outpostDomain: "auth.example.com", outpostUpstream: "http://authentik:9000" },
  metrics: { enabled: true, port: 9090 },
  logging: { enabled: true, format: "json" },
  dns: { enabled: true, resolvers: ["1.1.1.1"], fallbacks: [], timeout: "5s" },
  "dns-provider": {
    providers: { cloudflare: { api_token: "secret" } },
    default: "cloudflare",
  },
  "upstream-dns": { enabled: true, family: "both" },
  geoblock,
  waf: {
    enabled: true,
    mode: "On",
    load_owasp_crs: true,
    custom_directives: "",
    excluded_rule_ids: [920350],
  },
  "error-pages": {
    rules: [{ statuses: [502, 503], body: "Unavailable", contentType: "text/plain" }],
  },
  "default-response": { mode: "respond", status: 404, body: "Not found" },
  "trusted-proxies": {
    ranges: ["private_ranges", "192.0.2.0/24"],
    client_ip_headers: ["CF-Connecting-IP"],
    strict: true,
  },
};

describe("REST settings runtime validation", () => {
  for (const [group, input] of Object.entries(validGroups)) {
    it(`accepts the documented ${group} shape`, () => {
      expect(validateSettingsGroup(group, input)).toBe(input);
    });

    it(`rejects unknown fields for ${group}`, () => {
      expect(() => validateSettingsGroup(group, { ...input, unexpected: true }))
        .toThrow(SettingsValidationError);
    });
  }

  it("rejects type confusion and out-of-range values", () => {
    expect(() => validateSettingsGroup("metrics", { enabled: "yes", port: 70000 })).toThrow(/boolean/);
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      mode: "On\nSecRuleEngine Off",
    })).toThrow(/waf\.mode/);
    expect(() => validateSettingsGroup("geoblock", {
      ...geoblock,
      trusted_proxies: ["not-a-network"],
    })).toThrow(/IP address or CIDR/);
  });

  // Coraza rejects a body limit above 1 GiB while Caddy loads the config, which
  // takes down the whole document — so it has to fail at save time, with a
  // message that says which value is wrong.
  it("rejects WAF body limits Coraza would refuse", () => {
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      request_body_limit: 10737418240,
    })).toThrow(/waf\.request_body_limit must be an integer between/);
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      request_body_limit: 1048576,
      request_body_in_memory_limit: 2097152,
    })).toThrow(/must not exceed/);
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      request_body_limit_action: "Drop",
    })).toThrow(/Reject or ProcessPartial/);
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      custom_directives: "SecRequestBodyLimit 10737418240",
    })).toThrow(/out-of-range body limit/);
  });

  it("accepts WAF body limits inside Coraza's range", () => {
    const input = {
      ...validGroups.waf,
      request_body_limit: 1073741824,
      request_body_in_memory_limit: 1048576,
      request_body_limit_action: "ProcessPartial",
    };
    expect(validateSettingsGroup("waf", input)).toBe(input);
  });

  // Discussion #146: users reported a custom SecRuleUpdateActionById being
  // silently ignored. Unlike a plain SecRule (which is allowed and works),
  // the rule-mutation directive is dropped by the allowlist — so it must be
  // reported at save time, not fail silently.
  it("rejects custom WAF directives the allowlist will drop", () => {
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      custom_directives: 'SecRuleUpdateActionById 930130 "block"',
    })).toThrow(/will be dropped and never sent to Caddy/);
    expect(() => validateSettingsGroup("waf", {
      ...validGroups.waf,
      custom_directives: 'Include @owasp_crs/*.conf',
    })).toThrow(/will be dropped and never sent to Caddy/);
  });

  it("only rejects WAF directive lines an update newly drops", () => {
    const legacy = 'SecRule ARGS "@pmFromFile /etc/hosts" "id:1,deny"';
    const previousWaf = { custom_directives: legacy, load_owasp_crs: true };
    expect(() => validateSettingsGroup("waf", { ...validGroups.waf, custom_directives: legacy })).toThrow(/will be dropped/);
    expect(() => validateSettingsGroup(
      "waf",
      { ...validGroups.waf, mode: "DetectionOnly", custom_directives: legacy },
      { previousWaf }
    )).not.toThrow();
    expect(() => validateSettingsGroup(
      "waf",
      { ...validGroups.waf, custom_directives: `${legacy}\nSecRuleUpdateActionById 930130 "block"` },
      { previousWaf }
    )).toThrow(/SecRuleUpdateActionById/);
  });

  it("accepts custom WAF directives the allowlist permits", () => {
    const input = {
      ...validGroups.waf,
      custom_directives: 'SecRule REQUEST_URI "@contains /admin" "id:1001,phase:1,deny,status:403,log"',
    };
    expect(validateSettingsGroup("waf", input)).toBe(input);
  });

  it("rejects unsupported DNS providers and credential keys", () => {
    expect(() => validateSettingsGroup("dns-provider", {
      providers: { malicious: { command: "run" } },
      default: "malicious",
    })).toThrow(/Unsupported DNS provider/);
    expect(() => validateSettingsGroup("dns-provider", {
      providers: { cloudflare: { api_token: "secret", injected: "value" } },
      default: "cloudflare",
    })).toThrow(/unknown field/);
  });

  it("validates DNS challenge duration option fields", () => {
    const settings = (propagation: Record<string, unknown>) => ({
      providers: {
        netcup: {
          customer_number: "123456",
          api_key: "secret",
          api_password: "secret",
          ...propagation,
        },
      },
      default: "netcup",
    });

    expect(() => validateSettingsGroup("dns-provider", settings({ propagation_delay: "600s", propagation_timeout: "900s" })))
      .not.toThrow();
    expect(() => validateSettingsGroup("dns-provider", settings({ propagation_timeout: "-1" })))
      .not.toThrow();
    expect(() => validateSettingsGroup("dns-provider", settings({ propagation_delay: "600" })))
      .toThrow(/propagation_delay must be a duration/);
    expect(() => validateSettingsGroup("dns-provider", settings({ propagation_timeout: "soon" })))
      .toThrow(/propagation_timeout must be a duration/);
  });

  it("caps total payload size", () => {
    expect(() => validateSettingsGroup("acme", { caRootPem: "x".repeat(1024 * 1024 + 1) }))
      .toThrow(/must not exceed/);
  });

  it("accepts empty optional email and multiline ACME root PEM values", () => {
    expect(validateSettingsGroup("general", {
      primaryDomain: "example.com",
      acmeEmail: "",
    })).toEqual({ primaryDomain: "example.com", acmeEmail: "" });

    const caRootPem = "-----BEGIN CERTIFICATE-----\r\nMIIB\n-----END CERTIFICATE-----\n";
    expect(validateSettingsGroup("acme", { caRootPem })).toEqual({ caRootPem });
  });

  it("validates the ACME e-mail address", () => {
    for (const acmeEmail of ["admin@example.com", "first.last+tag@mail.example.co.uk"]) {
      expect(validateSettingsGroup("general", { primaryDomain: "example.com", acmeEmail })).toEqual({ primaryDomain: "example.com", acmeEmail });
    }
    for (const acmeEmail of ["admin", "admin@example", "@example.com", "admin@.example.com", "admin@example..com", "admin@example.com."]) {
      expect(() => validateSettingsGroup("general", { primaryDomain: "example.com", acmeEmail })).toThrow(/valid email address/);
    }
  });

  it("rejects non-line-break control characters in ACME root PEM values", () => {
    expect(() => validateSettingsGroup("acme", {
      caRootPem: "-----BEGIN CERTIFICATE-----\nsecret\u0000suffix\n-----END CERTIFICATE-----",
    })).toThrow(/control characters/);
  });
});

describe("trusted-proxies.proxy_protocol_ranges", () => {
  const base = { ranges: [] as string[] };

  it("stores the PROXY protocol sources normalized and leaves the other fields as given", () => {
    const input = { ranges: ["private_ranges"], strict: true, proxy_protocol_ranges: [" 192.168.1.1/24", "10.0.0.5", "10.0.0.5/32", "2001:db8::1/64"] };
    expect(validateSettingsGroup("trusted-proxies", input)).toEqual({
      ranges: ["private_ranges"],
      strict: true,
      proxy_protocol_ranges: ["192.168.1.0/24", "10.0.0.5", "2001:db8::/64"],
    });
    // The input itself is not changed.
    expect(input.proxy_protocol_ranges[0]).toBe(" 192.168.1.1/24");
  });

  it("accepts an empty list", () => {
    expect(validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: [] })).toEqual({ ...base, proxy_protocol_ranges: [] });
  });

  it("refuses sources that would let any client set its address", () => {
    expect(() => validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: ["0.0.0.0/0"] })).toThrow(
      /trusted-proxies\.proxy_protocol_ranges: "0\.0\.0\.0\/0" matches every address/
    );
    expect(() => validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: ["10.0.0.1", "::/0"] })).toThrow(/matches every address/);
    expect(() => validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: ["private_ranges"] })).toThrow(
      /"private_ranges" is not accepted here/
    );
  });

  it("refuses entries that are not addresses, and values that are not lists of strings", () => {
    for (const [value, message] of [
      [["firewall.lan"], /"firewall\.lan" is not an IP address or a CIDR range/],
      [["10.0.0.0/33"], /is not an IP address or a CIDR range/],
      [["10.0.0.1", 5], /proxy_protocol_ranges: \[1\] must be a string/],
      ["10.0.0.1", /proxy_protocol_ranges must be an array/],
      [{ allow: ["10.0.0.1"] }, /proxy_protocol_ranges must be an array/],
      [null, /proxy_protocol_ranges must be an array/],
    ] as const) {
      expect(() => validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: value }), JSON.stringify(value)).toThrow(message);
    }
  });

  it("refuses more than 100 sources", () => {
    const many = Array.from({ length: 101 }, (_, index) => `10.0.${index}.1`);
    expect(() => validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: many })).toThrow(/at most 100 entries/);
  });

  it("throws the settings validation error the REST route turns into a 400", () => {
    expect(() => validateSettingsGroup("trusted-proxies", { ...base, proxy_protocol_ranges: ["nope"] })).toThrow(SettingsValidationError);
  });
});
