"use server";

import { revalidatePath } from "next/cache";
import { revalidateSettingsPages } from "./revalidate";
import { requirePermission } from "@/src/lib/auth";
import { applyCaddyConfig } from "@/src/lib/caddy";
import { customDirectivesError, parseBodyLimitMib } from "@/src/lib/caddy-waf";
import { getInstanceMode, getSlaveMasterToken, setInstanceMode, setSlaveMasterToken, syncInstances } from "@/src/lib/instance-sync";
import {
  createInstance,
  deleteInstance,
  describeSyncKeyPin,
  pinInstanceSyncKey,
  pinSyncKey,
  resetInstanceSyncKeyPin,
  resetSyncKeyPin,
  updateInstance,
} from "@/src/lib/models/instances";
import { clearSetting, getSetting, setSetting, saveCloudflareSettings, getDnsProviderSettings, saveDnsProviderSettings, saveGeneralSettings, saveAcmeSettings, saveAuthentikSettings, saveForwardAuthSettings, saveMetricsSettings, saveLoggingSettings, saveDnsSettings, saveUpstreamDnsResolutionSettings, saveGeoBlockSettings, saveWafSettings, getWafSettings, saveErrorPagesSettings, saveTrustedProxiesSettings, saveDefaultResponseSettings, saveRateLimitSettings, type DefaultResponseSettings } from "@/src/lib/settings";
import { sanitizeErrorPageRules } from "@/src/lib/models/proxy-hosts";
import { SUPPRESSED_FROM_EVENT_REASON, suppressWafRuleForHost } from "@/src/lib/waf-suppression";
import { createWafExclusion, deleteWafExclusion, listWafExclusions } from "@/src/lib/models/waf-exclusions";
import { WAF_TUNING_KEYS } from "@/src/lib/waf-tuning";
import { getWafRuleMessages } from "@/src/lib/models/waf-events";
import type { CloudflareSettings, DnsProviderSettings, GeoBlockSettings, WafSettings } from "@/src/lib/settings";
import { getProviderDefinition, encryptProviderCredentials, isValidDnsDuration } from "@/src/lib/dns-providers";
import { toOAuthProviderView } from "@/src/lib/oauth-provider-view";
import {
  instanceSyncTokenValidationError,
  MIN_INSTANCE_SYNC_TOKEN_LENGTH,
} from "@/src/lib/instance-sync-token";
import { withSettingsUpdateLock } from "@/src/lib/settings-update-lock";
import { ApiClientError } from "@/src/lib/api-errors";
import { normalizeRateLimitSettings } from "@/src/lib/caddy-rate-limit";
import { normalizeProxyProtocolRanges } from "@/src/lib/proxy-protocol";
import { CaddyApplyError } from "@/src/lib/caddy-apply-error";
import { logAuditEvent } from "@/src/lib/audit";
import { parseRowId } from "@/src/lib/row-ids";

type ActionResult = {
  success: boolean;
  message?: string;
};

const VALID_UPSTREAM_DNS_FAMILIES = ["ipv6", "ipv4", "both"] as const;

function serializedSettingsAction<TArgs extends unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>
): (...args: TArgs) => Promise<TResult> {
  return async (...args: TArgs) => withSettingsUpdateLock(() => action(...args));
}

/**
 * Validates that a sync token meets minimum security requirements.
 * Tokens must be at least 32 characters to provide adequate entropy.
 */
function validateSyncToken(token: string): { valid: boolean; error?: string } {
  const error = instanceSyncTokenValidationError(token);
  if (error) {
    return {
      valid: false,
      error: `${error}. Consider using a randomly generated ${MIN_INSTANCE_SYNC_TOKEN_LENGTH}-byte token.`
    };
  }
  return { valid: true };
}

async function updateGeneralSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("general");
      await syncInstances();
      revalidateSettingsPages();
      return { success: true, message: "General settings reset to master defaults" };
    }
    await saveGeneralSettings({
      primaryDomain: String(formData.get("primaryDomain") ?? ""),
      acmeEmail: formData.get("acmeEmail") ? String(formData.get("acmeEmail")) : undefined
    });
    await syncInstances();
    revalidateSettingsPages();
    return { success: true, message: "General settings saved successfully" };
  } catch (error) {
    console.error("Failed to save general settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save general settings" };
  }
}

async function updateAcmeSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("acme");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "ACME settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return { success: true, message: `Settings reset, but could not apply to Caddy: ${errorMsg}` };
      }
    }

    const caUrl = formData.get("caUrl") ? String(formData.get("caUrl")).trim() : "";
    const caRootPem = formData.get("caRootPem") ? String(formData.get("caRootPem")).trim() : "";

    if (caUrl) {
      let parsed: URL;
      try {
        parsed = new URL(caUrl);
      } catch {
        return { success: false, message: "Invalid ACME directory URL." };
      }
      if (parsed.protocol !== "https:") {
        return { success: false, message: "ACME directory URL must use HTTPS." };
      }
    }

    await saveAcmeSettings({
      caUrl: caUrl.length > 0 ? caUrl : undefined,
      caRootPem: caRootPem.length > 0 ? caRootPem : undefined
    });

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "ACME settings saved successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return { success: true, message: `Settings saved, but could not apply to Caddy: ${errorMsg}` };
    }
  } catch (error) {
    console.error("Failed to save ACME settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save ACME settings" };
  }
}

async function updateCloudflareSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("cloudflare");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "Cloudflare settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return {
          success: true,
          message: `Settings reset, but could not apply to Caddy: ${errorMsg}`
        };
      }
    }
    const rawToken = formData.get("apiToken") ? String(formData.get("apiToken")).trim() : "";
    const clearToken = formData.get("clearToken") === "on";
    const current = await getSetting<CloudflareSettings>("cloudflare");

    const apiToken = clearToken ? "" : rawToken || current?.apiToken || "";
    const zoneId = formData.get("zoneId") ? String(formData.get("zoneId")) : undefined;
    const accountId = formData.get("accountId") ? String(formData.get("accountId")) : undefined;

    await saveCloudflareSettings({
      apiToken,
      zoneId: zoneId && zoneId.length > 0 ? zoneId : undefined,
      accountId: accountId && accountId.length > 0 ? accountId : undefined
    });

    // Try to apply the config, but don't fail if Caddy is unreachable
    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Cloudflare settings saved and applied to Caddy successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return {
        success: true, // Settings were saved successfully
        message: `Settings saved, but could not apply to Caddy: ${errorMsg}. You may need to start Caddy or check your configuration.`
      };
    }
  } catch (error) {
    console.error("Failed to save Cloudflare settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save Cloudflare settings" };
  }
}

async function updateDnsProviderSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("dns_provider");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "DNS provider settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return { success: true, message: `Settings reset, but could not apply to Caddy: ${errorMsg}` };
      }
    }

    const action = String(formData.get("action") ?? "save").trim();
    const providerName = String(formData.get("provider") ?? "").trim();
    const current = await getDnsProviderSettings();
    const settings: DnsProviderSettings = current ?? { providers: {}, default: null };

    if (action === "remove") {
      if (!providerName || !settings.providers[providerName]) {
        return { success: false, message: "No provider to remove" };
      }
      const def = getProviderDefinition(providerName);
      delete settings.providers[providerName];
      if (settings.default === providerName) {
        // Pick next configured provider, or null
        const remaining = Object.keys(settings.providers);
        settings.default = remaining.length > 0 ? remaining[0] : null;
      }
      await saveDnsProviderSettings(settings);
      await syncInstances();
      try { await applyCaddyConfig(); } catch { /* non-fatal */ }
      revalidateSettingsPages();
      return { success: true, message: `${def?.displayName ?? providerName} removed${settings.default ? `. Default is now ${settings.default}.` : "."}` };
    }

    if (action === "set-default") {
      const newDefault = providerName === "none" ? null : providerName;
      if (newDefault && !settings.providers[newDefault]) {
        return { success: false, message: `Cannot set default: ${providerName} is not configured` };
      }
      settings.default = newDefault;
      await saveDnsProviderSettings(settings);
      await syncInstances();
      try { await applyCaddyConfig(); } catch { /* non-fatal */ }
      revalidateSettingsPages();
      const label = newDefault ? (getProviderDefinition(newDefault)?.displayName ?? newDefault) : "None";
      return { success: true, message: `Default DNS provider set to ${label}` };
    }

    // action === "save": add or update a provider's credentials
    if (!providerName || providerName === "none") {
      return { success: false, message: "Select a provider to configure" };
    }

    const def = getProviderDefinition(providerName);
    if (!def) {
      return { success: false, message: `Unknown DNS provider: ${providerName}` };
    }

    const existingCreds = settings.providers[providerName];

    // Collect credentials from form
    const credentials: Record<string, string> = {};
    for (const field of def.fields) {
      const rawValue = formData.get(`credential_${field.key}`);
      const value = rawValue ? String(rawValue).trim() : "";
      if (value) {
        credentials[field.key] = value;
      } else if (existingCreds?.[field.key]) {
        credentials[field.key] = existingCreds[field.key];
      }
    }

    // Validate required fields
    for (const field of def.fields) {
      if (field.required && !credentials[field.key]) {
        return { success: false, message: `${field.label} is required for ${def.displayName}` };
      }
    }

    // Validate duration-typed option fields (e.g. propagation delay/timeout)
    for (const field of def.fields) {
      if (field.type === "duration" && credentials[field.key] && !isValidDnsDuration(credentials[field.key])) {
        return {
          success: false,
          message: `${field.label} must be a duration like "600s" or "10m" (or -1 to disable)`,
        };
      }
    }

    // Encrypt password fields before storing
    settings.providers[providerName] = encryptProviderCredentials(providerName, credentials);

    // If this is the first provider, make it the default
    if (!settings.default) {
      settings.default = providerName;
    }

    await saveDnsProviderSettings(settings);
    await syncInstances();

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      const isDefault = settings.default === providerName;
      return { success: true, message: `${def.displayName} saved${isDefault ? " (default)" : ""}` };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      return { success: true, message: `Settings saved, but could not apply to Caddy: ${errorMsg}` };
    }
  } catch (error) {
    console.error("Failed to save DNS provider settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save DNS provider settings" };
  }
}

async function updateAuthentikSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("authentik");
      await syncInstances();
      revalidateSettingsPages();
      return { success: true, message: "Authentik defaults reset to master values" };
    }
    const outpostDomain = String(formData.get("outpostDomain") ?? "").trim();
    const outpostUpstream = String(formData.get("outpostUpstream") ?? "").trim();
    const authEndpoint = formData.get("authEndpoint") ? String(formData.get("authEndpoint")).trim() : undefined;

    if (!outpostDomain || !outpostUpstream) {
      return { success: false, message: "Outpost domain and upstream are required" };
    }

    await saveAuthentikSettings({
      outpostDomain,
      outpostUpstream,
      authEndpoint: authEndpoint && authEndpoint.length > 0 ? authEndpoint : undefined
    });

    await syncInstances();
    revalidateSettingsPages();
    return { success: true, message: "Authentik defaults saved successfully" };
  } catch (error) {
    console.error("Failed to save Authentik settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save Authentik settings" };
  }
}

async function updateForwardAuthSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("forward_auth");
      await syncInstances();
      revalidateSettingsPages();
      return { success: true, message: "Forward Auth defaults reset to master values" };
    }
    const providerRaw = String(formData.get("provider") ?? "").trim();
    const provider = providerRaw === "custom" ? "custom" : providerRaw === "authelia" ? "authelia" : null;
    const authUpstream = String(formData.get("authUpstream") ?? "").trim();
    const authEndpoint = formData.get("authEndpoint") ? String(formData.get("authEndpoint")).trim() : undefined;

    if (!provider || !authUpstream) {
      return { success: false, message: "Provider and auth server URL are required" };
    }

    await saveForwardAuthSettings({
      provider,
      authUpstream,
      authEndpoint: authEndpoint && authEndpoint.length > 0 ? authEndpoint : undefined
    });

    await syncInstances();
    revalidateSettingsPages();
    return { success: true, message: "Forward Auth defaults saved successfully" };
  } catch (error) {
    console.error("Failed to save Forward Auth settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save Forward Auth settings" };
  }
}

async function updateMetricsSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("metrics");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "Metrics settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return {
          success: true,
          message: `Settings reset, but could not apply to Caddy: ${errorMsg}`
        };
      }
    }
    const enabled = formData.get("enabled") === "on";
    const portStr = formData.get("port") ? String(formData.get("port")).trim() : "";
    const port = portStr && !isNaN(Number(portStr)) ? Number(portStr) : 9090;

    await saveMetricsSettings({
      enabled,
      port
    });

    // Apply config to enable/disable metrics
    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Metrics settings saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return {
        success: true,
        message: `Settings saved, but could not apply to Caddy: ${errorMsg}`
      };
    }
  } catch (error) {
    console.error("Failed to save metrics settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save metrics settings" };
  }
}

async function updateLoggingSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("logging");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "Logging settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return {
          success: true,
          message: `Settings reset, but could not apply to Caddy: ${errorMsg}`
        };
      }
    }
    const enabled = formData.get("enabled") === "on";
    const format = formData.get("format") ? String(formData.get("format")).trim() : "json";

    // Validate format
    if (format !== "json" && format !== "console") {
      return { success: false, message: "Invalid log format. Must be 'json' or 'console'" };
    }

    await saveLoggingSettings({
      enabled,
      format: format as "json" | "console"
    });

    // Apply config to enable/disable logging
    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Logging settings saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return {
        success: true,
        message: `Settings saved, but could not apply to Caddy: ${errorMsg}`
      };
    }
  } catch (error) {
    console.error("Failed to save logging settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save logging settings" };
  }
}

function parseResolverList(value: string | null): string[] {
  if (!value) return [];
  return value
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function updateTrustedProxiesSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("trusted_proxies");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "Trusted proxies settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return { success: true, message: `Settings reset, but could not apply to Caddy: ${errorMsg}` };
      }
    }

    const ranges = parseResolverList(formData.get("ranges") ? String(formData.get("ranges")) : null);
    const clientIpHeaders = parseResolverList(
      formData.get("clientIpHeaders") ? String(formData.get("clientIpHeaders")) : null
    );
    const strict = formData.get("strict") === "on";
    const defaultGeoblock = formData.get("defaultGeoblock") === "on";
    const proxyProtocol = normalizeProxyProtocolRanges(String(formData.get("proxyProtocolRanges") ?? ""));
    if ("error" in proxyProtocol) {
      return { success: false, message: `PROXY protocol sources: ${proxyProtocol.error}` };
    }

    await saveTrustedProxiesSettings({
      ranges,
      client_ip_headers: clientIpHeaders.length > 0 ? clientIpHeaders : undefined,
      strict: strict || undefined,
      default_geoblock: defaultGeoblock || undefined,
      proxy_protocol_ranges: proxyProtocol.values.length > 0 ? proxyProtocol.values : undefined,
    });

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Trusted proxies settings saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return { success: true, message: `Settings saved, but could not apply to Caddy: ${errorMsg}` };
    }
  } catch (error) {
    console.error("Failed to save trusted proxies settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save trusted proxies settings" };
  }
}

async function updateDnsSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("dns");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "DNS settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return {
          success: true,
          message: `Settings reset, but could not apply to Caddy: ${errorMsg}`
        };
      }
    }
    const enabled = formData.get("enabled") === "on";
    const resolversRaw = formData.get("resolvers") ? String(formData.get("resolvers")) : "";
    const fallbacksRaw = formData.get("fallbacks") ? String(formData.get("fallbacks")) : "";
    const timeout = formData.get("timeout") ? String(formData.get("timeout")).trim() : undefined;

    const resolvers = parseResolverList(resolversRaw);
    const fallbacks = parseResolverList(fallbacksRaw);

    if (enabled && resolvers.length === 0) {
      return { success: false, message: "At least one DNS resolver is required when enabled" };
    }

    await saveDnsSettings({
      enabled,
      resolvers,
      fallbacks: fallbacks.length > 0 ? fallbacks : undefined,
      timeout: timeout && timeout.length > 0 ? timeout : undefined
    });

    // Apply config to use new DNS resolvers
    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "DNS settings saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return {
        success: true,
        message: `Settings saved, but could not apply to Caddy: ${errorMsg}`
      };
    }
  } catch (error) {
    console.error("Failed to save DNS settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save DNS settings" };
  }
}

async function updateUpstreamDnsResolutionSettingsActionUnlocked(
  _prevState: ActionResult | null,
  formData: FormData
): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("upstream_dns_resolution");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "Upstream DNS resolution settings reset to master defaults" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return {
          success: true,
          message: `Settings reset, but could not apply to Caddy: ${errorMsg}`
        };
      }
    }

    const enabled = formData.get("enabled") === "on";
    const familyRaw = formData.get("family") ? String(formData.get("family")).trim() : "both";
    if (!VALID_UPSTREAM_DNS_FAMILIES.includes(familyRaw as typeof VALID_UPSTREAM_DNS_FAMILIES[number])) {
      return { success: false, message: "Invalid address family selection" };
    }

    await saveUpstreamDnsResolutionSettings({
      enabled,
      family: familyRaw as "ipv6" | "ipv4" | "both"
    });

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Upstream DNS resolution settings saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return {
        success: true,
        message: `Settings saved, but could not apply to Caddy: ${errorMsg}`
      };
    }
  } catch (error) {
    console.error("Failed to save upstream DNS resolution settings:", error);
    return {
      success: false,
      message: error instanceof Error ? error.message : "Failed to save upstream DNS resolution settings"
    };
  }
}

async function updateInstanceModeActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("instances:write");
    const mode = String(formData.get("mode") ?? "").trim() as "standalone" | "master" | "slave";
    if (mode !== "standalone" && mode !== "master" && mode !== "slave") {
      return { success: false, message: "Invalid instance mode" };
    }
    await setInstanceMode(mode);
    revalidateSettingsPages();
    return { success: true, message: `Instance mode set to ${mode === "slave" ? "replica" : mode}` };
  } catch (error) {
    console.error("Failed to update instance mode:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to update instance mode" };
  }
}

async function updateSlaveMasterTokenActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("instances:write");
    const clearToken = formData.get("clearToken") === "on";
    const rawToken = formData.get("masterToken") ? String(formData.get("masterToken")).trim() : "";

    // If clearing, allow empty token
    if (clearToken) {
      await setSlaveMasterToken("");
      revalidateSettingsPages();
      return { success: true, message: "Master sync token removed" };
    }

    // If a new token is provided, validate it
    if (rawToken) {
      const validation = validateSyncToken(rawToken);
      if (!validation.valid) {
        return { success: false, message: validation.error };
      }
      await setSlaveMasterToken(rawToken);
      revalidateSettingsPages();
      return { success: true, message: "Master sync token updated" };
    }

    // No change - keep existing token
    const current = await getSlaveMasterToken();
    if (!current) {
      return { success: false, message: "No token provided. Please enter a sync token." };
    }
    return { success: true, message: "Master sync token unchanged" };
  } catch (error) {
    console.error("Failed to update master token:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to update master token" };
  }
}

export async function createSlaveInstanceAction(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("instances:write");
    const mode = await getInstanceMode();
    if (mode !== "master") {
      return { success: false, message: "Instance mode must be set to master to add replicas" };
    }
    const name = String(formData.get("name") ?? "").trim();
    const baseUrl = String(formData.get("baseUrl") ?? "").trim().replace(/\/$/, "");
    const apiToken = String(formData.get("apiToken") ?? "").trim();
    if (!name || !baseUrl || !apiToken) {
      return { success: false, message: "Name, base URL, and API token are required" };
    }

    // Validate token complexity
    const validation = validateSyncToken(apiToken);
    if (!validation.valid) {
      return { success: false, message: validation.error };
    }

    await createInstance({ name, baseUrl, apiToken, enabled: true });
    revalidateSettingsPages();
    return { success: true, message: "Replica added" };
  } catch (error) {
    console.error("Failed to create slave instance:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to add the replica" };
  }
}

export async function deleteSlaveInstanceAction(formData: FormData): Promise<void> {
  const session = await requirePermission("instances:write");
  const mode = await getInstanceMode();
  if (mode !== "master") {
    return;
  }
  const id = Number(formData.get("instanceId"));
  if (Number.isNaN(id)) {
    return;
  }
  await deleteInstance(id, Number(session.user.id));
  revalidateSettingsPages();
}

/**
 * Update a slave instance's name, base URL or token (left blank, the token is
 * kept), so changing them never needs removing the instance and its sync key
 * pin. A new base URL releases the pin of the old one (see updateInstance).
 */
export async function updateSlaveInstanceAction(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    const session = await requirePermission("instances:write");
    const mode = await getInstanceMode();
    if (mode !== "master") {
      return { success: false, message: "Instance mode must be set to master to manage replicas" };
    }
    const id = Number(formData.get("instanceId"));
    if (!Number.isInteger(id) || id <= 0) {
      return { success: false, message: "Invalid replica" };
    }
    const name = String(formData.get("name") ?? "").trim();
    const baseUrl = String(formData.get("baseUrl") ?? "").trim().replace(/\/$/, "");
    const apiToken = String(formData.get("apiToken") ?? "").trim();
    if (!name || !baseUrl) {
      return { success: false, message: "Name and base URL are required" };
    }
    if (apiToken) {
      const validation = validateSyncToken(apiToken);
      if (!validation.valid) {
        return { success: false, message: validation.error };
      }
    }
    await updateInstance(id, { name, baseUrl, ...(apiToken ? { apiToken } : {}) }, Number(session.user.id));
    revalidateSettingsPages();
    return { success: true, message: `Replica "${name}" updated` };
  } catch (error) {
    console.error("Failed to update slave instance:", error);
    return {
      success: false,
      message: error instanceof ApiClientError ? error.message : "Failed to update the replica"
    };
  }
}

/** The slave a sync key pin form is about: an instance by `instanceId`, else a slave URL by `slaveUrl`. */
function syncKeyPinTarget(formData: FormData): { instanceId: number } | { slaveUrl: string } | null {
  const rawInstanceId = formData.get("instanceId");
  if (rawInstanceId !== null) {
    const instanceId = parseRowId(rawInstanceId);
    return instanceId === null ? null : { instanceId };
  }
  const slaveUrl = String(formData.get("slaveUrl") ?? "").trim();
  return slaveUrl ? { slaveUrl } : null;
}

/**
 * Reset a slave's sync key pin, so the next sync pins the key the slave
 * presents: an instance's by `instanceId`, an INSTANCE_SLAVES entry's (or a
 * pin no slave uses) by `slaveUrl`.
 */
export async function resetSlaveSyncKeyPinAction(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    const session = await requirePermission("instances:write");
    const mode = await getInstanceMode();
    if (mode !== "master") {
      return { success: false, message: "Instance mode must be set to master to manage replicas" };
    }
    const actorUserId = Number(session.user.id);
    const target = syncKeyPinTarget(formData);
    if (!target) {
      return { success: false, message: "Invalid replica" };
    }
    const pin = "instanceId" in target
      ? await resetInstanceSyncKeyPin(target.instanceId, actorUserId)
      : await resetSyncKeyPin(target.slaveUrl, actorUserId);
    revalidateSettingsPages();
    const described = describeSyncKeyPin(pin);
    return {
      success: true,
      message: `${described[0].toUpperCase()}${described.slice(1)} reset. The next sync pins the key the replica ` +
        "presents; use Sync now, then check the new key id against the replica's.",
    };
  } catch (error) {
    console.error("Failed to reset slave sync key pin:", error);
    return {
      success: false,
      message: error instanceof ApiClientError ? error.message : "Failed to reset sync key pin"
    };
  }
}

/**
 * Pin the sync public key an admin read from a slave (its Instance sync page, or
 * GET /api/v1/instances/sync-key there): an instance's by `instanceId`, an
 * INSTANCE_SLAVES entry's by `slaveUrl`. Replaces any pin, with no sync that
 * trusts whatever key answers.
 */
export async function pinSlaveSyncKeyAction(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    const session = await requirePermission("instances:write");
    const mode = await getInstanceMode();
    if (mode !== "master") {
      return { success: false, message: "Instance mode must be set to master to manage replicas" };
    }
    const actorUserId = Number(session.user.id);
    const target = syncKeyPinTarget(formData);
    if (!target) {
      return { success: false, message: "Invalid replica" };
    }
    const publicKey = String(formData.get("publicKey") ?? "").trim();
    const pin = "instanceId" in target
      ? await pinInstanceSyncKey(target.instanceId, publicKey, actorUserId)
      : await pinSyncKey(target.slaveUrl, publicKey, actorUserId);
    revalidateSettingsPages();
    return { success: true, message: `Sync key ${pin.keyId} pinned. Syncs are sealed to this key only.` };
  } catch (error) {
    console.error("Failed to pin slave sync key:", error);
    return {
      success: false,
      message: error instanceof ApiClientError ? error.message : "Failed to pin sync key"
    };
  }
}

export async function toggleSlaveInstanceAction(formData: FormData): Promise<void> {
  await requirePermission("instances:write");
  const mode = await getInstanceMode();
  if (mode !== "master") {
    return;
  }
  const id = Number(formData.get("instanceId"));
  const enabled = formData.get("enabled") === "on";
  if (Number.isNaN(id)) {
    return;
  }
  await updateInstance(id, { enabled });
  revalidateSettingsPages();
}

function parseRedirectUrl(raw: FormDataEntryValue | null): string {
  if (!raw || typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (!trimmed) return "";
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    return trimmed;
  } catch {
    return "";
  }
}

function parseGeoBlockCheckbox(value: FormDataEntryValue | null): boolean {
  return value === "on" || value === "true" || value === "1";
}

function parseGeoBlockStringList(key: string, formData: FormData): string[] {
  const val = formData.get(key);
  if (!val || typeof val !== "string") return [];
  return val.split(",").map((s) => s.trim()).filter(Boolean);
}

function parseGeoBlockNumberList(key: string, formData: FormData): number[] {
  return parseGeoBlockStringList(key, formData)
    .map((s) => parseInt(s, 10))
    .filter((n) => !isNaN(n));
}

function parseGeoBlockResponseHeaders(formData: FormData): Record<string, string> {
  const keys = formData.getAll("geoblockResponseHeadersKeys[]") as string[];
  const values = formData.getAll("geoblockResponseHeadersValues[]") as string[];
  const headers: Record<string, string> = {};
  keys.forEach((key, i) => {
    const trimmed = key.trim();
    if (trimmed && /^[a-zA-Z0-9\-_]+$/.test(trimmed)) {
      headers[trimmed] = (values[i] ?? "").trim();
    }
  });
  return headers;
}

async function updateGeoBlockSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");

    const enabled = parseGeoBlockCheckbox(formData.get("geoblockEnabled"));

    const statusRaw = formData.get("geoblockResponseStatus");
    const statusNum = statusRaw && typeof statusRaw === "string" && statusRaw.trim() !== ""
      ? Number(statusRaw.trim())
      : NaN;
    const responseStatus = Number.isFinite(statusNum) && statusNum >= 100 && statusNum <= 599 ? statusNum : 403;

    const responseBodyRaw = formData.get("geoblockResponseBody");
    const responseBody = responseBodyRaw && typeof responseBodyRaw === "string" && responseBodyRaw.trim().length > 0
      ? responseBodyRaw.trim()
      : "Forbidden";

    const redirectUrlRaw = formData.get("geoblockRedirectUrl");
    const redirectUrl = parseRedirectUrl(redirectUrlRaw);

    const config: GeoBlockSettings = {
      enabled,
      block_countries: parseGeoBlockStringList("geoblockBlockCountries", formData),
      block_continents: parseGeoBlockStringList("geoblockBlockContinents", formData),
      block_asns: parseGeoBlockNumberList("geoblockBlockAsns", formData),
      block_cidrs: parseGeoBlockStringList("geoblockBlockCidrs", formData),
      block_ips: parseGeoBlockStringList("geoblockBlockIps", formData),
      allow_countries: parseGeoBlockStringList("geoblockAllowCountries", formData),
      allow_continents: parseGeoBlockStringList("geoblockAllowContinents", formData),
      allow_asns: parseGeoBlockNumberList("geoblockAllowAsns", formData),
      allow_cidrs: parseGeoBlockStringList("geoblockAllowCidrs", formData),
      allow_ips: parseGeoBlockStringList("geoblockAllowIps", formData),
      trusted_proxies: parseGeoBlockStringList("geoblockTrustedProxies", formData),
      fail_closed: parseGeoBlockCheckbox(formData.get("geoblockFailClosed")),
      response_status: responseStatus,
      response_body: responseBody,
      response_headers: parseGeoBlockResponseHeaders(formData),
      redirect_url: redirectUrl
    };

    await saveGeoBlockSettings(config);

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Geoblocking settings saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return {
        success: true,
        message: `Settings saved, but could not apply to Caddy: ${errorMsg}`
      };
    }
  } catch (error) {
    console.error("Failed to save geoblocking settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save geoblocking settings" };
  }
}

async function updateErrorPagesSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");

    const raw = formData.get("errorPagesJson");
    let rules: ReturnType<typeof sanitizeErrorPageRules> = [];
    if (raw && typeof raw === "string") {
      try {
        rules = sanitizeErrorPageRules(JSON.parse(raw));
      } catch {
        return { success: false, message: "Invalid error pages payload" };
      }
    }

    await saveErrorPagesSettings({ rules });

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Error pages saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return { success: true, message: `Settings saved, but could not apply to Caddy: ${errorMsg}` };
    }
  } catch (error) {
    console.error("Failed to save error pages settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save error pages settings" };
  }
}

/**
 * Global rate limiting defaults, posted as JSON by RateLimitSettingsFields.
 * Unlike most settings forms, a configuration Caddy refuses (for example a
 * Caddy image without the rate limit plugin) is rolled back: kept, it would
 * make every later apply fail too.
 */
async function updateRateLimitSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    const session = await requirePermission("settings:write");

    const raw = formData.get("rateLimitSettingsJson");
    let settings: ReturnType<typeof normalizeRateLimitSettings>;
    try {
      settings = normalizeRateLimitSettings(JSON.parse(typeof raw === "string" ? raw : ""), "Rate limiting");
    } catch (error) {
      if (error instanceof ApiClientError) return { success: false, message: error.message };
      return { success: false, message: "Invalid rate limiting payload" };
    }

    const previous = await getSetting<unknown>("rate_limit");
    await saveRateLimitSettings(settings);

    let applyWarning: string | null = null;
    try {
      await applyCaddyConfig();
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      if (error instanceof CaddyApplyError && error.code === "CADDY_REJECTED") {
        if (previous === null) await clearSetting("rate_limit");
        else await setSetting("rate_limit", previous);
        try {
          await applyCaddyConfig();
        } catch (restoreError) {
          console.error("Failed to reapply the previous Caddy config:", restoreError);
        }
        revalidateSettingsPages();
        return { success: false, message: `Caddy did not accept the rate limiting settings, so they were not saved: ${errorMsg}` };
      }
      applyWarning = errorMsg;
    }

    await logAuditEvent({
      userId: Number(session.user.id),
      action: "update",
      entityType: "setting",
      summary: "Updated rate limiting defaults",
      data: settings,
    });
    revalidateSettingsPages();
    return applyWarning
      ? { success: true, message: `Settings saved, but could not apply to Caddy: ${applyWarning}` }
      : { success: true, message: "Rate limiting settings saved and applied successfully" };
  } catch (error) {
    console.error("Failed to save rate limiting settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save rate limiting settings" };
  }
}

function parseDefaultResponseHeaders(value: FormDataEntryValue | null): Record<string, string> | undefined {
  if (typeof value !== "string" || value.trim().length === 0) return undefined;

  const headers: Record<string, string> = {};
  for (const rawLine of value.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator <= 0) {
      throw new Error(`Invalid response header line: ${rawLine}`);
    }
    headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
}

async function updateDefaultResponseSettingsActionUnlocked(
  _prevState: ActionResult | null,
  formData: FormData
): Promise<ActionResult> {
  try {
    await requirePermission("settings:write");
    const mode = await getInstanceMode();
    const overrideEnabled = formData.get("overrideEnabled") === "on";
    if (mode === "slave" && !overrideEnabled) {
      await clearSetting("default_response");
      try {
        await applyCaddyConfig();
        revalidateSettingsPages();
        return { success: true, message: "Default response reset to master settings" };
      } catch (error) {
        console.error("Failed to apply Caddy config:", error);
        revalidateSettingsPages();
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        await syncInstances();
        return { success: true, message: `Settings reset, but could not apply to Caddy: ${errorMsg}` };
      }
    }

    const responseMode = String(formData.get("mode") ?? "caddy");
    let next: DefaultResponseSettings;
    if (responseMode === "caddy" || responseMode === "abort") {
      next = { mode: responseMode };
    } else if (responseMode === "respond") {
      next = {
        mode: "respond",
        status: Number(formData.get("status") ?? 404),
        body: String(formData.get("body") ?? ""),
        headers: parseDefaultResponseHeaders(formData.get("headers")),
      };
    } else if (responseMode === "redirect") {
      next = {
        mode: "redirect",
        status: Number(formData.get("status") ?? 302),
        redirectUrl: String(formData.get("redirectUrl") ?? ""),
        headers: parseDefaultResponseHeaders(formData.get("headers")),
      };
    } else {
      return { success: false, message: "Invalid default response mode" };
    }

    await saveDefaultResponseSettings(next);

    try {
      await applyCaddyConfig();
      revalidateSettingsPages();
      return { success: true, message: "Default response saved and applied successfully" };
    } catch (error) {
      console.error("Failed to apply Caddy config:", error);
      revalidateSettingsPages();
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      await syncInstances();
      return { success: true, message: `Settings saved, but could not apply to Caddy: ${errorMsg}` };
    }
  } catch (error) {
    console.error("Failed to save default response settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save default response settings" };
  }
}

export async function syncSlaveInstancesAction(_prevState: ActionResult | null, _formData: FormData): Promise<ActionResult> {
  void _prevState;
  void _formData;
  try {
    await requirePermission("instances:write");
    const mode = await getInstanceMode();
    if (mode !== "master") {
      return { success: false, message: "Instance mode must be set to master to sync replicas" };
    }
    const result = await syncInstances();
    revalidateSettingsPages();

    const parts: string[] = [];
    if (result.success > 0) parts.push(`${result.success} succeeded`);
    if (result.failed > 0) parts.push(`${result.failed} failed`);
    if (result.skippedHttp > 0) parts.push(`${result.skippedHttp} skipped (HTTP blocked)`);

    if (result.skippedHttp > 0) {
      return {
        success: result.success > 0,
        message: `Sync: ${parts.join(", ")}. Set INSTANCE_SYNC_ALLOW_HTTP=true to allow insecure HTTP sync.`
      };
    }
    if (result.failed > 0) {
      return { success: true, message: `Sync completed with ${result.failed} failures (${result.success}/${result.total} succeeded)` };
    }
    return { success: true, message: `Sync completed (${result.success}/${result.total} succeeded)` };
  } catch (error) {
    console.error("Failed to sync slave instances:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to sync replicas" };
  }
}

export async function lookupWafRuleMessageAction(ruleId: number): Promise<{ message: string | null }> {
  await requirePermission("waf:read");
  const map = await getWafRuleMessages([ruleId]);
  return { message: map[ruleId] ?? null };
}

async function removeWafRuleGloballyActionUnlocked(ruleId: number): Promise<ActionResult> {
  try {
    const session = await requirePermission("waf:write");
    const exclusions = await listWafExclusions({ proxyHostId: null, ruleId });
    const whole = exclusions.filter((exclusion) => !exclusion.path && !exclusion.variable);
    if (whole.length === 0) return { success: false, message: `Rule ${ruleId} is not excluded globally.` };
    for (const exclusion of whole) {
      await deleteWafExclusion(exclusion.id, Number(session.user.id), { apply: applyCaddyConfig });
    }
    revalidateSettingsPages();
    revalidatePath("/waf");
    revalidatePath("/security");
    return { success: true, message: `Rule ${ruleId} removed from exclusions.` };
  } catch (error) {
    return { success: false, message: error instanceof Error ? error.message : "Failed to remove WAF rule" };
  }
}

async function suppressWafRuleGloballyActionUnlocked(ruleId: number): Promise<ActionResult> {
  try {
    const session = await requirePermission("waf:write");
    const existing = await listWafExclusions({ proxyHostId: null, ruleId });
    if (existing.some((exclusion) => !exclusion.path && !exclusion.variable)) {
      return { success: true, message: `Rule ${ruleId} is already excluded globally.` };
    }
    await createWafExclusion(
      { ruleId, proxyHostId: null, reason: SUPPRESSED_FROM_EVENT_REASON },
      Number(session.user.id),
      { apply: applyCaddyConfig }
    );
    revalidateSettingsPages();
    revalidatePath("/waf");
    revalidatePath("/security");
    return { success: true, message: `Rule ${ruleId} suppressed globally.` };
  } catch (error) {
    console.error("Failed to suppress WAF rule:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to suppress WAF rule" };
  }
}

export async function getOAuthProvidersAction() {
  await requirePermission("sso:read");
  const { listOAuthProviders } = await import("@/src/lib/models/oauth-providers");
  return listOAuthProviders();
}

export async function createOAuthProviderAction(data: {
  name: string;
  type: string;
  clientId: string;
  clientSecret: string;
  issuer?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  userinfoUrl?: string;
  scopes?: string;
  autoLink?: boolean;
}) {
  const session = await requirePermission("sso:write");
  const { createOAuthProvider } = await import("@/src/lib/models/oauth-providers");
  const { reloadOAuthProviders } = await import("@/src/lib/auth-server");
  const provider = await createOAuthProvider({ ...data, source: "ui" });
  await reloadOAuthProviders();
  const { createAuditEvent } = await import("@/src/lib/models/audit");
  await createAuditEvent({
    userId: Number(session.user.id),
    action: "oauth_provider_created",
    entityType: "oauth_provider",
    entityId: null,
    summary: `OAuth provider "${data.name}" created`,
    data: JSON.stringify({ providerId: provider.id }),
  });
  revalidateSettingsPages();
  return toOAuthProviderView(provider);
}

export async function updateOAuthProviderAction(
  id: string,
  data: Partial<{
    name: string;
    type: string;
    clientId: string;
    clientSecret: string;
    issuer: string | null;
    authorizationUrl: string | null;
    tokenUrl: string | null;
    userinfoUrl: string | null;
    scopes: string;
    autoLink: boolean;
    enabled: boolean;
  }>
) {
  const session = await requirePermission("sso:write");
  const { updateOAuthProvider } = await import("@/src/lib/models/oauth-providers");
  const { reloadOAuthProviders } = await import("@/src/lib/auth-server");
  const updated = await updateOAuthProvider(id, data);
  await reloadOAuthProviders();
  const { createAuditEvent } = await import("@/src/lib/models/audit");
  await createAuditEvent({
    userId: Number(session.user.id),
    action: "oauth_provider_updated",
    entityType: "oauth_provider",
    entityId: null,
    summary: `Updated OAuth provider "${id}"`,
    data: JSON.stringify({ providerId: id, fields: Object.keys(data) }),
  });
  revalidateSettingsPages();
  return updated ? toOAuthProviderView(updated) : null;
}

export async function deleteOAuthProviderAction(id: string) {
  const session = await requirePermission("sso:write");
  const { getOAuthProvider, deleteOAuthProvider } = await import("@/src/lib/models/oauth-providers");
  const { reloadOAuthProviders } = await import("@/src/lib/auth-server");
  const existing = await getOAuthProvider(id);
  await deleteOAuthProvider(id);
  await reloadOAuthProviders();
  const { createAuditEvent } = await import("@/src/lib/models/audit");
  await createAuditEvent({
    userId: Number(session.user.id),
    action: "oauth_provider_deleted",
    entityType: "oauth_provider",
    entityId: null,
    summary: `Deleted OAuth provider "${existing?.name ?? id}"`,
    data: JSON.stringify({ providerId: id }),
  });
  revalidateSettingsPages();
}

export async function suppressWafRuleForHostAction(ruleId: number, hostname: string): Promise<ActionResult> {
  try {
    const session = await requirePermission("waf:write");
    const userId = Number(session.user.id);
    const host = await suppressWafRuleForHost(ruleId, hostname, userId);
    if (!host) {
      return { success: false, message: `No proxy host found for ${hostname}.` };
    }
    revalidatePath("/proxy-hosts");
    revalidatePath("/waf");
    revalidatePath("/security");
    return { success: true, message: `Rule ${ruleId} suppressed for ${hostname}.` };
  } catch (error) {
    console.error("Failed to suppress WAF rule for host:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to suppress WAF rule" };
  }
}

async function updateWafSettingsActionUnlocked(_prevState: ActionResult | null, formData: FormData): Promise<ActionResult> {
  try {
    const session = await requirePermission("waf:write");

    const enabled = formData.get("wafEnabled") === "on";
    const mode: WafSettings["mode"] = enabled ? "On" : "Off";
    const loadOwasp = formData.get("wafLoadOwaspCrs") === "on";
    const customDirectives = typeof formData.get("wafCustomDirectives") === "string"
      ? (formData.get("wafCustomDirectives") as string).trim()
      : "";
    const existing = await getWafSettings();
    // Same check as the per-host WAF config: reject lines this save newly
    // drops from the generated config (a new line, or one the CRS setting now
    // drops), while a stored rule a later release started dropping doesn't
    // block saving unrelated fields (buildWafHandler still leaves it out and
    // logs it).
    const directiveError = customDirectivesError(
      customDirectives,
      { crsLoaded: loadOwasp },
      { directives: existing?.custom_directives, options: { crsLoaded: Boolean(existing?.load_owasp_crs) } }
    );
    if (directiveError) return { success: false, message: directiveError };
    const rawExcl = formData.get("wafExcludedRuleIds");
    // The excluded rule list is a view of the global exclusion records: left
    // out, saveWafSettings keeps them as they are.
    let excluded_rule_ids: number[] | undefined;
    if (rawExcl !== null) {
      excluded_rule_ids = (JSON.parse(rawExcl as string) as unknown[])
        .filter((x): x is number => Number.isInteger(x) && (x as number) > 0);
    }

    const requestBodyLimit = parseBodyLimitMib(formData.get("wafRequestBodyLimitMb"), "Request body limit");
    const requestBodyInMemoryLimit = parseBodyLimitMib(formData.get("wafRequestBodyInMemoryLimitMb"), "In-memory body limit");
    const rawAction = formData.get("wafRequestBodyLimitAction");
    const requestBodyLimitAction =
      rawAction === "Reject" || rawAction === "ProcessPartial" ? rawAction : undefined;
    if (
      requestBodyLimit !== undefined &&
      requestBodyInMemoryLimit !== undefined &&
      requestBodyInMemoryLimit > requestBodyLimit
    ) {
      return { success: false, message: "In-memory body limit must not exceed the request body limit." };
    }

    const config: WafSettings = {
      // This form has no tuning fields: keep the stored ones.
      ...Object.fromEntries(
        WAF_TUNING_KEYS.filter((key) => existing?.[key] !== undefined).map((key) => [key, existing?.[key]])
      ),
      enabled,
      mode,
      load_owasp_crs: loadOwasp,
      custom_directives: customDirectives,
      ...(excluded_rule_ids ? { excluded_rule_ids } : {}),
      ...(requestBodyLimit !== undefined ? { request_body_limit: requestBodyLimit } : {}),
      ...(requestBodyInMemoryLimit !== undefined ? { request_body_in_memory_limit: requestBodyInMemoryLimit } : {}),
      ...(requestBodyLimitAction ? { request_body_limit_action: requestBodyLimitAction } : {}),
    };
    await saveWafSettings(config, { actorUserId: Number(session.user.id) });
    await logAuditEvent({ userId: Number(session.user.id), action: "update", entityType: "waf_settings", summary: "Updated the global WAF settings", data: config });

    try {
      await applyCaddyConfig();
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return { success: true, message: `Settings saved, but could not apply to Caddy: ${errorMsg}` };
    }

    revalidateSettingsPages();
    revalidatePath("/waf");
    return { success: true, message: "WAF settings saved." };
  } catch (error) {
    console.error("Failed to save WAF settings:", error);
    return { success: false, message: error instanceof Error ? error.message : "Failed to save WAF settings" };
  }
}

export const updateGeneralSettingsAction = serializedSettingsAction(updateGeneralSettingsActionUnlocked);
export const updateAcmeSettingsAction = serializedSettingsAction(updateAcmeSettingsActionUnlocked);
export const updateCloudflareSettingsAction = serializedSettingsAction(updateCloudflareSettingsActionUnlocked);
export const updateDnsProviderSettingsAction = serializedSettingsAction(updateDnsProviderSettingsActionUnlocked);
export const updateAuthentikSettingsAction = serializedSettingsAction(updateAuthentikSettingsActionUnlocked);
export const updateForwardAuthSettingsAction = serializedSettingsAction(updateForwardAuthSettingsActionUnlocked);
export const updateMetricsSettingsAction = serializedSettingsAction(updateMetricsSettingsActionUnlocked);
export const updateLoggingSettingsAction = serializedSettingsAction(updateLoggingSettingsActionUnlocked);
export const updateTrustedProxiesSettingsAction = serializedSettingsAction(updateTrustedProxiesSettingsActionUnlocked);
export const updateDnsSettingsAction = serializedSettingsAction(updateDnsSettingsActionUnlocked);
export const updateUpstreamDnsResolutionSettingsAction = serializedSettingsAction(updateUpstreamDnsResolutionSettingsActionUnlocked);
export const updateInstanceModeAction = serializedSettingsAction(updateInstanceModeActionUnlocked);
export const updateSlaveMasterTokenAction = serializedSettingsAction(updateSlaveMasterTokenActionUnlocked);
export const updateGeoBlockSettingsAction = serializedSettingsAction(updateGeoBlockSettingsActionUnlocked);
export const updateErrorPagesSettingsAction = serializedSettingsAction(updateErrorPagesSettingsActionUnlocked);
export const updateDefaultResponseSettingsAction = serializedSettingsAction(updateDefaultResponseSettingsActionUnlocked);
export const updateRateLimitSettingsAction = serializedSettingsAction(updateRateLimitSettingsActionUnlocked);
export const removeWafRuleGloballyAction = serializedSettingsAction(removeWafRuleGloballyActionUnlocked);
export const suppressWafRuleGloballyAction = serializedSettingsAction(suppressWafRuleGloballyActionUnlocked);
export const updateWafSettingsAction = serializedSettingsAction(updateWafSettingsActionUnlocked);
