import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission, apiErrorResponse, logUnexpectedApiError } from "@/src/lib/api-auth";
import {
  getGeneralSettings, saveGeneralSettings,
  getAcmeSettings, saveAcmeSettings,
  getCloudflareSettings, saveCloudflareSettings,
  getAuthentikSettings, saveAuthentikSettings,
  getForwardAuthSettings, saveForwardAuthSettings,
  getMetricsSettings, saveMetricsSettings,
  getLoggingSettings, saveLoggingSettings,
  getDnsSettings, saveDnsSettings,
  getDnsProviderSettings, saveDnsProviderSettings,
  getUpstreamDnsResolutionSettings, saveUpstreamDnsResolutionSettings,
  getGeoBlockSettings, saveGeoBlockSettings,
  getWafSettings, saveWafSettings,
  getErrorPagesSettings, saveErrorPagesSettings,
  getDefaultResponseSettings, saveDefaultResponseSettings,
  getResponseHeadersSettings, saveResponseHeadersSettings,
  getTrustedProxiesSettings, saveTrustedProxiesSettings,
  getRateLimitSettings, saveRateLimitSettings,
  getSetting, setSetting, clearSetting,
} from "@/src/lib/settings";
import { getInstanceMode, setInstanceMode, getSlaveMasterToken, setSlaveMasterToken } from "@/src/lib/instance-sync";
import { applyCaddyConfig } from "@/src/lib/caddy";
import { DefaultResponseValidationError } from "@/src/lib/caddy-default-response";
import { instanceSyncTokenValidationError } from "@/src/lib/instance-sync-token";
import {
  encryptDnsProviderSettingCredentials,
  redactDnsProviderSettingsForApi,
  redactLegacyCloudflareSettingsForApi,
} from "@/src/lib/dns-providers";
import type { CloudflareSettings, DnsProviderSettings } from "@/src/lib/settings";
import {
  assertSettingsPayloadSize,
  SettingsValidationError,
  validateSettingsGroup,
} from "@/src/lib/settings-validation";
import { withSettingsUpdateLock } from "@/src/lib/settings-update-lock";
import { logAuditEvent } from "@/src/lib/audit";
import { readGlobalWafExclusionRows, restoreGlobalWafExclusionRows } from "@/src/lib/models/waf-exclusion-mirror";

type SettingsHandler = {
  read: () => Promise<unknown>;
  save: (data: never) => Promise<void>;
  storageKey: string;
  applyCaddy?: boolean;
  /** Audit summary recorded after a successful update. */
  audit?: string;
};

const SETTINGS_HANDLERS: Record<string, SettingsHandler> = {
  general: { read: getGeneralSettings, save: saveGeneralSettings as (data: never) => Promise<void>, storageKey: "general", applyCaddy: true },
  acme: { read: getAcmeSettings, save: saveAcmeSettings as (data: never) => Promise<void>, storageKey: "acme", applyCaddy: true },
  cloudflare: { read: getCloudflareSettings, save: saveCloudflareSettings as (data: never) => Promise<void>, storageKey: "cloudflare", applyCaddy: true },
  authentik: { read: getAuthentikSettings, save: saveAuthentikSettings as (data: never) => Promise<void>, storageKey: "authentik", applyCaddy: true },
  "forward-auth": { read: getForwardAuthSettings, save: saveForwardAuthSettings as (data: never) => Promise<void>, storageKey: "forward_auth" },
  metrics: { read: getMetricsSettings, save: saveMetricsSettings as (data: never) => Promise<void>, storageKey: "metrics", applyCaddy: true },
  logging: { read: getLoggingSettings, save: saveLoggingSettings as (data: never) => Promise<void>, storageKey: "logging", applyCaddy: true },
  dns: { read: getDnsSettings, save: saveDnsSettings as (data: never) => Promise<void>, storageKey: "dns", applyCaddy: true },
  "dns-provider": { read: getDnsProviderSettings, save: saveDnsProviderSettings as (data: never) => Promise<void>, storageKey: "dns_provider", applyCaddy: true },
  "upstream-dns": { read: getUpstreamDnsResolutionSettings, save: saveUpstreamDnsResolutionSettings as (data: never) => Promise<void>, storageKey: "upstream_dns_resolution", applyCaddy: true },
  geoblock: { read: getGeoBlockSettings, save: saveGeoBlockSettings as (data: never) => Promise<void>, storageKey: "geoblock", applyCaddy: true },
  // Saved with the caller as author of exclusion records the legacy excluded_rule_ids list adds (see PUT).
  waf: { read: getWafSettings, save: saveWafSettings as (data: never) => Promise<void>, storageKey: "waf", applyCaddy: true, audit: "Updated the global WAF settings" },
  "error-pages": { read: getErrorPagesSettings, save: saveErrorPagesSettings as (data: never) => Promise<void>, storageKey: "error_pages", applyCaddy: true },
  "default-response": {
    read: async () => (await getDefaultResponseSettings()) ?? { mode: "caddy" },
    save: saveDefaultResponseSettings as (data: never) => Promise<void>,
    storageKey: "default_response",
    applyCaddy: true,
  },
  "response-headers": {
    read: async () => (await getResponseHeadersSettings()) ?? { set: {}, remove: [] },
    save: saveResponseHeadersSettings as (data: never) => Promise<void>,
    storageKey: "response_headers",
    applyCaddy: true,
  },
  "trusted-proxies": { read: getTrustedProxiesSettings, save: saveTrustedProxiesSettings as (data: never) => Promise<void>, storageKey: "trusted_proxies", applyCaddy: true },
  "rate-limit": {
    read: async () => (await getRateLimitSettings()) ?? { enabled: false, rules: [], allowlist: [] },
    save: saveRateLimitSettings as (data: never) => Promise<void>,
    storageKey: "rate_limit",
    applyCaddy: true,
    audit: "Updated rate limiting defaults",
  },
};

/**
 * Groups that belong to other permission areas than "settings": the instance
 * mode and the slave's sync token are instance-sync configuration, and the
 * global WAF settings belong to the WAF.
 */
const INSTANCE_GROUPS = new Set(["instance-mode", "sync-token"]);
const WAF_GROUPS = new Set(["waf"]);

function unknownKey(input: Record<string, unknown>, allowed: readonly string[]): string | null {
  const allowedKeys = new Set(allowed);
  return Object.keys(input).find((key) => !allowedKeys.has(key)) ?? null;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ group: string }> }
) {
  try {
    const { group } = await params;
    if (INSTANCE_GROUPS.has(group)) {
      await requireApiPermission(request, "instances:read");
    } else if (WAF_GROUPS.has(group)) {
      await requireApiPermission(request, "waf:read");
    } else {
      await requireApiPermission(request, "settings:read");
    }

    if (group === "instance-mode") {
      const mode = await getInstanceMode();
      return NextResponse.json({ mode });
    }

    if (group === "sync-token") {
      const token = await getSlaveMasterToken();
      return NextResponse.json({ has_token: token !== null });
    }

    const handler = SETTINGS_HANDLERS[group];
    if (!handler) {
      return NextResponse.json({ error: "Unknown settings group" }, { status: 404 });
    }

    const settings = await handler.read();
    if (group === "cloudflare" && settings) {
      return NextResponse.json(
        redactLegacyCloudflareSettingsForApi(settings as CloudflareSettings),
        { headers: { "Cache-Control": "no-store" } }
      );
    }
    if (group === "dns-provider" && settings) {
      return NextResponse.json(
        redactDnsProviderSettingsForApi(settings as DnsProviderSettings),
        { headers: { "Cache-Control": "no-store" } }
      );
    }
    return NextResponse.json(settings ?? {});
  } catch (error) {
    return apiErrorResponse(error);
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ group: string }> }
) {
  try {
    const { group } = await params;
    let actorUserId: number | null = null;
    if (INSTANCE_GROUPS.has(group)) {
      await requireApiPermission(request, "instances:write");
    } else if (WAF_GROUPS.has(group)) {
      actorUserId = (await requireApiPermission(request, "waf:write")).userId;
    } else {
      actorUserId = (await requireApiPermission(request, "settings:write")).userId;
    }
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON payload" }, { status: 400 });
    }

    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return NextResponse.json({ error: "Settings payload must be an object" }, { status: 400 });
    }
    const input = body as Record<string, unknown>;
    try {
      assertSettingsPayloadSize(input);
    } catch (error) {
      if (error instanceof SettingsValidationError) {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }
      throw error;
    }

    if (group === "instance-mode") {
      const unexpected = unknownKey(input, ["mode"]);
      if (unexpected) {
        return NextResponse.json(
          { error: `instance-mode settings contains unknown field: ${unexpected}` },
          { status: 400 }
        );
      }
      const validModes = ["standalone", "master", "slave"];
      if (!validModes.includes(input.mode as string)) {
        return NextResponse.json(
          { error: `Invalid mode. Must be one of: ${validModes.join(", ")}` },
          { status: 400 }
        );
      }
      return await withSettingsUpdateLock(async () => {
        await setInstanceMode(input.mode as "standalone" | "master" | "slave");
        return NextResponse.json({ ok: true });
      });
    }

    if (group === "sync-token") {
      const unexpected = unknownKey(input, ["token"]);
      if (unexpected) {
        return NextResponse.json(
          { error: `sync-token settings contains unknown field: ${unexpected}` },
          { status: 400 }
        );
      }
      const token = input.token ?? null;
      const validationError = token === null ? null : instanceSyncTokenValidationError(token);
      if (validationError) {
        return NextResponse.json(
          { error: `${validationError}; token must otherwise be null` },
          { status: 400 }
        );
      }
      // instanceSyncTokenValidationError rejects every non-string value above.
      return await withSettingsUpdateLock(async () => {
        await setSlaveMasterToken(token as string | null);
        return NextResponse.json({ ok: true });
      });
    }

    const handler = SETTINGS_HANDLERS[group];
    if (!handler) {
      return NextResponse.json({ error: "Unknown settings group" }, { status: 404 });
    }

    let validated: unknown;
    try {
      validated = validateSettingsGroup(group, input, {
        previousWaf: group === "waf" ? await getWafSettings() : null,
      });
    } catch (error) {
      if (error instanceof SettingsValidationError || error instanceof DefaultResponseValidationError) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 }
        );
      }
      throw error;
    }

    return await withSettingsUpdateLock(async () => {
      // Preserve the exact local stored value (including encrypted credentials),
      // rather than the effective or redacted GET representation, for rollback.
      const previousValue = await getSetting<unknown>(handler.storageKey);
      // The WAF settings' excluded_rule_ids write exclusion records too; a
      // failed apply restores them with the setting.
      const previousExclusions = group === "waf" ? await readGlobalWafExclusionRows() : null;
      // Provider credentials are stored encrypted, as the dashboard form does.
      const toSave = group === "dns-provider" ? encryptDnsProviderSettingCredentials(validated) : validated;
      if (group === "waf") await saveWafSettings(toSave as never, { actorUserId });
      else await handler.save(toSave as never);

      if (handler.applyCaddy) {
        try {
          await applyCaddyConfig();
        } catch (applyError) {
          logUnexpectedApiError("Caddy settings apply failed", applyError);
          try {
            if (previousValue === null || previousValue === undefined) {
              await clearSetting(handler.storageKey);
            } else {
              await setSetting(handler.storageKey, previousValue);
            }
            if (previousExclusions) await restoreGlobalWafExclusionRows(previousExclusions);
          } catch (rollbackError) {
            logUnexpectedApiError("Settings rollback failed", rollbackError);
            return NextResponse.json(
              { error: "Failed to apply Caddy configuration and roll back settings" },
              { status: 500 }
            );
          }

          // Caddy's load is atomic, but a failure may also happen after load while
          // synchronizing instances. Best-effort reapply confirms the active
          // configuration matches the restored database state.
          try {
            await applyCaddyConfig();
          } catch (restoreApplyError) {
            logUnexpectedApiError("Previous Caddy settings reapply failed", restoreApplyError);
          }

          return NextResponse.json(
            { error: "Failed to apply Caddy configuration; settings were rolled back" },
            { status: 502 }
          );
        }
      }

      if (handler.audit) {
        await logAuditEvent({ userId: actorUserId, action: "update", entityType: "setting", summary: handler.audit, data: toSave });
      }
      return NextResponse.json({ ok: true });
    });
  } catch (error) {
    return apiErrorResponse(error);
  }
}
