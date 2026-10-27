import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import {
  getAuthentikSettings,
  getDefaultResponseSettings,
  getErrorPagesSettings,
  getForwardAuthSettings,
  getResponseHeadersSettings,
  getTrustedProxiesSettings,
  getUpstreamDnsResolutionSettings,
} from "@/src/lib/settings";
import { loadReplicaOverrides } from "../../settings/load";
import HostDefaultsClient from "./HostDefaultsClient";

export const metadata = { title: "Host defaults" };

export default async function HostDefaultsPage() {
  const { access } = await requirePermission("settings:read");
  const [defaultResponse, errorPages, responseHeaders, trustedProxies, upstreamDnsResolution, authentik, forwardAuth, replica] = await Promise.all([
    getDefaultResponseSettings(),
    getErrorPagesSettings(),
    getResponseHeadersSettings(),
    getTrustedProxiesSettings(),
    getUpstreamDnsResolutionSettings(),
    getAuthentikSettings(),
    getForwardAuthSettings(),
    loadReplicaOverrides({
      defaultResponse: "default_response",
      responseHeaders: "response_headers",
      trustedProxies: "trusted_proxies",
      upstreamDnsResolution: "upstream_dns_resolution",
      authentik: "authentik",
      forwardAuth: "forward_auth",
    }),
  ]);

  return (
    <HostDefaultsClient
      defaultResponse={defaultResponse}
      errorPages={errorPages}
      responseHeaders={responseHeaders}
      trustedProxies={trustedProxies}
      upstreamDnsResolution={upstreamDnsResolution}
      authentik={authentik}
      forwardAuth={forwardAuth}
      isSlave={replica.isSlave}
      overrides={replica.overrides}
      canSave={can(access, "settings:write")}
      canOpenProxyHosts={can(access, "proxy_hosts:read")}
    />
  );
}
