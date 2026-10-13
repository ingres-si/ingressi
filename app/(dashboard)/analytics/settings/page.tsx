import { requirePermission } from "@/src/lib/auth";
import { can, type Access } from "@/src/lib/permissions";
import { getLoggingSettings, getMetricsSettings } from "@/src/lib/settings";
import { getRetentionDays, isAnalyticsEnabled, querySummary, queryWafCount } from "@/src/lib/clickhouse/client";
import { describeClickHouseFailure } from "@/src/lib/clickhouse/failure";
import { loadReplicaOverrides } from "../../settings/load";
import AnalyticsSettingsClient, { type AnalyticsStatusView } from "./AnalyticsSettingsClient";

export const metadata = { title: "Analytics settings" };

/** How long the page waits for ClickHouse's totals before showing it without them. */
const ANALYTICS_TOTALS_TIMEOUT_MS = 2500;

/**
 * ClickHouse as configured by the environment, with traffic totals over the
 * retention window for roles that may read analytics across every host.
 */
async function analyticsStatus(access: Access): Promise<AnalyticsStatusView> {
  const enabled = isAnalyticsEnabled();
  const retentionDays = getRetentionDays();
  const view: AnalyticsStatusView = {
    enabled,
    retentionDays,
    retentionFromEnv: Boolean(process.env.CLICKHOUSE_RETENTION_DAYS?.trim()),
    totals: null,
    totalsError: null,
  };
  if (!enabled || !can(access, "analytics:read")) return view;
  const to = Math.floor(Date.now() / 1000);
  const from = to - retentionDays * 86_400;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const [summary, wafEvents] = await Promise.race([
      Promise.all([querySummary(from, to, []), queryWafCount(from, to)]),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("timeout")), ANALYTICS_TOTALS_TIMEOUT_MS);
      }),
    ]);
    view.totals = { requests: summary.totalRequests, wafEvents, bytes: summary.bytesServed, uniqueAddresses: summary.uniqueIps };
  } catch (error) {
    view.totalsError =
      error instanceof Error && error.message === "timeout"
        ? { label: "Did not answer within a few seconds", note: null }
        : describeClickHouseFailure(error);
  } finally {
    if (timer) clearTimeout(timer);
  }
  return view;
}

export default async function AnalyticsSettingsPage() {
  const { access } = await requirePermission("settings:read");
  const [analytics, logging, metrics, replica] = await Promise.all([
    analyticsStatus(access),
    getLoggingSettings(),
    getMetricsSettings(),
    loadReplicaOverrides({ logging: "logging", metrics: "metrics" }),
  ]);
  return (
    <AnalyticsSettingsClient
      analytics={analytics}
      logging={logging}
      metrics={metrics}
      isSlave={replica.isSlave}
      overrides={replica.overrides}
      canSave={can(access, "settings:write")}
      canOpenAnalytics={can(access, "analytics:read")}
    />
  );
}
