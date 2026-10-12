"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { KpiTile } from "@/components/ui/KpiTile";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionCard } from "@/components/ui/SectionCard";
import { StatusDot } from "@/components/ui/StatusDot";
import { formatBytes, formatCompact, formatCount } from "@/components/ui/chart-format";
import type { LoggingSettings, MetricsSettings } from "@/lib/settings";
import type { ClickHouseFailure } from "@/src/lib/clickhouse/failure";
import { CardNote, ChoiceField, OverrideRow, SettingRow, SettingRows, SettingsForm, SettingsGroupForms, ToggleField } from "@/src/components/settings/settings-form";
import { updateLoggingSettingsAction, updateMetricsSettingsAction } from "../../settings/actions";
import { useUnsavedWarning } from "../../settings/use-unsaved-warning";

type LogFormat = NonNullable<LoggingSettings["format"]>;

/** ClickHouse as this install uses it, and its totals over the retention window. */
export type AnalyticsStatusView = {
  /** CLICKHOUSE_PASSWORD is set, so traffic analytics run. */
  enabled: boolean;
  retentionDays: number;
  /** CLICKHOUSE_RETENTION_DAYS is set (otherwise the default applies). */
  retentionFromEnv: boolean;
  /** Totals over the retention window; null without analytics:read, or when ClickHouse did not answer. */
  totals: { requests: number; wafEvents: number; bytes: number; uniqueAddresses: number } | null;
  /** Why the totals are missing although analytics run (ClickHouse unreachable or slow), and what to check. */
  totalsError: ClickHouseFailure | null;
};

export type AnalyticsSettingsProps = {
  analytics: AnalyticsStatusView;
  logging: LoggingSettings | null;
  metrics: MetricsSettings | null;
  isSlave: boolean;
  /** On a replica: the settings it overrides instead of following its master. */
  overrides: { logging: boolean; metrics: boolean };
  /** settings:write */
  canSave: boolean;
  /** analytics:read, for the breadcrumb's link. */
  canOpenAnalytics: boolean;
};

/** Analytics settings: ClickHouse and its retention (set in the environment), the access log and Prometheus metrics. */
export default function AnalyticsSettingsClient({ analytics, logging, metrics, isSlave, overrides, canSave, canOpenAnalytics }: AnalyticsSettingsProps) {
  const onDirtyChange = useUnsavedWarning();
  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        className="mb-0"
        breadcrumb={["Observe", canOpenAnalytics ? { label: "Analytics", href: "/analytics" } : "Analytics", "Settings"]}
        title="Analytics settings"
      />
      <TrafficAnalyticsCard analytics={analytics} />
      <SettingsGroupForms name="Analytics settings" canSave={canSave} onDirtyChange={onDirtyChange}>
        <AccessLogCard logging={logging} isSlave={isSlave} override={overrides.logging} />
        <MetricsCard metrics={metrics} isSlave={isSlave} override={overrides.metrics} />
      </SettingsGroupForms>
    </div>
  );
}

function TrafficAnalyticsCard({ analytics }: { analytics: AnalyticsStatusView }) {
  const window = `last ${analytics.retentionDays} ${analytics.retentionDays === 1 ? "day" : "days"}`;
  const totals = analytics.totals;
  return (
    <SectionCard id="analytics" className="scroll-mt-20 md:scroll-mt-4" title="Traffic analytics" headingLevel={2} divided={false}>
      {totals && (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(150px,100%),1fr))] gap-2.5 px-5 pb-4">
          <KpiTile label="Requests" value={formatCompact(totals.requests)} note={window} />
          <KpiTile label="WAF events" value={formatCount(totals.wafEvents)} note={window} />
          <KpiTile label="Sent" value={formatBytes(totals.bytes)} note={window} />
          <KpiTile label="Unique addresses" value={formatCount(totals.uniqueAddresses)} note={window} />
        </div>
      )}
      <SettingRows>
        <SettingRow
          label="ClickHouse"
          note={analytics.enabled ? analytics.totalsError?.note ?? undefined : "Set CLICKHOUSE_PASSWORD and recreate the web container to turn it on."}
        >
          <span className="flex min-h-9 items-center">
            {!analytics.enabled ? (
              <StatusDot tone="off" label="Off" />
            ) : analytics.totalsError ? (
              <StatusDot tone="warn" label={analytics.totalsError.label} />
            ) : (
              <StatusDot tone="ok" label="Connected" />
            )}
          </span>
        </SettingRow>
        <SettingRow
          label="Keep events for"
          note={analytics.retentionFromEnv ? "Set by CLICKHOUSE_RETENTION_DAYS." : "The default. CLICKHOUSE_RETENTION_DAYS changes it."}
        >
          <span className="num flex min-h-9 items-center text-[13px]">
            {analytics.retentionDays} {analytics.retentionDays === 1 ? "day" : "days"}
          </span>
        </SettingRow>
      </SettingRows>
    </SectionCard>
  );
}

function AccessLogCard({ logging, isSlave, override: initialOverride }: { logging: LoggingSettings | null; isSlave: boolean; override: boolean }) {
  const [override, setOverride] = useState(initialOverride);
  const [enabled, setEnabled] = useState(logging?.enabled ?? false);
  const [format, setFormat] = useState<LogFormat>(logging?.format ?? "json");
  const disabled = isSlave && !override;
  return (
    <SectionCard id="logging" className="scroll-mt-20 md:scroll-mt-4" title="Access log" headingLevel={2} divided={false}>
      <SettingsForm action={updateLoggingSettingsAction} order={0}>
        <SettingRows>
          {isSlave && <OverrideRow id="logging-override" checked={override} onCheckedChange={setOverride} />}
          <SettingRow label="Access logging">
            <ToggleField
              id="logging-enabled"
              name="enabled"
              label="Log every proxied request"
              checked={enabled}
              onCheckedChange={setEnabled}
              disabled={disabled}
            />
          </SettingRow>
          <SettingRow label="Format" labelId="settings-log-format">
            <ChoiceField
              name="format"
              label="Log format"
              value={format}
              onChange={setFormat}
              disabled={disabled}
              options={[
                { value: "json", label: "JSON" },
                { value: "console", label: "Console (Common Log Format)" },
              ]}
            />
          </SettingRow>
        </SettingRows>
      </SettingsForm>
      {!enabled && <CardNote tone="warn">Traffic analytics get no new requests while access logging is off.</CardNote>}
    </SectionCard>
  );
}

function MetricsCard({ metrics, isSlave, override: initialOverride }: { metrics: MetricsSettings | null; isSlave: boolean; override: boolean }) {
  const [override, setOverride] = useState(initialOverride);
  const [port, setPort] = useState(String(metrics?.port ?? 9090));
  const disabled = isSlave && !override;
  return (
    <SectionCard id="metrics" className="scroll-mt-20 md:scroll-mt-4" title="Prometheus metrics" headingLevel={2} divided={false}>
      <SettingsForm action={updateMetricsSettingsAction} order={1}>
        <SettingRows>
          {isSlave && <OverrideRow id="metrics-override" checked={override} onCheckedChange={setOverride} />}
          <SettingRow label="Metrics endpoint">
            <ToggleField
              id="metrics-enabled"
              name="enabled"
              label="Expose /metrics on its own port"
              defaultChecked={metrics?.enabled ?? false}
              disabled={disabled}
            />
          </SettingRow>
          <SettingRow label="Port" htmlFor="settings-metrics-port">
            <Input
              id="settings-metrics-port"
              name="port"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(event) => setPort(event.target.value)}
              disabled={disabled}
              className="num w-[120px]"
            />
          </SettingRow>
          <SettingRow label="Scrape from" note="Inside the Docker network only.">
            <span className="num flex min-h-9 items-center text-[13px] [overflow-wrap:anywhere]">
              http://ingressi-caddy:{port || "9090"}/metrics
            </span>
          </SettingRow>
        </SettingRows>
      </SettingsForm>
    </SectionCard>
  );
}
