// SPDX-License-Identifier: Elastic-2.0
/**
 * The daily digest rendered for each channel type. Pure functions, no I/O.
 *
 * Host names, request paths, rule messages, audit summaries and alert titles
 * can come from requests or from what administrators typed, so every format
 * escapes them for its own markup. The AI narrative is always labeled.
 */
import { BRAND_NAME } from "@/src/lib/brand";
import { brandName } from "@/ee/white-label/store";
import { cleanText, escapeHtml, escapeSlack, escapeTeams } from "@/ee/alerting/format";
import { localDateTime } from "./digest-schedule";
import type { DigestFacts } from "./digest-data";
import { AI_GENERATED_SUMMARY_LABEL } from "./types";

export type DigestContent = {
  facts: DigestFacts;
  /** The AI narrative, already sanitized; null when not added. */
  narrative: string | null;
  timeZone: string;
  /** The local date the digest is for, "YYYY-MM-DD". */
  localDate: string;
  /** ISO 8601 */
  generatedAt: string;
};

export type DigestSection = { heading: string; kind: "paragraph" | "list"; lines: string[]; ai?: boolean };

/** ntfy turns longer messages into attachments; stay below its 4096-byte limit. */
const NTFY_MAX_BYTES = 3800;
const SLACK_MAX_CHARS = 12_000;
const TRUNCATED = "… (shortened; the e-mail and webhook versions have everything)";

function fmt(value: number): string {
  return value.toLocaleString("en-US");
}

function plural(value: number, word: string): string {
  return `${fmt(value)} ${word}${value === 1 ? "" : "s"}`;
}

function day(iso: string): string {
  return iso.slice(0, 10);
}

export function digestTitle(content: DigestContent): string {
  return `Daily security digest for ${content.localDate}`;
}

export function digestIntro(content: DigestContent): string {
  const to = localDateTime(new Date(content.facts.period.to), content.timeZone);
  return `${brandName()} security digest for the ${content.facts.period.hours} hours up to ${to} (${content.timeZone}).`;
}

/** The digest as format-neutral sections of plain text (unescaped). */
export function digestSections(content: DigestContent): DigestSection[] {
  const { facts, timeZone } = content;
  const sections: DigestSection[] = [];
  const at = (iso: string) => localDateTime(new Date(iso), timeZone);

  if (content.narrative) {
    sections.push({ heading: AI_GENERATED_SUMMARY_LABEL, kind: "paragraph", lines: [cleanText(content.narrative, 1500, true)], ai: true });
  }

  const traffic = facts.traffic;
  if (traffic) {
    sections.push({
      heading: "Traffic and blocked requests",
      kind: "list",
      lines: [
        `Requests: ${fmt(traffic.requests)} from ${plural(traffic.uniqueClients, "client")}`,
        `Blocked: ${fmt(traffic.blocked.total)} (WAF ${fmt(traffic.blocked.waf)}, geo/ASN blocking ${fmt(traffic.blocked.geo)}, access lists ${fmt(traffic.blocked.accessList)})`,
        `WAF matches that were not blocked: ${fmt(traffic.wafDetectedNotBlocked)}`,
      ],
    });
    const attacked: string[] = [];
    if (traffic.topAttackedHosts.length) {
      attacked.push(`Hosts: ${traffic.topAttackedHosts.map((item) => `${item.host} (${fmt(item.events)})`).join(", ")}`);
    }
    if (traffic.topAttackedPaths.length) {
      attacked.push(`Paths: ${traffic.topAttackedPaths.map((item) => `${item.host}${item.path} (${fmt(item.events)})`).join(", ")}`);
    }
    if (traffic.topWafRules.length) {
      attacked.push(
        `WAF rules: ${traffic.topWafRules.map((item) => `${item.ruleId}${item.message ? ` ${item.message}` : ""} (${fmt(item.events)})`).join(", ")}`
      );
    }
    if (traffic.topSourceCountries.length) {
      attacked.push(`Source countries: ${traffic.topSourceCountries.map((item) => `${item.country} (${fmt(item.events)})`).join(", ")}`);
    }
    if (traffic.topSourceNetworks?.length) {
      attacked.push(
        `Source networks: ${traffic.topSourceNetworks.map((item) => `AS${item.asn} ${item.organization} (${fmt(item.events)})`).join(", ")}`
      );
    }
    sections.push({ heading: "Most attacked", kind: "list", lines: attacked.length ? attacked : ["No WAF events or blocked requests."] });

    const fresh: string[] = [];
    if (traffic.newCountries) {
      fresh.push(
        traffic.newCountries.length
          ? `Countries: ${traffic.newCountries.map((item) => `${item.country} (${plural(item.requests, "request")})`).join(", ")}`
          : "No new countries."
      );
    }
    if (traffic.newNetworks) {
      fresh.push(
        traffic.newNetworks.length
          ? `Networks: ${traffic.newNetworks.map((item) => `AS${item.asn} ${item.organization} (${plural(item.requests, "request")})`).join(", ")}`
          : "No new networks."
      );
    }
    if (fresh.length) sections.push({ heading: "New sources compared with the previous 7 days", kind: "list", lines: fresh });
  } else {
    sections.push({
      heading: "Traffic and blocked requests",
      kind: "paragraph",
      lines: [facts.analytics.note ?? "Traffic figures are not available."],
    });
  }

  const certs = facts.certificates;
  sections.push({
    heading: `Certificates expiring within ${certs.withinDays} days`,
    kind: "list",
    lines: certs.expiring.length
      ? certs.expiring.map((cert) =>
          `${cert.kind} "${cert.name}" ${cert.expired ? `expired on ${day(cert.expiresAt)}` : `expires in ${plural(Math.max(cert.daysLeft, 0), "day")} (${day(cert.expiresAt)})`}`
        )
      : ["None (ACME certificates are renewed by Caddy and are not listed)."],
  });

  if (certs.attention?.length) sections.push({
    heading: "Certificate availability and validation",
    kind: "list",
    lines: certs.attention.map((cert) => `${cert.kind} "${cert.name}": ${cert.state}. ${cert.message}`),
  });

  const changes = facts.configChanges;
  sections.push({
    heading: `Configuration changes: ${fmt(changes.total)}`,
    kind: "list",
    lines: changes.total === 0
      ? ["No changes."]
      : [
          ...changes.recent.map((change) => `${at(change.at)} ${change.actor}: ${change.summary}`),
          ...(changes.total > changes.recent.length ? [`and ${fmt(changes.total - changes.recent.length)} more in the audit log`] : []),
        ],
  });

  const alerts = facts.alerts;
  sections.push({
    heading: `Alerts fired: ${fmt(alerts.fired)}`,
    kind: "list",
    lines: alerts.fired === 0
      ? ["No alerts fired."]
      : [
          ...alerts.recent.map((alert) => `${at(alert.at)} [${alert.severity}] ${alert.title}`),
          ...(alerts.fired > alerts.recent.length ? [`and ${fmt(alerts.fired - alerts.recent.length)} more in the alert history`] : []),
          ...(alerts.resolved > 0 ? [`${plural(alerts.resolved, "alert")} resolved`] : []),
        ],
  });

  if (facts.notes.length) sections.push({ heading: "Notes", kind: "list", lines: facts.notes });
  return sections;
}

function sectionLines(section: DigestSection, max: number): string[] {
  return section.lines.map((line) => cleanText(line, max, section.kind === "paragraph"));
}

/** Plain text for e-mail, ntfy and webhooks. */
export function renderDigestText(content: DigestContent): string {
  const parts = [digestTitle(content), digestIntro(content)];
  for (const section of digestSections(content)) {
    const lines = sectionLines(section, 2000);
    parts.push(
      "",
      section.heading,
      ...(section.kind === "list" ? lines.map((line) => `- ${line}`) : lines)
    );
  }
  parts.push("", `Sent by ${brandName()}`);
  return parts.join("\n");
}

export function renderDigestEmail(content: DigestContent): { subject: string; text: string; html: string } {
  const subject = cleanText(`[${brandName()}] ${digestTitle(content)}`, 250);
  const html: string[] = [
    `<h2 style="margin:0 0 8px">${escapeHtml(digestTitle(content))}</h2>`,
    `<p style="color:#666;margin:0 0 16px">${escapeHtml(digestIntro(content))}</p>`,
  ];
  for (const section of digestSections(content)) {
    const lines = sectionLines(section, 2000).map((line) => escapeHtml(line).replace(/\n/g, "<br>"));
    html.push(`<h3 style="margin:16px 0 4px">${escapeHtml(section.heading)}</h3>`);
    if (section.ai) {
      html.push(`<p style="color:#666;margin:0 0 4px"><em>Written by your AI model from the figures below; check it against them.</em></p>`);
    }
    html.push(section.kind === "list" ? `<ul style="margin:0;padding-left:20px">${lines.map((line) => `<li>${line}</li>`).join("")}</ul>` : `<p style="margin:0">${lines.join("<br>")}</p>`);
  }
  html.push(`<p style="color:#999;margin-top:24px">Sent by ${escapeHtml(brandName())}</p>`);
  return { subject, text: renderDigestText(content), html: html.join("\n") };
}

export function buildDigestSlackPayload(content: DigestContent): { text: string } {
  const parts = [`:bar_chart: *${escapeSlack(digestTitle(content))}*`, `_${escapeSlack(digestIntro(content))}_`];
  for (const section of digestSections(content)) {
    const lines = sectionLines(section, 1500).map(escapeSlack);
    parts.push("", `*${escapeSlack(section.heading)}*`, ...(section.kind === "list" ? lines.map((line) => `• ${line}`) : lines));
  }
  let text = parts.join("\n");
  if (text.length > SLACK_MAX_CHARS) text = `${text.slice(0, SLACK_MAX_CHARS - TRUNCATED.length - 1)}\n${TRUNCATED}`;
  return { text };
}

export function buildDigestTeamsPayload(content: DigestContent): Record<string, unknown> {
  const body: Record<string, unknown>[] = [
    { type: "TextBlock", text: escapeTeams(digestTitle(content)), weight: "Bolder", size: "Medium", wrap: true },
    { type: "TextBlock", text: escapeTeams(digestIntro(content)), isSubtle: true, wrap: true },
  ];
  for (const section of digestSections(content)) {
    const lines = sectionLines(section, 1500).map(escapeTeams);
    body.push(
      { type: "TextBlock", text: escapeTeams(section.heading), weight: "Bolder", spacing: "Medium", wrap: true },
      {
        type: "TextBlock",
        text: section.kind === "list" ? lines.map((line) => `- ${line}`).join("\n") : lines.join("\n\n"),
        wrap: true,
        ...(section.ai ? { isSubtle: true } : {}),
      }
    );
  }
  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body,
        },
      },
    ],
  };
}

/** Cuts `text` to at most `maxBytes` UTF-8 bytes, marking the cut. */
export function truncateUtf8(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  const budget = maxBytes - Buffer.byteLength(`\n${TRUNCATED}`, "utf8");
  let out = "";
  let used = 0;
  for (const char of text) {
    const size = Buffer.byteLength(char, "utf8");
    if (used + size > budget) break;
    out += char;
    used += size;
  }
  return `${out}\n${TRUNCATED}`;
}

export function buildDigestNtfyMessage(content: DigestContent, topic: string): Record<string, unknown> {
  return {
    topic,
    title: digestTitle(content),
    message: truncateUtf8(renderDigestText(content), NTFY_MAX_BYTES),
    priority: 3,
    tags: ["bar_chart"],
  };
}

export function buildDigestTelegramMessage(content: DigestContent, chatId: string): Record<string, unknown> {
  return {
    chat_id: chatId,
    text: truncateUtf8(`${digestTitle(content)}\n\n${renderDigestText(content)}`, NTFY_MAX_BYTES),
    disable_web_page_preview: true,
  };
}

export function buildDigestWebhookBody(content: DigestContent): Record<string, unknown> {
  return {
    version: 1,
    // An identifier receivers match on: it keeps the real name under white-label branding.
    source: BRAND_NAME.toLowerCase(),
    type: "digest",
    title: digestTitle(content),
    localDate: content.localDate,
    timeZone: content.timeZone,
    text: renderDigestText(content),
    facts: content.facts,
    narrative: content.narrative ? { label: AI_GENERATED_SUMMARY_LABEL, text: content.narrative } : null,
    at: content.generatedAt,
  };
}
