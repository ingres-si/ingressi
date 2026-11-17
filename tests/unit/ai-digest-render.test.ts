/**
 * Daily digest rendering per channel type: every section, escaping of values
 * that come from requests, the AI label, the no-ClickHouse variant and the
 * size limits of Slack and ntfy.
 */
import { describe, expect, it } from 'vitest';
import {
  buildDigestNtfyMessage,
  buildDigestSlackPayload,
  buildDigestTeamsPayload,
  buildDigestWebhookBody,
  digestSections,
  renderDigestEmail,
  renderDigestText,
  truncateUtf8,
  type DigestContent,
} from '@/ee/ai/digest-render';
import type { DigestFacts } from '@/ee/ai/digest-data';

const EVIL_HOST = '<script>alert(1)</script>.example.com';
const EVIL_PATH = '/login?<!channel>';

function facts(overrides: Partial<DigestFacts> = {}): DigestFacts {
  return {
    period: { from: '2026-10-01T06:00:00.000Z', to: '2026-10-02T06:00:00.000Z', hours: 24 },
    analytics: { status: 'ok', note: null },
    traffic: {
      requests: 12345,
      uniqueClients: 456,
      blocked: { total: 321, waf: 200, geo: 100, accessList: 21 },
      wafDetectedNotBlocked: 15,
      topAttackedHosts: [{ host: EVIL_HOST, events: 120 }, { host: 'app.example.com', events: 80 }],
      topAttackedPaths: [{ host: 'app.example.com', path: EVIL_PATH, events: 50 }],
      topWafRules: [{ ruleId: 942100, message: 'SQL Injection Attack Detected via libinjection', events: 40 }],
      topSourceCountries: [{ country: 'CN', events: 100 }],
      topSourceNetworks: [{ asn: 64500, organization: 'Example *Transit* Ltd', events: 80 }],
      newCountries: [{ country: 'BR', requests: 12 }],
      newNetworks: [],
    },
    certificates: { withinDays: 14, expiring: [{ kind: 'Certificate', name: 'example.com wildcard', expiresAt: '2026-10-11T00:00:00.000Z', daysLeft: 8, expired: false }] },
    configChanges: { total: 12, recent: [{ at: '2026-10-01T09:12:00.000Z', actor: 'admin', summary: 'Updated proxy host app' }] },
    alerts: { fired: 1, resolved: 1, recent: [{ at: '2026-10-01T10:00:00.000Z', severity: 'warning', title: 'WAF blocked 150 requests' }] },
    notes: [],
    ...overrides,
  };
}

function content(overrides: Partial<DigestContent> = {}): DigestContent {
  return {
    facts: facts(),
    narrative: 'Traffic was normal. Look at the SQL injection matches on app.example.com.',
    timeZone: 'Europe/Rome',
    localDate: '2026-10-02',
    generatedAt: '2026-10-02T06:00:00.000Z',
    ...overrides,
  };
}

describe('digest sections', () => {
  it('covers every section from aggregated facts', () => {
    const text = renderDigestText(content());
    expect(text).toContain('Daily security digest for 2026-10-02');
    expect(text).toContain('24 hours up to 2026-10-02 08:00 (Europe/Rome)');
    expect(text).toContain('AI-generated summary\nTraffic was normal.');
    expect(text).toContain('Requests: 12,345 from 456 clients');
    expect(text).toContain('Blocked: 321 (WAF 200, geo/ASN blocking 100, access lists 21)');
    expect(text).toContain('WAF matches that were not blocked: 15');
    expect(text).toContain('942100 SQL Injection Attack Detected via libinjection (40)');
    expect(text).toContain('Source countries: CN (100)');
    expect(text).toContain('AS64500 Example *Transit* Ltd (80)');
    expect(text).toContain('Countries: BR (12 requests)');
    expect(text).toContain('No new networks.');
    expect(text).toContain('Certificate "example.com wildcard" expires in 8 days (2026-10-11)');
    expect(text).toContain('Configuration changes: 12');
    expect(text).toContain('2026-10-01 11:12 admin: Updated proxy host app');
    expect(text).toContain('and 11 more in the audit log');
    expect(text).toContain('Alerts fired: 1');
    expect(text).toContain('[warning] WAF blocked 150 requests');
    expect(text).not.toMatch(/license/i);
  });

  it('says so when ClickHouse is not configured and still includes the rest', () => {
    const text = renderDigestText(content({
      narrative: null,
      facts: facts({ traffic: null, analytics: { status: 'disabled', note: 'ClickHouse analytics is not configured, so traffic, blocked-request and attack figures are not included.' } }),
    }));
    expect(text).toContain('ClickHouse analytics is not configured');
    expect(text).not.toContain('AI-generated');
    expect(text).not.toContain('Most attacked');
    expect(text).toContain('Certificates expiring within 14 days');
    expect(text).toContain('Alerts fired: 1');
  });

  it('labels only the narrative as AI-generated', () => {
    const sections = digestSections(content());
    expect(sections[0]).toMatchObject({ heading: 'AI-generated summary', ai: true });
    expect(sections.filter((section) => section.ai)).toHaveLength(1);
    expect(digestSections(content({ narrative: null })).some((section) => section.ai)).toBe(false);
  });
});

describe('digest formats per channel', () => {
  it('e-mail: HTML with every value escaped, plus the plain-text part', () => {
    const email = renderDigestEmail(content());
    expect(email.subject).toBe('[Ingressi] Daily security digest for 2026-10-02');
    expect(email.html).not.toContain('<script>');
    expect(email.html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;.example.com');
    expect(email.html).toContain('<h3 style="margin:16px 0 4px">AI-generated summary</h3>');
    expect(email.html).toContain('Written by your AI model');
    expect(email.text).toBe(renderDigestText(content()));
  });

  it('Slack: mrkdwn control characters escaped (no @channel mentions)', () => {
    const { text } = buildDigestSlackPayload(content());
    expect(text).toContain('*AI-generated summary*');
    expect(text).not.toContain('<!channel>');
    expect(text).toContain('&lt;!channel&gt;');
    expect(text).not.toContain('<script>');
  });

  it('Teams: an Adaptive Card with Markdown neutralised', () => {
    const card = buildDigestTeamsPayload(content()) as any;
    const blocks = card.attachments[0].content.body as { text: string }[];
    const all = blocks.map((block) => block.text).join('\n');
    expect(all).toContain('AI-generated summary');
    expect(all).toContain('Example \\*Transit\\* Ltd');
    expect(all).toContain('\\<script\\>');
  });

  it('ntfy: plain text within the size limit', () => {
    const message = buildDigestNtfyMessage(content(), 'ops') as any;
    expect(message).toMatchObject({ topic: 'ops', title: 'Daily security digest for 2026-10-02', priority: 3 });
    expect(message.message).toContain('AI-generated summary');
    const huge = content({ facts: facts({ configChanges: { total: 500, recent: Array.from({ length: 10 }, (_, i) => ({ at: '2026-10-01T09:12:00.000Z', actor: 'admin', summary: `Change ${i} ${'é'.repeat(400)}` })) } }) });
    const truncated = buildDigestNtfyMessage(huge, 'ops') as any;
    expect(Buffer.byteLength(truncated.message, 'utf8')).toBeLessThanOrEqual(3800);
    expect(truncated.message).toContain('shortened');
  });

  it('webhook: structured facts and a labeled narrative', () => {
    const body = buildDigestWebhookBody(content()) as any;
    expect(body).toMatchObject({ version: 1, source: 'ingressi', type: 'digest', localDate: '2026-10-02', timeZone: 'Europe/Rome' });
    expect(body.narrative).toEqual({ label: 'AI-generated summary', text: expect.stringContaining('Traffic was normal') });
    expect(body.facts.traffic.blocked.waf).toBe(200);
    expect(buildDigestWebhookBody(content({ narrative: null })).narrative).toBeNull();
  });

  it('truncates by UTF-8 bytes without splitting characters', () => {
    const out = truncateUtf8('€'.repeat(2000), 200);
    expect(Buffer.byteLength(out, 'utf8')).toBeLessThanOrEqual(200);
    expect(out).not.toContain('�');
    expect(truncateUtf8('short', 200)).toBe('short');
  });
});


describe('certificate availability rendering (issue 399)', () => {
  it('renders availability separately without inventing a zero-day expiry', () => {
    const text = renderDigestText(content({ facts: facts({ certificates: { withinDays: 14, expiring: [], attention: [{ kind: 'Managed certificate', name: 'missing.example', state: 'missing', message: 'No certificate available.' }] } }) }));
    expect(text).toContain('Certificate availability and validation');
    expect(text).toContain('missing.example": missing. No certificate available.');
    expect(text).not.toContain('expires in 0 days');
    expect(text).not.toMatch(/1970|Invalid Date/);
  });
});
