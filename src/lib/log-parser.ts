import { existsSync, statSync } from 'node:fs';
import type { BlockList } from 'node:net';
import { appDb } from './db';
import { logParseState } from './db/schema';
import { eq } from 'drizzle-orm';
import { insertTrafficEvents, type TrafficEventRow } from './clickhouse/client';
import { readLines as readLinesFrom } from './log-read';
import { config } from './config';
import { initGeoIp, lookupIp } from './analytics/geoip';
import { deriveOutcome } from './analytics/outcome';
import { userAgentFamily } from './analytics/user-agent';
import { WAF_TRANSACTION_LOG_FIELD } from './waf-log-fields';
import { getAddressRuleList, inAddressRules } from './analytics/address-rules';
import {
  collectWafLogLines,
  consumeWafViolation,
  createWafCorrelation,
  pruneWafCorrelation,
  type WafCorrelation,
} from './analytics/waf-correlation';
import { first } from '@/src/lib/db/ops';
import { creditFailedAnswers, failedAnswerChargeIds } from '@/ee/monetization/answer-credits';

const LOG_FILE = '/logs/access.log';
// Coraza's "WAF rule violation detected" lines (and the rules that matched)
// land here; read alongside the access log to tell WAF blocks apart.
const WAF_RULES_LOG = '/logs/waf-rules.log';
const BATCH_SIZE = 500;

let stopped = false;

// ── state helpers ────────────────────────────────────────────────────────────

async function getState(key: string): Promise<string | null> {
  const row = await first(appDb.select({ value: logParseState.value }).from(logParseState).where(eq(logParseState.key, key)).limit(1));
  return row?.value ?? null;
}

async function setState(key: string, value: string): Promise<void> {
  await appDb.insert(logParseState).values({ key, value }).onConflictDoUpdate({ target: logParseState.key, set: { value } });
}

// ── log parsing ──────────────────────────────────────────────────────────────

interface CaddyLogEntry {
  ts?: number;
  msg?: string;
  plugin?: string;
  // fields on "request blocked" entries (top-level)
  client_ip?: string;
  remote_addr?: string;
  method?: string;
  uri?: string;
  // fields on "handled request" entries
  status?: number;
  // Coraza's server-generated ID, evaluated by log_append after the WAF returns.
  [WAF_TRANSACTION_LOG_FIELD]?: unknown;
  size?: number;
  // seconds as a float (Caddy's default duration encoding), or a Go duration string
  duration?: unknown;
  resp_headers?: Record<string, string[]>;
  // added by the rate limit error route (caddy-rate-limit.ts) to requests the limiter refused
  rate_limit_zone?: unknown;
  // added by an access list (caddy-access-lists.ts) to requests it denied itself
  access_list?: unknown;
  request?: {
    client_ip?: string;
    remote_ip?: string;
    host?: string;
    method?: string;
    uri?: string;
    proto?: string;
    headers?: Record<string, string[]>;
  };
}

type BlockedSignatures = Set<string> | Map<string, number>;

function consumeBlockedSignature(blocked: BlockedSignatures, key: string): boolean {
  if (blocked instanceof Map) {
    const count = blocked.get(key) ?? 0;
    if (count <= 0) return false;
    if (count === 1) blocked.delete(key);
    else blocked.set(key, count - 1);
    return true;
  }
  return blocked.has(key);
}

// How long an unmatched "request blocked" signature is carried across parse
// passes while waiting for its paired "handled request" row to be written.
const BLOCKED_CARRYOVER_WINDOW_SEC = 120;

// Signatures collected in one pass but not yet matched to a "handled request"
// row. caddy-blocker logs "request blocked" immediately before Caddy logs the
// "handled request", so a parse-tick boundary can fall between the two lines.
// Carrying the unmatched signatures forward lets the next pass mark them.
let pendingBlocked: Map<string, number> = new Map();

// Build counted signatures from caddy-blocker's "request blocked" entries so we
// can mark the corresponding "handled request" rows correctly instead of using
// status === 403 (which would also catch legitimate upstream 403s). Pass an
// existing map via `into` to merge new signatures onto carried-over ones.
export function collectBlockedSignatures(lines: string[], into?: Map<string, number>): Map<string, number> {
  const blocked = into ?? new Map<string, number>();
  for (const line of lines) {
    let entry: CaddyLogEntry;
    try { entry = JSON.parse(line.trim()); } catch { continue; }
    if (entry.msg !== 'request blocked' || entry.plugin !== 'caddy-blocker') continue;
    const ts = Math.floor(entry.ts ?? 0);
    // Fail-closed blocks (client address unknown) log only remote_addr.
    const clientIp = entry.client_ip ?? remoteAddrIp(entry.remote_addr);
    const key = `${ts}|${clientIp}|${entry.method ?? ''}|${entry.uri ?? ''}`;
    blocked.set(key, (blocked.get(key) ?? 0) + 1);
  }
  return blocked;
}

/** The IP of a Go "host:port" remote address ("[::1]:443" → "::1"). */
function remoteAddrIp(remoteAddr: string | undefined): string {
  if (!remoteAddr) return '';
  const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(remoteAddr);
  if (v6) return v6[1];
  const colon = remoteAddr.lastIndexOf(':');
  return colon > 0 && remoteAddr.indexOf(':') === colon ? remoteAddr.slice(0, colon) : remoteAddr;
}

/**
 * Consumes the "request blocked" signature of a handled request. caddy-
 * blocker logs it while handling the request and Caddy the access log line
 * when the request is done, so the block may be a second or two older than
 * the line when the request straddles a second boundary.
 */
function consumeBlockedSignatureNear(blocked: BlockedSignatures, ts: number, rest: string): boolean {
  for (let back = 0; back <= 2; back++) {
    if (consumeBlockedSignature(blocked, `${ts - back}|${rest}`)) return true;
  }
  return false;
}

/** Caddy's `duration` in whole milliseconds (seconds as a float, or a Go duration string). */
export function durationMs(value: unknown): number {
  let ms = 0;
  if (typeof value === 'number' && Number.isFinite(value)) {
    ms = value * 1000;
  } else if (typeof value === 'string') {
    const units: Record<string, number> = { ns: 1e-6, us: 1e-3, 'µs': 1e-3, 'μs': 1e-3, ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
    const parts = value.trim().matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g);
    for (const [, amount, unit] of parts) ms += Number(amount) * units[unit];
  }
  if (!Number.isFinite(ms) || ms <= 0) return 0;
  return Math.min(Math.round(ms), 0xffffffff);
}

/** What parseLine correlates a "handled request" line with, beyond caddy-blocker signatures. */
export type ParseContext = {
  /** WAF violations and matched rules read from waf-rules.log (waf-correlation.ts). */
  waf?: WafCorrelation;
  /** Address rules of the geoblocking settings (address-rules.ts). */
  addressRules?: BlockList | null;
  /** The dashboard's forward-auth portal URL (BASE_URL + "/portal"). */
  portalUrl?: string | null;
};

// Drop carried-over signatures older than the carry-over window so the pending
// map can't grow unbounded when a "request blocked" line never gets a paired
// "handled request" row. The timestamp is the first field of the key.
export function pruneBlockedSignatures(blocked: Map<string, number>, refTs: number): Map<string, number> {
  const cutoff = refTs - BLOCKED_CARRYOVER_WINDOW_SEC;
  for (const [key, count] of blocked) {
    if (count <= 0) { blocked.delete(key); continue; }
    const ts = Number(key.slice(0, key.indexOf('|')));
    if (Number.isFinite(ts) && ts < cutoff) blocked.delete(key);
  }
  return blocked;
}

/** True for a request an access list denied with its own response (not caddy-blocker's). */
export function isAccessListDenial(entry: { access_list?: unknown }): boolean {
  return typeof entry.access_list === 'string' && entry.access_list.length > 0;
}

export function parseLine(line: string, blocked: BlockedSignatures, context: ParseContext = {}): TrafficEventRow | null {
  let entry: CaddyLogEntry;
  try {
    entry = JSON.parse(line);
  } catch {
    return null;
  }

  // Only process "handled request" log entries
  if (entry.msg !== 'handled request') return null;

  const req = entry.request ?? {};
  const clientIp = req.client_ip || req.remote_ip || '';
  const ts = Math.floor(entry.ts ?? Date.now() / 1000);
  const method = req.method ?? '';
  const uri = req.uri ?? '';
  const host = req.host ?? '';
  const status = entry.status ?? 0;
  const userAgent = req.headers?.['User-Agent']?.[0] ?? '';

  // caddy-blocker logs its blocks separately (matched by signature); an access
  // list's own denials carry their marker on the request's entry.
  const accessListDenied = isAccessListDenial(entry);
  const isBlocked = consumeBlockedSignatureNear(blocked, ts, `${clientIp}|${method}|${uri}`) || accessListDenied;
  // Only Caddy's own limiter names a zone; an upstream's 429 carries none.
  const isRateLimited = status === 429 && typeof entry.rate_limit_zone === 'string' && entry.rate_limit_zone.length > 0;
  // A blocked request never reached the WAF, so only look for a violation otherwise.
  const waf = isBlocked || isRateLimited ? null : consumeWafViolation(context.waf, entry[WAF_TRANSACTION_LOG_FIELD]);
  const outcome = deriveOutcome({
    status,
    rateLimitZone: entry.rate_limit_zone,
    blockedByBlocker: isBlocked,
    addressRule: accessListDenied || (isBlocked && inAddressRules(context.addressRules, clientIp)),
    wafBlocked: waf !== null,
    respHeaders: entry.resp_headers,
    requestHost: host,
    portalUrl: context.portalUrl ?? null,
  });
  const ip = clientIp ? lookupIp(clientIp) : { country: null, asn: 0, asOrg: '' };

  return {
    ts,
    client_ip: clientIp,
    country_code: ip.country,
    host,
    method,
    uri,
    status,
    proto: req.proto ?? '',
    bytes_sent: entry.size ?? 0,
    user_agent: userAgent,
    is_blocked: isBlocked,
    is_rate_limited: isRateLimited,
    asn: ip.asn,
    as_org: ip.asOrg,
    outcome,
    duration_ms: durationMs(entry.duration),
    ua_family: userAgentFamily(userAgent),
    waf_rule_id: waf?.ruleId ?? 0,
  };
}

// Re-exported so existing callers/tests keep importing `readLines` from here.
// The implementation lives in ./log-read because waf-log-parser needs the same
// newline-safe offset accounting.
export async function readLines(startOffset: number, file: string = LOG_FILE): Promise<{ lines: string[]; newOffset: number }> {
  return readLinesFrom(startOffset, file);
}

async function insertBatch(rows: TrafficEventRow[]): Promise<void> {
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    await insertTrafficEvents(rows.slice(i, i + BATCH_SIZE));
  }
}

// ── public API ───────────────────────────────────────────────────────────────

const LOG_DIR = '/logs';

/**
 * The parsers run on one dashboard container (the leader of PostgreSQL
 * replicas, or the only one) and read Caddy's logs from /logs. A container
 * without Caddy's log volume finds no file and would collect nothing without
 * a word, for as long as it leads. Production containers mount the volume
 * (docker-compose.yml); without it this says so each time the parser starts
 * (ee/docs/high-availability.md, PostgreSQL replicas, volumes).
 */
export function missingLogDirectoryWarning(
  dir: string = LOG_DIR,
  production: boolean = process.env.NODE_ENV === 'production'
): string | null {
  if (!production || existsSync(dir)) return null;
  return (
    `[log-parser] Caddy's log directory ${dir} is not mounted in this container: no traffic or WAF events are ` +
    "collected while it runs the background jobs. Mount Caddy's log volume on every dashboard replica."
  );
}

export async function initLogParser(): Promise<void> {
  await initGeoIp();
  const warning = missingLogDirectoryWarning();
  if (warning) console.error(warning);
  console.log('[log-parser] initialized');
}

// WAF violations read from waf-rules.log whose access log line has not been
// read yet (waf-correlation.ts).
let pendingWaf: WafCorrelation = createWafCorrelation();

// On the first pass (no stored position) only the end of waf-rules.log is
// read: violations of requests ingested long ago would never be matched.
const WAF_RULES_FIRST_READ_BYTES = 1024 * 1024;

/** New lines of waf-rules.log since the last pass. */
async function readNewWafRuleLines(): Promise<string[]> {
  if (!existsSync(WAF_RULES_LOG)) return [];
  let size: number;
  try {
    size = statSync(WAF_RULES_LOG).size;
  } catch {
    return [];
  }
  const storedOffset = await getState('access_waf_rules_offset');
  const storedSize = parseInt(await getState('access_waf_rules_size') ?? '0', 10);
  // First pass: the last megabyte (a line cut in half there fails to parse
  // and is skipped). Rotated (the file shrank): start over.
  const start = storedOffset === null
    ? Math.max(0, size - WAF_RULES_FIRST_READ_BYTES)
    : size < storedSize ? 0 : parseInt(storedOffset, 10) || 0;
  const { lines, newOffset } = await readLinesFrom(start, WAF_RULES_LOG);
  await setState('access_waf_rules_offset', String(newOffset));
  await setState('access_waf_rules_size', String(size));
  return lines;
}

function portalUrl(): string | null {
  try {
    return new URL('/portal', config.baseUrl).toString();
  } catch {
    return null;
  }
}

export async function parseNewLogEntries(): Promise<void> {
  if (stopped) return;
  if (!existsSync(LOG_FILE)) return;

  try {
    const storedOffset = parseInt(await getState('access_log_offset') ?? '0', 10);
    const storedSize = parseInt(await getState('access_log_size') ?? '0', 10);

    let currentSize: number;
    try {
      currentSize = statSync(LOG_FILE).size;
    } catch {
      return;
    }

    // Detect log rotation: file shrank
    const startOffset = currentSize < storedSize ? 0 : storedOffset;

    const { lines, newOffset } = await readLines(startOffset);

    // Read waf-rules.log AFTER the access log: the violation of every request
    // read above was logged before its access log line (waf-correlation.ts).
    let wafLines: string[] = [];
    try {
      wafLines = await readNewWafRuleLines();
    } catch (err) {
      console.warn('[log-parser] could not read waf-rules.log:', (err as Error).message);
    }
    collectWafLogLines(wafLines, pendingWaf);

    // API monetization: requests answered with a 5xx on plans that credit
    // failed answers are credited back, once per charge id, before the
    // position below is stored (a pass repeated after a crash credits
    // nothing twice). Never throws; what fails is retried next pass.
    await creditFailedAnswers(failedAnswerChargeIds(lines));

    if (lines.length > 0) {
      // Merge any signatures carried over from the previous pass (a "request
      // blocked" line whose "handled request" row hadn't been written yet).
      const blocked = collectBlockedSignatures(lines, pendingBlocked);
      const context: ParseContext = {
        waf: pendingWaf,
        addressRules: await getAddressRuleList().catch(() => null),
        portalUrl: portalUrl(),
      };
      const rows = lines.map(l => parseLine(l, blocked, context)).filter(r => r !== null);
      await insertBatch(rows);
      // Whatever signatures weren't consumed are unmatched blocks; carry the
      // recent ones forward and drop stale ones so the map can't grow forever.
      const latestTs = rows.length ? Math.max(...rows.map(r => r.ts)) : Math.floor(Date.now() / 1000);
      pendingBlocked = pruneBlockedSignatures(blocked, latestTs);
      pendingWaf = pruneWafCorrelation(pendingWaf, latestTs);
      const mitigated = rows.reduce((n, r) => n + (r.outcome && r.outcome !== 'served' ? 1 : 0), 0);
      console.log(`[log-parser] inserted ${rows.length} traffic events (${mitigated} mitigated)`);
    } else {
      pendingWaf = pruneWafCorrelation(pendingWaf, Math.floor(Date.now() / 1000));
    }

    await setState('access_log_offset', String(newOffset));
    await setState('access_log_size', String(currentSize));
  } catch (err) {
    console.error('[log-parser] error during parse:', err);
  }
}

export function stopLogParser(): void {
  stopped = true;
}
