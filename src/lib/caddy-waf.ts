/**
 * WAF handler builder and effective-config resolver for Caddy.
 * Extracted from caddy.ts so these functions can be unit tested.
 */
import { type WafSettings } from "./settings";
import { type WafHostConfig } from "./models/proxy-hosts";
import { crsTuningDirectives, resolveWafTuning, WAF_TUNING_KEYS, type WafTuningSettings } from "./waf-tuning";
import { buildExclusionDirectives, type WafExclusionRule } from "./waf-exclusions";

// ---------------------------------------------------------------------------
// Request body limits
// ---------------------------------------------------------------------------

/**
 * Coraza refuses to build a WAF whose request body limit exceeds 1 GiB
 * (internal/corazawaf/waf.go — "request body limit should be at most 1GiB").
 * coraza-caddy constructs its WAF while Caddy is loading the config, so a
 * single out-of-range value makes Caddy reject the ENTIRE config document —
 * every host goes unapplied, not just the offending one. Never emit a value
 * above this.
 */
export const CORAZA_MAX_BODY_LIMIT = 1_073_741_824; // 1 GiB

/** Below ~1 KiB the limit is meaningless and only serves to break uploads. */
export const CORAZA_MIN_BODY_LIMIT = 1_024;

/** Coraza's built-in default when no SecRequestBodyLimit directive is parsed. */
export const CORAZA_DEFAULT_BODY_LIMIT = 134_217_728; // 128 MiB

/**
 * SecRequestBodyLimit / SecRequestBodyInMemoryLimit set by
 * `@coraza.conf-recommended`, which we Include when load_owasp_crs is on.
 * The 12.5 MiB limit is why large uploads (Nextcloud/Immich chunks) fail with
 * the CRS enabled while the same host works with it off.
 */
export const CRS_BODY_LIMIT = 13_107_200; // 12.5 MiB
export const CRS_IN_MEMORY_BODY_LIMIT = 131_072; // 128 KiB

/** True when `value` is a byte count Coraza will accept for a body limit. */
export function isValidBodyLimit(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= CORAZA_MIN_BODY_LIMIT &&
    value <= CORAZA_MAX_BODY_LIMIT
  );
}

export function bodyLimitRangeMessage(label: string): string {
  return `${label} must be an integer between ${CORAZA_MIN_BODY_LIMIT} and ${CORAZA_MAX_BODY_LIMIT} bytes (1 GiB is Coraza's hard maximum)`;
}

/**
 * The settings are stored in bytes (what SecLang takes), but the forms ask for
 * MiB — nobody sizes an upload limit in bytes. Anything finer stays reachable
 * through the custom directives.
 */
export const BYTES_PER_MIB = 1_048_576;
export const MIN_BODY_LIMIT_MIB = 1;
export const MAX_BODY_LIMIT_MIB = CORAZA_MAX_BODY_LIMIT / BYTES_PER_MIB; // 1024

export function bytesToMib(bytes: number | undefined): string {
  return typeof bytes === "number" && bytes > 0 ? String(Math.round(bytes / BYTES_PER_MIB)) : "";
}

/** Parses a MiB form field into bytes. Blank means "unset — inherit the default". */
export function parseBodyLimitMib(raw: unknown, label: string): number | undefined {
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  const mib = Number(raw.trim());
  if (!Number.isInteger(mib) || mib < MIN_BODY_LIMIT_MIB || mib > MAX_BODY_LIMIT_MIB) {
    throw new Error(`${label} must be a whole number of MiB between ${MIN_BODY_LIMIT_MIB} and ${MAX_BODY_LIMIT_MIB}`);
  }
  return mib * BYTES_PER_MIB;
}

/** SecRequestBody*Limit directives that carry a byte count. */
const BODY_LIMIT_DIRECTIVE =
  /^(SecRequestBodyLimit|SecRequestBodyNoFilesLimit|SecRequestBodyInMemoryLimit)\s+(\d+)\s*$/i;
const BODY_LIMIT_ACTION_DIRECTIVE = /^SecRequestBodyLimitAction\s+(?:Reject|ProcessPartial)\s*$/i;
// Coraza operators that load data from the container filesystem or execute a
// program (inspectFile). Matched case-insensitively, negated or not.
const FILE_OR_EXEC_OPERATOR =
  /@\s*(inspectFile|pmFromFile|pmf|ipMatchFromFile|ipMatchF|validateSchema)\b/i;
// The data-file operators that may instead read a file shipped inside the
// embedded coraza-coreruleset filesystem (e.g. `@pmFromFile
// @owasp_crs/scanners-user-agents.data`), spelt as Coraza v3.7.0 registers
// them: its operator lookup is case-sensitive, so `@pmfromfile` fails to parse.
const CRS_DATA_OPERATORS = ['pmFromFile', 'pmf', 'ipMatchFromFile', 'ipMatchF'];
// With load_owasp_crs, coraza-caddy reads SecLang data files through a merge
// of the embedded coraza-coreruleset filesystem over the OS filesystem, and an
// inline directive's relative argument is looked up as-is, so
// `@owasp_crs/<name>` is served from the embedded rule set. A name the rule
// set lacks fails to load, and Caddy then refuses the whole config, so only
// the *.data files under rules/@owasp_crs in coraza-coreruleset v4.25.0 (the
// version docker/caddy/go.mod pins) are accepted.
const CRS_DATA_FILE_PREFIX = '@owasp_crs/';
const CRS_DATA_FILES = new Set([
  'ai-critical-artifacts.data',
  'asp-dotnet-errors.data',
  'iis-errors.data',
  'java-classes.data',
  'lfi-os-files.data',
  'php-errors.data',
  'php-function-names-933150.data',
  'php-variables.data',
  'restricted-files.data',
  'restricted-upload.data',
  'ruby-errors.data',
  'scanners-user-agents.data',
  'sql-errors.data',
  'ssrf-no-scheme.data',
  'ssrf.data',
  'unix-shell-aliases.data',
  'unix-shell-builtins.data',
  'unix-shell.data',
  'web-shells-asp.data',
  'web-shells-php.data',
  'windows-powershell-commands.data',
].map((name) => `${CRS_DATA_FILE_PREFIX}${name}`));
// Coraza's setenv action calls os.Setenv on the Caddy process, and
// ctl:ruleEngine switches the rule engine for the rest of the transaction.
// Both are judged on the parsed action list (ruleActionsDropReason); these
// raw-text patterns are a second net that also allows the whitespace and
// quotes Coraza strips around an action key or value (U+0085 included, which
// JavaScript's \s does not match).
const SETENV_ACTION = /\bsetenv[\s\u0085]*:/i;
const CTL_RULE_ENGINE_ACTION = /ctl[\s\u0085]*:[\s\u0085'"\\]*ruleEngine/i;
const SETENV_REASON = 'setenv is not allowed (it changes environment variables of the Caddy process)';
const CTL_RULE_ENGINE_REASON = 'ctl:ruleEngine is not allowed (it can conditionally disable the WAF)';
// SecRule and SecAction create rules, so they are the directives a pending
// `chain` attaches to. SecMarker also adds a rule and ends a pending chain.
const RULE_DIRECTIVE = /^Sec(?:Rule|Action)\s/i;
const MARKER_DIRECTIVE = /^SecMarker\s/i;
// Directives whose action list Coraza parses (SecDefaultAction's actions are
// merged into every later rule of its phase).
const ACTION_LIST_DIRECTIVE = /^Sec(?:Rule|Action|DefaultAction)\s/i;
// Go's unicode.IsSpace set, which strings.TrimSpace strips from every SecLang
// line and action key/value: JavaScript's \s minus U+FEFF, plus U+0085.
const GO_SPACE = '\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';
const GO_TRIM = new RegExp(`^[${GO_SPACE}]+|[${GO_SPACE}]+$`, 'g');

/** Go's strings.TrimSpace. */
function goTrimSpace(s: string): string {
  return s.replace(GO_TRIM, '');
}

/**
 * Returns the first custom directive whose byte count Coraza would reject, or
 * null when every body-limit line is in range. Input layers call this so the
 * user gets a precise error at save time instead of a silent drop here plus an
 * opaque "Caddy rejected configuration" later.
 */
export function findInvalidBodyLimitDirective(directives: string | null | undefined): string | null {
  if (!directives?.trim()) return null;
  for (const line of directives.split('\n')) {
    const trimmed = goTrimSpace(line);
    if (isOutOfRangeBodyLimit(trimmed)) return trimmed;
  }
  return null;
}

function isOutOfRangeBodyLimit(trimmedLine: string): boolean {
  const match = BODY_LIMIT_DIRECTIVE.exec(trimmedLine);
  return match !== null && !isValidBodyLimit(Number(match[2]));
}

/** A custom SecLang line Ingressi chose not to send to Caddy, plus why. */
export interface DroppedWafDirective {
  line: string;
  reason: string;
}

export interface CustomDirectiveFilterOptions {
  /**
   * Whether the WAF handler these directives end up in loads the OWASP CRS
   * (and with it the embedded `@owasp_crs/` filesystem). `false` drops rules
   * that read CRS data files; leave it undefined when the caller can't know —
   * e.g. a merge-mode host that inherits the global setting — and
   * buildWafHandler makes the final call with the effective value.
   */
  crsLoaded?: boolean;
  /**
   * Custom directives the WAF handler reads before these ones — the global
   * directives, for a merge-mode host. Their own lines are never reported,
   * but the rule ids they use are taken and a chain they leave open continues
   * into these lines, as in the merged handler.
   */
  precedingDirectives?: string | null;
  /**
   * Rule ids the generated directives of the handler already take (CRS
   * tuning, rule exclusions). A custom rule reusing one is dropped: Coraza
   * refuses a duplicate id, and Caddy then refuses the whole config.
   */
  reservedRuleIds?: ReadonlySet<number>;
}

// SecRule* variants that are NOT plain SecRule (must be rejected)
const BLOCKED_SECRULE_PREFIXES = [
  /^SecRuleEngine\s/i,
  /^SecRuleRemoveById\s/i,
  /^SecRuleRemoveByTag\s/i,
  /^SecRuleRemoveByMsg\s/i,
  /^SecRuleUpdateActionById\s/i,
  /^SecRuleUpdateTargetById\s/i,
];
const ALLOWED_PREFIXES = [
  /^SecRule\s/,
  /^SecAction\s/,
  /^SecMarker\s/,
  /^SecDefaultAction\s/,
];

/**
 * Coraza's cutQuotedString: the leading double-quoted string of `s` (quotes
 * included) and what follows it, honouring backslash escapes.
 */
function cutQuotedString(s: string): { quoted: string; rest: string } | null {
  if (!s.startsWith('"')) return null;
  let backslashes = 0;
  for (let i = 1; i < s.length; i++) {
    if (s[i] !== '"') {
      backslashes = s[i] === '\\' ? backslashes + 1 : 0;
      continue;
    }
    if (backslashes % 2 === 1) {
      backslashes = 0;
      continue;
    }
    return { quoted: s.slice(0, i + 1), rest: s.slice(i + 1) };
  }
  return null;
}

/** Go's strings.Trim(s, char) for a single character. */
function trimChar(s: string, char: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && s[start] === char) start++;
  while (end > start && s[end - 1] === char) end--;
  return s.slice(start, end);
}

/**
 * Splits a SecRule / SecAction / SecDefaultAction line into its operator
 * (SecRule only, escaped quotes unescaped) and action list, following
 * Coraza's seclang parser. Null when Coraza would not parse it either.
 */
function parseRuleParts(text: string): { operator: string | null; actions: string } | null {
  const space = text.indexOf(' ');
  if (space < 0) return null;
  const directive = text.slice(0, space).toLowerCase();
  let opts = text.slice(space + 1);
  // evaluateLine strips every surrounding quote when the options are quoted.
  if (opts.length >= 3 && opts.startsWith('"') && opts.endsWith('"')) opts = trimChar(opts, '"');

  if (directive === 'secaction' || directive === 'secdefaultaction') {
    const quoted = opts.length >= 2 && (opts[0] === '"' || opts[0] === "'") && opts.endsWith(opts[0]);
    return { operator: null, actions: quoted ? opts.slice(1, -1) : opts };
  }
  if (directive !== 'secrule') return null;

  const data = trimChar(opts, ' ');
  const varsEnd = data.indexOf(' ');
  if (varsEnd < 0) return null;
  const operator = cutQuotedString(data.slice(varsEnd + 1).replace(/^ +/, ''));
  if (!operator) return null;
  const rest = operator.rest.replace(/^ +/, '');
  if (rest && (rest.length < 2 || !rest.startsWith('"') || !rest.endsWith('"'))) return null;
  return {
    operator: operator.quoted.slice(1, -1).replace(/\\"/g, '"'),
    actions: rest ? rest.slice(1, -1) : '',
  };
}

/** Coraza's MaybeRemoveQuotes: strips one pair of matching surrounding quotes. */
function maybeRemoveQuotes(s: string): string {
  if (s.length < 2 || (s[0] !== '"' && s[0] !== "'") || !s.endsWith(s[0])) return s;
  return s.slice(1, -1);
}

/**
 * A SecLang action list split the way Coraza's parseActions and
 * appendRuleAction split it: commas and colons inside single quotes or after
 * a backslash don't count, keys are Go-trimmed and lower-cased, and values
 * are Go-trimmed and lose one pair of surrounding quotes.
 */
function parseActionList(actions: string): { key: string; value: string }[] {
  const parsed: { key: string; value: string }[] = [];
  let beforeKey = -1;
  let afterKey = -1;
  let inQuotes = false;
  const add = (end: number) => {
    parsed.push({
      key: goTrimSpace(actions.slice(beforeKey + 1, afterKey === -1 ? end : afterKey)).toLowerCase(),
      value: afterKey === -1 ? '' : maybeRemoveQuotes(goTrimSpace(actions.slice(afterKey + 1, end))),
    });
  };
  for (let i = 1; i < actions.length; i++) {
    if (actions[i - 1] === '\\') continue;
    const c = actions[i];
    if (c === "'") {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) continue;
    if (c === ':' && afterKey === -1) {
      afterKey = i;
    } else if (c === ',') {
      add(i);
      beforeKey = i;
      afterKey = -1;
    }
  }
  add(actions.length);
  return parsed;
}

/** True when a rule directive carries the `chain` action. */
function hasChainAction(text: string): boolean {
  const parts = parseRuleParts(text);
  // Unparseable lines fail in Coraza too; err toward treating them as chained
  // so a partial drop takes the neighbouring rule with it.
  if (!parts) return /(?:^|[\s",])chain\s*(?:[,"]|$)/i.test(text);
  return parseActionList(parts.actions).some(({ key }) => key === 'chain');
}

/**
 * True when a rule directive is an `allow` rule pinned to phase 1. Such a rule
 * only works ahead of the CRS: phase 1 rules run in file order, and `allow`
 * skips the rules after it.
 */
function isPhase1AllowRule(text: string): boolean {
  const parts = parseRuleParts(text);
  if (!parts) return false;
  const actions = parseActionList(parts.actions);
  const phase = actions.filter(({ key }) => key === 'phase').pop()?.value.toLowerCase();
  return (phase === '1' || phase === 'request') && actions.some(({ key }) => key === 'allow');
}

/**
 * Splits already-filtered custom directive lines into the phase 1 `allow`
 * rules (with their chain children), which must precede the CRS to take
 * effect, and everything else, which keeps its order.
 */
export function splitEarlyAllowRules(lines: string[]): { early: string[]; rest: string[] } {
  const trimmed = lines.map(goTrimSpace);
  const { units } = directiveUnits(trimmed);
  const early: string[] = [];
  const rest: string[] = [];
  const claimed = new Set<number>();
  let chaining = false;
  let chainEarly = false;
  for (const unit of units) {
    const text = joinUnit(unit.map((i) => trimmed[i]));
    if (!RULE_DIRECTIVE.test(text)) { chaining = false; continue; }
    const isEarly: boolean = chaining ? chainEarly : isPhase1AllowRule(text);
    if (!chaining) chainEarly = isEarly;
    chaining = hasChainAction(text);
    if (isEarly) {
      for (const i of unit) claimed.add(i);
      early.push(...unit.map((i) => lines[i]));
    }
  }
  lines.forEach((line, i) => { if (!claimed.has(i)) rest.push(line); });
  return { early, rest };
}

/**
 * The rule id a SecRule / SecAction directive sets, or null when it sets
 * none. Coraza's id action reads its value with strconv.Atoi, so `id:'09001'`
 * is rule 9001; with several id actions the last one wins.
 */
function ruleIdOf(text: string): number | null {
  const parts = parseRuleParts(text);
  if (!parts) return null;
  let id: number | null = null;
  for (const { key, value } of parseActionList(parts.actions)) {
    if (key !== 'id' || !/^[+-]?\d+$/.test(value)) continue;
    const parsed = Number(value);
    id = Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
  }
  return id;
}

/**
 * Why a SecRule / SecAction / SecDefaultAction directive is dropped, judged
 * on its action list as Coraza parses it, or null when it is allowed. A
 * directive this parser can't split is dropped too: Coraza would refuse it,
 * and with it the whole WAF config, and its actions can't be checked.
 */
function ruleActionsDropReason(text: string): string | null {
  if (!ACTION_LIST_DIRECTIVE.test(text)) return null;
  const parts = parseRuleParts(text);
  if (!parts) {
    return 'Coraza cannot parse it (a rule it rejects makes Caddy refuse the whole config)';
  }
  for (const { key, value } of parseActionList(parts.actions)) {
    if (key === 'setenv') return SETENV_REASON;
    if (key === 'ctl' && goTrimSpace(value).toLowerCase().startsWith('ruleengine')) {
      return CTL_RULE_ENGINE_REASON;
    }
  }
  return null;
}

/**
 * Why a data-file operator on this line is dropped, or null when it only
 * reads a data file from the embedded CRS filesystem that will be loaded.
 */
function fileOperatorDropReason(line: string, options: CustomDirectiveFilterOptions): string | null {
  const matches = [...line.matchAll(new RegExp(FILE_OR_EXEC_OPERATOR.source, 'gi'))];
  if (matches.length === 0) return null;
  const generic = `@${matches[0][1]} is not allowed (it reads files or runs programs inside the container)`;
  if (matches.length > 1) return generic;

  const operator = parseRuleParts(line)?.operator;
  if (!operator || !/^!?@/.test(operator)) return generic;
  // Split the way Coraza's ParseOperator does: at the first space, trimmed.
  const space = operator.indexOf(' ');
  const name = goTrimSpace(space < 0 ? operator : operator.slice(0, space)).replace(/^!?@/, '');
  const argument = space < 0 ? '' : goTrimSpace(operator.slice(space + 1));
  if (!argument.startsWith(CRS_DATA_FILE_PREFIX)) return generic;
  if (!CRS_DATA_OPERATORS.includes(name)) {
    const registered = CRS_DATA_OPERATORS.find((op) => op.toLowerCase() === name.toLowerCase());
    return registered
      ? `@${name} is not a Coraza operator (operator names are case-sensitive: use @${registered})`
      : generic;
  }
  if (!CRS_DATA_FILES.has(argument)) {
    return `${argument} is not a data file of the embedded OWASP CRS (coraza-coreruleset v4.25.0)`;
  }
  if (options.crsLoaded === false) {
    return `${argument} is an embedded OWASP CRS data file, which only exists when the OWASP CRS is loaded`;
  }
  return null;
}

/** Why a single non-comment line is dropped, or null when it is allowed. */
function lineDropReason(trimmed: string, options: CustomDirectiveFilterOptions): string | null {
  // Reject Include directives (prevents file inclusion from container filesystem)
  if (/^Include\s/i.test(trimmed)) {
    return 'Include is not allowed (prevents reading arbitrary files from the container filesystem)';
  }
  // Body limits are allowed, but only inside the range Coraza accepts —
  // an out-of-range value would make Caddy reject the whole config
  // document. Input validation reports these; dropping here is the net.
  // (SecRequestBodyNoFilesLimit parses but is not enforced by Coraza:
  // corazawaf/coraza#896. Kept accepted so existing configs keep loading.)
  const bodyLimit = BODY_LIMIT_DIRECTIVE.exec(trimmed);
  if (bodyLimit) {
    return isValidBodyLimit(Number(bodyLimit[2]))
      ? null
      : `body limit is out of range — ${bodyLimitRangeMessage('the byte count')}`;
  }
  if (BODY_LIMIT_ACTION_DIRECTIVE.test(trimmed)) return null;
  // Reject blocked SecRule* variants (e.g. SecRuleEngine, SecRuleUpdateActionById)
  // Checked before the generic allowlist so the reason is specific.
  if (BLOCKED_SECRULE_PREFIXES.some((pattern) => pattern.test(trimmed))) {
    return 'rule-mutation/engine directives are not allowed (they can disable WAF protections or override rule actions)';
  }
  // Check against allowlist
  if (!ALLOWED_PREFIXES.some((pattern) => pattern.test(trimmed))) {
    return 'not an allowed directive — only SecRule, SecAction, SecMarker, and SecDefaultAction are permitted';
  }
  // Reject ctl:ruleEngine inside allowed lines (can conditionally disable WAF)
  if (CTL_RULE_ENGINE_ACTION.test(trimmed)) return CTL_RULE_ENGINE_REASON;
  if (SETENV_ACTION.test(trimmed)) return SETENV_REASON;
  // Reject operators that read files or execute programs inside the Caddy
  // container (same rationale as Include above).
  return fileOperatorDropReason(trimmed, options);
}

/**
 * Groups line indexes into directives the way Coraza's parser assembles them:
 * blank and comment lines are skipped, a trailing backslash continues onto
 * the next line, and a line ending in a backtick opens a block that a line
 * starting with one closes. `open` holds the lines of a directive the text
 * never finishes; Coraza would join it onto whatever directive follows.
 */
function directiveUnits(trimmedLines: string[]): { units: number[][]; open: number[] | null } {
  const units: number[][] = [];
  let current: number[] = [];
  let inBackticks = false;
  trimmedLines.forEach((trimmed, index) => {
    if (!trimmed || trimmed.startsWith('#')) return;
    if (!inBackticks && trimmed.endsWith('`')) inBackticks = true;
    else if (inBackticks && trimmed.startsWith('`')) inBackticks = false;
    current.push(index);
    if (inBackticks || trimmed.endsWith('\\')) return;
    units.push(current);
    current = [];
  });
  return { units, open: current.length > 0 ? current : null };
}

/** The directive text Coraza evaluates for a unit of physical lines. */
function joinUnit(trimmedLines: string[]): string {
  let text = '';
  let inBackticks = false;
  for (const line of trimmedLines) {
    if (!inBackticks && line.endsWith('`')) inBackticks = true;
    else if (inBackticks && line.startsWith('`')) inBackticks = false;
    if (inBackticks) text += `${line}\n`;
    else text += line.endsWith('\\') ? line.slice(0, -1) : line;
  }
  return text;
}

/**
 * The strict allowlist that governs which user-supplied SecLang lines reach the
 * generated Caddy `waf` handler. Returns the lines that WILL be emitted
 * (`kept`) and the ones Ingressi will discard (`dropped`), each with a
 * human-readable reason.
 *
 * Lines are dropped per directive, not just per line: when any line of a
 * multi-line directive or of a `chain`ed rule is dropped, the rest of it goes
 * too. Keeping the remainder would hand Coraza a different rule — the next
 * kept SecRule becomes the chain child (a chain child with a disruptive action
 * fails to parse, and Caddy then rejects the whole config), a chain starter
 * with its children removed fires on its own match alone, and a continuation
 * backslash glues itself onto an unrelated directive. A directive left
 * unfinished at the end is dropped for the same reason.
 *
 * A rule whose id an earlier kept rule already uses is dropped as well, with
 * its chain: Coraza refuses a duplicate id, and Caddy then refuses the whole
 * config. Only the directives are compared; a custom rule reusing an OWASP
 * CRS rule id is not caught.
 *
 * Lines are trimmed and split the way Coraza's parser does it (Go whitespace,
 * U+0085 included), and SecRule / SecAction / SecDefaultAction are also
 * checked on their parsed action list, so spacing or quoting that Coraza
 * strips around an action can't hide it. Operator names and other rule
 * content are not checked beyond the operators that read files.
 *
 * buildWafHandler uses `kept` to build the handler (and logs `dropped`). The
 * validation layers use `dropped` to reject the input up front — the source of
 * "my WAF rule does nothing" reports (see discussion #146 re:
 * SecRuleUpdateActionById being dropped while SecRule works).
 */
export function filterCustomDirectives(
  raw: string | null | undefined,
  options: CustomDirectiveFilterOptions = {}
): { kept: string[]; dropped: DroppedWafDirective[] } {
  const preceding = options.precedingDirectives;
  // Joined the way resolveEffectiveWaf merges the global and host directives;
  // `raw` starts at line `firstOwnLine` of the joined text.
  const firstOwnLine = preceding && raw ? preceding.split('\n').length : 0;
  const { kept, dropped } = filterDirectiveLines(firstOwnLine > 0 ? `${preceding}\n${raw}` : raw, options);
  return {
    kept: kept.filter(({ index }) => index >= firstOwnLine).map(({ line }) => line),
    dropped: dropped.filter(({ index }) => index >= firstOwnLine).map(({ line, reason }) => ({ line, reason })),
  };
}

/**
 * filterCustomDirectives, with each line's index in `raw.split('\n')` so a
 * caller can tell which part of a joined text it came from.
 */
function filterDirectiveLines(
  raw: string | null | undefined,
  options: CustomDirectiveFilterOptions
): { kept: { line: string; index: number }[]; dropped: (DroppedWafDirective & { index: number })[] } {
  const kept: { line: string; index: number }[] = [];
  const dropped: (DroppedWafDirective & { index: number })[] = [];
  if (!raw?.trim()) return { kept, dropped };

  // Lines the trim below removes from the start.
  const offset = raw.slice(0, raw.length - raw.trimStart().length).split('\n').length - 1;
  const lines = raw.trim().split('\n');
  const trimmedLines = lines.map(goTrimSpace);
  // Empty lines and comments are always kept.
  const reasons: (string | null)[] = trimmedLines.map((trimmed) =>
    !trimmed || trimmed.startsWith('#') ? null : lineDropReason(trimmed, options)
  );
  const dropWith = (indexes: number[], what: string) => {
    const first = indexes.find((index) => reasons[index] !== null);
    if (first === undefined) return;
    for (const index of indexes) {
      reasons[index] ??= `part of a ${what} whose line "${trimmedLines[first]}" is dropped`;
    }
  };

  const { units, open } = directiveUnits(trimmedLines);
  if (open) units.push(open);
  const texts = units.map((unit) => joinUnit(unit.map((index) => trimmedLines[index])));
  units.forEach((unit, i) => {
    const reason = unit === open
      ? 'the directive is never finished (its last line continues with \\ or opens a ` block)'
      : ruleActionsDropReason(texts[i]);
    if (reason !== null && unit.every((index) => reasons[index] === null)) reasons[unit[0]] = reason;
    if (unit.length > 1) dropWith(unit, 'multi-line directive');
  });

  // The rules Coraza adds to its rule group, in order: a rule on its own or a
  // chain starter, whose `lines` then include its children's.
  const rules: { text: string; unitLength: number; lines: number[] }[] = [];
  let chain: number[] | null = null;
  for (const [i, unit] of units.entries()) {
    const text = texts[i];
    if (MARKER_DIRECTIVE.test(text)) {
      if (chain) dropWith(chain, 'chained rule');
      chain = null;
      continue;
    }
    if (!RULE_DIRECTIVE.test(text)) continue;
    const chained = hasChainAction(text);
    if (chain) {
      chain.push(...unit);
      if (!chained) {
        dropWith(chain, 'chained rule');
        chain = null;
      }
    } else {
      const rule = { text, unitLength: unit.length, lines: [...unit] };
      rules.push(rule);
      if (chained) chain = rule.lines;
    }
  }
  if (chain) dropWith(chain, 'chained rule');

  // Coraza refuses a rule whose id is already in its rule group (chain
  // children are not added to it). Only kept rules take an id, since a
  // dropped one never reaches Coraza.
  const usedIds = new Set<number>();
  const reserved = options.reservedRuleIds ?? new Set<number>();
  for (const rule of rules) {
    if (rule.lines.some((index) => reasons[index] !== null)) continue;
    const id = ruleIdOf(rule.text);
    if (id === null) continue;
    if (reserved.has(id)) {
      reasons[rule.lines[0]] =
        `rule id ${id} is used by the WAF settings (paranoia level, thresholds or rule exclusions); pick another id`;
      dropWith(rule.lines, rule.lines.length > rule.unitLength ? 'chained rule' : 'multi-line directive');
      continue;
    }
    if (!usedIds.has(id)) {
      usedIds.add(id);
      continue;
    }
    reasons[rule.lines[0]] =
      `rule id ${id} is already used by an earlier rule (Coraza refuses a duplicate id, and Caddy then refuses the whole config)`;
    dropWith(rule.lines, rule.lines.length > rule.unitLength ? 'chained rule' : 'multi-line directive');
  }

  lines.forEach((line, index) => {
    const reason = reasons[index];
    if (reason === null) kept.push({ line, index: offset + index });
    else dropped.push({ line: trimmedLines[index], reason, index: offset + index });
  });
  return { kept, dropped };
}

/**
 * Human-readable message describing the custom directives Ingressi will silently
 * drop. Shared by the global-settings and per-host validators so users learn
 * at save time — not after a confusing "nothing blocked" report.
 */
export function droppedWafDirectiveMessage(dropped: DroppedWafDirective[]): string {
  const items = dropped.map((d) => `"${d.line}" → ${d.reason}`).join('\n');
  return `waf.custom_directives contains ${dropped.length} line(s) that will be dropped and never sent to Caddy:\n${items}\nRemove or rewrite them for them to take effect.`;
}

/** The stored custom directives a new value replaces, with their filter options. */
export interface PreviousCustomDirectives {
  directives: string | null | undefined;
  options?: CustomDirectiveFilterOptions;
}

/**
 * The validation error for a custom_directives value, or null when every line
 * will reach Caddy. Out-of-range body limits get their own message since they
 * are the most common mistake.
 *
 * With `previous` (the stored value and the CRS state it was built with), only
 * lines that the change newly drops count: a stored rule that a later release
 * started dropping must not block unrelated edits — buildWafHandler still
 * leaves it out and logs it — while a new dropped line, or a kept one that
 * the new CRS setting drops, is still rejected.
 */
export function customDirectivesError(
  directives: string | null | undefined,
  options: CustomDirectiveFilterOptions = {},
  previous?: PreviousCustomDirectives
): string | null {
  let { dropped } = filterCustomDirectives(directives, options);
  if (previous) {
    // Matched by line text and counted, so a second copy of a dropped line
    // is still new.
    const alreadyDropped = new Map<string, number>();
    for (const { line } of filterCustomDirectives(previous.directives, previous.options).dropped) {
      alreadyDropped.set(line, (alreadyDropped.get(line) ?? 0) + 1);
    }
    dropped = dropped.filter(({ line }) => {
      const count = alreadyDropped.get(line) ?? 0;
      if (count > 0) alreadyDropped.set(line, count - 1);
      return count === 0;
    });
  }
  if (dropped.length === 0) return null;
  // Safe to echo: this line matched `<known directive name> <digits>`, never
  // free-form user text.
  const badBodyLimit = dropped.find(({ line }) => isOutOfRangeBodyLimit(line));
  if (badBodyLimit) {
    return `waf.custom_directives has an out-of-range body limit: "${badBodyLimit.line}" — ${bodyLimitRangeMessage("the byte count")}`;
  }
  // Lines in the message come straight from the user's custom_directives, but
  // only lines Ingressi will drop anyway are reported, so nothing new is echoed.
  return droppedWafDirectiveMessage(dropped);
}

// Dropped directives are logged once per source and content: config is
// rebuilt on every change, and repeating the same warning each time would
// bury it.
const warnedDroppedDirectives = new Set<string>();

function warnDroppedDirectives(source: string, dropped: DroppedWafDirective[]): void {
  const items = dropped.map((d) => `  "${d.line}" → ${d.reason}`).join('\n');
  const key = `${source}\n${items}`;
  if (warnedDroppedDirectives.has(key)) return;
  if (warnedDroppedDirectives.size >= 1000) warnedDroppedDirectives.clear();
  warnedDroppedDirectives.add(key);
  console.warn(
    `[waf] ${source}: ${dropped.length} custom directive line(s) are not sent to Caddy and have no effect:\n${items}`
  );
}

/** The source named for dropped lines that come from the global WAF settings. */
export const GLOBAL_WAF_SOURCE = 'global WAF settings';

/**
 * Where the custom directives of an effective WAF config come from, for the
 * dropped-directive warning: the global directives it starts with (if any),
 * then the host's own, named by `label`. `globalCrsLoaded` is the global
 * settings' own CRS state. Build it with wafDirectiveSource.
 */
export interface WafDirectiveSource {
  label: string;
  globalDirectives: string | null;
  globalCrsLoaded: boolean;
}

/**
 * Warns about dropped lines under the source they came from. `index` counts
 * lines of the effective custom_directives, whose first lines are the global
 * directives when `source` says so.
 *
 * A global line is reported under the global settings only when they drop it
 * on their own. One dropped only in this host's handler — the host turns the
 * CRS off under it, or its first line breaks a global chain — is reported
 * under the host, marked as coming from the global settings.
 */
function warnDroppedBySource(
  source: string | WafDirectiveSource,
  dropped: (DroppedWafDirective & { index: number })[]
): void {
  for (const [name, lines] of droppedBySource(source, dropped)) warnDroppedDirectives(name, lines);
}

/** The dropped lines grouped under the source warnDroppedBySource names. */
function droppedBySource(
  source: string | WafDirectiveSource,
  dropped: (DroppedWafDirective & { index: number })[]
): [string, DroppedWafDirective[]][] {
  if (typeof source === 'string') return dropped.length > 0 ? [[source, dropped]] : [];
  const globalLines = source.globalDirectives ? source.globalDirectives.split('\n').length : 0;
  const droppedByGlobal = new Set(
    filterDirectiveLines(source.globalDirectives, { crsLoaded: source.globalCrsLoaded }).dropped.map(({ index }) => index)
  );
  const bySource: [string, (DroppedWafDirective & { index: number })[]][] = [
    [GLOBAL_WAF_SOURCE, dropped.filter(({ index }) => index < globalLines && droppedByGlobal.has(index))],
    [
      `${source.label}, from the ${GLOBAL_WAF_SOURCE}`,
      dropped.filter(({ index }) => index < globalLines && !droppedByGlobal.has(index)),
    ],
    [source.label, dropped.filter(({ index }) => index >= globalLines)],
  ];
  return bySource.filter(([, lines]) => lines.length > 0);
}

/**
 * The effective settings resolveEffectiveWaf returns, plus the global
 * custom_directives they start with: the merge joins the global directives,
 * then the host's, and a host without its own config takes the global
 * settings as they are.
 */
function resolveWaf(
  global: WafSettings | null,
  host: WafHostConfig | null | undefined
): { waf: WafSettings; globalDirectives: string | null } | null {
  const hostEnabled = host?.enabled;
  const globalEnabled = global?.enabled;

  if (!hostEnabled && !globalEnabled) return null;

  // Override mode: use host config entirely
  if (host && host.waf_mode === "override") {
    if (!hostEnabled) return null;
    return {
      waf: {
        enabled: true,
        mode: host.mode ?? 'On',
        load_owasp_crs: host.load_owasp_crs ?? false,
        custom_directives: host.custom_directives ?? '',
        excluded_rule_ids: host.excluded_rule_ids,
        request_body_limit: host.request_body_limit,
        request_body_in_memory_limit: host.request_body_in_memory_limit,
        request_body_limit_action: host.request_body_limit_action,
      },
      globalDirectives: null,
    };
  }

  // Merge mode: start with global, overlay host fields.
  // host.enabled === false is an explicit opt-out — respect it even when global is on.
  if (host && global) {
    if (host.enabled === false) return null;
    return {
      waf: {
        // CRS tuning is global only; a merging host takes it as it is.
        ...pickWafTuning(global),
        enabled: true,
        mode: host.mode ?? global.mode,
        load_owasp_crs: host.load_owasp_crs ?? global.load_owasp_crs,
        custom_directives: [global.custom_directives, host.custom_directives].filter(Boolean).join('\n'),
        excluded_rule_ids: [
          ...(global.excluded_rule_ids ?? []),
          ...(host.excluded_rule_ids ?? []),
        ],
        // Body limits are scalars, not lists: the host value wins when set,
        // otherwise the global one applies.
        request_body_limit: host.request_body_limit ?? global.request_body_limit,
        request_body_in_memory_limit:
          host.request_body_in_memory_limit ?? global.request_body_in_memory_limit,
        request_body_limit_action:
          host.request_body_limit_action ?? global.request_body_limit_action,
      },
      globalDirectives: global.custom_directives || null,
    };
  }

  if (host?.enabled) {
    return {
      waf: {
        enabled: true,
        mode: host.mode ?? 'On',
        load_owasp_crs: host.load_owasp_crs ?? false,
        custom_directives: host.custom_directives ?? '',
        excluded_rule_ids: host.excluded_rule_ids,
        request_body_limit: host.request_body_limit,
        request_body_in_memory_limit: host.request_body_in_memory_limit,
        request_body_limit_action: host.request_body_limit_action,
      },
      globalDirectives: null,
    };
  }
  if (global?.enabled) return { waf: global, globalDirectives: global.custom_directives || null };
  return null;
}

/** The tuning fields of `settings`, without the rest. */
function pickWafTuning(settings: WafTuningSettings): WafTuningSettings {
  const picked: Record<string, unknown> = {};
  for (const key of WAF_TUNING_KEYS) {
    if (settings[key] !== undefined) picked[key] = settings[key];
  }
  return picked as WafTuningSettings;
}

/**
 * The exclusion records that apply to a proxy host's WAF handler: the global
 * ones (proxyHostId null) unless the host overrides the global settings, then
 * the host's own. Same rule as the legacy excluded_rule_ids lists.
 */
export function wafExclusionsForHost<T extends WafExclusionRule & { proxyHostId: number | null }>(
  exclusions: readonly T[],
  hostId: number,
  host: WafHostConfig | null | undefined
): T[] {
  const override = host?.waf_mode === "override" && host.enabled;
  return [
    ...(override ? [] : exclusions.filter((exclusion) => exclusion.proxyHostId === null)),
    ...exclusions.filter((exclusion) => exclusion.proxyHostId === hostId),
  ];
}

/**
 * Resolves the effective WAF settings for a proxy host by merging or overriding
 * the global WAF settings with the per-host WAF config.
 *
 * Semantics:
 *  - host = null/undefined          → global settings apply as-is
 *  - host.enabled === false          → explicit opt-out; no WAF regardless of global
 *  - host.waf_mode === "override"    → use host config entirely, ignore global
 *  - host.waf_mode === "merge" (default) → merge host settings on top of global
 *
 * CRS tuning (paranoia level, thresholds, over-the-limit action) comes from
 * the global settings; a host that overrides them gets the CRS defaults.
 */
export function resolveEffectiveWaf(
  global: WafSettings | null,
  host: WafHostConfig | null | undefined
): WafSettings | null {
  return resolveWaf(global, host)?.waf ?? null;
}

/**
 * The dropped-directive source for resolveEffectiveWaf(global, host): lines
 * the global settings drop on their own are reported under GLOBAL_WAF_SOURCE,
 * every other dropped line under `label`.
 */
export function wafDirectiveSource(
  global: WafSettings | null,
  host: WafHostConfig | null | undefined,
  label: string
): WafDirectiveSource {
  return {
    label,
    globalDirectives: resolveWaf(global, host)?.globalDirectives ?? null,
    globalCrsLoaded: Boolean(global?.load_owasp_crs),
  };
}

/** A stored custom directive line that the generated config leaves out. */
export interface DroppedWafDirectiveReport extends DroppedWafDirective {
  source: string;
}

/**
 * The stored custom directive lines that the WAF handlers built from these
 * settings leave out, under the source buildWafHandler's warning names. Save
 * validation refuses such lines, but stored values can predate a rule, and a
 * left-out deny rule (or a SecDefaultAction that later `block` rules rely on)
 * no longer blocks anything, so the WAF page lists them.
 */
export function listDroppedWafDirectives(
  global: WafSettings | null,
  hosts: readonly { name: string; domains: readonly string[]; waf?: WafHostConfig | null }[]
): DroppedWafDirectiveReport[] {
  const reports = new Map<string, DroppedWafDirectiveReport>();
  const collect = (waf: WafSettings | null, source: string | WafDirectiveSource) => {
    if (!waf?.enabled || waf.mode === 'Off') return;
    const { dropped } = filterDirectiveLines(waf.custom_directives, {
      crsLoaded: Boolean(waf.load_owasp_crs),
      reservedRuleIds: tuningRuleIds(waf),
    });
    for (const [name, lines] of droppedBySource(source, dropped)) {
      for (const { line, reason } of lines) reports.set(`${name}\n${line}\n${reason}`, { source: name, line, reason });
    }
  };
  collect(global, GLOBAL_WAF_SOURCE);
  for (const host of hosts) {
    collect(
      resolveEffectiveWaf(global, host.waf),
      wafDirectiveSource(global, host.waf, `proxy host "${host.name}" (${host.domains.join(", ")})`)
    );
  }
  return [...reports.values()];
}

/** Rule ids the CRS tuning directives of `waf` take (none without the CRS). */
function tuningRuleIds(waf: WafSettings): Set<number> {
  return new Set(waf.load_owasp_crs ? crsTuningDirectives(resolveWafTuning(waf)).ruleIds : []);
}

/**
 * Caddy request matcher for a WebSocket upgrade handshake — the HTTP GET that
 * carries `Connection: Upgrade` and `Upgrade: websocket`.  Mirrors Caddy's own
 * built-in `@websockets` named matcher so detection matches what `reverse_proxy`
 * itself uses to switch into tunnel mode.
 */
export const WEBSOCKET_UPGRADE_MATCHER: Record<string, unknown> = {
  header: {
    Connection: ['*Upgrade*'],
    Upgrade: ['websocket'],
  },
};

/** The rule id of RAW_BODY_RULE: outside the CRS and below the exclusion records' range. */
export const RAW_BODY_RULE_ID = 1_899_999_000;

/**
 * Bodies of a content type no parser is set for (protobuf, octet-stream, gRPC
 * and the like) are read as they are, into REQUEST_BODY. The CRS turns on
 * forceRequestBodyVariable for them (rule 901340), which ModSecurity answers
 * with REQUEST_BODY alone, but Coraza with its URL-encoded parser: every
 * "&"- and "="-separated fragment of binary data becomes an argument, and an
 * OpenTelemetry trace or a file upload matches dozens of attack rules
 * (coraza#938). Same condition as 901340, so form, multipart, XML and JSON
 * bodies keep their parsers; the CRS still refuses content types outside
 * tx.allowed_request_content_type (920420).
 */
export const RAW_BODY_RULE =
  `SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" ` +
  `"id:${RAW_BODY_RULE_ID},phase:1,pass,t:none,nolog,noauditlog,ctl:requestBodyProcessor=RAW"`;

/**
 * Builds the Caddy `waf` handler object for the given WAF settings.
 *
 * Important: @-prefixed SecLang paths (e.g. @coraza.conf-recommended) resolve
 * from the embedded coraza-coreruleset filesystem, which is only mounted by the
 * Caddy WAF plugin when `load_owasp_crs: true`.  Including those directives when
 * the embedded filesystem is unavailable causes a Caddy config load error:
 *   "failed to readfile: open @coraza.conf-recommended: no such file or directory"
 * Therefore all @-prefixed includes are gated behind load_owasp_crs.
 *
 * `source` names where the settings came from in the warning logged when
 * custom directives are dropped: a label, or a WafDirectiveSource that splits
 * the global directives from a proxy host's own.
 */
export function buildWafHandler(
  waf: WafSettings,
  source: string | WafDirectiveSource = 'WAF settings',
  exclusions: readonly WafExclusionRule[] = []
): Record<string, unknown> {
  const parts: string[] = [];
  // Tuning only exists with the CRS: its SecActions set CRS variables and
  // SecRuleUpdateActionById fails the whole config for a rule not loaded.
  const tuning = waf.load_owasp_crs
    ? crsTuningDirectives(resolveWafTuning(waf))
    : { beforeRules: [], afterRules: [], ruleIds: [] };
  const exclusionDirectives = buildExclusionDirectives(exclusions);
  // Filtered up front so phase 1 allow rules can go ahead of the CRS.
  const { kept, dropped } = filterDirectiveLines(waf.custom_directives, {
    crsLoaded: Boolean(waf.load_owasp_crs),
    reservedRuleIds: new Set([...tuning.ruleIds, ...exclusionDirectives.ruleIds, ...(waf.load_owasp_crs ? [RAW_BODY_RULE_ID] : [])]),
  });
  const { early: earlyAllowRules, rest: customLines } = splitEarlyAllowRules(kept.map(({ line }) => line));
  if (exclusionDirectives.skipped.length > 0) {
    console.warn(
      `[waf] ${typeof source === 'string' ? source : source.label}: ${exclusionDirectives.skipped.length} stored rule exclusion(s) are invalid and left out (ids ${exclusionDirectives.skipped.map((e) => e.id).join(', ')})`
    );
  }

  // `mode` is interpolated straight into the directive block, and settings are
  // stored without validation — so anything other than a known engine mode
  // (e.g. "On\nSecRuleRemoveById 1-999999") would smuggle in SecLang that the
  // custom_directives allowlist below exists to reject. Clamp to Coraza's three
  // real values and fall back to the safe one.
  const engineMode = waf.mode === 'Off' || waf.mode === 'DetectionOnly' ? waf.mode : 'On';

  if (waf.load_owasp_crs) {
    // @-prefixed paths resolve from the embedded coraza-coreruleset filesystem,
    // which is only mounted when load_owasp_crs is true.
    parts.push(
      'Include @coraza.conf-recommended',
      'Include @crs-setup.conf.example',
      // After coraza.conf-recommended picks JSON and XML, before the CRS forces a body variable.
      RAW_BODY_RULE,
      // The tuning SecActions set tx variables the CRS only defaults when unset.
      ...tuning.beforeRules,
      // Runtime exclusions run in phase 1 ahead of every rule they exclude.
      ...exclusionDirectives.rules,
      // Custom phase 1 allow rules (e.g. trusted LAN ranges) must precede the CRS.
      ...earlyAllowRules,
      'Include @owasp_crs/*.conf',
      // Before any SecRuleRemoveById: updating a removed rule fails the config.
      ...tuning.afterRules,
    );
  } else {
    parts.push(...exclusionDirectives.rules, ...earlyAllowRules);
  }

  // Whole-scope exclusions: the legacy excluded_rule_ids lists (runtime-
  // validated as positive integers) and the exclusion records without a path
  // or variable, which they normally mirror.
  const removedIds = new Set<number>(exclusionDirectives.removedRuleIds);
  for (const id of waf.excluded_rule_ids ?? []) {
    if (typeof id === "number" && Number.isFinite(id) && id > 0 && Number.isInteger(id)) removedIds.add(id);
  }
  if (removedIds.size > 0) {
    parts.push(`SecRuleRemoveById ${[...removedIds].join(' ')}`);
  }

  parts.push(
    `SecRuleEngine ${engineMode}`,
    // RelevantOnly logs transactions where a rule fired with the auditlog action (which all OWASP
    // CRS rules include via SecDefaultAction), covering both blocked and DetectionOnly hits.
    // Clean requests with no rule matches are silently skipped, avoiding massive log growth.
    'SecAuditEngine RelevantOnly',
    'SecAuditLog /logs/waf-audit.log',
    'SecAuditLogFormat JSON',
    // Note: the audit log ends up owned by caddy with mode 0644, so the web
    // container (a different UID) can read it but not truncate it once it passes
    // the parser's size cap. SecAuditLogFileMode cannot fix that — the container's
    // 0022 umask strips group-write from any mode we ask for, and requesting 0660
    // would only narrow world-read to group-read, breaking deployments that don't
    // add web to the caddy group. waf-log-parser therefore treats truncation as
    // best-effort and keeps ingesting when it fails.
    // Part H carries the matched rules, which waf-log-parser reads to attribute
    // each event to a rule id/message/severity. Bodies (I, J, E) and intermediate
    // response headers (D) are omitted to avoid logging multi-MB payloads.
    'SecAuditLogParts ABFHZ',
    'SecResponseBodyAccess Off',
  );

  // Body limits from the dedicated settings fields. Emitted after the CRS
  // include (so they override @coraza.conf-recommended's 12.5 MiB) but before
  // custom_directives, which stay the escape hatch that wins over the UI.
  if (isValidBodyLimit(waf.request_body_limit)) {
    parts.push(`SecRequestBodyLimit ${waf.request_body_limit}`);
  }
  if (isValidBodyLimit(waf.request_body_in_memory_limit)) {
    parts.push(`SecRequestBodyInMemoryLimit ${waf.request_body_in_memory_limit}`);
  }
  if (waf.request_body_limit_action === 'Reject' || waf.request_body_limit_action === 'ProcessPartial') {
    parts.push(`SecRequestBodyLimitAction ${waf.request_body_limit_action}`);
  }

  // Allowlist approach: only permit known-safe directive prefixes in custom
  // directives. Input validation rejects these lines on save, but stored
  // values can predate a rule, so say what is left out.
  if (dropped.length > 0) warnDroppedBySource(source, dropped);
  if (customLines.length > 0) {
    parts.push(customLines.join('\n'));
  }

  const handler: Record<string, unknown> = {
    handler: 'waf',
    directives: reconcileInMemoryBodyLimit(parts.join('\n'), waf.load_owasp_crs),
  };
  if (waf.load_owasp_crs) handler.load_owasp_crs = true;
  return handler;
}

/**
 * Coraza also validates `SecRequestBodyInMemoryLimit <= SecRequestBodyLimit`
 * and fails config load when it doesn't hold. That pairing is easy to break by
 * accident: lowering only the request limit leaves the CRS's 128 KiB in-memory
 * value above it, and the resulting rejection takes down every host's config,
 * not just this handler's.
 *
 * Coraza validates the FINAL parsed values, so only the last directive of each
 * kind matters. When they conflict, append a corrective in-memory line — the
 * last one wins, so the config stays loadable with the user's request limit
 * intact.
 */
function reconcileInMemoryBodyLimit(directives: string, crsLoaded: boolean): string {
  let requestLimit = crsLoaded ? CRS_BODY_LIMIT : CORAZA_DEFAULT_BODY_LIMIT;
  let inMemoryLimit = crsLoaded ? CRS_IN_MEMORY_BODY_LIMIT : null;

  for (const line of directives.split('\n')) {
    const match = BODY_LIMIT_DIRECTIVE.exec(line.trim());
    if (!match) continue;
    const name = match[1].toLowerCase();
    const value = Number(match[2]);
    if (name === 'secrequestbodylimit') requestLimit = value;
    else if (name === 'secrequestbodyinmemorylimit') inMemoryLimit = value;
  }

  if (inMemoryLimit === null || inMemoryLimit <= requestLimit) return directives;
  return `${directives}\nSecRequestBodyInMemoryLimit ${requestLimit}`;
}

/**
 * Builds the handler-chain entry that applies the WAF for a proxy route.
 *
 * When allowWebsocket is true the WAF handler is wrapped in a non-terminal
 * subroute that only runs for NON-WebSocket requests.  WebSocket upgrades must
 * bypass the coraza handler ENTIRELY — not merely have the rule engine turned
 * off via `ctl:ruleEngine=off` (issue #195):
 *
 *   The coraza-caddy middleware wraps the response writer to inspect the
 *   upstream response (SecLang phase 3/4 rules).  That wrapper does not pass
 *   through the connection hijack that a `101 Switching Protocols` upgrade
 *   performs, so the raw WebSocket bytes leak out without the HTTP status line.
 *   The client sees a corrupt "HTTP/0.9" response and the handshake fails.
 *   Disabling only the rule engine leaves the response wrapper in place, so the
 *   connection is still mangled — routing around the handler is the only fix.
 *
 * Because a Caddy `subroute` compiles its inner routes with the OUTER `next`
 * handler as their continuation, the WAF handler still wraps the downstream
 * `reverse_proxy` for ordinary requests (response inspection preserved); only
 * the matched-out WebSocket upgrade skips it and falls straight through to the
 * next handler in the chain.
 *
 * When allowWebsocket is false the bare WAF handler is returned so WebSocket
 * upgrades are inspected (and potentially blocked) like any other request.
 */
export function buildWafHandlerEntry(
  waf: WafSettings,
  allowWebsocket = false,
  source?: string | WafDirectiveSource,
  exclusions: readonly WafExclusionRule[] = []
): Record<string, unknown> {
  const wafHandler = buildWafHandler(waf, source, exclusions);
  if (!allowWebsocket) return wafHandler;
  return {
    handler: 'subroute',
    routes: [
      {
        match: [{ not: [WEBSOCKET_UPGRADE_MATCHER] }],
        handle: [wafHandler],
      },
    ],
  };
}
