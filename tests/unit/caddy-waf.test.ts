/**
 * Unit tests for src/lib/caddy-waf.ts
 *
 * Key regression: when WAF is enabled but OWASP CRS is NOT loaded,
 * the generated directives must NOT contain any @-prefixed Include paths
 * (e.g. @coraza.conf-recommended).  Those paths only resolve from the
 * embedded coraza-coreruleset filesystem which is mounted by the Caddy
 * plugin only when load_owasp_crs=true.  Including them without the
 * filesystem causes:
 *   "failed to readfile: open @coraza.conf-recommended: no such file or directory"
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  buildWafHandler,
  buildWafHandlerEntry,
  CORAZA_MAX_BODY_LIMIT,
  customDirectivesError,
  droppedWafDirectiveMessage,
  filterCustomDirectives,
  findInvalidBodyLimitDirective,
  GLOBAL_WAF_SOURCE,
  listDroppedWafDirectives,
  parseBodyLimitMib,
  resolveEffectiveWaf,
  wafDirectiveSource,
} from '../../src/lib/caddy-waf';
import { appendQuickTemplate, HOST_TEMPLATE_ID_OFFSET, WAF_QUICK_TEMPLATES } from '../../src/lib/waf-quick-templates';

const baseWaf = {
  enabled: true,
  mode: 'On' as const,
  load_owasp_crs: false,
  custom_directives: '',
};

// ---------------------------------------------------------------------------
// SecRuleEngine mode is interpolated into the directive block, and WAF settings
// are persisted without validation — so an unrecognised mode must never reach
// the config, or it would smuggle in SecLang past the custom_directives
// allowlist (e.g. disabling rules the allowlist explicitly refuses).
// ---------------------------------------------------------------------------

describe('buildWafHandler — SecRuleEngine mode sanitising', () => {
  function directives(mode: string): string {
    const handler = buildWafHandler({ ...baseWaf, mode: mode as typeof baseWaf.mode, load_owasp_crs: false });
    return handler.directives as string;
  }

  it('passes through the three real Coraza engine modes', () => {
    expect(directives('On')).toContain('SecRuleEngine On');
    expect(directives('Off')).toContain('SecRuleEngine Off');
    expect(directives('DetectionOnly')).toContain('SecRuleEngine DetectionOnly');
  });

  it('falls back to On for an unrecognised mode', () => {
    expect(directives('bogus')).toContain('SecRuleEngine On');
  });

  it('does not let a newline in mode inject extra directives', () => {
    const out = directives('On\nSecRuleRemoveById 1-999999');
    expect(out).toContain('SecRuleEngine On');
    expect(out).not.toContain('SecRuleRemoveById 1-999999');
  });

  it('always emits the audit log parts the event parser depends on', () => {
    const out = directives('On');
    // Part H carries the matched rules that waf-log-parser reads for rule
    // attribution; losing it silently strips rule id/message/severity.
    expect(out).toContain('SecAuditLogParts ABFHZ');
    expect(out).toContain('SecAuditLog /logs/waf-audit.log');
    expect(out).toContain('SecAuditLogFormat JSON');
  });
});

// ---------------------------------------------------------------------------
// Regression: @-prefixed paths must not appear without load_owasp_crs
// ---------------------------------------------------------------------------

describe('buildWafHandler — without OWASP CRS', () => {
  it('does NOT include @coraza.conf-recommended when load_owasp_crs is false', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: false });
    expect(handler.directives).not.toContain('@coraza.conf-recommended');
  });

  it('does NOT include any @-prefixed Include when load_owasp_crs is false', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: false });
    // Guard against any future @-prefixed file references leaking in
    expect(handler.directives).not.toMatch(/Include @/);
  });

  it('does NOT set load_owasp_crs field on handler when disabled', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: false });
    expect(handler.load_owasp_crs).toBeUndefined();
  });

  it('still emits SecRuleEngine directive', () => {
    const handler = buildWafHandler({ ...baseWaf, mode: 'On', load_owasp_crs: false });
    expect(handler.directives).toContain('SecRuleEngine On');
  });

  it('still emits SecRuleEngine Off in DetectionOnly-like mode', () => {
    const handler = buildWafHandler({ ...baseWaf, mode: 'Off', load_owasp_crs: false });
    expect(handler.directives).toContain('SecRuleEngine Off');
  });

  it('includes custom directives when provided', () => {
    const directive = 'SecRule REQUEST_HEADERS:User-Agent "@contains leakix.net" "id:9002,phase:1,deny,status:403,log"';
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: false, custom_directives: directive });
    expect(handler.directives).toContain(directive);
  });

  it('does not append empty/whitespace-only custom_directives', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: false, custom_directives: '   ' });
    // The directives string should end with the last standard directive
    expect((handler.directives as string).trimEnd()).not.toMatch(/\s+$/);
  });

  it('allows request body limit directives from custom directives', () => {
    const directives = [
      'SecRequestBodyLimit 536870912',
      'SecRequestBodyNoFilesLimit 536870912',
    ].join('\n');
    const handler = buildWafHandler({ ...baseWaf, custom_directives: directives });
    expect(handler.directives).toContain('SecRequestBodyLimit 536870912');
    expect(handler.directives).toContain('SecRequestBodyNoFilesLimit 536870912');
  });

  // Coraza refuses to build a WAF above 1 GiB, and coraza-caddy builds it while
  // Caddy loads the config — so an out-of-range value doesn't just fail this
  // host, it makes Caddy reject the whole document.
  it('drops body limits Coraza would refuse rather than breaking the config load', () => {
    const handler = buildWafHandler({
      ...baseWaf,
      custom_directives: [
        'SecRequestBodyLimit 10737418240',
        'SecRequestBodyInMemoryLimit 0',
        'SecRequestBodyLimit 536870912',
      ].join('\n'),
    });
    expect(handler.directives).not.toContain('10737418240');
    expect(handler.directives).not.toContain('SecRequestBodyInMemoryLimit 0');
    expect(handler.directives).toContain('SecRequestBodyLimit 536870912');
  });

  it('accepts a body limit exactly at Coraza\'s 1 GiB ceiling', () => {
    const handler = buildWafHandler({
      ...baseWaf,
      custom_directives: `SecRequestBodyLimit ${CORAZA_MAX_BODY_LIMIT}`,
    });
    expect(handler.directives).toContain(`SecRequestBodyLimit ${CORAZA_MAX_BODY_LIMIT}`);
  });

  it('allows related constrained request body limit directives', () => {
    const directives = [
      'SecRequestBodyInMemoryLimit 131072',
      'SecRequestBodyLimitAction ProcessPartial',
    ].join('\n');
    const handler = buildWafHandler({ ...baseWaf, custom_directives: directives });
    expect(handler.directives).toContain('SecRequestBodyInMemoryLimit 131072');
    expect(handler.directives).toContain('SecRequestBodyLimitAction ProcessPartial');
  });

  it('still rejects request body directives that can disable inspection', () => {
    const handler = buildWafHandler({
      ...baseWaf,
      custom_directives: 'SecRequestBodyAccess Off',
    });
    expect(handler.directives).not.toContain('SecRequestBodyAccess Off');
  });
});

// ---------------------------------------------------------------------------
// With OWASP CRS enabled
// ---------------------------------------------------------------------------

describe('buildWafHandler — with OWASP CRS', () => {
  it('includes @coraza.conf-recommended when load_owasp_crs is true', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: true });
    expect(handler.directives).toContain('Include @coraza.conf-recommended');
  });

  it('includes @crs-setup.conf.example when load_owasp_crs is true', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: true });
    expect(handler.directives).toContain('Include @crs-setup.conf.example');
  });

  it('includes @owasp_crs/*.conf when load_owasp_crs is true', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: true });
    expect(handler.directives).toContain('Include @owasp_crs/*.conf');
  });

  it('sets load_owasp_crs=true on the handler object', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: true });
    expect(handler.load_owasp_crs).toBe(true);
  });

  it('@coraza.conf-recommended appears BEFORE CRS includes', () => {
    const handler = buildWafHandler({ ...baseWaf, load_owasp_crs: true });
    const directives = handler.directives as string;
    const corazaPos = directives.indexOf('@coraza.conf-recommended');
    const crsPos = directives.indexOf('@owasp_crs');
    expect(corazaPos).toBeLessThan(crsPos);
  });
});

// ---------------------------------------------------------------------------
// Excluded rule IDs
// ---------------------------------------------------------------------------

describe('buildWafHandler — excluded_rule_ids', () => {
  it('emits SecRuleRemoveById with single ID', () => {
    const handler = buildWafHandler({ ...baseWaf, excluded_rule_ids: [941100] });
    expect(handler.directives).toContain('SecRuleRemoveById 941100');
  });

  it('emits SecRuleRemoveById with multiple IDs space-separated', () => {
    const handler = buildWafHandler({ ...baseWaf, excluded_rule_ids: [941100, 942200, 943300] });
    expect(handler.directives).toContain('SecRuleRemoveById 941100 942200 943300');
  });

  it('omits SecRuleRemoveById when excluded_rule_ids is empty', () => {
    const handler = buildWafHandler({ ...baseWaf, excluded_rule_ids: [] });
    expect(handler.directives).not.toContain('SecRuleRemoveById');
  });

  it('omits SecRuleRemoveById when excluded_rule_ids is undefined', () => {
    const handler = buildWafHandler({ ...baseWaf });
    expect(handler.directives).not.toContain('SecRuleRemoveById');
  });
});

// ---------------------------------------------------------------------------
// Handler structure
// ---------------------------------------------------------------------------

describe('buildWafHandler — handler structure', () => {
  it('always sets handler="waf"', () => {
    expect(buildWafHandler(baseWaf).handler).toBe('waf');
  });

  it('directives is a non-empty string', () => {
    const handler = buildWafHandler(baseWaf);
    expect(typeof handler.directives).toBe('string');
    expect((handler.directives as string).length).toBeGreaterThan(0);
  });

  it('always includes audit log directives', () => {
    const handler = buildWafHandler(baseWaf);
    expect(handler.directives).toContain('SecAuditEngine RelevantOnly');
    expect(handler.directives).toContain('SecAuditLog /logs/waf-audit.log');
    expect(handler.directives).toContain('SecAuditLogFormat JSON');
  });
});

// ---------------------------------------------------------------------------
// resolveEffectiveWaf
// ---------------------------------------------------------------------------

const globalWaf = {
  enabled: true,
  mode: 'On' as const,
  load_owasp_crs: false,
  custom_directives: 'SecRule REQUEST_HEADERS:User-Agent "@contains leakix.net" "id:9002,phase:1,deny,status:403,log"',
};

describe('resolveEffectiveWaf — no per-host config', () => {
  it('returns null when both global and host are null', () => {
    expect(resolveEffectiveWaf(null, null)).toBeNull();
  });

  it('returns null when global is disabled and host is null', () => {
    expect(resolveEffectiveWaf({ ...globalWaf, enabled: false }, null)).toBeNull();
  });

  it('applies global WAF when host has no per-host config (null)', () => {
    const result = resolveEffectiveWaf(globalWaf, null);
    expect(result).not.toBeNull();
    expect(result!.enabled).toBe(true);
    expect(result!.custom_directives).toContain('9002');
  });

  it('applies global WAF when host config is undefined', () => {
    const result = resolveEffectiveWaf(globalWaf, undefined);
    expect(result).not.toBeNull();
    expect(result!.custom_directives).toContain('9002');
  });
});

describe('resolveEffectiveWaf — merge mode (regression: host.enabled=false must opt out)', () => {
  it('returns null when host explicitly disables WAF in merge mode (the bug fix)', () => {
    // This was the bug: host.enabled=false in merge mode was ignored and global WAF applied anyway
    const result = resolveEffectiveWaf(globalWaf, { enabled: false, waf_mode: 'merge' });
    expect(result).toBeNull();
  });

  it('returns null when host.enabled=false with no waf_mode set (defaults to merge)', () => {
    const result = resolveEffectiveWaf(globalWaf, { enabled: false });
    expect(result).toBeNull();
  });

  it('merges host settings on top of global when host is enabled', () => {
    const result = resolveEffectiveWaf(globalWaf, {
      enabled: true,
      waf_mode: 'merge',
      mode: 'On',
      load_owasp_crs: true,
      custom_directives: 'SecRule ARGS "@contains evil" "id:9003,deny"',
    });
    expect(result).not.toBeNull();
    expect(result!.load_owasp_crs).toBe(true);
    // Both global and host custom directives are present
    expect(result!.custom_directives).toContain('9002');
    expect(result!.custom_directives).toContain('9003');
  });

  it('merge result has enabled=true', () => {
    const result = resolveEffectiveWaf(globalWaf, { enabled: true, waf_mode: 'merge' });
    expect(result!.enabled).toBe(true);
  });

  it('merged excluded_rule_ids combines global and host lists', () => {
    const global = { ...globalWaf, excluded_rule_ids: [941100] };
    const result = resolveEffectiveWaf(global, {
      enabled: true,
      waf_mode: 'merge',
      excluded_rule_ids: [942200],
    });
    expect(result!.excluded_rule_ids).toContain(941100);
    expect(result!.excluded_rule_ids).toContain(942200);
  });
});

describe('resolveEffectiveWaf — override mode', () => {
  it('returns null when host.enabled=false in override mode', () => {
    const result = resolveEffectiveWaf(globalWaf, { enabled: false, waf_mode: 'override' });
    expect(result).toBeNull();
  });

  it('uses only host config in override mode, ignores global custom_directives', () => {
    const result = resolveEffectiveWaf(globalWaf, {
      enabled: true,
      waf_mode: 'override',
      mode: 'On',
      load_owasp_crs: true,
      custom_directives: 'SecRule ARGS "@contains evil" "id:9003,deny"',
    });
    expect(result).not.toBeNull();
    expect(result!.custom_directives).toBe('SecRule ARGS "@contains evil" "id:9003,deny"');
    // Global directives are NOT included
    expect(result!.custom_directives).not.toContain('9002');
    expect(result!.load_owasp_crs).toBe(true);
  });

  it('host-only WAF with no global applies correctly', () => {
    const result = resolveEffectiveWaf(null, { enabled: true, waf_mode: 'override', mode: 'On' });
    expect(result).not.toBeNull();
    expect(result!.enabled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildWafHandlerEntry — WebSocket bypass (issue #195)
//
// Regression: enabling WAF on a proxy host mangled WebSocket connections into a
// corrupt "HTTP/0.9" response. The coraza middleware wraps the response writer
// to inspect the upstream response, and that wrapper breaks the 101 Switching
// Protocols connection hijack. The previous `ctl:ruleEngine=off` SecLang bypass
// did NOT help because it only disables rule evaluation, leaving the response
// wrapper in place. The fix routes WebSocket upgrades AROUND the WAF handler at
// the Caddy routing level via a subroute that excludes the upgrade request.
// ---------------------------------------------------------------------------

// Pull a deeply-nested handler tree apart for assertions
function subrouteOf(entry: Record<string, unknown>) {
  return entry as {
    handler: string;
    routes: Array<{ match: Array<Record<string, unknown>>; handle: Array<Record<string, unknown>> }>;
  };
}

describe('buildWafHandlerEntry — WebSocket bypass', () => {
  it('returns the bare WAF handler when allowWebsocket=false', () => {
    const entry = buildWafHandlerEntry(baseWaf, false);
    expect(entry.handler).toBe('waf');
    expect(typeof entry.directives).toBe('string');
  });

  it('returns the bare WAF handler when allowWebsocket not provided (default false)', () => {
    const entry = buildWafHandlerEntry(baseWaf);
    expect(entry.handler).toBe('waf');
  });

  it('wraps the WAF handler in a subroute when allowWebsocket=true', () => {
    const entry = subrouteOf(buildWafHandlerEntry(baseWaf, true));
    expect(entry.handler).toBe('subroute');
    expect(entry.routes).toHaveLength(1);
    // The inner route's only handler is the actual WAF handler
    expect(entry.routes[0].handle).toHaveLength(1);
    expect(entry.routes[0].handle[0].handler).toBe('waf');
  });

  it('subroute matches everything EXCEPT WebSocket upgrade requests', () => {
    const entry = subrouteOf(buildWafHandlerEntry(baseWaf, true));
    const match = entry.routes[0].match[0];
    // A `not` matcher on the WebSocket upgrade headers — WAF runs for non-WS only
    const not = match.not as Array<Record<string, unknown>>;
    expect(Array.isArray(not)).toBe(true);
    const header = not[0].header as Record<string, string[]>;
    expect(header.Connection).toEqual(['*Upgrade*']);
    expect(header.Upgrade).toEqual(['websocket']);
  });

  it('does NOT emit a ctl:ruleEngine=off SecLang bypass (the broken approach)', () => {
    const entry = subrouteOf(buildWafHandlerEntry(baseWaf, true));
    const directives = entry.routes[0].handle[0].directives as string;
    expect(directives).not.toContain('ctl:ruleEngine=off');
  });

  it('preserves the full WAF directive set inside the bypass subroute', () => {
    const entry = subrouteOf(buildWafHandlerEntry({ ...baseWaf, load_owasp_crs: true }, true));
    const wafHandler = entry.routes[0].handle[0];
    const directives = wafHandler.directives as string;
    expect(directives).toContain('SecRuleEngine On');
    expect(directives).toContain('SecAuditEngine RelevantOnly');
    expect(directives).toContain('Include @owasp_crs/*.conf');
    // load_owasp_crs flag must survive the wrapping
    expect(wafHandler.load_owasp_crs).toBe(true);
  });

  it('keeps custom directives inside the bypass subroute', () => {
    const entry = subrouteOf(buildWafHandlerEntry({
      ...baseWaf,
      custom_directives: 'SecRule ARGS "@contains evil" "id:9001,deny"',
    }, true));
    const directives = entry.routes[0].handle[0].directives as string;
    expect(directives).toContain('SecRule ARGS "@contains evil"');
  });
});

// ---------------------------------------------------------------------------
// Dedicated request body limit settings (#252)
//
// Coraza's WAF is built while Caddy loads the config, so every value emitted
// here has to satisfy Coraza's validation up front: <= 1 GiB, and the
// in-memory limit no larger than the request limit. A violation rejects the
// whole config document, leaving every host unapplied.
// ---------------------------------------------------------------------------

describe('buildWafHandler — request body limit settings', () => {
  it('emits the configured limits as SecLang directives', () => {
    const handler = buildWafHandler({
      ...baseWaf,
      request_body_limit: 536870912,
      request_body_in_memory_limit: 1048576,
      request_body_limit_action: 'ProcessPartial',
    });
    const directives = handler.directives as string;
    expect(directives).toContain('SecRequestBodyLimit 536870912');
    expect(directives).toContain('SecRequestBodyInMemoryLimit 1048576');
    expect(directives).toContain('SecRequestBodyLimitAction ProcessPartial');
  });

  it('emits nothing when the limits are unset', () => {
    const directives = buildWafHandler(baseWaf).directives as string;
    expect(directives).not.toContain('SecRequestBodyLimit');
    expect(directives).not.toContain('SecRequestBodyLimitAction');
  });

  it('overrides the CRS default by ordering the limit after the include', () => {
    const directives = buildWafHandler({
      ...baseWaf,
      load_owasp_crs: true,
      request_body_limit: 536870912,
    }).directives as string;
    const includeAt = directives.indexOf('Include @coraza.conf-recommended');
    const limitAt = directives.indexOf('SecRequestBodyLimit 536870912');
    expect(includeAt).toBeGreaterThanOrEqual(0);
    expect(limitAt).toBeGreaterThan(includeAt);
  });

  it('lets custom directives win over the settings fields', () => {
    const directives = buildWafHandler({
      ...baseWaf,
      request_body_limit: 536870912,
      custom_directives: 'SecRequestBodyLimit 268435456',
    }).directives as string;
    expect(directives.indexOf('SecRequestBodyLimit 268435456'))
      .toBeGreaterThan(directives.indexOf('SecRequestBodyLimit 536870912'));
  });

  it('ignores out-of-range and unknown values instead of emitting them', () => {
    const directives = buildWafHandler({
      ...baseWaf,
      request_body_limit: 10737418240,
      request_body_in_memory_limit: 0,
      request_body_limit_action: 'Off' as never,
    }).directives as string;
    expect(directives).not.toContain('SecRequestBodyLimit');
    expect(directives).not.toContain('SecRequestBodyLimitAction');
  });

  // Coraza validates the FINAL values, so the corrective line at the end wins.
  it('clamps an in-memory limit that would exceed the request limit', () => {
    const directives = buildWafHandler({
      ...baseWaf,
      load_owasp_crs: true,
      custom_directives: 'SecRequestBodyInMemoryLimit 268435456',
    }).directives as string;
    // CRS caps the request body at 12.5 MiB, so 256 MiB in memory is invalid.
    expect(directives.trimEnd().endsWith('SecRequestBodyInMemoryLimit 13107200')).toBe(true);
  });

  it('leaves a valid limit pair untouched', () => {
    const directives = buildWafHandler({
      ...baseWaf,
      load_owasp_crs: true,
      request_body_limit: 536870912,
      request_body_in_memory_limit: 268435456,
    }).directives as string;
    expect(directives.match(/SecRequestBodyInMemoryLimit/g)).toHaveLength(1);
  });
});

describe('resolveEffectiveWaf — body limits', () => {
  const globalWaf = {
    enabled: true,
    mode: 'On' as const,
    load_owasp_crs: true,
    custom_directives: '',
    request_body_limit: 134217728,
    request_body_limit_action: 'Reject' as const,
  };

  it('lets a host override the global limit in merge mode', () => {
    const effective = resolveEffectiveWaf(globalWaf, { enabled: true, request_body_limit: 536870912 });
    expect(effective?.request_body_limit).toBe(536870912);
    expect(effective?.request_body_limit_action).toBe('Reject');
  });

  it('inherits the global limit when the host leaves it unset', () => {
    const effective = resolveEffectiveWaf(globalWaf, { enabled: true });
    expect(effective?.request_body_limit).toBe(134217728);
  });

  it('does not inherit the global limit in override mode', () => {
    const effective = resolveEffectiveWaf(globalWaf, { enabled: true, waf_mode: 'override' });
    expect(effective?.request_body_limit).toBeUndefined();
  });
});

describe('findInvalidBodyLimitDirective', () => {
  it('reports the offending line so the user gets a precise error', () => {
    expect(findInvalidBodyLimitDirective('SecRequestBodyLimit 10737418240'))
      .toBe('SecRequestBodyLimit 10737418240');
  });

  it('passes in-range limits, comments and unrelated directives', () => {
    expect(findInvalidBodyLimitDirective([
      '# raise the upload ceiling',
      'SecRequestBodyLimit 536870912',
      'SecRule ARGS "@contains evil" "id:9001,deny"',
    ].join('\n'))).toBeNull();
    expect(findInvalidBodyLimitDirective('')).toBeNull();
    expect(findInvalidBodyLimitDirective(undefined)).toBeNull();
  });
});

describe('parseBodyLimitMib', () => {
  it('converts MiB to bytes and treats blank as unset', () => {
    expect(parseBodyLimitMib('512', 'Limit')).toBe(536870912);
    expect(parseBodyLimitMib('', 'Limit')).toBeUndefined();
    expect(parseBodyLimitMib('  ', 'Limit')).toBeUndefined();
    expect(parseBodyLimitMib(null, 'Limit')).toBeUndefined();
  });

  it('rejects values Coraza would refuse', () => {
    expect(() => parseBodyLimitMib('1025', 'Limit')).toThrow(/between 1 and 1024/);
    expect(() => parseBodyLimitMib('0', 'Limit')).toThrow();
    expect(() => parseBodyLimitMib('1.5', 'Limit')).toThrow();
    expect(() => parseBodyLimitMib('abc', 'Limit')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// filterCustomDirectives
// ---------------------------------------------------------------------------
// The allowlist that guards custom_directives. buildWafHandler must only ever
// emit `kept`. The `dropped` list is what validation surfaces to the user so a
// directive like SecRuleUpdateActionById (discussion #146) fails loudly instead
// of silently doing nothing.

describe('filterCustomDirectives', () => {
  it('keeps plain SecRule, SecAction, SecMarker and SecDefaultAction lines', () => {
    const { kept, dropped } = filterCustomDirectives([
      'SecRule REQUEST_URI "@contains /admin" "id:1001,phase:1,deny"',
      'SecAction "id:1101,phase:1,log"',
      'SecMarker marker1',
      'SecDefaultAction "phase:1,log,pass"',
    ].join('\n'));
    expect(dropped).toEqual([]);
    expect(kept).toHaveLength(4);
  });

  it('drops rule-mutation/engine directives with a reason', () => {
    const { kept, dropped } = filterCustomDirectives('SecRuleUpdateActionById 930130 "block"');
    expect(kept).toEqual([]);
    expect(dropped).toHaveLength(1);
    expect(dropped[0]).toMatchObject({ line: 'SecRuleUpdateActionById 930130 "block"' });
    expect(dropped[0].reason).toMatch(/rule-mutation/);
  });

  it('drops Include directives with a reason', () => {
    const { dropped } = filterCustomDirectives('Include @owasp_crs/*.conf');
    expect(dropped[0].reason).toMatch(/Include is not allowed/);
  });

  it('drops out-of-range body limits but keeps in-range ones', () => {
    const { kept, dropped } = filterCustomDirectives([
      'SecRequestBodyLimit 10737418240',
      'SecRequestBodyLimit 536870912',
    ].join('\n'));
    expect(dropped).toHaveLength(1);
    expect(dropped[0].line).toBe('SecRequestBodyLimit 10737418240');
    expect(kept).toContain('SecRequestBodyLimit 536870912');
  });

  it('drops ctl:ruleEngine even inside an allowed line', () => {
    const { dropped } = filterCustomDirectives('SecAction "id:9001,phase:1,ctl:ruleEngine=Off"');
    expect(dropped).toHaveLength(1);
    expect(dropped[0].reason).toMatch(/ctl:ruleEngine/);
  });

  it('drops rules using operators that read files or run programs', () => {
    const lines = [
      'SecRule FILES_TMPNAMES "@inspectFile /usr/local/bin/scan" "id:9101,deny"',
      'SecRule ARGS "@pmFromFile /etc/hosts" "id:9102,deny"',
      'SecRule ARGS "@pmf words.txt" "id:9103,deny"',
      'SecRule REMOTE_ADDR "!@ipMatchFromFile /data/ips.txt" "id:9104,deny"',
      'SecRule REMOTE_ADDR "@ipMatchF ips.txt" "id:9105,deny"',
      'SecRule REQUEST_BODY "@validateSchema /data/schema.json" "id:9106,deny"',
      'SecRule ARGS "@INSPECTFILE /bin/x" "id:9107,deny"',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([]);
    expect(dropped).toHaveLength(lines.length);
    for (const item of dropped) expect(item.reason).toMatch(/reads files or runs programs/);
  });

  it('keeps rules whose operators only look similar to file operators', () => {
    const line = 'SecRule ARGS "@pm pmfoo inspectFile" "id:9108,deny"';
    const { kept, dropped } = filterCustomDirectives(line);
    expect(dropped).toEqual([]);
    expect(kept).toEqual([line]);
  });

  it('preserves empty lines and comments', () => {
    const { kept, dropped } = filterCustomDirectives('# comment\n\nSecRule ARGS "@contains evil" "id:9002,deny"');
    expect(dropped).toEqual([]);
    expect(kept).toEqual(['# comment', '', 'SecRule ARGS "@contains evil" "id:9002,deny"']);
  });

  it('returns empty results for blank input', () => {
    expect(filterCustomDirectives('')).toEqual({ kept: [], dropped: [] });
    expect(filterCustomDirectives(undefined)).toEqual({ kept: [], dropped: [] });
  });

  it('drops the setenv action, which changes the Caddy process environment', () => {
    const lines = [
      'SecAction "id:9201,phase:1,pass,nolog,setenv:GODEBUG=x509sha1=1"',
      'SecRule ARGS "@contains x" "id:9202,pass, SETENV :FOO=%{REQUEST_HEADERS.x}"',
      'SecDefaultAction "phase:1,log,pass,setenv:FOO=1"',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([]);
    expect(dropped).toHaveLength(lines.length);
    for (const item of dropped) expect(item.reason).toMatch(/setenv is not allowed/);
  });

  // Coraza trims action keys and values with Go's strings.TrimSpace (which
  // also strips U+0085) and removes one pair of quotes around a value, so
  // each of these still runs setenv or turns the rule engine off.
  it('drops setenv and ctl:ruleEngine however Coraza lets them be spaced or quoted', () => {
    const lines = [
      'SecAction "id:9211,phase:1,pass,nolog,ctl: ruleEngine=Off"',
      'SecAction "id:9212,phase:1,pass,nolog,ctl :ruleEngine=Off"',
      'SecAction "id:9213,phase:1,pass,nolog,ctl:\'ruleEngine=Off\'"',
      'SecAction "id:9214,phase:1,pass,nolog,ctl\u0085:ruleEngine=Off"',
      'SecRule ARGS "@contains x" "id:9215,pass,ctl:\u0085ruleEngine=DetectionOnly"',
      'SecAction "id:9216,phase:1,pass,nolog,setenv\u0085:GODEBUG=x509sha1=1"',
      'SecAction "id:9217,phase:1,pass,nolog,\u0085setenv:GODEBUG=x509sha1=1"',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([]);
    expect(dropped.map((d) => d.line)).toEqual(lines);
    for (const item of dropped) expect(item.reason).toMatch(/ctl:ruleEngine is not allowed|setenv is not allowed/);
  });

  it('keeps other ctl actions', () => {
    const line = 'SecRule REQUEST_URI "@beginsWith /api" "id:9218,phase:1,pass,nolog,ctl:ruleRemoveById=941100"';
    expect(filterCustomDirectives(line)).toEqual({ kept: [line], dropped: [] });
  });

  // Coraza fails to build a WAF when one rule doesn't parse, and Caddy then
  // rejects the whole config document.
  it('drops rule directives Coraza cannot parse', () => {
    const lines = [
      'SecRule\tARGS "@contains x" "id:9221,deny"',
      'SecRule ARGS "@contains x" \'id:9222,deny\'',
      'SecRule ARGS "@contains x" "id:9223,deny" trailing',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([]);
    expect(dropped.map((d) => d.line)).toEqual(lines);
    for (const item of dropped) expect(item.reason).toMatch(/Coraza cannot parse it/);
  });

  it('drops a directive the text never finishes, which Coraza would join onto the next one', () => {
    const standalone = 'SecRule ARGS "@contains x" "id:9231,deny"';
    const unfinished = 'SecAction "id:9232,phase:1,pass,nolog" \\';
    const { kept, dropped } = filterCustomDirectives([standalone, unfinished].join('\n'));
    expect(kept).toEqual([standalone]);
    expect(dropped).toEqual([{ line: unfinished, reason: expect.stringMatching(/never finished/) }]);

    const handler = buildWafHandler({ ...baseWaf, custom_directives: unfinished, request_body_limit: 1_048_576 });
    expect(handler.directives).not.toContain('id:9232');
  });

  it('trims lines the way Coraza does, U+0085 included', () => {
    const line = 'SecRequestBodyLimit 1048576\u0085';
    expect(filterCustomDirectives(line)).toEqual({ kept: [line], dropped: [] });
    expect(findInvalidBodyLimitDirective('SecRequestBodyLimit 10737418240\u0085')).toBe('SecRequestBodyLimit 10737418240');
  });
});

// A chain is one rule to Coraza: the SecRule after a `chain` starter becomes
// its child. Dropping only some of its lines hands Coraza a different rule —
// or one it refuses to parse, which makes Caddy reject the whole config.
describe('filterCustomDirectives — chained and multi-line rules', () => {
  const standalone = 'SecRule ARGS "@contains x" "id:101,deny"';

  it('drops the whole chain when a chain child is dropped, keeping the next rule standalone', () => {
    const starter = 'SecRule REQUEST_URI "@beginsWith /admin" "id:100,deny,chain"';
    const child = 'SecRule REMOTE_ADDR "!@ipMatchFromFile allow.txt"';
    const { kept, dropped } = filterCustomDirectives([starter, child, standalone].join('\n'));
    expect(kept).toEqual([standalone]);
    expect(dropped.map((d) => d.line)).toEqual([starter, child]);
    expect(dropped[0].reason).toMatch(/part of a chained rule whose line "SecRule REMOTE_ADDR/);
    expect(dropped[1].reason).toMatch(/ipMatchFromFile is not allowed/);
  });

  it('drops the chain children when the chain starter is dropped', () => {
    const starter = 'SecRule ARGS "@pmFromFile /etc/hosts" "id:110,deny,chain"';
    const child = 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8"';
    const { kept, dropped } = filterCustomDirectives([starter, child, standalone].join('\n'));
    expect(kept).toEqual([standalone]);
    expect(dropped.map((d) => d.line)).toEqual([starter, child]);
  });

  it('drops every link of a longer chain, across comments, when a middle link is dropped', () => {
    const lines = [
      'SecRule REQUEST_URI "@beginsWith /api" "id:120,phase:1,deny,chain"',
      '# the middle link reads a file',
      'SecRule REQUEST_HEADERS:User-Agent "@pmf agents.txt" "chain"',
      'SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8"',
      standalone,
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual(['# the middle link reads a file', standalone]);
    expect(dropped.map((d) => d.line)).toEqual([lines[0], lines[2], lines[3]]);
  });

  it('keeps a chain untouched when none of its lines is dropped', () => {
    const lines = [
      'SecRule REQUEST_URI "@beginsWith /admin" "id:130,phase:1,deny,msg:\'no, chain here\',chain"',
      'SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8"',
      'SecRule ARGS "@pmFromFile /etc/hosts" "id:131,deny"',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([lines[0], lines[1]]);
    expect(dropped.map((d) => d.line)).toEqual([lines[2]]);
  });

  it('does not treat chain inside a quoted action value or operator as the chain action', () => {
    const lines = [
      'SecRule ARGS "@contains chain" "id:140,deny,msg:\'chain\'"',
      'SecRule ARGS "@pmFromFile /etc/hosts" "id:141,deny"',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([lines[0]]);
    expect(dropped.map((d) => d.line)).toEqual([lines[1]]);
  });

  it('ends a pending chain at SecMarker', () => {
    const lines = [
      'SecRule ARGS "@pmFromFile /etc/hosts" "id:150,deny,chain"',
      'SecMarker END_CHECKS',
      standalone,
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([lines[1], standalone]);
    expect(dropped.map((d) => d.line)).toEqual([lines[0]]);
  });

  it('drops every line of a backslash-continued directive together', () => {
    const lines = [
      'SecRule REQUEST_URI "@beginsWith /admin" \\',
      '    "id:160,phase:1,deny"',
      standalone,
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([standalone]);
    expect(dropped.map((d) => d.line)).toEqual([lines[0], lines[1].trim()]);
    expect(dropped[0].reason).toMatch(/part of a multi-line directive/);
  });

  it('drops the chain child of a dropped multi-line chain starter', () => {
    const lines = [
      'SecRule REQUEST_URI "@beginsWith /admin" \\',
      '    "id:170,deny,chain"',
      'SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8"',
      standalone,
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'));
    expect(kept).toEqual([standalone]);
    expect(dropped).toHaveLength(3);
  });

  it('keeps no partial chain in the generated handler', () => {
    const handler = buildWafHandler({
      ...baseWaf,
      custom_directives: [
        'SecRule REQUEST_URI "@beginsWith /admin" "id:100,deny,chain"',
        'SecRule REMOTE_ADDR "!@ipMatchFromFile allow.txt"',
        standalone,
      ].join('\n'),
    });
    const directives = handler.directives as string;
    expect(directives).not.toContain('id:100');
    expect(directives).toContain(standalone);
  });
});

// With load_owasp_crs, coraza-caddy serves `@owasp_crs/<file>` from the
// embedded CRS filesystem, so data-file operators pointing there read no
// container files.
// Coraza refuses a rule id already in its rule group, and Caddy then refuses
// the whole config, so a repeated id is dropped like any other bad line.
describe('filterCustomDirectives — duplicate rule ids', () => {
  it('drops a later rule that reuses a kept rule\'s id, with its chain', () => {
    const first = 'SecRule ARGS "@contains a" "id:9701,deny"';
    const again = 'SecAction "id:9701,phase:1,pass,nolog"';
    const starter = `SecRule REQUEST_URI "@beginsWith /x" "id:'09701',deny,chain"`;
    const child = 'SecRule ARGS "@contains b" "t:none"';
    const next = 'SecRule ARGS "@contains c" "id:9702,deny"';
    const { kept, dropped } = filterCustomDirectives([first, again, starter, child, next].join('\n'));
    expect(kept).toEqual([first, next]);
    expect(dropped).toEqual([
      { line: again, reason: expect.stringMatching(/^rule id 9701 is already used by an earlier rule/) },
      { line: starter, reason: expect.stringMatching(/^rule id 9701 is already used/) },
      { line: child, reason: `part of a chained rule whose line "${starter}" is dropped` },
    ]);
  });

  it('lets a rule reuse the id of a rule that is dropped for another reason', () => {
    const droppedFirst = 'SecRule ARGS "@contains a" "id:9711,deny,setenv:x=1"';
    const reuse = 'SecRule ARGS "@contains b" "id:9711,deny"';
    expect(filterCustomDirectives(`${droppedFirst}\n${reuse}`).kept).toEqual([reuse]);
  });

  it('keeps a repeated template out of the generated handler, whichever part of a merge repeats it', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const template = WAF_QUICK_TEMPLATES.find((t) => t.label === 'Skip OWASP CRS for path')!.snippet;
    const twice = `${template}\n${template.replace('/api/', '/webhook/')}`;
    expect(filterCustomDirectives(twice, { crsLoaded: true }).kept).toEqual([template]);

    const global = { ...baseWaf, load_owasp_crs: true, custom_directives: template };
    const host = { enabled: true, waf_mode: 'merge' as const, custom_directives: template };
    const handler = buildWafHandler(resolveEffectiveWaf(global, host)!, wafDirectiveSource(global, host, 'proxy host "dup-9001"'));
    expect(String(handler.directives).match(/id:9001,/g)).toHaveLength(1);
    const messages = warn.mock.calls.map((args) => String(args[0]));
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain('[waf] proxy host "dup-9001":');
    expect(messages[0]).toContain('rule id 9001 is already used');
    warn.mockRestore();
  });
});

describe('filterCustomDirectives — embedded CRS data files', () => {
  const crsRule = 'SecRule REQUEST_HEADERS:User-Agent "@pmFromFile @owasp_crs/scanners-user-agents.data" "id:9301,deny"';

  it('keeps data-file operators reading an embedded CRS data file', () => {
    const lines = [
      crsRule,
      'SecRule ARGS "@pmf @owasp_crs/unix-shell.data" "id:9302,deny"',
      'SecRule REMOTE_ADDR "!@ipMatchFromFile @owasp_crs/ssrf.data" "id:9303,deny"',
      'SecRule REMOTE_ADDR "@ipMatchF   @owasp_crs/ssrf-no-scheme.data" "id:9304,deny"',
    ];
    for (const crsLoaded of [true, undefined]) {
      const { kept, dropped } = filterCustomDirectives(lines.join('\n'), { crsLoaded });
      expect(dropped).toEqual([]);
      expect(kept).toEqual(lines);
    }
  });

  it('drops them when the CRS filesystem is not loaded', () => {
    const { kept, dropped } = filterCustomDirectives(crsRule, { crsLoaded: false });
    expect(kept).toEqual([]);
    expect(dropped[0].reason).toMatch(/only exists when the OWASP CRS is loaded/);
  });

  it('drops paths that leave the embedded prefix and operators that are not data lookups', () => {
    const lines = [
      'SecRule ARGS "@pmFromFile @owasp_crs/../../etc/passwd" "id:9311,deny"',
      'SecRule ARGS "@pmFromFile @owasp_crs/sub/x.data" "id:9312,deny"',
      'SecRule ARGS "@pmFromFile @owasp_crs/..data" "id:9313,deny"',
      'SecRule ARGS "@pmFromFile /srv/@owasp_crs/x.data" "id:9314,deny"',
      'SecRule ARGS "@pmFromFile @owasp_crs/a.data @owasp_crs/b.data" "id:9315,deny"',
      'SecRule FILES_TMPNAMES "@inspectFile @owasp_crs/x.data" "id:9316,deny"',
      'SecRule REQUEST_BODY "@validateSchema @owasp_crs/x.data" "id:9317,deny"',
      'SecRule ARGS "@pmFromFile @owasp_crs/x.data" "id:9318,deny,msg:\'@pmf /etc/hosts\'"',
      'SecRule ARGS "@rx @pmFromFile @owasp_crs/x.data" "id:9319,deny"',
      'SecRule ARGS "@pmFromFile @owasp_crs/x.data" \\',
    ];
    const { kept, dropped } = filterCustomDirectives(lines.join('\n'), { crsLoaded: true });
    expect(kept).toEqual([]);
    expect(dropped).toHaveLength(lines.length);
    for (const item of dropped) {
      expect(item.reason).toMatch(/reads files or runs programs|is not a data file of the embedded OWASP CRS/);
    }
  });

  // Coraza v3.7.0 looks operators up case-sensitively and fails to load a
  // data file the embedded rule set lacks; either one makes Caddy refuse the
  // whole config.
  it('keeps only the operator spellings Coraza registers', () => {
    for (const operator of ['pmfromfile', 'PMF', 'PmFromFile', 'ipmatchf', 'IPMatchFromFile']) {
      const line = `SecRule ARGS "@${operator} @owasp_crs/unix-shell.data" "id:9321,deny"`;
      const { kept, dropped } = filterCustomDirectives(line, { crsLoaded: true });
      expect(kept).toEqual([]);
      expect(dropped[0].reason).toMatch(/operator names are case-sensitive/);
      expect(customDirectivesError(line, { crsLoaded: true })).toMatch(/will be dropped/);
    }
    expect(filterCustomDirectives('SecRule ARGS "@PMF @owasp_crs/unix-shell.data" "id:9321,deny"').dropped[0].reason)
      .toContain('use @pmf');
  });

  it('keeps only data files the embedded rule set ships', () => {
    for (const file of ['unix-shel.data', 'Unix-Shell.data', 'unix-shell.conf', 'REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example']) {
      const line = `SecRule ARGS "@pmFromFile @owasp_crs/${file}" "id:9322,deny"`;
      const { kept, dropped } = filterCustomDirectives(line, { crsLoaded: true });
      expect(kept).toEqual([]);
      expect(dropped[0].reason).toBe(`@owasp_crs/${file} is not a data file of the embedded OWASP CRS (coraza-coreruleset v4.25.0)`);
    }
    for (const file of ['unix-shell.data', 'windows-powershell-commands.data', 'php-function-names-933150.data']) {
      const line = `SecRule ARGS "@pmFromFile @owasp_crs/${file}" "id:9323,deny"`;
      expect(filterCustomDirectives(line, { crsLoaded: true })).toEqual({ kept: [line], dropped: [] });
      expect(customDirectivesError(line, { crsLoaded: true })).toBeNull();
    }
  });

  it('emits the rule only when the handler loads the CRS', () => {
    expect(buildWafHandler({ ...baseWaf, load_owasp_crs: true, custom_directives: crsRule }).directives).toContain(crsRule);
    expect(buildWafHandler({ ...baseWaf, load_owasp_crs: false, custom_directives: crsRule }).directives).not.toContain(crsRule);
  });
});

describe('buildWafHandler — dropped directive warning', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('logs the dropped lines once per source and content', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const waf = { ...baseWaf, custom_directives: 'SecRule ARGS "@pmFromFile /etc/warn-test" "id:9401,deny"' };

    buildWafHandlerEntry(waf, false, 'proxy host "app.example.com"');
    buildWafHandlerEntry(waf, false, 'proxy host "app.example.com"');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('proxy host "app.example.com"');
    expect(warn.mock.calls[0][0]).toContain('@pmFromFile /etc/warn-test');
    expect(warn.mock.calls[0][0]).toMatch(/reads files or runs programs/);

    buildWafHandlerEntry(waf, false, 'proxy host "other.example.com"');
    expect(warn).toHaveBeenCalledTimes(2);
  });

  it('reports global lines under the global settings, once, and host lines under the host', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const globalRule = 'SecRule ARGS "@pmFromFile /etc/warn-global" "id:9403,deny"';
    const hostRule = 'SecRule ARGS "@pmFromFile /etc/warn-host" "id:9404,deny"';
    const global = { ...baseWaf, custom_directives: `\n# global\n${globalRule}` };
    const hosts = [
      { label: 'proxy host "a"', config: { enabled: true, custom_directives: hostRule } },
      { label: 'proxy host "b"', config: { enabled: true } },
      { label: 'proxy host "c"', config: null },
    ];
    for (const { label, config } of hosts) {
      const effective = resolveEffectiveWaf(global, config)!;
      buildWafHandlerEntry(effective, false, wafDirectiveSource(global, config, label));
    }

    const messages = warn.mock.calls.map((args) => String(args[0]));
    const globalWarnings = messages.filter((message) => message.includes('warn-global'));
    expect(globalWarnings).toHaveLength(1);
    expect(globalWarnings[0]).toContain(`[waf] ${GLOBAL_WAF_SOURCE}:`);
    expect(globalWarnings[0]).not.toContain('warn-host');
    const hostWarnings = messages.filter((message) => message.includes('warn-host'));
    expect(hostWarnings).toHaveLength(1);
    expect(hostWarnings[0]).toContain('[waf] proxy host "a":');
    expect(hostWarnings[0]).not.toContain('warn-global');
  });

  it('reports an override-mode host\'s lines under the host', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const global = { ...baseWaf, custom_directives: 'SecRule ARGS "@contains x" "id:9405,deny"' };
    const config = {
      enabled: true,
      waf_mode: 'override' as const,
      custom_directives: 'SecRule ARGS "@pmFromFile /etc/warn-override" "id:9406,deny"',
    };
    buildWafHandlerEntry(resolveEffectiveWaf(global, config)!, false, wafDirectiveSource(global, config, 'proxy host "d"'));
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('[waf] proxy host "d":');
  });

  it('reports a global line that only this host\'s CRS setting drops under the host', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const crsRule = 'SecRule ARGS "@pmFromFile @owasp_crs/unix-shell.data" "id:9407,phase:2,deny"';
    const global = { ...baseWaf, load_owasp_crs: true, custom_directives: crsRule };
    const hosts = [
      { label: 'proxy host "H" (h.example.com)', config: { enabled: true, waf_mode: 'merge' as const, load_owasp_crs: false } },
      { label: 'proxy host "I" (i.example.com)', config: null },
    ];
    for (const { label, config } of hosts) {
      buildWafHandler(resolveEffectiveWaf(global, config)!, wafDirectiveSource(global, config, label));
    }
    expect(warn).toHaveBeenCalledTimes(1);
    const message = String(warn.mock.calls[0][0]);
    expect(message).toContain(`[waf] proxy host "H" (h.example.com), from the ${GLOBAL_WAF_SOURCE}:`);
    expect(message).toContain('@owasp_crs/unix-shell.data');
    expect(message).not.toContain(`[waf] ${GLOBAL_WAF_SOURCE}:`);
  });

  it('reports a global chain that the host\'s first line breaks under the host', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const starter = 'SecRule REQUEST_URI "@beginsWith /admin" "id:9408,phase:2,deny,chain"';
    const child = 'SecRule ARGS "@pmFromFile /etc/warn-chain" "t:none"';
    const global = { ...baseWaf, custom_directives: starter };
    const config = { enabled: true, custom_directives: child };
    buildWafHandler(resolveEffectiveWaf(global, config)!, wafDirectiveSource(global, config, 'proxy host "J"'));
    const messages = warn.mock.calls.map((args) => String(args[0]));
    expect(messages).toHaveLength(2);
    const fromGlobal = messages.find((m) => m.startsWith(`[waf] proxy host "J", from the ${GLOBAL_WAF_SOURCE}:`));
    expect(fromGlobal).toContain(`"${starter}" → part of a chained rule`);
    const fromHost = messages.find((m) => m.startsWith('[waf] proxy host "J":'));
    expect(fromHost).toContain(`"${child}" → @pmFromFile is not allowed`);
    expect(fromHost).not.toContain('id:9408');
  });

  it('stays quiet when every directive is kept', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    buildWafHandler({ ...baseWaf, custom_directives: 'SecRule ARGS "@contains quiet" "id:9402,deny"' });
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('customDirectivesError', () => {
  it('reports out-of-range body limits, then dropped lines, and null when all lines are kept', () => {
    expect(customDirectivesError('SecRequestBodyLimit 10737418240')).toMatch(/out-of-range body limit/);
    expect(customDirectivesError('Include /etc/passwd')).toMatch(/will be dropped and never sent to Caddy/);
    expect(customDirectivesError('SecRule ARGS "@contains x" "id:9501,deny"')).toBeNull();
    expect(customDirectivesError('')).toBeNull();
  });

  it('passes the CRS state through to the filter', () => {
    const rule = 'SecRule ARGS "@pmf @owasp_crs/unix-shell.data" "id:9502,deny"';
    expect(customDirectivesError(rule, { crsLoaded: true })).toBeNull();
    expect(customDirectivesError(rule, { crsLoaded: false })).toMatch(/OWASP CRS is loaded/);
  });
});

// With the stored value passed as `previous`, only what the change newly
// drops is an error: a stored rule a later release started dropping must not
// block other edits, but nothing new may be dropped silently.
describe('customDirectivesError — against the stored directives', () => {
  const legacy = 'SecRule REMOTE_ADDR "@ipMatchFromFile /etc/caddy/blocklist.txt" "id:9601,phase:1,deny"';
  const kept = 'SecRule ARGS "@contains x" "id:9602,deny"';
  const crsRule = 'SecRule ARGS "@pmf @owasp_crs/unix-shell.data" "id:9603,deny"';

  it('accepts a stored dropped line left in place, alone or next to new kept lines', () => {
    const previous = { directives: legacy };
    expect(customDirectivesError(legacy, {}, previous)).toBeNull();
    expect(customDirectivesError(`  ${legacy}  \r\n${kept}`, {}, previous)).toBeNull();
  });

  it('rejects a newly dropped line and reports only that one', () => {
    const added = 'SecRule ARGS "@pmFromFile /etc/hosts" "id:9604,deny"';
    const message = customDirectivesError(`${legacy}\n${added}`, {}, { directives: legacy });
    expect(message).toMatch(/contains 1 line\(s\) that will be dropped/);
    expect(message).toContain(added);
    expect(message).not.toContain('id:9601');
  });

  it('rejects a second copy of a stored dropped line', () => {
    expect(customDirectivesError(`${legacy}\n${legacy}`, {}, { directives: legacy })).toMatch(/ipMatchFromFile is not allowed/);
  });

  it('rejects turning the CRS off under an unchanged rule that needs it', () => {
    const previous = { directives: crsRule, options: { crsLoaded: true } };
    expect(customDirectivesError(crsRule, { crsLoaded: true }, previous)).toBeNull();
    expect(customDirectivesError(crsRule, { crsLoaded: false }, previous)).toMatch(/OWASP CRS is loaded/);
    expect(customDirectivesError(crsRule, { crsLoaded: false }, { directives: crsRule, options: { crsLoaded: false } })).toBeNull();
  });

  it('rejects a kept line that a newly added chain starter drags along', () => {
    const starter = 'SecRule REQUEST_URI "@beginsWith /admin" "id:9605,deny,chain"';
    const message = customDirectivesError(`${starter}\n${legacy}`, {}, { directives: legacy });
    expect(message).toContain(starter);
    expect(message).toMatch(/part of a chained rule/);
  });

  it('keeps the body-limit message for a newly out-of-range body limit', () => {
    expect(customDirectivesError(`${legacy}\nSecRequestBodyLimit 10737418240`, {}, { directives: legacy }))
      .toMatch(/out-of-range body limit: "SecRequestBodyLimit 10737418240"/);
    expect(customDirectivesError('SecRequestBodyLimit 10737418240', {}, { directives: 'SecRequestBodyLimit 10737418240' }))
      .toBeNull();
  });
});

describe('customDirectivesError — duplicate rule ids', () => {
  const template = WAF_QUICK_TEMPLATES.find((t) => t.label === 'Skip OWASP CRS for path')!.snippet;

  it('rejects a rule id used twice in the value', () => {
    expect(customDirectivesError(`${template}\n${template.replace('/api/', '/webhook/')}`, { crsLoaded: true }))
      .toMatch(/rule id 9001 is already used by an earlier rule/);
  });

  it('checks a merge-mode host against the global directives it follows, reporting only its own lines', () => {
    expect(customDirectivesError(template, { precedingDirectives: template })).toMatch(/rule id 9001 is already used/);
    expect(customDirectivesError(template, { precedingDirectives: `Include /etc/passwd\n${template.replace('9001', '9101')}` }))
      .toBeNull();
    expect(customDirectivesError('', { precedingDirectives: `${template}\n${template}` })).toBeNull();
  });

  it('accepts a stored duplicate left in place', () => {
    const stored = `${template}\n${template}`;
    expect(customDirectivesError(stored, {}, { directives: stored })).toBeNull();
    expect(customDirectivesError(`${stored}\n${template}`, {}, { directives: stored })).toMatch(/rule id 9001/);
  });
});

// Both WAF forms offer these; a snippet the filter drops would make the form
// refuse to save right after the click.
describe('WAF_QUICK_TEMPLATES', () => {
  it('only inserts lines the filter keeps, with or without the CRS', () => {
    for (const { label, snippet } of WAF_QUICK_TEMPLATES) {
      for (const crsLoaded of [true, false, undefined]) {
        expect({ label, ...filterCustomDirectives(snippet, { crsLoaded }) }).toEqual({ label, kept: [snippet], dropped: [] });
        expect(customDirectivesError(snippet, { crsLoaded })).toBeNull();
      }
    }
    const all = WAF_QUICK_TEMPLATES.map((t) => t.snippet).join('\n');
    expect(filterCustomDirectives(all, { crsLoaded: true }).dropped).toEqual([]);
  });

  it('gives every template its own rule id', () => {
    const ids = WAF_QUICK_TEMPLATES.map((t) => /\bid:(\d+)/.exec(t.snippet)?.[1]);
    expect(ids.every(Boolean)).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('inserts a template as is into an empty value, on a new line otherwise', () => {
    const [first, second] = WAF_QUICK_TEMPLATES;
    expect(appendQuickTemplate('', first)).toBe(first.snippet);
    expect(appendQuickTemplate('# mine', second)).toBe(`# mine\n${second.snippet}`);
  });

  it('moves the rule id past the ids in use, so clicking templates again stays loadable', () => {
    let global = '';
    let host = '';
    for (let round = 0; round < 3; round++) {
      for (const template of WAF_QUICK_TEMPLATES) {
        global = appendQuickTemplate(global, template);
        host = appendQuickTemplate(host, template, HOST_TEMPLATE_ID_OFFSET);
      }
    }
    expect(global.split('\n')).toHaveLength(3 * WAF_QUICK_TEMPLATES.length);
    expect(filterCustomDirectives(global, { crsLoaded: true }).dropped).toEqual([]);
    expect(customDirectivesError(host, { crsLoaded: true, precedingDirectives: global })).toBeNull();
    const merged = resolveEffectiveWaf(
      { ...baseWaf, load_owasp_crs: true, custom_directives: global },
      { enabled: true, custom_directives: host }
    )!;
    expect(filterCustomDirectives(merged.custom_directives, { crsLoaded: true }).dropped).toEqual([]);
  });

  it('switches CRS rules off per transaction instead of with rule-removal directives', () => {
    const byLabel = new Map(WAF_QUICK_TEMPLATES.map((t) => [t.label, t.snippet]));
    expect(byLabel.get('Skip OWASP CRS for path')).toMatch(/^SecRule REQUEST_FILENAME "@rx \\A\/api\/.*\\z" ".*phase:1,.*ctl:ruleRemoveByTag=OWASP_CRS"$/);
    expect(byLabel.get('Skip OWASP CRS XSS rules')).toMatch(/^SecAction ".*phase:1,.*ctl:ruleRemoveByTag=attack-xss"$/);
  });
});

describe('droppedWafDirectiveMessage', () => {
  it('names each dropped line and its reason', () => {
    const msg = droppedWafDirectiveMessage([
      { line: 'SecRuleUpdateActionById 930130 "block"', reason: 'rule-mutation/engine directives are not allowed' },
    ]);
    expect(msg).toMatch(/will be dropped and never sent to Caddy/);
    expect(msg).toMatch(/SecRuleUpdateActionById 930130 "block"/);
    expect(msg).toMatch(/rule-mutation/);
  });
});

// Stored lines that predate a filter rule are left out of the config; a
// left-out deny rule silently stops blocking, so the WAF page lists them.
describe('listDroppedWafDirectives', () => {
  const fromFile = 'SecRule REMOTE_ADDR "!@ipMatchFromFile /data/allow.txt" "id:9501,phase:1,deny,status:403"';
  const kept = 'SecRule ARGS "@contains evil" "id:9502,deny"';

  it('lists global and host lines under their source, once each', () => {
    const global = { ...baseWaf, custom_directives: `${fromFile}\n${kept}` };
    const hosts = [
      { name: 'inherits', domains: ['a.example.com'], waf: null },
      {
        name: 'merged',
        domains: ['b.example.com'],
        waf: { enabled: true, waf_mode: 'merge' as const, custom_directives: 'SecAction "id:9601,phase:1,setenv:X=1"' },
      },
    ];
    const reports = listDroppedWafDirectives(global, hosts);
    expect(reports.map(({ source, line }) => [source, line])).toEqual([
      [GLOBAL_WAF_SOURCE, fromFile],
      ['proxy host "merged" (b.example.com)', 'SecAction "id:9601,phase:1,setenv:X=1"'],
    ]);
    expect(reports[0].reason).toMatch(/ipMatchFromFile/);
  });

  it('lists nothing for a WAF that is off or has only kept lines', () => {
    expect(listDroppedWafDirectives({ ...baseWaf, enabled: false, custom_directives: fromFile }, [])).toEqual([]);
    expect(listDroppedWafDirectives({ ...baseWaf, mode: 'Off', custom_directives: fromFile }, [])).toEqual([]);
    expect(listDroppedWafDirectives({ ...baseWaf, custom_directives: kept }, [])).toEqual([]);
  });
});

describe('phase 1 allow rules in custom directives (#373)', () => {
  it('are emitted before the CRS include; other rules stay after', () => {
    const h = buildWafHandler({
      enabled: true, mode: 'On', load_owasp_crs: true,
      custom_directives: 'SecRule REMOTE_ADDR "@ipMatch 192.168.200.0/23" "id:9000,phase:1,allow,nolog"\nSecRule REQUEST_URI "@contains /x" "id:9001,phase:1,deny"',
    } as never) as { directives: string };
    const d = h.directives;
    expect(d.indexOf('id:9000')).toBeGreaterThan(-1);
    expect(d.indexOf('id:9000')).toBeLessThan(d.indexOf('Include @owasp_crs/*.conf'));
    expect(d.indexOf('id:9001')).toBeGreaterThan(d.indexOf('Include @owasp_crs/*.conf'));
  });
});
