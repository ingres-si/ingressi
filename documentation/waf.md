# Web application firewall

The WAF inspects requests before they reach a proxy host's upstream. It is [Coraza](https://coraza.io/) with the OWASP Core Rule Set 4.25, both built into the Caddy image. It is off until an administrator turns it on, for one host or for all hosts.

The settings are on the **WAF settings** page (`/waf`); the matched requests are on [Security events](security-events.md) (`/security`), next to the requests the other rules stopped. Reading either needs the `waf:read` permission, changing anything `waf:write`. The old WAF events address (`/waf/events`) opens Security events filtered to the WAF.

## Global mode

| Mode | What happens |
| --- | --- |
| Off | Requests reach the upstreams without inspection. Nothing is logged. |
| Detection only | Every request is checked and matches are logged as events, but nothing is blocked. |
| Blocking | A request whose anomaly score reaches the inbound threshold gets `403 Forbidden`. Every match is logged. |

**Apply to all hosts** decides which hosts use the WAF. On, every proxy host does, except hosts that turn it off. Off, only hosts that turn their WAF on use it, with the global mode unless they set their own.

## Rule set and paranoia level

**Load the Core Rule Set** adds the OWASP rules for SQL injection, cross-site scripting, file inclusion, remote code execution, scanners and protocol abuse (on by default when the WAF is on). Without it only your custom rules run.

The **paranoia level** (1 to 4, `tx.blocking_paranoia_level`) decides how many rules run:

| Level | Name | False positives |
| --- | --- | --- |
| 1 | Baseline | Rare. Common attacks, with rules that seldom match normal traffic. |
| 2 | Elevated | Some. Encoded and obfuscated attacks. Search boxes, rich-text editors and JSON APIs usually need an exclusion or two. |
| 3 | Strict | Frequent. Limits on special characters, argument lengths and request formats. Run it in detection only for a week first. |
| 4 | Paranoid | Very frequent. Only for small APIs whose inputs you control. |

**Also log level N+1 matches without blocking them** (`tx.detection_paranoia_level`) runs the rules of the next level too, but they only log: their events show what raising the level would catch, and break, before you raise it.

## Anomaly scoring

Each Core Rule Set rule that matches adds points to the request's anomaly score: critical 5, error 4, warning 3, notice 2. Rule 949110 compares the score with the **inbound anomaly threshold** (default 5, so one critical match is enough). Responses are scored the same way for leaks such as SQL errors and stack traces, against the **outbound anomaly threshold** (default 4, rule 959100). Thresholds go from 1 to 10,000; a higher threshold lets more through.

**Over the threshold** is what happens then:

- **Block with 403** (default).
- **Log only**: the request is logged as an event and reaches the upstream. Rules 949110, 949111, 959100 and 959101 are switched to `pass`. Custom rules that deny still block, unlike detection only.

These values are global. Hosts that merge with the global settings use them; a host that overrides the global settings runs the Core Rule Set defaults. They are written as `SecAction` rules 900000, 900001 and 900110 before the rules load, and only when they differ from the defaults; a custom rule that reuses one of these ids is left out of the configuration.

## Request bodies

Coraza holds each request body to inspect it. With the Core Rule Set its limit is 12.5 MiB, which is why large uploads fail with `413`. **Largest body inspected** and **Kept in memory** change it (in MiB, up to 1,024, Coraza's maximum). **Over the limit**: reject with `413`, or inspect the start and forward the rest. Hosts can set their own limits.

Form, multipart, JSON and XML bodies are parsed into arguments the rules check. Bodies of any other content type (protobuf such as OpenTelemetry traces, `application/octet-stream`, gRPC) are inspected as they are, as one value: Coraza would otherwise read them as form data, and every fragment of binary data would become an argument that dozens of attack rules match. The Core Rule Set still refuses content types it does not allow (rule 920420); exclude 920420 for the path of an API that takes such bodies.

## Per-host mode

Each proxy host has a WAF mode:

| Mode | Stored as (`waf` of the proxy host) | What it does |
| --- | --- | --- |
| Inherit | `enabled: true`, no `mode` | Uses the WAF with the global mode, also when the WAF does not apply to all hosts. |
| Off | `enabled: false` | No WAF for this host. Its other WAF settings are kept for when it is turned on again. |
| Detection only | `mode: "DetectionOnly"` | Logs, never blocks. Useful for a trial week on one host. |
| Blocking | `mode: "On"` | Blocks over the threshold. |

A host without WAF settings of its own follows the global settings. Older stored values keep their meaning: `mode: "Off"` with `enabled: true` is off.

The **Per-host settings** table on the WAF settings page shows every host's mode, whether it follows, merges with or overrides the global settings, what it changes, and its events of the last 7 days. Hosts with WAF settings of their own, exclusions or events come first; the table can be searched by name or domain, filtered by mode and is paged 25 hosts at a time. The mode can be changed there; everything else is in the proxy host's WAF section.

## Rule exclusions

An exclusion stops one rule from checking some requests. Every other rule still checks them. An exclusion has:

- **Rule**: the rule id, such as `942100`. The rules that decide blocking (949110, 949111, 959100, 959101) cannot be excluded; use detection only or log only instead.
- **Scope**: global (every host that follows or merges with the global settings) or one proxy host.
- **Path** (optional): only requests to this path, exactly or as a prefix. The path is matched decoded, without the query string, after `.` and `..` segments are resolved, so `/api/../admin` is not under `/api/`.
- **Variable** (optional): only this variable, such as `ARGS:content`, `REQUEST_HEADERS:Content-Type` or `REQUEST_COOKIES:session`. Names are plain (letters, digits, `_ . - [ ]`); regular expressions are not accepted.
- **Reason**, who added it and when.

Without a path or variable, the rule is removed for the scope (`SecRuleRemoveById`). With one, a rule that runs before the Core Rule Set removes it for matching requests (`ctl:ruleRemoveById`, or `ctl:ruleRemoveTargetById` for a variable). Generated rules take ids from 1,900,000,000 up.

Exclusions apply as soon as they are added or removed. If Caddy does not accept the new configuration, the change is undone.

The **Rule exclusions** table lists the newest first, 25 at a time, and can be searched by rule id, rule message, host, path, variable, reason or author. Its times are UTC.

Exclusions made before this release were plain rule id lists (`excluded_rule_ids` of the global settings and of each proxy host). They are turned into exclusions without a reason when Ingressi starts. The lists keep working: they always hold the exclusions without a path or variable, and sending a list through the settings or proxy host API replaces those (exclusions with a path or variable stay). Leaving the list out keeps them.

## Why a request was blocked

Open a WAF event on **Security events** to see why it was blocked: every rule that matched, the points each added, the matched variable and data, the total score against the threshold, and the rule that decided. Rules above the blocking paranoia level show as logged only. The threshold comes from the audit record when it has it, otherwise from the current settings.

For each rule that added points, the event suggests the narrowest exclusion: the rule, on the host that served the request, for the request's path, on the matched variable when the record names one. **This was a false positive** opens the exclusion form with it filled in; the host, path (picked from the directories above the request's path, or typed) and variable can all be changed before adding. A path with an ID in it matches only that one ID, so the form offers the directory above it. Only add one when the request was legitimate.

## Logs for Fail2Ban and similar tools

The `[hostname ""]` in the Coraza lines of `waf-rules.log` is always empty: Coraza fills it from the server address, which the Caddy connector does not provide, so Ingressi cannot change it. Use `waf-audit.log` (JSON, in the same log volume) instead: each record has the request's `Host` header, URI, client address and every matched rule id.

## Credentials in events

In the event log, credential header values (`Authorization`, `Cookie`, `Set-Cookie`, API-key and token headers, …) and the cookie or credential values that rule messages echo are stored as `[redacted]`.

## Custom rules

SecLang directives (`SecRule`, `SecAction`, `SecMarker`, `SecDefaultAction` and the body limit directives) run after the Core Rule Set on every host that follows or merges with the global settings. Lines that could read files, run programs or switch the WAF off are left out, and the page lists them before you save. Use ids from 9000 up; the Core Rule Set uses 900000 to 999999.

A rule with `phase:1` and the `allow` action (for example to trust a LAN range) is placed before the Core Rule Set instead, so it skips the rules after it. It is the only kind of custom rule that runs first.

```
SecRule REMOTE_ADDR "@ipMatch 192.168.0.0/16" "id:9000,phase:1,allow,nolog,msg:'Trusted LAN'"
```

For example:
```
SecRule REQUEST_URI "@beginsWith /admin/" "id:9001,phase:1,deny,status:403,log,msg:'Admin path blocked'"
```

Lines that could read files, run programs or switch the WAF off are not sent to Caddy, nor are some that would make Caddy refuse the whole config:

- `Include`, rule-engine and rule-mutation directives (`SecRuleEngine`, `SecRuleRemoveById`, `SecRuleUpdateActionById`, …)
- the operators `@pmFromFile`/`@pmf`, `@ipMatchFromFile`/`@ipMatchF`, `@inspectFile` and `@validateSchema`. The data-file operators are allowed with a single `@owasp_crs/<name>.data` argument when the CRS is loaded for that host or the global handler. The operator must use Coraza's exact, case-sensitive spelling (`@pmFromFile`, `@pmf`, `@ipMatchFromFile`, `@ipMatchF`; `@pmfromfile` or `@PMF` is dropped), and `<name>.data` must be one of the 21 data files shipped with coraza-coreruleset v4.25.0 (e.g. `unix-shell.data`, `scanners-user-agents.data`)
- the `setenv` action and `ctl:ruleEngine`, in any spacing or quoting
- `SecRule`/`SecAction`/`SecDefaultAction` lines whose structure Coraza cannot parse (e.g. a `SecRule` without a quoted operator), and any directive continued over several lines with a trailing `\` (write each directive on one line)
- a rule whose `id:` an earlier rule already uses, including a merge-mode host rule that reuses a global rule id (the global directives come first), since Coraza refuses duplicate ids. Ids that clash with OWASP CRS rules are not checked, so avoid 900000–999999 and the 2000xx ids of `coraza.conf-recommended` when the CRS is loaded

Operator names and other rule content are not validated: a typo such as `@contians` still reaches Caddy, which then refuses the whole config.

When one rule of a chain is dropped, the whole chain is dropped. Rules stored before these checks existed are not deleted: they are left out of the generated config and reported in the web container log (`[waf] <source>: N custom directive line(s) are not sent to Caddy…`). Saving a proxy host or the global WAF settings (dashboard or `PUT /api/v1/settings/waf`) is rejected only for lines the save newly drops, including turning **Load OWASP CRS** off while a rule reads an `@owasp_crs/` file, so a stored rule does not block unrelated edits. A merge-mode host that inherits the global CRS setting is not re-checked when the global CRS is turned off; its `@owasp_crs/` rules are then only reported in the log.

## REST API

| Endpoint | What |
| --- | --- |
| `GET/PUT /api/v1/settings/waf` | Global settings: `enabled`, `mode`, `load_owasp_crs`, `paranoia_level`, `detection_paranoia_level`, `inbound_anomaly_threshold`, `outbound_anomaly_threshold`, `anomaly_action` (`block` or `log`), body limits, custom directives, `excluded_rule_ids`. |
| `GET/POST /api/v1/waf/exclusions`, `GET/PATCH/DELETE /api/v1/waf/exclusions/{id}` | Rule exclusions. |
| `POST /api/v1/waf/exclusions/batch` | Several exclusions at once (`{ "exclusions": [...] }`, 1 to 50): all or none, with one apply. |
| `GET /api/v1/waf/hosts`, `GET/PUT /api/v1/waf/hosts/{id}` | Per-host modes: `{"mode": "inherit" \| "off" \| "detection_only" \| "block"}`. |
| `GET /api/v1/waf/events` | Events, newest first; `id` is Coraza's transaction id. |
| `GET /api/v1/waf/events/{id}/explain` | Why the request was blocked. |
| `GET /api/v1/waf/events/{id}/suggested-exclusion` | The suggested exclusions; post one to `/api/v1/waf/exclusions` to create it. |

Every change is recorded in the audit log. Exclusions and the global settings reach sync replicas with the rest of the configuration, and are part of configuration export, backups and history.
