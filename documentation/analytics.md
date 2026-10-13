# Traffic analytics

With access logging on and ClickHouse enabled (see [Enabling analytics](#enabling-analytics-recommended)), every request Caddy handles is stored for the retention window: 30 days by default, `CLICKHOUSE_RETENTION_DAYS` changes it. Nothing is sampled.

## Storage and retention

Analytics uses a bundled ClickHouse instance for storing and querying traffic events and WAF events. Data is retained for **30 days** by default via ClickHouse's TTL. Change the window with the `CLICKHOUSE_RETENTION_DAYS` environment variable: at the next start, the existing tables move to the new TTL and expired data is deleted.

### Enabling analytics (recommended)

Analytics is enabled via the `clickhouse` Docker Compose profile. The default `.env.example` has it on:

```env
COMPOSE_PROFILES=clickhouse
CLICKHOUSE_PASSWORD=
```

Set `CLICKHOUSE_PASSWORD` to a generated value (`openssl rand -base64 32`); compose refuses to start the `clickhouse` profile while it is empty.

Then start (or recreate) the stack:

```bash
docker compose up -d
```

### Disabling analytics

Remove `clickhouse` from `COMPOSE_PROFILES` (or leave the variable empty) and omit `CLICKHOUSE_PASSWORD`:

```env
COMPOSE_PROFILES=
```

The web container starts normally without ClickHouse. The Analytics page shows a notice explaining that ClickHouse is not enabled, and no data is collected.

### Combining profiles

To run both analytics and GeoIP updates ([geo-blocking.md](geo-blocking.md#geoip-setup)) simultaneously, list both profiles:

```env
COMPOSE_PROFILES=clickhouse,geoipupdate
CLICKHOUSE_PASSWORD=…
GEOIPUPDATE_ACCOUNT_ID=…
GEOIPUPDATE_LICENSE_KEY=…
```

### When ClickHouse does not answer

**Analytics settings** shows whether the dashboard reaches ClickHouse, and what to check when it does not:

- **Host name not found** (`getaddrinfo ENOTFOUND clickhouse` in `docker compose logs web`): the ClickHouse container is not running. Docker's DNS has no entry for a container that is stopped or between restarts, so this usually means ClickHouse exits at start-up and `docker compose ps` shows it as `Restarting`. `docker compose logs clickhouse` says why. A CPU that lacks SSE 4.2 stops it with *Instruction check fail*: on a Proxmox VM, set the CPU type to `host` or `x86-64-v2-AES` instead of `kvm64`. ARM boards older than ARMv8.2, such as the Raspberry Pi 4, cannot run ClickHouse.
- **Connection refused**: ClickHouse is starting, or `CLICKHOUSE_URL` points at a port where nothing listens. If it lasts, `docker compose logs clickhouse` says why.

`docker compose up -d` printing *Skipped: optional dependency "clickhouse"* means the same: ClickHouse never became healthy, so the web container started without it. Leave `CLICKHOUSE_URL`, `CLICKHOUSE_USER` and `CLICKHOUSE_DB` unset with the bundled ClickHouse; their defaults match it.

## What each request records

The web container reads Caddy's access log every 30 seconds and stores one row per request in the ClickHouse table `traffic_events`:

| Field | Column | Where it comes from |
| --- | --- | --- |
| Time, client address, Host, method, URI, status, HTTP version, bytes sent, User-Agent | `ts`, `client_ip`, `host`, `method`, `uri`, `status`, `proto`, `bytes_sent`, `user_agent` | The access log line |
| Country | `country_code` | GeoLite2-Country. Private addresses have none; the analytics show them as `LAN`, unknown ones as `XX`. |
| Network | `asn`, `as_org` | GeoLite2-ASN: the autonomous system number and its organisation. `0` and empty when unknown. |
| Outcome | `outcome` | What happened to the request, see below. |
| Duration | `duration_ms` | Caddy's `duration`, in milliseconds. |
| User-agent family | `ua_family` | A short name for the User-Agent: `Chrome · Windows`, `curl 8.5.0`, `Googlebot 2.1`, `(none)`. |
| WAF rule | `waf_rule_id` | The rule that made the WAF block the request; `0` otherwise. |
| Blocked, rate limited | `is_blocked`, `is_rate_limited` | Kept for older queries: geo blocking and Caddy's rate limiter. |

geoipupdate downloads both GeoLite2 databases (the `geoipupdate` compose profile). Without them, country and network are empty and everything else works.

The upstream a request went to and the upstream's own status are not recorded: Caddy's access log does not carry them.

Rows stored before an upgrade keep empty values for the new columns. Their outcome is worked out from `is_blocked` and `is_rate_limited` (geo or rate limited, otherwise served), so WAF blocks and sign-in redirects from before the upgrade count as served. They expire with the retention window.

## Outcomes

Each request has one outcome. Every outcome but **served** counts as **mitigated**.

| Outcome | Meaning | How it is recognised |
| --- | --- | --- |
| `rate_limit` | The rate limiter refused it | Status 429 and the access log line names the rate limit zone. A 429 from the upstream is served. |
| `geo` | A country, continent or AS number rule blocked it | caddy-blocker logged "request blocked" for the same client, method and URI. Also fail-closed blocking of an unknown client address. |
| `access` | An address rule or basic authentication refused it | A caddy-blocker block whose client address is listed in a `block_ips` or `block_cidrs` rule (global or of any host), or a 401 with Caddy's basic-auth challenge (`Basic realm="restricted"`). |
| `waf` | The WAF blocked it | Coraza logged "WAF rule violation detected" for the same client, Host and URI (in `waf-rules.log`). Matches in detection-only mode are served. |
| `auth` | Forward auth sent it to sign in, or refused the signed-in user | A redirect to the dashboard's sign-in portal (`BASE_URL/portal?rd=…`), to Authentik's outpost, to oauth2-proxy's `/oauth2/start` or `/oauth2/sign_in`, or to any URL whose `rd` parameter points back to the requested host. |
| `served` | Everything else, whatever the status | |

The rules apply in this order, and the first that matches wins. When the WAF blocks a request while inspecting the response, Coraza logs no violation and the request counts as served; the WAF event is still recorded and shown under Security events.

The web container needs read access to `waf-rules.log` for WAF outcomes, as it already has for WAF events.

## The Analytics page

**Observe › Analytics** shows the traffic of the hosts you can see:

- **Header**: the range (last hour, 24 hours, 7 days, 30 days, or a custom start and end in UTC), **Compare to previous period** (off, with the date the data starts, when the retention window holds no previous period), **Export CSV** (the chart's numbers: one row per bucket with each series, the total and the previous period) and **Views** (saved views, below).
- **Filters**: type part of a host, path, address or user agent in the filter box: it offers "Path contains …" (and the like, for the fields that have a match) and the matching values with their request counts, most requested first; Enter takes the highlighted one. **More filters** picks any dimension, `is` or `is not` (and `contains` or `does not contain` for the text fields), and a value, with the busiest values as suggestions. Clicking a chip's operator turns the filter around (`is` ↔ `is not`, `contains` ↔ `does not contain`). On a top list, hover a row (on a touch screen the buttons are always shown) and press **Only** to show just that value or **Exclude** to hide it; a message says what the page shows now and **Undo** takes the filter away again. Every number on the page follows the filters. Each filter is a chip in the filter bar: its **×** removes it, **Clear filters** removes them all, and the browser's back button steps back through them.
- **Headline numbers**: requests, bandwidth, unique addresses, mitigated requests (with their share) and the 5xx error rate, each with its change and a trend line ("No earlier data" when the retention window holds no previous period). Selecting one shows it on the chart.
- **Chart**: the selected number over time, grouped where that adds up: requests by outcome, status class or host; bytes in total or by host; mitigated requests by source or host; error responses by status class or host; unique addresses in total only (one address can appear in many buckets). The dashed line is the previous period; the legend hides and shows series; the busiest moment of mitigation links to the Security events list for the same range and filters.
- **Top dimensions**: hosts, paths, countries (as a list or a map), source networks, status codes, source addresses, user agents, methods, HTTP versions and, when the WAF blocked anything, WAF rules. Rows whose requests were often mitigated say so. **View all** lists up to 100 values.
- **Requests**: the latest requests matching the filters, newest first, or only the mitigated ones, with **Show more** for older ones. A run of identical requests (same outcome, request, status, source and user agent, each within a minute of the next) is one row with a count such as ×7. The rule of a request the WAF blocked links to its events on [Security events](security-events.md). Every request is stored; nothing is sampled. Times are in UTC.

The last hour and 24 hours refresh every 30 seconds while the page is visible. Everything the page shows is in its address, so a link opens the same view and the browser's back button undoes a change:

| Parameter | Values |
| --- | --- |
| `range` | `1h`, `24h` (default), `7d`, `30d`, or `custom` with `from` and `to` in Unix seconds |
| `metric` | `requests` (default), `bytes`, `visitors`, `mitigated`, `errors` |
| `group` | `outcome`, `status`, `host` or `none`, where the metric allows it |
| `compare` | `0` hides the previous period |
| `filter` | One per filter: `host:app.example.com`, `!country:CN` to exclude, `~path:suggest` for "contains", `!~path:suggest` for "does not contain" |
| `filters` | Also accepted: the filters as the API's JSON array, `[{"dim":"host","op":"is","value":"app.example.com"}]` |

For example `/analytics?range=7d&metric=errors&filter=host:app.example.com`.

When ClickHouse is not configured the page explains how to turn analytics on; when it does not answer, the page says so and offers to retry. With access logging off (**Analytics settings**) no new requests are recorded, and the page says that too.

## Filters, metrics and grouping

Every analytics view takes a range, filters, a metric and a grouping.

- **Range**: the last hour (1-minute buckets), 24 hours (30 minutes), 7 days (3 hours), 30 days (1 day), or a custom range of up to 92 days cut into about 60 buckets. Buckets are aligned in UTC; the last one holds the current time.
- **Previous period**: the same length right before the range, for comparison. When any of it is older than the retention window there is none, and the API says so (`"reason": "retention"`): with 30-day retention, the 30-day view has no previous period.
- **Filters**: `host`, `path` (without the query string), `country`, `asn`, `status` (a code such as `404` or a class such as `5xx`), `method`, `protocol`, `ip`, `user_agent` (a family), `outcome` and `waf_rule`, each with `is` or `is_not`; `host`, `path`, `user_agent` and `ip` also with `contains` or `not_contains` (part of the text, any case). Several `is` and `contains` filters on one dimension match any of them. Values are checked for their dimension and passed to ClickHouse as query parameters.
- **Metrics**: requests, bytes sent, unique visitors (distinct client addresses, approximate), mitigated requests and error responses (status 400 and up). The headline numbers are requests, bandwidth, unique visitors, mitigated (with its share of requests) and the 5xx error rate, each with its change from the previous period.
- **Grouping**: by outcome, status class, or host (the busiest hosts, the rest as "other hosts").

## Per-host summaries

The proxy hosts list and a host's page show the traffic of the Host names the host's domains serve: a domain itself, or one label under a wildcard domain, port and case ignored. A name that is one host's domain and matches another host's wildcard belongs to the first, as in Caddy.

## Security events

Mitigated requests by source over time come from the outcomes above. Top WAF rules and source addresses come from the WAF events, which also hold detection-only matches; the source addresses add the requests the other rules stopped. The event list merges WAF events and requests stopped by geo, access, sign-in and rate limit rules. The [Security events](security-events.md) page shows them all.

## Traffic signals

The overview's figures, each proxy host's page and `GET /signals` use these signals, at most five of each:

- **5xx bursts**: in the last 24 hours, runs of minutes in which a host answered with 5xx (gaps of up to 2 minutes join runs), with at least 10 such responses and at least 10% of the host's requests in those minutes. Each shows the count, the first and last 5xx, the most frequent status, method and path, and whether it is still going on (a 5xx in the last 5 minutes).
- **Mitigation spikes**: hosts with at least 50 mitigated requests in the last 24 hours and three times their daily average over the 7 days before.
- **Blocked-traffic concentrations**: a host, path and outcome with at least 50 mitigated requests in the last 24 hours, with the countries they came from and, for WAF blocks, the rule.

Spikes and concentrations leave out sign-in redirects: a busy login page is no blocked traffic. The overview's **Needs attention** list does not use these signals; server errors there are alerts of the built-in Error rate rule ([needs-attention.md](needs-attention.md)).

## Saved views

A saved view is a name for a range, filters, metric and grouping. On the Analytics page, **Save view** stores the current settings and **Views** opens a saved view or manages them: rename, share, save the current settings to it, copy its link, or delete it (ten a page, with a search by name or owner once there are more). It belongs to the user who saved it. Shared, it is listed for everyone who can read analytics. Only the owner changes a view; the owner, or an administrator for a shared view, deletes it. A user can save up to 100 views. Saving, changing and deleting a view is recorded in the audit log (`analytics_view`). Views are not synced to slave instances and are deleted with their owner.

## Asking in plain language

With the AI analyst and an AI provider set up, **Ask about your traffic** at the top of the page takes a question such as "Which countries were blocked most last week on the shop hosts?". Your model turns it into a query over the same metrics, dimensions and filters as this page; the query is checked and runs here, and the answer links to this page with the same settings. See [Analytics questions](../ee/docs/analytics-questions.md) for what the model sees and the limits.

## Who can see what

Everything here needs the `analytics:read` permission. The raw Coraza audit record of a WAF event is WAF event detail: it stays on the Security events page and `GET /api/waf-events`, which need `waf:read`. Per-host summaries follow the role's tag scope: a host outside it answers 404, as a missing one does.

When analytics is off or ClickHouse does not answer, pages and the API show no data instead of an error, with `status` set to `disabled` or `unavailable`.

## REST API

All under `/api/v1/analytics`, with permission `analytics:read`. The reference is at `/api-docs` (tag **Analytics**).

| Endpoint | What it returns |
| --- | --- |
| `GET /query` | One metric in buckets, grouped, with the previous period, headline numbers and peaks. Parameters: `range` or `from` and `to`, `filters` (JSON), `metric`, `groupBy`, `topHosts`. |
| `GET /top` | The busiest values of each dimension (`dimensions`, `limit`), with counts, shares and mitigated shares. |
| `GET /requests` | The latest matching requests (`limit`, `offset`). |
| `GET /hosts` | Per-host summaries with sparklines (`ids` to limit them). |
| `GET /hosts/{id}` | One proxy host's summary. |
| `GET /security/series`, `/security/rules`, `/security/sources`, `/security/hosts`, `/security/events` | Security events: mitigated requests by source with the peak explained, top rules, sources and hosts, and the event list (`kind`, `filters` on host, path, country, ip, method and waf_rule). |
| `GET /signals` | The traffic signals: 5xx bursts, mitigation spikes and blocked-traffic concentrations. |
| `GET, POST /views`, `GET, PATCH, DELETE /views/{id}` | Saved views. |
| `POST /questions`, `/questions/saved...` | Plain-language questions and saved questions (see [Analytics questions](../ee/docs/analytics-questions.md)). |

```bash
curl -G https://dash.example.com/api/v1/analytics/query \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'range=7d' \
  --data-urlencode 'metric=errors' \
  --data-urlencode 'filters=[{"dim":"host","op":"is","value":"app.example.com"},{"dim":"status","op":"is","value":"5xx"}]'
```
