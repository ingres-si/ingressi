# Proxy hosts

A proxy host sends the traffic for one or more domains to services on your network. Caddy obtains and renews a certificate for its domains unless you choose one.

## The list

**Traffic → Proxy hosts** lists every host you may see (a custom role limited to tags sees the hosts with one of its tags). Each row shows:

- **Host**: the first domain (a link to the host's page), how many more it serves, its name and its first upstream.
- **Status**: *No issues* (none of the problems below; it does not check the upstreams, see [Upstream health](#upstream-health)), *Disabled*, *Waiting for approval* (a change to it waits in [change approvals](../ee/docs/change-approvals.md)), or the first thing that needs a look:
  - a burst of 5xx responses in the last 24 hours ("501 burst at 09:02", or "since" while it lasts),
  - a 5xx share of 5% or more over 24 hours (with at least 20 requests),
  - blocked traffic far above the host's usual,
  - a certificate that expired, whose renewal is failing, or an imported one that expires within 30 days.
- **Requests, 24h** and **5xx**: from [analytics](analytics.md), with a bar showing each host's share of the busiest host's requests. Shown to users with `analytics:read` when ClickHouse is configured. When ClickHouse does not answer, the list says so above the table and leaves out the traffic, the 5xx rates and the traffic alerts.
- **Protection**: what applies to the host once its own settings and the global ones are combined: WAF (blocking or detection only), sign-in (SSO with dashboard accounts, Authentik, forward auth), access list, client certificates (mTLS), rate limiting and geo blocking.
- **Certificate**: days left, issuer and expiry date, and the renewal state when Caddy is renewing it or the renewal fails (from the [certificates](certificates.md) overview; users without `certificates:read` see only whether Caddy obtains it).
- **Tags**: select one to show only hosts with that tag.

Search matches names, domains, upstreams and tags, ignoring case, as you type; `/` focuses the search from anywhere on the page and Escape clears it. Typing does not add to the browser's history. The text is matched literally: `%` and `_` are ordinary characters, not wildcards (the L4 Proxy Hosts search works the same way). The status filter shows the hosts that need attention or the disabled ones; the protection and tag filters narrow the list further. By default, the list is sorted by requests in the last 24 hours (by host name without analytics). **Profile → Interface → Default list order** can change the account's initial ordering; an explicit sort in the URL wins. The Host, Status, Requests and 5xx headings sort by that column; the Name button beside Host sorts by the host's name instead of its domain, so names with a shared prefix or emoji stay together. **Group by tag** lays the list out in a section per tag (hosts without a tag last, under "No tag"), with the sort ordering the hosts inside each section; a host with several tags appears once, under its alphabetically first tag, or under the first tag the tag filter selected. The choice is in the address (`?group=tag`), so reload and shared links keep it. To put hosts together, give them a shared tag, in bulk with **Add tag** on the selected hosts.

The list shows 25 hosts a page, with the pager under it. The page is in the address (`?page=2`), so back, reload and shared links keep it; changing the search, a filter or the sort goes back to the first page.

Select hosts with the checkboxes to act on several at once: turn WAF blocking on, add a tag, enable, disable or delete them (after a confirmation). Each host goes through the same checks as a change to it alone: your role's tags, the change approval policies (a protected host gets a change request instead) and the audit log, which records one event per host. Caddy is applied once for the whole batch.

The row menu opens the host, edits or duplicates it, enables or disables it, or deletes it.

Links that open the list with something prepared: `/proxy-hosts?search=<text>`, `?create=1` (with `&domain=<domain>`) opens a new host, and `?edit=<id>` a host's page at Routing.

## A host's page

Select a host's domain to open its page. Its tabs are **Overview**, the sections of the [host editor](proxy-host-editor.md) (for roles that may change hosts) and **History**; they switch in place, so looking at a host and changing it happen on one page. The overview shows:

- **What needs attention**: a 5xx burst (when it happened, how many responses, the most frequent request), unusual blocked traffic, a certificate problem, an upstream Caddy took out of rotation, or a change waiting for approval, with links to the matching requests, alerts or pages.
- **Last 24 hours**: requests, 5xx responses and their share, distinct clients and bandwidth, a chart of served and 5xx responses per 30 minutes, and the 5xx share per 30 minutes. When an error-rate alert rule watches the host, its threshold is drawn on that line (shown to users with `alerts:read`).
- **Upstreams**: each upstream with what Caddy reports about it, and the host's health check settings. Without health checks the page says so, and **Turn on health checks** opens the Routing tab with passive health checks on (failures remembered for 30 seconds) as an unsaved change to review and save.
- **Where requests go**: the busiest paths with their 5xx responses, and the status codes.
- **Configuration**: one line per section of the host editor (routing, security, access, certificate, headers, and advanced settings when any are set), each with **Edit**, which opens that tab.

The **History** tab lists the latest audit log entries about the host (with `audit_log:read`), with the fields each change made when [configuration history](../ee/docs/config-history.md) kept the versions around it, and a link to roll back (with `config_history:restore`).

The page needs `proxy_hosts:read`. A host outside your role's tags answers "not found", as a host that does not exist.

## Upstream health

The dashboard reads Caddy's upstream pool from its admin API (`GET /reverse_proxy/upstreams`) when the page opens. Caddy reports, for each address it dials, the requests in flight and the failures its passive health checks counted within their fail duration. So:

- **No recent failures** (up) and **Taken out after N failures** (down) need passive health checks with a fail duration on the host.
- Without them the upstream is **Not checked**: Caddy counts no failures, and it does not report the results of active health checks.
- **Not reported by Caddy** means Caddy has no entry for the address: the configuration is not applied yet, or upstream DNS pinning makes Caddy dial the resolved addresses instead.
- Hosts with the same upstream share Caddy's counts.

`GET /api/v1/proxy-hosts/{id}/health` returns the same: the host's status, whether Caddy answered, the health check settings and each upstream's status, failures and requests in flight. It needs `proxy_hosts:read` and answers 404 outside the caller's scope.
