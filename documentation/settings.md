# Settings

Settings are on pages next to what they configure. **Settings** itself, at the bottom of the sidebar, holds the settings of the install: the primary domain and the dashboard address. Branding has a page of its own under it ([white-label.md](../ee/docs/white-label.md)).

## Where each setting is

The pages are listed under their sidebar entry, which shows them while one of its pages is open. The command palette (Ctrl+K or ⌘K) finds each section by name ([command-palette.md](command-palette.md)).

| Page | Sidebar entry | What it holds |
| --- | --- | --- |
| Settings (`/settings`) | Settings | Primary domain, the dashboard address (`BASE_URL`, read-only) |
| Certificate settings (`/certificates/settings`) | Certificates | Let's Encrypt or your own ACME directory and its root certificate, the contact e-mail, DNS-01 providers and resolvers, certificate storage |
| Host defaults (`/proxy-hosts/defaults`) | Proxy hosts | Requests for unknown hosts ([default-response.md](default-response.md)), fallback error pages, response headers for every response, trusted proxies, upstream DNS pinning ([upstream-dns-pinning.md](upstream-dns-pinning.md)), Authentik and generic forward auth defaults for new hosts |
| Geo blocking (`/geo-blocking`) | Security events | Default geo blocking rules and the GeoLite2 databases ([geo-blocking.md](geo-blocking.md)) |
| Rate limiting (`/rate-limiting`) | Security events | Default rate limits, clients never limited and IPv6 grouping ([rate-limiting.md](rate-limiting.md)) |
| Analytics settings (`/analytics/settings`) | Analytics | ClickHouse and its retention (read-only), the access log, Prometheus metrics |
| OAuth providers (`/oauth-providers`) | Sign-in and directories | OpenID Connect and OAuth providers for dashboard sign-in ([oauth.md](oauth.md)) |
| Instance sync (`/instances`) | Fleet | Standalone, master or replica, a master's replicas and their sync key pins, a replica's master connection ([instance-sync.md](instance-sync.md)) |
| High availability (`/high-availability`) | High availability | The dashboard cluster (read-only) and shared state ([high-availability.md](../ee/docs/high-availability.md)) |
| Backups (`/backups`) | Change history | Scheduled backups to S3-compatible storage; the backups line on Change history links here ([scheduled-backups.md](../ee/docs/scheduled-backups.md)) |

Every page needs `settings:read`, and saving needs `settings:write`, except Backups, which needs `backups:read` (and `backups:write` to change them), as on the REST API. Some sections belong to an area with its own permissions, as on the REST API: instance sync (`instances:read`, `instances:write`), OAuth providers (`sso:read`, `sso:write`), certificate storage, the cluster and shared state (`high_availability:read`, `high_availability:write`). A role without the read permission sees a notice in their place.

## Saving

A page has one save bar under its forms. It counts the fields you changed; **Save changes** saves every changed card of the page, and **Discard** puts the page back as it was loaded. The browser asks before leaving a page with unsaved changes. DNS-01 providers, certificate storage, OAuth providers, replicas, shared state and backups save each change on their own, since they ask for confirmation or credentials.

On an instance sync replica, each card that the master syncs has **Override the master's settings on this replica**. Off, the card follows the master.

## Details

- **Contact e-mail.** The ACME contact e-mail on Certificate settings is saved with the primary domain on Settings: both are the `general` settings group of the REST API.
- **Trusted proxies** apply to Caddy's main HTTP server, so access logs, analytics, the country map, rate limiting, access list address rules, the addresses that skip sign-in and anything using `{http.vars.client_ip}` see the real client address. Empty client address headers mean `X-Forwarded-For`; Cloudflare sends `Cf-Connecting-Ip`. **Use these ranges for geo blocking too** applies them to geo blocking unless geo blocking has a trusted proxy list of its own.
- **PROXY protocol from** (under Trusted proxies) lists the TCP load balancers in front of Caddy that open each connection to ports 80 and 443 with a PROXY protocol header, v1 or v2: HAProxy in TCP mode, a cloud network load balancer, OPNsense or another Caddy with layer4. Caddy takes the client address from the header before anything else reads it, so everything above, and geo blocking, sees the visitor instead of the balancer. Only the listed addresses may send the header. From them it is optional, so clients that connect to Caddy directly keep working; from any other address a header is read and its address ignored, so nobody else can claim an address. List the balancers themselves (`192.168.1.1`, not `192.168.1.1/24`, which lets the whole network send headers): `private_ranges` and ranges that match every address are refused. Trusted ranges then apply to the address the header names, so a CDN in front of the balancer is listed there as before. HTTP/3 (QUIC, over UDP) carries no PROXY header. In the REST API it is `proxy_protocol_ranges` in the `trusted-proxies` group.
- **Error pages** are sent for every host; a host's own error page for the same status wins.
- **Response headers** are set or removed on every response of the main server: every host, requests for unknown hosts and error responses. Removing `Server` and `Via` hides the `Server: Caddy` and `Via: 1.1 Caddy` headers, and an upstream's own `Server` header too. These apply last, so they replace what the upstream, Caddy or a host's own handlers in raw Caddy JSON set. Request placeholders such as `{http.request.host}` are filled in, except request headers and cookies, which a page script could then read. `Content-Length`, `Transfer-Encoding` and the other framing headers cannot be changed. REST group: `response-headers` (`{"set": {"Name": "value"}, "remove": ["Server", "Via"]}`).
- **Forward auth defaults** fill in the Authentik or Authelia fields when you turn forward auth on for a new proxy host. Existing hosts keep their values.
- **DNS-01.** Provider credentials are stored encrypted and are never shown again; a certificate can use a provider other than the default. With your own resolvers, Caddy looks up the challenge record through them before asking the CA to validate, which helps with slow propagation or split-horizon DNS ([certificates.md](certificates.md)).
- **GeoLite2 databases** are read from `/usr/share/GeoIP` by Caddy and the dashboard alike. The `geoipupdate` service downloads and updates them when it runs (`docker compose --profile geoipupdate`, with a MaxMind account). Without them, country, continent and network rules do not match and analytics show no countries.
- **Traffic analytics** run when `CLICKHOUSE_PASSWORD` is set (with `CLICKHOUSE_URL`, `CLICKHOUSE_USER` and `CLICKHOUSE_DB`); after changing it, recreate the web container. Events are kept for `CLICKHOUSE_RETENTION_DAYS` days (30 by default); ClickHouse deletes older ones itself. The totals on the page cover that window and need `analytics:read`.
- **Access log.** Caddy writes it to `/logs/access.log` in the `caddy-logs` volume (`docker exec ingressi-caddy tail -f /logs/access.log` follows it). Traffic analytics are read from it, so with access logging off they receive no new requests.
- **Prometheus metrics** are served on their own port (9090 by default, separate from Caddy's admin API on 2019) at `http://ingressi-caddy:<port>/metrics`, reachable from inside the Docker network only.

## Links

Links to the old Settings page keep working: `/settings?section=<id>`, `/settings#<id>` and `/settings?group=<id>` open the page that holds the section.

| Old id | Opens |
| --- | --- |
| `general` | `/settings` |
| `acme` | `/certificates/settings` |
| `dns-providers`, `dns-resolvers`, `certificate-storage` | `/certificates/settings#<id>` |
| `default-response`, `error-pages`, `trusted-proxies`, `upstream-dns`, `forward-auth`, `authentik` | `/proxy-hosts/defaults#<id>` |
| `geoblock` | `/geo-blocking` |
| `rate-limit` | `/rate-limiting` |
| `analytics`, `logging`, `metrics` | `/analytics/settings`, `/analytics/settings#logging`, `/analytics/settings#metrics` |
| `oauth` | `/oauth-providers` |
| `sync`, `instance-sync` | `/instances` |
| `high-availability`, `shared-state` | `/high-availability`, `/high-availability#shared-state` |
| `backups` | `/backups` |
| `branding` | `/branding` |

The settings REST API (`/api/v1/settings/...`) is unchanged.
