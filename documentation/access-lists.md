# Access lists

An access list decides who may reach the proxy hosts it is attached to: which addresses and networks, which countries, continents and networks (AS numbers), and who has to sign in with a username and password first.

One list can serve many hosts. A host uses at most one list, set in the proxy host's settings. Changing a list changes every host using it at once.

## The Access lists page

**Traffic → Access lists** has two tabs:

- **Lists**: the lists you attach to hosts. Each row says in plain words what the list does ("Allows only 203.0.113.0/26 and private networks · basic auth for 2 users"), which hosts use it (with links to them) and, with analytics on, what it stopped in the last 24 hours. Search finds a list by its name, description, rule values and notes, basic-auth users, or the hosts using it. **New access list** asks for a name and whether it starts as a **blocklist** (everyone gets in except what you deny; also the choice for basic auth only) or an **allowlist** (only what you allow gets in), then opens the list's page.
- **Blocked sources** (`/access-lists?tab=blocked-sources`): the global list described [below](#blocked-sources), with search. **Block a source** adds an address, network, country, continent or AS number at once; **Unblock** removes it at once.

A list's page (`/access-lists/{id}`) shows its rules in the order they are checked, then **Everyone else**: the default action, for requests no rule matches. The summary under the title follows your changes as you make them. It warns when the list would deny every request, and when allow rules change nothing because everyone else is allowed too. Changes are saved together with **Save list**; leaving the page with unsaved changes asks first.

## Rules

A rule allows or denies requests that match it:

| Match by | Values |
| --- | --- |
| Address or network (`ip`) | IPv4 and IPv6 addresses and CIDR ranges: `203.0.113.7`, `203.0.113.0/26`, `2001:db8::/48`. `private_ranges` covers the private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, fd00::/8, ::1). A range is stored as its network address: `203.0.113.77/24` becomes `203.0.113.0/24`. |
| Country (`country`) | Two-letter ISO country codes: `IT`, `FR`. |
| Continent (`continent`) | `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`. |
| AS number (`asn`) | `AS64500` or `64500`. |

A rule can hold up to 500 values of one kind, a note, and an expiry. A list holds up to 2000 rules.

**The first rule that matches decides.** Rules are checked from the top; a request that matches an allow rule goes on, one that matches a deny rule is refused, and later rules are not looked at. A request that matches no rule gets the list's **default action** (**Everyone else** on the list's page): let through (the default) or deny.

Some examples:

- **Allowlist.** Allow `203.0.113.0/26` and `10.13.13.0/24`, default deny: only the office and the VPN get in.
- **Blocklist.** Deny `198.51.100.0/24` and `AS64500`, default allow: everyone else gets in.
- **Europe only.** Allow continent `EU`, allow `private_ranges`, default deny.
- **An exception.** Allow `192.0.2.10`, then deny country `CN`: that one address gets in from China. In the other order, the deny comes first and the address is refused.

Countries, continents and AS numbers come from the GeoLite2 databases, which the `geoipupdate` service refreshes every 72 hours. Without the databases those rules match nothing, so a deny by country lets everyone through and an allow by country lets nobody through.

## Client addresses

Address rules match the client address Caddy works out, so **Host defaults → Trusted proxies** applies: behind a trusted proxy, the address comes from `X-Forwarded-For` (or the headers configured there). Without trusted proxies, it is the address of the connection.

Country, continent and AS number rules look up the same address. When a request comes from a trusted proxy that sends no usable `X-Forwarded-For`, the address is unknown: country and AS number rules cannot match it. **Deny when the client address is unknown** (`failClosed`) denies such requests instead of letting them through. The page shows this switch only when trusted proxies are configured (or the switch is on): without them the address is always known. With a default action of deny, country, continent and AS number allows never let such requests in.

## What a denied request gets

By default `403 Forbidden`. A list can set another status (400 to 599) and body, or a URL to redirect to (`302`) instead.

## Members (basic auth)

A list can also have members (**Basic auth** on the list's page): usernames and passwords, stored only as bcrypt hashes, so a password is shown only until the list is saved. With members, visitors the rules let through then have to sign in. Without members, nobody is asked to sign in. A list with members and no rules works exactly as access lists always did.

Turn on **Skip Basic Auth for allowed addresses** to ask for a username and password only from clients the list does not name. Clients that match an **Allow** address rule (an IP or CIDR; country, continent and AS number rules cannot skip it) go straight in; everyone else the rules let through still signs in. A client whose address cannot be worked out behind a trusted proxy is asked to sign in. The setting is `skipAuthForAllowed` in the REST API.

## Blocked sources

**Blocked sources** is one global list that applies to every host, before anything else: before rate limiting, the WAF, path rules and each host's own list. It only denies, and lets through everything it does not name. Use it for scanners and networks that keep probing.

The **Block** button on a Security events entry adds the address here. An entry can carry a reason and an expiry; expired entries stop applying at once and are removed within a minute.

Blocked sources applies to HTTP hosts. L4 (TCP/UDP) hosts are not covered.

## Where it runs

On every request a server takes:

1. Blocked sources
2. Rate limiting
3. WAF, geo blocking, then the host's access list rules
4. Path blocks, path rewrites and redirects
5. The host's access list members (basic auth) or the API monetization gate
6. Forward auth and the upstream

Global geo blocking (the **Geo blocking** page) still works as before and runs before the host's list. A list cannot let in what global geo blocking refuses.

## What it stopped

The Access lists page shows, per list and per host using it, the requests stopped in the last 24 hours, and for lists with members the failed sign-ins (`401` answers). The counts come from analytics, so access logging and ClickHouse must be on; without them the page leaves the counts out. A request counts as stopped when it was blocked on one of the list's hosts; global geo blocking on the same host counts too. Blocked sources counts the blocked requests from the addresses and countries it names, on any host. `GET /api/v1/access-lists/stats` also gives the totals, the 24 hours before, and where stopped requests came from and went to; the Security events page lists the requests themselves.

The request total and what Blocked sources stopped need `analytics:read` as well; the rest needs `access_lists:read`. Users with a tag scope see only the hosts in their scope.

## Replicas, export and history

Rules and list settings sync to slave instances with the lists, and are part of configuration export and import, configuration history and fleet revisions. A slave refuses rules the dashboard would never write (values that do not parse, rules of lists it was not sent).

## REST API

Reading needs `access_lists:read`, changing needs `access_lists:write`. Every change applies the Caddy configuration and is recorded in the audit log.

| Endpoint | |
| --- | --- |
| `GET`, `POST /api/v1/access-lists` | Lists; create one with `rules`, settings and `users`. |
| `GET`, `PUT`, `DELETE /api/v1/access-lists/{id}` | One list. `PUT` with `rules` replaces every rule in order; rules sent with their `id` keep it. |
| `GET`, `POST`, `PUT /api/v1/access-lists/{id}/rules` | The rules in order; add one (at `position`, last by default); replace all. |
| `GET`, `PUT`, `DELETE /api/v1/access-lists/{id}/rules/{ruleId}` | One rule. |
| `POST /api/v1/access-lists/{id}/rules/reorder` | `{ "ruleIds": [...] }`, every rule once. |
| `POST /api/v1/access-lists/{id}/entries`, `DELETE .../entries/{entryId}` | Members. |
| `GET`, `PUT /api/v1/access-lists/blocked-sources` | The Blocked sources list (`id` is null before its first use). |
| `GET`, `POST /api/v1/access-lists/blocked-sources/entries`, `DELETE .../entries/{entryId}` | Its entries. |
| `GET /api/v1/access-lists/stats` | Where each list is used and what it stopped. |

Create an allowlist:

```bash
curl -X POST https://dash.example.com/api/v1/access-lists \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "name": "Office and VPN",
    "defaultAction": "deny",
    "rules": [
      { "action": "allow", "kind": "ip", "values": ["203.0.113.0/26"], "note": "Office" },
      { "action": "allow", "kind": "ip", "values": ["10.13.13.0/24"], "note": "VPN peers" }
    ]
  }'
```

Block an address on every host for a day:

```bash
curl -X POST https://dash.example.com/api/v1/access-lists/blocked-sources/entries \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{ "address": "198.51.100.19", "reason": "Scanner hitting every host", "expiresInSeconds": 86400 }'
```

It answers `201` with the new entry, or `200` with the existing one when the address is already blocked (its reason and expiry are updated when sent). A country, continent or AS number takes `kind` and `value` instead of `address`: `{ "kind": "asn", "value": "AS64500" }`. Blocking every address (`0.0.0.0/0`, `::/0`) is refused.

Values that do not parse, unknown fields and settings out of range answer `400` and change nothing.
