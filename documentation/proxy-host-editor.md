# Proxy host editor

A host is changed on its own page (`/proxy-hosts/<id>`): next to **Overview** and **History**, its tabs hold the editor's sections. Switching tabs never leaves the page, unsaved changes survive the switch, and a bar at the bottom appears once something changed, with **Discard**, **Review changes** and **Save**. Following a link away from the page with unsaved changes asks first. New hosts are made at **Proxy hosts → New host** (`/proxy-hosts/new`), with the same tabs; **Duplicate** opens a new host that starts as a copy (`/proxy-hosts/new?from=<id>`). The old editor address, `/proxy-hosts/<id>/edit`, leads to the host's page.

## Sections

The settings are grouped in six sections. Each has its own address, so a link can open it directly, for example `/proxy-hosts/12#security`; a card can be linked too (`#waf`, `#geo-blocking`).

- **Routing**: domains, upstreams, load balancing with retries and active and passive health checks (under **Custom load balancing**; active checks need a path or a port and passive checks a time to remember failures, filled in as 30s when they are turned on, or Caddy runs neither), WebSockets, the Host header sent upstream, skipping the upstream certificate check, and path-based routes with their own upstreams and load balancing. A new host also asks for its name and tags here.
- **Security**: the WAF mode of the host (global mode, off, detect only or block), under **Advanced** whether the global WAF settings apply too, the OWASP Core Rule Set, request body limits and custom SecLang directives (it opens by itself when one of them is not the default), the rules excluded on this host, rate limiting and geo blocking.
- **Access**: the access list, sign-in in front of the host (the built-in sign-in with the users and groups it lets in, Authentik, or Authelia and other forward-auth servers), client certificates (mTLS) and blocked paths.
- **Certificate**: the certificate the host uses (Caddy's own, or one from the Certificates page) and the redirect from HTTP to HTTPS.
- **Headers**: Strict Transport Security.
- **Advanced**: name and tags of an existing host, redirects and rewrites, error pages, upstream name resolution and raw Caddy JSON. Only administrators can change raw Caddy JSON.

Rule exclusions and path-based mTLS access rules are saved on their own, as soon as they are added, changed or removed, not with the host's other changes.

## What some settings do

- **Load balancing** off: Caddy picks any upstream at random, without health checks or retries. A path-based route without its own load balancing does the same with its upstreams.
- **WebSockets**: the WAF lets WebSocket upgrade requests through without inspecting them, so long-lived streams are not cut. Caddy proxies WebSockets either way.
- **Skip upstream certificate check**: accepts an `https://` upstream whose certificate does not match its address. Meant for upstreams with a self-signed certificate.
- **WAF mode**: *Global mode* follows the WAF settings (when those apply only to hosts that pick a mode, a host on global mode has no WAF). *Detect only* inspects every request and logs matches to Security events without blocking; *Block* answers 403 to requests that reach the anomaly threshold. **Global WAF settings: Ignore them** leaves out the global exclusions, directives and limits. With the Core Rule Set the WAF reads at most 12.5 MiB of a request body unless the host raises it (up to 1024 MiB). Custom directives run after the Core Rule Set.
- **Rule exclusions**: every rule this host skips, with where (every request, a path, a variable) and why. **Add exclusion** finds the rule by its id or its name, and narrows it to a path or a variable if needed; **Change** and **Remove** act on one in place. **Matched this host in the last 7 days** lists the rules that hit the host's requests, with how often they blocked and the path they matched most, each with **Exclude…**, which opens the same form with the rule and that path offered. Adding and changing exclusions needs `waf:write`; they apply right away. A new host gets whole-host exclusions as a list of rule ids, saved with it.
- **Rate limiting** off still applies the global default rules; *Override global* with no rules limits nothing. Over a limit, clients get 429 with `Retry-After`. See [rate-limiting.md](rate-limiting.md).
- **Access list**: with none, anyone can reach the host; sign-in and the upstream's own checks still apply. The global Blocked sources list applies to every host.
- **Sign-in**: *Only these paths* limits sign-in to some paths (blank: the whole host); *Never these paths* is ignored when only some paths are protected. Headers copied to the upstream cannot be sent by clients themselves. Requests carrying a *Skip sign-in* header reach the upstream without signing in, so the upstream must check them. *Skip sign-in from* lists addresses and networks that reach the host without signing in; the WAF, access list and the other protections still apply to them, and the editor warns when the client address cannot be trusted. See [forward-auth.md](forward-auth.md#skipping-sign-in-for-some-addresses).
- **Client certificates (mTLS)**: clients without a certificate from a trusted role or one of the chosen certificates cannot connect at all. Roles and client certificates are made on the Certificates page.
- **Blocked paths** are answered with their status and body; the upstream never sees them. A path that bypasses the blocks is never blocked, even when a blocked path matches it too: allow `/secret` and block `/*` to expose only `/secret`.
- **Geo blocking**: allow rules win over block rules. With geo blocking off on the host, only the global rules apply. Trusted proxies' `X-Forwarded-For` names the client; *Block clients whose address is unknown* blocks requests whose client cannot be told, for example behind a trusted proxy that sends no usable `X-Forwarded-For`. A redirect replaces the status and body with a 302. See [geo-blocking.md](geo-blocking.md).
- **Certificate**: Caddy obtains a certificate for each domain over ACME once the host is saved and renews it about 30 days before it expires; *Obtained with* says whether that is DNS-01 (with which provider) or HTTP-01. Wildcard domains need a DNS provider in Certificate settings. For a domain whose DNS is hosted by another provider than the default, *Use a different DNS provider* creates a managed certificate with it (see [Certificates](certificates.md#choosing-a-dns-provider)). An imported certificate is not renewed: import a new one before it expires. A host that still has no certificate 15 minutes after it was saved shows *No certificate issued* instead of *No issues*.
- **Strict Transport Security** tells browsers to use only HTTPS for two years; with subdomains, every name under the host's domains too. Other request or response headers are set with handlers in raw Caddy JSON; headers for every host are on Host defaults ([settings.md](settings.md)).
- **Redirects** answer the client; **rewrites** change the path the upstream sees. The path prefix is put in front of every path, for apps served under a sub-path.
- **Error pages** replace the body of error responses (502 while the upstream is down, for example); the status code stays the same.
- **Upstream name resolution** matters only when upstreams are names: own DNS resolvers replace the system's, and [DNS pinning](upstream-dns-pinning.md) resolves the names when the configuration is applied.
- **Raw Caddy JSON** is checked when you save: Caddy refuses a configuration it cannot load.

## Saving

The bar at the bottom counts the unsaved changes against the saved host. **Review changes** (or **Save**, or Ctrl+S) opens the review before anything is saved. It shows:

- each change as before and after, with **Show** to jump to the setting and **Undo** to put it back;
- whether a change approval policy covers the change. Then saving creates a change request instead of applying it: the review says how many approvals it needs, the change window and when it next opens, and asks for a reason for the approvers. Users allowed to make emergency changes can apply it at once with a reason;
- the impact: which host changes, that Caddy reloads and on how many nodes, and the certificates Caddy will request for new domains.

Problems the form can tell on its own, such as an invalid domain or a rate limit window over an hour, are shown next to the field before saving. A problem the server finds is shown next to its field when it names one, otherwise in the review.

Leaving the page with unsaved changes asks first.

## REST API

The editor saves through the same checks as the REST API (`POST /api/v1/proxy-hosts`, `PUT /api/v1/proxy-hosts/{id}`). The review's answer is available to scripts too: send the body of the create or the update to

- `POST /api/v1/proxy-hosts/preview` for a new host,
- `POST /api/v1/proxy-hosts/{id}/preview` for a change.

Both need `proxy_hosts:write`, run the same scope checks as the write and store nothing. The answer holds `approval` (whether a policy covers the change, the policies, the approvals needed, the change window and whether the caller may apply it as an emergency change), `changes` (field by field) and `impact`.

```bash
curl -X POST https://dash.example.com/api/v1/proxy-hosts/12/preview -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"domains": ["app.example.com", "www.example.com"]}'
```

The old address `/proxy-hosts?create=1` (with `&domain=`) still opens a new host.
