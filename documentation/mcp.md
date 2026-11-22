# MCP server

Ingressi runs a [Model Context Protocol](https://modelcontextprotocol.io) server, so an AI client — Claude, ChatGPT, Cursor, VS Code, or anything else that speaks MCP — can read and change this instance with the permissions of the account that approves it. The server is protected by OAuth 2.1: the client discovers it, registers itself, sends you to a consent page, and then calls it with a short-lived bearer token.

**Settings → MCP server** (`/mcp`) shows the endpoint, the two switches, the clients that registered and every live grant. Opening it needs `settings:read`; changing the switches and revoking clients needs `settings:write`.

## Connecting a client

Give the client this URL:

```
{BASE_URL}/api/mcp
```

With `BASE_URL=https://ingressi.example.com`, that is `https://ingressi.example.com/api/mcp`.

The client then:

1. calls the endpoint without a token and receives `401` with
   `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`;
2. reads the protected resource metadata (RFC 9728) and the authorization server metadata (RFC 8414) at
   `/.well-known/oauth-authorization-server`;
3. registers itself at `/api/oauth/register` (RFC 7591, public client with PKCE) unless an administrator closed registration;
4. opens `/oauth/authorize` in a browser. You sign in if needed, see the client's name, the account and the scopes it asks for, and approve or cancel;
5. exchanges the authorization code at `/api/oauth/token` with its PKCE verifier and receives an access token (one hour) and a refresh token (30 days, rotated on every use).

`BASE_URL` must be the address users and MCP clients reach Ingressi on. Discovery documents and tokens are built from it, never from the request's `Host` header.

Client-specific shortcuts:

- **Claude Code**: `claude mcp add --transport http ingressi https://ingressi.example.com/api/mcp`
- **Clients configured with JSON** (Claude Code's `.mcp.json`, Cursor, VS Code) use the `http`/`streamable-http` transport with the URL above; no headers are needed, the OAuth flow starts on first use.
- **Clients that cannot do dynamic registration** need a client id and secret first: call `/api/oauth/register` yourself (`curl -X POST …/api/oauth/register -H 'Content-Type: application/json' -d '{"client_name":"…","redirect_uris":["https://…"],"token_endpoint_auth_method":"client_secret_basic"}'`) and put the returned `client_id` and `client_secret` into the client's configuration. There is no pre-registration form in the dashboard.

The endpoint is stateless: it answers each JSON-RPC message on its own and issues no `MCP-Session-Id`. `GET` and `DELETE` answer `405`, as the Streamable HTTP transport allows, because no server-initiated SSE stream is offered.

## Scopes and permissions

A consent screen offers two scopes:

| Scope | What it grants |
| --- | --- |
| `mcp.read` | Every `…:read` permission the account holds, now and after a role change. |
| `mcp.write` | Every permission the account holds, read and write, now and after a role change. |

A client may also ask for a single permission from the catalogue, such as `proxy_hosts:read` or `certificates:write`. Step-up challenges use that form: a token with only `mcp.read` that calls a write tool gets `403` with `WWW-Authenticate: … error="insufficient_scope", scope="mcp.read mcp.write proxy_hosts:write"`, and the client can authorize again with the wider scope.

Permissions are evaluated on every request against the account's **current** role, custom role and tag scope, exactly like the REST API: demoting a user, deleting a custom role or removing a tag from a host takes effect immediately, even for a token that still names the scope. A token with scopes is never an administrator in the REST sense (it holds only the permissions its scopes expand to), and a custom role's tag scope still limits which hosts it can see and change. As with a scoped API token, administrator-only fields (raw Caddy JSON on a host) stay unavailable even when an administrator approves `mcp.write`.

## Tools

| Tool | Permission | What it does |
| --- | --- | --- |
| `get_overview` | any signed-in user | The dashboard overview: attention items, traffic, busiest hosts, nodes, recent changes. Sections the account cannot read are null. |
| `list_proxy_hosts` | `proxy_hosts:read` | Hosts the account can see, filtered by text, tag or enabled state. |
| `get_proxy_host` | `proxy_hosts:read` | One host in full. |
| `list_l4_proxy_hosts` / `get_l4_proxy_host` | `l4_proxy_hosts:read` | TCP/UDP hosts. |
| `list_certificates` | `certificates:read` | ACME, imported and managed certificate rows with expiry and renewal state. |
| `list_imported_certificates` | `certificates:read` | The stored certificate rows (never keys). |
| `list_access_lists` / `get_access_list` | `access_lists:read` | Access lists, rules and members. |
| `list_users` | `users:read` | Accounts without secrets. |
| `list_groups` | `groups:read` | Forward-auth groups. |
| `search` | any signed-in user | The command palette's search, filtered per group. |
| `list_audit_events` | `audit_log:read` | The audit log with filters. |
| `list_security_events` | `waf:read` | Blocked and mitigated requests from ClickHouse. |
| `query_traffic` | `analytics:read` | Traffic over a range, grouped by total, host, outcome or status. |
| `get_caddy_status` | `settings:read` | Whether Caddy is reachable and the last apply. |
| `create_proxy_host` / `update_proxy_host` / `delete_proxy_host` | `proxy_hosts:write` | Change HTTP hosts. |
| `create_l4_proxy_host` / `update_l4_proxy_host` / `delete_l4_proxy_host` | `l4_proxy_hosts:write` | Change TCP/UDP hosts. |
| `create_access_list` / `update_access_list` / `delete_access_list` | `access_lists:write` | Change access lists. |
| `apply_caddy_config` | `settings:write` | Rebuild and apply the Caddy configuration. |

The host tools take every field of the REST API's host objects (`loadBalancer`, `waf`, `mtls`, `forwardAuth`, `redirects`, `locationRules`, `pathAccessLists`, `errorPages`, `rateLimit`, `tags`, …) and pass them to the same model, so validation, tag scope and the change-approval gate behave exactly as on the dashboard. A host a change-approval policy protects comes back as a change request instead of changing; the tool says so and does not retry.

A change is applied to Caddy before the tool answers. A change that was stored but is not live yet answers with `saved: true` and the Caddy error; `get_caddy_status` says why and `apply_caddy_config` retries after the problem is fixed.

## Resources and prompts

Resources are read-only JSON views: `ingressi://overview`, `ingressi://proxy-hosts`, `ingressi://proxy-hosts/{id}`, `ingressi://l4-proxy-hosts`, `ingressi://l4-proxy-hosts/{id}`, `ingressi://certificates`, `ingressi://access-lists`, `ingressi://access-lists/{id}` and `ingressi://audit-log`. Each needs the same permission as the list or detail page; one the account cannot read answers "resource not found", never a partial view.

Prompts are ready-made instructions: `review_proxy_host`, `triage_security_events`, `onboard_service` and `certificate_expiry_check`. They only tell the model which tools to call; the account's permissions still decide what those tools return.

## Security

- **Approval is per client and account.** The consent page names the client, the signed-in account, the redirect host and each scope. A loopback redirect adds a warning: a client on your own computer could be started by someone else.
- **PKCE S256 is required**, every authorization code is single use and lives five minutes, and codes are bound to the client, redirect URI, scopes and resource.
- **A code is only issued when you submit the consent form.** Opening an authorization URL does not issue one, even for a client approved before, so another site cannot collect a code through the browser. `prompt=none` is answered with `consent_required`; refresh tokens keep repeat approvals rare.
- **Access tokens are audience-bound** to `{BASE_URL}/api/mcp` and only hashes are stored. They live one hour; refresh tokens rotate and a reused refresh token revokes the whole grant. An MCP token is accepted only at `/api/mcp`: the REST API reads its own token table, so the two credentials never cross over.
- **Redirect URIs are matched exactly**, except that a loopback redirect may use another port (RFC 8252). Registration accepts HTTPS or loopback HTTP only.
- **The Origin header is checked** on every request, which stops a web page on another origin from reaching a locally reachable instance (DNS rebinding).
- **Discovery fetches nothing.** Client ID Metadata Documents are not supported, so a client-supplied URL never becomes a request from the instance; dynamic registration is the mechanism offered instead.
- **Stored secrets are hashed with PBKDF2-HMAC-SHA-256 keyed by `SESSION_SECRET`.** The values are 256-bit random tokens and client secrets, not user passwords; the keyed, deliberately slow digest means a database copy alone does not allow offline testing. Rotating `SESSION_SECRET` invalidates existing MCP grants, and clients re-authorize.
- **Everything is audited**: client registration, consent granted or denied, revocation, and the changes the tools make through the normal models.
- **Turning the server off** (Settings → MCP server) makes the endpoint, discovery and OAuth endpoints answer `404`. Existing grants are kept and work again when it is turned back on; revoke them to end them.

## REST API

| Endpoint | Permission | Purpose |
| --- | --- | --- |
| `GET /api/v1/mcp/settings` | `settings:read` | Endpoint, discovery URLs, scopes, tools and the two switches. |
| `PUT /api/v1/mcp/settings` | `settings:write` | `{enabled, allowDynamicRegistration}`. |
| `GET /api/v1/mcp/clients` | `settings:read` | Registered OAuth clients. |
| `DELETE /api/v1/mcp/clients/{clientId}` | `settings:write` | Revoke a client and all its grants. |
| `GET /api/v1/mcp/connections` | `settings:read` | Live grants with account, scopes and last use. |
| `DELETE /api/v1/mcp/connections/{id}` | `settings:write` | Revoke one grant. |

The public OAuth endpoints themselves are `/api/oauth/register`, `/api/oauth/token`, `/api/oauth/revoke`, `/api/oauth/authorize` (the consent form's POST) and `/oauth/authorize` (the consent page), plus the two discovery documents above.

## Troubleshooting

| What you see | What it means |
| --- | --- |
| The client never opens a browser | It received `401` but could not read the discovery documents. Check that `BASE_URL` is the URL the client reached and that `/.well-known/oauth-protected-resource` answers. |
| `invalid_redirect_uri` on registration | The client's callback is plain HTTP on a non-loopback host, or carries a fragment. Use HTTPS, or a `localhost`/`127.0.0.1` callback. |
| `invalid_client` / `invalid_grant` | The client id is revoked or unknown, the code expired or was used, or the PKCE verifier does not match. Start the connection again. |
| `insufficient_scope` (`403`) | The token was approved for fewer scopes than the tool needs. Authorize again with the `scope` the challenge names. |
| "Your account does not hold the permission …" | The account's role lacks the permission; a new authorization cannot add it. Ask an administrator for a role that holds it. |
| `registration_not_supported` (`403`) | An administrator turned dynamic registration off, or the instance reached the 500-client limit; revoke unused clients on Settings → MCP server. |
| Tools answer `saved: true` | Caddy did not take the change. `get_caddy_status` says why; fix it and call `apply_caddy_config`. |

On a high availability deployment the MCP endpoint is served by the leader like the rest of the dashboard; OAuth state is in the shared database, so a client that lands on a standby is answered by the usual standby response and retries.
