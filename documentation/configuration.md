# Configuration reference

The web container is configured with environment variables. Copy `.env.example` to `.env` to start (see the [Quick start](../README.md#quick-start)); recreate the container with `docker compose up -d` after a change, since `docker compose restart` does not re-read `.env`.

## Environment variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SESSION_SECRET` | Session encryption key (32+ chars). Also encrypts stored secrets | None | **Yes** |
| `SESSION_SECRET_PREVIOUS` | Earlier `SESSION_SECRET` values (comma-separated), used to decrypt stored secrets after a rotation and, on an instance sync slave, to prove its new sync key to the master. See [Rotating SESSION_SECRET](security.md#rotating-session_secret) | None | No |
| `ADMIN_USERNAME` | Admin login username: 3–255 characters from `A-Z a-z 0-9 _ . @ -` (the login page refuses others and ignores case) | `admin` | **Yes** |
| `ADMIN_PASSWORD` | Admin password (see the [production requirements](security.md#production-checklist)) | `admin` (dev only) | **Yes** |
| `BASE_URL` | Public URL where users access the dashboard.<br/>**Required for OAuth and the MCP server** - must match redirect URIs; the MCP endpoint, its discovery documents and the audience of its tokens are built from it ([mcp.md](mcp.md)) | `http://localhost:3000` | **Yes** (if using OAuth or MCP) |
| `KEEP_ALIVE_TIMEOUT` | How long the web server keeps an idle connection open, in milliseconds. Keep it above the idle time of any proxy in front (Caddy: 2 minutes), or the proxy can reuse a connection the server just closed and answer 502 | `125000` | No |
| `CADDY_API_URL` | Caddy Admin API endpoint | `http://caddy:2019` (prod)<br/>`http://localhost:2019` (dev) | No |
| `DATABASE_URL` | The database: a SQLite file, or a `postgres://` URL to run on PostgreSQL (see [PostgreSQL](postgresql.md)) | `file:/app/data/ingressi.db` | No |
| `CERTS_DIRECTORY` | Certificate storage directory | `./data/certs` | No |
| `LOGIN_MAX_ATTEMPTS` | Failed attempts that trigger a block: per client (and per account) for forward-auth portal logins, per user for password changes and OAuth account linking, where starting a link counts every attempt (see [Login rate limits](forward-auth.md#login-rate-limits)) | `5` | No |
| `LOGIN_WINDOW_MS` | Window in which those failures are counted, in milliseconds | `300000` (5 min) | No |
| `LOGIN_BLOCK_MS` | How long a block lasts, in milliseconds | `900000` (15 min) | No |
| `FORWARD_AUTH_ALLOWED_PORTS` | Non-standard ports (comma-separated, e.g. `8443`) on which browsers reach forward-auth protected sites | None | No (required for such ports) |
| `TRUSTED_CLIENT_IP_HEADER` | Header holding the real client IP for the portal login and sync endpoint rate limits (e.g. `cf-connecting-ip` behind a CDN). Leave unset when Caddy is the outermost proxy; set it only if every route to Ingressi overwrites that header. See [Login rate limits](forward-auth.md#login-rate-limits) | None (rightmost `X-Forwarded-For`) | No |
| `OAUTH_ENABLED` | Enable OAuth2/OIDC authentication | `false` | No |
| `OAUTH_PROVIDER_NAME` | Display name for OAuth provider | `OAuth2` | No |
| `OAUTH_CLIENT_ID` | OAuth2 client ID | None | No |
| `OAUTH_CLIENT_SECRET` | OAuth2 client secret | None | No |
| `OAUTH_ISSUER` | OAuth2 OIDC issuer URL | None | No |
| `OAUTH_AUTHORIZATION_URL` | Optional OAuth authorization endpoint override | Auto-discovered from `OAUTH_ISSUER` | No |
| `OAUTH_TOKEN_URL` | Optional OAuth token endpoint override | Auto-discovered from `OAUTH_ISSUER` | No |
| `OAUTH_USERINFO_URL` | Optional OAuth userinfo endpoint override | Auto-discovered from `OAUTH_ISSUER` | No |
| `OAUTH_ALLOW_AUTO_LINKING` | Allow auto-linking OAuth identities to existing users | `false` | No |
| `AUTH_TRUST_HOST` | Trust the Host header for URL construction (only behind proxies that rewrite Host) | `false` | No |
| `AUTH_ALLOW_SELF_REGISTRATION` | Allow public email/password account registration | `false` | No |
| `AUTH_ALLOW_OAUTH_REGISTRATION` | Allow first-time OAuth/OIDC identities to create user accounts | `false` | No |
| `AUTH_ALLOW_OAUTH_ROLE_FROM_CLAIMS` | Let an OAuth IdP's profile claims set a new user's role and status (otherwise `user`/`active`) | `false` | No |
| `AUTH_RATE_LIMIT_ENABLED` | Enable Better Auth's per-client rate limiting of `/api/auth` requests, dashboard sign-in included | `true` | No |
| `AUTH_RATE_LIMIT_WINDOW` | Better Auth rate limit window in seconds. Sign-in and sign-up keep Better Auth's built-in limit of 3 requests per 10 seconds | `60` | No |
| `AUTH_RATE_LIMIT_MAX` | Max requests per window | `5` | No |
| `INSTANCE_MODE` | Instance role: `standalone`, `master`, or `slave` | `standalone` | No |
| `INSTANCE_SYNC_TOKEN` | Bearer token slaves use to authenticate sync requests (32–512 characters, no surrounding whitespace) | None | No (required if `slave`) |
| `INSTANCE_SLAVES` | JSON array of slave instances for the master to push to (same token rules). An entry may pin the slave's sync key with `syncPublicKey` or `syncKeyId`; see [Sync key pinning](instance-sync.md#sync-key-pinning) | None | No |
| `INSTANCE_SYNC_INTERVAL` | Periodic sync interval in seconds (`0` = disabled, minimum `30`) | `0` | No |
| `INSTANCE_SYNC_ALLOW_HTTP` | Allow sync over HTTP (for internal Docker networks) | `false` | No |
| `INSTANCE_SYNC_TIMEOUT_MS` | Master only: time limit for one sync request to a slave, including the slave's apply (clamped to `5000`–`300000`) | `60000` (60 s) | No |
| `INSTANCE_SYNC_RATE_MAX` | Slave only: requests per client address and window to `/api/instances/sync`, counted separately for syncs and key requests | `60` | No |
| `INSTANCE_SYNC_RATE_WINDOW_MS` | Slave only: window of that limit in milliseconds | `60000` | No |
| `INSTANCE_SYNC_MAX_BYTES` | Slave only: largest sync payload accepted, in bytes | `10485760` (10 MiB) | No |
| `INSTANCE_SYNC_MODE` | Slave only: `pull` makes the slave poll its master instead of being pushed to (fleet pull replicas; see `ee/docs/fleet.md`) | `push` | No |
| `INSTANCE_MASTER_URL` | Pull replica only: the master's base URL (`https`; `http` only with `INSTANCE_SYNC_ALLOW_HTTP`) | None | With `INSTANCE_SYNC_MODE=pull` |
| `INSTANCE_PULL_TOKEN` | Pull replica only: the credential the master issued for it (shown once) | None | With `INSTANCE_SYNC_MODE=pull` |
| `INSTANCE_PULL_INTERVAL` | Pull replica only: seconds between polls (`10`–`3600`, with jitter) | `30` | No |
| `INSTANCE_PULL_APPLY_TIMEOUT` | Master only: seconds a fleet rollout waits for a pull replica to confirm a revision (`60`–`86400`) | `600` | No |
| `INSTANCE_PULL_RATE_MAX` | Master only: pull replica polls per client address and window (`INSTANCE_PULL_RATE_WINDOW_MS`, default 60000) | `300` | No |
| `CLICKHOUSE_URL` | ClickHouse HTTP endpoint for analytics | `http://clickhouse:8123` | No |
| `CLICKHOUSE_USER` | ClickHouse username | `ingressi` | No |
| `CLICKHOUSE_PASSWORD` | ClickHouse password (`openssl rand -base64 32`). Required when the `clickhouse` profile is active. | None | No (required if analytics enabled) |
| `CLICKHOUSE_DB` | ClickHouse database name | `analytics` | No |
| `CLICKHOUSE_RETENTION_DAYS` | Days analytics events are kept (see [Analytics](analytics.md#storage-and-retention)) | `30` | No |

With the stock `docker-compose.yml`, the web container only receives the variables listed in the `web` service's `environment`; a value in `.env` for any other variable in this table has no effect until you add it there (for example `INSTANCE_MODE: ${INSTANCE_MODE:-}`; an empty value leaves the mode to the Instance sync page). Give numeric variables their documented default rather than an empty one, e.g. `LOGIN_MAX_ATTEMPTS: ${LOGIN_MAX_ATTEMPTS:-5}`: an empty value is read as 0.

In production, `SESSION_SECRET` and `ADMIN_PASSWORD` must meet the [production requirements](security.md#production-checklist).
