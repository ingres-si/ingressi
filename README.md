# Ingressi

Self-hosted reverse proxy built on [Caddy](https://caddyserver.com/): proxy hosts with automatic HTTPS, load balancing, TCP/UDP streams and traffic analytics, configured from a web dashboard and REST API. Optional per host: a web application firewall, access rules, rate limiting and a sign-in portal. Formerly **Caddy Proxy Manager**.

[![License: MIT + Elastic-2.0 (ee/)](https://img.shields.io/badge/license-MIT%20%2B%20Elastic--2.0%20%28ee%2F%29-green.svg)](#license)
[![Next.js](https://img.shields.io/badge/Next.js-16-black)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)

[Report a bug](https://github.com/ingres-si/ingressi/issues) • [Request a feature](https://github.com/ingres-si/ingressi/issues) • [Discussions](https://github.com/ingres-si/ingressi/discussions) • [Sponsor](https://github.com/sponsors/fuomag9)

<img width="100%" alt="The Ingressi overview: what needs attention, traffic of the last 24 hours, the busiest hosts and recent changes" src=".github/assets/dashboard.png" />

## Quick start

```bash
git clone https://github.com/ingres-si/ingressi.git
cd ingressi
cp .env.example .env
# Fill in SESSION_SECRET, ADMIN_PASSWORD and CLICKHOUSE_PASSWORD
# (generate the secrets with: openssl rand -base64 32)
docker compose up -d
```

`SESSION_SECRET` needs at least 32 characters. `ADMIN_PASSWORD` needs at least 12, with upper- and lowercase letters, a number and a special character. With other values the web container stops at start-up and restarts; `docker compose logs web` says which value to change, and `docker compose up -d --force-recreate web` applies the corrected `.env`.

Sign in at `http://localhost:3000/login` with `ADMIN_USERNAME` (`admin` in `.env.example`) and `ADMIN_PASSWORD`.

Data persists in Docker volumes (caddy-manager-data, caddy-data, caddy-config, caddy-logs, geoip-data, clickhouse-data, acme-ca). The environment variables are listed in the [configuration reference](documentation/configuration.md); before going to production, read [Security](documentation/security.md).

## Upgrading from Caddy Proxy Manager

Caddy Proxy Manager is now Ingressi. The old header, cookie and database names keep working; [upgrading-to-ingressi.md](documentation/upgrading-to-ingressi.md) lists every rename and what to change. Before any upgrade, read the [upgrade notes](documentation/upgrade-notes.md) of every version since yours, then run `docker compose pull && docker compose up -d`.

## Features

- **Proxy hosts:** reverse proxies with custom headers, several upstreams, load balancing (8 policies), active and passive health checks, retries, path-based routes, redirects and rewrites
- **L4 proxy hosts:** TCP/UDP stream proxying with TLS SNI matching, proxy protocol (v1/v2), load balancing, health checks and geo blocking; a sidecar manages the Docker Compose ports
- **Certificates:** automatic HTTPS through ACME (Let's Encrypt, ZeroSSL), DNS-01 with 22 DNS providers, imported certificates, and an optional built-in CA for client certificates (mTLS) with role-based path rules
- **Visibility:** traffic analytics in ClickHouse, security events and an audit log of every change
- **Optional protections, per host** (off until an administrator turns them on): a web application firewall (Coraza with the OWASP Core Rule Set, per-host modes, rule exclusions and custom SecLang rules), access lists (address, country, continent and AS number rules, and basic auth), geo blocking and rate limiting
- **Users and sign-in:** dashboard accounts and groups, OAuth2/OIDC sign-in to the dashboard, multi-factor authentication and passkeys, and an optional sign-in portal in front of proxied apps, which reuses dashboard sign-ins from your identity provider and passes the user's identity to the app in headers (or Authentik and other forward-auth servers instead)
- **Instance sync:** a master copies its own configuration to replicas, with secrets sealed to each replica's own key
- **REST API** under `/api/v1/` with API tokens and an OpenAPI reference at `/api-docs`, and a command palette (Ctrl+K / ⌘K)
- **MCP server** at `/api/mcp` for AI clients: OAuth 2.1 with PKCE and dynamic client registration, a consent screen, scopes that follow the account's permissions, and tools for hosts, certificates, access lists, analytics and the audit log ([documentation/mcp.md](documentation/mcp.md))
- **Dark mode** and a responsive interface for phones

Ingressi also includes alerting, configuration history and rollback, SAML and LDAP sign-in, enforced SSO, SCIM provisioning, custom roles, change approvals, access reviews, compliance reports, audit streaming, scheduled backups, fleet management, high availability, white-label branding, an AI analyst and API monetization. Their code is in `ee/`; [ee/docs/](ee/docs/README.md) describes each one.

## Documentation

- **Installing and running:** [Configuration reference](documentation/configuration.md), [Security](documentation/security.md), [Upgrade notes](documentation/upgrade-notes.md), [Upgrading from Caddy Proxy Manager](documentation/upgrading-to-ingressi.md), [Setup checklist](documentation/setup-checklist.md), [PostgreSQL](documentation/postgresql.md), [Instance sync](documentation/instance-sync.md), [Fleet management](ee/docs/fleet.md), [High availability](ee/docs/high-availability.md), [Scheduled backups](ee/docs/scheduled-backups.md), [Air-gapped installs](ee/docs/air-gapped.md)
- **Dashboard:** [Overview](documentation/overview.md), [Needs attention](documentation/needs-attention.md), [Search and the command palette](documentation/command-palette.md), [Settings](documentation/settings.md), [Profile, sessions and API tokens](documentation/profile.md), [Audit log](documentation/audit-log.md), [Charts](documentation/charts.md), [MCP server](documentation/mcp.md), [Alerting](ee/docs/alerting.md), [Configuration history](ee/docs/config-history.md), [Change approvals](ee/docs/change-approvals.md), [White-label](ee/docs/white-label.md)
- **Hosts and certificates:** [Proxy hosts](documentation/proxy-hosts.md), [Proxy host editor](documentation/proxy-host-editor.md), [L4 proxy hosts](documentation/l4-proxy-hosts.md), [Host tags](documentation/host-tags.md), [Certificates](documentation/certificates.md), [Default response](documentation/default-response.md), [Upstream DNS pinning](documentation/upstream-dns-pinning.md), [API monetization](ee/docs/api-monetization.md)
- **Optional protections:** [Web application firewall](documentation/waf.md), [Security events](documentation/security-events.md), [Access lists](documentation/access-lists.md), [Geo blocking](documentation/geo-blocking.md), [Rate limiting](documentation/rate-limiting.md)
- **Users and sign-in:** [Forward auth portal](documentation/forward-auth.md), [OAuth and OpenID Connect sign-in](documentation/oauth.md), [Users and groups](documentation/users-and-groups.md), [Sign-in and directories](documentation/sign-in-and-directories.md), [Multi-factor authentication](documentation/mfa.md), [SAML single sign-on](ee/docs/sso-saml.md), [LDAP / Active Directory](ee/docs/ldap.md), [Enforced SSO](ee/docs/sso-enforcement.md), [SCIM provisioning](ee/docs/scim.md), [Custom roles](ee/docs/custom-roles.md), [Access reviews](ee/docs/access-reviews.md)
- **Analytics:** [Traffic analytics](documentation/analytics.md), [AI analyst](ee/docs/ai-analyst.md), [Analytics questions](ee/docs/analytics-questions.md)
- **Audit and compliance:** [Audit streaming and export](ee/docs/audit-streaming.md), [Compliance reports](ee/docs/compliance-reports.md)

## PostgreSQL and high availability

- **PostgreSQL:** SQLite is the default; a `postgres://` URL in `DATABASE_URL` runs Ingressi on PostgreSQL, and an existing install can be copied over ([postgresql.md](documentation/postgresql.md)).
- **High availability:** shared certificate storage for Caddy nodes, a dashboard cluster with failover, shared state and PostgreSQL replicas ([high-availability.md](ee/docs/high-availability.md)).

## Security

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ingres-si/ingressi/security/advisories/new), not in a public issue. [SECURITY.md](SECURITY.md) has the disclosure policy and how to verify release images; [documentation/security.md](documentation/security.md) covers running Ingressi in production.

## Support the project

Ingressi is free, every feature included. It used to have paid editions; the EU's Cyber Resilience Act made selling it as a one-person project not worth it. If Ingressi is useful to you, please consider [sponsoring it on GitHub](https://github.com/sponsors/fuomag9) or on [Ko-fi](https://ko-fi.com/fuomag9).

## Contributing

Bugs and feature requests go to [GitHub Issues](https://github.com/ingres-si/ingressi/issues), questions and ideas to [GitHub Discussions](https://github.com/ingres-si/ingressi/discussions). Pull requests are welcome: fork the repository, work on a branch and open a pull request against `develop`.

- Follow the existing code style (TypeScript, Prettier).
- Add tests for new behaviour. `bun run test:all` runs the typecheck, lint, the PostgreSQL schema check, and the unit and integration tests on SQLite and then on PostgreSQL (`TEST_DATABASE_URL`, a disposable server; see `scripts/test-all.sh`). Every test file that uses the database runs on both; `src/lib/db/README.md` explains how.
- Update the documentation for user-facing changes.

## License

Everything under `ee/` is under the [Elastic License 2.0](ee/LICENSE): you may use, self-host and modify it, but you may not offer it to others as a hosted or managed service. Everything else is under the [MIT License](LICENSE).

Next.js only finds pages and API routes under `app/`, so each page or route implemented in `ee/` keeps a file there that only re-exports it. These routing files are MIT and contain no code under the Elastic License 2.0. [ee/README.md](ee/README.md#where-ee-code-lives) lists every `ee/` module and the files that route to it.

Caddy is a trademark of its respective owner. Ingressi is an independent project and is not affiliated with or endorsed by the Caddy project.

## Acknowledgments

- [Caddy](https://caddyserver.com/), the web server Ingressi is built on
- [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager), which inspired the project
- [Next.js](https://nextjs.org/), [shadcn/ui](https://ui.shadcn.com/) and [Drizzle ORM](https://orm.drizzle.team/)
