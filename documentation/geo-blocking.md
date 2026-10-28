# Geo blocking

Geo blocking is configured per proxy host. It requires MaxMind GeoLite2 databases (see [GeoIP setup](#geoip-setup)).

It also has a fail-closed mode, custom response codes and bodies, and trusted proxy support. The defaults for every host are on the **Geo blocking** page (`/geo-blocking`, under Security events in the sidebar; [settings.md](settings.md)), and L4 proxy hosts have geo blocking of their own. [Access lists](access-lists.md) can allow or deny by country, continent and AS number too.

## Rule types

| Type | Example | Description |
|------|---------|-------------|
| Country | `DE` | ISO 3166-1 alpha-2 country code |
| Continent | `EU` | `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA` |
| ASN | `64496` | Autonomous System Number |
| CIDR | `203.0.113.0/24` | IP range in CIDR notation |
| IP | `203.0.113.10` | Exact IP address |

Rules can be **block** or **allow**. Allow rules win over block rules, so you can block a continent and allow specific IPs or ASNs through. Allow rules only make exceptions to block rules: on their own they block nothing. To let only some countries in, block every continent and allow those countries.

## Global and host rules

A host's own rules either **merge with** the global rules (both apply) or **override** them (only the host's apply). Global rules apply only while **Use default rules** is on on the **Geo blocking** page: turned off, the rules stay saved but no host uses them, merged or not. A host whose geo blocking is off uses the global rules, unless it is set to override them, which leaves it without geo blocking.

The Proxy Hosts list shows the geo blocking that applies to each host as a **Geo** pill, for example *Geo · blocks CN, RU*. Geo blocking with nothing to block (no rules, or allow rules only) shows none.

With **Use these ranges for geo blocking too** (trusted proxies, [settings.md](settings.md)), the server's trusted proxy ranges stand in for a list of trusted proxies that is empty: in the global rules, in a host's own rules, and in rules that override the global ones. A host that merges with the global rules gets the global list, which is the server's ranges when the global rules list none, together with the proxies the host lists itself. A list you write is never replaced.

## GeoIP setup

Geo blocking requires MaxMind GeoLite2 Country and/or ASN databases. Use the bundled `geoipupdate` service:

1. Register for a free MaxMind account at [maxmind.com](https://www.maxmind.com/)
2. Generate a license key with `GeoLite2-Country` and `GeoLite2-ASN` permissions
3. Add to your `.env`:
   ```
   GEOIPUPDATE_ACCOUNT_ID=your-account-id
   GEOIPUPDATE_LICENSE_KEY=your-license-key
   ```
4. Start with the `geoipupdate` profile:
   ```bash
   docker compose --profile geoipupdate up -d
   ```

The databases are stored in the `geoip-data` Docker volume and shared between the web and Caddy containers.
