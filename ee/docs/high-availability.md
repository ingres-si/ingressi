# High availability

Code: `ee/high-availability/` (Elastic License 2.0). The hooks it uses in the core (the `storage` block in `buildCaddyDocument`, the settings group in instance sync and the configuration) are MIT.

High availability comes in phases. Four are in this release:

1. **Shared certificate storage for Caddy nodes** (phase 1): every Caddy keeps its certificates in one Redis or Valkey, so each is ordered once and every node serves it. Most of this page.
2. **A dashboard cluster** (phase 2): the web container runs as one leader and warm standbys, the database is streamed to object storage with Litestream, and a standby takes over on its own when the leader stops. See [Dashboard cluster](#dashboard-cluster).
3. **Shared state** (phase 3): forward-auth sessions and API monetization balances in the same Redis or Valkey, so every web node serves forward auth and monetized hosts alike. See [Shared state](#shared-state-phase-3).
4. **PostgreSQL replicas** (phase 4): with the dashboard on PostgreSQL, several web containers share one database and all serve requests; one of them runs the background jobs. See [PostgreSQL replicas](#postgresql-replicas).

## Why

With local storage, every Caddy keeps certificates in its own `/data` and orders its own. Five nodes serving the same names order the same certificate five times, which is exactly Let's Encrypt's limit of 5 certificates for the same set of names per week. One more node, or one re-created volume, and issuance fails.

Caddy instances that use the same storage form a cluster. They lock per certificate name, so each certificate is ordered once and every node serves it. They share OCSP staples. They keep the HTTP-01 and TLS-ALPN-01 challenge tokens in the storage, so whichever node the load balancer sends the CA's validation request to can answer it.

## Cluster design

```
                     clients
                        │
     load balancer: TCP 80 and 443 to every node
        ┌───────────────┼───────────────┐
   ┌────┴─────┐    ┌────┴─────┐    ┌────┴─────┐
   │ caddy    │    │ caddy    │    │ caddy    │
   │ web      │    │ web      │    │ web      │
   │ (master) │    │ (slave)  │    │ (slave)  │
   └────┬─────┘    └────┬─────┘    └────┬─────┘
        └───────────────┼───────────────┘
            Redis or Valkey (Sentinel or cluster)
```

- **N nodes.** Each runs Caddy and its own web container. One web container is the master: the dashboard where you make changes. The others run with `INSTANCE_MODE=slave` and receive the configuration through instance sync, which applies it to their own Caddy.
- **One shared Redis or Valkey.** Every Caddy uses it for certificates. The setting is synced, so the slaves use the master's.
- **A load balancer** in front, passing TCP 80 and 443 through to every node (TLS ends on Caddy). Port 80 can go to any node: the HTTP-01 tokens are shared. Caddy sees the balancer as the client unless it keeps the client's address: have it send the PROXY protocol (`send-proxy-v2` in HAProxy) and list its addresses under **Host defaults → Trusted proxies → PROXY protocol from** ([settings.md](../../documentation/settings.md#details)), or access lists, rate limits and analytics all see one address.
- Keep each Caddy's admin API (port 2019) on a network only its own web container shares. The default compose file does not publish it.

## What survives which failure

| Failure | Traffic | Certificates | Configuration changes |
| --- | --- | --- | --- |
| One Caddy node | The load balancer routes around it. | Every other node has every certificate. | Unaffected. |
| A slave's web container | Its Caddy keeps serving its last configuration. Hosts that use Ingressi forward auth fail on that node: its Caddy asks its own web container. | Unaffected. | That node misses changes until it is back and synced again. |
| The master's web container (the dashboard) | Every node keeps serving. | Renewals continue: Caddy renews, not the dashboard. | None until the master is back. |
| Redis or Valkey unreachable | Running nodes keep serving the certificates they hold in memory. | Renewals and new certificates wait and are retried. A Caddy that restarts during the outage cannot load its configuration (the storage module connects while loading) and stays down until the storage is back. | Every change fails to apply while the storage cannot be reached; Caddy keeps its configuration. |
| Redis or Valkey loses its data | Serving continues from memory. | After a restart each name is ordered again, once for the whole cluster. | Unaffected. |

So run Redis or Valkey itself highly available (Sentinel or cluster, or a managed service with replication), with persistence (AOF) on, and monitor it.

## Honest limits

- **Without the [dashboard cluster](#dashboard-cluster) or [PostgreSQL replicas](#postgresql-replicas) the dashboard is one master.** While it is down nothing can be changed, and its database is only as safe as its backups ([scheduled-backups.md](scheduled-backups.md)). Run the master as a dashboard cluster, or as several replicas on PostgreSQL, so that another web container takes over.
- **Ingressi forward auth and the API monetization gate call each node's own web container.** Users, groups and forward-auth grants are not synced to instance sync slaves, so slaves never serve Ingressi forward auth: route those hosts to the master's node, use web nodes that share the master's database (high availability standbys with [shared state](#shared-state-phase-3), or [PostgreSQL replicas](#postgresql-replicas)), or use an external forward-auth provider (Authelia, Authentik). Slaves serve monetized hosts only when the master lets them, gated with the master's balances through shared state or allowances from its gate ([API monetization](api-monetization.md#sync-replicas-and-pull-replicas)). Without shared state a forward-auth session lives on the node where the user signed in, and API balances in one process.
- **Custom ACME CA root.** The `acme-ca` volume only carries `custom-ca-root.pem`, which Caddy reads by path. Each web container writes it for its own Caddy, so this works on every node with a web container. A bare Caddy node without one needs the file at `/acme-ca/custom-ca-root.pem` itself (and its whole configuration some other way): bare nodes are not supported in this phase.
- **Redis and Valkey only.** S3 storage (`techknowlogick/certmagic-s3`) was considered: its current release, the first that locks with conditional writes, needs a newer Caddy than this build pins, and older releases lock without them. It can be added when the Caddy pin moves.

## Set up

1. Run Redis or Valkey (a maintained release) that every Caddy node can reach. Turn on persistence and a password; use TLS when the traffic leaves a private network.
2. **Upgrade every node first**, web and Caddy images both. A slave on an older release ignores the setting and keeps local storage. A Caddy image without the Redis storage module refuses the configuration (Caddy keeps its previous one).
3. Open **Certificate settings** (`/certificates/settings`), card **Certificate storage**. Fill in the mode, the addresses, the password, a key prefix and, if you want, an encryption key and TLS. **Test connection**.
4. **Save without enabling**, then copy the existing certificates in ([Moving certificates](#moving-certificates)).
5. **Enable shared storage.** The master applies it to its own Caddy and syncs it to the slaves.

If Caddy cannot use the storage (it cannot reach it, the password is wrong, the module is missing), the master puts the previous setting back and says why. A slave that cannot use it keeps its previous configuration and reports the failed sync.

## Settings

| Field | Notes |
| --- | --- |
| Mode | `standalone` (one server), `cluster` (Redis/Valkey Cluster), `sentinel` (Sentinel failover). |
| Addresses | `host:port`, IPv6 in brackets. The server; cluster nodes to start from; or the Sentinels. Up to 16. |
| Master name | Sentinel mode: the name the Sentinels know the master by. |
| Database | 0 to 255; always 0 in cluster mode. |
| User name | Optional ACL user. |
| Password, Sentinel password | Stored encrypted, or read from an environment variable on every Caddy node (below). |
| Key prefix | Default `caddy`. Every key starts with it, so several clusters can share one server: give each its own prefix. Segments of letters, digits, `.`, `_`, `-`, separated by `/`. |
| Encryption key | Optional. Caddy encrypts every value with AES before storing it, using the first 32 bytes of the key (at least 32). Every node uses the same key. Keep a copy: without it the stored certificates cannot be read, and changing it makes Caddy order them again. |
| TLS | Connect over TLS; optionally trust your own CA certificates (PEM), or skip verification. |

Caddy waits at most 5 seconds for the server when connecting, reading and writing.

The generated Caddy configuration gets a top-level `storage` block (module `caddy.storage.redis`, from [pberkel/caddy-storage-redis](https://github.com/pberkel/caddy-storage-redis), pinned in `docker/caddy/go.mod`) next to `admin`, `logging` and `apps`. Local storage adds nothing, which is Caddy's default.

## Secrets

- Stored secrets are encrypted with `SESSION_SECRET`, never returned by the API (only `hasPassword`, `hasEncryptionKey`, ...), shown as "changed" in configuration history diffs, and recorded in the audit log only as `stored` or `env:NAME`.
- Instance sync seals them to each slave's key, like DNS provider credentials; the slave stores them under its own `SESSION_SECRET`.
- A password must be entered again when the addresses, mode or TLS settings change: a stored password only goes to the servers it was entered for. The same rule applies to **Test connection**.
- **They end up in Caddy's configuration.** Ingressi posts the configuration to Caddy's admin API, so a stored secret is in plain text in `GET /config/` on port 2019 and in Caddy's autosave file (`/config/caddy/autosave.json` in the `caddy-config` volume). Keep port 2019 unpublished and the volume private.
- **Or keep them off the dashboard entirely.** Choose *Environment variable on every Caddy node* for a secret. The configuration then holds `{env.CADDY_STORAGE_PASSWORD}` instead of the value: the module expands it from the Caddy process's environment, so the secret is never stored, synced, posted or autosaved. Every Caddy node must set the variable (in its `environment:`); a node without it cannot use the storage and keeps its previous configuration. Names must start with `CADDY_STORAGE_`, so the setting can never make Caddy send any other variable. Test connection cannot use such a secret and says so (`complete: false`).
- Braces in a stored secret are escaped, so Caddy's placeholder expansion never changes it.

## Moving certificates

Switching storage makes Caddy look for certificates in the new storage. Whatever it does not find, it orders again. Caddy can copy everything itself with `caddy storage export` and `caddy storage import`. The Certificate storage card shows a `storage.json` for this: a Caddy configuration with only the storage, whose secrets are `{env.*}` placeholders. Save it next to `docker-compose.yml` and set the variables it names in your shell.

### Copy the certificates in (recommended)

Before enabling, on one node (the master's, usually), while it still uses local storage:

```bash
export CADDY_STORAGE_PASSWORD='...'   # and CADDY_STORAGE_ENCRYPTION_KEY if you use one
docker compose exec -T -e CADDY_STORAGE_PASSWORD="$CADDY_STORAGE_PASSWORD" caddy sh -c \
  'cat > /tmp/storage.json && caddy storage export --config /config/caddy/autosave.json --output - | caddy storage import --config /tmp/storage.json --input -; rm -f /tmp/storage.json' \
  < storage.json
```

`Successfully imported storage` means done. Then enable shared storage: every node finds the certificates and orders nothing. One node is enough; the other nodes' copies are for the same names.

### Or let them be issued again

Skip the copy and enable. Each name is ordered once for the whole cluster, but at once, so mind the CA's limits. Let's Encrypt allows 50 new certificates per registered domain and 5 for the same set of names per week. If every node already ordered its own certificate for some names this week, the second limit may be nearly used up. With many hosts, copy instead.

### Switch back to local storage

**Switch back to local storage** keeps the Redis settings so you can enable them again; **Remove setting** forgets them too. Each node then orders the certificates it does not have in `/data`. To avoid that, on **every** node, before switching:

```bash
docker compose exec -T -e CADDY_STORAGE_PASSWORD="$CADDY_STORAGE_PASSWORD" caddy sh -c \
  'cat > /tmp/storage.json && echo "{}" > /tmp/local.json && caddy storage export --config /tmp/storage.json --output - | caddy storage import --config /tmp/local.json --input -; rm -f /tmp/storage.json /tmp/local.json' \
  < storage.json
```

Nothing is deleted from Redis or Valkey; remove the keys under the prefix yourself when you no longer need them.

## Test connection

**Test connection** (`POST /api/v1/high-availability/storage/test`) runs from the web container you click it on, not from Caddy: on a slave it tests that node's connection. Only Caddy needs to reach the storage; for the test, the web container must reach it too. It connects (asking the Sentinels for the master in Sentinel mode; checking cluster support and following a redirect in cluster mode), signs in, selects the database, then writes, reads back and deletes a key under the prefix (`<prefix>/.storage-test/<uuid>`, which expires after a minute in any case). Each step reports a fixed message; nothing the server sends is shown. It changes nothing and is recorded in the audit log (`certificate_storage_tested`).

## REST API

| Method and path | Permission | Notes |
| --- | --- | --- |
| `GET /api/v1/high-availability/storage` | `high_availability:read` | The storage in effect, `source` (`default`, `local`, `master`), `configurable`, `editable`, the migration config. No secrets. |
| `PUT /api/v1/high-availability/storage` | `high_availability:write` | `{backend, redis}`. A missing `redis` keeps the stored one; `null` removes it. Secrets: a string sets, `null` removes, `""` or missing keeps. `409` on a slave, `502` when Caddy does not take it (the previous setting is put back). |
| `DELETE /api/v1/high-availability/storage` | `high_availability:write` | Back to local storage, Redis settings forgotten. |
| `POST /api/v1/high-availability/storage/test` | `high_availability:write` | Without a body: the storage in effect. With `{redis}`: those settings, with the stored secrets for the ones left out. |
| `GET /api/v1/high-availability/cluster` | `high_availability:read` | The [dashboard cluster](#dashboard-cluster): this node's role, the lease holder and its epoch, replication, the last restore, the nodes, the configuration without secrets. `enabled: false` without `HA_ENABLED`. On PostgreSQL, `postgres` holds the replicas. |
| `GET /api/v1/cluster/nodes` | `high_availability:read` | The [PostgreSQL replicas](#postgresql-replicas): the replica answering, the leader, every replica's status, last heartbeat, version and schema. `enabled: false` on SQLite. |

```bash
curl -X PUT https://dash.example.com/api/v1/high-availability/storage \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"backend":"redis","redis":{"mode":"sentinel","addresses":["sentinel-1.example.com:26379","sentinel-2.example.com:26379"],
       "masterName":"certs","passwordEnv":"CADDY_STORAGE_PASSWORD","keyPrefix":"caddy/eu-west","tls":{"enabled":true}}}'

curl -X PUT https://dash.example.com/api/v1/high-availability/storage \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"backend":"local"}'
```

Audit events: `certificate_storage_updated`, `certificate_storage_removed`, `certificate_storage_tested`.

## Permissions

The `high_availability` area has `read` and `write`. `write` is **administrator-level** (only administrators can grant it) and cannot be held by a role with a tag scope: it decides where every host's private keys are kept.

## Instance sync, fleet, history

- The setting is the settings group `certificate_storage`. Instance sync sends it to every slave, its secrets sealed to the slave's key. A slave cannot change it (`409`).
- Older slaves ignore the group and keep local storage. Upgrade them before enabling.
- Fleet revisions ([fleet.md](fleet.md)) carry it like the other settings groups: a promotion-only environment switches storage when the revision is promoted, so a canary node can try shared storage before the rest.
- Configuration export, import and history include it.

## Rate limiting

`mholt/caddy-ratelimit` has a distributed mode that shares rate limiter state through Caddy's configured storage. With shared storage, its limits then hold across the cluster instead of per node.

## Dashboard cluster

Phase 2 runs the web container (the dashboard) as **one leader and warm standbys**, keeping SQLite. The leader serves the dashboard and the API and runs every scheduler and background job. A standby keeps a read-only copy of the database, serves the request-path routes, and takes over on its own when the leader stops. Configuration is by environment variables only. With `HA_ENABLED` unset nothing changes: the container starts exactly as before.

Code: `ee/high-availability/cluster/` (the supervisor, the lease, Litestream), with hooks in the core: `ee/high-availability/role.ts`, `src/lib/background-jobs.ts`, `ee/high-availability/request-path.ts`, the standby answer in `proxy.ts` and the health check.

### How it works

```
                 users                         Caddy (forward auth, API gate)
                   │                                        │
   load balancer: /api/health        load balancer: /api/health?scope=request-path
                   │                                        │
        ┌──────────┴──────────┐                  ┌──────────┴──────────┐
   ┌────┴─────┐          ┌────┴─────┐       (every node with a copy)
   │ web-1    │          │ web-2    │
   │ leader   │          │ standby  │◄── litestream restore -f (warm copy, read-only)
   │ dashboard│          │ request- │
   │ + jobs   │          │ path only│
   └──┬────┬──┘          └────┬─────┘
      │    └── litestream replicate ──► S3-compatible bucket
      │                                  <path>/replicas/e<epoch>-<id>/   one per leader term
      │                                  <path>/cluster.json              which replica is current
      └─────── lease ──────► Redis or Valkey ◄────── standbys try to take the lease
```

- **The supervisor.** With `HA_ENABLED=true` the container's first process is a small supervisor (`/app/ha/supervisor.js`). It holds or waits for the lease and runs the dashboard and Litestream as its children. The dashboard learns its role from the supervisor (`HA_ROLE`) and reads its status file.
- **The leader lease** lives in Redis or Valkey: the key `{<prefix>}:lease` is set with `SET … NX PX <TTL>` (15 seconds by default) and holds a random token, the node id and the **fencing epoch**, a counter raised with `INCR` on every acquisition. The leader renews it every third of the TTL with a compare-and-renew script (only the holder's exact value is extended). Every key shares one hash tag, so the scripts also run on Redis Cluster.
- **Crash-only fencing.** The leader's deadline is the time it *sent* its last successful renewal plus the TTL, minus a margin (a fifth of the TTL, at most 2 seconds). Redis started the TTL later, when the request arrived, so the deadline always comes before the lease can expire. If a renewal has not succeeded by then, or Redis says another node holds the lease, the supervisor kills the dashboard and Litestream at once (`SIGKILL`) and exits; the container restarts as a standby. The dashboard has its own watchdog too: it exits when the supervisor stops vouching for the lease.
- **Only the leader runs jobs.** Start-up tasks (database repairs, applying the configuration to Caddy), the Caddy monitor, instance sync, pull replicas, log and WAF log ingestion, ClickHouse set-up, audit streaming and retention, alert evaluation, scheduled backups, change approvals, access list expiry, access reviews, the fleet scheduler, directory health checks, compliance reports, AI digests and API monetization metering all start through one gate (`startBackgroundJobs` in `src/lib/background-jobs.ts`). A standby starts none of them.
- **Replication.** The leader runs `litestream replicate`, which streams every change to `<HA_S3_PATH>/replicas/e<epoch>-<random>/` in the bucket, sending at most every `HA_SYNC_INTERVAL_SECONDS` (1 by default). Each leader term writes a replica of its own: a former leader that wakes up from a pause can only add to its own, abandoned replica, never to the current one. The current replica is recorded in Redis (`{<prefix>}:replica`, written only by the lease holder) and in `<HA_S3_PATH>/cluster.json`.
- **Standbys** run the dashboard with `HA_ROLE=standby`. It answers the health check with 503, serves the [request-path routes](#request-path-routes), and answers everything else (the dashboard, the API, sign-in to the dashboard) with `503` and a short explanation (`X-HA-Role: standby`). Every `HA_STANDBY_FOLLOW_INTERVAL_SECONDS` (5 by default) `litestream restore -f` applies the leader's changes to a read-only copy, which the request-path routes read.

**A takeover**, in order:

1. A standby finds the lease free and takes it (epoch raised). From now on it renews it.
2. It stops its standby dashboard and its warm copy.
3. It restores the newest state of the current replica into a new file (`litestream restore`, with a quick integrity check) and puts it in place of its own database file. A standby's own file is never trusted: it may be a former leader's, behind or diverged.
4. It starts `litestream replicate` to a new replica of its own and waits until that replica holds a full copy.
5. It points the cluster at the new replica (Redis, then `cluster.json`).
6. Only then does it start the dashboard as the leader, which runs migrations and the start-up tasks and applies the configuration to Caddy.

If any step fails, it gives the lease back and tries again later (after 5 seconds, doubling up to a minute). It never serves the dashboard on a database it could not vouch for.

Replicas of earlier terms are deleted a minute after a takeover, except the one the leader restored from.

### RPO and RTO

- **A planned hand-over** (`docker compose stop`, a rolling update, `SIGTERM`): the leader stops its dashboard, lets Litestream send what is left, then gives the lease back. A standby takes over at its next attempt (every 2 seconds). **Nothing is lost.** The dashboard is unavailable for the restore and the start: typically 10 to 20 seconds.
- **A crash or a lost host:** changes committed in the last 1 to 2 seconds may be lost (Litestream turns new transactions into a file every second and sends them every `HA_SYNC_INTERVAL_SECONDS`), plus anything that could not be sent while object storage was unreachable. The dashboard is back after the lease expires (the TTL, 15 seconds), the next attempt (up to 2 seconds), the restore (seconds for a database of a few megabytes), the first copy to the new replica and the start: typically **25 to 40 seconds**.
- **Proxied traffic is not interrupted** either way: Caddy keeps serving its configuration. Forward-auth checks continue on the standbys (see [Request-path routes](#request-path-routes)).

### What happens when

| Failure | What happens | Data |
| --- | --- | --- |
| The leader crashes, or its host is lost | The lease expires; a standby restores the current replica and takes over. | Changes of the last 1 to 2 seconds. |
| The leader is paused or cut off from Redis | It cannot renew: at its deadline it kills its dashboard and Litestream and exits, before the lease can expire. A standby takes over. | As above. |
| The former leader comes back | It starts as a standby. Its own database file is never used again: if it is promoted later, it restores the current replica first. Anything it wrote into its old replica after losing the lease is ignored. | Nothing more. |
| Redis or Valkey unreachable | The leader stops at its deadline (after at most the TTL); standbys cannot take the lease. **The dashboard is down until Redis is back**; then a node takes the lease and restores. Caddy keeps serving. | Nothing more. |
| Redis or Valkey loses its data (or fails over without the lease key) | The lease looks free: a standby takes it, while the old leader stops at its next renewal (within a third of the TTL). The new leader finds the current replica in `cluster.json` and raises the epoch above it. | Changes the old leader made in those seconds went to its own replica and are lost. |
| Object storage unreachable, leader running | The leader keeps serving; Litestream retries and changes wait on its disk. The High availability page and the API show the replication lag growing. | At risk only if the leader is also lost before storage is back. |
| Object storage unreachable during a takeover | No standby can restore, so none takes over: the dashboard stays down until storage is back. | Nothing more. |
| A restore fails (missing or damaged files) | The node gives the lease back and retries with a growing delay; the error is on the High availability page and in the API (`lastRestore`). | See [Runbook: a lost bucket](#runbook-a-lost-bucket). |
| First start, empty bucket | The node that has a database sets the cluster up from it. A node without a database waits. | Nothing. |
| The bucket was emptied while the leader runs | Every 5 minutes the leader checks that its replica still exists; when it is gone, it sends a full copy again and rewrites `cluster.json`. | Nothing, if the leader stays up. |
| The bucket was emptied and no leader runs | No node takes over: an empty replica is never taken for a first start. | See the runbook. |
| Litestream or the dashboard stops on the leader | The supervisor restarts it after 5 seconds; the leader keeps its lease. | Changes wait on disk meanwhile. |
| A standby's warm copy fails | The standby keeps its last copy and retries; the High availability page shows it. | Nothing. |

So run Redis or Valkey highly available (Sentinel, a cluster, or a managed service) with persistence, and keep the object storage durable (versioning is a good idea).

### Set up

1. **Run Redis or Valkey** that every web node can reach, with persistence and a password, allowing `EVAL`. It can be the one Caddy uses for certificates, with its own key prefix.
2. **Create a bucket** on S3-compatible storage (examples below) and an access key that may list the bucket and read, write and delete objects under the path.
3. **Upgrade the web image**: it includes Litestream (pinned release, checksum verified at build time) and the supervisor.
4. **Turn high availability on for the existing node first**: set the `HA_*` variables below, a unique `HA_NODE_ID`, and restart it. Finding the bucket empty, it becomes the leader and sends its database as the first replica. The **High availability** page shows it as the leader with the replication time.
5. **Add standbys**: the same image and variables, a different `HA_NODE_ID`, their own data volume (it can start empty) and the same `SESSION_SECRET` (stored secrets are encrypted with it). Every node points `CADDY_API_URL` at the same Caddy admin endpoint, or the Caddy nodes are instance sync slaves of the cluster.
6. **Put a load balancer in front** that checks `/api/health` (below), and give the containers 60 seconds to stop (`stop_grace_period: 60s`), so a hand-over loses nothing.

`docker-compose.ha.yml` is a complete example on one machine: two web nodes, Valkey, MinIO and a Caddy load balancer.

```bash
docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d
```

### Environment variables

| Variable | Default | Notes |
| --- | --- | --- |
| `HA_ENABLED` | off | `true` starts the supervisor. Every node of the cluster sets it. With it, a missing or invalid variable below stops the container (exit 78): a node meant for a cluster never runs on its own. |
| `HA_NODE_ID` | the host name | Unique per node: letters, digits, `.`, `_`, `-`, up to 64. |
| `HA_REDIS_MODE` | `standalone` | `standalone`, `sentinel` or `cluster`. |
| `HA_REDIS_ADDRESSES` | required | `host:port`, comma-separated: the server, the Sentinels, or cluster nodes to start from. IPv6 in brackets. |
| `HA_REDIS_MASTER_NAME` | | Sentinel mode: the master's name. |
| `HA_REDIS_DB` | `0` | Not in cluster mode. |
| `HA_REDIS_USERNAME`, `HA_REDIS_PASSWORD` | | ACL user and password. |
| `HA_REDIS_SENTINEL_PASSWORD` | | Sentinel mode. |
| `HA_REDIS_TLS` | `false` | Connect over TLS. `HA_REDIS_TLS_CA_FILE`: PEM certificates to trust; `HA_REDIS_TLS_INSECURE_SKIP_VERIFY`: do not verify. |
| `HA_REDIS_KEY_PREFIX` | `ingressi-ha` | Keys are `{<prefix>}:lease`, `:epoch`, `:replica`, `:nodes`. Give each cluster its own. |
| `HA_LEASE_TTL_SECONDS` | `15` | 5 to 300. Longer survives longer Redis hiccups but makes failover slower. |
| `HA_S3_ENDPOINT` | AWS S3 | The S3 API origin (`https://…` or `http://…` on a private network), without a path. Leave unset for AWS. |
| `HA_S3_REGION` | `us-east-1` | `auto` for Cloudflare R2. |
| `HA_S3_BUCKET` | required | |
| `HA_S3_PATH` | `ingressi` | Prefix inside the bucket: `cluster.json` and `replicas/` go under it. One per cluster. |
| `HA_S3_ACCESS_KEY_ID`, `HA_S3_SECRET_ACCESS_KEY` | required | Passed to Litestream through its environment only; never written to a file or shown. |
| `HA_S3_FORCE_PATH_STYLE` | `true` with an endpoint | `https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`. |
| `HA_SYNC_INTERVAL_SECONDS` | `1` | How often Litestream sends changes (1 to 60). |
| `HA_STANDBY_FOLLOW_INTERVAL_SECONDS` | `5` | How often standbys update their warm copy; `0` keeps none (standbys then answer the request-path routes with an empty database). Each update lists the replica: mind the request costs of your provider. |
| `HA_RECOVER_FROM_LOCAL` | off | Runbook only: see [a lost bucket](#runbook-a-lost-bucket). |
| `HA_LITESTREAM_BIN` | `litestream` | Outside the image. |

The database is the file of `DATABASE_PATH` (or `DATABASE_URL`); the supervisor keeps its own files in `ha/` next to it (mode 0700): Litestream's configurations and socket, the status file, the warm copy.

### Object storage

**AWS S3**

```env
HA_S3_REGION=eu-central-1
HA_S3_BUCKET=example-ingressi-ha
HA_S3_PATH=prod
```

The key's policy needs `s3:ListBucket` on the bucket (for the prefix) and `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on `arn:aws:s3:::example-ingressi-ha/prod/*`.

**Cloudflare R2**

```env
HA_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
HA_S3_REGION=auto
HA_S3_BUCKET=example-ingressi-ha
```

Create an R2 API token with *Object Read & Write* on the bucket.

**MinIO** (or another S3-compatible server)

```env
HA_S3_ENDPOINT=http://minio.internal.example.com:9000
HA_S3_BUCKET=ingressi-ha
HA_S3_FORCE_PATH_STYLE=true
```

MinIO's community edition is no longer maintained or published as images; `docker-compose.ha.yml` uses Chainguard's free MinIO images for the example. For production prefer a maintained, replicated store. A server with a certificate from your own CA needs it trusted in the image (`SSL_CERT_FILE` for Litestream, `NODE_EXTRA_CA_CERTS` for the supervisor).

### Load balancer

The health check answers by role:

| Request | Leader | Standby | Without HA |
| --- | --- | --- | --- |
| `GET /api/health` | 200 (503 once its lease can no longer be vouched for) | 503 | 200 |
| `GET /api/health?scope=request-path` | 200 | 200 with a warm copy, else 503 | 200 |
| `GET /api/health?scope=leader` | 200 (503 once its lease can no longer be vouched for) | 503 | 200 |
| `GET /api/health?scope=live` | 200 | 200 | 200 |

Send the dashboard (`BASE_URL`) to the nodes that answer `/api/health` with 200: there is one. Use `scope=live` for container liveness, so standbys are not restarted.

**Caddy**

```caddy
dashboard.example.com {
	reverse_proxy 192.0.2.11:3000 192.0.2.12:3000 {
		health_uri /api/health
		health_interval 2s
		health_status 200
		lb_try_duration 15s
	}
}
```

**HAProxy**

```haproxy
backend dashboard
    option httpchk GET /api/health
    http-check expect status 200
    server web-1 192.0.2.11:3000 check inter 2s fall 2 rise 1
    server web-2 192.0.2.12:3000 check inter 2s fall 2 rise 1

backend request_path
    option httpchk GET "/api/health?scope=request-path"
    http-check expect status 200
    server web-1 192.0.2.11:3000 check inter 2s fall 2 rise 1
    server web-2 192.0.2.12:3000 check inter 2s fall 2 rise 1
```

**Kubernetes**: a StatefulSet (one volume per pod), `readinessProbe` on `/api/health` (only the leader is ready, so the Service sends traffic to it alone), `livenessProbe` on `/api/health?scope=live`, and `terminationGracePeriodSeconds: 60`. A Service can only use the pods' one readiness probe; for the request-path routes, point Caddy at the pods directly or at a second load balancer that checks `scope=request-path`.

### Request-path routes

A standby keeps serving these routes; the single list, with the reason for each, is `ee/high-availability/request-path.ts` (`isRequestPathRoute`):

| Route | Called by |
| --- | --- |
| `/api/forward-auth/verify` | Caddy, for every request to a host protected by Ingressi forward auth |
| `/api/forward-auth/callback` | Caddy, for `/.ingressi-auth/callback` on protected hosts after sign-in |
| `/portal`, `/api/forward-auth/login`, `/api/forward-auth/session-login` | Visitors of protected hosts signing in |
| `/api/branding/*` | The portal's logos |
| `/api/monetization/gate` | Caddy, for every request to a host with API monetization |

On a standby the database is a read-only copy that trails the leader by a few seconds (the follow interval plus Litestream's own steps, typically under 10). Checking a forward-auth session (`verify`) only reads, so it works there: protected hosts keep working through a failover. Routes that change state need it shared through Redis or Valkey: with [shared state](#shared-state-phase-3) on, redeeming a sign-in code (`callback`) and metering API usage (the gate) work on standbys too. Portal sign-in still writes to the database (the sign-in and its audit event), so send the portal and its login routes to the leader; without shared state, send everything but `verify` there. `docker-compose.ha.yml` shows how: Caddy reaches the dashboard through `FORWARD_AUTH_INTERNAL_URL`, pointing at a load balancer that sends `/api/forward-auth/verify` to every node that answers `scope=request-path` and the rest to the leader.

### Dashboard page and API

The **High availability** page (`/high-availability`) shows this node's role, the lease holder and its fencing epoch, when Litestream last confirmed the replica up to date (and the lag), the last restore, the nodes as they last reported themselves (role, warm copy, time), and the configuration without secrets. It is read-only: the cluster is configured with environment variables. Only the leader serves the dashboard, so this is the leader's view. It needs `high_availability:read`.

`GET /api/v1/high-availability/cluster` returns the same (see [REST API](#rest-api)). A standby answers the API with 503.

Every takeover is in the audit log: `ha_leader_started`, recorded by the new leader when its dashboard starts, with the node, the epoch and what its database was restored from.

### Runbook: failover

- **Planned** (maintenance, upgrades): stop or restart the leader's container (`docker compose stop web`). It hands the lease over after Litestream's last sync; a standby takes over within seconds. Upgrade the standbys first, then the leader: the new leader runs the migrations of its release.
- **Unplanned**: nothing to do. A standby takes over within about 40 seconds. Afterwards, check the **High availability** page: the new leader, its last restore (`Restored from the newest replica`) and a replication lag of a few seconds.
- **To move the leader to a given node**, stop the others' containers briefly, or stop the leader while the chosen node is the only standby.
- **If no node becomes the leader**: look at the containers' logs (`[ha]` lines) and `lastRestore.error` in each node's report. The usual causes: Redis unreachable, object storage unreachable, a first start without a database, or [a lost bucket](#runbook-a-lost-bucket).

### Runbook: a lost bucket

**The leader is still running.** It notices within 5 minutes that its replica is gone and sends a full copy again (log: `replica … is gone from object storage; sending a full copy again`), then rewrites `cluster.json`. Check that the High availability page shows a recent replication time.

**No leader is running** (every node stopped, and the bucket or path was emptied or deleted). No node will take over, by design: an empty replica is never taken for a first start.

1. Stop every web node.
2. Pick the node that was the leader last: its data volume holds the newest database (the logs say which node was the leader; `ingressi.db` there has the newest modification time).
3. Recreate the bucket if needed, then start only that node with `HA_RECOVER_FROM_LOCAL=true`. It takes the lease, finds the current replica empty, and sends its own database as a new replica (High availability page: `Recovered from this node's own database`).
4. Remove `HA_RECOVER_FROM_LOCAL` and restart that node: it takes over again, this time from the new replica. Then start the others.

**The bucket and the last leader's disk are both lost**: restore a scheduled backup ([scheduled-backups.md](scheduled-backups.md)) on one node without `HA_ENABLED`, then set the cluster up again on an empty path: a new `HA_S3_PATH` and a new `HA_REDIS_KEY_PREFIX` (or delete `cluster.json`, the `replicas/` objects and the `{<prefix>}:replica` and `{<prefix>}:epoch` keys).

### Limits

- **One leader writes.** Standbys do not take writes; the cluster is for availability, not for spreading load.
- **Request-path state is per node** unless [shared state](#shared-state-phase-3) is on: see [Request-path routes](#request-path-routes).
- **L4 ports**: the l4-port-manager watches one data volume. In a cluster, set `L4_PORTS_DIR` on every web node to a directory on a volume they share with it, or change L4 ports while a known node leads.
- **Instance sync slaves cannot be clusters** (`INSTANCE_MODE=slave` with `HA_ENABLED` refuses to start). A cluster is the master or a standalone dashboard.
- **The node list** shows up to 32 nodes; reports older than 15 minutes are dropped.
- **Clocks**: lease timing uses each node's clock between renewals; keep them in sync (NTP). Node ids must be unique.

## Shared state (phase 3)

With several web nodes (a leader and standbys that share its database), a user signed in through one node's portal must pass forward auth on every node, and an API consumer must be charged once for the whole cluster. **Shared state** keeps that request-path state in Redis or Valkey instead of each node's database and memory:

| State | Without shared state | With shared state |
| --- | --- | --- |
| Forward-auth sessions | `forward_auth_sessions` in SQLite | Redis, 7 days, as before |
| Exchange codes (portal to callback) | `forward_auth_exchanges` | Redis, 60 seconds, one use |
| Redirect intents (the portal's `rid`) | `forward_auth_redirect_intents` | Redis, 10 minutes, one use |
| API balances, free requests, per-minute windows | the dashboard process, written to SQLite every 5 seconds | Redis, charged by one atomic script per request |
| Top-ups and adjustments | the ledger at once | Redis at once, the ledger within seconds |
| Consumer portal and API rate limits | per process | Redis, for the cluster |

Users, groups, grants, hosts, plans, consumers and keys stay in the database: shared state holds only what request paths write. Each node checks access against its database on every request, as before.

### Turn it on

1. Configure the Redis or Valkey settings of the [certificate storage](#settings) (**Save without enabling** is enough: certificate storage can stay local).
2. If a password is read from an environment variable (`CADDY_STORAGE_*`), set it on every **web** container too: the web containers connect with these settings.
3. **High availability → Shared state → Turn on**, or `PUT /api/v1/high-availability/shared-state` with `{"enabled": true}`. The node checks that it reaches the server first (`502` otherwise) and writes its own pending API usage to the ledger.

It is a switch of its own on the certificate storage's connection: one Redis or Valkey deployment serves both, with the same settings, secrets, TLS, Sentinel and cluster support, but each moves something different (where Caddy keeps certificates, where web nodes keep sessions and balances) and can be turned on, tested and rolled back without the other. While shared state is on, the certificate storage cannot move to another server or lose its Redis settings (`409`): turn shared state off first. Passwords, TLS and the Caddy key prefix can change.

Turning shared state on or off signs forward-auth users out once (they sign in again through the portal); API balances continue from the ledger.

### Keys

Every key starts with `<key prefix>:<generation>:` (prefix `ingressi` by default; the generation changes each time shared state is turned on, so nothing left from an earlier period is read again). Forward-auth keys share the hash tag `{fa}`, each API consumer's keys `{mz:<id>}`, so every script stays in one cluster slot. Every key has a TTL: sessions expire with the session, codes and intents with their lifetime, a consumer's counters 35 days after their last use, indexes and markers within days.

Tokens, codes and intent ids are stored only as SHA-256 hashes, as in SQLite. No API keys or their hashes are stored (the gate checks those against its own copy of the database), and nothing else that is not in clear in SQLite too: user and host ids, origins, redirect URIs, amounts, counts and ledger descriptions. Give the Redis user an ACL limited to its key patterns (`~caddy/*`, `~ingressi:*`) if other applications share the server.

### Charging and the ledger

Each gate request runs one Lua script on the consumer's hash: it checks the per-minute window, uses a free request or checks the balance against the overdraft allowance, and charges, all at once, so requests on several nodes never spend the same money twice. The hash is created from the consumer's database row the first time it is needed.

The ledger in the leader's database stays the record that reports, the overview and invoices read. Every five seconds the leader writes back what the nodes counted:

- **Usage:** the consumer's hash keeps cumulative counters (charged micro-units, requests, free requests). The leader writes the difference to the hour's usage row and the stored balance, and records how far it got (`monetization_shared_cursors`) in the same transaction, so a write-back repeated after a crash counts nothing twice.
- **Top-ups and adjustments** credit the shared balance at once and are queued for the ledger in the same step, at most once per reference (`stripe:<session>`, `adjustment:<reference>`). The leader writes each queued credit once (`monetization_shared_credits`, in the same transaction) and takes it off the queue afterwards. On the leader, a Stripe webhook or an adjustment is written to the ledger before it answers.

**High availability → Shared state** and `GET /api/v1/high-availability/shared-state/status` show the sessions and consumers held, credits not yet in the ledger, and the last write-back.

### Revocation

Revocation takes effect on every node at once, also on nodes whose copy of the database trails the leader's: signing out a session (`DELETE /api/v1/forward-auth-sessions/{id}`), ending a user's sessions, disabling, deleting or deprovisioning (SCIM) a user, disabling an organisation and changing a password end the user's shared sessions. Removing a user from a group, deleting a group, replacing a host's grants, moving users or hosts between organisations and restoring a configuration end the sessions the database no longer allows. Deleting a host ends its sessions. For API monetization, disabling a consumer and revoking a key are refused by every node at once.

A deleted user's sessions are ended before the account is removed: if the shared state cannot be reached the deletion fails and the account stays, so a later account with the same id can never find them.

### When Redis or Valkey is unavailable

Request paths fail closed rather than count on one node: hosts behind Ingressi forward auth and monetized hosts answer `503` with `Retry-After`, and the portal cannot sign anyone in until the server is back. The same applies when shared state is on but cannot be used (no Redis settings, a password variable missing in a web container); the card says why. Usage counted before an outage stays in Redis and is written back afterwards.

If Redis or Valkey **loses its data**, sessions are gone (users sign in again) and each consumer's balance starts again from the ledger: usage and credits not yet written back (seconds) are lost, in the consumers' favour for usage. Run it with persistence (AOF) and replication, as for certificate storage.

### Turn it off

**Turn off** (`PUT … {"enabled": false}`) writes the shared balances to the ledger first and changes nothing when it cannot (`502`). **Remove setting** (`DELETE`) turns shared state off even when the server cannot be reached; usage and credits not yet in the ledger are then lost. Keys left in Redis expire on their own.

### Leader and standbys

Only the leader writes back to the database. A node started as a standby (`HA_ROLE=standby`) never does; a lock in Redis keeps two nodes from writing back at once, and the write-back is idempotent either way. Every node announces changes to plans, consumers, keys and hosts; the others reload their copy of the gate's configuration at once and again for ten seconds (a standby's database trails the leader's), and every 30 seconds in any case.

### Permissions, sync

Permissions: `high_availability:read` to read, `high_availability:write` (administrator-level) to change. Audit events: `ha_shared_state_updated`, `ha_shared_state_removed`.

The setting is the instance's own (settings key `ha_shared_state`): it is not synced to instance sync slaves (they keep request-path state local and serve no Ingressi forward auth), not in configuration export, history or fleet revisions. Standbys share the leader's database and so its setting. A master whose replicas serve monetized hosts through shared state sends them its namespace with the configuration, and those replicas hold the Redis or Valkey credentials: they are trusted like the master, so use that mode only for nodes you trust as such ([API monetization](api-monetization.md#sync-replicas-and-pull-replicas)).

| Method and path | Permission | Notes |
| --- | --- | --- |
| `GET /api/v1/high-availability/shared-state` | `high_availability:read` | `enabled`, `backend` in use, `keyPrefix`, `namespace`, the connection (from certificate storage, no secrets), `editable`, `error`. |
| `PUT /api/v1/high-availability/shared-state` | `high_availability:write` | `{enabled?, keyPrefix?}`. `400` without the certificate storage's Redis settings, `409` on a slave, `502` when the server cannot be reached or the balances cannot be written back. |
| `DELETE /api/v1/high-availability/shared-state` | `high_availability:write` | Off, whatever the server says. |
| `GET /api/v1/high-availability/shared-state/status` | `high_availability:read` | `reachable`, `keys` (`forwardAuthSessions`, `monetizationConsumers`, `pendingCredits`), `drain` (last write-back), `leader`. |

```bash
curl -X PUT https://dash.example.com/api/v1/high-availability/shared-state \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"enabled":true,"keyPrefix":"ingressi"}'
```

## PostgreSQL replicas

With the dashboard on PostgreSQL (`DATABASE_URL=postgres://…`), several web containers can point at the same database. Every replica serves the dashboard, the API and the request-path routes (forward auth, the portal, the API gate) from it. One replica, the **leader**, runs the background jobs: the start-up tasks, applying the configuration to Caddy, the Caddy monitor, log and WAF log ingestion, ClickHouse set-up, audit streaming and retention, instance sync, pull replicas, alerts, scheduled backups, change approvals, access list expiry, access reviews, the fleet scheduler, directory health checks, compliance reports, AI digests, API monetization metering and the shared state write-back. The others start none of them.

Nothing else is needed: no `HA_*` variables, no Redis for the lead, no object storage. `HA_ENABLED` (the SQLite cluster above) is refused with a PostgreSQL URL. On SQLite none of this runs.

Code: `src/lib/db/leader.ts` (the election), `src/lib/cluster-nodes.ts` (membership), `src/lib/background-jobs.ts` (the jobs), `ee/high-availability/replicas.ts` (the view), `src/lib/dashboard-upstreams.ts` (how Caddy reaches the replicas), `docker-compose.postgres.yml` (a deployment).

### Leader election

- Every replica keeps one connection of its own to PostgreSQL for the election, outside its pool, and tries every 3 seconds to take a session advisory lock (`pg_try_advisory_lock`). The replica whose session holds it leads.
- The leader checks every 2 seconds, on that connection, that its session still holds the lock.
- **Crash-only fencing.** When the connection reports an error or closes, a check fails, takes longer than 3 seconds or finds the lock gone, or no check has succeeded for 6 seconds, the replica stops leading at once: it stops its background jobs first, and only then closes the connection (which frees the lock if its session still held it). It never repairs a connection it can no longer vouch for. Then it competes again on a new connection, as a follower.
- For a leader the server can no longer reach, PostgreSQL ends the session after about 20 seconds (TCP keepalives and `tcp_user_timeout`, set on that session), which frees the lock for another replica. The leader has stopped its jobs well before that.
- On `SIGTERM` or `SIGINT` (`docker compose stop`, a rolling restart) the leader stops its jobs, then releases the lock: another replica takes over within about 3 seconds. Every replica records that it stopped. The process exits once this is done, after 8 seconds at most. The image sets `NEXT_MANUAL_SIG_HANDLE=true` for this; set it too if you run the server outside the image.
- Every takeover is in the audit log: `ha_leader_started`, with the replica's id.

The lock decides who starts the jobs; it does not fence writes. A job run that was already going when its replica stopped leading finishes on its own, so work that must never overlap anywhere (applying the Caddy configuration, a backup, a rollout) also takes a cluster lock.

| Failure | What happens |
| --- | --- |
| The leader stops cleanly | It stops its jobs and releases the lock; another replica leads within about 3 seconds. |
| The leader crashes or its host is lost | The server notices the closed connection, or ends the session after about 20 seconds; another replica takes over. |
| The leader is cut off from PostgreSQL | It stops its jobs within 6 seconds and keeps trying to reconnect; its requests fail until the database is back. Another replica takes over once the server ends the old session. |
| PostgreSQL restarts | Every session ends: the leader stops its jobs at once. When the server is back, one replica takes the lock again. |
| The leader's session is ended by hand (`pg_terminate_backend`) | It stops its jobs as soon as its connection reports it, and follows. |
| A start-up task that must succeed fails on the leader | It stops its jobs and lets another replica lead for a minute (doubling up to an hour). On the first start of a replica that leads at once, the server does not start, as on SQLite. |

The election needs a direct connection to PostgreSQL or a pooler in **session** mode: a pooler in transaction mode (PgBouncer's `pool_mode = transaction`) cannot hold a session lock. Each replica uses one connection for it, on top of its pool (`DATABASE_POOL_MAX`).

### Membership

Each replica registers in the `cluster_nodes` table when it starts and records a heartbeat every 10 seconds: its id, host name (a label only), version, the newest migration it knows, when it was first seen and when it started, and whether it leads. A replica silent for 45 seconds shows as gone; one that stopped cleanly shows as stopped; rows silent for 30 days are deleted by the leader. A new node id joins when it starts; the audit log records it (`ha_replica_joined`).

The **node id** is `INGRESSI_NODE_ID` (letters, digits, `.`, `_`, `-`, up to 64; it must be unique), or else an id generated once and kept in the container's data volume (`/app/data/node-id`; `INGRESSI_DATA_DIR` moves it). A container without a data volume gets a new id at every start: set `INGRESSI_NODE_ID` for it.

**One process per node id.** Two containers on one data volume, or with the same `INGRESSI_NODE_ID`, would otherwise count as one replica and write over each other's heartbeat and leader flag. So every process draws a random token when it starts and records it with its heartbeat:

- A heartbeat that finds another process's token on its node id, written within 45 seconds, means two processes share the id. The newer one (the later start) refuses to run as a replica: it stops leading and running jobs, answers every request but the health check with `503` and the reason (`X-HA-Role: refused`; `/api/health` answers `503` too, except `scope=live`), logs why (`[replicas] This replica was not admitted: another process is already running with its node id …`, with the id) and tries again every 30 seconds. It runs once the other process has stopped. The refusal is in the audit log (`ha_replica_refused`, reason `duplicate`). The older process runs on, writes its heartbeat back and logs a warning.
- A container restarted after a crash finds its own old row, written seconds ago by a process that no longer exists. That is not a duplicate: it takes the row over, serves requests at once, and competes for the lead after one heartbeat interval (about 15 seconds) has shown that nobody else writes the row.
- Give every container its own data volume or its own `INGRESSI_NODE_ID`.

### Deploy

`docker-compose.postgres.yml` is an override of `docker-compose.yml`: PostgreSQL 17 next to the stack (C collation, a health check, the `postgres-data` volume, `max_connections` 200, reachable only on the compose network), the web service on it, and a second replica, `web-2`, started by the `replicas` profile.

1. Run one replica on PostgreSQL first: set `POSTGRES_PASSWORD` in `.env` (letters and digits, it goes into a URL: `openssl rand -hex 32`) and start with the override, as in [PostgreSQL](../../documentation/postgresql.md#a-fresh-install). An existing install is copied from SQLite first ([Moving an existing install](../../documentation/postgresql.md#moving-an-existing-install)).

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
   ```

   `COMPOSE_FILE=docker-compose.yml:docker-compose.postgres.yml` in `.env` saves typing the files.
2. In `.env`, add `replicas` to `COMPOSE_PROFILES` (`COMPOSE_PROFILES=clickhouse,replicas`) and list the replicas for Caddy: `DASHBOARD_UPSTREAMS=web:3000,web-2:3000`.
3. Run the same `up -d` again. `web` is recreated with the new list; `web-2` starts once `web` is healthy and joins. The **High availability** page shows both.
4. Make the dashboard reachable through both replicas ([The dashboard](#the-dashboard)).

A third replica is a copy of `web-2` in your own override file: another service name, its own data volume, `L4_PORTS_DIR` on `caddy-manager-data`, and its name in `DASHBOARD_UPSTREAMS`. Do not use `deploy.replicas` or `docker compose up --scale`: the copies would share one data volume, and so one node id, and all but the oldest would refuse to run.

### Topologies

```
                          clients (80, 443)
                                  │
                             ┌────┴────┐
                             │  caddy  │── access and WAF logs ──► caddy-logs
                             └────┬────┘
   Caddy to the replicas: forward auth, sign-in callback, API gate (DASHBOARD_UPSTREAMS)
   the replicas to Caddy: its admin API on :2019 (CADDY_API_URL, the same on every replica)
                 ┌────────────────┴────────────────┐
            ┌────┴─────┐                      ┌────┴─────┐
            │ web      │                      │ web-2    │
            │ leader   │                      │ follower │
            └────┬─────┘                      └────┬─────┘
                 └────────────────┬────────────────┘
                           PostgreSQL 17

   every replica mounts caddy-logs, acme-ca and geoip-data; each has a data volume of its own
```

| Topology | Supported | What it takes |
| --- | --- | --- |
| One web container, one Caddy, PostgreSQL | Yes | The override without the `replicas` profile. |
| Several replicas and one Caddy on one Docker host | Yes | The override with the `replicas` profile, as above. |
| Replicas on several machines, one Caddy | Yes | Every replica reaches PostgreSQL, and Caddy's admin API on a private network under the name `caddy` (Caddy only answers its admin API for that name: map it with `extra_hosts`). Caddy reaches every replica (`DASHBOARD_UPSTREAMS` with their private addresses). Every replica mounts Caddy's log directory at `/logs` and the `acme-ca` directory, for example from a network file system. Never publish port 2019. |
| Several Caddy nodes | Yes, as instance sync slaves | The replicas' leader syncs the configuration to the slaves, each a web container on SQLite and a Caddy; [shared certificate storage](#cluster-design) lets them share certificates. Slaves serve neither Ingressi forward auth nor monetized hosts ([Honest limits](#honest-limits)). |
| A Caddy per replica, each replica on its own | No | A change reaches only the Caddy of the replica that applied it, and only the leader's Caddy is watched for drift. Every replica points `CADDY_API_URL` at the same Caddy. |

API monetization with more than one replica needs [shared state](#shared-state-phase-3): without it, turning monetization on is refused (`409`).

### Volumes

| Volume | Mounted at | Which replicas | Why |
| --- | --- | --- | --- |
| A data volume of its own (`caddy-manager-data` for `web`, `web-2-data` for `web-2`) | `/app/data` | Each its own | The node id (`node-id`). Two replicas on one data volume would have one id: the newer one refuses to run ([Membership](#membership)). |
| `caddy-manager-data` | `/app/data` on `web`, `L4_PORTS_DIR` on the others | Every replica, read-write | The L4 ports files the l4-port-manager watches. Any replica may apply the configuration. |
| `caddy-logs` | `/logs` | Every replica, read-write | The leader reads Caddy's access and WAF logs and truncates `waf-audit.log` once it has read it. The lead can move to any replica. |
| `acme-ca` | `/acme-ca` | Every replica, read-write | The custom ACME CA root, written by the replica that applies the configuration. |
| `geoip-data` | `/usr/share/GeoIP` | Every replica, read-only | Country and network lookups. |

How far the logs were read is kept in the database, so a new leader goes on where the last one stopped. A leader without `/logs` collects no traffic or WAF events while it leads, and says so in its log each time it starts the parsers (`[log-parser] Caddy's log directory /logs is not mounted …`). Lines Caddy rolled away meanwhile are not read.

### Caddy and the replicas

Caddy calls the dashboard for every request to a host behind Ingressi forward auth (`/api/forward-auth/verify`), for the sign-in callback on those hosts, and for every request to a monetized host (`/api/monetization/gate`). `DASHBOARD_UPSTREAMS` lists the replicas it sends these to: `host:port`, separated by commas, IPv6 in brackets, `http://` allowed in front. Set it to the same value on every replica: any replica may apply the configuration.

- Unset or empty, Caddy uses the single address it always used: `FORWARD_AUTH_INTERNAL_URL`, else `web:3000`, else the host of `BASE_URL`. With one address the configuration is exactly as without replicas. `DASHBOARD_UPSTREAMS` wins over `FORWARD_AUTH_INTERNAL_URL`.
- With several, each of these routes checks `/api/health` on every replica when Caddy loads the configuration and every 10 seconds after. A replica that does not answer 200 within 5 seconds (stopped, starting, or refused because another process uses its node id) gets nothing until it does.
- Three failed requests to a replica within 10 seconds take it out for those 10 seconds, for every route at once.
- A request that could not reach a replica is tried on another for up to 5 seconds, every 250 milliseconds. One that reached a replica and got no answer is tried again for the forward-auth check and the callback (the check only reads; a sign-in code is redeemed once, so a repeat is refused, never counted twice), never for the API gate: it charges the consumer when it answers.
- An entry that is not an address stops the container at start-up with a message that names its position.
- A new list reaches Caddy the next time the configuration is applied. A replica applies it whenever it starts leading, so recreating the replicas is enough. Replicas with different lists would change Caddy's configuration at every change of leader.

Each Caddy route that calls the dashboard runs its own health check, so with many protected or monetized hosts the replicas answer a few small `/api/health` requests a second. The check does not touch the database.

On Kubernetes, either point `DASHBOARD_UPSTREAMS` at one Service whose readiness probe is `/api/health` (the Service balances, and keeps refused or stopped pods out), or list the pods of a StatefulSet through a headless Service (`ingressi-web-0.ingressi-web:3000,ingressi-web-1.ingressi-web:3000`). Caddy treats one name as one upstream however many addresses it resolves to, and its dynamic upstreams have no active health checks: that is why the list names every replica.

### The dashboard

Sessions and sign-in rate limits are in the database, and every replica hears of a change to what it caches at once, so any replica serves any signed-in user: no sticky sessions. Set the same `BASE_URL`, `SESSION_SECRET` and `CADDY_API_URL` on every replica.

- **Behind Caddy.** Add a proxy host for the dashboard (`dash.example.com`) with every replica as an upstream (`web:3000`, `web-2:3000`), load balancing on, and an active health check on `/api/health`. Set `BASE_URL` to `https://dash.example.com`. The override still publishes port 3000 of `web` for the first set-up; remove it, or bind it to `127.0.0.1`, once the proxy host works.
- **Your own load balancer.** Send the dashboard to every replica that answers `/api/health` with 200:

  ```haproxy
  backend dashboard
      option httpchk GET /api/health
      http-check expect status 200
      server web-1 192.0.2.11:3000 check inter 2s fall 2 rise 1
      server web-2 192.0.2.12:3000 check inter 2s fall 2 rise 1
  ```

### Health checks

| Request | Follower | Leader | Refused replica |
| --- | --- | --- | --- |
| `GET /api/health` | 200 | 200 | 503 |
| `GET /api/health?scope=request-path` | 200 | 200 | 503 |
| `GET /api/health?scope=leader` | 503 (`follower`) | 200 | 503 |
| `GET /api/health?scope=live` | 200 | 200 | 200 |

Load balancers and Caddy use `/api/health`. `scope=leader` tells which replica runs the jobs; `scope=live` is for container liveness, so a refused replica is not restarted over and over.

### Connections

Each replica opens up to `DATABASE_POOL_MAX` (10) connections for queries, up to 20 for cluster locks, one for the leader election and one for change notifications (`LISTEN`). Set PostgreSQL's `max_connections` to at least the number of replicas × (`DATABASE_POOL_MAX` + 22), plus what you connect yourself (`psql`, backups, the copy and break-glass tools). The override sets 200: enough for five replicas. Connect directly or through a pooler in session mode, never in transaction mode.

### Upgrades and restarts

- **To upgrade, stop every replica, then start the new version.** The first replica to start migrates the database; a replica refuses to start on a database a newer version migrated. The High availability page warns when live replicas run different versions.

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.postgres.yml pull
  docker compose -f docker-compose.yml -f docker-compose.postgres.yml stop web web-2
  docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
  ```

  While no replica runs, hosts behind Ingressi forward auth and monetized hosts fail: plan a short window. Do not let an image updater (Watchtower and the like) replace the replicas one at a time: the replica it starts first migrates the database under the others.
- A restart without an upgrade can be rolling: restart one replica at a time. The leader hands the lead over within seconds when it stops, and Caddy sends requests to the replicas that answer.

### Backups

- **The database**: `pg_dump`, or point-in-time recovery on a managed service. With the override:

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.postgres.yml exec -T postgres \
    pg_dump -U ingressi -d ingressi --format=custom > ingressi-$(date +%F).dump
  ```

  To restore, stop every replica and restore into an empty database created as in [Requirements](../../documentation/postgresql.md#requirements) (`pg_restore -U ingressi -d ingressi --no-owner`), then start them.
- **The data volumes**: `caddy-manager-data` holds the L4 ports files and `web`'s node id; the other replicas' volumes hold only their node ids, which a replica generates again if lost (it then joins as a new replica).
- **`SESSION_SECRET`**, with the backups: the stored secrets are encrypted with it.
- Caddy's own volumes, as without replicas.

### Dashboard page and API

The **High availability** page shows **PostgreSQL mode**: every replica with its role (leader, follower, stopped, gone), last heartbeat, version, schema and when it was first seen, which one leads, and this replica's election state. It is read-only: a replica joins by starting with the same `DATABASE_URL`. It needs `high_availability:read`, as does `GET /api/v1/cluster/nodes`, which returns the same (see [REST API](#rest-api)).

Nothing here is a setting: there is nothing to sync to instance sync slaves, export or restore. `DASHBOARD_UPSTREAMS` is an environment variable of each replica.

### Limits

- **Clocks**: heartbeats and the gone state use each replica's clock; keep them in sync (NTP).
- **L4 ports**: the l4-port-manager watches `caddy-manager-data`. Every replica writes the L4 ports files there: `web` in its data directory, the others through `L4_PORTS_DIR`, as the override does for `web-2`.
- **One Caddy, or instance sync slaves**: see [Topologies](#topologies).

## Coming soon

- **Upgrades without stopping every replica.** Today an upgrade stops every PostgreSQL replica first.
