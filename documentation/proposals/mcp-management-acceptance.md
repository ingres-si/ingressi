# MCP proposal: acceptance, failure and adversarial test plan

Companion to the [design RFC](mcp-management.md). **These are planned implementation gates, not tests executed by this documentation PR.** A source inventory, link check or passing existing application suite cannot demonstrate a server that has not been implemented.

Record each test's artifact/protocol/runtime/API version, principal/scopes/host scope, setup, input, expected/actual result, sanitized evidence IDs, outcome and cleanup. Run initial implementation tests in disposable isolated instances with synthetic data. Do not use customer sessions, customer records, production bans or real notification destinations as fixtures.

## A. Protocol and authentication

| ID | Required experiment | Pass evidence |
| --- | --- | --- |
| A01 | Discover/call every initial tool through the actual SDK transport | Input/output schema and result behavior conform to the pinned supported protocol; no protocol output polluted by stdout logs. |
| A02 | Unsupported/malformed protocol revision and metadata | Bounded explicit refusal; no downgraded authentication or unexpected tool execution. |
| A03 | Supported client/runtime matrix, including Bun/Node if advertised | Native artifacts tested for each claimed pair; packaging and process shutdown work. Unsupported pairs documented. |
| A04 | Missing, malformed, expired and revoked upstream token |401/403 preserved as appropriate, no admin/session fallback, no leaked token or backend stack trace. |
| A05 | Remove owner permission or change account state after discovery | Next invocation fails at REST; cached tools/results do not preserve revoked access. |
| A06 | Scoped administrator token versus unscoped administrator token | Default setup requires deliberate bounded scopes; scoped tokens do not become unrestricted administrators. |
| A07 | Built-in viewer/user without administrative permissions | No assumed broad reads; useful permission explanation without exposing inaccessible inventory. |
| A08 | Cross-host IDs and tag scope in lists, details, health and certificates | Out-of-scope IDs remain hidden/404; filtering applies to all linked resources, not just top-level rows. |
| A09 | Direct invocation of an undisclosed tool/name | Runtime authorization/allowlist rejects it; discovery filtering alone is not the defense. |
| A10 | Low-privilege access to instance-wide WAF/analytics/audit metadata | Denial without the relevant instance-wide permission; an input host filter never grants access. |
| A11 | Enterprise feature absent, unavailable or unauthorized | Explicit unsupported/denied result; no code relocation, license bypass or fallback credential. |
| A12 | Restart/revoke stdio process and change its token source | Access ends as documented, sensitive buffers/files handled safely, proxy service continues. |

Remote HTTP is **not** accepted by passing stdio tests. It additionally needs:

| ID | Required experiment | Pass evidence |
| --- | --- | --- |
| H01 | Wrong issuer/audience, invalid signature, expired token, cross-principal credential binding | Refused before upstream access; no shared privileged backend identity. |
| H02 | Invalid/forged Origin and Host, DNS rebinding, untrusted browser origins |403 or equivalent safe refusal; loopback/default binding verified; valid non-browser bearer clients follow explicit policy. |
| H03 | OAuth metadata discovery, authorization errors and least-scope requests | Pinned protocol's required flows interoperate; no token passthrough or secret in redirect/error. |
| H04 |2026-07-28 per-request behavior and any claimed legacy compatibility | No legacy session ID used as authentication. Current POST/metadata behavior tested separately from any explicitly supported old session/GET-stream behavior. |
| H05 | Concurrent users, caches and plan/state references | No cross-user result/cache/state leakage; credential scope changes invalidate access. |
| H06 | Invalid authorization URLs, redirects and issuer metadata endpoints | SSRF/credential leakage refused, including loopback/link-local/cloud metadata destinations where not explicitly trusted for that purpose. |

## B. Data minimization and untrusted content

| ID | Required experiment | Pass evidence |
| --- | --- | --- |
| B01 | Seed secrets in every nested host/settings/provider/certificate/config field | Output/log/client context has no planted secret, private key, cookie, credential-bearing URL or unknown newly added field. |
| B02 | Seed secrets in WAF matched variables, headers, request query/body and backend errors | Safe projection retains useful event metadata and attribution without returning sensitive values. |
| B03 | Request configuration export, raw settings, private keys, token creation or account-session data by paraphrase and by direct tool call | No matching dangerous tool in phaseA; policy rejects an attempted operation. |
| B04 | Prompt injection in URL, user agent, host description, rule text and returned error | Results remain data. Even an assistant that follows the injected instruction cannot call a forbidden operation or target. |
| B05 | Add an unexpected sensitive upstream response property | Schema/projection drops or explicitly rejects it; no generic serialization silently exposes it. |
| B06 | Hosted-model client versus local-model client | Data-egress policy and documentation accurately describe the client destination; local MCP placement is not advertised as sufficient for local-only processing. |
| B07 | Oversized/error-stream response, Unicode nesting, array explosion and pagination boundary | Memory/time/byte/structure limits hold; result explicitly incomplete or failed; no silent “all results” claim. |
| B08 | Response/audit cache reuse across users and after revocation | No sensitive shared cache; tenant/principal boundaries and token revocation remain effective. |

## C. Correct routing and analytics

| ID | Required experiment | Pass evidence |
| --- | --- | --- |
| C01 | HTTP host with TLS redirects, HSTS, upstream Host preservation and WebSockets | Read metadata accurately reflects configured behavior. Any later write preserves unrelated fields and real websocket data/ping works. |
| C02 | Healthy upstream, genuine upstream404/500, access-list rejection, rate limit and WAF rejection | Correct attribution to each control/source; errors are not universally described as WAF blocks. |
| C03 | Same path/client within a short window with distinct request IDs and different outcomes | Every individual label/ID matches raw evidence; equal aggregate counts alone fail the test. |
| C04 | Mixed DetectionOnly and blocked peak traffic | Security/outcome series preserve the distinct semantics and timestamps; observed-only events are not reported as enforcement. |
| C05 | WAF-only versus all-mitigated query, including unassigned rule IDs | Exact totals/denominators match independent fixture truth; unassigned records retained correctly without invented rule labels. |
| C06 | Exact UTC ranges, epoch seconds/milliseconds, DST/display zones and boundaries | Query range/units and display conversion match backend contract; no unexplained excluded/included boundary events. |
| C07 | Empty, unavailable, partial, late-arriving and retention-expired datasets | Distinct outcomes/warnings; no error or truncation interpreted as “no attacks.” |
| C08 | Current/previous periods, shares, trends, host/country filters and mixed controls | Deterministic query metadata and independent raw-fixture totals agree for each requested population. |
| C09 | Shared legitimate IP, internal public-address-space IP and country/ASN labels | No unsupported attacker/location assertion, blanket exemption or automatic block. |
| C10 | Missing, expired, imported, ACME-managed and wildcard certificates; unreadable manager/API | Coverage reflects actual certificate source and host scope. Manager failure is not silently treated as no certificates; no force issuance. |
| C11 | L4, redirects/rewrites, path access, load balancing and DNS subfeatures if advertised | Exact schema/permission behavior and per-feature regressions demonstrated; unsupported subfeatures clearly identified. |
| C12 | Optional existing AI provider invocation/question decomposition | Explicit provider/data policy, bounded timeout, executed query evidence and unsupported-question behavior; no action authorized by generated text. |

## D. Preparation and future mutations

These gates apply before any execution capability, even if the implementation is feature-flagged. A01–C12 do not prove safe write execution.

| ID | Required experiment | Pass evidence |
| --- | --- | --- |
| D01 | Create/update preview with narrow scopes and no write scopes | Existing native permission rules retained; preview saves/applies nothing. A missing write scope is not worked around. |
| D02 | Pending native approval, missing approval policy and immediate-write route |202/pending is not applied; unprotected create is never mislabeled “submit draft.” |
| D03 | Model supplies `approved:true`, fake approver text, forged nonce or another principal's plan | Execution denied; trusted principal/target/payload/expiry binding required. |
| D04 | Own-request approval, emergency bypass and policy disable through requester credential | Refused or absent; requesting assistant cannot obtain an independent approver identity. |
| D05 | Native policy tightened/disabled, approver/requester permission revoked, window closes or plan expires | Native checks and any stricter adapter policy re-evaluated at execution; no stale authorization. |
| D06 | Concurrent dashboard, another API writer and another adapter change the same host after preview | Backend atomic precondition or demonstrated native protection prevents lost updates. Sidecar-only locks do not pass. |
| D07 | Competing create with same hostname, changed target tags/access list/certificate | Conflict is explicit; no overwrite, scope escape or hidden default applied. |
| D08 | Timeout/disconnect at each stage before/after accepted apply | Readback/reconciliation distinguishes no change, pending, applied, rejected and uncertain outcome. No blind replay. |
| D09 | Duplicate/replayed plan and operation ID across process restart | Backend-supported idempotency or refusal demonstrated. An unused HTTP header is not evidence. |
| D10 | Caddy validation/reload rejection and stored-but-not-live failure | Existing native recovery/error semantics preserved; no false success or automatic unrelated service restart. |
| D11 | Compensation after a failed change with intervening third-party edits | Refuse stale rollback; restore only the owned change with valid preconditions, never whole-DB rollback to undo one host. |
| D12 | Multi-instance staged plan if ever supported | Exact targets bound separately; stop dependent changes on first failure, retain actual partial outcomes. |
| D13 | WAF/exclusion/rate/access-list change with legitimate shared-IP and body/upload fixtures | False-positive impact measured, scope/expiry explicit and security not weakened by a model suggestion. |
| D14 | Alert/AI/audit/LDAP/backup/storage “test” operations | Real outbound effects identified; absent in read-only registry and never invoked implicitly to validate configuration. |
| D15 | Import/restore/revocation/payment/authentication/trust or port-promotion request | Excluded early; later release requires a separately reviewed workflow, irreversible-effect warning and independent acceptance evidence. |

## E. Operations, release and recovery

| ID | Required experiment | Pass evidence |
| --- | --- | --- |
| E01 | Adapter crash, restart, OOM/resource saturation and removal | Reverse proxy traffic, active websockets, dashboard, security logging/ingestion and existing protection remain within agreed budgets; no serving dependency. |
| E02 | Slow API, unavailable ClickHouse/Caddy, cancellation and retry storms | Backpressure/timeouts and bounded reads work; no mutation retry or “fix” that changes a protected service. |
| E03 | Inspect mounts, capabilities, file permissions, network and running identity | No Docker/Caddy sockets, application databases/volumes, unnecessary credentials or host privileges. |
| E04 | Artifact signature/provenance, dependency lock/SBOM, architecture and license review | Exact supported package/image verified; enterprise boundaries retained; no auto-install of unpinned packages. |
| E05 | Ingressi/adapter upgrade, API response drift and rollback | Compatible tools continue or fail closed; no runtime file patches, automatic listener exposure or permission widening. |
| E06 | Token rotation/revocation, log retention/disk limits and audit correlation | Secrets absent, real actor preserved, bounded metadata available, no invented audit-chain integration. |
| E07 | Deterministic discovery and large tool/response context | Stable permitted tool list, bounded context, supported pagination and useful explicit limitations. |
| E08 | Upgrade with new real hosts, saved views and prior configuration edits | Actual inventory/settings retained; tests derive expected inventory from verified snapshots instead of hardcoded sample counts. |
| E09 | Before/after baseline and cleanup on success/failure | Existing container/process identities, serving settings, security schedules, health and acquisition/firewall continuity preserved; all owned fixtures removed. |
| E10 | Read-only removal and future write-journal recovery | Stop/revoke adapter safely; any future incomplete operation has an explicit reconciled status, not a fabricated rollback success. |

## Evidence and release decision

An implementation release report should publish:

1. Exact source/package/image/protocol/runtime/API versions, verified provenance and tested client matrix.
2. Registry of implemented tools, endpoint permissions and safe output schemas; each unimplemented feature marked unsupported.
3. Per-test PASS/FAIL/NOT TESTED with minimal reproducible fixtures and independent expected truth.
4. Known limitations, proposed budgets versus measured capacity, data-egress policy and enterprise availability.
5. Before/after protection/serving evidence, owned-fixture cleanup and tested disable/recovery procedure.

Release phaseA only after its applicable gates pass. Remote HTTP, preparation, write execution and enterprise adapters have independent additional gates; a read-only release does not implicitly enable any of them. Maintainer agreement on this proposal is not a release, a deployment authorization or a production-readiness verdict.
