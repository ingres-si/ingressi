/**
 * The PostgreSQL width of every integer column of schema.sqlite.ts (boolean
 * columns excepted), by table and column name as they are in the database.
 *
 * SQLite stores any integer in up to 8 bytes; PostgreSQL's `integer` (int4)
 * stops at 2,147,483,647. scripts/db/generate-pg-schema.ts emits `integer`
 * for "int4" and `bigint({ mode: "number" })` (int8, read as a JavaScript
 * number, exact up to 2^53 - 1) for "int8". Use int8 for money, byte sizes,
 * sequences and counters that only grow, and for anything a third party
 * defines as larger than a signed 32-bit number; ids and bounded settings stay
 * int4. tests/unit/db-schema-generated.test.ts fails while a column is
 * missing here, so a new integer column must be classified before it ships.
 */
export type PgIntegerType = "int4" | "int8";

export const PG_INTEGER_COLUMNS: Readonly<Record<string, Readonly<Record<string, PgIntegerType>>>> = {
  users: { id: "int4", customRoleId: "int4" },
  sign_in_sources: { lastUserId: "int4" },
  sessions: { id: "int4", userId: "int4" },
  accounts: { id: "int4", userId: "int4" },
  verifications: { id: "int4" },
  oauth_states: { id: "int4" },
  pending_oauth_links: { id: "int4", userId: "int4" },
  instances: { id: "int4" },
  access_lists: { id: "int4", createdBy: "int4", denyStatus: "int4" },
  access_list_entries: { id: "int4", accessListId: "int4" },
  certificates: { id: "int4", createdBy: "int4" },
  ca_certificates: { id: "int4", createdBy: "int4" },
  issued_client_certificates: { id: "int4", caCertificateId: "int4", createdBy: "int4" },
  proxy_hosts: {
    id: "int4",
    certificateId: "int4",
    accessListId: "int4",
    ownerUserId: "int4",
  },
  api_tokens: { id: "int4", createdBy: "int4" },
  mcp_oauth_consents: { id: "int4", userId: "int4" },
  mcp_oauth_codes: { id: "int4", userId: "int4" },
  mcp_oauth_tokens: { id: "int4", userId: "int4" },
  audit_events: {
    id: "int4",
    userId: "int4",
    entityId: "int4",
    configBeforeId: "int4",
    configAfterId: "int4",
    changeRequestId: "int4",
  },
  mtls_roles: { id: "int4", createdBy: "int4" },
  mtls_certificate_roles: { id: "int4", issuedClientCertificateId: "int4", mtlsRoleId: "int4" },
  mtls_access_rules: { id: "int4", proxyHostId: "int4", priority: "int4", createdBy: "int4" },
  groups: { id: "int4", createdBy: "int4" },
  group_members: { id: "int4", groupId: "int4", userId: "int4" },
  forward_auth_access: { id: "int4", proxyHostId: "int4", userId: "int4", groupId: "int4" },
  forward_auth_sessions: { id: "int4", userId: "int4", proxyHostId: "int4" },
  forward_auth_exchanges: { id: "int4", sessionId: "int4", proxyHostId: "int4" },
  forward_auth_redirect_intents: { id: "int4", proxyHostId: "int4" },
  l4_proxy_hosts: { id: "int4", ownerUserId: "int4" },
  // lastDeliveredId is an audit_events.id.
  audit_sinks: { id: "int4", lastDeliveredId: "int4", consecutiveFailures: "int4" },
  config_snapshots: { id: "int4", userId: "int4", sizeBytes: "int8", previousId: "int4" },
  alert_channels: { id: "int4" },
  alert_rules: { id: "int4", cooldownMinutes: "int4", forMinutes: "int4" },
  alert_rule_states: { id: "int4", ruleId: "int4" },
  alert_events: { id: "int4", ruleId: "int4" },
  alert_silences: { id: "int4", ruleId: "int4", createdBy: "int4" },
  backup_destinations: { id: "int4", retention: "int4", consecutiveFailures: "int4" },
  backup_runs: { id: "int4", destinationId: "int4", sizeBytes: "int8", prunedCount: "int4" },
  // WAF rule ids stay below 2^31 (src/lib/waf-exclusions.ts).
  waf_tuning_suggestions: { ruleId: "int4", proxyHostId: "int4", score: "int4", decidedBy: "int4" },
  two_factors: { id: "int4", userId: "int4", failedVerificationCount: "int4" },
  custom_roles: { id: "int4", createdBy: "int4" },
  // Amounts are micro-units (up to 10^13, ee/monetization/money.ts).
  // includedRequestsPerMonth is at most 10^9 (ee/monetization/plans.ts), and
  // freeUsageCount never exceeds it.
  monetization_plans: {
    id: "int4",
    pricePerRequestMicros: "int8",
    includedRequestsPerMonth: "int4",
    requestsPerMinute: "int4",
    postpaidCapMicros: "int8",
    postpaidThresholdMicros: "int8",
  },
  // cardExpMonth (1-12) and cardExpYear (four digits) are Stripe's card expiry.
  monetization_consumers: {
    id: "int4",
    planId: "int4",
    balanceMicros: "int8",
    overdraftAllowanceMicros: "int8",
    freeUsageCount: "int4",
    cardExpMonth: "int4",
    cardExpYear: "int4",
    createdBy: "int4",
  },
  monetization_keys: { id: "int4", consumerId: "int4" },
  // requests and freeRequests are counters that each flush adds to.
  monetization_ledger: {
    id: "int4",
    consumerId: "int4",
    amountMicros: "int8",
    balanceAfterMicros: "int8",
    requests: "int8",
    freeRequests: "int8",
    createdBy: "int4",
  },
  // x402 prices are US cents (a host's price per request).
  monetization_hosts: {
    proxyHostId: "int4",
    x402PriceCents: "int4",
  },
  approval_policies: { id: "int4", requiredApprovals: "int4", requestTtlHours: "int4", createdBy: "int4" },
  compliance_reports: { id: "int4", generatedBy: "int4", sizeBytes: "int8", scheduleId: "int4" },
  change_requests: {
    id: "int4",
    targetId: "int4",
    requiredApprovals: "int4",
    requestedBy: "int4",
    emergencyBy: "int4",
    appliedBy: "int4",
  },
  change_request_reviews: { id: "int4", requestId: "int4", userId: "int4" },
  compliance_incidents: {
    id: "int4",
    alertEventId: "int4",
    createdBy: "int4",
    updatedBy: "int4",
    classifiedBy: "int4",
  },
  ldap_directories: { id: "int4", connectTimeoutMs: "int4", operationTimeoutMs: "int4", createdBy: "int4" },
  scim_tokens: { id: "int4", createdBy: "int4" },
  scim_users: { id: "int4", userId: "int4", createdByTokenId: "int4" },
  scim_groups: { id: "int4", groupId: "int4", createdByTokenId: "int4" },
  scim_group_members: { id: "int4", groupId: "int4", userId: "int4" },
  scim_role_mappings: { id: "int4", groupId: "int4", customRoleId: "int4", priority: "int4" },
  access_review_campaigns: { id: "int4", scheduleId: "int4", createdBy: "int4" },
  access_review_items: {
    id: "int4",
    campaignId: "int4",
    subjectUserId: "int4",
    targetId: "int4",
    decidedBy: "int4",
  },
  access_review_schedules: {
    id: "int4",
    durationDays: "int4",
    intervalMonths: "int4",
    lastCampaignId: "int4",
    createdBy: "int4",
  },
  fleet_environments: { id: "int4", position: "int4", revisionId: "int4", canaryWaitSeconds: "int4" },
  fleet_instances: { instanceId: "int4", environmentId: "int4", revisionId: "int4" },
  fleet_revisions: { id: "int4", createdBy: "int4", sizeBytes: "int8" },
  fleet_rollouts: {
    id: "int4",
    environmentId: "int4",
    revisionId: "int4",
    fromRevisionId: "int4",
    sourceEnvironmentId: "int4",
    rollbackOfId: "int4",
    canaryInstanceId: "int4",
    canaryWaitSeconds: "int4",
    startedBy: "int4",
  },
  fleet_rollout_targets: { id: "int4", rolloutId: "int4", instanceId: "int4" },
  fleet_pull_replicas: {
    instanceId: "int4",
    pollIntervalSeconds: "int4",
    deliveredRevisionId: "int4",
    resyncRevisionId: "int4",
  },
  saml_providers: { id: "int4", createdBy: "int4" },
  saml_group_roles: { id: "int4", providerId: "int4" },
  saml_requests: { id: "int4", providerId: "int4" },
  saml_used_assertions: { id: "int4", providerId: "int4" },
  analytics_saved_views: { id: "int4", userId: "int4" },
  waf_rule_exclusions: { id: "int4", ruleId: "int4", proxyHostId: "int4", createdBy: "int4" },
  access_list_rules: { id: "int4", accessListId: "int4", position: "int4", createdBy: "int4" },
  // A WebAuthn signature counter is an unsigned 32-bit number.
  passkeys: { id: "int4", userId: "int4", counter: "int8" },
  user_preferences: { userId: "int4" },
  ldap_directory_health: { directoryId: "int4", consecutiveFailures: "int4" },
  compliance_report_schedules: { id: "int4", dayOfMonth: "int4", createdBy: "int4" },
  compliance_restore_tests: { id: "int4", backupDestinationId: "int4", recordedBy: "int4" },
  analytics_questions: { id: "int4", userId: "int4" },
  // Any safe integer the feed publishes (ee/rule-feed/feed.ts).
  // Totals of a usage epoch, which lasts as long as the shared counters do.
  monetization_shared_cursors: {
    consumerId: "int4",
    chargedMicros: "int8",
    requests: "int8",
    freeRequests: "int8",
  },
  monetization_shared_credits: { consumerId: "int4", ledgerId: "int4" },
  monetization_payments: {
    id: "int4",
    consumerId: "int4",
    amountMicros: "int8",
    refundedMicros: "int8",
    disputedMicros: "int8",
    ledgerId: "int4",
  },
  monetization_answer_credits: { consumerId: "int4", amountMicros: "int8" },
  // recordAttempts: Stripe refusals of one payment, at most X402_RECORD_ATTEMPTS.
  monetization_x402_payments: { id: "int4", proxyHostId: "int4", consumerId: "int4", amountMicros: "int8", recordAttempts: "int4" },
  // Times in milliseconds since the epoch; attempts and held stay below a limiter's maxAttempts.
  rate_limit_counters: {
    attempts: "int4",
    windowStartMs: "int8",
    blockedUntilMs: "int8",
    held: "int4",
    heldUntilMs: "int8",
    expiresAtMs: "int8",
  },
  // A new row per client address and path: the id grows quickly. lastRequest is in milliseconds.
  auth_rate_limits: { id: "int8", count: "int4", lastRequest: "int8" },
};

/** The PostgreSQL width of an integer column, or undefined when it is not classified. */
export function pgIntegerType(table: string, column: string): PgIntegerType | undefined {
  return Object.hasOwn(PG_INTEGER_COLUMNS, table) && Object.hasOwn(PG_INTEGER_COLUMNS[table], column)
    ? PG_INTEGER_COLUMNS[table][column]
    : undefined;
}
