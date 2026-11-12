/**
 * Next.js instrumentation hook - runs once when the server starts
 * https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 *
 * Everything that writes at start-up, pushes configuration, runs on a timer
 * or works in the background is a job in SERVER_JOBS, started through
 * startBackgroundJobs() (src/lib/background-jobs.ts). In a high availability
 * cluster only the leader starts them; a standby starts none
 * (tests/unit/ha-background-jobs.test.ts keeps every job in the list). With
 * PostgreSQL replicas they run on the elected leader and are stopped (`stop`)
 * when it stops leading, so a job that keeps running needs a stop function.
 * A job that must also stop when the server stops registers that with
 * onShutdown (src/lib/shutdown.ts), never with process.on/once: a replica
 * starts its jobs again every time it leads, and a task registered again
 * under its name replaces the earlier one instead of adding a listener.
 */
import type { BackgroundJob } from "./lib/background-jobs";

/**
 * Start-up database tasks. Failures that leave secrets unprotected stop the
 * server in production, as before.
 */
async function runStartupDatabaseTasks() {
  const { ensureAdminUser } = await import("./lib/init-db");
  try {
    await ensureAdminUser();
    console.log("Database initialization complete");
  } catch (error) {
    console.error("Failed to initialize database:", error);
    // Don't throw - let the app start anyway, errors will surface when users try to use features
  }

  // Permissions that became administrator-level leave the roles that already held them, once.
  try {
    const { removeReclassifiedPermissions } = await import("../ee/custom-roles/reclassified");
    for (const role of await removeReclassifiedPermissions()) {
      console.warn(
        `Removed ${role.removed.join(", ")} from custom role ${JSON.stringify(role.name)}: it is administrator-level ` +
          "from this release on; an administrator can grant it again on the Users page"
      );
    }
  } catch (error) {
    console.error("Failed to review custom roles for administrator-level permissions:", error);
  }

  // Only reports: stored usernames are never changed on startup.
  const { findSignInUsernamesToReview } = await import("./lib/models/user");
  try {
    for (const { userId, username, reason } of await findSignInUsernamesToReview()) {
      console.warn(
        reason === "shared"
          ? `Sign-in username ${JSON.stringify(username)} of user ${userId} is also another account's username, ` +
            "email address or forward-auth portal name; give one of them a different username on the Users page"
          : `Sign-in username ${JSON.stringify(username)} of user ${userId} is an email address other than the ` +
            "account's own and can be somebody else's; check it on the Users page"
      );
    }
  } catch (error) {
    console.error("Failed to check sign-in usernames:", error);
  }

  // Imported keys and provider options could contain plaintext secrets in
  // older releases. Repair them before any request handler reads the rows.
  // Whether a migration below rewrote stored secrets, leaving their old
  // (plaintext) bytes behind for purgeDeletedDatabaseContent.
  let rewroteSecrets = false;
  const { migrateLegacyCertificateStorage } = await import("./lib/models/certificates");
  try {
    const migrated = await migrateLegacyCertificateStorage();
    rewroteSecrets ||= migrated > 0;
    if (migrated > 0) {
      console.log(`Hardened ${migrated} legacy certificate record(s)`);
    }
  } catch (error) {
    console.error("Failed to harden legacy certificate storage");
    if (process.env.NODE_ENV === "production") throw error;
  }

  const { migrateLegacyCaPrivateKeys } = await import("./lib/models/ca-certificates");
  try {
    const migrated = await migrateLegacyCaPrivateKeys();
    rewroteSecrets ||= migrated > 0;
    if (migrated > 0) {
      console.log(`Encrypted ${migrated} legacy CA private key(s)`);
    }
  } catch (error) {
    console.error("Failed to encrypt legacy CA private keys");
    if (process.env.NODE_ENV === "production") throw error;
  }

  // After a SESSION_SECRET rotation, re-encrypt stored secrets that only an
  // old key (SESSION_SECRET_PREVIOUS or a rejected placeholder) decrypts,
  // and encrypt DNS provider / Cloudflare credentials stored in plaintext, before
  // anything reads them to build the Caddy configuration.
  const { reencryptStoredSecrets } = await import("./lib/secret-rotation");
  try {
    const { reencrypted, encryptedPlaintext, failed, clearedOAuthTokens } = await reencryptStoredSecrets();
    rewroteSecrets ||= reencrypted > 0 || encryptedPlaintext > 0 || clearedOAuthTokens > 0;
    if (reencrypted > 0) {
      console.log(`Re-encrypted ${reencrypted} stored secret(s) with the current SESSION_SECRET`);
    }
    if (encryptedPlaintext > 0) {
      console.log(`Encrypted ${encryptedPlaintext} DNS provider credential(s) that were stored in plaintext`);
    }
    if (clearedOAuthTokens > 0) {
      console.log(
        `Cleared ${clearedOAuthTokens} stored OAuth sign-in token(s) that no key decrypts; ` +
        "Ingressi does not use them and the next OAuth sign-in stores new ones"
      );
    }
    if (failed > 0) {
      console.warn(
        `${failed} stored secret(s) listed above could not be decrypted with SESSION_SECRET or SESSION_SECRET_PREVIOUS; ` +
        "re-enter them in the UI or set SESSION_SECRET_PREVIOUS to the secret they were stored with"
      );
    }
  } catch (error) {
    // Values that were not re-encrypted still decrypt with the fallback keys.
    console.error("Failed to re-encrypt stored secrets:", error);
  }

  // secure_delete only covers what is deleted from now on; VACUUM drops the
  // old plaintext the migrations above (or earlier releases) left in the
  // database file.
  const { purgeDeletedDatabaseContent } = await import("./lib/db");
  if (await purgeDeletedDatabaseContent(rewroteSecrets)) {
    console.log("Vacuumed the database so deleted and replaced secrets no longer remain in it");
  }

  // WAF rule exclusions became records (migration 0043): give every rule id
  // in the older excluded_rule_ids lists one. Idempotent; the lists stay as
  // a mirror of the whole-scope records.
  const { importLegacyWafExclusionsNow } = await import("./lib/models/waf-exclusion-mirror");
  try {
    const imported = await importLegacyWafExclusionsNow();
    if (imported > 0) console.log(`Recorded ${imported} WAF rule exclusion(s) from the excluded rule lists`);
  } catch (error) {
    // The lists still apply on their own (buildWafHandler reads them too).
    console.error("Failed to record WAF rule exclusions from the excluded rule lists:", error);
  }
}

/** The intervals the jobs below start themselves, so their stop functions can clear them. */
const jobTimers: {
  logParser?: ReturnType<typeof setInterval>;
  wafLogParser?: ReturnType<typeof setInterval>;
  instanceSync?: ReturnType<typeof setInterval>;
  stopAuditJobs?: () => void;
  stopMonetizationJobs?: () => void;
} = {};

/** Every start-up task and background job of the server, in start order. Leader-only in a cluster. */
const SERVER_JOBS: readonly BackgroundJob[] = [
  { name: "start-up database tasks", critical: true, start: runStartupDatabaseTasks },

  // High availability (ee/high-availability/cluster): a new leader records
  // in the audit log that it took over, and from what.
  {
    name: "high availability leadership record",
    start: async () => {
      const { recordLeadership } = await import("../ee/high-availability/cluster/audit");
      await recordLeadership();
    },
  },

  // Apply Caddy configuration from database on startup
  {
    name: "Caddy configuration",
    start: async () => {
      const { applyCaddyConfig } = await import("./lib/caddy");
      try {
        console.log("Applying Caddy configuration from database...");
        await applyCaddyConfig();
        console.log("Caddy configuration applied successfully");
      } catch (error) {
        console.error("Failed to apply Caddy configuration on startup:", error);
        // Don't throw: Caddy may still be starting (e.g. both updated at once). The Caddy
        // monitor applies again once Caddy answers (src/lib/caddy-monitor.ts).
      }
    },
  },

  // API monetization (ee/monetization): load the gate's in-memory index and
  // write metered usage every few seconds and when the process exits.
  {
    name: "API monetization metering",
    skipInTests: true,
    start: async () => {
      const { startMonetizationEngine } = await import("../ee/monetization/engine");
      await startMonetizationEngine();
    },
    stop: async () => {
      const { stopMonetizationEngine } = await import("../ee/monetization/engine");
      await stopMonetizationEngine();
    },
  },

  // API monetization (ee/monetization/jobs.ts): postpaid charges, reconciling
  // charges whose outcome is unknown, usage history retention. Leader only.
  {
    name: "API monetization billing and retention",
    skipInTests: true,
    start: async () => {
      const { startMonetizationJobs } = await import("../ee/monetization/jobs");
      jobTimers.stopMonetizationJobs?.();
      jobTimers.stopMonetizationJobs = startMonetizationJobs();
    },
    stop: () => {
      jobTimers.stopMonetizationJobs?.();
      jobTimers.stopMonetizationJobs = undefined;
    },
  },

  // Start Caddy health monitoring to detect restarts and auto-reapply config
  {
    name: "Caddy health monitoring",
    start: async () => {
      const { startCaddyMonitoring } = await import("./lib/caddy-monitor");
      startCaddyMonitoring();
      console.log("Caddy health monitoring started");
    },
    stop: async () => {
      const { stopCaddyMonitoring } = await import("./lib/caddy-monitor");
      stopCaddyMonitoring();
    },
  },

  // Initialize ClickHouse analytics database
  {
    name: "ClickHouse analytics",
    start: async () => {
      const { initClickHouse } = await import("./lib/clickhouse/client");
      // ClickHouse may still be starting (e.g. updated at the same moment): retry in the
      // background, 5 s after the first failure, doubling up to 5 minutes, until it works.
      // Never throws: analytics is non-critical.
      let delay = 5_000;
      const attempt = async (): Promise<void> => {
        try {
          await initClickHouse();
          console.log("ClickHouse analytics initialized");
        } catch (error) {
          console.error(`Failed to initialize ClickHouse (retrying in ${delay / 1000}s):`, error);
          setTimeout(() => void attempt(), delay).unref?.();
          delay = Math.min(delay * 2, 300_000);
        }
      };
      await attempt();
    },
  },

  // Start log parser for analytics
  {
    name: "log parser",
    start: async () => {
      const { closeClickHouse } = await import("./lib/clickhouse/client");
      const { initLogParser, parseNewLogEntries, stopLogParser } = await import("./lib/log-parser");
      const { onShutdown } = await import("./lib/shutdown");
      await initLogParser();
      clearInterval(jobTimers.logParser);
      jobTimers.logParser = setInterval(() => void (async () => {
        try {
          await parseNewLogEntries();
        } catch (err) {
          console.error("Log parser interval error:", err);
        }
      })(), 30_000);
      // One task per name, however often this replica leads (src/lib/shutdown.ts).
      onShutdown("stopping the log parser", async () => {
        stopLogParser();
        clearInterval(jobTimers.logParser);
        await closeClickHouse();
      });
      console.log("Log parser started");
    },
    // Only the interval: stopLogParser() is for shutdown (the parser never runs again).
    stop: () => {
      clearInterval(jobTimers.logParser);
      jobTimers.logParser = undefined;
    },
  },

  // Start WAF log parser for WAF event tracking
  {
    name: "WAF log parser",
    start: async () => {
      const { initWafLogParser, parseNewWafLogEntries, stopWafLogParser } = await import("./lib/waf-log-parser");
      const { onShutdown } = await import("./lib/shutdown");
      await initWafLogParser();
      clearInterval(jobTimers.wafLogParser);
      jobTimers.wafLogParser = setInterval(() => void (async () => {
        try {
          await parseNewWafLogEntries();
        } catch (err) {
          console.error("WAF log parser interval error:", err);
        }
      })(), 30_000);
      onShutdown("stopping the WAF log parser", () => {
        stopWafLogParser();
        clearInterval(jobTimers.wafLogParser);
      });
      console.log("WAF log parser started");
    },
    stop: () => {
      clearInterval(jobTimers.wafLogParser);
      jobTimers.wafLogParser = undefined;
    },
  },

  // Audit streaming to configured sinks and the daily audit log retention
  // run (ee/audit).
  {
    name: "audit streaming and retention jobs",
    skipInTests: true,
    start: async () => {
      const { startAuditBackgroundJobs } = await import("@/ee/audit/worker");
      const { onShutdown } = await import("./lib/shutdown");
      jobTimers.stopAuditJobs?.();
      jobTimers.stopAuditJobs = startAuditBackgroundJobs();
      onShutdown("stopping audit streaming and retention", () => jobTimers.stopAuditJobs?.());
      console.log("Audit streaming and retention jobs started");
    },
    stop: () => {
      jobTimers.stopAuditJobs?.();
      jobTimers.stopAuditJobs = undefined;
    },
  },

  // Start periodic instance sync if configured (master mode only)
  {
    name: "periodic instance sync",
    start: async () => {
      const { getInstanceMode, getSyncIntervalMs, runPeriodicInstanceSync } = await import("./lib/instance-sync");
      const mode = await getInstanceMode();
      const intervalMs = getSyncIntervalMs();

      if (mode === "master" && intervalMs > 0) {
        console.log(`Starting periodic instance sync (every ${intervalMs / 1000}s)`);
        clearInterval(jobTimers.instanceSync);
        jobTimers.instanceSync = setInterval(() => void (async () => {
          try {
            const result = await runPeriodicInstanceSync();
            if (result === null) {
              console.warn("Periodic sync skipped: the previous sync is still running");
            } else if (result.total > 0) {
              console.log(`Periodic sync completed: ${result.success}/${result.total} succeeded`);
            }
          } catch (error) {
            console.error("Periodic sync failed:", error);
          }
        })(), intervalMs);
      }
    },
    stop: () => {
      clearInterval(jobTimers.instanceSync);
      jobTimers.instanceSync = undefined;
    },
  },

  // Pull replicas (ee/fleet): a slave with INSTANCE_SYNC_MODE=pull polls its
  // master instead of waiting for pushes.
  {
    name: "pull replica agent",
    skipInTests: true,
    start: async () => {
      const { startPullAgent } = await import("../ee/fleet/pull-agent");
      if (startPullAgent()) console.log("Pull replica: polling the master for configuration");
    },
    stop: async () => {
      const { stopPullAgent } = await import("../ee/fleet/pull-agent");
      stopPullAgent();
    },
  },

  // Alert evaluation (ee/alerting): every minute, on the node where the
  // rules are configured (they are not synced to slaves).
  {
    name: "alert evaluator",
    skipInTests: true,
    start: async () => {
      const { startAlertEvaluator } = await import("../ee/alerting/scheduler");
      startAlertEvaluator();
      console.log("Alert evaluator started");
    },
    stop: async () => {
      const { stopAlertEvaluator } = await import("../ee/alerting/scheduler");
      stopAlertEvaluator();
    },
  },

  // Scheduled configuration backups (ee/backups): every minute, due
  // destinations upload an encrypted export to S3-compatible storage. They
  // are not synced to slaves.
  {
    name: "backup scheduler",
    skipInTests: true,
    start: async () => {
      const { startBackupScheduler } = await import("../ee/backups/scheduler");
      startBackupScheduler();
      console.log("Backup scheduler started");
    },
    stop: async () => {
      const { stopBackupScheduler } = await import("../ee/backups/scheduler");
      stopBackupScheduler();
    },
  },

  // Change approvals (ee/approvals): every minute, approved changes to
  // protected hosts are applied when their change windows open and stale
  // requests expire, on the node where the policies are configured (not
  // synced to slaves).
  {
    name: "change approval scheduler",
    skipInTests: true,
    start: async () => {
      const { startApprovalScheduler } = await import("../ee/approvals/scheduler");
      startApprovalScheduler();
      console.log("Change approval scheduler started");
    },
    stop: async () => {
      const { stopApprovalScheduler } = await import("../ee/approvals/scheduler");
      stopApprovalScheduler();
    },
  },

  // Access list rules with an expiry (blocked sources added for a while):
  // removed when they expire, every minute.
  {
    name: "access list expiry job",
    skipInTests: true,
    start: async () => {
      const { startAccessListExpiry } = await import("./lib/access-list-expiry");
      startAccessListExpiry();
      console.log("Access list expiry job started");
    },
    stop: async () => {
      const { stopAccessListExpiry } = await import("./lib/access-list-expiry");
      stopAccessListExpiry();
    },
  },

  // Recurring access reviews (ee/access-reviews): due schedules start a
  // campaign. Master-only data (not synced).
  {
    name: "access review scheduler",
    skipInTests: true,
    start: async () => {
      const { startAccessReviewScheduler } = await import("../ee/access-reviews/scheduler");
      startAccessReviewScheduler();
      console.log("Access review scheduler started");
    },
    stop: async () => {
      const { stopAccessReviewScheduler } = await import("../ee/access-reviews/scheduler");
      stopAccessReviewScheduler();
    },
  },

  // Fleet management (ee/fleet): rollout steps and drift checks, on the
  // master.
  {
    name: "fleet scheduler",
    skipInTests: true,
    start: async () => {
      const { startFleetScheduler } = await import("../ee/fleet/scheduler");
      startFleetScheduler();
      console.log("Fleet scheduler started");
    },
    stop: async () => {
      const { stopFleetScheduler } = await import("../ee/fleet/scheduler");
      stopFleetScheduler();
    },
  },

  // LDAP directory health (ee/ldap): every 5 minutes each enabled
  // directory is connected to, bound with its service account and its user
  // search base read.
  {
    name: "directory health checks",
    skipInTests: true,
    start: async () => {
      const { startDirectoryHealthChecks } = await import("../ee/ldap/health");
      startDirectoryHealthChecks();
      console.log("Directory health checks started");
    },
    stop: async () => {
      const { stopDirectoryHealthChecks } = await import("../ee/ldap/health");
      stopDirectoryHealthChecks();
    },
  },

  // Scheduled compliance evidence reports (ee/compliance): due schedules
  // generate their reports. Master-local data (not synced).
  {
    name: "compliance report scheduler",
    skipInTests: true,
    start: async () => {
      const { startReportScheduler } = await import("../ee/compliance/scheduler");
      startReportScheduler();
      console.log("Compliance report scheduler started");
    },
    stop: async () => {
      const { stopReportScheduler } = await import("../ee/compliance/scheduler");
      stopReportScheduler();
    },
  },

  // Daily security digest (ee/ai): checked every minute, sent once a day
  // from the node where it is configured (not synced to slaves).
  {
    name: "daily digest scheduler",
    skipInTests: true,
    start: async () => {
      const { startDigestScheduler } = await import("../ee/ai/digest-scheduler");
      startDigestScheduler();
      console.log("Daily digest scheduler started");
    },
    stop: async () => {
      const { stopDigestScheduler } = await import("../ee/ai/digest-scheduler");
      stopDigestScheduler();
    },
  },

  // High availability shared state (ee/high-availability/shared-state): the
  // leader writes the API balances and credits the nodes counted in Redis or
  // Valkey back to the ledger. Does nothing while shared state is off.
  {
    name: "shared state write-back",
    skipInTests: true,
    start: async () => {
      const { startSharedStateDrain } = await import("../ee/high-availability/shared-state/workers");
      startSharedStateDrain();
    },
    stop: async () => {
      const { stopSharedStateDrain } = await import("../ee/high-availability/shared-state/workers");
      stopSharedStateDrain();
    },
  },
  // Expired rate limiter counters and short-lived entries (src/lib/shared-runtime-state.ts).
  {
    name: "shared runtime state pruning",
    skipInTests: true,
    start: async () => (await import("./lib/shared-runtime-state")).startSharedRuntimeStatePrune(),
    stop: async () => (await import("./lib/shared-runtime-state")).stopSharedRuntimeStatePrune(),
  },
];

/**
 * Jobs every node runs, standbys included: they serve the request-path
 * routes from shared state and never write to the database.
 */
const EVERY_NODE_JOBS: readonly BackgroundJob[] = [
  // Shared state decides which node writes balances back with the cluster's
  // own leader rule (a standby or a leader whose lease lapsed never does),
  // and stays off on sync slaves as before.
  {
    name: "shared state leader check",
    start: async () => {
      const { setSharedStateLeaderCheck } = await import("../ee/high-availability/shared-state/leader");
      const { mayRunBackgroundJobs } = await import("./lib/background-jobs");
      const { getInstanceMode } = await import("./lib/instance-sync");
      setSharedStateLeaderCheck(async () => mayRunBackgroundJobs() && (await getInstanceMode()) !== "slave");
    },
  },

  // Reports gate charges and keeps every node's copy of the gate's
  // configuration current when another node announces a change.
  {
    name: "shared state node worker",
    skipInTests: true,
    start: async () => {
      const { startSharedStateNodeWorker } = await import("../ee/high-availability/shared-state/workers");
      startSharedStateNodeWorker();
    },
  },
];

export async function register() {
  // Only run on the server side
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  try {
    await startServer();
  } catch (error) {
    if (process.env.NODE_ENV !== "production") throw error;
    // Next.js catches an error thrown here and keeps the server running,
    // answering every request with 500 while the container looks healthy to
    // `docker compose up`. Exit instead, so the container restarts and
    // `docker compose ps` and the logs show why.
    console.error("Ingressi could not start:", error);
    process.exit(1);
  }
}

async function startServer() {
  // Stopping (SIGTERM, SIGINT): the image leaves the signals to the
  // application (NEXT_MANUAL_SIG_HANDLE), which exits once the shutdown
  // tasks finished (src/lib/shutdown.ts). Installed first, so the server
  // exits on a signal however far start-up got.
  const { installShutdownHandler } = await import("./lib/shutdown");
  installShutdownHandler();

  // Validate production configuration early to catch misconfigurations
  const { validateProductionConfig } = await import("./lib/config");
  try {
    validateProductionConfig();
  } catch (error) {
    // Fail fast in production with bad config (register() exits)
    if (process.env.NODE_ENV === "production") throw error;
    console.error("Configuration validation failed:", error);
  }

  // High availability (ee/docs/high-availability.md): a leader exits as
  // soon as its lease can no longer be vouched for; a standby starts none
  // of the jobs above.
  const { startLeaderWatchdog } = await import("../ee/high-availability/role");
  startLeaderWatchdog();

  // The database before anything uses it: schema migrations, then the
  // one-time data migrations (src/lib/db/startup.ts). Every node runs it;
  // a standby's read-only copy skips the data migrations.
  const { runDatabaseStartup } = await import("./lib/db/startup");
  await runDatabaseStartup();

  // What requests read without waiting for the database (the branding, the
  // providers Better Auth is built with): loaded here, then read again by
  // the code that changes it (src/lib/db/cached-value.ts).
  const { loadStartupCaches } = await import("./lib/startup-caches");
  await loadStartupCaches();

  const { startBackgroundJobs, startEveryNodeJobs } = await import("./lib/background-jobs");
  await startEveryNodeJobs(EVERY_NODE_JOBS);
  await startBackgroundJobs(SERVER_JOBS);
}
