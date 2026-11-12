#!/bin/sh
#
# L4 Port Manager Sidecar
#
# On startup: makes sure the caddy container has the L4 ports bound (the main
# compose stack starts caddy without the L4 ports override file). Caddy is only
# recreated when it is not running with every port of the override, so a
# restart or an image update of this sidecar does not restart caddy as well.
#
# During runtime: watches the trigger file for changes and re-applies when
# the web app signals that port configuration has changed.
#
# Only ever recreates the caddy container — never touches any other service.
#
# Environment variables:
#   DATA_DIR              - Path to shared data volume (default: /data)
#   COMPOSE_DIR           - Path to compose files (default: /compose)
#   CADDY_CONTAINER_NAME  - Caddy container name (default: ingressi-caddy, then the "caddy" service of this
#                           sidecar's compose project, then the pre-rename caddy-proxy-manager-caddy)
#   COMPOSE_PROJECT_NAME  - Override compose project name (auto-detected from caddy container labels if unset)
#   COMPOSE_HOST_DIR      - Only for non-standard bind-mount deployments: host
#                           path passed as --project-directory so relative
#                           bind-mount paths resolve on the host. The official
#                           named-volume setup must leave this unset.
#   POLL_INTERVAL         - Seconds between trigger file checks (default: 2)
#   COMPOSE_SKIP_OVERRIDE - If non-empty, skip docker-compose.override.yml (useful in test environments)
#   COMPOSE_EXTRA_FILE    - If set, include this additional compose file (e.g. a test-specific override)
#   APPLY_LOCK_MAX_AGE    - Seconds after which an apply lock is considered stale (default: 10)
#   CADDY_STARTUP_WAIT    - Seconds to wait at startup for a stopped caddy container to come back, e.g.
#                           while an image updater recreates it, before recreating it here (default: 60)

set -e

DATA_DIR="${DATA_DIR:-/data}"
COMPOSE_DIR="${COMPOSE_DIR:-/compose}"
POLL_INTERVAL="${POLL_INTERVAL:-2}"
CADDY_CONTAINER_NAME="${CADDY_CONTAINER_NAME:-ingressi-caddy}"
# Container name of caddy in compose files from before the rename to Ingressi.
LEGACY_CADDY_CONTAINER_NAME="caddy-proxy-manager-caddy"

TRIGGER_FILE="$DATA_DIR/l4-ports.trigger"
STATUS_FILE="$DATA_DIR/l4-ports.status"
OVERRIDE_FILE="$DATA_DIR/docker-compose.l4-ports.yml"

log() {
  echo "[l4-port-manager] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

write_status() {
  state="$1"
  message="$2"
  applied_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  error="${3:-}"

  cat > "$STATUS_FILE" <<STATUSEOF
{
  "state": "$state",
  "message": "$message",
  "appliedAt": "$applied_at"$([ -n "$error" ] && echo ",
  \"error\": \"$error\"" || echo "")
}
STATUSEOF
}

# The caddy container's name: CADDY_CONTAINER_NAME when it exists, else the
# "caddy" service of this sidecar's own compose project (whatever container_name
# an override gives it), else the pre-rename name (compose files from before the
# rename).
caddy_container() {
  if docker inspect "$CADDY_CONTAINER_NAME" >/dev/null 2>&1; then
    echo "$CADDY_CONTAINER_NAME"
    return
  fi
  OWN_PROJECT=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$(hostname)" 2>/dev/null || echo "")
  if [ -n "$OWN_PROJECT" ]; then
    BY_LABEL=$(docker ps -a --filter "label=com.docker.compose.project=$OWN_PROJECT" --filter "label=com.docker.compose.service=caddy" --format '{{.Names}}' 2>/dev/null | head -n 1)
    if [ -n "$BY_LABEL" ]; then
      echo "$BY_LABEL"
      return
    fi
  fi
  if docker inspect "$LEGACY_CADDY_CONTAINER_NAME" >/dev/null 2>&1; then
    echo "$LEGACY_CADDY_CONTAINER_NAME"
  else
    echo "$CADDY_CONTAINER_NAME"
  fi
}

# Auto-detect the Docker Compose project name from the running caddy container's labels.
# This ensures we operate on the correct project regardless of where compose files are mounted.
detect_project_name() {
  if [ -n "$COMPOSE_PROJECT_NAME" ]; then
    echo "$COMPOSE_PROJECT_NAME"
    return
  fi
  detected=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$(caddy_container)" 2>/dev/null || echo "")
  if [ -n "$detected" ]; then
    echo "$detected"
  else
    # The directory the repository is cloned into by default.
    echo "caddy-proxy-manager"
  fi
}

APPLY_LOCK="$DATA_DIR/.l4-apply.lock"
APPLY_LOCK_MAX_AGE="${APPLY_LOCK_MAX_AGE:-10}"
CADDY_STARTUP_WAIT="${CADDY_STARTUP_WAIT:-60}"

caddy_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$(caddy_container)" 2>/dev/null)" = "true" ]
}

# True when caddy runs and publishes every port of the override file. Port
# entries are list items like - "7881:7881" or - "7882:7882/udp"; anything this
# cannot read counts as not bound, so caddy is recreated as before.
ports_bound() {
  caddy_running || return 1
  ENTRIES=$(grep -cE '^[[:space:]]*-[[:space:]]' "$OVERRIDE_FILE" 2>/dev/null || true)
  WANTED=$(sed -n 's/^[[:space:]]*-[[:space:]]*"\{0,1\}[0-9]\{1,5\}:\([0-9]\{1,5\}\(\/[a-z]\{3\}\)\{0,1\}\)"\{0,1\}[[:space:]]*$/\1/p' "$OVERRIDE_FILE")
  [ -n "$WANTED" ] || return 1
  [ "$(echo "$WANTED" | wc -l | tr -d ' ')" = "${ENTRIES:-0}" ] || return 1
  BOUND=" $(docker inspect --format '{{range $p, $b := .HostConfig.PortBindings}}{{$p}} {{end}}' "$(caddy_container)" 2>/dev/null) "
  for PORT in $WANTED; do
    case "$PORT" in */*) ;; *) PORT="$PORT/tcp" ;; esac
    case "$BOUND" in *" $PORT "*) ;; *) return 1 ;; esac
  done
  return 0
}

# Never let a failed apply leave the lock behind or kill the poll loop.
# The lock must only exist while an apply is genuinely in progress.
trap 'rm -f "$APPLY_LOCK"' EXIT INT TERM

# Apply the current port override — recreates only the caddy container.
do_apply() {
  # Record timestamp so startup can detect an in-progress apply.
  date +%s > "$APPLY_LOCK"

  # The trigger this apply answers, read before compose reads the override
  # file: a trigger written later than this may ask for ports this apply did
  # not see, and must stay for the poll loop (see the end of this function).
  APPLY_TRIGGER=$(cat "$TRIGGER_FILE" 2>/dev/null || echo "")

  COMPOSE_PROJECT="$(detect_project_name)"
  log "Using compose project: $COMPOSE_PROJECT"

  # Build compose args. Files are read from COMPOSE_DIR (container path).
  # COMPOSE_HOST_DIR (when set) is passed as --project-directory so the Docker
  # daemon resolves relative bind-mount paths (e.g. ./geoip-data) against the
  # actual host project directory rather than the sidecar's /compose mount.
  # NOTE: only relevant for non-standard bind-mount deployments. The official
  # named-volume setup has no relative paths to resolve and must leave this
  # unset.
  COMPOSE_ARGS="-p $COMPOSE_PROJECT"
  if [ -n "$COMPOSE_HOST_DIR" ]; then
    COMPOSE_ARGS="$COMPOSE_ARGS --project-directory $COMPOSE_HOST_DIR"
  fi
  # Explicitly supply the .env file so required variables are available even
  # when --project-directory points to a host path not mounted in the sidecar.
  if [ -f "$COMPOSE_DIR/.env" ]; then
    COMPOSE_ARGS="$COMPOSE_ARGS --env-file $COMPOSE_DIR/.env"
  fi
  COMPOSE_ARGS="$COMPOSE_ARGS -f $COMPOSE_DIR/docker-compose.yml"
  if [ -z "$COMPOSE_SKIP_OVERRIDE" ] && [ -f "$COMPOSE_DIR/docker-compose.override.yml" ]; then
    COMPOSE_ARGS="$COMPOSE_ARGS -f $COMPOSE_DIR/docker-compose.override.yml"
  fi
  if [ -n "$COMPOSE_EXTRA_FILE" ] && [ -f "$COMPOSE_EXTRA_FILE" ]; then
    COMPOSE_ARGS="$COMPOSE_ARGS -f $COMPOSE_EXTRA_FILE"
  fi
  if [ -f "$OVERRIDE_FILE" ]; then
    COMPOSE_ARGS="$COMPOSE_ARGS -f $OVERRIDE_FILE"
  fi

  write_status "applying" "Recreating caddy container with updated ports..."

  # Capture the compose result without letting `set -e` abort the script on
  # failure. The old form (`COMPOSE_OUTPUT=$(...); COMPOSE_EXIT=$?`) killed the
  # sidecar on the first compose error — before the failure was logged, before
  # a "failed" status was written, and before the apply lock was removed. That
  # left a stale lock which made every subsequent startup skip the restore,
  # so caddy came back up WITHOUT the L4 ports bound and voice/video traffic
  # silently broke until someone re-applied by hand.
  COMPOSE_OUTPUT=""
  COMPOSE_EXIT=0
  # shellcheck disable=SC2086
  # NOTE: do NOT write `if ! VAR=$(cmd); then EXIT=$?; fi` — inside the negated
  # if, $? is the *inverted* status (0 on failure), so the failure is never seen.
  if COMPOSE_OUTPUT=$(docker compose $COMPOSE_ARGS up -d --no-deps --pull never --force-recreate caddy 2>&1); then
    COMPOSE_EXIT=0
  else
    COMPOSE_EXIT=$?
  fi
  log "$COMPOSE_OUTPUT"
  if [ $COMPOSE_EXIT -eq 0 ]; then
    log "Caddy container recreated successfully."

    # Wait for caddy healthcheck to pass
    HEALTH_TIMEOUT=30
    HEALTH_WAITED=0
    HEALTH="unknown"
    while [ "$HEALTH_WAITED" -lt "$HEALTH_TIMEOUT" ]; do
      HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$(caddy_container)" 2>/dev/null || echo "unknown")
      if [ "$HEALTH" = "healthy" ]; then
        break
      fi
      sleep 1
      HEALTH_WAITED=$((HEALTH_WAITED + 1))
    done

    if [ "$HEALTH" = "healthy" ]; then
      write_status "applied" "Caddy container recreated and healthy with updated ports."
      log "Caddy is healthy."
    else
      write_status "applied" "Caddy container recreated but health check status: $HEALTH (may still be starting)."
      log "Warning: Caddy health status is '$HEALTH' after ${HEALTH_TIMEOUT}s."
    fi
  else
    # Truncate output to avoid oversized status files
    SHORT_OUTPUT=$(echo "$COMPOSE_OUTPUT" | tail -5)
    ERROR_MSG="Failed to recreate caddy container: $SHORT_OUTPUT"
    write_status "failed" "$ERROR_MSG" "$ERROR_MSG"
    log "ERROR: $ERROR_MSG"
  fi

  # Delete the trigger file after processing so stale triggers don't cause
  # "Waiting for port manager sidecar..." on the next boot. Only the trigger
  # this apply answered: one written while it ran is left for the poll loop,
  # which would otherwise never see it. The file is moved aside first (one
  # atomic step), so a trigger written after that is never the one deleted;
  # what was moved is put back unless it is the answered trigger or a newer
  # one has arrived meanwhile.
  if [ -n "$APPLY_TRIGGER" ] && mv "$TRIGGER_FILE" "$TRIGGER_FILE.done" 2>/dev/null; then
    if [ "$(cat "$TRIGGER_FILE.done" 2>/dev/null || echo "")" = "$APPLY_TRIGGER" ] || [ -f "$TRIGGER_FILE" ]; then
      rm -f "$TRIGGER_FILE.done"
    else
      mv "$TRIGGER_FILE.done" "$TRIGGER_FILE"
    fi
  fi

  # Clear the apply lock — the apply completed (success or failure).
  rm -f "$APPLY_LOCK"
}

# ---------------------------------------------------------------------------
# Startup: always apply the override so caddy has the correct ports bound.
# (The main compose stack starts caddy without the L4 ports override file.)
# Only apply if the override file exists (created on first "Apply Ports").
#
# If the apply lock is younger than APPLY_LOCK_MAX_AGE seconds, this container
# was likely just recreated as a side effect of a compose "up" targeting caddy.
# In that case WAIT for the in-progress apply to release the lock instead of
# skipping outright — a previously-crashed apply must never permanently suppress
# the startup restore. If the lock does not clear within the grace window
# (crashed apply), take over and re-apply unconditionally.
# ---------------------------------------------------------------------------
# The trigger as it is before the startup apply: what the poll loop takes as
# already handled (by the apply below, or before this boot). Read here, not
# after the apply: a trigger written while the startup apply runs is newer
# than what that apply saw, and the poll loop has to apply it.
# Use explicit assignment — do NOT use ${VAR:-fallback} which treats empty as unset.
LAST_TRIGGER=$(cat "$TRIGGER_FILE" 2>/dev/null || echo "")

if [ -f "$OVERRIDE_FILE" ]; then
  if [ -f "$APPLY_LOCK" ]; then
    LOCK_TS=$(cat "$APPLY_LOCK" 2>/dev/null || echo "0")
    NOW=$(date +%s)
    if [ $((NOW - LOCK_TS)) -lt "$APPLY_LOCK_MAX_AGE" ]; then
      log "Startup: recent apply lock found — waiting up to ${APPLY_LOCK_MAX_AGE}s for in-progress apply..."
      WAITED=0
      while [ -f "$APPLY_LOCK" ] && [ "$WAITED" -lt "$APPLY_LOCK_MAX_AGE" ]; do
        sleep 1
        WAITED=$((WAITED + 1))
      done
    fi
    if [ -f "$APPLY_LOCK" ]; then
      log "Startup: apply lock is stale (crashed apply?) — taking over and re-applying."
    fi
  fi

  # Caddy may be stopped for a moment, e.g. while an image updater recreates it
  # (keeping its port bindings): wait for it rather than racing to recreate it.
  WAITED=0
  while ! caddy_running && [ "$WAITED" -lt "$CADDY_STARTUP_WAIT" ]; do
    sleep 2
    WAITED=$((WAITED + 2))
  done

  if ports_bound; then
    write_status "applied" "Caddy already publishes the L4 ports."
    log "Startup: caddy already publishes every L4 port; not recreating it."
  else
    log "Startup: applying existing L4 port override..."
    do_apply
  fi
else
  write_status "idle" "Port manager sidecar is running and ready."
  log "Started. No L4 port override file yet."
fi

log "Watching $TRIGGER_FILE for changes (poll every ${POLL_INTERVAL}s)"

while true; do
  sleep "$POLL_INTERVAL"

  CURRENT_TRIGGER=$(cat "$TRIGGER_FILE" 2>/dev/null || echo "")
  if [ "$CURRENT_TRIGGER" = "$LAST_TRIGGER" ]; then
    continue
  fi

  # Empty trigger means the file was just deleted — nothing to do.
  if [ -z "$CURRENT_TRIGGER" ]; then
    LAST_TRIGGER=""
    continue
  fi

  LAST_TRIGGER="$CURRENT_TRIGGER"
  log "Trigger changed. Applying port changes..."
  do_apply
done
