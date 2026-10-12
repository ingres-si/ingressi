/** Why the dashboard could not query ClickHouse, as shown on the analytics settings page. */
export interface ClickHouseFailure {
  label: string;
  /** What to check next, or null when the error says nothing more specific. */
  note: string | null;
}

/** The host name in CLICKHOUSE_URL does not resolve (Node and Bun use the same codes). */
const UNRESOLVED_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN']);
/** The host answers but nothing listens on the port. */
const REFUSED_CODES = new Set(['ECONNREFUSED', 'ConnectionRefused', 'FailedToOpenSocket']);

function errorCode(error: unknown): unknown {
  if (!error || typeof error !== 'object') return undefined;
  const code = (error as { code?: unknown }).code;
  if (code !== undefined) return code;
  const cause = (error as { cause?: unknown }).cause;
  return cause && cause !== error ? errorCode(cause) : undefined;
}

/**
 * The status for a failed ClickHouse query. Docker's DNS has no entry for a
 * container that is stopped or between restarts, so with the bundled
 * ClickHouse a name that does not resolve almost always means its container
 * keeps exiting at start-up; its own log says why.
 */
export function describeClickHouseFailure(error: unknown): ClickHouseFailure {
  const code = errorCode(error);
  if (UNRESOLVED_CODES.has(code as string)) {
    return {
      label: 'Host name not found',
      note: 'The ClickHouse container is not running or keeps restarting: docker compose logs clickhouse says why. With a ClickHouse server of your own, check CLICKHOUSE_URL.',
    };
  }
  if (REFUSED_CODES.has(code as string)) {
    return {
      label: 'Connection refused',
      note: 'ClickHouse is starting, or nothing listens at CLICKHOUSE_URL. If this lasts, docker compose logs clickhouse says why.',
    };
  }
  return { label: 'Not reachable from the dashboard', note: null };
}
