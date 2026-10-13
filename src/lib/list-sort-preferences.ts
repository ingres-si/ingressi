/**
 * Sort preferences shared by the three dashboard lists whose columns are
 * user-sortable. Stored preferences use "default" or "<key>:<direction>".
 */
export const SORT_DIRECTIONS = ["asc", "desc"] as const;
export type SortDirection = (typeof SORT_DIRECTIONS)[number];

export type StoredSortPreference<K extends string> = "default" | `${K}:${SortDirection}`;

export const PROXY_HOST_SORT_KEYS = ["requests", "host", "name", "status", "errors", "created"] as const;
export type ProxyHostSortKey = (typeof PROXY_HOST_SORT_KEYS)[number];
export type ProxyHostsSortPreference = StoredSortPreference<ProxyHostSortKey>;

export const L4_PROXY_HOST_SORT_KEYS = ["name", "protocol", "listenAddress", "upstreams", "enabled", "createdAt"] as const;
export type L4ProxyHostSortKey = (typeof L4_PROXY_HOST_SORT_KEYS)[number];
export type L4ProxyHostsSortPreference = StoredSortPreference<L4ProxyHostSortKey>;

export const CLIENT_CERTIFICATE_SORT_KEYS = ["name", "ca", "issued", "expires"] as const;
export type ClientCertificateSortKey = (typeof CLIENT_CERTIFICATE_SORT_KEYS)[number];
export type ClientCertificatesSortPreference = StoredSortPreference<ClientCertificateSortKey>;

function preferenceValues<K extends string>(keys: readonly K[]): StoredSortPreference<K>[] {
  return ["default", ...keys.flatMap((key) => SORT_DIRECTIONS.map((dir) => `${key}:${dir}` as StoredSortPreference<K>))];
}

export const PROXY_HOST_SORT_PREFERENCES = preferenceValues(PROXY_HOST_SORT_KEYS);
export const L4_PROXY_HOST_SORT_PREFERENCES = preferenceValues(L4_PROXY_HOST_SORT_KEYS);
export const CLIENT_CERTIFICATE_SORT_PREFERENCES = preferenceValues(CLIENT_CERTIFICATE_SORT_KEYS);

function isStoredSortPreference<K extends string>(
  value: unknown,
  values: readonly StoredSortPreference<K>[]
): value is StoredSortPreference<K> {
  return typeof value === "string" && (values as readonly string[]).includes(value);
}

export function isProxyHostsSortPreference(value: unknown): value is ProxyHostsSortPreference {
  return isStoredSortPreference(value, PROXY_HOST_SORT_PREFERENCES);
}

export function isL4ProxyHostsSortPreference(value: unknown): value is L4ProxyHostsSortPreference {
  return isStoredSortPreference(value, L4_PROXY_HOST_SORT_PREFERENCES);
}

export function isClientCertificatesSortPreference(value: unknown): value is ClientCertificatesSortPreference {
  return isStoredSortPreference(value, CLIENT_CERTIFICATE_SORT_PREFERENCES);
}

export function parseStoredSortPreference<K extends string>(
  value: StoredSortPreference<K>
): { key: K; dir: SortDirection } | null {
  if (value === "default") return null;
  const separator = value.lastIndexOf(":");
  return {
    key: value.slice(0, separator) as K,
    dir: value.slice(separator + 1) as SortDirection,
  };
}
