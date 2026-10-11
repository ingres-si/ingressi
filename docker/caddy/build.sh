#!/bin/sh
set -eu

module_version() {
  version="$(go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' "$1")"
  if [ -z "$version" ]; then
    echo "No pinned version found for $1" >&2
    exit 1
  fi
  printf '%s' "$version"
}

caddy_version="$(module_version github.com/caddyserver/caddy/v2)"
set -- "$caddy_version"

while IFS= read -r module; do
  version="$(module_version "$module")"
  set -- "$@" --with "$module@$version"
done <<'MODULES'
github.com/caddy-dns/cloudflare
github.com/caddy-dns/route53
github.com/caddy-dns/digitalocean
github.com/caddy-dns/duckdns
github.com/caddy-dns/hetzner
github.com/caddy-dns/vultr
github.com/caddy-dns/porkbun
github.com/caddy-dns/godaddy
github.com/caddy-dns/namecheap
github.com/caddy-dns/ovh
github.com/caddy-dns/ionos
github.com/caddy-dns/linode
github.com/caddy-dns/njalla
github.com/caddy-dns/netcup
github.com/caddy-dns/spaceship
github.com/caddy-dns/desec
github.com/caddy-dns/bunny
github.com/caddy-dns/dynu
github.com/caddy-dns/acmedns
github.com/caddy-dns/infomaniak
github.com/caddy-dns/inwx
github.com/caddy-dns/cloudns
github.com/caddy-dns/rfc2136
github.com/mholt/caddy-l4
github.com/mholt/caddy-ratelimit
github.com/fuomag9/caddy-blocker-plugin
github.com/corazawaf/coraza-caddy/v2
github.com/pberkel/caddy-storage-redis
MODULES

# Set by update-compatibility-pins.sh only while Caddy imports github.com/google/cel-go.
cel_go_version="$(go list -m -f '{{if .Replace}}{{.Replace.Version}}{{end}}' github.com/google/cel-go 2>/dev/null || true)"
if [ -n "$cel_go_version" ]; then
  set -- "$@" --replace "github.com/google/cel-go=github.com/google/cel-go@$cel_go_version"
fi

GOOS="$TARGETOS" GOARCH="$TARGETARCH" xcaddy build "$@" --output /usr/bin/caddy
