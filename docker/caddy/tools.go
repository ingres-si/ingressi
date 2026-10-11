// This module is a version-pinning manifest for the Caddy build; nothing here
// ships — xcaddy builds the real binary from these pins in its own module.
// The blank imports must stay untagged and in sync with build.sh: they keep
// `go mod tidy` (run by Dependabot on every update) from treating the
// requirements as unused and stripping the require block from go.mod, and
// they give CodeQL a buildable package to analyze (this is the repo's only
// Go module). xcaddy is pinned via the `tool` directive in go.mod because it
// only ships a main package, which cannot be imported.
//
// github.com/google/cel-go is intentionally absent: it has no root package
// and is already pulled in transitively by Caddy. Its compatibility version
// is managed through the replace directive in go.mod.

package tools

import (
	_ "github.com/caddy-dns/acmedns"
	_ "github.com/caddy-dns/bunny"
	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddy-dns/cloudns"
	_ "github.com/caddy-dns/desec"
	_ "github.com/caddy-dns/digitalocean"
	_ "github.com/caddy-dns/duckdns"
	_ "github.com/caddy-dns/dynu"
	_ "github.com/caddy-dns/godaddy"
	_ "github.com/caddy-dns/hetzner"
	_ "github.com/caddy-dns/infomaniak"
	_ "github.com/caddy-dns/inwx"
	_ "github.com/caddy-dns/ionos"
	_ "github.com/caddy-dns/linode"
	_ "github.com/caddy-dns/namecheap"
	_ "github.com/caddy-dns/netcup"
	_ "github.com/caddy-dns/njalla"
	_ "github.com/caddy-dns/ovh"
	_ "github.com/caddy-dns/porkbun"
	_ "github.com/caddy-dns/rfc2136"
	_ "github.com/caddy-dns/route53"
	_ "github.com/caddy-dns/spaceship"
	_ "github.com/caddy-dns/vultr"
	_ "github.com/caddyserver/caddy/v2"
	_ "github.com/corazawaf/coraza-caddy/v2"
	_ "github.com/fuomag9/caddy-blocker-plugin"
	_ "github.com/mholt/caddy-l4"
	_ "github.com/mholt/caddy-ratelimit"
	_ "github.com/pberkel/caddy-storage-redis"
)
