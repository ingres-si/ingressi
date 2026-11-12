#!/bin/sh
# Caddy starts from the configuration it applied last (--resume), admin
# listener included, so the Caddyfile's CADDY_ADMIN_LISTEN would only count on
# a first start. When the saved configuration names another admin listener
# than CADDY_ADMIN_LISTEN, it is rewritten to the wanted one before Caddy
# starts, so changing the variable (TCP port to unix socket or back) takes
# effect with a restart and the web service finds Caddy where it looks for it.
# The web service sets the listener again with every apply.
set -eu

autosave="${XDG_CONFIG_HOME:-/config}/caddy/autosave.json"
want="${CADDY_ADMIN_LISTEN:-0.0.0.0:2019}"

# Only a plain listen address is written into the file (nothing sed or JSON
# would read as more than text), and only into a file that starts the way
# Caddy and the web service write it. Anything else is left alone.
if [ -f "$autosave" ] && printf '%s' "$want" | grep -Eq '^[][A-Za-z0-9._:/|-]+$'; then
  have=$(sed -n '1s#^{"admin":{"listen":"\([^"]*\)".*#\1#p' "$autosave")
  if [ -n "$have" ] && [ "$have" != "$want" ]; then
    if sed '1s#^{"admin":{"listen":"[^"]*"#{"admin":{"listen":"'"$want"'"#' "$autosave" > "$autosave.new" && mv "$autosave.new" "$autosave"; then
      echo "caddy-entrypoint: admin listener of the saved configuration changed from $have to $want"
    else
      rm -f "$autosave.new"
      echo "caddy-entrypoint: could not rewrite the admin listener of the saved configuration" >&2
    fi
  fi
fi

exec "$@"
