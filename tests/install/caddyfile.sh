#!/bin/sh
# Tests how install.sh adds the server to Caddy's configuration (native way):
#   sh tests/install/caddyfile.sh
# A stock Caddyfile from the Debian package is replaced (with a backup); a customised one only
# gets one import line, also when the script runs twice.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
export HANGAR_LIB_ONLY=1
# shellcheck source=install.sh
. "$here/../../install.sh"

failures=0
check() {
  if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi
}

# Stock Caddyfile: replaced, backup kept.
dir=$(mktemp -d)
cat > "$dir/Caddyfile" <<'STOCK'
# The Caddyfile is an easy way to configure your Caddy web server.
:80 {
	root * /usr/share/caddy
	file_server
}
STOCK
HANGAR_CADDY_DIR=$dir caddy_files team.example.org
check "stock: backup kept" "grep -q 'easy way' '$dir'/Caddyfile.bak.*"
check "stock: no :80 site left" "! grep -q '^:80' '$dir/Caddyfile'"
check "stock: imports the snippet" "grep -qx 'import $dir/hangar-server.caddy' '$dir/Caddyfile'"
check "snippet: site for the domain" "grep -q '^team.example.org {' '$dir/hangar-server.caddy'"
check "snippet: proxies to 127.0.0.1:8080" "grep -q 'reverse_proxy 127.0.0.1:8080' '$dir/hangar-server.caddy'"
rm -rf "$dir"

# Customised Caddyfile: kept, one import line appended, idempotent.
dir=$(mktemp -d)
printf 'shop.example.org {\n\treverse_proxy 127.0.0.1:3000\n}\n' > "$dir/Caddyfile"
HANGAR_CADDY_DIR=$dir caddy_files team.example.org
HANGAR_CADDY_DIR=$dir caddy_files team.example.org
check "custom: own site kept" "grep -q '^shop.example.org {' '$dir/Caddyfile'"
check "custom: exactly one import" "[ \"\$(grep -cx 'import $dir/hangar-server.caddy' '$dir/Caddyfile')\" = 1 ]"
check "custom: no backup needed" "! ls '$dir'/Caddyfile.bak.* > /dev/null 2>&1"
rm -rf "$dir"

# Stock header comment kept, but an own site added: that is customised, never replaced.
dir=$(mktemp -d)
cat > "$dir/Caddyfile" <<'EDITED'
# The Caddyfile is an easy way to configure your Caddy web server.
:80 {
	root * /usr/share/caddy
	file_server
}

shop.example.org {
	reverse_proxy 127.0.0.1:3000
}
EDITED
HANGAR_CADDY_DIR=$dir caddy_files team.example.org
check "edited stock: own site kept" "grep -q '^shop.example.org {' '$dir/Caddyfile'"
check "edited stock: import appended" "grep -qx 'import $dir/hangar-server.caddy' '$dir/Caddyfile'"
rm -rf "$dir"

# Caddy rejects the result (e.g. the domain is already a site): everything is put back.
dir=$(mktemp -d)
bin=$(mktemp -d)
cat > "$bin/caddy" <<'STUB'
#!/bin/sh
[ "$1" = validate ] && exit 1
exit 0
STUB
chmod +x "$bin/caddy"
printf 'team.example.org {
	respond "old"
}
' > "$dir/Caddyfile"
cp "$dir/Caddyfile" "$dir/original"
if PATH="$bin:$PATH" HANGAR_CADDY_DIR=$dir caddy_apply team.example.org > /dev/null; then applied=yes; else applied=no; fi
check "invalid: reported as not applied" "[ '$applied' = no ]"
check "invalid: Caddyfile restored" "cmp -s '$dir/original' '$dir/Caddyfile'"
check "invalid: snippet removed" "[ ! -e '$dir/hangar-server.caddy' ]"
rm -rf "$dir" "$bin"

# Caddy accepts it: applied.
dir=$(mktemp -d)
bin=$(mktemp -d)
printf '#!/bin/sh
exit 0
' > "$bin/caddy"
chmod +x "$bin/caddy"
if PATH="$bin:$PATH" HANGAR_CADDY_DIR=$dir caddy_apply team.example.org > /dev/null; then applied=yes; else applied=no; fi
check "valid: applied" "[ '$applied' = yes ] && [ -e '$dir/hangar-server.caddy' ]"
rm -rf "$dir" "$bin"

# No Caddyfile yet: created with the import.
dir=$(mktemp -d)
HANGAR_CADDY_DIR=$dir caddy_files team.example.org
check "missing: created with import" "grep -qx 'import $dir/hangar-server.caddy' '$dir/Caddyfile'"
rm -rf "$dir"

[ "$failures" = 0 ] && echo "all Caddyfile checks passed"
exit "$failures"
