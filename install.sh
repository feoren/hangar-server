#!/bin/sh
# Hangar server: install and update on Linux.
#
#   curl -fsSL https://github.com/feoren/hangar-server/releases/latest/download/install.sh | sudo sh
#
# It asks for the domain (which must already point to this server), your e-mail address and
# the way to run the server:
#
#   docker  Docker Compose with Caddy for HTTPS, in /opt/hangar-server.
#   native  The static binary as a systemd service, Caddy for HTTPS from its apt repository.
#
# It then starts the server, creates your first team and prints your sign-in link. Run it again
# later to update; settings and data stay.
#
# Options (after "sh -s --" when piped):  --docker | --native   --version X.Y.Z   --help
# Without questions, e.g.:
#   curl -fsSL .../install.sh | sudo HANGAR_DOMAIN=team.example.org HANGAR_EMAIL=you@example.org \
#     HANGAR_MODE=docker HANGAR_YES=1 sh
#
# Environment: HANGAR_DOMAIN, HANGAR_EMAIL, HANGAR_TEAM (default Team), HANGAR_MODE (docker or
# native), HANGAR_VERSION, HANGAR_YES=1 (answer yes: install Docker or Caddy when missing),
# HANGAR_SKIP_CADDY=1 (native: you run your own reverse proxy), HANGAR_DIR (Docker folder).
set -eu

DEFAULT_VERSION=0.6.2
REPO_URL=https://github.com/feoren/hangar-server

DOCKER_DIR="${HANGAR_DIR:-/opt/hangar-server}"
LIB_DIR=/usr/local/lib/hangar-server
ETC_DIR=/etc/hangar-server
DATA_DIR=/var/lib/hangar-server
WRAPPER=/usr/local/bin/hangar-server
UNIT=/etc/systemd/system/hangar-server.service
SERVICE_USER=hangar-server
# Native way: local port of the server behind the reverse proxy.
PORT="${HANGAR_PORT:-8080}"

NL='
'

say() { printf '%s\n' "$*"; }
fail() {
  printf '\nError: %s\n' "$*" >&2
  if [ "${INSTALLING:-}" = 1 ]; then
    printf 'Fix the cause and run the script again; it continues where it stopped.\n' >&2
  fi
  exit 1
}

# matches VALUE REGEX: a single line that matches the extended regular expression.
matches() {
  case "$1" in *"$NL"*) return 1 ;; esac
  printf '%s\n' "$1" | grep -Eq "$2"
}

# has_tty: a terminal for questions exists (also when the script itself comes through a pipe).
has_tty() { (: < /dev/tty) 2>/dev/null; }

# ask VARIABLE "Question" [DEFAULT]: keeps a value given in the environment, else asks on the
# terminal. Without a terminal, DEFAULT is taken; without a default, that is an error.
ask() {
  eval "current=\${$1:-}"
  if [ -n "$current" ]; then return 0; fi
  if ! has_tty; then
    [ $# -ge 3 ] || fail "no terminal for questions; set $1 in the environment"
    eval "$1=\$3"
    return 0
  fi
  printf '%s ' "$2" > /dev/tty
  read -r answer < /dev/tty || answer=''
  [ -n "$answer" ] || [ $# -lt 3 ] || answer=$3
  eval "$1=\$answer"
}

confirm() {
  [ "${HANGAR_YES:-}" = 1 ] && return 0
  has_tty || return 1
  printf '%s [y/N] ' "$1" > /dev/tty
  read -r answer < /dev/tty || answer=''
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# port_owner PORT: name of the process listening on the TCP port, empty when free or unknown.
port_owner() {
  if command -v ss > /dev/null 2>&1; then
    owner=$(ss -ltnpH "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n 1)
    if [ -z "$owner" ] && [ -n "$(ss -ltnH "sport = :$1" 2>/dev/null)" ]; then owner='another program'; fi
    printf '%s' "$owner"
    return 0
  fi
  # Without ss: listening sockets (state 0A) in /proc, port in hex.
  hex=$(printf '%04X' "$1")
  if cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == p { found = 1 } END { exit !found }'; then
    printf 'another program'
  fi
}

random_secret() {
  secret=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
  [ ${#secret} -eq 64 ] || fail "could not read random bytes from /dev/urandom"
  printf '%s' "$secret"
}

# download URL FILE
download() {
  if command -v curl > /dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1" || fail "download failed: $1"
  elif command -v wget > /dev/null 2>&1; then
    wget -q -O "$2" "$1" || fail "download failed: $1"
  else
    fail "curl or wget is needed"
  fi
}

# write_env FILE WAY: the settings of a new installation (WAY is docker or native). When FILE
# exists from an unfinished run, its SERVER_SECRET is kept.
write_env() {
  secret=''
  if [ -f "$1" ]; then
    secret=$(sed -n 's/^SERVER_SECRET=//p' "$1" | head -n 1)
  fi
  [ -n "$secret" ] || secret=$(random_secret)
  umask 077
  {
    say "# Hangar server settings. Keep this file private."
    if [ "$2" = docker ]; then
      say "# Version of the image; the install script updates it."
      say "HANGAR_VERSION=$VERSION"
    else
      say "DATA_DIR=$DATA_DIR"
      say "BIND_ADDR=127.0.0.1:$PORT"
      say "# Only the reverse proxy on this host reaches the server."
      say "TRUST_PROXY=true"
    fi
    say "IDENTITY=local"
    say "PUBLIC_URL=https://$DOMAIN"
    say "SERVER_SECRET=$secret"
    say "# invite: only existing accounts and invited addresses. open: anyone."
    say "SIGNUP=invite"
    say "LOG_FORMAT=json"
    say ""
    say "# Mail. none: invitation and sign-in links are printed for the admin, who passes them on."
    say "# For mails set MAIL_TRANSPORT=smtp, fill in the lines below and restart the server."
    say "# Put values that contain \$, \\ or \" in single quotes, e.g. SMTP_PASSWORD='pa\$\$word'."
    say "MAIL_TRANSPORT=none"
    say "MAIL_FROM=\"Hangar <$EMAIL>\""
    say "SMTP_HOST="
    say "SMTP_TLS=starttls"
    say "SMTP_PORT=587"
    say "SMTP_USERNAME="
    say "SMTP_PASSWORD="
  } > "$1"
  umask 022
}

# --- Caddy (native way) ----------------------------------------------------------------------

# caddy_site DOMAIN: the site block for the server on this host.
caddy_site() {
  cat <<EOF
# Hangar server, written by its install script. Access logs stay off: paths like
# /invite/<token> and /auth/magic/<token> carry secrets.
$1 {
	encode zstd gzip
	header -Server
	reverse_proxy 127.0.0.1:$PORT {
		# Long-lived WebSocket connections; the server pings every 25 s.
		stream_timeout 24h
		stream_close_delay 5s
	}
}
EOF
}

# caddy_stock FILE: the file is the unchanged Caddyfile of the Caddy package (only its :80 demo
# site, comments aside).
caddy_stock() {
  content=$(sed -e 's/#.*//' "$1" | tr -s ' \t\n' '   ' | sed -e 's/^ //' -e 's/ $//')
  [ "$content" = ':80 { root * /usr/share/caddy file_server }' ]
}

# caddy_files DOMAIN: writes the site snippet and imports it in the Caddyfile. The stock Caddyfile
# of the package is replaced (backup Caddyfile.bak.<time>); any other one only gets the import
# line, once.
caddy_files() {
  dir="${HANGAR_CADDY_DIR:-/etc/caddy}"
  mkdir -p "$dir"
  caddy_site "$1" > "$dir/hangar-server.caddy"
  line="import $dir/hangar-server.caddy"
  if [ ! -f "$dir/Caddyfile" ]; then
    say "$line" > "$dir/Caddyfile"
  elif caddy_stock "$dir/Caddyfile"; then
    cp "$dir/Caddyfile" "$dir/Caddyfile.bak.$(date +%Y%m%d-%H%M%S)"
    say "$line" > "$dir/Caddyfile"
  elif ! grep -qxF "$line" "$dir/Caddyfile"; then
    printf '\n%s\n' "$line" >> "$dir/Caddyfile"
  fi
}

# caddy_apply DOMAIN: caddy_files, then Caddy checks the result. If Caddy rejects it, the
# Caddyfile is put back as it was and the snippet removed; returns 1 then.
caddy_apply() {
  dir="${HANGAR_CADDY_DIR:-/etc/caddy}"
  saved=$(mktemp)
  had_file=no
  if [ -f "$dir/Caddyfile" ]; then
    cp "$dir/Caddyfile" "$saved"
    had_file=yes
  fi
  caddy_files "$1"
  if caddy validate --adapter caddyfile --config "$dir/Caddyfile" > "$saved.log" 2>&1; then
    rm -f "$saved" "$saved.log"
    return 0
  fi
  say "Caddy rejects the configuration with the new site, so it was left unchanged:"
  tail -n 3 "$saved.log"
  if [ "$had_file" = yes ]; then cp "$saved" "$dir/Caddyfile"; else rm -f "$dir/Caddyfile"; fi
  for backup in "$dir"/Caddyfile.bak.*; do
    if [ -e "$backup" ] && cmp -s "$backup" "$dir/Caddyfile"; then rm -f "$backup"; fi
  done
  rm -f "$dir/hangar-server.caddy" "$saved" "$saved.log"
  return 1
}

proxy_help() {
  say ""
  say "Set up your reverse proxy for https://$DOMAIN with:"
  say "  upstream http://127.0.0.1:$PORT, WebSocket upgrades allowed (path /v1/live),"
  say "  long timeouts (the connection stays open; the server pings every 25 s),"
  say "  X-Forwarded-For set by the proxy to the client address (nginx:"
  say "  proxy_set_header X-Forwarded-For \$remote_addr;). A proxy that passes the client's own"
  say "  header on lets anyone bypass the per-address limits (TRUST_PROXY=true is set)."
}

# caddy_configure: installs Caddy if needed and agreed, then adds the site. Returns 1 when the
# operator has to set up a reverse proxy.
caddy_configure() {
  if [ "${HANGAR_SKIP_CADDY:-}" = 1 ]; then
    proxy_help
    return 1
  fi
  for port in 80 443; do
    owner=$(port_owner "$port")
    if [ -n "$owner" ] && [ "$owner" != caddy ]; then
      say "Port $port is used by $owner, so Caddy is not set up."
      proxy_help
      return 1
    fi
  done
  if ! command -v caddy > /dev/null 2>&1; then
    if command -v apt-get > /dev/null 2>&1 && confirm "Install Caddy for HTTPS from its official apt repository?"; then
      if ! caddy_install; then
        say "Installing Caddy failed."
        proxy_help
        return 1
      fi
    else
      say "Caddy is not installed: https://caddyserver.com/docs/install"
      proxy_help
      return 1
    fi
  fi
  if ! caddy_apply "$DOMAIN"; then
    proxy_help
    return 1
  fi
  # A running Caddy only reloads: a restart would stop all its sites if anything went wrong.
  if systemctl is-active --quiet caddy; then
    systemctl reload caddy || { say "Caddy did not reload; see: journalctl -u caddy"; proxy_help; return 1; }
  else
    systemctl enable --now caddy || { say "Caddy did not start; see: journalctl -u caddy"; proxy_help; return 1; }
  fi
}

# caddy_install: Caddy from its official apt repository (Debian, Ubuntu).
caddy_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || return 1
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg || return 1
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg || return 1
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list || return 1
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq || return 1
  apt-get install -y -qq caddy
}

if [ "${HANGAR_LIB_ONLY:-}" = 1 ]; then
  # Sourced by tests/install/caddyfile.sh: functions only.
  # shellcheck disable=SC2317 # exit only runs when the script was not sourced
  return 0 2>/dev/null || exit 0
fi

# --- Options ---------------------------------------------------------------------------------

VERSION="${HANGAR_VERSION:-$DEFAULT_VERSION}"
MODE="${HANGAR_MODE:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) MODE=docker ;;
    --native) MODE=native ;;
    --version)
      [ $# -ge 2 ] || fail "--version needs a value"
      VERSION=$2
      shift
      ;;
    --version=*) VERSION=${1#--version=} ;;
    -h|--help)
      sed -n '2,/^set -eu/p' "$0" 2>/dev/null | sed '$d' | sed 's/^# \{0,1\}//' || true
      exit 0
      ;;
    *) fail "unknown option $1 (see --help)" ;;
  esac
  shift
done

matches "$VERSION" '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || fail "not a version: $VERSION"
case "$MODE" in ""|docker|native) ;; *) fail "HANGAR_MODE must be docker or native" ;; esac
matches "$DOCKER_DIR" '^/[A-Za-z0-9._/-]*$' || fail "not an absolute folder: $DOCKER_DIR"
[ "$(uname -s)" = Linux ] || fail "this script installs on Linux"
[ "$(id -u)" = 0 ] || fail "please run as root, for example with sudo"

RELEASE_URL="$REPO_URL/releases/download/v$VERSION"

# --- Docker way ------------------------------------------------------------------------------

docker_ready() {
  if ! command -v docker > /dev/null 2>&1; then
    say "Docker is not installed."
    if confirm "Install Docker now with Docker's official script (get.docker.com)?"; then
      tmp=$(mktemp)
      download https://get.docker.com "$tmp"
      sh "$tmp"
      rm -f "$tmp"
    else
      fail "install Docker Engine with the Compose plugin first: https://docs.docker.com/engine/install/"
    fi
  fi
  docker compose version > /dev/null 2>&1 \
    || fail "the Docker Compose plugin is missing: https://docs.docker.com/compose/install/linux/"
  compose_version=$(docker compose version --short 2>/dev/null | sed 's/^v//')
  major=${compose_version%%.*}
  minor=${compose_version#*.}
  minor=${minor%%.*}
  if matches "$major.$minor" '^[0-9]+\.[0-9]+$' && { [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 24 ]; }; }; then
    fail "Docker Compose $compose_version is too old; version 2.24 or newer is needed: https://docs.docker.com/compose/install/linux/"
  fi
}

# docker_compose_file: the Compose file of this version, verified against SHA256SUMS and only
# then put in place, so an aborted or altered download never replaces a working file.
docker_compose_file() {
  if [ -n "${HANGAR_COMPOSE_FILE:-}" ]; then
    cp "$HANGAR_COMPOSE_FILE" "$DOCKER_DIR/docker-compose.yml"
    return 0
  fi
  tmp=$(mktemp -d)
  download "$RELEASE_URL/docker-compose.yml" "$tmp/docker-compose.yml"
  download "$RELEASE_URL/SHA256SUMS" "$tmp/SHA256SUMS"
  grep " \*\{0,1\}docker-compose.yml\$" "$tmp/SHA256SUMS" > "$tmp/expected" \
    || { rm -rf "$tmp"; fail "docker-compose.yml is not listed in SHA256SUMS"; }
  (cd "$tmp" && sha256sum -c expected > /dev/null 2>&1) \
    || { rm -rf "$tmp"; fail "checksum of docker-compose.yml does not match; nothing was changed"; }
  mv "$tmp/docker-compose.yml" "$DOCKER_DIR/docker-compose.yml"
  rm -rf "$tmp"
}

docker_wait() {
  tries=0
  until docker compose exec -T server /usr/local/bin/hangar-server healthcheck > /dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 45 ] || fail "the server does not start; see: cd $DOCKER_DIR && docker compose logs server"
    sleep 2
  done
}

docker_update() {
  say "Updating the Hangar server in $DOCKER_DIR to $VERSION"
  docker_ready
  cd "$DOCKER_DIR"
  docker_compose_file
  if grep -q '^HANGAR_VERSION=' .env; then
    sed -i "s/^HANGAR_VERSION=.*/HANGAR_VERSION=$VERSION/" .env
  else
    printf 'HANGAR_VERSION=%s\n' "$VERSION" >> .env
  fi
  # Caddy follows caddy:2-alpine and gets its security updates here.
  docker compose pull --quiet caddy || say "Warning: could not fetch a newer Caddy image; keeping the current one."
  docker compose up -d --remove-orphans
  docker_wait
  say ""
  say "Updated to $VERSION. Hangar reconnects on its own."
}

docker_install() {
  docker_ready
  own_caddy=no
  if [ -f "$DOCKER_DIR/docker-compose.yml" ] \
    && (cd "$DOCKER_DIR" && docker compose ps --services --status running 2>/dev/null | grep -qx caddy); then
    own_caddy=yes
  fi
  for port in 80 443; do
    owner=$(port_owner "$port")
    if [ -n "$owner" ] && [ "$own_caddy" = no ]; then
      fail "port $port is used by $owner. The bundled Caddy needs ports 80 and 443; with a web server of your own, use the native way with HANGAR_SKIP_CADDY=1 or the image directly (README)"
    fi
  done
  mkdir -p "$DOCKER_DIR"
  cd "$DOCKER_DIR"
  write_env .env docker
  docker_compose_file
  docker compose up -d
  say "Waiting for the server ..."
  docker_wait
  ADMIN="cd $DOCKER_DIR && docker compose run --rm server"
  PROXY_READY=yes
}

# --- Native way ------------------------------------------------------------------------------

native_asset() {
  case "$(uname -m)" in
    x86_64|amd64) say hangar-server-x86_64-linux-musl ;;
    aarch64|arm64) say hangar-server-aarch64-linux-musl ;;
    *) fail "no binary for $(uname -m); use the Docker way" ;;
  esac
}

# native_binary: downloads and verifies the binary, then installs it as the current version.
# Nothing on the system changes before the checksum matches.
native_binary() {
  asset=$(native_asset)
  tmp=$(mktemp -d)
  if [ -n "${HANGAR_BINARY:-}" ]; then
    cp "$HANGAR_BINARY" "$tmp/$asset"
    cp "${HANGAR_SUMS:?HANGAR_SUMS is needed with HANGAR_BINARY}" "$tmp/SHA256SUMS"
  else
    say "Downloading $asset $VERSION ..."
    download "$RELEASE_URL/$asset" "$tmp/$asset"
    download "$RELEASE_URL/SHA256SUMS" "$tmp/SHA256SUMS"
  fi
  grep " \*\{0,1\}$asset\$" "$tmp/SHA256SUMS" > "$tmp/expected" || fail "$asset is not listed in SHA256SUMS"
  (cd "$tmp" && sha256sum -c expected > /dev/null 2>&1) || { rm -rf "$tmp"; fail "checksum of $asset does not match; nothing was changed"; }
  install -d -m 755 "$LIB_DIR"
  install -m 755 "$tmp/$asset" "$LIB_DIR/hangar-server-$VERSION"
  ln -sfn "hangar-server-$VERSION" "$LIB_DIR/current"
  rm -rf "$tmp"
}

native_files() {
  if ! id "$SERVICE_USER" > /dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
  install -d -m 750 -o root -g "$SERVICE_USER" "$ETC_DIR"

  cat > "$WRAPPER" <<EOF
#!/bin/sh
# Admin commands of the Hangar server, for example: sudo hangar-server teams
[ "\$(id -u)" = 0 ] || { echo "run it with sudo: sudo hangar-server \$*" >&2; exit 1; }
cd $ETC_DIR || exit 1
exec runuser -u $SERVICE_USER -- $LIB_DIR/current "\$@"
EOF
  chmod 755 "$WRAPPER"

  cat > "$UNIT" <<EOF
# Hangar server, written by its install script.
[Unit]
Description=Hangar server
Documentation=$REPO_URL
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$ETC_DIR/.env
ExecStart=$LIB_DIR/current serve
Restart=on-failure
RestartSec=2
TimeoutStopSec=20
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$DATA_DIR
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
UMask=0077
# About 2 MiB per connection plus 64 MiB; the server warns when MAX_CONNECTIONS does not fit.
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

native_wait() {
  tries=0
  until "$WRAPPER" healthcheck > /dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || fail "the server does not start; see: journalctl -u hangar-server"
    sleep 1
  done
}

native_update() {
  say "Updating the Hangar server to $VERSION"
  native_binary
  native_files
  systemctl restart hangar-server
  native_wait
  say ""
  say "Updated to $VERSION. Hangar reconnects on its own."
}

native_install() {
  command -v systemctl > /dev/null 2>&1 || fail "the native way needs systemd; use the Docker way"
  { matches "$PORT" '^[0-9]{2,5}$' && [ "$PORT" -le 65535 ]; } \
    || fail "HANGAR_PORT must be a port number (10-65535)"
  if ! systemctl is-active --quiet hangar-server; then
    owner=$(port_owner "$PORT")
    [ -z "$owner" ] || fail "port $PORT is used by $owner; choose another one with HANGAR_PORT=8081"
  fi
  native_binary
  native_files
  write_env "$ETC_DIR/.env" native
  chown root:"$SERVICE_USER" "$ETC_DIR/.env"
  chmod 640 "$ETC_DIR/.env"
  systemctl enable hangar-server
  systemctl restart hangar-server
  say "Waiting for the server ..."
  native_wait
  if caddy_configure; then PROXY_READY=yes; else PROXY_READY=no; fi
  ADMIN="sudo hangar-server"
}

# admin ARGS...: an admin command of the server just installed (last line of stdout).
admin() {
  if [ "$MODE" = docker ]; then
    (cd "$DOCKER_DIR" && docker compose run --rm -T server "$@") 2>/dev/null | tail -n 1
  else
    "$WRAPPER" "$@" 2>/dev/null | tail -n 1
  fi
}

# first_team: the ID of the owner's team named TEAM, created unless an earlier run did.
first_team() {
  existing=$( { if [ "$MODE" = docker ]; then
      (cd "$DOCKER_DIR" && docker compose run --rm -T server teams) 2>/dev/null
    else
      "$WRAPPER" teams 2>/dev/null
    fi; } | HANGAR_MATCH_TEAM="$TEAM" HANGAR_MATCH_OWNER="$EMAIL" awk -F '\t' \
      '$2 == ENVIRON["HANGAR_MATCH_TEAM"] && $3 == ENVIRON["HANGAR_MATCH_OWNER"] { print $1; exit }')
  if [ -n "$existing" ]; then say "$existing"; else admin create-team "$EMAIL" "$TEAM"; fi
}

# --- Update an existing installation ---------------------------------------------------------

# Written at the very end of a new installation; without it, a run continues the installation.
MARKER=.install-complete

if [ -f "$DOCKER_DIR/$MARKER" ]; then
  [ "$MODE" != native ] || fail "a Docker installation exists in $DOCKER_DIR; remove it before switching ways"
  docker_update
  exit 0
fi
if [ -f "$ETC_DIR/$MARKER" ]; then
  [ "$MODE" != docker ] || fail "a native installation exists in $ETC_DIR; remove it before switching ways"
  native_update
  exit 0
fi

# --- New installation ------------------------------------------------------------------------

if [ -f "$DOCKER_DIR/.env" ]; then
  [ "$MODE" != native ] || fail "an unfinished Docker installation exists in $DOCKER_DIR; remove it to use the native way"
  MODE=docker
  say "Hangar server $VERSION: continuing the unfinished installation in $DOCKER_DIR"
elif [ -f "$ETC_DIR/.env" ]; then
  [ "$MODE" != docker ] || fail "an unfinished native installation exists in $ETC_DIR; remove it to use the Docker way"
  MODE=native
  say "Hangar server $VERSION: continuing the unfinished installation in $ETC_DIR"
else
  say "Hangar server $VERSION: new installation"
fi
INSTALLING=1
say ""
ask HANGAR_DOMAIN "Domain of the server, already pointing to this machine (e.g. team.example.org):"
DOMAIN=$(printf '%s' "$HANGAR_DOMAIN" | tr '[:upper:]' '[:lower:]')
matches "$DOMAIN" '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$' \
  || fail "not a domain name: $DOMAIN"

ask HANGAR_EMAIL "Your e-mail address (first account):"
EMAIL=$(printf '%s' "$HANGAR_EMAIL" | tr '[:upper:]' '[:lower:]')
matches "$EMAIL" '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' || fail "not an e-mail address: $EMAIL"

HANGAR_TEAM="${HANGAR_TEAM:-}"
ask HANGAR_TEAM "Name of your first team (Enter = Team):" Team
TEAM=$(printf '%s' "$HANGAR_TEAM" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
matches "$TEAM" '^[^[:cntrl:]"]+$' || fail "not a team name: $TEAM"

if [ -z "$MODE" ]; then
  if command -v docker > /dev/null 2>&1; then suggested=docker; else suggested=native; fi
  HANGAR_MODE=''
  ask HANGAR_MODE "Run it with docker or native (systemd service)? (Enter = $suggested):" "$suggested"
  MODE="$HANGAR_MODE"
  case "$MODE" in docker|native) ;; *) fail "answer docker or native" ;; esac
fi

if command -v getent > /dev/null 2>&1 && ! getent hosts "$DOMAIN" > /dev/null 2>&1; then
  say "Warning: $DOMAIN does not resolve yet. HTTPS works only once it points to this machine."
fi

if [ "$MODE" = docker ]; then docker_install; else native_install; fi
TEAM_ID=$(first_team) || TEAM_ID=''
LINK=$(admin login-link "$EMAIL") || LINK=''

case "$TEAM_ID" in
  t_*) ;;
  *) say "Warning: the team was not created; run: $ADMIN create-team $EMAIL \"$TEAM\"" ;;
esac
case "$LINK" in
  "https://$DOMAIN/auth/magic/"*) ;;
  *) LINK="(not created; run: $ADMIN login-link $EMAIL)" ;;
esac

if [ "$MODE" = docker ]; then touch "$DOCKER_DIR/$MARKER"; else touch "$ETC_DIR/$MARKER"; fi

say ""
if [ "$PROXY_READY" = yes ]; then
  say "Done. Your Hangar server runs at https://$DOMAIN"
else
  say "Done. The server runs on http://127.0.0.1:$PORT; https://$DOMAIN works once your reverse"
  say "proxy forwards to it as described above."
fi
say ""
say "1. In Hangar open Settings > Account and enter as server address:"
say "     https://$DOMAIN/api/v1"
say "   Click Apply, then Sign in. Hangar shows a code."
say "2. Open this sign-in link in your browser (once, valid for one hour) and confirm the code:"
say "     $LINK"
say "   A new link at any time: $ADMIN login-link $EMAIL"
say "3. Your team \"$TEAM\" is ready. Invite people; each command prints a one-time link"
say "   (seven days, only for that address) that you pass on:"
say "     $ADMIN invite \"$TEAM\" anna@example.org"
say "   Teams and open invitations: $ADMIN teams"
say ""
say "Update: run this script again. Back up the data regularly: $REPO_URL/blob/main/docs/operations.md"
