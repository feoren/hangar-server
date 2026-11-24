# Operations

Detailed guide for running the server: the three ways to install it, operation, the official
service on a Strato V-Server, and the full configuration. The short path is in the
[README](../README.md).

## Ways to run it

Every release `vX.Y.Z` publishes the image `ghcr.io/feoren/hangar-server:X.Y.Z` (amd64, arm64)
and, on the GitHub release page, `install.sh`, `docker-compose.yml`, the static binaries
`hangar-server-x86_64-linux-musl` and `hangar-server-aarch64-linux-musl`, and `SHA256SUMS`.

### Install script (empty Linux server)

```sh
curl -fsSL https://github.com/feoren/hangar-server/releases/latest/download/install.sh | sudo sh
```

It asks for the domain, your e-mail address and the way (`docker` or `native`), generates
`SERVER_SECRET`, starts the server, creates the first team and prints the sign-in link. Options
after `sh -s --`: `--docker`, `--native`, `--version X.Y.Z`. Unattended: `HANGAR_DOMAIN`,
`HANGAR_EMAIL`, `HANGAR_TEAM`, `HANGAR_MODE`, `HANGAR_YES=1` (install Docker or Caddy without
asking), `HANGAR_SKIP_CADDY=1` (native, own reverse proxy), `HANGAR_PORT` (native, local port,
default 8080). Running it again updates to the script's version and keeps settings and data. If
a first installation stops halfway (port in use, no network), fix the cause and run it again: it
continues with the same settings and creates the team only once. Values in `.env` that contain
`$`, `\` or `"` belong in single quotes, so that systemd and the admin command read them alike.

| | Docker way | Native way |
| --- | --- | --- |
| Files | `/opt/hangar-server/` (`.env`, `docker-compose.yml`) | `/etc/hangar-server/.env`, binary in `/usr/local/lib/hangar-server/` |
| Data | volume `hangar-server_team-data` | `/var/lib/hangar-server` |
| HTTPS | Caddy container | Caddy from its apt repository (`/etc/caddy/hangar-server.caddy`); a customised `Caddyfile` only gets an `import` line |
| Admin commands | `cd /opt/hangar-server && docker compose run --rm server teams` | `sudo hangar-server teams` |
| Logs | `docker compose logs -f server` | `journalctl -u hangar-server -f` |
| Restart | `docker compose restart server` | `systemctl restart hangar-server` |

The native service runs as the system user `hangar-server`, listens on `127.0.0.1:8080` only and
is hardened by systemd (`ProtectSystem=strict`, `NoNewPrivileges`, 512 MiB memory limit). If ports
80 and 443 already belong to another web server, the script leaves Caddy out and prints what the
reverse proxy needs: upstream `http://127.0.0.1:8080`, WebSocket upgrades on `/v1/live`, long
timeouts, `X-Forwarded-For` set to the client address (see "Image only" below).

Removing a native installation: `systemctl disable --now hangar-server`, then delete
`/etc/systemd/system/hangar-server.service`, `/usr/local/bin/hangar-server`,
`/usr/local/lib/hangar-server`, `/etc/hangar-server`, `/etc/caddy/hangar-server.caddy` (and its
`import` line), the user `hangar-server` and, only if the data is no longer needed,
`/var/lib/hangar-server`.

### Docker Compose or Portainer stack

`docker-compose.yml` is self-contained: the published image plus Caddy, whose configuration is
part of the file. It needs only `PUBLIC_URL` and `SERVER_SECRET`, from a `.env` next to it or as
stack variables in Portainer:

```sh
curl -fsSLO https://github.com/feoren/hangar-server/releases/latest/download/docker-compose.yml
printf 'PUBLIC_URL=https://team.example.org\nSERVER_SECRET=%s\n' "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

`PUBLIC_URL` has no trailing slash, since Caddy uses it as the site address. Docker Compose 2.24
or newer is needed (inline `configs`, optional `env_file`). The DNS name must point to the host
and ports 80 and 443 must be free; the server listens only inside the Compose network. Further settings from [.env.example](../.env.example) go into the
same `.env`. `HANGAR_VERSION` in `.env` pins another image version. To build from this checkout
instead: `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`.
Swarm (`docker stack deploy`) does not support the inline configuration.

### Image only (own reverse proxy)

For Plesk, Portainer containers, a NAS or any host with HTTPS already in place:

```sh
docker run -d --name hangar-server --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v hangar-data:/data \
  -e IDENTITY=local -e PUBLIC_URL=https://team.example.org \
  -e SERVER_SECRET="$(openssl rand -hex 32)" -e TRUST_PROXY=true \
  ghcr.io/feoren/hangar-server:<version>
```

Point the proxy at `http://127.0.0.1:8080` with WebSocket upgrades and long timeouts. With
`TRUST_PROXY=true` the server takes the client address from the last `X-Forwarded-For` entry, so
the proxy must set that header itself (nginx: `proxy_set_header X-Forwarded-For $remote_addr;`,
or `$proxy_add_x_forwarded_for`; Caddy and Traefik do it on their
own). A proxy that passes a client's header on unchanged lets anyone pick their address and
bypass every per-address limit. Admin commands: `docker exec hangar-server hangar-server teams`.

## Operation

- **Data:** `hangar-team.db` (+ `-wal`, `-shm`), when self-hosting also `ticket-signing.key`,
  and with `MAIL_TRANSPORT=log` the `mail/` folder, all in `DATA_DIR` (`/data` in the image).
- **Backups:** `sqlite3 <DATA_DIR>/hangar-team.db ".backup /backup/team.db"` or a snapshot with
  the server stopped; back up `ticket-signing.key` as well. Reservations, the log position,
  undelivered `notify` messages and blocked devices are stored in the database and survive
  restarts; claims do not (clients resend them after `welcome`).
- **Migrations** run automatically on startup (`sqlx migrate`, embedded).
- **Shutdown:** SIGTERM closes live connections with 1012 and waits up to 10 s until they have
  ended and left their teams (Compose `stop_grace_period` and systemd `TimeoutStopSec` give
  20 s); the app reconnects.
- **Logs:** JSON on stdout, fine-grained control via `RUST_LOG`.
- **Monitoring:** `/health` from outside (uptime monitor) and `HEALTHCHECK` in the image.
- **Memory:** limited to 512 MiB (200 connections with up to 1 MiB read buffer each,
  docs/protocol.md); unused teams are unloaded after 10 min. Per team, claims take at most
  32 MiB and the replay window at most 4 MiB.
- **Housekeeping** (hourly): used ticket IDs after expiry, processed revocations after 30 days,
  transcripts after `TRANSCRIPT_RETENTION_DAYS` (in batches of 500, each a short write), and devices in `relay_devices` not seen for
  90 days (the table is only written, every `hello` refreshes it).

## Running on a Strato V-Server

For the official service at `team-hangar.feoren.com` on a Strato V-Server with Docker.

### Prerequisites

- Debian or Ubuntu LTS with Docker Engine and the Compose plugin (`docker compose version`).
  Install following Docker's guide for the distribution (Docker's package repository, not the
  old `docker-compose`).
- Ports 80 and 443 (TCP, plus 443/UDP for HTTP/3) open: in the Strato firewall in the customer
  area (server login, firewall/security) **and**, if active, in `ufw`
  (`ufw allow 80/tcp`, `ufw allow 443/tcp`, `ufw allow 443/udp`). SSH with keys only.
  Port 8080 of the server stays closed; only Caddy is reachable from outside.
- DNS: `A` (and `AAAA` for IPv6) for `team-hangar.feoren.com` pointing to the server's IP. Caddy
  can only obtain the certificate once the name resolves.
- From the website: the relay's bearer token (`RELAY_REVOCATION_TOKEN`) and the public signing
  keys. The keys are served by `https://hangar.feoren.com/api/v1/keys`; they go into
  `TICKET_PUBLIC_KEYS` as `kid:base64url`, comma-separated. [UNVERIFIED: exact response format
  of `/api/v1/keys`; the authoritative source is `wiki/Team-Schnittstelle.md` of the website.]

### Getting the image onto the server

The app's crates are kept as a fixed copy in `vendor/` (see [development.md](development.md)), so
the build needs neither the app repository nor GitHub, only crates.io for the remaining
dependencies.

Normally the server pulls the published image `ghcr.io/feoren/hangar-server:<version>`; only
`docker-compose.yml` and `.env` belong on the server. Without access to ghcr.io, build the image
locally and transfer it under the same name:

```sh
docker build -t ghcr.io/feoren/hangar-server:<version> .
docker save ghcr.io/feoren/hangar-server:<version> | ssh <server> docker load
```

### Setup and start

```sh
cp .env.example .env
chmod 600 .env
```

In `.env`, at least:

```
PUBLIC_URL=https://team-hangar.feoren.com
# Not used in official mode, but the Compose file asks for it: any random value.
SERVER_SECRET=<openssl rand -hex 32>
IDENTITY=official
TICKET_AUDIENCE=hangar-relay
TICKET_PUBLIC_KEYS=<kid>:<base64url>[,<kid2>:<base64url>]
REVOCATION_URL=https://hangar.feoren.com/api/v1/team/revocations
RELAY_REVOCATION_TOKEN=<token from the website>
TRUST_PROXY=true
LOG_FORMAT=json
```

Then:

```sh
docker compose up -d
```

### Checking

```sh
curl -fsS https://team-hangar.feoren.com/health           # {"status":"ok","version":"..."}
docker compose ps                                          # both services "healthy"/"running"
docker compose logs -f --tail=100 server               # JSON lines, "server ready"
```

The log must not contain the warning `REVOCATION_URL missing`; errors while fetching the
revocation list appear as `revocation list not processed` with increasing intervals. Caddy
problems (certificate) are shown by `docker compose logs caddy`.

### Updates

```sh
# new version: HANGAR_VERSION=<version> in .env, or the docker-compose.yml of the release
docker compose pull && docker compose up -d --remove-orphans
docker image prune -f
```

Migrations run on startup. Connections are closed with 1012, and the app reconnects with its
cursor.

**Coming from `hangar-team-server` (0.4.0 and earlier):** the project, the binary and the image
were renamed to `hangar-server`, and the Compose service `teamserver` is now `server`. Keep the
directory you cloned into, so the data volume keeps its name. The Compose file now pulls the
published image and carries the Caddy configuration itself: `TEAM_DOMAIN` and `Caddyfile` are no
longer used, and `PUBLIC_URL` and `SERVER_SECRET` must be in `.env`. Then
`docker compose up -d --remove-orphans`. Admin commands are now `docker compose run --rm server ...`.

### Backing up the data volume

While running, use SQLite's online backup (consistent even during writes):

```sh
docker run --rm -v <project>_team-data:/data -v /root/backup:/backup \
  keinos/sqlite3 sqlite3 /data/hangar-team.db ".backup '/backup/team-$(date +%F).db'"
```

`docker volume ls` shows the volume name (the prefix is the directory name of the Compose
project). Run the backup daily via cron and copy it off the server; never copy a lone `-wal`
file along with it (see RUSTSEC-2026-0459 in docs/dependencies.md). Restoring: stop the
container, place the file in the volume as `hangar-team.db` (remove old `-wal`/`-shm`), start.
[UNVERIFIED: the helper image `keinos/sqlite3` is an example; any image with `sqlite3` 3.27 or
later will do.]

### Restart behavior

- `restart: unless-stopped`: Docker starts both services again after a crash and after a server
  reboot.
- Reservations including timeouts, open release requests and cooldowns, the log position,
  undelivered `notify` messages and blocked devices are restored from the database. After the
  start, all holders count as disconnected: their timeouts run, with a warning beforehand.
- Clients whose cursor is at the stored head continue without a snapshot; older ones fetch a
  snapshot. The apps resend claims after `welcome`.
- Tickets do not remain valid across the interruption: the app fetches a new one from the
  website.

## Configuration

All keys with explanations are in [.env.example](../.env.example). The most important ones:

| Variable | Meaning |
| --- | --- |
| `IDENTITY` | `official` or `local` |
| `PUBLIC_URL` | own origin, required |
| `ROOT_REDIRECT` | optional: target for browser requests to `/` (308), e.g. `https://hangar.feoren.com/`; empty = 404 |
| `TICKET_PUBLIC_KEYS` | `kid:base64url` of the ticket issuers; required with `official` |
| `TICKET_AUDIENCE` | required value for `aud`; empty = `hangar-relay` (official) or `PUBLIC_URL` (local) |
| `LICENSE_PUBLIC_KEYS` | the website's keys for license documents (self-hosting); empty = the built-in key of hangar.feoren.com |
| `SERVER_SECRET` | at least 32 characters (self-hosting) |
| `MAIL_TRANSPORT` | `smtp`, `log`, `none` |
| `TRUST_PROXY` | `true` only behind a reverse proxy that sets `X-Forwarded-For` itself (Caddy does) |
| `REVOCATION_URL`, `RELAY_REVOCATION_TOKEN` | official: signed revocation list from the website, every 15 s ([docs/revocation-format.md](revocation-format.md)) |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | default 200 and 20; plan for about 2 MiB of memory per connection plus 64 MiB, the server warns at startup when the memory limit does not fit |


## Self-hosting step by step

1. `IDENTITY=local`, `SERVER_SECRET`, `PUBLIC_URL`; mail via SMTP or `MAIL_TRANSPORT=none`.
2. Sign in the first person: in Hangar, enter **`<PUBLIC_URL>/api/v1`** as the server address
   (e.g. `https://team.example.org/api/v1`) and sign in (device flow). Under this single base,
   the server offers the same account API as hangar.feoren.com
   ([docs/account-api.md](account-api.md)); the ticket itself names the live channel
   `wss://<host>/v1/live`. The `/device` page asks for the email address. With `SIGNUP=invite`
   and no mail: run `docker compose run --rm server login-link admin@example.org` on the host
   and open the link. Connected devices are listed at `<PUBLIC_URL>/account/devices` (Hangar
   links to the page) and can be disconnected there.

   > **TLS is mandatory outside your own machine.** Hangar accepts `http`/`ws` only for
   > `127.0.0.1`, `localhost` and `[::1]`. On a LAN or the internet, the server needs a
   > certificate, for example via the bundled Caddy (Let's Encrypt) or Caddy with
   > `tls internal` and your own CA on the machines in the LAN; `PUBLIC_URL` then starts with
   > `https://`.
3. Create a team and invite people, most easily on the host (Hangar has no invite button when
   self-hosting; native way: `sudo hangar-server` instead of `docker compose run --rm server`):

   ```sh
   docker compose run --rm server create-team admin@example.org Engineering
   docker compose run --rm server invite Engineering anna@example.org          # member
   docker compose run --rm server invite Engineering ben@example.org admin
   docker compose run --rm server teams                                         # overview
   ```

   `create-team` creates the owner's account if needed and prints the team ID. `invite` takes
   the team ID or the exact name (only the ID if names are identical) and prints the invitation
   link; no mail is ever sent in this case. The link can be used once, is valid for 7 days and
   only for this address; calling it again renews the link and invalidates the old one. For an
   address without an account, opening and confirming it joins the team and signs that address
   in in the browser; then enter the same server address in Hangar, sign in, confirm the code.
   An address that already has an account must be signed in first (in the browser, or without
   mail via `login-link`) and then opens the link again: since the inviter gets the link, it
   never signs in an existing account. The server checks the seat limit on acceptance. Whatever a script uses further (link, team ID) is the last line on stdout.
   Without a license, the server is for one person (the owner): `invite` refuses with a hint at
   the license instead of printing a link (step 4). Without mail, pass the link on only to the
   invited person: whoever opens it first gets the new account. Should someone report their link
   as already used, give them `login-link` for their address; its first use ends every session
   the account had before.

   Via the API, the same is done with `POST /v1/teams` and `POST /v1/teams/{team}/invitations`;
   without mail, the API returns the link to the admin.
4. Teams need a license: without one, the server runs for one person (private use). Buy a Team
   plan with the seats you need on hangar.feoren.com, download the license document in your
   account and place it on the server, most easily on the host:

   ```sh
   docker compose run --rm -T server license - < hangar-license-2026-11-17.txt
   ```

   The command reads the file from stdin (`-`) or from a path inside the container, verifies it
   against `LICENSE_PUBLIC_KEYS`, creates the account of the address named in the license if
   needed and stores the license for it; running it again with a new file replaces the old one.
   Via the API, the signed-in owner does the same with `PUT /v1/license`. Seats apply to all
   teams of this owner. When a license expires or is removed, nothing is deleted: everyone who
   already joined keeps access, only new people are refused (`license_required`) until a valid
   license is stored again.
