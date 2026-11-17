# Operations

Detailed guide for running the server with Docker: in general, for the official service on a
Strato V-Server, and the full configuration. The short path is in the [README](../README.md).

## Running (VPS or Docker host)

1. Create `.env` from `.env.example`: `PUBLIC_URL`, `TEAM_DOMAIN`, keys, and with
   `IDENTITY=local` also `SERVER_SECRET` and mail.
2. Point the DNS of `TEAM_DOMAIN` to the host, open ports 80 and 443.
3. `docker compose up -d --build`. Caddy obtains the certificate; the server listens only
   inside the Compose network.
4. Check: `curl https://<domain>/health` returns `{"status":"ok",...}`.

- **Data:** one volume `team-data` (`/data`): `hangar-team.db` (+ `-wal`, `-shm`), when
  self-hosting also `ticket-signing.key`, and with `MAIL_TRANSPORT=log` the `mail/` folder.
- **Backups:** `sqlite3 /data/hangar-team.db ".backup /backup/team.db"` or a volume snapshot
  with the container stopped; back up `ticket-signing.key` as well. Reservations, the log
  position, undelivered `notify` messages and blocked devices are stored in the database and
  survive restarts; claims do not (clients resend them after `welcome`).
- **Migrations** run automatically on startup (`sqlx migrate`, embedded).
- **Shutdown:** SIGTERM closes live connections with 1012; the app reconnects.
- **Logs:** JSON on stdout (`docker compose logs`), fine-grained control via `RUST_LOG`.
- **Monitoring:** `/health` from outside (uptime monitor) and `HEALTHCHECK` in the image.
- **Memory:** limited to 512 MiB in Compose (200 connections with up to 1 MiB read buffer each,
  docs/protocol.md); unused teams are unloaded after 10 min.

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

Then either copy the whole repository to the server (`git clone` or `rsync`) and build there, or
build the image locally and transfer it:

```sh
docker build -t hangar-server:<version> .
docker save hangar-server:<version> | ssh <server> docker load
```

(in the second case, remove `build: .` from `docker-compose.yml` and set `image:` to this name;
`Caddyfile`, `docker-compose.yml` and `.env` still belong on the server).

### Setup and start

```sh
cp .env.example .env
chmod 600 .env
```

In `.env`, at least:

```
PUBLIC_URL=https://team-hangar.feoren.com
TEAM_DOMAIN=team-hangar.feoren.com
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
docker compose up -d --build     # with a preloaded image: docker compose up -d
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
git pull                                   # or transfer and load a new image
docker compose up -d --build               # rebuilds and replaces the container
docker image prune -f
```

Migrations run on startup. Connections are closed with 1012, and the app reconnects with its
cursor.

**Coming from `hangar-team-server` (0.4.0 and earlier):** the project, the binary and the image
were renamed to `hangar-server`, and the Compose service `teamserver` is now `server`. Keep the
directory you cloned into, so the data volume keeps its name, and add `--remove-orphans` once:
`docker compose up -d --build --remove-orphans`. Admin commands are now
`docker compose run --rm server ...`.

### Backing up the data volume

While running, use SQLite's online backup (consistent even during writes):

```sh
docker run --rm -v hangar-server_team-data:/data -v /root/backup:/backup \
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
| `LICENSE_PUBLIC_KEYS` | the website's keys for license documents (self-hosting) |
| `SERVER_SECRET` | at least 32 characters (self-hosting) |
| `MAIL_TRANSPORT` | `smtp`, `log`, `none` |
| `TRUST_PROXY` | `true` only behind your own Caddy |
| `REVOCATION_URL`, `RELAY_REVOCATION_TOKEN` | official: signed revocation list from the website, every 15 s ([docs/revocation-format.md](revocation-format.md)) |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | default 200 and 200; plan for about 2 MiB of memory per connection |


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
   > certificate, for example via the bundled Caddy (`Caddyfile`, Let's Encrypt) or Caddy with
   > `tls internal` and your own CA on the machines in the LAN; `PUBLIC_URL` then starts with
   > `https://`.
3. Create a team and invite people, most easily on the host (Hangar has no invite button when
   self-hosting):

   ```sh
   docker compose run --rm server create-team admin@example.org Engineering
   docker compose run --rm server invite Engineering anna@example.org          # member
   docker compose run --rm server invite Engineering ben@example.org admin
   docker compose run --rm server teams                                         # overview
   ```

   `create-team` creates the owner's account if needed and prints the team ID. `invite` takes
   the team ID or the exact name (only the ID if names are identical) and prints the invitation
   link; no mail is ever sent in this case. The link can be used once, is valid for 7 days and
   only for this address; calling it again renews the link and invalidates the old one. Whoever
   opens and confirms it is signed in in the browser and becomes a member; then enter the same
   server address in Hangar, sign in, confirm the code. The server checks the seat limit on
   acceptance. Whatever a script uses further (link, team ID) is the last line on stdout.

   Via the API, the same is done with `POST /v1/teams` and `POST /v1/teams/{team}/invitations`;
   without mail, the API returns the link to the admin.
4. From the fourth person on: buy seats on hangar.feoren.com, download the license document in
   your account and place it on the server, most easily on the host:

   ```sh
   docker compose run --rm -T server license - < hangar-license-2026-11-17.txt
   ```

   The command reads the file from stdin (`-`) or from a path inside the container, verifies it
   against `LICENSE_PUBLIC_KEYS`, creates the account of the address named in the license if
   needed and stores the license for it; running it again with a new file replaces the old one.
   Via the API, the signed-in owner does the same with `PUT /v1/license`. Seats apply to all
   teams of this owner.
