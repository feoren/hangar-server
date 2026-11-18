# Hangar Server

[![CI](https://github.com/feoren/hangar-server/actions/workflows/ci.yml/badge.svg)](https://github.com/feoren/hangar-server/actions/workflows/ci.yml)
[![License: Elastic 2.0](https://img.shields.io/badge/license-Elastic%202.0-blue)](LICENSE)

The server for teamwork in [Hangar](https://github.com/feoren/hangar), the desktop app for AI
coding agents. It connects the Hangar apps of a team: who is working on what right now, who has
reserved which task, which files an agent is changing, plus end-to-end encrypted notes. The server
never sees plaintext; it only stores and relays encrypted data.

## Do I need this?

**Usually not.** Out of the box, Hangar uses the official service at
[hangar.feoren.com](https://hangar.feoren.com), where there is nothing to set up.

You only need this server if your team wants to run its **own server**, for example to keep all
data inside your own network.

## Set up your own server

You need a domain name that points to your server. Pick one of three ways:

**A. Install script** (an empty Linux server; recommended)

```sh
curl -fsSL https://github.com/feoren/hangar-server/releases/latest/download/install.sh | sudo sh
```

It asks for your domain, your e-mail address and whether to run the server with Docker or
natively as a systemd service. HTTPS comes from Caddy, which it sets up for you. At the end it
prints your sign-in link. Run it again later to update.

**B. Docker Compose or Portainer stack** (a host with Docker and free ports 80 and 443)

```sh
curl -fsSLO https://github.com/feoren/hangar-server/releases/latest/download/docker-compose.yml
printf 'PUBLIC_URL=https://team.example.org\nSERVER_SECRET=%s\n' "$(openssl rand -hex 32)" > .env
docker compose up -d
```

`PUBLIC_URL` is your address without a trailing slash; Docker Compose 2.24 or newer is needed.
The file needs nothing else; in Portainer, paste it as a stack and set `PUBLIC_URL` and
`SERVER_SECRET` as variables.

**C. Image only** (you already have a reverse proxy with HTTPS)

```sh
docker run -d --name hangar-server --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v hangar-data:/data -e IDENTITY=local -e PUBLIC_URL=https://team.example.org \
  -e SERVER_SECRET="$(openssl rand -hex 32)" -e TRUST_PROXY=true \
  ghcr.io/feoren/hangar-server:0.5.1
```

Check it with `curl https://team.example.org/health` (returns `{"status":"ok",...}`).

**Create a team and invite people**

```sh
docker compose run --rm server create-team you@example.org Engineering
docker compose run --rm server invite Engineering anna@example.org
docker compose run --rm server teams                  # overview
```

With the native way it is `sudo hangar-server create-team ...`, with the image only
`docker exec hangar-server hangar-server create-team ...`. The install script already created
your first team. `invite` prints an invitation link. Send it to the person; it can be used once
and is valid for 7 days. Add `admin` at the end to give them admin rights. Mail is optional;
without it (`MAIL_TRANSPORT=none`) the server prints links like this.

**Connect in Hangar**

In Hangar, enter `https://team.example.org/api/v1` as the server address, click sign in and
confirm the code in the browser. Without a mail server, you get the sign-in link for the browser
with `docker compose run --rm server login-link you@example.org`.

## Good to know

- **Seats:** Up to 3 people are free. For more, buy seats on
  [hangar.feoren.com](https://hangar.feoren.com), download the license file in your account
  and install it with `docker compose run --rm -T server license - < hangar-license-2026-11-17.txt`
  (native: `sudo hangar-server license - < hangar-license-2026-11-17.txt`).
- **Backups:** All data lives in the Docker volume `team-data` (native: `/var/lib/hangar-server`).
  Back it up regularly as described in [docs/operations.md](docs/operations.md).
- **Updates:** run the install script again, or set `HANGAR_VERSION` in `.env` and run
  `docker compose pull && docker compose up -d`. The database is migrated automatically on
  startup.
- **HTTPS only:** Outside your own machine, Hangar only connects via `https`.

## More documentation

| Topic | File |
| --- | --- |
| Operations in detail: configuration, backups, restarts, official service | [docs/operations.md](docs/operations.md) |
| All HTTP routes | [docs/http-api.md](docs/http-api.md) |
| Account API for the app | [docs/account-api.md](docs/account-api.md) |
| Protocol of the live channel | [docs/protocol.md](docs/protocol.md) |
| Security and threat model | [docs/security.md](docs/security.md) |
| Code, building, tests, crates from the app | [docs/development.md](docs/development.md) |
| All settings with explanations | [.env.example](.env.example) |

> **Note:** The encryption scheme is the app's own protocol and has not been externally audited
> yet. Please read [docs/security.md](docs/security.md) before using it with sensitive data.

## License and security

[Elastic License 2.0](LICENSE): using, modifying and self-hosting for your own team are allowed.
Offering the server as a hosted service to others, or circumventing the seat and license check,
is not.

Please do not report security vulnerabilities publicly; follow [SECURITY.md](SECURITY.md)
instead.
