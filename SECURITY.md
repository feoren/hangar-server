# Security Policy

The team server holds accounts, sessions and invitations in self-hosted mode and relays the
end-to-end encrypted data of teams, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue.** Use GitHub's
[private vulnerability reporting](../../security/advisories/new) instead. Include the server
version (`GET /health`), the mode (`IDENTITY=local` or `official`), steps to reproduce and the
impact you expect.

You will get an initial response within a week. Once a fix is released, the advisory is published
with credit to you unless you prefer otherwise.

## Supported versions

Only the latest version on `main` receives security fixes.

## Scope

In scope, for example:

- getting a relay ticket, a session or team access without being entitled to it
- bypassing the checks of the membership log, key rotation or key packages before they are stored
- reading or changing another team's data on the relay
- bypassing rate limits, connection limits or the license check
- secrets (tokens, keys, magic links) leaking into logs, responses or mails

Out of scope: the cryptography of the end-to-end scheme itself, which lives in the
[Hangar app](https://github.com/feoren/hangar) and is reported there, and vulnerabilities in the
desktop app. The threat model and known limits are in [docs/security.md](docs/security.md).
