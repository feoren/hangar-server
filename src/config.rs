//! Configuration from environment variables (optionally via `.env`). Template: `.env.example`.
//! If something required is missing or a value is invalid, the server does not start.

use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

use crate::signed::{KeySet, KeySetError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    /// Official mode: accounts, projects and seats live on the website; the relay only verifies
    /// its tickets.
    Official,
    /// Self-hosting: built-in sign-in, teams, invitations, license check; issues tickets itself
    /// in the same format.
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTransport {
    Smtp,
    /// Mails as `.eml` under `DATA_DIR/mail/` (development).
    Log,
    /// No mails; the server returns invitation links and magic links to the admin.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// TLS from the first byte (port 465).
    Smtps,
    /// STARTTLS, mandatory (port 587).
    Starttls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signup {
    /// Only existing accounts and invited addresses can sign in.
    Invite,
    /// Any address can create an account.
    Open,
}

#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: SmtpTls,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"***")
            .field("tls", &self.tls)
            .finish()
    }
}

/// Where the relay fetches the revocation list from. Outgoing requests go only to exactly this
/// address (no redirects).
#[derive(Clone)]
pub struct RevocationSource {
    pub url: String,
    pub token: String,
    pub interval_s: u64,
}

impl std::fmt::Debug for RevocationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationSource")
            .field("url", &self.url)
            .field("token", &"***")
            .field("interval_s", &self.interval_s)
            .finish()
    }
}

/// `https://` with host and path, without credentials, query or fragment; `http://` only to
/// `localhost` or `127.0.0.1` (development, tests).
pub fn valid_revocation_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let plain_ok = scheme == "http" && (host == "localhost" || host == "127.0.0.1");
    (scheme == "https" || plain_ok) && !host.is_empty() && !rest.contains(['@', '?', '#', ' '])
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub database_url: String,
    pub identity: IdentityMode,
    /// Public origin of this server without path, e.g. `https://team.example.org`.
    pub public_url: String,
    /// Target for browser requests to the start page `/` (`ROOT_REDIRECT`), e.g. the product page.
    /// Empty = `/` answers with 404. Only `https://` (or `http://` for localhost).
    pub root_redirect: Option<String>,
    pub ticket_keys: KeySet,
    /// Required value for `aud` in every ticket. Official mode: `hangar-relay` (what the website
    /// issues); self-hosting: our own origin. `TICKET_AUDIENCE` overrides both.
    pub ticket_audience: String,
    /// Official mode: signed revocation list of the website (`docs/revocation-format.md`).
    pub revocation: Option<RevocationSource>,
    pub allowed_origins: Vec<String>,
    pub trust_proxy: bool,
    /// `REQUIRE_DEVICE_PROOF`: serve only protocol version 3 and newer, so every device proves
    /// possession of its signing key at `hello`. Off by default while released apps of version
    /// 1 and 2 are still in use (`docs/operations.md`).
    pub require_device_proof: bool,
    /// Whether `build` starts the relay's timer and housekeeping. Always on in operation (not
    /// read from the environment); off only in a test that drives `Relay::tick` itself.
    pub relay_timers: bool,
    pub max_connections: usize,
    pub max_connections_per_member: usize,
    pub max_connections_per_ip: usize,
    pub connection_max_age_s: u64,
    /// Deadline for the first valid `hello` of a new connection (milliseconds).
    pub hello_timeout_ms: u64,
    /// Deadline for a removed device after `device.removed` (or after its `hello`) to still send
    /// its `memberlog.get`; afterwards close 4403 (milliseconds).
    pub removed_grace_ms: u64,
    pub reservation_inactivity_s: u64,
    pub reservation_warn_s: u64,
    pub blob_quota_bytes: u64,
    /// Memory budget for the claims (`claim.set`) of one member in a team, in bytes (see
    /// `DEFAULT_CLAIM_BYTES_PER_MEMBER`); not configurable through the environment.
    pub claim_bytes_per_member: usize,
    /// Memory budget for all claims of a team, in bytes (`DEFAULT_CLAIM_BYTES_PER_TEAM`).
    pub claim_bytes_per_team: usize,
    pub transcript_retention_days: u64,
    pub log_json: bool,
    // Self-hosting
    pub server_secret: Vec<u8>,
    pub license_keys: KeySet,
    pub license_revoked: Vec<String>,
    pub signup: Signup,
    pub mail_transport: MailTransport,
    pub mail_from: String,
    pub smtp: Option<SmtpConfig>,
    pub default_lang: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("identity", &self.identity)
            .field("public_url", &self.public_url)
            .field("ticket_keys", &self.ticket_keys)
            .field("license_keys", &self.license_keys)
            .field("mail_transport", &self.mail_transport)
            .field("smtp", &self.smtp)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0} is missing")]
    Missing(&'static str),
    #[error("{0} is invalid: {1}")]
    Invalid(&'static str, String),
    #[error("{0}: {1}")]
    Keys(&'static str, KeySetError),
}

/// Audience of the website's tickets (`TEAM_TICKET_AUDIENCE` there, default `hangar-relay`).
pub const DEFAULT_TICKET_AUDIENCE: &str = "hangar-relay";

/// Without a valid `hello` within this deadline the server closes the connection, so
/// connections without a ticket do not occupy seats.
pub const DEFAULT_HELLO_TIMEOUT_MS: u64 = hangar_team_protocol::close::HELLO_TIMEOUT_SECS * 1000;

/// How long a removed device may still read the membership log, so the app can verify its
/// removal against the signed entry.
pub const DEFAULT_REMOVED_GRACE_MS: u64 = 5_000;

/// Claims of one member in a team. The largest `claim.set` takes about 240 KB in memory (1000
/// files and a detail of 175,000 characters), so 4 MiB hold 17 of them; a usual claim (a few
/// dozen files, a few KiB of detail) needs a few KiB, so the 64 sessions per device stay far
/// below it.
pub const DEFAULT_CLAIM_BYTES_PER_MEMBER: usize = 4 * 1024 * 1024;

/// Claims of a whole team: eight members at the member budget. Without it, 2000 sessions of
/// the largest kind would hold about 480 MB.
pub const DEFAULT_CLAIM_BYTES_PER_TEAM: usize = 32 * 1024 * 1024;

fn var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn number<T: std::str::FromStr>(name: &'static str, default: T) -> Result<T, ConfigError> {
    match var(name) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|_| ConfigError::Invalid(name, v)),
    }
}

fn flag(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match var(name).as_deref() {
        None => Ok(default),
        Some("true" | "1" | "yes") => Ok(true),
        Some("false" | "0" | "no") => Ok(false),
        Some(v) => Err(ConfigError::Invalid(name, v.to_owned())),
    }
}

/// Validates the target of `ROOT_REDIRECT`: absolute URL with `https://` (or `http://` only for
/// localhost or 127.0.0.1), ASCII only (Unicode hosts as Punycode), no whitespace or
/// control characters, at most 2048 characters.
pub fn parse_redirect(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() > 2048
        || !raw.is_ascii()
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let rest = if let Some(rest) = raw.strip_prefix("https://") {
        rest
    } else {
        let rest = raw.strip_prefix("http://")?;
        let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
        if host != "localhost" && host != "127.0.0.1" {
            return None;
        }
        rest
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') {
        return None;
    }
    Some(raw.to_owned())
}

/// Origin without path and without trailing slash; http(s) only.
pub fn normalize_origin(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_end_matches('/');
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return None;
    }
    Some(raw.to_lowercase())
}

/// Memory the process needs besides its connections (teams, database, buffers).
const MEMORY_RESERVE: u64 = 64 * 1024 * 1024;
/// Memory to plan per live connection (docs/protocol.md, "Memory per connection").
const MEMORY_PER_CONNECTION: u64 = 2 * 1024 * 1024;

/// Connections that fit into `limit` bytes of memory.
pub fn connections_for_memory(limit: u64) -> u64 {
    limit.saturating_sub(MEMORY_RESERVE) / MEMORY_PER_CONNECTION
}

/// A warning when `MAX_CONNECTIONS` exceeds what the memory limit holds: then the process would
/// be killed for lack of memory instead of rejecting connections with 503.
pub fn memory_warning(max_connections: usize, limit: Option<u64>) -> Option<String> {
    let limit = limit?;
    let fits = connections_for_memory(limit);
    (max_connections as u64 > fits).then(|| {
        format!(
            "MAX_CONNECTIONS={max_connections} exceeds the memory limit of {} MiB, which holds about {fits} connections; set MAX_CONNECTIONS={fits} or raise the limit",
            limit / (1024 * 1024)
        )
    })
}

/// Content of cgroup v2 `memory.max`: bytes, or `max` for no limit.
pub fn parse_memory_max(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// The memory limit of this process's cgroup (container or systemd `MemoryMax`), if any.
pub fn memory_limit() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|text| parse_memory_max(&text))
}

/// Keys for license documents: `raw` (`LICENSE_PUBLIC_KEYS`) or, when empty, the official
/// website's key.
pub fn license_keys_from(raw: &str) -> Result<KeySet, ConfigError> {
    let raw = match raw.trim() {
        "" => crate::license::OFFICIAL_LICENSE_KEYS,
        set => set,
    };
    KeySet::parse(raw).map_err(|e| ConfigError::Keys("LICENSE_PUBLIC_KEYS", e))
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let data_dir = PathBuf::from(var("DATA_DIR").unwrap_or_else(|| "/data".into()));
        let identity = match var("IDENTITY").as_deref() {
            None | Some("official") => IdentityMode::Official,
            Some("local") => IdentityMode::Local,
            Some(v) => return Err(ConfigError::Invalid("IDENTITY", v.into())),
        };
        let bind = var("BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| ConfigError::Invalid("BIND_ADDR", var("BIND_ADDR").unwrap_or_default()))?;
        let public_url = match var("PUBLIC_URL") {
            Some(v) => match normalize_origin(&v) {
                Some(o) => o,
                None => return Err(ConfigError::Invalid("PUBLIC_URL", v)),
            },
            None => return Err(ConfigError::Missing("PUBLIC_URL")),
        };
        let ticket_keys = KeySet::parse(&var("TICKET_PUBLIC_KEYS").unwrap_or_default())
            .map_err(|e| ConfigError::Keys("TICKET_PUBLIC_KEYS", e))?;
        if identity == IdentityMode::Official && ticket_keys.is_empty() {
            return Err(ConfigError::Missing("TICKET_PUBLIC_KEYS"));
        }
        let mut allowed_origins = Vec::new();
        for o in var("ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|o| !o.is_empty())
        {
            allowed_origins.push(
                normalize_origin(o)
                    .ok_or_else(|| ConfigError::Invalid("ALLOWED_ORIGINS", o.into()))?,
            );
        }
        let server_secret = var("SERVER_SECRET").unwrap_or_default().into_bytes();
        if identity == IdentityMode::Local && server_secret.len() < 32 {
            return Err(ConfigError::Invalid(
                "SERVER_SECRET",
                "at least 32 characters".into(),
            ));
        }
        let mail_transport = match var("MAIL_TRANSPORT").as_deref() {
            None | Some("none") => MailTransport::None,
            Some("log") => MailTransport::Log,
            Some("smtp") => MailTransport::Smtp,
            Some(v) => return Err(ConfigError::Invalid("MAIL_TRANSPORT", v.into())),
        };
        let smtp = if mail_transport == MailTransport::Smtp {
            let tls = match var("SMTP_TLS").as_deref() {
                None | Some("starttls") => SmtpTls::Starttls,
                Some("smtps") => SmtpTls::Smtps,
                Some(v) => return Err(ConfigError::Invalid("SMTP_TLS", v.into())),
            };
            Some(SmtpConfig {
                host: var("SMTP_HOST").ok_or(ConfigError::Missing("SMTP_HOST"))?,
                port: number("SMTP_PORT", if tls == SmtpTls::Smtps { 465 } else { 587 })?,
                username: var("SMTP_USERNAME").unwrap_or_default(),
                password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
                tls,
            })
        } else {
            None
        };
        let mail_from = var("MAIL_FROM").unwrap_or_else(|| "Hangar <noreply@localhost>".into());
        if mail_transport != MailTransport::None
            && mail_from.parse::<lettre::message::Mailbox>().is_err()
        {
            return Err(ConfigError::Invalid("MAIL_FROM", mail_from));
        }
        let default_lang = var("DEFAULT_LANG").unwrap_or_else(|| "en".into());
        if !crate::mail::i18n::LANGS.contains(&default_lang.as_str()) {
            return Err(ConfigError::Invalid("DEFAULT_LANG", default_lang));
        }
        let ticket_audience = var("TICKET_AUDIENCE").unwrap_or_else(|| match identity {
            IdentityMode::Official => DEFAULT_TICKET_AUDIENCE.to_owned(),
            IdentityMode::Local => public_url.clone(),
        });
        if !crate::util::is_opaque(&ticket_audience, 256) {
            return Err(ConfigError::Invalid("TICKET_AUDIENCE", ticket_audience));
        }
        let revocation = match var("REVOCATION_URL") {
            None => None,
            Some(url) => {
                if !valid_revocation_url(&url) {
                    return Err(ConfigError::Invalid("REVOCATION_URL", url));
                }
                let token = std::env::var("RELAY_REVOCATION_TOKEN").unwrap_or_default();
                if token.trim().len() < 32 {
                    return Err(ConfigError::Invalid(
                        "RELAY_REVOCATION_TOKEN",
                        "at least 32 characters".into(),
                    ));
                }
                Some(RevocationSource {
                    url,
                    token: token.trim().to_owned(),
                    interval_s: number("REVOCATION_INTERVAL_SECS", 15)?.max(1),
                })
            }
        };
        let database_url = format!("sqlite://{}", data_dir.join("hangar-team.db").display());
        Ok(Config {
            bind,
            data_dir,
            database_url,
            identity,
            public_url,
            root_redirect: match var("ROOT_REDIRECT") {
                None => None,
                Some(v) => Some(
                    parse_redirect(&v).ok_or(ConfigError::Invalid("ROOT_REDIRECT", v.clone()))?,
                ),
            },
            ticket_keys,
            ticket_audience,
            revocation,
            allowed_origins,
            trust_proxy: flag("TRUST_PROXY", false)?,
            require_device_proof: flag("REQUIRE_DEVICE_PROOF", false)?,
            relay_timers: true,
            max_connections: number("MAX_CONNECTIONS", 200)?,
            max_connections_per_member: number("MAX_CONNECTIONS_PER_MEMBER", 8)?,
            max_connections_per_ip: number("MAX_CONNECTIONS_PER_IP", 20)?,
            connection_max_age_s: number("CONNECTION_MAX_AGE_SECS", 600)?,
            hello_timeout_ms: DEFAULT_HELLO_TIMEOUT_MS,
            removed_grace_ms: DEFAULT_REMOVED_GRACE_MS,
            reservation_inactivity_s: number("RESERVATION_INACTIVITY_SECS", 1800)?,
            reservation_warn_s: number("RESERVATION_WARN_SECS", 300)?,
            blob_quota_bytes: number("BLOB_QUOTA_BYTES", 64 * 1024 * 1024)?,
            claim_bytes_per_member: DEFAULT_CLAIM_BYTES_PER_MEMBER,
            claim_bytes_per_team: DEFAULT_CLAIM_BYTES_PER_TEAM,
            transcript_retention_days: number("TRANSCRIPT_RETENTION_DAYS", 90)?,
            log_json: var("LOG_FORMAT").as_deref() != Some("pretty"),
            server_secret,
            license_keys: license_keys_from(&var("LICENSE_PUBLIC_KEYS").unwrap_or_default())?,
            license_revoked: var("LICENSE_REVOKED")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
            signup: match var("SIGNUP").as_deref() {
                None | Some("invite") => Signup::Invite,
                Some("open") => Signup::Open,
                Some(v) => return Err(ConfigError::Invalid("SIGNUP", v.into())),
            },
            mail_transport,
            mail_from,
            smtp,
            default_lang,
        })
    }

    /// Configuration for tests: everything local, no mails, database in its own temp directory.
    pub fn for_tests(identity: IdentityMode, ticket_keys: KeySet) -> Self {
        let data_dir =
            std::env::temp_dir().join(format!("hangar-team-test-{}", crate::util::random_id()));
        let database_url = format!("sqlite://{}", data_dir.join("hangar-team.db").display());
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            data_dir,
            database_url,
            identity,
            public_url: "http://localhost:8080".into(),
            root_redirect: None,
            ticket_keys,
            ticket_audience: match identity {
                IdentityMode::Official => DEFAULT_TICKET_AUDIENCE.into(),
                IdentityMode::Local => "http://localhost:8080".into(),
            },
            revocation: None,
            allowed_origins: Vec::new(),
            trust_proxy: false,
            require_device_proof: false,
            relay_timers: true,
            max_connections: 100,
            max_connections_per_member: 8,
            max_connections_per_ip: 200,
            connection_max_age_s: 600,
            hello_timeout_ms: DEFAULT_HELLO_TIMEOUT_MS,
            // Shorter than in production so the tests do not wait long for the deadline to expire.
            removed_grace_ms: 1_000,
            reservation_inactivity_s: 1800,
            reservation_warn_s: 300,
            blob_quota_bytes: 1024 * 1024,
            claim_bytes_per_member: DEFAULT_CLAIM_BYTES_PER_MEMBER,
            claim_bytes_per_team: DEFAULT_CLAIM_BYTES_PER_TEAM,
            transcript_retention_days: 90,
            log_json: false,
            server_secret: b"test-secret-test-secret-test-secret!".to_vec(),
            license_keys: KeySet::default(),
            license_revoked: Vec::new(),
            signup: Signup::Invite,
            mail_transport: MailTransport::None,
            mail_from: "Hangar <noreply@localhost>".into(),
            smtp: None,
            default_lang: "en".into(),
        }
    }

    pub fn is_https(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    /// Allowed origins: our own origin and the configured ones.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        let origin = origin.trim_end_matches('/').to_lowercase();
        origin == self.public_url || self.allowed_origins.contains(&origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin() {
        assert_eq!(
            normalize_origin("https://Team.Example.org/"),
            Some("https://team.example.org".into())
        );
        assert_eq!(normalize_origin("https://a.org/path"), None);
        assert_eq!(normalize_origin("ftp://a.org"), None);
        assert_eq!(normalize_origin("https://user@a.org"), None);
    }

    #[test]
    fn root_redirect() {
        assert_eq!(
            parse_redirect("https://hangar.feoren.com/"),
            Some("https://hangar.feoren.com/".into())
        );
        assert_eq!(
            parse_redirect("http://localhost:8000/path"),
            Some("http://localhost:8000/path".into())
        );
        assert_eq!(parse_redirect("http://example.org/"), None);
        assert_eq!(parse_redirect("javascript:alert(1)"), None);
        assert_eq!(parse_redirect("//evil.example"), None);
        assert_eq!(parse_redirect("https://"), None);
        assert_eq!(parse_redirect("https://user@evil.example/"), None);
        assert_eq!(
            parse_redirect(
                "https://a.org/
Set-Cookie: x"
            ),
            None
        );
        assert_eq!(parse_redirect("https://a.org/ x"), None);
        assert_eq!(parse_redirect("https://bücher.example/"), None);
        assert_eq!(parse_redirect(r"https://a.org\@evil.example/"), None);
        assert_eq!(parse_redirect("http://localhost.evil.example/"), None);
    }

    #[test]
    fn connections_that_exceed_the_memory_limit_are_reported() {
        let mib = 1024 * 1024;
        assert_eq!(connections_for_memory(512 * mib), 224);
        assert!(
            memory_warning(200, Some(512 * mib)).is_none(),
            "the defaults fit"
        );
        assert!(memory_warning(20_000, Some(512 * mib)).is_some());
        assert!(memory_warning(150, Some(512 * mib)).is_none());
        assert!(memory_warning(20_000, None).is_none(), "no limit known");
    }

    #[test]
    fn cgroup_memory_limit_is_parsed() {
        assert_eq!(
            parse_memory_max(
                "536870912
"
            ),
            Some(536_870_912)
        );
        assert_eq!(
            parse_memory_max(
                "max
"
            ),
            None
        );
        assert_eq!(parse_memory_max("garbage"), None);
    }

    #[test]
    fn license_keys_default_to_official() {
        for raw in ["", "  "] {
            let keys = license_keys_from(raw).unwrap();
            assert!(keys.kids().any(|kid| kid == "prod-20261109"), "{raw:?}");
        }
    }

    #[test]
    fn license_keys_env_replaces_default() {
        let keys = license_keys_from("t1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(keys.kids().any(|kid| kid == "t1"));
        assert!(!keys.kids().any(|kid| kid == "prod-20261109"));
    }
}
