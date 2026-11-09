//! Konfiguration aus Umgebungsvariablen (optional über `.env`). Vorlage: `.env.example`.
//! Fehlt etwas Nötiges oder ist ein Wert ungültig, startet der Server nicht.

use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

use crate::signed::{KeySet, KeySetError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    /// Offizieller Betrieb: Konten, Projekte und Plätze auf der Webseite; das Relay prüft nur
    /// deren Tickets.
    Official,
    /// Selbstbetrieb: eigene Anmeldung, Teams, Einladungen, Lizenzprüfung; stellt selbst
    /// Tickets im selben Format aus.
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTransport {
    Smtp,
    /// Mails als `.eml` unter `DATA_DIR/mail/` (Entwicklung).
    Log,
    /// Keine Mails; Einladungs- und Anmeldelinks gibt der Server an den Admin zurück.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// TLS ab dem ersten Byte (Port 465).
    Smtps,
    /// STARTTLS, Pflicht (Port 587).
    Starttls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signup {
    /// Nur bestehende Konten und eingeladene Adressen können sich anmelden.
    Invite,
    /// Jede Adresse kann ein Konto anlegen.
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

/// Woher das Relay die Widerrufsliste holt. Ausgehende Anfragen gehen nur an genau diese
/// Adresse (ohne Weiterleitungen).
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

/// `https://` mit Host und Pfad, ohne Zugangsdaten, Abfrage oder Fragment; `http://` nur zu
/// `localhost` oder `127.0.0.1` (Entwicklung, Tests).
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
    /// Öffentlicher Ursprung dieses Servers ohne Pfad, z. B. `https://team.example.org`.
    pub public_url: String,
    pub ticket_keys: KeySet,
    /// Pflichtwert für `aud` in jedem Ticket. Offiziell `hangar-relay` (so stellt die Webseite
    /// aus), im Selbstbetrieb der eigene Ursprung; `TICKET_AUDIENCE` überschreibt beides.
    pub ticket_audience: String,
    /// Offizieller Betrieb: signierte Widerrufsliste der Webseite (`docs/revocation-format.md`).
    pub revocation: Option<RevocationSource>,
    pub allowed_origins: Vec<String>,
    pub trust_proxy: bool,
    pub max_connections: usize,
    pub max_connections_per_member: usize,
    pub max_connections_per_ip: usize,
    pub connection_max_age_s: u64,
    /// Frist für das erste gültige `hello` einer neuen Verbindung (Millisekunden).
    pub hello_timeout_ms: u64,
    pub reservation_inactivity_s: u64,
    pub reservation_warn_s: u64,
    pub blob_quota_bytes: u64,
    pub transcript_retention_days: u64,
    pub log_json: bool,
    // Selbstbetrieb
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
    #[error("{0} fehlt")]
    Missing(&'static str),
    #[error("{0} ist ungültig: {1}")]
    Invalid(&'static str, String),
    #[error("{0}: {1}")]
    Keys(&'static str, KeySetError),
}

/// Zielgruppe der Tickets der Webseite (`TEAM_TICKET_AUDIENCE` dort, Vorgabe `hangar-relay`).
pub const DEFAULT_TICKET_AUDIENCE: &str = "hangar-relay";

/// Ohne gültiges `hello` innerhalb dieser Frist schließt der Server die Verbindung; so
/// belegen Verbindungen ohne Ticket keine Plätze.
pub const DEFAULT_HELLO_TIMEOUT_MS: u64 = hangar_team_protocol::close::HELLO_TIMEOUT_SECS * 1000;

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

/// Ursprung ohne Pfad und ohne Schrägstrich am Ende; nur http(s).
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
                "mindestens 32 Zeichen".into(),
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
                        "mindestens 32 Zeichen".into(),
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
            ticket_keys,
            ticket_audience,
            revocation,
            allowed_origins,
            trust_proxy: flag("TRUST_PROXY", false)?,
            max_connections: number("MAX_CONNECTIONS", 200)?,
            max_connections_per_member: number("MAX_CONNECTIONS_PER_MEMBER", 8)?,
            max_connections_per_ip: number("MAX_CONNECTIONS_PER_IP", 20)?,
            connection_max_age_s: number("CONNECTION_MAX_AGE_SECS", 600)?,
            hello_timeout_ms: DEFAULT_HELLO_TIMEOUT_MS,
            reservation_inactivity_s: number("RESERVATION_INACTIVITY_SECS", 1800)?,
            reservation_warn_s: number("RESERVATION_WARN_SECS", 300)?,
            blob_quota_bytes: number("BLOB_QUOTA_BYTES", 64 * 1024 * 1024)?,
            transcript_retention_days: number("TRANSCRIPT_RETENTION_DAYS", 90)?,
            log_json: var("LOG_FORMAT").as_deref() != Some("pretty"),
            server_secret,
            license_keys: KeySet::parse(&var("LICENSE_PUBLIC_KEYS").unwrap_or_default())
                .map_err(|e| ConfigError::Keys("LICENSE_PUBLIC_KEYS", e))?,
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

    /// Konfiguration für Tests: alles lokal, keine Mails, Datenbank in einem eigenen Temp-Ordner.
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
            ticket_keys,
            ticket_audience: match identity {
                IdentityMode::Official => DEFAULT_TICKET_AUDIENCE.into(),
                IdentityMode::Local => "http://localhost:8080".into(),
            },
            revocation: None,
            allowed_origins: Vec::new(),
            trust_proxy: false,
            max_connections: 100,
            max_connections_per_member: 8,
            max_connections_per_ip: 200,
            connection_max_age_s: 600,
            hello_timeout_ms: DEFAULT_HELLO_TIMEOUT_MS,
            reservation_inactivity_s: 1800,
            reservation_warn_s: 300,
            blob_quota_bytes: 1024 * 1024,
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

    /// Erlaubte Origins: der eigene Ursprung und die konfigurierten.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        let origin = origin.trim_end_matches('/').to_lowercase();
        origin == self.public_url || self.allowed_origins.contains(&origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ursprung() {
        assert_eq!(
            normalize_origin("https://Team.Example.org/"),
            Some("https://team.example.org".into())
        );
        assert_eq!(normalize_origin("https://a.org/pfad"), None);
        assert_eq!(normalize_origin("ftp://a.org"), None);
        assert_eq!(normalize_origin("https://user@a.org"), None);
    }
}
