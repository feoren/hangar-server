//! Mailversand: SMTP über lettre mit TLS (STARTTLS Pflicht oder SMTPS), `log` schreibt `.eml`
//! nach `DATA_DIR/mail/`, `none` verschickt nichts. Versand außerhalb der Anfrage über eine
//! Warteschlange im Speicher mit begrenzten Wiederholungen; die Antwortzeit verrät so nicht, ob
//! eine Mail entstand. Ein Neustart verliert ungesendete Mails (Links lassen sich neu anfordern,
//! Einladungen erneut senden).

pub mod i18n;
pub mod templates;

use std::path::PathBuf;
use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tokio::sync::{mpsc, watch};

use crate::config::{Config, MailTransport, SmtpTls};
use templates::{render, MailKind};

const QUEUE: usize = 1000;
const ATTEMPTS: u32 = 3;

struct Job {
    to: Mailbox,
    message: templates::Rendered,
}

#[derive(Clone)]
pub struct Mailer {
    tx: Option<mpsc::Sender<Job>>,
    server_host: String,
}

enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    Log(PathBuf),
}

impl Mailer {
    /// Startet den Versand. Ohne Mail (`none`) bleibt der Mailer stumm.
    pub fn start(config: &Config, mut shutdown: watch::Receiver<bool>) -> Result<Mailer, String> {
        let server_host = config
            .public_url
            .split("://")
            .nth(1)
            .unwrap_or(&config.public_url)
            .to_owned();
        let transport = match config.mail_transport {
            MailTransport::None => {
                return Ok(Mailer {
                    tx: None,
                    server_host,
                })
            }
            MailTransport::Log => {
                let dir = config.data_dir.join("mail");
                std::fs::create_dir_all(&dir).map_err(|e| format!("Mailordner: {e}"))?;
                Transport::Log(dir)
            }
            MailTransport::Smtp => {
                let smtp = config.smtp.as_ref().ok_or("SMTP_HOST fehlt")?;
                let builder = match smtp.tls {
                    SmtpTls::Smtps => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host),
                    SmtpTls::Starttls => {
                        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
                    }
                }
                .map_err(|e| format!("SMTP: {e}"))?;
                let mut builder = builder
                    .port(smtp.port)
                    .timeout(Some(Duration::from_secs(20)));
                if !smtp.username.is_empty() {
                    builder = builder.credentials(Credentials::new(
                        smtp.username.clone(),
                        smtp.password.clone(),
                    ));
                }
                Transport::Smtp(builder.build())
            }
        };
        let from: Mailbox = config
            .mail_from
            .parse()
            .map_err(|e| format!("MAIL_FROM: {e}"))?;
        let (tx, mut rx) = mpsc::channel::<Job>(QUEUE);
        tokio::spawn(async move {
            loop {
                let job = tokio::select! {
                    job = rx.recv() => match job { Some(job) => job, None => break },
                    _ = shutdown.changed() => break,
                };
                deliver(&transport, &from, job).await;
            }
        });
        Ok(Mailer {
            tx: Some(tx),
            server_host,
        })
    }

    pub fn enabled(&self) -> bool {
        self.tx.is_some()
    }

    /// Reiht eine Mail ein. `false`: kein Versand eingerichtet oder Warteschlange voll.
    pub fn send(&self, to: &str, lang: &str, kind: MailKind) -> bool {
        let Some(tx) = &self.tx else { return false };
        let Ok(to) = to.parse::<Mailbox>() else {
            tracing::warn!("Empfängeradresse nicht verwendbar");
            return false;
        };
        let message = render(&kind, lang, &self.server_host);
        tx.try_send(Job { to, message }).is_ok()
    }
}

fn build(from: &Mailbox, job: &Job) -> Result<Message, lettre::error::Error> {
    Message::builder()
        .from(from.clone())
        .to(job.to.clone())
        .subject(job.message.subject.clone())
        .multipart(MultiPart::alternative_plain_html(
            job.message.text.clone(),
            job.message.html.clone(),
        ))
}

async fn deliver(transport: &Transport, from: &Mailbox, job: Job) {
    let message = match build(from, &job) {
        Ok(message) => message,
        Err(error) => {
            tracing::error!(%error, "Mail nicht baubar");
            return;
        }
    };
    for attempt in 1..=ATTEMPTS {
        let result = match transport {
            Transport::Smtp(smtp) => smtp
                .send(message.clone())
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Transport::Log(dir) => {
                let name = format!("{}-{}.eml", crate::util::now_ms(), crate::util::random_id());
                tokio::fs::write(dir.join(name), message.formatted())
                    .await
                    .map_err(|e| e.to_string())
            }
        };
        match result {
            Ok(()) => {
                tracing::info!("Mail versendet");
                return;
            }
            Err(error) => {
                tracing::warn!(attempt, %error, "Mailversand fehlgeschlagen");
                tokio::time::sleep(Duration::from_secs(5 * u64::from(attempt * attempt))).await;
            }
        }
    }
    tracing::error!("Mail nach {ATTEMPTS} Versuchen verworfen");
}
