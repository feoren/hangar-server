//! Mail delivery: SMTP via lettre with TLS (mandatory STARTTLS or SMTPS), `log` writes `.eml`
//! to `DATA_DIR/mail/`, `none` sends nothing. Delivery happens outside the request via an
//! in-memory queue with limited retries, so the response time does not reveal whether a mail
//! was produced. A restart loses unsent mails (links can be requested again, invitations
//! resent).

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
    /// Starts delivery. Without mail (`none`) the mailer stays silent.
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
                std::fs::create_dir_all(&dir).map_err(|e| format!("mail directory: {e}"))?;
                Transport::Log(dir)
            }
            MailTransport::Smtp => {
                let smtp = config.smtp.as_ref().ok_or("SMTP_HOST is missing")?;
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

    /// Enqueues a mail. `false`: no delivery configured or queue full.
    pub fn send(&self, to: &str, lang: &str, kind: MailKind) -> bool {
        let Some(tx) = &self.tx else { return false };
        let Ok(to) = to.parse::<Mailbox>() else {
            tracing::warn!("recipient address not usable");
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
            tracing::error!(%error, "mail could not be built");
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
                tracing::info!("mail sent");
                return;
            }
            Err(error) => {
                tracing::warn!(attempt, %error, "mail delivery failed");
                tokio::time::sleep(Duration::from_secs(5 * u64::from(attempt * attempt))).await;
            }
        }
    }
    tracing::error!("mail discarded after {ATTEMPTS} attempts");
}
