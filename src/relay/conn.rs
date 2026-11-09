//! Eine WebSocket-Verbindung: der einzige Live-Kanal. Ping alle 25 s, Trennung nach 60 s ohne
//! Lebenszeichen, `hello` binnen 15 s, Ratenbegrenzung je Verbindung, Grenzen je Mitglied und
//! je Client-Adresse, Höchstalter (danach neues Ticket nötig).
//!
//! Ein entferntes Gerät (`device.removed`, oder sein `hello` nach der Sperre) bekommt eine kurze
//! Frist (`Relay::removed_grace`, Vorgabe 5 s), in der die Verbindung nur noch `memberlog.get`
//! beantwortet bekommt, mit Einträgen bis zu dem, der es entfernte; alles andere wird mit
//! `err forbidden` abgelehnt und schreibt nichts. Nach der letzten Seite oder mit Ablauf der Frist
//! Close 4403. So prüft die App ihre Entfernung am signierten Eintrag und kommt mit einer neuen
//! Geräte-ID zurück.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{FutureExt, SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex, Notify};

use super::team::{close, Joined as JoinOutcome, Outgoing, Subscriber, Team};
use super::{Relay, RenewRefused};
use crate::http::{AppState, ClientIp};
use crate::util::now_ms;
use crate::wire::{
    self, ack, error, limits::MAX_FRAME_BYTES, ClientMessage, ErrorBody, ErrorCode, Holder,
    MemberId, OpId, ServerFrame, ServerMessage, TeamId,
};

pub const PING_INTERVAL: Duration = Duration::from_secs(25);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Ausgehende Rahmen je Verbindung, bevor sie als zu langsam gilt.
const QUEUE: usize = 512;
const BURST: f64 = 120.0;
const PER_SECOND: f64 = 30.0;
const MAX_BAD_FRAMES: u32 = 20;

/// `GET /v1/live`: Upgrade auf WebSocket. Mit `Origin` nur aus der Liste erlaubter Ursprünge
/// (die App sendet keinen; ein Browser auf fremder Seite wird so abgewiesen). Zu viele
/// Verbindungen gesamt oder von einer Adresse: 503.
pub async fn upgrade(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Some(origin) = headers.get("origin").and_then(|o| o.to_str().ok()) {
        if !state.config.origin_allowed(origin) {
            return (StatusCode::FORBIDDEN, "origin").into_response();
        }
    }
    let ip_key = ip.key();
    if !state.relay.acquire_ip(&ip_key) {
        tracing::info!("zu viele Verbindungen von einer Adresse");
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    }
    if !state.relay.acquire_connection() {
        state.relay.release_ip(&ip_key);
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    }
    let relay = state.relay.clone();
    let shutdown = state.shutdown.clone();
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_failed_upgrade({
            let relay = relay.clone();
            let ip_key = ip_key.clone();
            move |_| {
                relay.release_connection();
                relay.release_ip(&ip_key);
            }
        })
        .on_upgrade(move |socket| async move {
            run(socket, relay.clone(), shutdown).await;
            relay.release_connection();
            relay.release_ip(&ip_key);
        })
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self) -> Result<(), u64> {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.at).as_secs_f64() * PER_SECOND).min(BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        Err(((1.0 - self.tokens) / PER_SECOND * 1000.0).ceil() as u64)
    }
}

struct Joined {
    team: Arc<Mutex<Team>>,
    /// Wann das Ticket dieses Teams zuletzt geprüft wurde (`hello` oder `ticket.renew`).
    ticket_at: Instant,
}

fn text(id: Option<OpId>, team: Option<TeamId>, message: ServerMessage) -> Option<Outgoing> {
    wire::encode_server(&ServerFrame {
        id,
        seq: None,
        team,
        message,
    })
    .ok()
    .map(|t| Outgoing::Text(Utf8Bytes::from(t)))
}

fn send(tx: &mpsc::Sender<Outgoing>, out: Option<Outgoing>) {
    if let Some(out) = out {
        let _ = tx.try_send(out);
    }
}

fn err(id: Option<OpId>, team: Option<TeamId>, body: ErrorBody) -> Option<Outgoing> {
    text(id, team, ServerMessage::Err(body))
}

async fn run(
    socket: WebSocket,
    relay: Arc<Relay>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let conn = relay.next_conn();
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Outgoing>(QUEUE);
    let kick = Arc::new(Notify::new());
    let removed = Arc::new(Notify::new());

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                next = rx.recv() => match next {
                    Some(Outgoing::Text(t)) => {
                        if sink.send(Message::Text(t)).await.is_err() { break; }
                    }
                    Some(Outgoing::Close(code, reason)) => {
                        let _ = sink.send(Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from_static(reason) }))).await;
                        break;
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Default::default())).await.is_err() { break; }
                }
            }
        }
        let _ = sink.close().await;
    });

    let started = Instant::now();
    let mut member: Option<String> = None;
    let mut joined: HashMap<String, Joined> = HashMap::new();
    let mut bucket = Bucket {
        tokens: BURST,
        at: Instant::now(),
    };
    let mut bad = 0u32;
    // Frist eines entfernten Geräts (siehe Moduldoku); `Some`: nur noch `memberlog.get`.
    let mut departing: Option<Instant> = None;
    let close: Option<(u16, &'static str)> = loop {
        // Höchstalter je Team ab dem letzten geprüften Ticket; `ticket.renew` startet es neu.
        let oldest = joined
            .values()
            .map(|j| j.ticket_at)
            .min()
            .unwrap_or(started);
        let age_left = relay.connection_max_age.saturating_sub(oldest.elapsed());
        // Bis zum ersten gültigen `hello` gilt eine kurze Frist: Pings allein halten keinen
        // Verbindungsplatz.
        let hello_left = joined
            .is_empty()
            .then(|| relay.hello_timeout.saturating_sub(started.elapsed()));
        let hello_deadline = async move {
            match hello_left {
                Some(left) => tokio::time::sleep(left).await,
                None => std::future::pending::<()>().await,
            }
        };
        let grace_deadline = async move {
            match departing {
                Some(until) => tokio::time::sleep_until(until.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        let next = tokio::select! {
            next = tokio::time::timeout(IDLE_TIMEOUT, stream.next()) => next,
            _ = kick.notified() => break Some((1013, "slow consumer")),
            _ = tokio::time::sleep(age_left) => break Some((close::CLOSE_ROLE_CHANGED, "ticket renewal")),
            _ = hello_deadline => break Some((close::CLOSE_HELLO_TIMEOUT, "hello required")),
            _ = grace_deadline => break Some((close::CLOSE_REMOVED, "device removed")),
            _ = removed.notified(), if departing.is_none() => {
                departing = Some(Instant::now() + relay.removed_grace);
                continue;
            }
            _ = shutdown.changed() => break Some((1012, "restart")),
        };
        let message = match next {
            Err(_) => break Some((1001, "idle")),
            Ok(None) | Ok(Some(Err(_))) => break None,
            Ok(Some(Ok(message))) => message,
        };
        let raw = match message {
            Message::Text(t) => t,
            Message::Close(_) => break None,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Binary(_) => {
                send(&tx, err(None, None, error(ErrorCode::BadRequest)));
                continue;
            }
        };
        if let Err(wait) = bucket.take() {
            let body = ErrorBody {
                code: ErrorCode::RateLimited,
                retry_after_ms: Some(wait),
                holder: None,
            };
            send(&tx, err(None, None, body));
            continue;
        }
        let frame = match wire::decode_client(raw.as_str()) {
            Ok(frame) => frame,
            Err(decode) => {
                bad += 1;
                send(&tx, err(None, None, error(decode.code())));
                if bad > MAX_BAD_FRAMES {
                    break Some((close::CLOSE_HELLO_TIMEOUT, "bad frames"));
                }
                continue;
            }
        };
        let op = frame.id;
        let team_id = frame.team;
        // Kam die Entfernung zugleich mit diesem Rahmen, wählt `select!` nicht verlässlich
        // zuerst sie: ein schon ausgelöstes `removed` gilt vor dem Rahmen.
        if departing.is_none() && removed.notified().now_or_never().is_some() {
            departing = Some(Instant::now() + relay.removed_grace);
        }
        if departing.is_some() {
            // In der Frist: nur `memberlog.get` des Teams, das das Gerät entfernte.
            let ClientMessage::MemberLogGet(get) = frame.message else {
                send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden)));
                continue;
            };
            let entry = team_id
                .as_ref()
                .and_then(|t| joined.get(t.as_str()))
                .map(|j| j.team.clone());
            let Some(team) = entry else {
                send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden)));
                continue;
            };
            let answered = team
                .lock()
                .await
                .departing_log_get(&relay.db, conn, &op, get.after)
                .await;
            match answered {
                Ok(Some(true)) => break Some((close::CLOSE_REMOVED, "device removed")),
                Ok(Some(false)) => {}
                Ok(None) => send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden))),
                Err(failure) => {
                    tracing::error!(error = %failure, "Log für entferntes Gerät nicht lesbar");
                    send(&tx, err(Some(op), team_id, error(ErrorCode::BadRequest)));
                }
            }
            continue;
        }
        match frame.message {
            ClientMessage::Ping => send(&tx, text(Some(op), team_id, ServerMessage::Ack(ack()))),
            ClientMessage::Hello(hello) => {
                let Some(team_id) = team_id else { continue };
                let reply_err = |code| err(Some(op.clone()), Some(team_id.clone()), error(code));
                if joined.contains_key(team_id.as_str()) {
                    send(&tx, reply_err(ErrorCode::BadRequest));
                    continue;
                }
                let (claims, proto) = match relay
                    .check_hello(
                        hello.ticket.as_str(),
                        team_id.as_str(),
                        hello.device.as_str(),
                        hello.proto,
                    )
                    .await
                {
                    Ok(ok) => ok,
                    Err(code) => {
                        send(&tx, reply_err(code));
                        // Abgelehnte Tickets zählen wie kaputte Rahmen (kein Raten am Stück).
                        bad += 1;
                        if bad > MAX_BAD_FRAMES {
                            break Some((close::CLOSE_HELLO_TIMEOUT, "bad frames"));
                        }
                        continue;
                    }
                };
                let Ok(member_id) = MemberId::new(claims.sub.clone()) else {
                    send(&tx, reply_err(ErrorCode::Forbidden));
                    continue;
                };
                // Eine Verbindung gehört genau einem Mitglied.
                match &member {
                    Some(m) if *m != claims.sub => {
                        send(&tx, reply_err(ErrorCode::Forbidden));
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        if !relay.acquire_member(&claims.sub) {
                            send(&tx, reply_err(ErrorCode::Limit));
                            continue;
                        }
                        member = Some(claims.sub.clone());
                    }
                }
                let team = match relay.team(team_id.as_str()).await {
                    Ok(team) => team,
                    Err(failure) => {
                        tracing::error!(error = %failure, "Team nicht ladbar");
                        send(&tx, reply_err(ErrorCode::BadRequest));
                        continue;
                    }
                };
                let sub = Subscriber {
                    holder: Holder {
                        member: member_id,
                        device: hello.device.clone(),
                    },
                    role: claims.role,
                    tx: tx.clone(),
                    kick: kick.clone(),
                    removed: removed.clone(),
                };
                let iat_ms = u64::try_from(claims.iat).unwrap_or(0).saturating_mul(1000);
                let result = {
                    let mut guard = team.lock().await;
                    let result = guard
                        .join(
                            &relay.db,
                            conn,
                            &op,
                            sub,
                            hello.last_seq.as_ref(),
                            proto,
                            iat_ms,
                            now_ms(),
                            // Nur eine Verbindung ohne anderes Team: ihr 4403 trifft kein
                            // Team, aus dem das Gerät nicht entfernt wurde.
                            joined.is_empty(),
                        )
                        .await;
                    relay.forward_attention(&mut guard);
                    result
                };
                match result {
                    Ok(Ok(outcome)) => {
                        if outcome == JoinOutcome::Departing {
                            departing = Some(Instant::now() + relay.removed_grace);
                        } else {
                            tracing::info!(conn, "Gerät angemeldet");
                        }
                        joined.insert(
                            team_id.as_str().to_owned(),
                            Joined {
                                team,
                                ticket_at: Instant::now(),
                            },
                        );
                    }
                    Ok(Err(code)) => send(&tx, reply_err(code)),
                    Err(failure) => {
                        tracing::error!(error = %failure, "Anmeldung im Team fehlgeschlagen");
                        send(&tx, reply_err(ErrorCode::BadRequest));
                    }
                }
            }
            ClientMessage::TicketRenew(renew) => {
                let Some(team_id) = team_id else { continue };
                let (Some(entry), Some(member)) =
                    (joined.get_mut(team_id.as_str()), member.as_ref())
                else {
                    send(
                        &tx,
                        err(Some(op), Some(team_id), error(ErrorCode::BadRequest)),
                    );
                    continue;
                };
                match relay
                    .check_renew(renew.ticket.as_str(), team_id.as_str(), member)
                    .await
                {
                    Ok(claims) => {
                        entry.ticket_at = Instant::now();
                        let applied = match MemberId::new(claims.sub.clone()) {
                            Ok(member_id) => {
                                let mut guard = entry.team.lock().await;
                                guard
                                    .apply_role(&relay.db, &member_id, claims.role, now_ms())
                                    .await
                            }
                            Err(_) => Ok(()),
                        };
                        match applied {
                            Ok(()) => send(
                                &tx,
                                text(Some(op), Some(team_id), ServerMessage::Ack(ack())),
                            ),
                            Err(failure) => {
                                tracing::error!(error = %failure, "Rolle nicht übernommen");
                                send(
                                    &tx,
                                    err(Some(op), Some(team_id), error(ErrorCode::BadRequest)),
                                );
                            }
                        }
                    }
                    Err(RenewRefused::OtherTeam) => {
                        send(
                            &tx,
                            err(Some(op), Some(team_id), error(ErrorCode::Forbidden)),
                        );
                        break Some((close::CLOSE_REMOVED, "ticket for another team"));
                    }
                    Err(RenewRefused::Removed) => break Some((close::CLOSE_REMOVED, "no access")),
                    Err(RenewRefused::Stale) => {
                        break Some((close::CLOSE_ROLE_CHANGED, "ticket predates role change"))
                    }
                    Err(RenewRefused::Failed) => {
                        send(
                            &tx,
                            err(Some(op), Some(team_id), error(ErrorCode::BadRequest)),
                        );
                    }
                }
            }
            other => {
                let Some(team_id) = team_id else { continue };
                let Some(entry) = joined.get(team_id.as_str()) else {
                    send(
                        &tx,
                        err(Some(op), Some(team_id), error(ErrorCode::Forbidden)),
                    );
                    continue;
                };
                let mut guard = entry.team.lock().await;
                if let Err(failure) = guard
                    .handle(&relay.db, &relay.limits, conn, &op, other, now_ms())
                    .await
                {
                    tracing::error!(error = %failure, "Absicht nicht verarbeitet");
                    drop(guard);
                    send(
                        &tx,
                        err(Some(op), Some(team_id), error(ErrorCode::BadRequest)),
                    );
                    continue;
                }
                relay.forward_attention(&mut guard);
            }
        }
    };

    for (_, entry) in joined.drain() {
        let mut guard = entry.team.lock().await;
        if let Err(failure) = guard.leave(&relay.db, conn, now_ms()).await {
            tracing::error!(error = %failure, "Abmelden im Team fehlgeschlagen");
        }
        relay.forward_attention(&mut guard);
    }
    if let Some(member) = member {
        relay.release_member(&member);
    }
    if let Some((code, reason)) = close {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            tx.send(Outgoing::Close(code, reason)),
        )
        .await;
    }
    drop(tx);
    // Ein Gegenüber, das nicht mehr liest, hält den Schreiber nicht ewig fest.
    let abort = writer.abort_handle();
    if tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .is_err()
    {
        abort.abort();
    }
}
