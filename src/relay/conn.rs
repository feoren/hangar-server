//! One WebSocket connection: the only live channel. Ping every 25 s, disconnect after 60 s
//! without a sign of life, `hello` within 15 s, rate limiting per connection, limits per member
//! and per client address, maximum age (a new ticket is needed afterwards).
//!
//! A removed device (`device.removed`, or its `hello` after the block) gets a short grace period
//! (`Relay::removed_grace`, default 5 s) per team: in that team the connection only gets answers
//! to `memberlog.get`, with entries up to the one that removed it; everything else for that team
//! is rejected with `err forbidden` and writes nothing. Other teams of the connection are not
//! affected. After the last page or when the grace period expires, the connection leaves that
//! team; close 4403 only when no team is left (while every team is in its grace period, frames
//! without a team such as `ping` are rejected as well). This way the app verifies its removal
//! against the signed entry and comes back with a new device ID.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex, Notify};

use super::outbox::{outbox, Outbox};
use super::team::{close, Handled, Joined as JoinOutcome, Outgoing, Subscriber, Team};
use super::{Relay, RenewRefused};
use crate::http::{AppState, ClientIp};
use crate::util::now_ms;
use crate::wire::{
    self, ack, error, limits::MAX_FRAME_BYTES, ClientMessage, ErrorBody, ErrorCode, Holder,
    MemberId, OpId, ServerFrame, ServerMessage, TeamId, MIN_PROTOCOL_VERSION,
};

pub const PING_INTERVAL: Duration = Duration::from_secs(25);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const BURST: f64 = 120.0;
const PER_SECOND: f64 = 30.0;
const MAX_BAD_FRAMES: u32 = 20;

/// `GET /v1/live`: upgrade to WebSocket. With `Origin` only from the list of allowed origins
/// (the app sends none; a browser on a foreign site is rejected this way). Too many connections
/// in total or from one address: 503.
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
        tracing::info!("too many connections from one address");
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    }
    if !state.relay.acquire_connection() {
        state.relay.release_ip(&ip_key);
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    }
    // Until its first valid `hello` the connection also holds a slot of the smaller quota for
    // connections that have not signed in (`run` frees it); newer ones push the oldest out.
    let Some((waiting, pushed_out)) = state.relay.acquire_before_hello(&ip.wide_key()) else {
        state.relay.release_connection();
        state.relay.release_ip(&ip_key);
        tracing::info!("too many connections without hello from one address");
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    };
    let relay = state.relay.clone();
    let shutdown = state.shutdown.clone();
    // Small buffers: tungstenite reserves 128 KiB per connection by default, which alone fills
    // 512 MiB at a few thousand idle connections. Large frames still grow them as needed.
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .on_failed_upgrade({
            let relay = relay.clone();
            let ip_key = ip_key.clone();
            move |_| {
                relay.release_before_hello(waiting);
                relay.release_connection();
                relay.release_ip(&ip_key);
            }
        })
        .on_upgrade(move |socket| async move {
            run(socket, relay.clone(), shutdown, waiting, pushed_out).await;
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
    /// When the ticket for this team was last checked (`hello` or `ticket.renew`).
    ticket_at: Instant,
    /// End of the grace period after the device was removed from this team (see module docs).
    departing: Option<Instant>,
}

/// Starts the grace period of `team` (once; a second removal does not extend it).
fn start_grace(joined: &mut HashMap<String, Joined>, team: &str, grace: Duration) {
    if let Some(entry) = joined.get_mut(team) {
        entry
            .departing
            .get_or_insert_with(|| Instant::now() + grace);
    }
}

/// The connection leaves a team (closed, grace period over, last log page read).
async fn leave(relay: &Relay, conn: u64, entry: Joined) {
    let mut guard = entry.team.lock().await;
    if let Err(failure) = guard.leave(&relay.db, conn, now_ms()).await {
        tracing::error!(error = %failure, "leaving the team failed");
    }
    relay.forward_attention(&mut guard);
}

/// A frame sent here, outside the team (answers before or without a joined team), may not
/// depend on a negotiated version: only kinds every supported version knows.
fn text(id: Option<OpId>, team: Option<TeamId>, message: ServerMessage) -> Option<Outgoing> {
    if message.since() > MIN_PROTOCOL_VERSION {
        tracing::error!(
            kind = message.kind(),
            "kind newer than the oldest version not sent"
        );
        return None;
    }
    wire::encode_server(&ServerFrame {
        id,
        seq: None,
        team,
        message,
    })
    .ok()
    .map(|t| Outgoing::Text(Utf8Bytes::from(t)))
}

fn send(tx: &Outbox, out: Option<Outgoing>) {
    if let Some(out) = out {
        // A full queue kicks the connection (see `outbox`).
        tx.try_send(out);
    }
}

fn err(id: Option<OpId>, team: Option<TeamId>, body: ErrorBody) -> Option<Outgoing> {
    text(id, team, ServerMessage::Err(body))
}

async fn run(
    socket: WebSocket,
    relay: Arc<Relay>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    waiting: u64,
    pushed_out: Arc<Notify>,
) {
    let conn = relay.next_conn();
    let (mut sink, mut stream) = socket.split();
    let kick = Arc::new(Notify::new());
    let (tx, mut rx) = outbox(kick.clone());
    // Teams that removed this device; the team sends its ID (see `Team::drop_device`).
    let (removed, mut removed_rx) = mpsc::unbounded_channel::<String>();
    // The writer ends once the connection is closed or broken (a close frame of the team, a
    // failed send): then the reading side stops as well instead of holding its teams until the
    // idle timeout while a client keeps the socket open without answering.
    let writer_done = Arc::new(Notify::new());
    let done = writer_done.clone();

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                next = rx.recv() => match next {
                    Some(Outgoing::Text(t)) => {
                        if sink.send(Message::Text(t)).await.is_err() { break; }
                    }
                    Some(Outgoing::Batch(frames)) => {
                        let mut sent = Ok(());
                        for t in frames {
                            sent = sink.feed(Message::Text(t)).await;
                            if sent.is_err() { break; }
                        }
                        if sent.is_err() || sink.flush().await.is_err() { break; }
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
        // Before `close`: a peer that no longer reads can hold `close` up, the reader stops now.
        done.notify_one();
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
    // Still holds a slot of the quota before `hello` (see `upgrade`).
    let mut before_hello = true;
    let close: Option<(u16, &'static str)> = loop {
        // Maximum age per team since the last checked ticket; `ticket.renew` restarts it.
        let oldest = joined
            .values()
            .map(|j| j.ticket_at)
            .min()
            .unwrap_or(started);
        let age_left = relay.connection_max_age.saturating_sub(oldest.elapsed());
        // Until the first valid `hello` a short deadline applies: pings alone do not hold a
        // connection slot.
        let hello_left = joined
            .is_empty()
            .then(|| relay.hello_timeout.saturating_sub(started.elapsed()));
        let hello_deadline = async move {
            match hello_left {
                Some(left) => tokio::time::sleep(left).await,
                None => std::future::pending::<()>().await,
            }
        };
        let grace = joined.values().filter_map(|j| j.departing).min();
        let grace_deadline = async move {
            match grace {
                Some(until) => tokio::time::sleep_until(until.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        let next = tokio::select! {
            next = tokio::time::timeout(IDLE_TIMEOUT, stream.next()) => next,
            _ = kick.notified() => break Some((1013, "slow consumer")),
            _ = writer_done.notified() => break None,
            _ = tokio::time::sleep(age_left) => break Some((close::CLOSE_ROLE_CHANGED, "ticket renewal")),
            _ = hello_deadline => break Some((close::CLOSE_HELLO_TIMEOUT, "hello required")),
            _ = pushed_out.notified(), if before_hello => break Some((close::CLOSE_HELLO_TIMEOUT, "hello required")),
            _ = grace_deadline => {
                // The connection leaves only the teams whose grace period is over.
                let now = Instant::now();
                let over: Vec<String> = joined
                    .iter()
                    .filter(|(_, j)| j.departing.is_some_and(|until| until <= now))
                    .map(|(team, _)| team.clone())
                    .collect();
                for team in over {
                    if let Some(entry) = joined.remove(&team) {
                        leave(&relay, conn, entry).await;
                    }
                }
                if joined.is_empty() {
                    break Some((close::CLOSE_REMOVED, "device removed"));
                }
                continue;
            }
            Some(team) = removed_rx.recv() => {
                start_grace(&mut joined, &team, relay.removed_grace);
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
                bad += 1;
                send(&tx, err(None, None, error(ErrorCode::BadRequest)));
                if bad > MAX_BAD_FRAMES {
                    break Some((close::CLOSE_HELLO_TIMEOUT, "bad frames"));
                }
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
        // Before signing in, only `hello` makes sense: anything else counts as a broken frame, so
        // that a connection without a ticket cannot keep the server parsing until its deadline.
        if before_hello && !matches!(frame.message, ClientMessage::Hello(_)) {
            bad += 1;
            if bad > MAX_BAD_FRAMES {
                break Some((close::CLOSE_HELLO_TIMEOUT, "bad frames"));
            }
        }
        let op = frame.id;
        let team_id = frame.team;
        // If the removal arrived together with this frame, `select!` does not reliably pick it
        // first: an already reported removal takes precedence over the frame.
        while let Ok(team) = removed_rx.try_recv() {
            start_grace(&mut joined, &team, relay.removed_grace);
        }
        let departing = team_id
            .as_ref()
            .and_then(|t| joined.get(t.as_str()))
            .filter(|j| j.departing.is_some())
            .map(|j| j.team.clone());
        let only_departing = !joined.is_empty() && joined.values().all(|j| j.departing.is_some());
        if departing.is_some() || only_departing {
            // During the grace period of this team (or of every team): only `memberlog.get` of
            // a team that removed the device. `device.keys` and `device.prove` there get `ack`
            // without effect: the app sends both before its log fetch.
            if let (Some(team), ClientMessage::DeviceKeys(_) | ClientMessage::DeviceProve(_)) =
                (departing.as_ref(), &frame.message)
            {
                if !team.lock().await.departing_ack(conn, &op, &frame.message) {
                    send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden)));
                }
                continue;
            }
            let ClientMessage::MemberLogGet(get) = frame.message else {
                send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden)));
                continue;
            };
            let (Some(team), Some(id)) = (departing, team_id.clone()) else {
                send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden)));
                continue;
            };
            let answered = team
                .lock()
                .await
                .departing_log_get(&relay.db, conn, &op, get.after)
                .await;
            match answered {
                Ok(Some(true)) => {
                    // Last page: the connection leaves only this team.
                    if let Some(entry) = joined.remove(id.as_str()) {
                        leave(&relay, conn, entry).await;
                    }
                    if joined.is_empty() {
                        break Some((close::CLOSE_REMOVED, "device removed"));
                    }
                }
                Ok(Some(false)) => {}
                Ok(None) => send(&tx, err(Some(op), team_id, error(ErrorCode::Forbidden))),
                Err(failure) => {
                    tracing::error!(error = %failure, "cannot read log for removed device");
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
                    Ok(ok) => {
                        if std::mem::take(&mut before_hello) {
                            relay.release_before_hello(waiting);
                        }
                        ok
                    }
                    Err(code) => {
                        send(&tx, reply_err(code));
                        // Rejected tickets count like broken frames (no guessing in a row).
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
                // A connection belongs to exactly one member.
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
                        tracing::error!(error = %failure, "cannot load team");
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
                    proto,
                    tx: tx.clone(),
                    kick: kick.clone(),
                    removed: removed.clone(),
                    possession: Default::default(),
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
                            iat_ms,
                            now_ms(),
                            // Only a connection without another team: its 4403 does not hit a
                            // team the device was not removed from.
                            joined.is_empty(),
                        )
                        .await;
                    // `REQUIRE_DEVICE_PROOF` switched on after this `hello` was checked: read
                    // again under the team lock, which the switch also takes, so the
                    // connection cannot slip past it.
                    if matches!(result, Ok(Ok(JoinOutcome::Member)))
                        && proto < relay.proto_range().min()
                    {
                        if let Err(failure) = guard.require_device_proof(&relay.db, now_ms()).await
                        {
                            tracing::error!(error = %failure, "older versions not closed");
                        }
                    }
                    relay.forward_attention(&mut guard);
                    result
                };
                match result {
                    Ok(Ok(outcome)) => {
                        let departing = (outcome == JoinOutcome::Departing)
                            .then(|| Instant::now() + relay.removed_grace);
                        if departing.is_none() {
                            tracing::info!(conn, "device joined");
                        }
                        joined.insert(
                            team_id.as_str().to_owned(),
                            Joined {
                                team,
                                ticket_at: Instant::now(),
                                departing,
                            },
                        );
                    }
                    Ok(Err(code)) => send(&tx, reply_err(code)),
                    Err(failure) => {
                        tracing::error!(error = %failure, "joining the team failed");
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
                                tracing::error!(error = %failure, "role not applied");
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
                let handled = guard
                    .handle(&relay.db, &relay.limits, conn, &op, other, now_ms())
                    .await;
                relay.forward_attention(&mut guard);
                drop(guard);
                match handled {
                    Ok(Handled::Done) => {}
                    // A refused `device.prove`: no trying signatures without bound.
                    Ok(Handled::BadFrame) => {
                        bad += 1;
                        if bad > MAX_BAD_FRAMES {
                            break Some((close::CLOSE_HELLO_TIMEOUT, "bad frames"));
                        }
                    }
                    Err(failure) => {
                        tracing::error!(error = %failure, "intent not processed");
                        send(
                            &tx,
                            err(Some(op), Some(team_id), error(ErrorCode::BadRequest)),
                        );
                    }
                }
            }
        }
    };

    for (_, entry) in joined.drain() {
        leave(&relay, conn, entry).await;
    }
    if before_hello {
        relay.release_before_hello(waiting);
    }
    if let Some(member) = member {
        relay.release_member(&member);
    }
    if let Some((code, reason)) = close {
        let _ = tokio::time::timeout(Duration::from_secs(2), tx.close(code, reason)).await;
    }
    drop(tx);
    // A peer that no longer reads does not hold the writer forever.
    let abort = writer.abort_handle();
    if tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .is_err()
    {
        abort.abort();
    }
}
