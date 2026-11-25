//! Shared helpers for the integration tests: server on a free port, tickets, WebSocket client.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use hangar_server::config::{Config, IdentityMode};
use hangar_server::signed::{self, KeySet, TICKET_CONTEXT};
use hangar_server::ticket::{Role, TicketClaims};
use hangar_server::util::{b64, now_s, random_id};
use hangar_server::wire::{
    self, Ciphertext, ClientFrame, ClientMessage, Cursor, DeviceId, Hello, Holder, MemberId, OpId,
    ProtoRange, ServerFrame, ServerMessage, SessionKey, TeamId, Ticket,
};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub const KID: &str = "test-1";

pub fn website_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

pub fn website_keys() -> KeySet {
    KeySet::parse(&format!(
        "{KID}:{}",
        b64(website_key().verifying_key().as_bytes())
    ))
    .unwrap()
}

pub fn team_id(s: &str) -> TeamId {
    TeamId::new(s).unwrap()
}
pub fn device(s: &str) -> DeviceId {
    DeviceId::new(s).unwrap()
}
pub fn member(s: &str) -> MemberId {
    MemberId::new(s).unwrap()
}
pub fn holder(m: &str, d: &str) -> Holder {
    Holder {
        member: member(m),
        device: device(d),
    }
}
pub fn cipher(s: &str) -> Ciphertext {
    Ciphertext::new(s).unwrap()
}
pub fn session(s: &str) -> SessionKey {
    SessionKey::new(s).unwrap()
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub server: hangar_server::Server,
}

pub async fn start(mut config: Config) -> TestServer {
    config.max_connections_per_member = 16;
    let server = hangar_server::build(config).await.expect("server starts");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = server
        .router
        .clone()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    TestServer { addr, server }
}

pub async fn start_official() -> TestServer {
    start(Config::for_tests(IdentityMode::Official, website_keys())).await
}

pub fn claims(member: &str, team: &str, role: Role) -> TicketClaims {
    let now = now_s();
    TicketClaims {
        v: 1,
        kid: KID.into(),
        sub: member.into(),
        prj: team.into(),
        role,
        seat_ok: true,
        iat: now,
        exp: now + 60,
        jti: format!("jti{}", random_id()),
        aud: Some("hangar-relay".into()),
    }
}

pub fn sign_ticket(claims: &TicketClaims, key: &SigningKey) -> String {
    signed::sign(&serde_json::to_vec(claims).unwrap(), TICKET_CONTEXT, key)
}

pub fn ticket(member: &str, team: &str, role: Role) -> String {
    sign_ticket(&claims(member, team, role), &website_key())
}

pub struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next: u32,
    /// Close code, if the server closed the connection.
    pub closed: Option<u16>,
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Client {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/live"))
            .await
            .expect("connects");
        Client {
            ws,
            next: 0,
            closed: None,
        }
    }

    pub fn op(&mut self) -> String {
        self.next += 1;
        format!("op-{}-{}", self.next, random_id())
    }

    pub async fn send(&mut self, op: &str, team: Option<&str>, message: ClientMessage) {
        let frame = ClientFrame {
            id: OpId::new(op).unwrap(),
            team: team.map(team_id),
            message,
        };
        let text = wire::encode_client(&frame).expect("frame encodable");
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        self.ws
            .send(Message::Text(text.to_owned().into()))
            .await
            .unwrap();
    }

    /// Next server frame (pings skipped); `None` on timeout or end of stream.
    pub async fn recv(&mut self) -> Option<ServerFrame> {
        loop {
            let next = tokio::time::timeout(Duration::from_secs(5), self.ws.next())
                .await
                .ok()??;
            match next.ok()? {
                Message::Text(t) => {
                    return Some(wire::decode_server(t.as_str()).expect("valid server frame"))
                }
                Message::Close(frame) => {
                    self.closed = frame.map(|f| u16::from(f.code));
                    return None;
                }
                _ => continue,
            }
        }
    }

    /// Next server frame as the relay sent it (pings skipped); `None` on timeout or end.
    pub async fn recv_text(&mut self) -> Option<String> {
        loop {
            let next = tokio::time::timeout(Duration::from_secs(5), self.ws.next())
                .await
                .ok()??;
            match next.ok()? {
                Message::Text(t) => return Some(t.as_str().to_owned()),
                Message::Close(frame) => {
                    self.closed = frame.map(|f| u16::from(f.code));
                    return None;
                }
                _ => continue,
            }
        }
    }

    /// Reads until the server closes and returns the close code.
    pub async fn close_code(&mut self) -> Option<u16> {
        while self.recv().await.is_some() {}
        self.closed
    }

    /// Waits for a frame satisfying `pred` and returns it.
    pub async fn until(&mut self, pred: impl Fn(&ServerFrame) -> bool) -> ServerFrame {
        loop {
            let frame = self.recv().await.expect("expected frame did not arrive");
            if pred(&frame) {
                return frame;
            }
        }
    }

    /// Reply to `op` (ack, err, welcome, resync_required, devices, memberlog.entries).
    pub async fn answer(&mut self, op: &str) -> ServerFrame {
        let op = op.to_owned();
        self.until(move |f| {
            f.id.as_ref().map(|i| i.as_str()) == Some(op.as_str())
                && !matches!(f.message, ServerMessage::ResyncRequired(_))
        })
        .await
    }

    pub async fn hello_with(
        &mut self,
        team: &str,
        ticket: String,
        device_id: &str,
        proto: ProtoRange,
        cursor: Option<Cursor>,
    ) -> ServerFrame {
        let op = self.op();
        self.send(
            &op,
            Some(team),
            ClientMessage::Hello(Hello {
                ticket: Ticket::new(ticket).unwrap(),
                device: device(device_id),
                proto,
                last_seq: cursor,
            }),
        )
        .await;
        self.answer(&op).await
    }

    pub async fn hello(
        &mut self,
        team: &str,
        ticket: String,
        device_id: &str,
        cursor: Option<Cursor>,
    ) -> ServerFrame {
        self.hello_with(team, ticket, device_id, ProtoRange::CURRENT, cursor)
            .await
    }

    /// Connects and says hello; returns the client and the welcome.
    pub async fn join(
        addr: SocketAddr,
        team: &str,
        member: &str,
        role: Role,
    ) -> (Client, wire::Welcome) {
        let mut client = Client::connect(addr).await;
        let frame = client
            .hello(
                team,
                ticket(member, team, role),
                &format!("{member}-device"),
                None,
            )
            .await;
        match frame.message {
            ServerMessage::Welcome(w) => (client, w),
            other => panic!("no welcome: {other:?}"),
        }
    }

    pub async fn request(&mut self, team: &str, message: ClientMessage) -> ServerFrame {
        let op = self.op();
        self.send(&op, Some(team), message).await;
        self.answer(&op).await
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}

/// Close code as a number (for comparisons without tungstenite types).
pub fn code_of(code: CloseCode) -> u16 {
    u16::from(code)
}

// ---------------------------------------------------------------------------------------------
// End-to-end: real device keys and signed log entries (hangar-team-crypto)

use hangar_server::wire::{
    DeviceKeys, DeviceRemove, KeyRotate, KeyWrap, MemberLogAppend, UnixMillis,
};
use hangar_team_crypto::entropy::OsEntropy;
use hangar_team_crypto::epoch::TeamSecret;
use hangar_team_crypto::identity::DeviceIdentity;
use hangar_team_crypto::memberlog::{
    DeviceEntry, Endorsement, EntryBody, EntryKind, LogVerifier, TeamState,
};
use hangar_team_crypto::rotation::{plan_rotation, wrap_for_device};

/// A log entry that is never valid (for checks that fail earlier).
pub fn dummy_log() -> MemberLogAppend {
    MemberLogAppend {
        index: 1,
        prev: None,
        entry: cipher("YQ"),
    }
}

/// A device with real keys.
pub struct Dev {
    pub holder: Holder,
    pub identity: DeviceIdentity,
}

impl Dev {
    pub fn new(m: &str, d: &str) -> Dev {
        Dev {
            holder: holder(m, d),
            identity: DeviceIdentity::generate(&mut OsEntropy).unwrap(),
        }
    }

    pub fn keys(&self, team: &str) -> DeviceKeys {
        self.identity.device_keys(&team_id(team), &self.holder)
    }

    pub fn entry(&self, team: &str) -> DeviceEntry {
        DeviceEntry::new(&team_id(team), &self.holder, &self.identity, false)
    }
}

/// A client's view of the log: builds entries and applies them once the relay has accepted
/// them.
pub struct Log {
    pub team: String,
    pub verifier: LogVerifier,
}

pub fn now() -> UnixMillis {
    UnixMillis(hangar_server::util::now_ms())
}

impl Log {
    pub fn new(team: &str) -> Log {
        Log {
            team: team.into(),
            verifier: LogVerifier::new(team_id(team)),
        }
    }

    pub fn state(&self) -> &TeamState {
        self.verifier.state().expect("team created")
    }

    fn next(&self, issuer: &Dev, kind: EntryKind) -> MemberLogAppend {
        self.state()
            .next_body(issuer.holder.clone(), now(), kind)
            .sign(&issuer.identity)
            .unwrap()
    }

    pub fn create(&self, owner: &Dev) -> MemberLogAppend {
        EntryBody::create_team(
            team_id(&self.team),
            owner.holder.clone(),
            now(),
            vec![owner.entry(&self.team)],
        )
        .sign(&owner.identity)
        .unwrap()
    }

    pub fn add_member(
        &self,
        issuer: &Dev,
        new: &Dev,
        role: hangar_server::wire::Role,
    ) -> MemberLogAppend {
        self.next(
            issuer,
            EntryKind::AddMember {
                member: new.holder.member.clone(),
                role,
                devices: vec![new.entry(&self.team)],
            },
        )
    }

    /// Additional device of a member, endorsed and added by `endorser` (same member).
    pub fn add_device(&self, endorser: &Dev, new: &Dev) -> MemberLogAppend {
        let signature = endorser.identity.endorse(
            &team_id(&self.team),
            &new.holder,
            &new.identity.public_keys(),
            false,
        );
        self.next(
            endorser,
            EntryKind::AddDevice {
                member: new.holder.member.clone(),
                device: new.entry(&self.team),
                endorsement: Endorsement {
                    device: endorser.holder.device.clone(),
                    signature,
                },
            },
        )
    }

    pub fn remove_member(&self, issuer: &Dev, member: &str) -> MemberLogAppend {
        self.next(
            issuer,
            EntryKind::RemoveMember {
                member: MemberId::new(member).unwrap(),
            },
        )
    }

    pub fn remove_device(&self, issuer: &Dev, target: &Holder) -> DeviceRemove {
        DeviceRemove {
            holder: target.clone(),
            log: self.next(
                issuer,
                EntryKind::RemoveDevice {
                    holder: target.clone(),
                },
            ),
        }
    }

    pub fn rotate(&self, issuer: &Dev) -> (KeyRotate, TeamSecret) {
        let rotation = plan_rotation(
            self.state(),
            &issuer.identity,
            &issuer.holder,
            None,
            now(),
            &mut OsEntropy,
        )
        .unwrap();
        (rotation.rotate, rotation.secret)
    }

    pub fn wrap(&self, secret: &TeamSecret, target: &Holder) -> KeyWrap {
        wrap_for_device(self.state(), secret, target, &mut OsEntropy).unwrap()
    }

    /// Applies an entry the relay has accepted (same checks as there).
    pub fn accept(&mut self, append: &MemberLogAppend, sender: &Holder) {
        self.verifier
            .admit(append, sender, hangar_server::wire::Role::Owner)
            .expect("locally valid");
    }

    pub fn accept_rotation(&mut self, rotate: &KeyRotate, sender: &Holder) {
        self.verifier
            .admit_rotation(rotate, sender, hangar_server::wire::Role::Owner)
            .expect("locally valid");
    }

    pub fn accept_removal(&mut self, remove: &DeviceRemove, sender: &Holder) {
        self.verifier
            .admit_device_remove(remove, sender, hangar_server::wire::Role::Owner)
            .expect("locally valid");
    }
}

impl Dev {
    /// `device.prove` for the `welcome` of this device's connection to `team`.
    pub fn prove(&self, team: &str, welcome: &wire::Welcome) -> ClientMessage {
        let challenge = welcome
            .challenge
            .expect("welcome of version 3 carries a challenge");
        ClientMessage::DeviceProve(self.identity.prove_connection(
            &team_id(team),
            &self.holder,
            welcome.proto,
            &challenge,
        ))
    }
}

impl Client {
    /// Connects as `dev` and does what the app does after `welcome`: `device.keys`, then on
    /// version 3 `device.prove`.
    pub async fn join_device(addr: SocketAddr, team: &str, dev: &Dev, role: Role) -> Client {
        Client::join_device_with(addr, team, dev, role, ProtoRange::CURRENT).await
    }

    pub async fn join_device_with(
        addr: SocketAddr,
        team: &str,
        dev: &Dev,
        role: Role,
        proto: ProtoRange,
    ) -> Client {
        let mut client = Client::connect(addr).await;
        let frame = client
            .hello_with(
                team,
                ticket(dev.holder.member.as_str(), team, role),
                dev.holder.device.as_str(),
                proto,
                None,
            )
            .await;
        let ServerMessage::Welcome(welcome) = frame.message else {
            panic!("no welcome: {frame:?}");
        };
        client.register(team, dev, &welcome).await;
        client
    }

    /// `device.keys` and, on version 3, `device.prove` after `welcome`.
    pub async fn register(&mut self, team: &str, dev: &Dev, welcome: &wire::Welcome) {
        let r = self
            .request(team, ClientMessage::DeviceKeys(dev.keys(team)))
            .await;
        assert!(matches!(r.message, ServerMessage::Ack(_)), "{r:?}");
        if welcome.challenge.is_some() {
            let r = self.request(team, dev.prove(team, welcome)).await;
            assert!(matches!(r.message, ServerMessage::Ack(_)), "{r:?}");
        }
    }
}
