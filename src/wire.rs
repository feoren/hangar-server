//! Das Wire-Format des Teamprotokolls kommt aus dem Crate `hangar-team-protocol` der App
//! (Schritt C). Dieses Modul bündelt nur die Namen, die der Relay-Kern braucht, damit er an
//! einer Stelle vom Crate abhängt. Was dem Crate für das Relay fehlt: `docs/protocol-wishes.md`.

pub use hangar_team_protocol::e2e::{
    check_append, check_rotate, ChainError, ChainHead, KeyProof, LogHash, PublicKey,
};
pub use hangar_team_protocol::hash::{KeyedHash, PathHashes};
pub use hangar_team_protocol::ids::{
    BlobId, Ciphertext, DeviceId, Epoch, InvalidValue, MemberId, OpId, Sealed, Seq, SessionKey,
    StreamId, TeamId, Ticket, UnixMillis,
};
pub use hangar_team_protocol::wire::*;
pub use hangar_team_protocol::PROTOCOL_VERSION;
pub use hangar_team_protocol::{close, limits};

/// Rolle aus dem Ticket in die Rolle des Protokolls.
pub fn role(role: crate::ticket::Role) -> Role {
    match role {
        crate::ticket::Role::Owner => Role::Owner,
        crate::ticket::Role::Admin => Role::Admin,
        crate::ticket::Role::Member => Role::Member,
    }
}

/// `err` mit nur einem Code.
pub fn error(code: ErrorCode) -> ErrorBody {
    ErrorBody {
        code,
        retry_after_ms: None,
        holder: None,
    }
}

/// Leere Bestätigung.
pub fn ack() -> Ack {
    Ack {
        blob: None,
        content: None,
        keys: None,
    }
}
