//! The wire format of the team protocol comes from the app's `hangar-team-protocol` crate
//! (step C). This module only bundles the names the relay core needs, so that it depends on the
//! crate in a single place. What the crate still lacks for the relay: `docs/protocol-wishes.md`.

pub use hangar_team_protocol::e2e::{
    check_append, check_rotate, ChainError, ChainHead, Challenge, KeyProof, LogHash, PublicKey,
};
pub use hangar_team_protocol::hash::{KeyedHash, PathHashes};
pub use hangar_team_protocol::ids::{
    BlobId, Ciphertext, DeviceId, Epoch, InvalidValue, MemberId, OpId, Sealed, Seq, SessionKey,
    StreamId, TeamId, Ticket, UnixMillis,
};
pub use hangar_team_protocol::wire::*;
pub use hangar_team_protocol::{close, limits};
pub use hangar_team_protocol::{
    DECISIONS_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, PROOF_PROTOCOL_VERSION, PROTOCOL_VERSION,
};

/// Maps the role from the ticket to the protocol role.
pub fn role(role: crate::ticket::Role) -> Role {
    match role {
        crate::ticket::Role::Owner => Role::Owner,
        crate::ticket::Role::Admin => Role::Admin,
        crate::ticket::Role::Member => Role::Member,
    }
}

/// `err` with only a code.
pub fn error(code: ErrorCode) -> ErrorBody {
    ErrorBody {
        code,
        retry_after_ms: None,
        holder: None,
    }
}

/// Empty acknowledgement.
pub fn ack() -> Ack {
    Ack {
        blob: None,
        content: None,
        keys: None,
    }
}
