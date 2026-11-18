//! Outgoing queue of one connection, limited by frames and by bytes.
//!
//! A frame limit alone is not enough: a client that asks for large answers (`blob.get`,
//! `memberlog.get` pages of up to 1 MiB) and stops reading would otherwise pile up hundreds of
//! MiB. Whoever exceeds either limit is kicked (close 1013) and catches up via its cursor.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Notify};

use super::team::Outgoing;

/// Outgoing frames per connection before it counts as too slow.
pub const QUEUE_FRAMES: usize = 512;
/// Outgoing bytes per connection before it counts as too slow: a few of the largest frames.
pub const QUEUE_BYTES: usize = 4 * 1024 * 1024;

fn size(out: &Outgoing) -> usize {
    match out {
        Outgoing::Text(text) => text.len(),
        Outgoing::Close(..) => 0,
    }
}

/// Sending side; cheap to clone, shared by the connection and the teams it joined.
#[derive(Debug, Clone)]
pub struct Outbox {
    tx: mpsc::Sender<Outgoing>,
    queued: Arc<AtomicUsize>,
    kick: Arc<Notify>,
    max_bytes: usize,
}

/// Receiving side, read by the connection's writer task.
#[derive(Debug)]
pub struct Inbox {
    rx: mpsc::Receiver<Outgoing>,
    queued: Arc<AtomicUsize>,
}

/// A queue whose sender triggers `kick` when the receiver falls behind.
pub fn outbox(kick: Arc<Notify>) -> (Outbox, Inbox) {
    with_limits(kick, QUEUE_FRAMES, QUEUE_BYTES)
}

fn with_limits(kick: Arc<Notify>, frames: usize, bytes: usize) -> (Outbox, Inbox) {
    let (tx, rx) = mpsc::channel(frames);
    let queued = Arc::new(AtomicUsize::new(0));
    (
        Outbox {
            tx,
            queued: queued.clone(),
            kick,
            max_bytes: bytes,
        },
        Inbox { rx, queued },
    )
}

impl Outbox {
    /// Queues the frame; `false` (and a kick) when the queue is full by frames or bytes, or the
    /// connection is gone.
    pub fn try_send(&self, out: Outgoing) -> bool {
        let len = size(&out);
        let before = self.queued.fetch_add(len, Ordering::AcqRel);
        if before + len > self.max_bytes || self.tx.try_send(out).is_err() {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            self.kick.notify_one();
            return false;
        }
        true
    }
}

impl Outbox {
    /// The final close of the connection: waits for room instead of kicking.
    pub async fn close(&self, code: u16, reason: &'static str) {
        let _ = self.tx.send(Outgoing::Close(code, reason)).await;
    }
}

impl Inbox {
    pub async fn recv(&mut self) -> Option<Outgoing> {
        let out = self.rx.recv().await?;
        self.queued.fetch_sub(size(&out), Ordering::AcqRel);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ws::Utf8Bytes;

    fn text(len: usize) -> Outgoing {
        Outgoing::Text(Utf8Bytes::from("x".repeat(len)))
    }

    #[tokio::test]
    async fn bytes_limit_kicks_before_memory_piles_up() {
        let kick = Arc::new(Notify::new());
        let (out, mut inbox) = with_limits(kick.clone(), 100, 1000);
        assert!(out.try_send(text(400)));
        assert!(out.try_send(text(400)));
        assert!(!out.try_send(text(400)), "1200 bytes exceed the budget");
        assert!(kick.notified().now_or_never().is_some(), "kicked");
        // Reading frees the budget again.
        assert!(inbox.recv().await.is_some());
        assert!(out.try_send(text(400)));
    }

    #[tokio::test]
    async fn frame_limit_still_applies_to_small_frames() {
        let kick = Arc::new(Notify::new());
        let (out, _inbox) = with_limits(kick.clone(), 2, 1000);
        assert!(out.try_send(text(1)));
        assert!(out.try_send(text(1)));
        assert!(!out.try_send(text(1)));
        assert!(kick.notified().now_or_never().is_some());
    }

    #[tokio::test]
    async fn close_counts_no_bytes() {
        let kick = Arc::new(Notify::new());
        let (out, mut inbox) = with_limits(kick, 10, 10);
        assert!(out.try_send(text(10)));
        assert!(out.try_send(Outgoing::Close(1000, "bye")));
        assert!(matches!(inbox.recv().await, Some(Outgoing::Text(_))));
        assert!(matches!(inbox.recv().await, Some(Outgoing::Close(1000, _))));
    }

    use futures_util::FutureExt;
}
