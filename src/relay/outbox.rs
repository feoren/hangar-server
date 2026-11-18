//! Outgoing queue of one connection, limited by frames and by bytes.
//!
//! A frame limit alone is not enough: a client that asks for large answers (`blob.get`,
//! `memberlog.get` pages of up to 1 MiB) and stops reading would otherwise pile up hundreds of
//! MiB. Whoever exceeds either limit is kicked (close 1013) and catches up via its cursor.
//! The catch-up after `hello` (replay or snapshot) is a single entry (`Outgoing::Batch`) and
//! counts against a budget of its own (`BATCH_BYTES`), so a long one does not kick the client
//! right away, but several at once (many teams) cannot pile up either.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Notify};

use super::team::Outgoing;

/// Outgoing frames per connection before it counts as too slow.
pub const QUEUE_FRAMES: usize = 512;
/// Outgoing bytes per connection before it counts as too slow: a few of the largest frames.
pub const QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Queued catch-up bytes per connection before it counts as too slow: four teams with a full
/// replay window (4 MiB each).
pub const BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Bytes counted against `QUEUE_BYTES`. The catch-up of a `hello` (`Batch`) counts against
/// `BATCH_BYTES` instead (`batch_size`): one must not kick a client before it has read
/// anything.
fn size(out: &Outgoing) -> usize {
    match out {
        Outgoing::Text(text) => text.len(),
        Outgoing::Batch(_) | Outgoing::Close(..) => 0,
    }
}

fn batch_size(out: &Outgoing) -> usize {
    match out {
        Outgoing::Batch(frames) => frames.iter().map(|f| f.len()).sum(),
        Outgoing::Text(_) | Outgoing::Close(..) => 0,
    }
}

/// Sending side; cheap to clone, shared by the connection and the teams it joined.
#[derive(Debug, Clone)]
pub struct Outbox {
    tx: mpsc::Sender<Outgoing>,
    queued: Arc<AtomicUsize>,
    batched: Arc<AtomicUsize>,
    kick: Arc<Notify>,
    max_bytes: usize,
}

/// Receiving side, read by the connection's writer task.
#[derive(Debug)]
pub struct Inbox {
    rx: mpsc::Receiver<Outgoing>,
    queued: Arc<AtomicUsize>,
    batched: Arc<AtomicUsize>,
}

/// A queue whose sender triggers `kick` when the receiver falls behind.
pub fn outbox(kick: Arc<Notify>) -> (Outbox, Inbox) {
    with_limits(kick, QUEUE_FRAMES, QUEUE_BYTES)
}

fn with_limits(kick: Arc<Notify>, frames: usize, bytes: usize) -> (Outbox, Inbox) {
    let (tx, rx) = mpsc::channel(frames);
    let queued = Arc::new(AtomicUsize::new(0));
    let batched = Arc::new(AtomicUsize::new(0));
    (
        Outbox {
            tx,
            queued: queued.clone(),
            batched: batched.clone(),
            kick,
            max_bytes: bytes,
        },
        Inbox {
            rx,
            queued,
            batched,
        },
    )
}

impl Outbox {
    /// Queues the frame; `false` (and a kick) when the queue is full by frames or bytes, or the
    /// connection is gone.
    pub fn try_send(&self, out: Outgoing) -> bool {
        let len = size(&out);
        let batch = batch_size(&out);
        let before = self.queued.fetch_add(len, Ordering::AcqRel);
        let before_batch = self.batched.fetch_add(batch, Ordering::AcqRel);
        if before + len > self.max_bytes
            || before_batch + batch > BATCH_BYTES
            || self.tx.try_send(out).is_err()
        {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            self.batched.fetch_sub(batch, Ordering::AcqRel);
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
        self.batched.fetch_sub(batch_size(&out), Ordering::AcqRel);
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
    async fn catch_up_is_one_entry_without_bytes() {
        let kick = Arc::new(Notify::new());
        let (out, mut inbox) = with_limits(kick.clone(), 2, 10);
        let frames = vec![Utf8Bytes::from("x".repeat(10)); 5];
        assert!(out.try_send(Outgoing::Batch(frames)));
        assert!(out.try_send(text(10)), "the batch takes no byte budget");
        assert!(kick.notified().now_or_never().is_none());
        assert!(matches!(inbox.recv().await, Some(Outgoing::Batch(f)) if f.len() == 5));
    }

    #[tokio::test]
    async fn catch_ups_have_their_own_byte_budget() {
        let kick = Arc::new(Notify::new());
        let (out, mut inbox) = outbox(kick.clone());
        // Two catch-ups of 9 MiB each (several teams joined at once) exceed 16 MiB.
        let batch = || Outgoing::Batch(vec![Utf8Bytes::from("x".repeat(1024 * 1024)); 9]);
        assert!(out.try_send(batch()));
        assert!(kick.notified().now_or_never().is_none());
        assert!(
            !out.try_send(batch()),
            "18 MiB of catch-up exceed the budget"
        );
        assert!(kick.notified().now_or_never().is_some(), "kicked");
        // Reading the first one frees its bytes.
        assert!(matches!(inbox.recv().await, Some(Outgoing::Batch(_))));
        assert!(out.try_send(batch()));
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
