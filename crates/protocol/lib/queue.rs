//! Byte-budgeted transport mailboxes. Shared dispatch never waits on a consumer.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// Transport mailbox budget, including per-frame metadata. A route whose
/// consumer leaves this much unread closes the transport instead of stalling
/// dispatch for every other route.
pub const TRANSPORT_QUEUE_BYTES: usize = 32 * 1024 * 1024;

// Covers the mpsc block links and allocator bookkeeping per queued item.
const QUEUE_NODE_OVERHEAD_BYTES: usize = 64;

/// A byte-budgeted sender. Payload sizes are supplied by the framing boundary.
pub struct Sender<T> {
    tx: mpsc::UnboundedSender<(T, OwnedSemaphorePermit)>,
    budget: Arc<Semaphore>,
    limit: usize,
}

/// A byte-budgeted receiver. Dequeuing releases queue space; the consumer owns
/// at most one additional frame while performing its I/O.
pub struct Receiver<T> {
    rx: mpsc::UnboundedReceiver<(T, OwnedSemaphorePermit)>,
    budget: Arc<Semaphore>,
}

/// Create a mailbox bounded by payload bytes plus message and queue metadata.
pub fn channel<T>(limit: usize) -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let budget = Arc::new(Semaphore::new(limit));
    (
        Sender {
            tx,
            budget: Arc::clone(&budget),
            limit,
        },
        Receiver { rx, budget },
    )
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            budget: Arc::clone(&self.budget),
            limit: self.limit,
        }
    }
}

impl<T> Sender<T> {
    /// Whether the consumer has closed or dropped its receiver.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
    fn charge(&self, bytes: usize) -> Option<u32> {
        // Defend the allocator against both byte overflow and zero-byte floods.
        bytes
            .checked_add(
                std::mem::size_of::<T>()
                    + std::mem::size_of::<OwnedSemaphorePermit>()
                    + QUEUE_NODE_OVERHEAD_BYTES,
            )
            .filter(|n| *n <= self.limit)
            .and_then(|n| u32::try_from(n).ok())
    }

    /// Enqueue without waiting; return the original item on closure or exhaustion.
    pub fn try_send(&self, item: T, bytes: usize) -> Result<(), T> {
        let Some(charge) = self.charge(bytes) else {
            return Err(item);
        };
        let Ok(permit) = Arc::clone(&self.budget).try_acquire_many_owned(charge) else {
            return Err(item);
        };
        self.tx.send((item, permit)).map_err(|e| e.0.0)
    }
}

impl<T> Receiver<T> {
    /// Receive the next item, or `None` when every sender has closed.
    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await.map(|(item, _permit)| item)
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.budget.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn byte_budget_releases_on_read_and_wakes_on_drop() {
        let (tx, mut rx) = channel::<Vec<u8>>(1024);
        assert!(tx.try_send(vec![0; 800], 800).is_ok());
        assert!(tx.try_send(vec![0; 800], 800).is_err());
        assert_eq!(rx.recv().await.unwrap().len(), 800);
        assert!(tx.try_send(vec![0; 800], 800).is_ok());
        drop(rx);
        assert!(tx.try_send(vec![0; 8], 8).is_err());
        assert!(tx.try_send(Vec::new(), usize::MAX).is_err());
    }
}
