//! TCP connections from the host to an address the guest can reach, over raw bulk transfer.
//!
//! agentd dials the destination from inside the guest. Both directions are bounded by bulk
//! credit: the guest admits host bytes only up to the window it granted, and the host grants
//! guest bytes back only once the caller has taken them with [`GuestTcpStream::read`].

use std::sync::{
    Arc, Mutex as SyncMutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_agent_client::AgentFrame;
use microsandbox_protocol::{
    bulk::{
        BULK_FLOW_MASK_GUEST_TO_HOST, BULK_FLOW_MASK_HOST_TO_GUEST, BulkAccepted, BulkCancel,
        BulkCancelReason, BulkCredit, BulkFinish, BulkFlow, BulkKind, BulkOffer, BulkReceiveState,
        BulkRecord, BulkSendState,
    },
    message::{Message, MessageType},
    tcp::{TcpConnect, TcpConnected, TcpFailed},
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};

use crate::{MicrosandboxError, MicrosandboxResult, Sandbox, agent::AgentClient};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// How long a closing connection may go without progress — the guest writing more of the host's
/// bytes, then its terminal reply — before it is reset.
pub const GUEST_TCP_CLOSE_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A TCP connection agentd opened from inside the guest.
///
/// All methods take `&self`, so one task can read while another writes. Reads and writes are
/// each serialized. Dropping the stream without [`close`](Self::close) or
/// [`abort`](Self::abort) aborts it in the background.
pub struct GuestTcpStream {
    shared: Arc<Shared>,
    reader: Mutex<Reader>,
    writer: Mutex<()>,
    _owner: oneshot::Sender<()>,
}

/// Whether the guest confirmed that a closed connection released its socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestTcpCleanup {
    /// The guest sent its terminal reply: its socket is closed or handed to an orderly drain.
    Acknowledged,
    /// No terminal reply arrived within [`GUEST_TCP_CLOSE_IDLE_TIMEOUT`], or the agent connection
    /// was lost first. The guest socket may still be open.
    Unknown,
}

/// State shared by the stream and its frame pump.
struct Shared {
    client: Arc<AgentClient>,
    id: u32,
    send: SyncMutex<BulkSendState>,
    receive: SyncMutex<BulkReceiveState>,
    /// Woken on every credit grant, on the end of the stream, and on release.
    progress: Notify,
    end: watch::Sender<Option<End>>,
    /// A guest protocol violation or cancellation; the stream is being torn down.
    failure: SyncMutex<Option<String>>,
    /// The host's finish was sent.
    finished: AtomicBool,
    /// The guest's finish arrived.
    guest_finished: AtomicBool,
    /// Close or abort released the connection; nothing more is read or written.
    released: AtomicBool,
    cancel_sent: AtomicBool,
}

/// How the guest stream ended.
#[derive(Clone, Debug)]
struct End {
    /// The guest's own terminal reply ended it.
    acknowledged: bool,
    error: Option<String>,
}

enum Inbound {
    Data { payload: Bytes, end: u64 },
    Eof,
}

struct Reader {
    /// Unbounded on purpose: the pump must never wait on a stalled reader, or credit for the
    /// opposite direction would stall too. The guest's bytes are bounded by the credit it was
    /// granted, which `BulkReceiveState::accept_record` enforces before anything is queued.
    events: mpsc::UnboundedReceiver<Inbound>,
    eof: bool,
}

/// What the pump does after one frame.
enum Flow {
    Continue,
    Ended,
    Violation(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Open a TCP connection from inside the guest to `host:port`.
    ///
    /// Each connection uses its own agent connection, so a misbehaving one cannot disturb
    /// other operations on the sandbox. `host` is resolved by the guest.
    pub async fn dial_tcp(
        &self,
        host: impl Into<String>,
        port: u16,
    ) -> MicrosandboxResult<GuestTcpStream> {
        let client = super::fs::agent::connect_agent(self.backend().as_ref(), self.name()).await?;
        GuestTcpStream::connect(Arc::new(client), host, port).await
    }
}

impl GuestTcpStream {
    /// Open a TCP connection from inside the guest over an existing agent connection.
    pub async fn connect(
        client: Arc<AgentClient>,
        host: impl Into<String>,
        port: u16,
    ) -> MicrosandboxResult<Self> {
        if !client.supports(MessageType::BulkAccepted) {
            return Err(MicrosandboxError::Custom(
                "guest agent cannot carry bulk TCP; restart the sandbox with the current runtime"
                    .into(),
            ));
        }
        let host = host.into();
        let offer = BulkOffer::tcp();
        let (id, mut frames) = client
            .stream_frames(
                MessageType::TcpConnect,
                &TcpConnect {
                    host: host.clone(),
                    port,
                    bulk: Some(offer),
                },
            )
            .await?;
        let negotiated = negotiate(&mut frames, offer, &host, port).await;
        let (send, receive) = match negotiated {
            Ok(states) => states,
            Err((error, connected)) => {
                // A refused connect ended with its terminal reply; a connected stream that
                // failed negotiation still holds a guest socket.
                if connected {
                    let _ = client
                        .cancel_bulk(id, &cancel_message("bulk TCP negotiation failed"))
                        .await;
                }
                return Err(error);
            }
        };

        let (end, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            client,
            id,
            send: SyncMutex::new(send),
            receive: SyncMutex::new(receive),
            progress: Notify::new(),
            end,
            failure: SyncMutex::new(None),
            finished: AtomicBool::new(false),
            guest_finished: AtomicBool::new(false),
            released: AtomicBool::new(false),
            cancel_sent: AtomicBool::new(false),
        });
        let (events_tx, events) = mpsc::unbounded_channel();
        let (owner, owner_gone) = oneshot::channel();
        tokio::spawn(pump(Arc::clone(&shared), frames, events_tx, owner_gone));
        Ok(Self {
            shared,
            reader: Mutex::new(Reader { events, eof: false }),
            writer: Mutex::new(()),
            _owner: owner,
        })
    }

    /// Read the next chunk the guest received from its destination; `None` once the destination
    /// ended its side in order.
    ///
    /// The chunk's credit goes back to the guest as it is returned, so the guest holds at most
    /// one credit window of bytes the caller has not taken yet.
    pub async fn read(&self) -> MicrosandboxResult<Option<Bytes>> {
        let mut reader = self.reader.lock().await;
        if reader.eof {
            return Ok(None);
        }
        if self.shared.released.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        match reader.events.recv().await {
            Some(Inbound::Data { payload, end }) => {
                let credit = self
                    .shared
                    .receive
                    .lock()
                    .expect("bulk receive state poisoned")
                    .consume(end)
                    .map_err(|error| bulk_error("advance TCP bulk credit", error))?;
                if let Some(credit) = credit {
                    // A connection that cannot carry the grant is gone; the bytes already here
                    // are still the caller's, and the next read reports the loss.
                    let _ = self
                        .shared
                        .client
                        .send(self.shared.id, MessageType::BulkCredit, &credit)
                        .await;
                }
                Ok(Some(payload))
            }
            Some(Inbound::Eof) => {
                reader.eof = true;
                Ok(None)
            }
            None => Err(self.shared.read_error()),
        }
    }

    /// Write all of `data`, waiting for guest credit as needed.
    pub async fn write(&self, data: impl Into<Bytes>) -> MicrosandboxResult<()> {
        let _writer = self.writer.lock().await;
        let mut remaining = data.into();
        while !remaining.is_empty() {
            // Register before inspecting credit so a grant in between is not missed.
            let notified = self.shared.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.shared.check_writable()?;
            let admitted = {
                let mut send = self.shared.send.lock().expect("bulk send state poisoned");
                let len = remaining
                    .len()
                    .min(send.max_record_payload() as usize)
                    .min(usize::try_from(send.available_credit()).unwrap_or(usize::MAX));
                if len == 0 {
                    None
                } else {
                    let offset = send
                        .admit(len)
                        .map_err(|error| bulk_error("admit TCP bulk record", error))?;
                    Some((offset, len))
                }
            };
            let Some((offset, len)) = admitted else {
                notified.await;
                continue;
            };
            self.shared
                .client
                .send_bulk(BulkRecord {
                    id: self.shared.id,
                    kind: BulkKind::Tcp,
                    flow: BulkFlow::HostToGuest,
                    offset,
                    payload: remaining.split_to(len),
                })
                .await?;
        }
        Ok(())
    }

    /// Half-close: the guest shuts down its write side once it has written every byte before
    /// this. Reads continue until the destination ends its side. A second call does nothing.
    pub async fn shutdown_write(&self) -> MicrosandboxResult<()> {
        let _writer = self.writer.lock().await;
        if self.shared.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        self.shared.check_writable()?;
        self.shared.finish().await
    }

    /// Orderly close: finish the write side if it is still open, wait until the guest has
    /// written every byte to its destination, then release the connection without a reset.
    ///
    /// Writes in flight must have completed. The wait is bounded by
    /// [`GUEST_TCP_CLOSE_IDLE_TIMEOUT`] of no progress; bytes still undelivered then are
    /// discarded, the destination sees a reset, and this returns an error.
    pub async fn close(&self) -> MicrosandboxResult<GuestTcpCleanup> {
        {
            let _writer = self.writer.lock().await;
            if !self.shared.finished.load(Ordering::Acquire) && self.shared.check_writable().is_ok()
            {
                self.shared.finish().await?;
            }
        }
        let undelivered = self.shared.drain().await;
        self.shared.release();
        let in_order = undelivered == 0
            && self.shared.guest_finished.load(Ordering::Acquire)
            && self.shared.failure().is_none();
        // Both directions ended in order: the guest ends the stream itself.
        if !in_order {
            self.shared.cancel("guest TCP stream closed").await;
        }
        let cleanup = self.shared.wait_end().await;
        if undelivered > 0 {
            return Err(MicrosandboxError::Custom(format!(
                "guest TCP close: {undelivered} bytes were not written to the destination"
            )));
        }
        Ok(cleanup)
    }

    /// Abort: discard unwritten bytes and release the connection now. The destination sees a
    /// reset unless the guest had already written every byte and the finish.
    pub async fn abort(&self) -> GuestTcpCleanup {
        self.shared.release();
        self.shared.cancel("guest TCP stream aborted").await;
        self.shared.wait_end().await
    }
}

impl Shared {
    fn failure(&self) -> Option<String> {
        self.failure.lock().expect("failure state poisoned").clone()
    }

    fn fail(&self, error: String) {
        self.failure
            .lock()
            .expect("failure state poisoned")
            .get_or_insert(error);
        self.progress.notify_waiters();
    }

    fn check_writable(&self) -> MicrosandboxResult<()> {
        if self.released.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        if self.finished.load(Ordering::Acquire) {
            return Err(MicrosandboxError::Custom(
                "guest TCP write side is already shut down".into(),
            ));
        }
        if let Some(error) = self.failure() {
            return Err(MicrosandboxError::Custom(format!(
                "guest TCP stream: {error}"
            )));
        }
        if let Some(end) = self.end.borrow().as_ref() {
            return Err(MicrosandboxError::Custom(format!(
                "guest TCP stream ended: {}",
                end.error.as_deref().unwrap_or("closed")
            )));
        }
        Ok(())
    }

    fn read_error(&self) -> MicrosandboxError {
        if self.released.load(Ordering::Acquire) {
            return closed_error();
        }
        let error = self.failure().or_else(|| {
            self.end
                .borrow()
                .as_ref()
                .map(|end| end.error.clone().unwrap_or_else(|| "closed".into()))
        });
        MicrosandboxError::Custom(format!(
            "guest TCP stream ended before the destination finished: {}",
            error.as_deref().unwrap_or("connection lost")
        ))
    }

    async fn finish(&self) -> MicrosandboxResult<()> {
        let finish = self
            .send
            .lock()
            .expect("bulk send state poisoned")
            .finish()
            .map_err(|error| bulk_error("finish TCP bulk flow", error))?;
        self.client
            .send(self.id, MessageType::BulkFinish, &finish)
            .await?;
        self.finished.store(true, Ordering::Release);
        Ok(())
    }

    /// Wait until the guest has written every host byte, the stream ended, or it went
    /// [`GUEST_TCP_CLOSE_IDLE_TIMEOUT`] without progress. Returns the bytes still undelivered.
    async fn drain(&self) -> u64 {
        let mut deadline = tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT;
        let mut last = None;
        loop {
            let notified = self.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (consumed, sent) = {
                let send = self.send.lock().expect("bulk send state poisoned");
                (send.consumed_offset(), send.next_offset())
            };
            if consumed == sent || self.end.borrow().is_some() || self.failure().is_some() {
                return sent - consumed;
            }
            if last.is_some_and(|last| consumed > last) {
                deadline = tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT;
            }
            last = Some(consumed);
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline) => return sent - consumed,
            }
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.progress.notify_waiters();
    }

    /// Ask agentd to tear the guest socket down, once. agentd resets it unless every host byte
    /// and the finish were already written, and answers with the stream's terminal reply.
    async fn cancel(&self, message: &str) {
        if self.end.borrow().is_some() || self.cancel_sent.swap(true, Ordering::AcqRel) {
            return;
        }
        // A connection that cannot carry the cancel is lost; the pump records that end.
        let _ = self
            .client
            .cancel_bulk(self.id, &cancel_message(message))
            .await;
    }

    async fn wait_end(&self) -> GuestTcpCleanup {
        let mut end = self.end.subscribe();
        let ended =
            tokio::time::timeout(GUEST_TCP_CLOSE_IDLE_TIMEOUT, end.wait_for(Option::is_some)).await;
        match ended {
            Ok(Ok(end)) if end.as_ref().is_some_and(|end| end.acknowledged) => {
                GuestTcpCleanup::Acknowledged
            }
            _ => GuestTcpCleanup::Unknown,
        }
    }

    fn set_end(&self, end: End) {
        self.end.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(end);
            true
        });
        self.progress.notify_waiters();
    }

    fn handle(&self, frame: AgentFrame, events: &mpsc::UnboundedSender<Inbound>) -> Flow {
        let message = match frame {
            AgentFrame::Bulk(record) => {
                let end = self
                    .receive
                    .lock()
                    .expect("bulk receive state poisoned")
                    .accept_record(&record);
                return match end {
                    Ok(end) => {
                        // A reader that is gone no longer wants the bytes.
                        let _ = events.send(Inbound::Data {
                            payload: record.payload,
                            end,
                        });
                        Flow::Continue
                    }
                    Err(error) => Flow::Violation(format!("invalid TCP bulk record: {error}")),
                };
            }
            AgentFrame::Control(message) => message,
        };
        match message.t {
            MessageType::BulkCredit => {
                let applied = decode::<BulkCredit>(&message).and_then(|credit| {
                    self.send
                        .lock()
                        .expect("bulk send state poisoned")
                        .apply_credit(credit)
                        .map_err(|error| format!("invalid TCP bulk credit: {error}"))
                });
                match applied {
                    Ok(_) => {
                        self.progress.notify_waiters();
                        Flow::Continue
                    }
                    Err(error) => Flow::Violation(error),
                }
            }
            MessageType::BulkFinish => {
                let accepted = decode::<BulkFinish>(&message).and_then(|finish| {
                    self.receive
                        .lock()
                        .expect("bulk receive state poisoned")
                        .accept_finish(finish)
                        .map_err(|error| format!("invalid TCP bulk finish: {error}"))
                });
                match accepted {
                    Ok(()) => {
                        self.guest_finished.store(true, Ordering::Release);
                        let _ = events.send(Inbound::Eof);
                        Flow::Continue
                    }
                    Err(error) => Flow::Violation(error),
                }
            }
            MessageType::BulkCancel => {
                let reason = decode::<BulkCancel>(&message)
                    .map(|cancel| cancel.message)
                    .unwrap_or_else(|error| error);
                Flow::Violation(format!("guest cancelled the TCP stream: {reason}"))
            }
            MessageType::TcpClosed => {
                self.set_end(End {
                    acknowledged: true,
                    error: None,
                });
                Flow::Ended
            }
            MessageType::TcpFailed => {
                let error = decode::<TcpFailed>(&message)
                    .map(|failed| failed.error)
                    .unwrap_or_else(|error| error);
                self.set_end(End {
                    acknowledged: true,
                    error: Some(error),
                });
                Flow::Ended
            }
            other => Flow::Violation(format!("unexpected guest TCP message {}", other.as_str())),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Await the connect reply and bulk acceptance. An error carries whether the guest connected.
async fn negotiate(
    frames: &mut mpsc::Receiver<AgentFrame>,
    offer: BulkOffer,
    host: &str,
    port: u16,
) -> Result<(BulkSendState, BulkReceiveState), (MicrosandboxError, bool)> {
    let refused = |detail: String| {
        MicrosandboxError::Custom(format!("guest TCP connect to {host}:{port}: {detail}"))
    };
    let first = next_control(frames)
        .await
        .map_err(|error| (refused(error), false))?;
    match first.t {
        MessageType::TcpConnected => {
            first
                .payload::<TcpConnected>()
                .map_err(|error| (error.into(), true))?;
        }
        MessageType::TcpFailed => {
            let failed = first
                .payload::<TcpFailed>()
                .map_err(|error| (error.into(), false))?;
            return Err((refused(failed.error), false));
        }
        other => {
            return Err((
                refused(format!("unexpected reply {}", other.as_str())),
                false,
            ));
        }
    }
    let accepted = next_control(frames)
        .await
        .map_err(|error| (refused(error), true))?;
    if accepted.t != MessageType::BulkAccepted {
        return Err((
            refused(format!(
                "expected bulk acceptance, got {}",
                accepted.t.as_str()
            )),
            true,
        ));
    }
    let accepted = accepted
        .payload::<BulkAccepted>()
        .map_err(|error| (error.into(), true))?
        .validate_against(
            offer,
            BulkKind::Tcp,
            BULK_FLOW_MASK_HOST_TO_GUEST | BULK_FLOW_MASK_GUEST_TO_HOST,
        )
        .map_err(|error| (bulk_error("invalid TCP bulk acceptance", error), true))?;
    let send = BulkSendState::new(
        BulkKind::Tcp,
        BulkFlow::HostToGuest,
        accepted.max_record_payload,
        accepted.host_to_guest_credit_limit,
    )
    .map_err(|error| (bulk_error("create TCP bulk send state", error), true))?;
    let receive = BulkReceiveState::new(
        BulkKind::Tcp,
        BulkFlow::GuestToHost,
        accepted.max_record_payload,
        accepted.guest_to_host_credit_limit,
        offer.guest_to_host_credit_limit,
    )
    .map_err(|error| (bulk_error("create TCP bulk receive state", error), true))?;
    Ok((send, receive))
}

async fn next_control(frames: &mut mpsc::Receiver<AgentFrame>) -> Result<Message, String> {
    match frames.recv().await {
        Some(AgentFrame::Control(message)) => Ok(message),
        Some(AgentFrame::Bulk(_)) => Err("raw data arrived before the connect reply".into()),
        None => Err("agent stream closed before the connect reply".into()),
    }
}

/// Route one connection's agent frames without ever waiting on its reader or writer.
///
/// Runs until the guest's terminal reply or the loss of the agent connection. Once the stream
/// is dropped or the guest broke the protocol, it cancels the guest socket and waits at most
/// [`GUEST_TCP_CLOSE_IDLE_TIMEOUT`] for that reply.
async fn pump(
    shared: Arc<Shared>,
    mut frames: mpsc::Receiver<AgentFrame>,
    events: mpsc::UnboundedSender<Inbound>,
    mut owner: oneshot::Receiver<()>,
) {
    let mut owned = true;
    let mut deadline = None;
    loop {
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = &mut owner, if owned => {
                owned = false;
                shared.release();
                shared.cancel("guest TCP stream dropped").await;
                deadline.get_or_insert(tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT);
            }
            frame = frames.recv() => {
                let Some(frame) = frame else {
                    shared.set_end(End {
                        acknowledged: false,
                        error: Some("agent connection lost".into()),
                    });
                    break;
                };
                match shared.handle(frame, &events) {
                    Flow::Continue => {}
                    Flow::Ended => break,
                    Flow::Violation(error) => {
                        shared.fail(error);
                        shared.cancel("guest TCP protocol violation").await;
                        deadline.get_or_insert(
                            tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT,
                        );
                    }
                }
            }
            () = expired => {
                shared.set_end(End {
                    acknowledged: false,
                    error: Some("no terminal reply from the guest".into()),
                });
                break;
            }
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(message: &Message) -> Result<T, String> {
    message
        .payload::<T>()
        .map_err(|error| format!("decode {}: {error}", message.t.as_str()))
}

fn cancel_message(message: &str) -> BulkCancel {
    BulkCancel {
        kind: BulkKind::Tcp,
        reason: BulkCancelReason::CallerCancelled,
        message: message.into(),
    }
}

fn bulk_error(context: &str, error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::Custom(format!("{context}: {error}"))
}

fn closed_error() -> MicrosandboxError {
    MicrosandboxError::Custom("guest TCP stream is closed".into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
