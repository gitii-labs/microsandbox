//! A scripted agent for guest TCP tests: it negotiates the generation-9 bulk TCP path and relays
//! real loopback destination sockets the way agentd does.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_protocol::{
    bulk::{
        BULK_FLOW_MASK_GUEST_TO_HOST, BULK_FLOW_MASK_HOST_TO_GUEST, BulkAccepted, BulkCancel,
        BulkCredit, BulkFinish, BulkFlow, BulkKind, BulkReceiveState, BulkRecord, BulkSendState,
        DEFAULT_BULK_RECORD_PAYLOAD, MAX_BULK_RECORD_PAYLOAD,
    },
    codec,
    core::Ready,
    message::{FLAG_BULK, Message, MessageType},
    tcp::{TcpClosed, TcpConnect, TcpConnected, TcpFailed},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinSet;

use super::GUEST_TCP_CLOSE_IDLE_TIMEOUT;

/// Host-to-guest bytes the scripted agent admits before it returns credit.
pub(crate) const AGENT_CREDIT: u64 = 64 * 1024;

/// Host-to-guest credit a paced guest grants at a time.
pub(crate) const PACED_CREDIT: u64 = 8 * 1024;

/// How long a paced guest takes to grant each [`PACED_CREDIT`]: well inside the forward's idle
/// close bound, while draining one SSH window this way takes twice that bound.
pub(crate) const CREDIT_PACE: Duration =
    Duration::from_millis(GUEST_TCP_CLOSE_IDLE_TIMEOUT.as_millis() as u64 / 4);

/// How long a slow guest takes to write each host record it already holds credit for: inside the
/// forward's idle close bound, while writing the two records one SSH window holds outlasts it.
pub(crate) const SLOW_WRITE: Duration =
    Duration::from_millis(GUEST_TCP_CLOSE_IDLE_TIMEOUT.as_millis() as u64 * 3 / 4);

/// Host-to-guest credit and receive window of a slow guest: far more than one SSH window, so
/// writing that much never reaches the half-window point where ordinary credit is sent.
pub(crate) const SLOW_WINDOW: u64 = 4 * AGENT_CREDIT;

//--------------------------------------------------------------------------------------------------
// Scripted agent
//--------------------------------------------------------------------------------------------------

/// One frame the scripted agent writes to the host.
pub(crate) enum ToHost {
    Control(Message),
    Bulk(BulkRecord),
}

/// One host-to-guest event for a guest socket.
pub(crate) enum ToSocket {
    Record(BulkRecord),
    Finish(BulkFinish),
}

/// Guest-to-host sender state, shared by the socket reader and the host's credit updates.
pub(crate) struct GuestSend {
    state: Mutex<BulkSendState>,
    credit: Notify,
}

/// Sends a connection's one terminal reply, as agentd does once both directions have ended or
/// the destination has failed.
pub(crate) struct GuestTerminal {
    id: u32,
    open_directions: std::sync::atomic::AtomicU8,
    sent: AtomicBool,
    out: mpsc::UnboundedSender<ToHost>,
    /// Set once the host's finish was written to the destination, as agentd's `Teardown::Drain`.
    host_finished: AtomicBool,
}

impl GuestTerminal {
    fn direction_ended(&self) {
        if self.open_directions.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.send();
        }
    }

    /// Answer a host cancel the way agentd does: with the stream's one terminal reply.
    fn fail(&self) {
        if !self.sent.swap(true, Ordering::SeqCst) {
            // A host that hung up has no use for the reply.
            let _ = self.out.send(control(
                MessageType::TcpFailed,
                self.id,
                &TcpFailed {
                    error: "cancelled by the host".into(),
                },
            ));
        }
    }

    fn send(&self) {
        if !self.sent.swap(true, Ordering::SeqCst) {
            // A host that hung up has no use for the reply.
            let _ = self
                .out
                .send(control(MessageType::TcpClosed, self.id, &TcpClosed {}));
        }
    }
}

/// How a guest returns host-to-guest credit, chosen by destination port.
#[derive(Clone, Copy, Default)]
pub(crate) struct GuestPorts {
    /// Never hands host bytes to its destination, so never returns credit, like a guest whose
    /// destination has stopped reading. It still repeats its initial grant every
    /// [`CREDIT_PACE`], which is no progress.
    pub(crate) stalled: Option<u16>,
    /// Returns [`PACED_CREDIT`] at a time, each [`CREDIT_PACE`] after the last bytes were written.
    pub(crate) paced: Option<u16>,
    /// Writes each host record [`SLOW_WRITE`] after it arrives, so credit is still outstanding
    /// when the host finishes. Its window is wide enough that only agentd's per-write reports
    /// after a finish, not half-window credit, show the host that progress.
    pub(crate) slow: Option<u16>,
}

/// How one connection returns host-to-guest credit.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Credit {
    Returned,
    Withheld,
    Paced,
    Slow,
}

/// One forwarded guest connection. Dropping it aborts its socket tasks, which closes the socket.
pub(crate) struct GuestConnection {
    to_socket: mpsc::UnboundedSender<ToSocket>,
    send: Arc<GuestSend>,
    /// Set as soon as the host's finish arrives, ahead of the records it follows, as agentd's
    /// finish channel overtakes its data queue.
    finish_pending: Arc<AtomicBool>,
    socket: RawFd,
    terminal: Arc<GuestTerminal>,
    _tasks: JoinSet<()>,
}

pub(crate) fn control<T: serde::Serialize>(t: MessageType, id: u32, payload: &T) -> ToHost {
    ToHost::Control(Message::with_payload(t, id, payload).unwrap())
}

/// Serve one agent connection the way agentd serves bulk TCP: the guest-to-host flow is sent
/// against the host's credit, and host-to-guest credit is returned once the destination socket
/// has the bytes, except where `ports` says otherwise.
pub(crate) async fn run_agent(listener: TcpListener, ports: GuestPorts) {
    let (socket, _) = listener.accept().await.unwrap();
    let (mut reader, mut writer) = socket.into_split();
    writer.write_all(&1u32.to_be_bytes()).await.unwrap();
    writer.write_all(&1024u32.to_be_bytes()).await.unwrap();
    codec::write_message(
        &mut writer,
        &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
    )
    .await
    .unwrap();
    let (out, mut out_rx) = mpsc::unbounded_channel();
    let writing = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let written = match frame {
                ToHost::Control(message) => codec::write_message(&mut writer, &message).await,
                ToHost::Bulk(record) => codec::write_bulk_record(&mut writer, &record).await,
            };
            // The host hung up; nothing is left to tell it.
            if written.is_err() {
                return;
            }
        }
    });

    let mut connections = HashMap::<u32, GuestConnection>::new();
    while let Ok(frame) = codec::read_raw_frame(&mut reader).await {
        if frame.flags & FLAG_BULK != 0 {
            let record = codec::raw_frame_to_bulk(frame, MAX_BULK_RECORD_PAYLOAD).unwrap();
            // A record racing the host's own cancellation has no connection left to reach.
            if let Some(connection) = connections.get(&record.id) {
                let _ = connection.to_socket.send(ToSocket::Record(record));
            }
            continue;
        }
        let message = codec::raw_frame_to_message(frame).unwrap();
        match message.t {
            MessageType::TcpConnect => {
                if let Some(connection) = open_guest_connection(&message, &out, ports).await {
                    connections.insert(message.id, connection);
                }
            }
            MessageType::BulkCredit => {
                let credit: BulkCredit = message.payload().unwrap();
                if let Some(connection) = connections.get(&message.id) {
                    connection
                        .send
                        .state
                        .lock()
                        .await
                        .apply_credit(credit)
                        .unwrap();
                    connection.send.credit.notify_one();
                }
            }
            MessageType::BulkFinish => {
                let finish: BulkFinish = message.payload().unwrap();
                if let Some(connection) = connections.get(&message.id) {
                    connection.finish_pending.store(true, Ordering::SeqCst);
                    let _ = connection.to_socket.send(ToSocket::Finish(finish));
                }
            }
            MessageType::BulkCancel => {
                let _: BulkCancel = message.payload().unwrap();
                // Like agentd: a stream whose host side ended in order drains to an orderly close;
                // any other is reset. Either way the cancel is answered with a terminal reply.
                if let Some(connection) = connections.remove(&message.id) {
                    if connection.terminal.host_finished.load(Ordering::SeqCst) {
                        clear_linger(connection.socket);
                    }
                    connection.terminal.fail();
                }
            }
            other => panic!("unexpected agent message {other:?}"),
        }
    }
    drop((connections, out));
    writing.await.unwrap();
}

pub(crate) async fn open_guest_connection(
    message: &Message,
    out: &mpsc::UnboundedSender<ToHost>,
    ports: GuestPorts,
) -> Option<GuestConnection> {
    let id = message.id;
    let request: TcpConnect = message.payload().unwrap();
    let credit = if ports.stalled == Some(request.port) {
        Credit::Withheld
    } else if ports.paced == Some(request.port) {
        Credit::Paced
    } else if ports.slow == Some(request.port) {
        Credit::Slow
    } else {
        Credit::Returned
    };
    let (initial_credit, window) = match credit {
        Credit::Paced => (PACED_CREDIT, AGENT_CREDIT),
        Credit::Slow => (SLOW_WINDOW, SLOW_WINDOW),
        Credit::Returned | Credit::Withheld => (AGENT_CREDIT, AGENT_CREDIT),
    };
    let offer = request
        .bulk
        .expect("SSH forwarding negotiates bulk TCP with a generation-9 agent");
    // Like agentd: a refused destination ends the stream with its terminal failure.
    let socket = match TcpStream::connect((request.host.as_str(), request.port)).await {
        Ok(socket) => socket,
        Err(error) => {
            let _ = out.send(control(
                MessageType::TcpFailed,
                id,
                &TcpFailed {
                    error: error.to_string(),
                },
            ));
            return None;
        }
    };
    // A connection dropped before both directions ended is an abort, which the destination sees
    // as a reset rather than an orderly end of stream.
    socket.set_zero_linger().unwrap();
    let socket_fd = socket.as_raw_fd();
    let accepted = BulkAccepted {
        kind: BulkKind::Tcp,
        flows: BULK_FLOW_MASK_HOST_TO_GUEST | BULK_FLOW_MASK_GUEST_TO_HOST,
        format: offer.format,
        max_record_payload: offer.max_record_payload.min(DEFAULT_BULK_RECORD_PAYLOAD),
        host_to_guest_credit_limit: initial_credit,
        guest_to_host_credit_limit: offer.guest_to_host_credit_limit,
    };
    out.send(control(MessageType::TcpConnected, id, &TcpConnected {}))
        .unwrap();
    out.send(control(MessageType::BulkAccepted, id, &accepted))
        .unwrap();

    let send = Arc::new(GuestSend {
        state: Mutex::new(
            BulkSendState::new(
                BulkKind::Tcp,
                BulkFlow::GuestToHost,
                accepted.max_record_payload,
                accepted.guest_to_host_credit_limit,
            )
            .unwrap(),
        ),
        credit: Notify::new(),
    });
    let receive = BulkReceiveState::new(
        BulkKind::Tcp,
        BulkFlow::HostToGuest,
        accepted.max_record_payload,
        initial_credit,
        window,
    )
    .unwrap();
    let (to_socket, events) = mpsc::unbounded_channel();
    // Unlike `into_split`, dropping these halves never shuts the stream down on its own.
    let (socket_reader, socket_writer) = tokio::io::split(socket);
    let terminal = Arc::new(GuestTerminal {
        id,
        open_directions: std::sync::atomic::AtomicU8::new(2),
        sent: AtomicBool::new(false),
        out: out.clone(),
        host_finished: AtomicBool::new(false),
    });
    let mut tasks = JoinSet::new();
    tasks.spawn(relay_socket_to_host(
        id,
        socket_reader,
        Arc::clone(&send),
        out.clone(),
        Arc::clone(&terminal),
    ));
    if credit == Credit::Withheld {
        tasks.spawn(repeat_initial_credit(id, out.clone(), initial_credit));
    }
    let finish_pending = Arc::new(AtomicBool::new(false));
    tasks.spawn(relay_host_to_socket(
        socket_writer,
        events,
        receive,
        out.clone(),
        credit,
        Arc::clone(&finish_pending),
        Arc::clone(&terminal),
    ));
    Some(GuestConnection {
        to_socket,
        send,
        finish_pending,
        socket: socket_fd,
        terminal,
        _tasks: tasks,
    })
}

pub(crate) async fn relay_socket_to_host(
    id: u32,
    mut socket: ReadHalf<TcpStream>,
    send: Arc<GuestSend>,
    out: mpsc::UnboundedSender<ToHost>,
    terminal: Arc<GuestTerminal>,
) {
    let mut buffer = vec![0; DEFAULT_BULK_RECORD_PAYLOAD as usize];
    loop {
        let available = {
            let state = send.state.lock().await;
            state
                .available_credit()
                .min(u64::from(state.max_record_payload())) as usize
        };
        if available == 0 {
            send.credit.notified().await;
            continue;
        }
        // A host that hung up has no use for the rest of this connection.
        match socket.read(&mut buffer[..available]).await {
            Ok(0) => {
                let finish = send.state.lock().await.finish().unwrap();
                let _ = out.send(control(MessageType::BulkFinish, id, &finish));
                terminal.direction_ended();
                return;
            }
            Ok(read) => {
                let offset = send.state.lock().await.admit(read).unwrap();
                let _ = out.send(ToHost::Bulk(BulkRecord {
                    id,
                    kind: BulkKind::Tcp,
                    flow: BulkFlow::GuestToHost,
                    offset,
                    payload: Bytes::copy_from_slice(&buffer[..read]),
                }));
            }
            Err(_) => {
                terminal.send();
                return;
            }
        }
    }
}

pub(crate) async fn repeat_initial_credit(id: u32, out: mpsc::UnboundedSender<ToHost>, limit: u64) {
    let credit = BulkCredit {
        kind: BulkKind::Tcp,
        flow: BulkFlow::HostToGuest,
        consumed_offset: 0,
        credit_limit: limit,
    };
    // The repetition interval is what the stalled guest exists to exercise.
    loop {
        tokio::time::sleep(CREDIT_PACE).await;
        if out
            .send(control(MessageType::BulkCredit, id, &credit))
            .is_err()
        {
            return;
        }
    }
}

pub(crate) async fn relay_host_to_socket(
    mut socket: WriteHalf<TcpStream>,
    mut events: mpsc::UnboundedReceiver<ToSocket>,
    mut receive: BulkReceiveState,
    out: mpsc::UnboundedSender<ToHost>,
    credit_mode: Credit,
    finish_pending: Arc<AtomicBool>,
    terminal: Arc<GuestTerminal>,
) {
    let id = terminal.id;
    while let Some(event) = events.recv().await {
        match event {
            ToSocket::Record(record) => {
                // Admission also proves the host never sends past the credit it was given.
                let end = receive.accept_record(&record).unwrap();
                if credit_mode == Credit::Withheld {
                    continue;
                }
                if credit_mode == Credit::Slow {
                    // The delay before each write is what the slow guest exists to exercise.
                    tokio::time::sleep(SLOW_WRITE).await;
                }
                // A destination that went away is reported by the socket reader.
                if socket.write_all(&record.payload).await.is_err() {
                    return;
                }
                // Like agentd: every write completed while a finish is pending is reported.
                let credit = receive.consume(end).unwrap().or_else(|| {
                    finish_pending.load(Ordering::SeqCst).then(|| BulkCredit {
                        kind: BulkKind::Tcp,
                        flow: BulkFlow::HostToGuest,
                        consumed_offset: end,
                        credit_limit: receive.credit_limit(),
                    })
                });
                let credit = if credit_mode == Credit::Paced {
                    // The pace between grants is what the paced guest exists to exercise.
                    tokio::time::sleep(CREDIT_PACE).await;
                    Some(BulkCredit {
                        kind: BulkKind::Tcp,
                        flow: BulkFlow::HostToGuest,
                        consumed_offset: end,
                        credit_limit: end + PACED_CREDIT,
                    })
                } else {
                    credit
                };
                if let Some(credit) = credit {
                    let _ = out.send(control(MessageType::BulkCredit, id, &credit));
                }
            }
            ToSocket::Finish(finish) => {
                receive.accept_finish(finish).unwrap();
                // Like agentd: the finish waits behind host bytes not yet written, which a
                // guest that withholds them never writes.
                if credit_mode == Credit::Withheld {
                    continue;
                }
                // Like agentd: once every host byte is written, report that before the FIN.
                let drained = BulkCredit {
                    kind: BulkKind::Tcp,
                    flow: BulkFlow::HostToGuest,
                    consumed_offset: receive.next_expected_offset(),
                    credit_limit: receive.credit_limit(),
                };
                let _ = out.send(control(MessageType::BulkCredit, id, &drained));
                if socket.shutdown().await.is_err() {
                    return;
                }
                terminal.host_finished.store(true, Ordering::SeqCst);
                terminal.direction_ended();
            }
        }
    }
}

/// Turn a destination socket's abortive close back into an orderly one.
fn clear_linger(socket: RawFd) {
    let linger = libc::linger {
        l_onoff: 0,
        l_linger: 0,
    };
    // SAFETY: the socket is open while its connection's tasks hold its halves, and the option
    // value is a valid `linger` of the size passed.
    let set = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(
        set,
        0,
        "clear SO_LINGER: {}",
        std::io::Error::last_os_error()
    );
}
