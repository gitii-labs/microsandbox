//! Opt-in non-KVM test agent. Only the guest boundary is scripted: the SDK relay, native
//! registry, Unix descriptors, Go TCPConn and cancellation cleanup are the production path.

use std::collections::HashMap;
use std::os::raw::{c_char, c_uchar};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use microsandbox::agent::AgentClient;
use microsandbox_protocol::{
    bulk::{
        BULK_FLOW_MASK_GUEST_TO_HOST, BULK_FLOW_MASK_HOST_TO_GUEST, BulkAccepted, BulkCancel,
        BulkCancelReason, BulkCredit, BulkFinish, BulkFlow, BulkKind, BulkRecord,
        DEFAULT_BULK_RECORD_PAYLOAD,
    },
    codec,
    core::Ready,
    message::{FLAG_BULK, Message, MessageType},
    tcp::{TcpClosed, TcpConnect, TcpConnected, TcpFailed},
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use super::{FfiError, GuestTcpConnection, Handle, relay_connection, run_c};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CREDIT: u64 = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Observed {
    input: u64,
    finish: bool,
    cancelled: bool,
    disconnected: bool,
    disconnect_on_cancel: bool,
}

struct Fixture {
    events: mpsc::UnboundedSender<u8>,
    observed: watch::Receiver<Observed>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn fixtures() -> &'static RwLock<HashMap<Handle, Arc<Fixture>>> {
    static FIXTURES: OnceLock<RwLock<HashMap<Handle, Arc<Fixture>>>> = OnceLock::new();
    FIXTURES.get_or_init(|| RwLock::new(HashMap::new()))
}

async fn send<T: serde::Serialize>(
    socket: &mut OwnedWriteHalf,
    id: u32,
    t: MessageType,
    p: &T,
) -> microsandbox_protocol::ProtocolResult<()> {
    let mut wire = Vec::new();
    codec::encode_to_buf(&Message::with_payload(t, id, p).unwrap(), &mut wire)?;
    // Tokio's scalar TCP write uses MSG_NOSIGNAL. Its vectored write uses writev, which can
    // kill a Go host from this Rust worker if cleanup closed the peer before this reply.
    socket.write_all(&wire).await?;
    Ok(())
}

async fn serve(
    listener: TcpListener,
    mut events: mpsc::UnboundedReceiver<u8>,
    observed: watch::Sender<Observed>,
) {
    let (socket, _) = listener.accept().await.unwrap();
    let (mut reader, mut socket) = socket.into_split();
    socket.write_all(&1u32.to_be_bytes()).await.unwrap();
    socket.write_all(&1024u32.to_be_bytes()).await.unwrap();
    send(&mut socket, 0, MessageType::Ready, &Ready::default())
        .await
        .unwrap();
    let frame = codec::read_raw_frame(&mut reader).await.unwrap();
    let message = codec::raw_frame_to_message(frame).unwrap();
    assert_eq!(message.t, MessageType::TcpConnect);
    let id = message.id;
    let request: TcpConnect = message.payload().unwrap();
    let offer = request.bulk.unwrap();
    send(&mut socket, id, MessageType::TcpConnected, &TcpConnected {})
        .await
        .unwrap();
    send(
        &mut socket,
        id,
        MessageType::BulkAccepted,
        &BulkAccepted {
            kind: BulkKind::Tcp,
            flows: BULK_FLOW_MASK_HOST_TO_GUEST | BULK_FLOW_MASK_GUEST_TO_HOST,
            format: offer.format,
            max_record_payload: DEFAULT_BULK_RECORD_PAYLOAD.min(offer.max_record_payload),
            host_to_guest_credit_limit: CREDIT,
            guest_to_host_credit_limit: offer.guest_to_host_credit_limit,
        },
    )
    .await
    .unwrap();
    let (frames, mut input) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        // Frame reads are not cancel-safe. Only select on completed frames below.
        while let Ok(frame) = codec::read_raw_frame(&mut reader).await {
            if frames.send(frame).is_err() {
                break;
            }
        }
    });
    let mut terminal_sent = false;
    let mut guest_finished = false;
    loop {
        tokio::select! {
            frame = input.recv() => {
                let Some(frame) = frame else { break; };
                if frame.flags & FLAG_BULK != 0 {
                    let record = codec::raw_frame_to_bulk(frame, DEFAULT_BULK_RECORD_PAYLOAD).unwrap();
                    observed.send_modify(|state| state.input += record.payload.len() as u64);
                    assert!(observed.borrow().input <= CREDIT, "host exceeded credit");
                    continue;
                }
                let message = codec::raw_frame_to_message(frame).unwrap();
                match message.t {
                    MessageType::BulkFinish => {
                        observed.send_modify(|state| state.finish = true);
                        if guest_finished {
                            if send(&mut socket, id, MessageType::TcpClosed, &TcpClosed {}).await.is_err() { break; }
                            terminal_sent = true;
                        }
                    }
                    MessageType::BulkCancel => {
                        let _: BulkCancel = message.payload().unwrap();
                        observed.send_modify(|state| state.cancelled = true);
                        if observed.borrow().disconnect_on_cancel { break; }
                        if terminal_sent { continue; }
                        // Force the credit-after-cancel ordering on every cleanup, including finalizers.
                        if send(&mut socket, id, MessageType::BulkCredit, &BulkCredit {
                            kind: BulkKind::Tcp, flow: BulkFlow::HostToGuest,
                            consumed_offset: 0, credit_limit: CREDIT,
                        }).await.is_err() { break; }
                        if send(&mut socket, id, MessageType::TcpFailed, &TcpFailed { error: "host cancelled".into() }).await.is_err() { break; }
                        terminal_sent = true;
                    }
                    MessageType::BulkCredit => {},
                    other => panic!("unexpected host message {other:?}"),
                }
            }
            event = events.recv() => {
                match event {
                    Some(1) => {
                        if send(&mut socket, id, MessageType::BulkCancel, &BulkCancel {
                            kind: BulkKind::Tcp, reason: BulkCancelReason::CallerCancelled,
                            message: "guest reset".into(),
                        }).await.is_err() { break; }
                        if send(&mut socket, id, MessageType::TcpFailed, &TcpFailed { error: "guest reset".into() }).await.is_err() { break; }
                        terminal_sent = true;
                    }
                    Some(2) => { if send(&mut socket, id, MessageType::TcpConnected, &TcpConnected {}).await.is_err() { break; } },
                    Some(3) => {
                        if send(&mut socket, id, MessageType::BulkFinish, &BulkFinish { kind: BulkKind::Tcp, flow: BulkFlow::GuestToHost, final_offset: 0 }).await.is_err() { break; }
                        guest_finished = true;
                        if observed.borrow().finish {
                            if send(&mut socket, id, MessageType::TcpClosed, &TcpClosed {}).await.is_err() { break; }
                            terminal_sent = true;
                        }
                    }
                    Some(4) => {
                        if send(&mut socket, id, MessageType::BulkCredit, &BulkCredit { kind: BulkKind::Tcp, flow: BulkFlow::HostToGuest, consumed_offset: CREDIT + 1, credit_limit: CREDIT + 1 }).await.is_err() { break; }
                    }
                    Some(5) => {
                        let mut wire = Vec::new();
                        codec::encode_bulk_to_buf(&BulkRecord { id, kind: BulkKind::Tcp, flow: BulkFlow::GuestToHost, offset: 1, payload: b"invalid offset".as_slice().into() }, &mut wire).unwrap();
                        if socket.write_all(&wire).await.is_err() { break; }
                    }
                    Some(6) => break,
                    Some(7) => observed.send_modify(|state| state.disconnect_on_cancel = true),
                    Some(8) => {
                        // agentd's established-socket I/O failure has no BulkCancel or finish.
                        if send(&mut socket, id, MessageType::TcpFailed, &TcpFailed { error: "read TCP stream: connection reset".into() }).await.is_err() { break; }
                        terminal_sent = true;
                    }
                    Some(other) => panic!("unexpected fixture event {other}"),
                    None => break,
                }
            }
        }
    }
    observed.send_modify(|state| state.disconnected = true);
}

/// Dial through a real loopback agent, then use the production socket-pair registration.
/// cbindgen:ignore
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_test_tcp_dial(
    cancel_id: u64,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        Ok(Box::pin(async {
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .map_err(super::socket_error)?;
            let address = listener.local_addr().map_err(super::socket_error)?;
            let (events, rx) = mpsc::unbounded_channel();
            let (observed, state) = watch::channel(Observed::default());
            tokio::spawn(serve(listener, rx, observed));
            let socket = TcpStream::connect(address)
                .await
                .map_err(super::socket_error)?;
            let client = Arc::new(
                AgentClient::connect_stream_with_timeout(socket, Duration::from_secs(2))
                    .await
                    .map_err(microsandbox::MicrosandboxError::from)?,
            );
            let connection = GuestTcpConnection::connect(client, "127.0.0.1", 80).await?;
            let result = relay_connection(connection)?;
            let value: serde_json::Value = serde_json::from_str(&result).unwrap();
            let handle = value["conn"].as_u64().unwrap();
            fixtures().write().unwrap().insert(
                handle,
                Arc::new(Fixture {
                    events,
                    observed: state,
                }),
            );
            Ok(result)
        }))
    })
}

/// Send a guest reset (1), unexpected control (2), ordered EOF (3), invalid credit (4), invalid
/// record (5), disconnect (6), arm disconnect on the next host cancel (7), or a failed socket
/// terminal without cancel/EOF (8). Await admitted input (10), host finish (11), host cancel (12),
/// or agent disconnect (13). Waiting is cancelable through the real FFI token.
/// cbindgen:ignore
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_test_tcp_event(
    cancel_id: u64,
    conn: Handle,
    event: u8,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let fixture = fixtures()
            .read()
            .unwrap()
            .get(&conn)
            .cloned()
            .ok_or_else(|| FfiError::invalid_handle(conn))?;
        Ok(Box::pin(async move {
            match event {
                1..=6 => fixture
                    .events
                    .send(event)
                    .map_err(|_| FfiError::internal("test agent disconnected"))?,
                8 => fixture
                    .events
                    .send(event)
                    .map_err(|_| FfiError::internal("test agent disconnected"))?,
                7 => {
                    fixture
                        .events
                        .send(event)
                        .map_err(|_| FfiError::internal("test agent disconnected"))?;
                    let mut observed = fixture.observed.clone();
                    observed
                        .wait_for(|state| state.disconnect_on_cancel)
                        .await
                        .map_err(|_| FfiError::internal("test agent observation lost"))?;
                }
                10..=13 => {
                    let mut observed = fixture.observed.clone();
                    observed
                        .wait_for(|state| match event {
                            10 => state.input == CREDIT,
                            11 => state.finish,
                            12 => state.cancelled,
                            13 => state.disconnected,
                            _ => unreachable!(),
                        })
                        .await
                        .map_err(|_| FfiError::internal("test agent observation lost"))?;
                    if event == 13 {
                        fixtures().write().unwrap().remove(&conn);
                    }
                }
                _ => return Err(FfiError::internal("invalid test event")),
            }
            Ok(r#"{"ok":true}"#.into())
        }))
    })
}
