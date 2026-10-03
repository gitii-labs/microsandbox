//! [`GuestTcpStream`] over a real loopback agent connection, against a scripted agent that
//! negotiates the generation-9 bulk TCP path and relays real loopback destination sockets the
//! way agentd does.

use std::collections::HashMap;
use std::sync::atomic::AtomicU8;

use super::*;
use microsandbox_protocol::{
    bulk::{DEFAULT_BULK_RECORD_PAYLOAD, MAX_BULK_RECORD_PAYLOAD},
    codec,
    core::Ready,
    message::FLAG_BULK,
    tcp::TcpClosed,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

/// Host-to-guest bytes the scripted guest admits before it returns credit: far below the
/// transfers below, so they only pass if credit keeps flowing.
const AGENT_CREDIT: u64 = 64 * 1024;

/// How long a test waits to prove that something does not happen.
const SETTLE: Duration = Duration::from_millis(300);

//--------------------------------------------------------------------------------------------------
// Scripted agent
//--------------------------------------------------------------------------------------------------

enum ToHost {
    Control(Message),
    Bulk(BulkRecord),
}

enum ToSocket {
    Record(BulkRecord),
    Finish(BulkFinish),
}

struct GuestSend {
    state: tokio::sync::Mutex<BulkSendState>,
    credit: Notify,
}

/// Sends the connection's one terminal reply once both directions have ended.
struct GuestTerminal {
    id: u32,
    open_directions: AtomicU8,
    sent: AtomicBool,
    out: mpsc::UnboundedSender<ToHost>,
}

impl GuestTerminal {
    fn direction_ended(&self) {
        if self.open_directions.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.send(MessageType::TcpClosed);
        }
    }

    fn send(&self, kind: MessageType) {
        if self.sent.swap(true, Ordering::SeqCst) {
            return;
        }
        let message = match kind {
            MessageType::TcpClosed => Message::with_payload(kind, self.id, &TcpClosed {}),
            _ => Message::with_payload(
                kind,
                self.id,
                &TcpFailed {
                    error: "cancelled".into(),
                },
            ),
        };
        // A host that hung up has no use for the reply.
        let _ = self.out.send(ToHost::Control(message.unwrap()));
    }
}

/// Whether the guest never writes host bytes to its destinations, so never returns credit, like
/// a guest whose destination has stopped reading.
#[derive(Clone, Copy, Default)]
struct Stalled(bool);

struct GuestConnection {
    to_socket: mpsc::UnboundedSender<ToSocket>,
    send: Arc<GuestSend>,
    terminal: Arc<GuestTerminal>,
    _tasks: JoinSet<()>,
}

fn control<T: serde::Serialize>(t: MessageType, id: u32, payload: &T) -> ToHost {
    ToHost::Control(Message::with_payload(t, id, payload).unwrap())
}

async fn run_agent(listener: TcpListener, stalled: Stalled) {
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
            if written.is_err() {
                return;
            }
        }
    });

    let mut connections = HashMap::<u32, GuestConnection>::new();
    while let Ok(frame) = codec::read_raw_frame(&mut reader).await {
        if frame.flags & FLAG_BULK != 0 {
            let record = codec::raw_frame_to_bulk(frame, MAX_BULK_RECORD_PAYLOAD).unwrap();
            if let Some(connection) = connections.get(&record.id) {
                let _ = connection.to_socket.send(ToSocket::Record(record));
            }
            continue;
        }
        let message = codec::raw_frame_to_message(frame).unwrap();
        match message.t {
            MessageType::TcpConnect => {
                if let Some(connection) = open_guest_connection(&message, &out, stalled).await {
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
                    let _ = connection.to_socket.send(ToSocket::Finish(finish));
                }
            }
            MessageType::BulkCancel => {
                let _: BulkCancel = message.payload().unwrap();
                // Like agentd: dropping the socket resets it, and the cancel is answered with
                // the stream's terminal reply.
                if let Some(connection) = connections.remove(&message.id) {
                    connection.terminal.send(MessageType::TcpFailed);
                }
            }
            other => panic!("unexpected agent message {other:?}"),
        }
    }
    drop((connections, out));
    writing.await.unwrap();
}

async fn open_guest_connection(
    message: &Message,
    out: &mpsc::UnboundedSender<ToHost>,
    stalled: Stalled,
) -> Option<GuestConnection> {
    let id = message.id;
    let request: TcpConnect = message.payload().unwrap();
    let offer = request.bulk.expect("the dial negotiates bulk TCP");
    let socket = match TcpStream::connect((request.host.as_str(), request.port)).await {
        Ok(socket) => socket,
        Err(error) => {
            out.send(control(
                MessageType::TcpFailed,
                id,
                &TcpFailed {
                    error: error.to_string(),
                },
            ))
            .unwrap();
            return None;
        }
    };
    // A connection dropped before both directions ended is an abort: the destination sees a
    // reset rather than an orderly end of stream.
    socket.set_zero_linger().unwrap();
    let accepted = BulkAccepted {
        kind: BulkKind::Tcp,
        flows: BULK_FLOW_MASK_HOST_TO_GUEST | BULK_FLOW_MASK_GUEST_TO_HOST,
        format: offer.format,
        max_record_payload: offer.max_record_payload.min(DEFAULT_BULK_RECORD_PAYLOAD),
        host_to_guest_credit_limit: AGENT_CREDIT,
        guest_to_host_credit_limit: offer.guest_to_host_credit_limit,
    };
    out.send(control(MessageType::TcpConnected, id, &TcpConnected {}))
        .unwrap();
    out.send(control(MessageType::BulkAccepted, id, &accepted))
        .unwrap();

    let send = Arc::new(GuestSend {
        state: tokio::sync::Mutex::new(
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
        AGENT_CREDIT,
        AGENT_CREDIT,
    )
    .unwrap();
    let (to_socket, events) = mpsc::unbounded_channel();
    let (socket_reader, socket_writer) = tokio::io::split(socket);
    let terminal = Arc::new(GuestTerminal {
        id,
        open_directions: AtomicU8::new(2),
        sent: AtomicBool::new(false),
        out: out.clone(),
    });
    let mut tasks = JoinSet::new();
    tasks.spawn(relay_socket_to_host(
        id,
        socket_reader,
        Arc::clone(&send),
        out.clone(),
        Arc::clone(&terminal),
    ));
    tasks.spawn(relay_host_to_socket(
        socket_writer,
        events,
        receive,
        out.clone(),
        stalled.0,
        Arc::clone(&terminal),
    ));
    Some(GuestConnection {
        to_socket,
        send,
        terminal,
        _tasks: tasks,
    })
}

async fn relay_socket_to_host(
    id: u32,
    mut socket: ReadHalf<TcpStream>,
    send: Arc<GuestSend>,
    out: mpsc::UnboundedSender<ToHost>,
    terminal: Arc<GuestTerminal>,
) {
    let mut buffer = vec![0; DEFAULT_BULK_RECORD_PAYLOAD as usize];
    loop {
        let notified = send.credit.notified();
        let available = {
            let state = send.state.lock().await;
            state
                .available_credit()
                .min(u64::from(state.max_record_payload())) as usize
        };
        if available == 0 {
            notified.await;
            continue;
        }
        match socket.read(&mut buffer[..available]).await {
            Ok(0) => {
                let finish = send.state.lock().await.finish().unwrap();
                let _ = out.send(control(MessageType::BulkFinish, id, &finish));
                terminal.direction_ended();
                return;
            }
            Ok(read) => {
                // Admission proves the guest never sends past the credit the host granted.
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
                terminal.send(MessageType::TcpFailed);
                return;
            }
        }
    }
}

async fn relay_host_to_socket(
    mut socket: WriteHalf<TcpStream>,
    mut events: mpsc::UnboundedReceiver<ToSocket>,
    mut receive: BulkReceiveState,
    out: mpsc::UnboundedSender<ToHost>,
    stalled: bool,
    terminal: Arc<GuestTerminal>,
) {
    let id = terminal.id;
    while let Some(event) = events.recv().await {
        match event {
            ToSocket::Record(record) => {
                // Admission also proves the host never sends past the credit it was given.
                let end = receive.accept_record(&record).unwrap();
                if stalled {
                    continue;
                }
                if socket.write_all(&record.payload).await.is_err() {
                    return;
                }
                if let Some(credit) = receive.consume(end).unwrap() {
                    let _ = out.send(control(MessageType::BulkCredit, id, &credit));
                }
            }
            ToSocket::Finish(finish) => {
                receive.accept_finish(finish).unwrap();
                // A stalled guest is still writing the earlier records, so the finish waits.
                if stalled {
                    continue;
                }
                // Like agentd: every host byte is written, so report that before the FIN.
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
                terminal.direction_ended();
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Fixture
//--------------------------------------------------------------------------------------------------

struct Fixture {
    client: Arc<AgentClient>,
    destination: TcpListener,
    agent: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(stalled: Stalled) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let agent = tokio::spawn(run_agent(listener, stalled));
        let client = Arc::new(
            AgentClient::connect_stream_with_timeout(
                TcpStream::connect(address).await.unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap(),
        );
        assert!(client.supports(MessageType::BulkAccepted));
        Self {
            client,
            destination: TcpListener::bind(("127.0.0.1", 0)).await.unwrap(),
            agent,
        }
    }

    fn port(&self) -> u16 {
        self.destination.local_addr().unwrap().port()
    }

    /// Dial the destination and accept the guest's connection to it.
    async fn dial(&self) -> (GuestTcpStream, TcpStream) {
        let stream = GuestTcpStream::connect(Arc::clone(&self.client), "127.0.0.1", self.port())
            .await
            .unwrap();
        let (peer, _) = self.destination.accept().await.unwrap();
        (stream, peer)
    }

    /// Drop the agent connection and wait for the agent, which ends only once the host hung up.
    async fn finish(self) {
        drop(self.client);
        self.agent.await.unwrap();
    }
}

async fn read_to_end(stream: &GuestTcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    while let Some(chunk) = stream.read().await.unwrap() {
        data.extend_from_slice(&chunk);
    }
    data
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn transfers_far_beyond_the_credit_window_in_both_directions() {
    let fixture = Fixture::new(Stalled::default()).await;
    let (stream, peer) = fixture.dial().await;
    // Larger than both windows: the host's offer to the guest and the guest's AGENT_CREDIT.
    let upload = pattern(16 * AGENT_CREDIT as usize, 7);
    let download = pattern(
        BulkOffer::tcp().guest_to_host_credit_limit as usize + 300_000,
        3,
    );

    let (mut peer_read, mut peer_write) = peer.into_split();
    let destination = {
        let download = download.clone();
        tokio::spawn(async move {
            let writing = async {
                peer_write.write_all(&download).await.unwrap();
                peer_write.shutdown().await.unwrap();
            };
            let mut received = Vec::new();
            let reading = peer_read.read_to_end(&mut received);
            let ((), read) = tokio::join!(writing, reading);
            read.unwrap();
            received
        })
    };
    let (written, received) = tokio::join!(
        async {
            stream.write(upload.clone()).await.unwrap();
            stream.shutdown_write().await.unwrap();
        },
        read_to_end(&stream),
    );
    let () = written;
    assert_eq!(received, download);
    assert_eq!(destination.await.unwrap(), upload);
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    drop(stream);
    fixture.finish().await;
}

#[tokio::test]
async fn a_stalled_destination_stops_the_writer_at_the_credit_window() {
    let fixture = Fixture::new(Stalled(true)).await;
    let (stream, mut peer) = fixture.dial().await;

    let written =
        tokio::time::timeout(SETTLE, stream.write(pattern(4 * AGENT_CREDIT as usize, 1))).await;
    assert!(
        written.is_err(),
        "a write past the window must wait for credit"
    );
    // The guest admitted exactly its window and never more.
    {
        let send = stream.shared.send.lock().unwrap();
        assert_eq!(send.next_offset(), AGENT_CREDIT);
        assert_eq!(send.consumed_offset(), 0);
    }

    assert_eq!(stream.abort().await, GuestTcpCleanup::Acknowledged);
    let mut buffer = [0; 1];
    let reset = peer.read(&mut buffer).await;
    assert!(
        reset.is_err(),
        "an aborted connection resets its destination: {reset:?}"
    );
    assert!(stream.write(Bytes::from_static(b"late")).await.is_err());
    assert!(stream.read().await.is_err());
    drop(stream);
    fixture.finish().await;
}

#[tokio::test]
async fn host_half_close_leaves_the_guest_side_readable() {
    let fixture = Fixture::new(Stalled::default()).await;
    let (stream, mut peer) = fixture.dial().await;

    stream.write(Bytes::from_static(b"request")).await.unwrap();
    stream.shutdown_write().await.unwrap();
    assert!(stream.write(Bytes::from_static(b"more")).await.is_err());
    let mut request = Vec::new();
    peer.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");

    peer.write_all(b"response").await.unwrap();
    peer.shutdown().await.unwrap();
    assert_eq!(read_to_end(&stream).await, b"response");
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    drop(stream);
    fixture.finish().await;
}

#[tokio::test]
async fn guest_half_close_leaves_the_host_side_writable() {
    let fixture = Fixture::new(Stalled::default()).await;
    let (stream, mut peer) = fixture.dial().await;

    peer.write_all(b"banner").await.unwrap();
    peer.shutdown().await.unwrap();
    assert_eq!(read_to_end(&stream).await, b"banner");
    assert!(stream.read().await.unwrap().is_none());

    stream
        .write(Bytes::from_static(b"after eof"))
        .await
        .unwrap();
    stream.shutdown_write().await.unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"after eof");
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    drop(stream);
    fixture.finish().await;
}

#[tokio::test]
async fn close_delivers_every_written_byte_before_releasing() {
    let fixture = Fixture::new(Stalled::default()).await;
    let (stream, mut peer) = fixture.dial().await;
    let upload = pattern(8 * AGENT_CREDIT as usize, 9);

    stream.write(upload.clone()).await.unwrap();
    let reading = tokio::spawn(async move {
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.map(|_| received)
    });
    // The destination never ends its side, so the release is a cancel after the drain.
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    // agentd hands a finished, drained socket to an orderly drain; this scripted guest resets
    // instead. Either way every byte arrived first, which is what close promises.
    match reading.await.unwrap() {
        Ok(received) => assert_eq!(received, upload),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        stream.shared.send.lock().unwrap().consumed_offset(),
        upload.len() as u64
    );
    drop(stream);
    fixture.finish().await;
}

#[tokio::test]
async fn close_reports_bytes_a_stalled_guest_never_wrote() {
    let fixture = Fixture::new(Stalled(true)).await;
    let (stream, _peer) = fixture.dial().await;

    stream.write(pattern(1000, 2)).await.unwrap();
    let started = tokio::time::Instant::now();
    let error = stream.close().await.unwrap_err();
    assert!(error.to_string().contains("1000 bytes"), "{error}");
    assert!(started.elapsed() >= GUEST_TCP_CLOSE_IDLE_TIMEOUT);
    drop(stream);
    fixture.finish().await;
}

#[tokio::test]
async fn a_refused_destination_fails_the_dial() {
    let fixture = Fixture::new(Stalled::default()).await;
    let port = fixture.port();
    let Fixture {
        client,
        destination,
        agent,
    } = fixture;
    drop(destination);
    let error = GuestTcpStream::connect(Arc::clone(&client), "127.0.0.1", port)
        .await
        .err()
        .expect("nothing listens on the port");
    assert!(error.to_string().contains("guest TCP connect"), "{error}");
    drop(client);
    agent.await.unwrap();
}

#[tokio::test]
async fn dropping_a_stream_releases_the_guest_socket() {
    let fixture = Fixture::new(Stalled::default()).await;
    let (stream, mut peer) = fixture.dial().await;
    drop(stream);
    let mut buffer = [0; 1];
    let reset = peer.read(&mut buffer).await;
    assert!(
        reset.is_err(),
        "a dropped stream aborts its destination: {reset:?}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn concurrent_dials_stay_independent() {
    const CONNECTIONS: usize = 16;
    let fixture = Arc::new(Fixture::new(Stalled::default()).await);
    let port = fixture.port();
    let mut echoes = JoinSet::new();
    let acceptor = {
        let fixture = Arc::clone(&fixture);
        tokio::spawn(async move {
            for _ in 0..CONNECTIONS {
                let (mut peer, _) = fixture.destination.accept().await.unwrap();
                echoes.spawn(async move {
                    let (mut read, mut write) = peer.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                    write.shutdown().await.unwrap();
                });
            }
            while let Some(echo) = echoes.join_next().await {
                echo.unwrap();
            }
        })
    };
    let mut dials = JoinSet::new();
    for seed in 0..CONNECTIONS {
        let client = Arc::clone(&fixture.client);
        dials.spawn(async move {
            let stream = GuestTcpStream::connect(client, "127.0.0.1", port)
                .await
                .unwrap();
            let payload = pattern(3 * AGENT_CREDIT as usize + seed, seed as u8);
            let (written, echoed) = tokio::join!(
                async {
                    stream.write(payload.clone()).await.unwrap();
                    stream.shutdown_write().await.unwrap();
                },
                read_to_end(&stream),
            );
            let () = written;
            assert_eq!(echoed, payload);
            assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
        });
    }
    while let Some(dial) = dials.join_next().await {
        dial.unwrap();
    }
    acceptor.await.unwrap();
    Arc::into_inner(fixture).unwrap().finish().await;
}
