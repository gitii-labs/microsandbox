//! SSH direct-tcpip forwarding through the real [`SshSession`] on a loopback SSH connection,
//! against a scripted agent that negotiates the generation-9 bulk TCP path and relays real
//! loopback sockets.

use super::*;
use microsandbox_protocol::{
    bulk::{BulkAccepted, DEFAULT_BULK_RECORD_PAYLOAD, MAX_BULK_RECORD_PAYLOAD},
    codec,
    core::Ready,
    message::{FLAG_BULK, Message},
};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

/// Host-to-guest bytes the scripted agent admits before it returns credit.
const AGENT_CREDIT: u64 = 64 * 1024;

/// Receive window the SSH server grants each channel.
const SSH_WINDOW: u32 = 64 * 1024;

/// Largest SSH packet the server accepts. It divides [`AGENT_CREDIT`] and [`SSH_WINDOW`], so
/// every packet is admitted by the guest, and its window returned, whole.
const SSH_PACKET: u32 = 32 * 1024;

//--------------------------------------------------------------------------------------------------
// Scripted agent
//--------------------------------------------------------------------------------------------------

/// One frame the scripted agent writes to the host.
enum ToHost {
    Control(Message),
    Bulk(BulkRecord),
}

/// One host-to-guest event for a guest socket.
enum ToSocket {
    Record(BulkRecord),
    Finish(BulkFinish),
}

/// Guest-to-host sender state, shared by the socket reader and the host's credit updates.
struct GuestSend {
    state: Mutex<BulkSendState>,
    credit: Notify,
}

/// One forwarded guest connection. Dropping it aborts its socket tasks, which closes the socket.
struct GuestConnection {
    to_socket: mpsc::UnboundedSender<ToSocket>,
    send: Arc<GuestSend>,
    _tasks: JoinSet<()>,
}

fn control<T: serde::Serialize>(t: MessageType, id: u32, payload: &T) -> ToHost {
    ToHost::Control(Message::with_payload(t, id, payload).unwrap())
}

/// Serve one agent connection the way agentd serves bulk TCP: the guest-to-host flow is sent
/// against the host's credit, and host-to-guest credit is returned once the destination socket
/// has the bytes. A connection to `stalled_port` never hands host bytes to its destination, so
/// it never returns credit, like a guest whose destination has stopped reading.
async fn run_agent(listener: TcpListener, stalled_port: Option<u16>) {
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
                let connection = open_guest_connection(&message, &out, stalled_port).await;
                connections.insert(message.id, connection);
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
                connections.remove(&message.id);
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
    stalled_port: Option<u16>,
) -> GuestConnection {
    let id = message.id;
    let request: TcpConnect = message.payload().unwrap();
    let offer = request
        .bulk
        .expect("SSH forwarding negotiates bulk TCP with a generation-9 agent");
    let socket = TcpStream::connect((request.host.as_str(), request.port))
        .await
        .unwrap();
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
        AGENT_CREDIT,
        AGENT_CREDIT,
    )
    .unwrap();
    let (to_socket, events) = mpsc::unbounded_channel();
    let (socket_reader, socket_writer) = socket.into_split();
    let mut tasks = JoinSet::new();
    tasks.spawn(relay_socket_to_host(
        id,
        socket_reader,
        Arc::clone(&send),
        out.clone(),
    ));
    tasks.spawn(relay_host_to_socket(
        id,
        socket_writer,
        events,
        receive,
        out.clone(),
        stalled_port == Some(request.port),
    ));
    GuestConnection {
        to_socket,
        send,
        _tasks: tasks,
    }
}

async fn relay_socket_to_host(
    id: u32,
    mut socket: OwnedReadHalf,
    send: Arc<GuestSend>,
    out: mpsc::UnboundedSender<ToHost>,
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
                let _ = out.send(control(MessageType::TcpClosed, id, &TcpClosed {}));
                return;
            }
        }
    }
}

async fn relay_host_to_socket(
    id: u32,
    mut socket: OwnedWriteHalf,
    mut events: mpsc::UnboundedReceiver<ToSocket>,
    mut receive: BulkReceiveState,
    out: mpsc::UnboundedSender<ToHost>,
    stalled: bool,
) {
    while let Some(event) = events.recv().await {
        match event {
            ToSocket::Record(record) => {
                // Admission also proves the host never sends past the credit it was given.
                let end = receive.accept_record(&record).unwrap();
                if stalled {
                    continue;
                }
                // A destination that went away is reported by the socket reader.
                if socket.write_all(&record.payload).await.is_err() {
                    return;
                }
                if let Some(credit) = receive.consume(end).unwrap() {
                    let _ = out.send(control(MessageType::BulkCredit, id, &credit));
                }
            }
            ToSocket::Finish(finish) => {
                receive.accept_finish(finish).unwrap();
                if socket.shutdown().await.is_err() {
                    return;
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// SSH fixture
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Client {
    adjustments: usize,
    stop_after: Option<usize>,
    stalled: Option<oneshot::Sender<()>>,
}

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn adjust_window(&mut self, _: ChannelId, window: u32) -> u32 {
        self.adjustments += 1;
        if self.stop_after.is_some_and(|n| self.adjustments >= n) {
            1
        } else {
            window
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        if self.stop_after.is_some_and(|n| self.adjustments >= n)
            && session.sender_window_size(channel) == 0
            && let Some(stalled) = self.stalled.take()
        {
            stalled.send(()).unwrap();
        }
        Ok(())
    }
}

struct FixtureOptions {
    client: Client,
    client_window: u32,
    event_buffer_size: Option<usize>,
    stalled_port: Option<u16>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            client: Client::default(),
            client_window: SSH_WINDOW,
            event_buffer_size: None,
            stalled_port: None,
        }
    }
}

struct Fixture {
    client: russh::client::Handle<Client>,
    destination: TcpListener,
    server: tokio::task::JoinHandle<()>,
    agent: tokio::task::JoinHandle<()>,
    _home: tempfile::TempDir,
}

impl Fixture {
    async fn new(options: FixtureOptions) -> Self {
        let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let agent_address = agent_listener.local_addr().unwrap();
        let agent = tokio::spawn(run_agent(agent_listener, options.stalled_port));
        let agent_client = Arc::new(
            AgentClient::connect_stream_with_timeout(
                TcpStream::connect(agent_address).await.unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap(),
        );
        assert!(agent_client.supports(MessageType::BulkAccepted));

        let home = tempfile::tempdir().unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let mut config = crate::SandboxConfig::default();
        config.spec.name = "ssh-forward".into();
        let sandbox = Sandbox::from_local(
            backend,
            crate::backend::SandboxLocalState {
                db_id: 0,
                handle: None,
                client: Arc::clone(&agent_client),
            },
            config,
        );
        let key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let mut session = SshSession::new(SshSettings {
            sandbox,
            authorized_keys: Arc::new(vec![key.public_key().public_key_base64()]),
            guest_user: None,
            sftp: false,
        });
        session.client = Some(agent_client);

        let mut server_config = russh::server::Config {
            keys: vec![
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap(),
            ],
            window_size: SSH_WINDOW,
            maximum_packet_size: SSH_PACKET,
            ..Default::default()
        };
        if let Some(size) = options.event_buffer_size {
            server_config.event_buffer_size = size;
        }
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(server_config, socket, session)
                .await
                .unwrap()
                .await
                .unwrap();
        });

        let client_config = Arc::new(russh::client::Config {
            window_size: options.client_window,
            ..Default::default()
        });
        let mut client = russh::client::connect(client_config, address, options.client)
            .await
            .unwrap();
        assert!(
            client
                .authenticate_publickey("test", PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .unwrap()
                .success()
        );
        Self {
            client,
            destination: TcpListener::bind(("127.0.0.1", 0)).await.unwrap(),
            server,
            agent,
            _home: home,
        }
    }

    /// Open a forward to `destination` and accept the guest's connection to it.
    async fn open_to(&self, destination: &TcpListener) -> (Channel<ClientMsg>, TcpStream) {
        let port = destination.local_addr().unwrap().port();
        let channel = self
            .client
            .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0)
            .await
            .unwrap();
        let (peer, _) = destination.accept().await.unwrap();
        (channel, peer)
    }

    async fn open(&self) -> (Channel<ClientMsg>, TcpStream) {
        self.open_to(&self.destination).await
    }

    /// Disconnect and wait for the server and the agent to finish, which they do only once
    /// every forward has cancelled its guest stream.
    async fn finish(self) {
        self.client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
            .await
            .unwrap();
        drop(self.client);
        self.server.await.unwrap();
        self.agent.await.unwrap();
    }
}

/// Close a channel and wait for the server's close, so nothing is left for it to answer when the
/// client disconnects.
async fn close(mut channel: Channel<ClientMsg>) {
    channel.close().await.unwrap();
    while let Some(message) = channel.wait().await {
        if matches!(message, ChannelMsg::Close) {
            return;
        }
    }
}

/// The next data a channel delivers, past its window updates.
async fn next_data(channel: &mut Channel<ClientMsg>) -> Bytes {
    loop {
        match channel.wait().await.unwrap() {
            ChannelMsg::Data { data } => return data,
            ChannelMsg::WindowAdjusted { .. } => {}
            other => panic!("expected channel data, got {other:?}"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// A guest stream that stops draining holds its SSH peer to exactly the bytes the guest admitted
/// plus one receive window, while new channels on the same connection keep working.
#[tokio::test]
async fn stalled_guest_stream_holds_its_peer_and_leaves_the_connection_live() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let stalled = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let fixture = Fixture::new(FixtureOptions {
            stalled_port: Some(stalled.local_addr().unwrap().port()),
            ..Default::default()
        })
        .await;
        let (forwarded, _held) = fixture.open_to(&stalled).await;
        // The guest admits its credit and the server returns window for exactly those bytes.
        forwarded
            .data_bytes(vec![0u8; AGENT_CREDIT as usize + SSH_WINDOW as usize])
            .await
            .unwrap();

        // The session loop still opens channels and forwards while the stalled one cannot drain.
        let session = fixture.client.channel_open_session().await.unwrap();
        let (mut live, mut peer) = fixture.open().await;
        live.data(&b"alive"[..]).await.unwrap();
        let mut bytes = [0; 5];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"alive");
        peer.write_all(b"back").await.unwrap();
        assert_eq!(next_data(&mut live).await.as_ref(), b"back");

        // Every window update for data sent before those opens has arrived by now, and none
        // returned window for bytes the guest never admitted.
        assert_eq!(forwarded.writable_packet_size().await, 0);

        close(live).await;
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        close(forwarded).await;
        close(session).await;
        fixture.finish().await;
    })
    .await
    .unwrap();
}

/// Output the SSH peer will not accept pauses only that direction: input keeps flowing past
/// several guest credit windows, and closing this or another channel still closes its guest
/// stream.
#[tokio::test]
async fn paused_ssh_output_keeps_input_and_other_channel_close_live() {
    tokio::time::timeout(Duration::from_secs(20), async {
        // A one-byte SSH window never auto-replenishes (target / 2 == 0).
        let fixture = Fixture::new(FixtureOptions {
            client_window: 1,
            ..Default::default()
        })
        .await;
        let (mut first, mut peer) = fixture.open().await;
        peer.write_all(b"ab").await.unwrap();
        // The one-byte SSH window fills.
        assert_eq!(next_data(&mut first).await.as_ref(), b"a");
        let input = 4 * AGENT_CREDIT as usize;
        let receive = tokio::spawn(async move {
            let mut data = vec![0; input];
            peer.read_exact(&mut data).await.unwrap();
            assert!(data.iter().all(|b| *b == 7));
            peer
        });
        first.data_bytes(vec![7; input]).await.unwrap();
        let mut peer = receive.await.unwrap();

        let (second, mut other) = fixture.open().await;
        close(second).await;
        assert_eq!(other.read(&mut [0]).await.unwrap(), 0);
        close(first).await;
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        fixture.finish().await;
    })
    .await
    .unwrap();
}

/// With a single application queue slot, the output writer reserves its next chunk while the
/// session processes earlier messages and repeated window replenishments. Once the peer stops
/// replenishing, the session still opens and closes channels, and closing the blocked forward
/// closes its guest stream.
#[tokio::test]
async fn repeated_ssh_replenishment_preserves_queued_reservations_and_controls() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (stalled, exhausted) = oneshot::channel();
        let fixture = Fixture::new(FixtureOptions {
            client: Client {
                stop_after: Some(8),
                stalled: Some(stalled),
                ..Default::default()
            },
            event_buffer_size: Some(1),
            ..Default::default()
        })
        .await;
        let (first, mut peer) = fixture.open().await;
        let (mut reader, writer) = first.split();
        let received = tokio::spawn(async move {
            let mut bytes = 0;
            while let Some(message) = reader.wait().await {
                match message {
                    ChannelMsg::Data { data } => bytes += data.len(),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            bytes
        });
        // More than the host's guest-to-host credit and both sockets' buffers can hold, so the
        // producer is still writing when the forward closes.
        let produced = 4 * microsandbox_protocol::bulk::DEFAULT_BULK_WINDOW as usize;
        let producer = tokio::spawn(async move { peer.write_all(&vec![1; produced]).await });
        exhausted.await.unwrap();

        let (second, mut other) = fixture.open().await;
        close(second).await;
        assert_eq!(other.read(&mut [0]).await.unwrap(), 0);
        writer.close().await.unwrap();
        assert!(received.await.unwrap() > SSH_WINDOW as usize * 4);
        let error = producer.await.unwrap().unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
        drop(writer);
        fixture.finish().await;
    })
    .await
    .unwrap();
}

type PendingOpen = (ChannelOpenHandle, russh::server::Handle, ChannelId);
type Opening = tokio::task::JoinHandle<Result<Channel<ClientMsg>, russh::Error>>;

struct OpenGate {
    pending: mpsc::Sender<PendingOpen>,
    remaining: usize,
    blocked: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

impl russh::server::Handler for OpenGate {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pending
            .send((reply, session.handle(), channel.id()))
            .await
            .unwrap();
        self.remaining -= 1;
        if self.remaining == 0 {
            self.blocked.take().unwrap().send(()).unwrap();
            self.release.take().unwrap().await.unwrap();
        }
        Ok(())
    }
}

struct SaturatedOpens {
    client: Arc<russh::client::Handle<Client>>,
    pending: Vec<PendingOpen>,
    openings: Vec<Opening>,
    release: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
}

impl SaturatedOpens {
    async fn new() -> Self {
        const OPENS: usize = 3;
        const QUEUE_SLOTS: usize = 10;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap(),
            ],
            event_buffer_size: QUEUE_SLOTS,
            ..Default::default()
        });
        let (pending, mut pending_rx) = mpsc::channel(OPENS);
        let (blocked, blocked_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(
                config,
                socket,
                OpenGate {
                    pending,
                    remaining: OPENS,
                    blocked: Some(blocked),
                    release: Some(release_rx),
                },
            )
            .await
            .unwrap()
            .await
        });
        let mut client =
            russh::client::connect(Arc::new(Default::default()), address, Client::default())
                .await
                .unwrap();
        assert!(client.authenticate_none("test").await.unwrap().success());
        let client = Arc::new(client);
        let mut openings = Vec::new();
        for _ in 0..OPENS {
            let client = Arc::clone(&client);
            openings.push(tokio::spawn(async move {
                client
                    .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 0)
                    .await
            }));
        }
        blocked_rx.await.unwrap();
        let mut pending = Vec::new();
        for _ in 0..OPENS {
            pending.push(pending_rx.recv().await.unwrap());
        }
        // The network callback is held, so all ten enqueues occupy distinct
        // application slots. No timing assumption is used to establish fullness.
        let (_, session, id) = &pending[0];
        for _ in 0..QUEUE_SLOTS {
            session.channel_success(*id).await.unwrap();
        }
        Self {
            client,
            pending,
            openings,
            release,
            server,
        }
    }
}

#[tokio::test]
async fn saturated_open_queue_preserves_cancelled_accept_and_delivers_all_rejections() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = SaturatedOpens::new().await;
        {
            let accepting = fixture.pending[0].0.respond(Ok(()));
            tokio::pin!(accepting);
            assert!(futures::poll!(&mut accepting).is_pending());
        } // Cancel without consuming the pending reply state.
        let rejections = fixture
            .pending
            .into_iter()
            .map(|(mut reply, session, _)| {
                tokio::spawn(async move { finish_ssh_open(&mut reply, false, &session).await })
            })
            .collect::<Vec<_>>();
        fixture.release.send(()).unwrap();
        for rejection in rejections {
            assert!(rejection.await.unwrap());
        }
        for opening in fixture.openings {
            assert!(matches!(
                opening.await.unwrap(),
                Err(russh::Error::ChannelOpenFailure(
                    ChannelOpenFailure::AdministrativelyProhibited
                ))
            ));
        }
        fixture
            .client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
            .await
            .unwrap();
        drop(fixture.client);
        fixture.server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn saturated_open_reply_deadline_or_abandonment_terminates_transport() {
    for abandon in [false, true] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut fixture = SaturatedOpens::new().await;
            if abandon {
                drop(fixture.pending.remove(0));
            } else {
                let replies = fixture
                    .pending
                    .drain(..)
                    .map(|(mut reply, session, _)| {
                        tokio::spawn(
                            async move { finish_ssh_open(&mut reply, false, &session).await },
                        )
                    })
                    .collect::<Vec<_>>();
                for reply in replies {
                    assert!(!reply.await.unwrap());
                }
            }
            assert!(matches!(
                fixture.server.await.unwrap(),
                Err(russh::Error::Disconnect)
            ));
            for opening in fixture.openings {
                assert!(opening.await.unwrap().is_err());
            }
            drop((fixture.client, fixture.pending, fixture.release));
        })
        .await
        .unwrap();
    }
}
