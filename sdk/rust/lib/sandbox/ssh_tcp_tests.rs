//! SSH direct-tcpip forwarding and definitive channel-open replies on a real loopback SSH
//! connection.

use super::*;
use microsandbox_protocol::{codec, core::Ready, message::Message};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct Client;

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &russh::keys::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Forwards direct-tcpip channels through the session's own supervisor, relays and manual
/// receive windows, against an agent the test controls.
struct Forwarder {
    client: Arc<AgentClient>,
    channels: HashMap<ChannelId, (mpsc::UnboundedSender<SshTcpInput>, watch::Sender<bool>)>,
}

impl russh::server::Handler for Forwarder {
    type Error = anyhow::Error;

    fn manual_receive_window(&self, channel: ChannelId) -> bool {
        self.channels.contains_key(&channel)
    }

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let session = session.handle();
        tokio::spawn(async move {
            let mut reply = reply;
            finish_ssh_open(&mut reply, true, &session).await;
        });
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let id = channel.id();
        let writer = channel.make_writer();
        let (input, input_rx) = mpsc::unbounded_channel();
        let (stop, stop_rx) = watch::channel(false);
        self.channels.insert(id, (input, stop));
        tokio::spawn(run_tcp_forward(
            TcpChannelOpen {
                channel: id,
                host: host.to_string(),
                port: u16::try_from(port).unwrap(),
                reply,
                session: session.handle(),
            },
            Arc::clone(&self.client),
            writer,
            input_rx,
            stop_rx,
        ));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some((input, _)) = self.channels.get(&channel) {
            let _ = input.send(SshTcpInput::Data(Bytes::copy_from_slice(data)));
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some((_, stop)) = self.channels.remove(&channel) {
            stop.send_replace(true);
        }
        Ok(())
    }
}

/// A guest that connects, then never reads the forwarded bytes, stalls only its own channel:
/// the SSH session loop keeps answering, and the stalled channel's backlog is held to its
/// receive window rather than growing with whatever the peer sends.
#[tokio::test]
async fn stalled_guest_stream_leaves_the_ssh_session_live() {
    const WINDOW: u32 = 64 * 1024;
    const PAYLOAD: usize = 16 * 1024 * 1024;
    tokio::time::timeout(Duration::from_secs(20), async {
        let (client_io, mut agent_io) = tokio::io::duplex(16 * 1024);
        let (stalled, stalled_rx) = oneshot::channel();
        let agent = tokio::spawn(async move {
            agent_io.write_all(&1u32.to_be_bytes()).await.unwrap();
            agent_io.write_all(&1024u32.to_be_bytes()).await.unwrap();
            // Generation 7 predates bulk transfer, so the forward uses plain TCP data frames,
            // and an agent that stops reading back-pressures the relay directly.
            let mut ready =
                Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
            ready.v = 7;
            codec::write_message(&mut agent_io, &ready).await.unwrap();
            loop {
                let message = codec::read_message(&mut agent_io).await.unwrap();
                match message.t {
                    MessageType::TcpConnect => {
                        let mut connected = Message::with_payload(
                            MessageType::TcpConnected,
                            message.id,
                            &TcpConnected {},
                        )
                        .unwrap();
                        connected.v = 7;
                        codec::write_message(&mut agent_io, &connected)
                            .await
                            .unwrap();
                    }
                    MessageType::TcpData => break,
                    other => panic!("unexpected agent message {other:?}"),
                }
            }
            stalled.send(()).unwrap();
            // Hold the connection open without reading another byte.
            std::future::pending::<()>().await;
            drop(agent_io);
        });
        let agent_client = Arc::new(
            AgentClient::connect_stream_with_timeout(client_io, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert!(!agent_client.supports(MessageType::BulkAccepted));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap(),
            ],
            window_size: WINDOW,
            ..Default::default()
        });
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(
                config,
                socket,
                Forwarder {
                    client: agent_client,
                    channels: HashMap::new(),
                },
            )
            .await
            .unwrap()
            .await
        });
        let mut client = russh::client::connect(Arc::new(Default::default()), address, Client)
            .await
            .unwrap();
        assert!(client.authenticate_none("test").await.unwrap().success());

        let forwarded = client
            .channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 0)
            .await
            .unwrap();
        let writer = tokio::spawn(async move {
            let payload = vec![0u8; PAYLOAD];
            forwarded.data(&payload[..]).await
        });
        stalled_rx.await.unwrap();

        // The session loop still answers while the forwarded channel cannot drain.
        client.channel_open_session().await.unwrap();
        // The peer is held to the receive window, so most of the payload is still unsent.
        assert!(!writer.is_finished());

        writer.abort();
        client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
            .await
            .unwrap();
        drop(client);
        server.await.unwrap().unwrap();
        agent.abort();
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
        let mut client = russh::client::connect(Arc::new(Default::default()), address, Client)
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
