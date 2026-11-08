//! Close handshakes over authenticated SSH on real loopback sockets.

use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::client;
use crate::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use crate::server::{self, Auth, ChannelOpenHandle, VerifiedPublicKey};
use crate::{Channel, ChannelId, ChannelMsg, Disconnect, Error};

type Opened = (Channel<server::Msg>, server::Handle);

const CLOSE_TEST_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIVE_WINDOW: u32 = 65536;
const BOTH_CLOSES: u8 = 0b11;

/// Observe actual packet writes, holding both readers until each peer has sent CLOSE.
/// This is transport instrumentation only; russh still creates and processes every packet.
struct CloseBarrier {
    armed: AtomicBool,
    emitted: AtomicU8,
    recipients: [AtomicU32; 2],
    readers: [AtomicWaker; 2],
}

impl CloseBarrier {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            emitted: AtomicU8::new(0),
            recipients: [AtomicU32::new(0), AtomicU32::new(0)],
            readers: [AtomicWaker::new(), AtomicWaker::new()],
        }
    }

    fn arm(&self, client_recipient: ChannelId, server_recipient: ChannelId) {
        self.recipients[0].store(client_recipient.0, Ordering::Relaxed);
        self.recipients[1].store(server_recipient.0, Ordering::Relaxed);
        self.armed.store(true, Ordering::Release);
    }

    fn observing(&self) -> bool {
        self.armed.load(Ordering::Acquire) && self.emitted.load(Ordering::Acquire) != BOTH_CLOSES
    }
}

struct ObservedTransport {
    socket: TcpStream,
    barrier: Option<Arc<CloseBarrier>>,
    side: usize,
    packet: Vec<u8>,
}

impl ObservedTransport {
    fn new(socket: TcpStream, barrier: Option<Arc<CloseBarrier>>, side: usize) -> Self {
        Self {
            socket,
            barrier,
            side,
            packet: Vec::new(),
        }
    }

    fn observe_written(&mut self, bytes: &[u8]) {
        let Some(barrier) = &self.barrier else { return };
        if !barrier.observing() {
            return;
        }
        self.packet.extend_from_slice(bytes);
        // Only the simultaneous-close fixture negotiates none cipher/MAC/compression.
        // Packet boundaries and message IDs are therefore visible without replacing SSH.
        while self.packet.len() >= 4 {
            let packet_length = u32::from_be_bytes(self.packet[..4].try_into().unwrap()) as usize;
            let total = 4 + packet_length;
            if self.packet.len() < total {
                return;
            }
            assert!(
                packet_length >= 10,
                "CLOSE packet must include its recipient and padding"
            );
            assert_eq!(
                self.packet[5],
                crate::msg::CHANNEL_CLOSE,
                "only CLOSE is emitted after the established-channel barrier is armed"
            );
            let recipient = u32::from_be_bytes(self.packet[6..10].try_into().unwrap());
            assert_eq!(
                recipient,
                barrier.recipients[self.side].load(Ordering::Acquire)
            );
            let previous = barrier.emitted.fetch_or(1 << self.side, Ordering::AcqRel);
            assert_eq!(
                previous & (1 << self.side),
                0,
                "CLOSE emitted only once per side"
            );
            self.packet.drain(..total);
            if previous | (1 << self.side) == BOTH_CLOSES {
                for reader in &barrier.readers {
                    reader.wake();
                }
            }
        }
    }
}

impl AsyncRead for ObservedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(barrier) = &self.barrier {
            if barrier.observing() {
                barrier.readers[self.side].register(cx.waker());
                if barrier.observing() {
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObservedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.socket).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                self.observe_written(&buf[..written]);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

fn observable_packets(preferred: &mut crate::Preferred) {
    preferred.cipher = Cow::Owned(vec![crate::cipher::NONE]);
    preferred.mac = Cow::Owned(vec![crate::mac::NONE]);
    preferred.compression = Cow::Owned(vec![crate::compression::NONE]);
}

struct Server {
    key: PublicKey,
    opened: mpsc::UnboundedSender<Opened>,
    closed: mpsc::UnboundedSender<ChannelId>,
}

struct Client {
    closed: mpsc::UnboundedSender<ChannelId>,
}

impl server::Handler for Server {
    type Error = Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        assert_eq!(key.public_key, &self.key);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        mut reply: ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.opened.send((channel, session.handle())).unwrap();
        reply.respond(Ok(())).await.unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.closed.send(channel).unwrap();
        Ok(())
    }
}

impl client::Handler for Client {
    type Error = Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.closed.send(channel).unwrap();
        Ok(())
    }
}

struct Fixture {
    client: client::Handle<Client>,
    client_channel: Channel<client::Msg>,
    server_channel: Channel<server::Msg>,
    server_handle: server::Handle,
    openings: mpsc::UnboundedReceiver<Opened>,
    client_closed: mpsc::UnboundedReceiver<ChannelId>,
    server_closed: mpsc::UnboundedReceiver<ChannelId>,
    server_task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(client_window: u32) -> Self {
        Self::with_barrier(client_window, None).await
    }

    async fn with_barrier(client_window: u32, barrier: Option<Arc<CloseBarrier>>) -> Self {
        let key = PrivateKey::random(
            &mut crate::keys::key::safe_rng(),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let mut config = server::Config {
            keys: vec![
                PrivateKey::random(
                    &mut crate::keys::key::safe_rng(),
                    ssh_key::Algorithm::Ed25519,
                )
                .unwrap(),
            ],
            ..Default::default()
        };
        if barrier.is_some() {
            observable_packets(&mut config.preferred);
        }
        let config = Arc::new(config);
        let (opened, mut openings) = mpsc::unbounded_channel();
        let (server_closed_tx, server_closed) = mpsc::unbounded_channel();
        let handler = Server {
            key: key.public_key().clone(),
            opened,
            closed: server_closed_tx,
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_barrier = barrier.clone();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(
                config,
                ObservedTransport::new(socket, server_barrier, 1),
                handler,
            )
            .await
            .unwrap()
            .await
            .unwrap();
        });
        let (client_closed_tx, client_closed) = mpsc::unbounded_channel();
        let mut client_config = client::Config {
            window_size: client_window,
            ..Default::default()
        };
        if barrier.is_some() {
            observable_packets(&mut client_config.preferred);
        }
        let socket = TcpStream::connect(address).await.unwrap();
        let mut client = client::connect_stream(
            Arc::new(client_config),
            ObservedTransport::new(socket, barrier, 0),
            Client {
                closed: client_closed_tx,
            },
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "close-test",
                    PrivateKeyWithHashAlg::new(Arc::new(key), None)
                )
                .await
                .unwrap()
                .success()
        );
        let client_channel = client.channel_open_session().await.unwrap();
        let (server_channel, server_handle) = openings.recv().await.unwrap();
        Self {
            client,
            client_channel,
            server_channel,
            server_handle,
            openings,
            client_closed,
            server_closed,
            server_task,
        }
    }

    async fn finish(mut self) {
        let client_id = self.client_channel.id();
        let server_id = self.server_channel.id();
        assert_eq!(self.client_closed.recv().await, Some(client_id));
        assert_eq!(self.server_closed.recv().await, Some(server_id));
        assert!(self.client_closed.try_recv().is_err());
        assert!(self.server_closed.try_recv().is_err());
        // The close handshake leaves the same authenticated connection usable.
        let mut another = self.client.channel_open_session().await.unwrap();
        let (mut server_channel, _) = self.openings.recv().await.unwrap();
        another.close().await.unwrap();
        expect_close(&mut another).await;
        expect_close(&mut server_channel).await;
        self.client
            .disconnect(Disconnect::ByApplication, "test complete", "en")
            .await
            .unwrap();
        drop(self.client);
        self.server_task.await.unwrap();
    }
}

async fn expect_close<S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static>(
    channel: &mut Channel<S>,
) {
    loop {
        match channel
            .wait()
            .await
            .expect("channel must deliver its peer's CLOSE")
        {
            ChannelMsg::Close => break,
            ChannelMsg::WindowAdjusted { .. } => {}
            other => panic!("expected CLOSE, got {other:?}"),
        }
    }
    assert!(
        channel.wait().await.is_none(),
        "closed channel must release its sender"
    );
}

#[tokio::test]
async fn client_initiated_close_delivers_both_acknowledgements() {
    tokio::time::timeout(CLOSE_TEST_TIMEOUT, async {
        let mut fixture = Fixture::new(RECEIVE_WINDOW).await;
        fixture.client_channel.close().await.unwrap();
        expect_close(&mut fixture.server_channel).await;
        expect_close(&mut fixture.client_channel).await;
        fixture.finish().await;
    })
    .await
    .expect("client-initiated close handshake stalled");
}

#[tokio::test]
async fn server_initiated_close_delivers_both_acknowledgements() {
    tokio::time::timeout(CLOSE_TEST_TIMEOUT, async {
        let mut fixture = Fixture::new(RECEIVE_WINDOW).await;
        fixture.server_channel.close().await.unwrap();
        expect_close(&mut fixture.client_channel).await;
        expect_close(&mut fixture.server_channel).await;
        fixture.finish().await;
    })
    .await
    .expect("server-initiated close handshake stalled");
}

#[tokio::test]
async fn simultaneous_close_delivers_both_acknowledgements() {
    tokio::time::timeout(CLOSE_TEST_TIMEOUT, async {
        let barrier = Arc::new(CloseBarrier::new());
        let mut fixture = Fixture::with_barrier(RECEIVE_WINDOW, Some(barrier.clone())).await;
        // Both sessions must finish writing their own CLOSE before either can read its peer's.
        barrier.arm(fixture.server_channel.id(), fixture.client_channel.id());
        let (client, server) = tokio::join!(
            fixture.client_channel.close(),
            fixture.server_channel.close(),
        );
        client.unwrap();
        server.unwrap();
        expect_close(&mut fixture.client_channel).await;
        expect_close(&mut fixture.server_channel).await;
        assert_eq!(barrier.emitted.load(Ordering::Acquire), BOTH_CLOSES);
        fixture.finish().await;
    })
    .await
    .expect("simultaneous close handshake stalled");
}

#[tokio::test]
async fn peer_close_does_not_wait_for_blocked_output() {
    tokio::time::timeout(CLOSE_TEST_TIMEOUT, async {
        // A one-byte receive window does not replenish automatically.
        let mut fixture = Fixture::new(1).await;
        fixture
            .server_handle
            .data(fixture.server_channel.id(), b"ab".to_vec())
            .await
            .unwrap();
        assert!(matches!(fixture.client_channel.wait().await,
            Some(ChannelMsg::Data { data }) if data.as_ref() == b"a"));
        assert_eq!(fixture.server_channel.writable_packet_size().await, 0);
        fixture.server_channel.close().await.unwrap();
        fixture.client_channel.close().await.unwrap();
        expect_close(&mut fixture.client_channel).await;
        expect_close(&mut fixture.server_channel).await;
        fixture.finish().await;
    })
    .await
    .expect("peer CLOSE waited for output that cannot drain");
}

#[tokio::test]
async fn queued_output_drains_before_local_close_and_acknowledgement() {
    tokio::time::timeout(CLOSE_TEST_TIMEOUT, async {
        let mut fixture = Fixture::new(RECEIVE_WINDOW).await;
        let payload: Vec<u8> = (0..4 * RECEIVE_WINDOW)
            .map(|index| (index % 251) as u8)
            .collect();
        fixture
            .server_handle
            .data(fixture.server_channel.id(), payload.clone())
            .await
            .unwrap();
        fixture.server_channel.close().await.unwrap();

        let mut received = Vec::new();
        loop {
            match fixture
                .client_channel
                .wait()
                .await
                .expect("queued output must end in CLOSE")
            {
                ChannelMsg::Data { data } => received.extend_from_slice(&data),
                ChannelMsg::Close => break,
                ChannelMsg::WindowAdjusted { .. } => {}
                other => panic!("unexpected queued-output event {other:?}"),
            }
        }
        assert_eq!(received, payload);
        assert!(fixture.client_channel.wait().await.is_none());
        expect_close(&mut fixture.server_channel).await;
        fixture.finish().await;
    })
    .await
    .expect("queued output or close acknowledgement stalled");
}
