//! Close handshakes over authenticated SSH on real loopback sockets.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::client;
use crate::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use crate::server::{self, Auth, ChannelOpenHandle, VerifiedPublicKey};
use crate::{Channel, ChannelId, ChannelMsg, Disconnect, Error};

type Opened = (Channel<server::Msg>, server::Handle);

const CLOSE_TEST_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIVE_WINDOW: u32 = 65536;

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
        let key = PrivateKey::random(
            &mut crate::keys::key::safe_rng(),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let config = Arc::new(server::Config {
            keys: vec![
                PrivateKey::random(
                    &mut crate::keys::key::safe_rng(),
                    ssh_key::Algorithm::Ed25519,
                )
                .unwrap(),
            ],
            ..Default::default()
        });
        let (opened, mut openings) = mpsc::unbounded_channel();
        let (server_closed_tx, server_closed) = mpsc::unbounded_channel();
        let handler = Server {
            key: key.public_key().clone(),
            opened,
            closed: server_closed_tx,
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(config, socket, handler)
                .await
                .unwrap()
                .await
                .unwrap();
        });
        let (client_closed_tx, client_closed) = mpsc::unbounded_channel();
        let mut client = client::connect(
            Arc::new(client::Config {
                window_size: client_window,
                ..Default::default()
            }),
            address,
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
        let mut fixture = Fixture::new(RECEIVE_WINDOW).await;
        let (client, server) = tokio::join!(
            fixture.client_channel.close(),
            fixture.server_channel.close(),
        );
        client.unwrap();
        server.unwrap();
        expect_close(&mut fixture.client_channel).await;
        expect_close(&mut fixture.server_channel).await;
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
