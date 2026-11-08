//! The SDK SFTP client over authenticated loopback SSH and a real file-backed SFTP3 server.
//! The guest agent relay is outside this transport regression; no VM is started.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::{SshClient, SshClientHandler};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Transfers {
    version: Option<u32>,
    opened: usize,
    closed: usize,
    read_bytes: usize,
    written_bytes: usize,
    remaining_handles: usize,
}

struct Files {
    root: PathBuf,
    handles: HashMap<String, File>,
    transfers: Transfers,
    finished: mpsc::UnboundedSender<Transfers>,
}

struct Server {
    key: PublicKey,
    root: PathBuf,
    channels: HashMap<ChannelId, Channel<Msg>>,
    finished: mpsc::UnboundedSender<Transfers>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl russh_sftp::server::Handler for Files {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported.into()
    }

    async fn init(
        &mut self,
        version: u32,
        _: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        assert_eq!(version, 3, "client must negotiate SFTP3 on the wire");
        self.transfers.version = Some(version);
        let response = Version::new();
        assert_eq!(response.version, 3);
        Ok(response)
    }

    async fn open(
        &mut self,
        id: u32,
        path: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        // Fixture confinement: the transport test operates on one basename, never host paths.
        assert_eq!(path, "payload.bin");
        let file = OpenOptions::new()
            .read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE))
            .create(flags.contains(OpenFlags::CREATE))
            .truncate(flags.contains(OpenFlags::TRUNCATE))
            .open(self.root.join(path))
            .map_err(file_error)?;
        let handle = self.transfers.opened.to_string();
        self.transfers.opened += 1;
        assert!(self.handles.insert(handle.clone(), file).is_none());
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let file = self
            .handles
            .remove(&handle)
            .expect("CLOSE must identify an open file");
        drop(file);
        self.transfers.closed += 1;
        Ok(success(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self
            .handles
            .get_mut(&handle)
            .expect("READ must identify an open file");
        file.seek(SeekFrom::Start(offset)).map_err(file_error)?;
        let mut data = vec![0; len as usize];
        let read = file.read(&mut data).map_err(file_error)?;
        if read == 0 {
            return Err(StatusCode::Eof.into());
        }
        data.truncate(read);
        self.transfers.read_bytes += read;
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self
            .handles
            .get_mut(&handle)
            .expect("WRITE must identify an open file");
        file.seek(SeekFrom::Start(offset)).map_err(file_error)?;
        file.write_all(&data).map_err(file_error)?;
        self.transfers.written_bytes += data.len();
        Ok(success(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        assert_eq!(path, "payload.bin");
        let metadata = std::fs::metadata(self.root.join(path)).map_err(file_error)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(metadata.len()),
                ..Default::default()
            },
        })
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        self.transfers.remaining_handles = self.handles.len();
        // The receiver outlives the SFTP worker and is awaited before SSH teardown.
        self.finished
            .send(std::mem::take(&mut self.transfers))
            .unwrap();
    }
}

impl russh::server::Handler for Server {
    type Error = russh::Error;

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
        channel: Channel<Msg>,
        mut reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.respond(Ok(())).await.unwrap();
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(name, "sftp");
        let channel = self.channels.remove(&id).unwrap();
        session.channel_success(id)?;
        russh_sftp::server::run(
            channel.into_stream(),
            Files {
                root: self.root.clone(),
                handles: HashMap::new(),
                transfers: Transfers::default(),
                finished: self.finished.clone(),
            },
        )
        .await;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn success(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: "en".into(),
    }
}

fn file_error(error: std::io::Error) -> StatusReply {
    let status = if error.kind() == std::io::ErrorKind::NotFound {
        StatusCode::NoSuchFile
    } else {
        StatusCode::Failure
    };
    status.with_message(error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn sftp3_loopback_transfers_real_files_offsets_and_closes_each_session() {
    tokio::time::timeout(Duration::from_secs(20), async {
        const WINDOW: u32 = 64 * 1024;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payload.bin");
        assert!(!path.exists());
        let key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let (finished, mut completions) = mpsc::unbounded_channel();
        let handler = Server {
            key: key.public_key().clone(),
            root: directory.path().to_path_buf(),
            channels: HashMap::new(),
            finished,
        };
        let config = Arc::new(russh::server::Config {
            keys: vec![
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap(),
            ],
            window_size: WINDOW,
            ..Default::default()
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            russh::server::run_stream(config, socket, handler)
                .await
                .unwrap()
                .await
                .unwrap();
        });
        let mut handle = russh::client::connect(
            Arc::new(russh::client::Config {
                window_size: WINDOW,
                ..Default::default()
            }),
            address,
            SshClientHandler,
        )
        .await
        .unwrap();
        assert!(
            handle
                .authenticate_publickey(
                    "sftp-test",
                    PrivateKeyWithHashAlg::new(Arc::new(key), None)
                )
                .await
                .unwrap()
                .success()
        );
        let ssh = SshClient {
            handle,
            term: "xterm".into(),
            server_task: None,
            negotiated_version: None,
        };

        let sftp = ssh.sftp().await.unwrap();
        assert!(!sftp.try_exists("payload.bin").await.unwrap());
        let mut expected: Vec<u8> = (0..6 * WINDOW).map(|offset| (offset % 251) as u8).collect();
        let mut file = sftp.create("payload.bin").await.unwrap();
        file.write_all(&expected).await.unwrap();
        file.seek(SeekFrom::Start(17)).await.unwrap();
        file.write_all(b"offset!!").await.unwrap();
        file.close().await.unwrap();
        expected[17..25].copy_from_slice(b"offset!!");
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert_eq!(
            sftp.metadata("payload.bin").await.unwrap().size,
            Some(expected.len() as u64)
        );
        assert_eq!(sftp.read("payload.bin").await.unwrap(), expected);
        sftp.close().await.unwrap();
        let first = completions.recv().await.unwrap();
        assert_eq!(first.version, Some(3));
        assert_eq!(
            (first.opened, first.closed, first.remaining_handles),
            (2, 2, 0)
        );
        assert!(first.read_bytes > WINDOW as usize);
        assert_eq!(first.written_bytes, expected.len() + 8);

        // A completed SFTP channel must not close the authenticated SSH connection.
        let second = ssh.sftp().await.unwrap();
        assert_eq!(second.read("payload.bin").await.unwrap(), expected);
        second.close().await.unwrap();
        let second = completions.recv().await.unwrap();
        assert_eq!(second.version, Some(3));
        assert_eq!(
            (second.opened, second.closed, second.remaining_handles),
            (1, 1, 0)
        );
        ssh.close().await.unwrap();
        server.await.unwrap();
    })
    .await
    .expect("authenticated SFTP3 loopback transfer did not finish");
}
