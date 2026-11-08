//! Host-file copy admission over a real Unix agent transport, without a VM.

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::time::Duration;

use microsandbox_protocol::{
    bulk::{BULK_FLOW_MASK_HOST_TO_GUEST, BulkAccepted, BulkFinish, BulkFlow, BulkKind},
    codec,
    core::Ready,
    fs::{FsData, FsOp, FsRequest, FsResponse, FsResponseData},
    message::{FLAG_BULK, Message, MessageType},
};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

use super::{FS_INLINE_WRITE_MAX, agent};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEADLINE: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn reply(stream: &mut UnixStream, id: u32, data: Option<FsResponseData>) {
    codec::write_message(
        stream,
        &Message::with_payload(
            MessageType::FsResponse,
            id,
            &FsResponse {
                ok: true,
                error: None,
                data,
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
}

/// A file-backed peer exercises the current filesystem wire contract, not a native binding stub.
async fn receive_copy(
    listener: UnixListener,
    destination: std::path::PathBuf,
    expected_bulk: bool,
    first_write: oneshot::Sender<()>,
) {
    let (mut stream, _) = listener.accept().await.unwrap();
    stream.write_all(&1u32.to_be_bytes()).await.unwrap();
    stream.write_all(&1024u32.to_be_bytes()).await.unwrap();
    codec::write_message(
        &mut stream,
        &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
    )
    .await
    .unwrap();
    let open = codec::read_message(&mut stream).await.unwrap();
    assert_eq!(open.t, MessageType::FsRequest);
    let request: FsRequest = open.payload().unwrap();
    assert!(matches!(request.op, FsOp::OpenFile { ref path, .. } if path == "/uploaded"));
    let mut file = std::fs::File::create(&destination).unwrap();
    reply(&mut stream, open.id, Some(FsResponseData::Handle(7))).await;
    let write = codec::read_message(&mut stream).await.unwrap();
    let request: FsRequest = write.payload().unwrap();
    assert!(matches!(
        request.op,
        FsOp::Write {
            handle: 7,
            offset: 0,
            ..
        }
    ));
    assert_eq!(request.bulk.is_some(), expected_bulk);
    if let Some(offer) = request.bulk {
        let accepted = BulkAccepted {
            kind: BulkKind::Filesystem,
            flows: BULK_FLOW_MASK_HOST_TO_GUEST,
            format: offer.format,
            max_record_payload: offer.max_record_payload,
            host_to_guest_credit_limit: 64 * 1024,
            guest_to_host_credit_limit: offer.guest_to_host_credit_limit,
        };
        codec::write_message(
            &mut stream,
            &Message::with_payload(MessageType::BulkAccepted, write.id, &accepted).unwrap(),
        )
        .await
        .unwrap();
    }
    let mut first_write = Some(first_write);
    let mut offset = 0;
    loop {
        let frame = codec::read_raw_frame(&mut stream).await.unwrap();
        assert_eq!(frame.id, write.id);
        let data = if frame.flags & FLAG_BULK != 0 {
            assert!(expected_bulk);
            let record = codec::raw_frame_to_bulk(frame, 64 * 1024).unwrap();
            assert_eq!(record.kind, BulkKind::Filesystem);
            assert_eq!(record.flow, BulkFlow::HostToGuest);
            assert_eq!(record.offset, offset);
            record.payload.to_vec()
        } else {
            let message = codec::raw_frame_to_message(frame).unwrap();
            if expected_bulk {
                assert_eq!(message.t, MessageType::BulkFinish);
                let finish: BulkFinish = message.payload().unwrap();
                assert_eq!(finish.kind, BulkKind::Filesystem);
                assert_eq!(finish.flow, BulkFlow::HostToGuest);
                assert_eq!(finish.final_offset, offset);
                break;
            }
            assert_eq!(message.t, MessageType::FsData);
            let data: FsData = message.payload().unwrap();
            if data.data.is_empty() {
                break;
            }
            data.data
        };
        file.write_all(&data).unwrap();
        offset += data.len() as u64;
        if let Some(first_write) = first_write.take() {
            // Completion comes only after the peer actually wrote the first host chunk.
            first_write.send(()).unwrap();
        }
    }
    reply(&mut stream, write.id, None).await;
    let close = codec::read_message(&mut stream).await.unwrap();
    let request: FsRequest = close.payload().unwrap();
    assert!(matches!(request.op, FsOp::CloseHandle { handle: 7 }));
    reply(&mut stream, close.id, None).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn fifo_copy_admits_first_write_before_writer_eof() {
    let directory = tempfile::tempdir().unwrap();
    let backend = crate::test_support::local_backend_builder(directory.path())
        .build()
        .await
        .unwrap();
    let socket = backend
        .agent_socket_paths("copy")
        .into_iter()
        .find(|path| microsandbox_runtime::ipc::socket_path_fits(path))
        .expect("private fixture needs a usable Unix socket path");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(socket).unwrap();
    let fifo = directory.path().join("input");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    let destination = directory.path().join("received");
    let (first_tx, first_rx) = oneshot::channel();
    let peer = tokio::spawn(receive_copy(listener, destination.clone(), true, first_tx));
    let copy =
        tokio::spawn(
            async move { agent::copy_from_host(&backend, "copy", &fifo, "/uploaded").await },
        );
    let fifo = directory.path().join("input");
    let mut writer = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new().write(true).open(fifo).unwrap()
    })
    .await
    .unwrap();
    let metadata = writer.metadata().unwrap();
    assert!(metadata.file_type().is_fifo());
    assert_eq!(metadata.len(), 0);
    writer.write_all(b"initial ").unwrap();
    let admitted = tokio::time::timeout(DEADLINE, first_rx).await;
    if admitted.is_ok() {
        assert_eq!(std::fs::read(&destination).unwrap(), b"initial ");
        writer.write_all(b"remaining").unwrap();
    }
    // Closing on either outcome releases the real FIFO read even when the assertion fails.
    drop(writer);
    let copied = tokio::time::timeout(DEADLINE, copy).await;
    let served = tokio::time::timeout(DEADLINE, peer).await;
    assert!(
        admitted.is_ok(),
        "first guest write waited for FIFO EOF: copy={copied:?}, peer={served:?}"
    );
    admitted.unwrap().unwrap();
    copied.unwrap().unwrap().unwrap();
    served.unwrap().unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"initial remaining");
}

#[tokio::test]
async fn regular_host_copies_keep_the_inline_cutoff() {
    for size in [0, FS_INLINE_WRITE_MAX, FS_INLINE_WRITE_MAX + 1] {
        let directory = tempfile::tempdir().unwrap();
        let backend = crate::test_support::local_backend_builder(directory.path())
            .build()
            .await
            .unwrap();
        let socket = backend
            .agent_socket_paths("copy")
            .into_iter()
            .find(|path| microsandbox_runtime::ipc::socket_path_fits(path))
            .unwrap();
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(socket).unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("received");
        let bytes = vec![42; size as usize];
        std::fs::write(&source, &bytes).unwrap();
        let (first_tx, _first_rx) = oneshot::channel();
        let peer = tokio::spawn(receive_copy(
            listener,
            destination.clone(),
            size > FS_INLINE_WRITE_MAX,
            first_tx,
        ));
        tokio::time::timeout(
            DEADLINE,
            agent::copy_from_host(&backend, "copy", &source, "/uploaded"),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(DEADLINE, peer).await.unwrap().unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), bytes);
    }
}
