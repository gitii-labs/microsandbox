//! Guest TCP connections handed to Go as one end of a Unix socket pair.
//!
//! Go reads and writes the socket directly, so a byte stream crosses the boundary without a
//! call per chunk. Two relay tasks join the Rust end to a [`GuestTcpStream`]. Each waits on the
//! side it feeds, so Go's socket buffers and the stream's bulk credit bound both directions.
//! Only the end of a direction crosses as a call: Go asks for its cause after the socket ends.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::raw::{c_char, c_uchar};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex, OnceLock, RwLock};

use microsandbox::{GUEST_TCP_CLOSE_IDLE_TIMEOUT, GuestTcpCleanup, GuestTcpStream};
use tokio::io::Interest;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{FfiError, Handle, cstr, get, run, run_c};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Largest read from Go's socket handed to the stream at once; the stream splits it into
/// records within the negotiated record size.
const SOCKET_CHUNK: usize = 256 * 1024;

#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct TcpBridge {
    stream: Arc<GuestTcpStream>,
    /// Bytes the socket-to-guest relay has handed to the stream. It advances only as the guest
    /// grants credit, so it measures a closing connection's progress.
    forwarded: watch::Receiver<u64>,
    to_guest: Mutex<Option<JoinHandle<()>>>,
    from_guest: Mutex<Option<JoinHandle<()>>>,
    /// Ends both relays: an abort, or a guest stream that ended abnormally.
    stop: CancellationToken,
    errors: Arc<Errors>,
}

/// Why a direction ended other than in order. Go reads these once its socket reports the end.
#[derive(Default)]
struct Errors {
    read: SyncMutex<Option<String>>,
    write: SyncMutex<Option<String>>,
}

//--------------------------------------------------------------------------------------------------
// Functions: Registry
//--------------------------------------------------------------------------------------------------

static NEXT_TCP_HANDLE: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static RwLock<HashMap<Handle, Arc<TcpBridge>>> {
    static REG: OnceLock<RwLock<HashMap<Handle, Arc<TcpBridge>>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn lookup(handle: Handle) -> Result<Arc<TcpBridge>, FfiError> {
    registry()
        .read()
        .map_err(|_| FfiError::internal("tcp registry poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn take(handle: Handle) -> Result<Arc<TcpBridge>, FfiError> {
    registry()
        .write()
        .map_err(|_| FfiError::internal("tcp registry poisoned"))?
        .remove(&handle)
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

//--------------------------------------------------------------------------------------------------
// Functions: Relays
//--------------------------------------------------------------------------------------------------

fn record(slot: &SyncMutex<Option<String>>, error: impl ToString) {
    slot.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(|| error.to_string());
}

fn shutdown(socket: &UnixStream, how: libc::c_int) {
    // A socket whose peer is already gone has nothing left to shut down.
    unsafe { libc::shutdown(socket.as_raw_fd(), how) };
}

/// Write all of `data` without raising SIGPIPE, which a Go host would not survive on a
/// non-Go thread.
async fn send_all(socket: &UnixStream, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        socket.writable().await?;
        let sent = socket.try_io(Interest::WRITABLE, || {
            let sent = unsafe {
                libc::send(
                    socket.as_raw_fd(),
                    data.as_ptr().cast(),
                    data.len(),
                    SEND_FLAGS,
                )
            };
            if sent < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(sent as usize)
            }
        });
        match sent {
            Ok(sent) => data = &data[sent..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn relay_to_guest(
    socket: Arc<UnixStream>,
    stream: Arc<GuestTcpStream>,
    forwarded: watch::Sender<u64>,
    stop: CancellationToken,
    errors: Arc<Errors>,
) {
    let mut buffer = vec![0; SOCKET_CHUNK];
    let outcome = loop {
        let read = tokio::select! {
            // An abort or a failed guest stream: Go's further writes have nowhere to go.
            () = stop.cancelled() => break Err("guest TCP stream ended".into()),
            read = async {
                loop {
                    socket.readable().await?;
                    match socket.try_read(&mut buffer) {
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        read => return read,
                    }
                }
            } => read,
        };
        match read {
            Ok(0) => break stream.shutdown_write().await.map_err(|e| e.to_string()),
            Ok(read) => {
                if let Err(error) = stream.write(buffer[..read].to_vec()).await {
                    break Err(error.to_string());
                }
                forwarded.send_modify(|total| *total += read as u64);
            }
            Err(error) => break Err(format!("read from the Go socket: {error}")),
        }
    };
    if let Err(error) = outcome {
        record(&errors.write, error);
        // Go's next write fails instead of filling a buffer nobody drains.
        shutdown(&socket, libc::SHUT_RD);
    }
}

async fn relay_from_guest(
    socket: Arc<UnixStream>,
    stream: Arc<GuestTcpStream>,
    stop: CancellationToken,
    errors: Arc<Errors>,
) {
    loop {
        let read = tokio::select! {
            () = stop.cancelled() => return,
            read = stream.read() => read,
        };
        match read {
            Ok(Some(chunk)) => {
                // Go closed its socket: nothing reads the rest, and close releases the stream.
                if send_all(&socket, &chunk).await.is_err() {
                    return;
                }
            }
            Ok(None) => {
                shutdown(&socket, libc::SHUT_WR);
                return;
            }
            Err(error) => {
                record(&errors.read, error);
                shutdown(&socket, libc::SHUT_WR);
                stop.cancel();
                return;
            }
        }
    }
}

/// Wait for the socket-to-guest relay to hand Go's last bytes to the stream, for as long as it
/// keeps making progress. Returns whether it finished.
async fn wait_forwarded(bridge: &TcpBridge) -> bool {
    let Some(mut task) = bridge.to_guest.lock().await.take() else {
        return true;
    };
    let mut forwarded = bridge.forwarded.clone();
    loop {
        tokio::select! {
            _ = &mut task => return true,
            changed = forwarded.changed() => {
                if changed.is_err() {
                    return (&mut task).await.is_ok();
                }
            }
            () = tokio::time::sleep(GUEST_TCP_CLOSE_IDLE_TIMEOUT) => {
                bridge.stop.cancel();
                let _ = task.await;
                return false;
            }
        }
    }
}

fn cleanup_json(cleanup: GuestTcpCleanup) -> String {
    let cleanup = match cleanup {
        GuestTcpCleanup::Acknowledged => "acknowledged",
        GuestTcpCleanup::Unknown => "unknown",
    };
    serde_json::json!({ "cleanup": cleanup }).to_string()
}

//--------------------------------------------------------------------------------------------------
// Functions: C ABI
//--------------------------------------------------------------------------------------------------

/// Open a TCP connection from inside the guest to `host:port`.
///
/// Returns `{"conn":<handle>,"fd":<fd>}`. Go owns `fd`, one end of a close-on-exec Unix stream
/// socket pair carrying the connection's bytes. Release the handle with `msb_tcp_conn_close`
/// or `msb_tcp_conn_abort`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_dial_tcp(
    cancel_id: u64,
    handle: Handle,
    host: *const c_char,
    port: u16,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox = get(handle)?;
        let host = unsafe { cstr(host) }?;
        Ok(Box::pin(async move {
            let stream = Arc::new(sandbox.dial_tcp(host, port).await?);
            let (ours, theirs) = std::os::unix::net::UnixStream::pair()
                .map_err(|error| FfiError::internal(format!("socket pair: {error}")))?;
            #[cfg(target_vendor = "apple")]
            {
                let on: libc::c_int = 1;
                // Writes to a socket Go closed must fail, not raise SIGPIPE.
                unsafe {
                    libc::setsockopt(
                        ours.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_NOSIGPIPE,
                        (&on as *const libc::c_int).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
            }
            ours.set_nonblocking(true)
                .map_err(|error| FfiError::internal(format!("socket pair: {error}")))?;
            let socket = Arc::new(
                UnixStream::from_std(ours)
                    .map_err(|error| FfiError::internal(format!("socket pair: {error}")))?,
            );
            let (forwarded_tx, forwarded) = watch::channel(0);
            let stop = CancellationToken::new();
            let errors = Arc::new(Errors::default());
            let to_guest = tokio::spawn(relay_to_guest(
                Arc::clone(&socket),
                Arc::clone(&stream),
                forwarded_tx,
                stop.clone(),
                Arc::clone(&errors),
            ));
            let from_guest = tokio::spawn(relay_from_guest(
                socket,
                Arc::clone(&stream),
                stop.clone(),
                Arc::clone(&errors),
            ));
            let conn = NEXT_TCP_HANDLE.fetch_add(1, Ordering::Relaxed);
            registry()
                .write()
                .map_err(|_| FfiError::internal("tcp registry poisoned"))?
                .insert(
                    conn,
                    Arc::new(TcpBridge {
                        stream,
                        forwarded,
                        to_guest: Mutex::new(Some(to_guest)),
                        from_guest: Mutex::new(Some(from_guest)),
                        stop,
                        errors,
                    }),
                );
            let fd = theirs.into_raw_fd();
            Ok(serde_json::json!({ "conn": conn, "fd": fd }).to_string())
        }))
    })
}

/// Why each direction ended, if not in order: `{"read_error":<string|null>,"write_error":...}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_status(
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let bridge = lookup(conn)?;
        let read = bridge.errors.read.lock().map(|e| e.clone()).ok().flatten();
        let write = bridge.errors.write.lock().map(|e| e.clone()).ok().flatten();
        Ok(serde_json::json!({ "read_error": read, "write_error": write }).to_string())
    })
}

/// Orderly close, after Go closed its socket: deliver every byte Go wrote, then release the
/// guest connection without a reset. Returns `{"cleanup":"acknowledged"|"unknown"}`, or an
/// error when bytes could not be delivered within the idle bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_close(
    cancel_id: u64,
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let bridge = take(conn)?;
        Ok(Box::pin(async move {
            let forwarded = wait_forwarded(&bridge).await;
            let closed = bridge.stream.close().await;
            bridge.stop.cancel();
            if let Some(task) = bridge.from_guest.lock().await.take() {
                let _ = task.await;
            }
            let cleanup = closed?;
            if !forwarded {
                return Err(FfiError::internal(
                    "guest TCP close: the guest stopped accepting bytes before Go's last write",
                ));
            }
            Ok(cleanup_json(cleanup))
        }))
    })
}

/// Abort: discard unwritten bytes and reset the guest connection.
/// Returns `{"cleanup":"acknowledged"|"unknown"}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_abort(
    cancel_id: u64,
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let bridge = take(conn)?;
        Ok(Box::pin(async move {
            bridge.stop.cancel();
            let cleanup = bridge.stream.abort().await;
            for task in [&bridge.to_guest, &bridge.from_guest] {
                if let Some(task) = task.lock().await.take() {
                    let _ = task.await;
                }
            }
            Ok(cleanup_json(cleanup))
        }))
    })
}
