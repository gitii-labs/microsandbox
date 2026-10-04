//! Unix socket writes must not raise SIGPIPE in an embedding process such as Go. Tokio/Mio's
//! vectored Unix write uses writev, unlike the signal-safe scalar socket send.

use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use nix::sys::socket::{MsgFlags, sendmsg};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::UnixStream;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const SEND_FLAGS: MsgFlags = MsgFlags::MSG_NOSIGNAL;
// Mio installs SO_NOSIGPIPE when it creates a macOS socket.
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: MsgFlags = MsgFlags::empty();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct SignalSafeUnixStream(UnixStream);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SignalSafeUnixStream {
    pub(crate) fn new(socket: UnixStream) -> Self {
        Self(socket)
    }
    pub(crate) fn socket(&self) -> &UnixStream {
        &self.0
    }
    pub(crate) fn into_inner(self) -> UnixStream {
        self.0
    }

    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            ready!(self.0.poll_write_ready(cx))?;
            let sent = self.0.try_io(Interest::WRITABLE, || {
                sendmsg::<()>(self.0.as_raw_fd(), buffers, &[], SEND_FLAGS, None)
                    .map_err(std::io::Error::from)
            });
            match sent {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsyncRead for SignalSafeUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl AsyncWrite for SignalSafeUnixStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_send(cx, &[IoSlice::new(buffer)])
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_send(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
