//! Socket evidence for runtimes predating lifecycle locks. No protocol request is sent here.

use std::io;
use std::path::{Path, PathBuf};

use tokio::net::UnixStream;

use super::process_exit::RuntimeExit;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeExit {
    /// Pin before connecting, then authenticate a control or agent endpoint against that process.
    pub(super) async fn capture_socket(
        pid: Option<i32>,
        run_dir: &Path,
        sandboxes_dir: &Path,
        name: &str,
    ) -> io::Result<Option<Self>> {
        // Pin before connecting; a later occupant of the PID must not become this owner.
        let process = Self::capture_pid(pid)?;
        let agents = crate::runtime::spawn::sandbox_agent_socket_path_candidates_with_roots(
            run_dir,
            sandboxes_dir,
            name,
        );
        let mut endpoints: Vec<_> = agents
            .iter()
            .map(|path| microsandbox_runtime::control::control_socket_path_for(path))
            .collect();
        endpoints.extend(agents);
        let Some(process) = process else {
            // A disappearing ephemeral row or stale/missing PID cannot authorize cleanup
            // while a server still owns this sandbox's endpoint.
            return if connect_endpoint(endpoints).await?.is_some() {
                Err(io::Error::other(
                    "live runtime endpoint has no matching catalog process",
                ))
            } else {
                Ok(None)
            };
        };
        if process.connect_verified(endpoints).await?.is_some() {
            return Ok(Some(process));
        }
        // Released runtimes unlink their sockets before publishing terminal rows and
        // exiting. A live PID without endpoint evidence may also be recycled: neither
        // case authorizes signalling it or certifying that its disks are released.
        if !process.has_exited()? {
            return Err(io::Error::other(
                "cannot authenticate live catalog process: runtime endpoints are unavailable; refusing to report stop complete",
            ));
        }
        Ok(None)
    }

    /// Authenticate the actual connection before any handshake or shutdown bytes are written.
    pub(super) async fn connect_verified(
        &self,
        paths: Vec<PathBuf>,
    ) -> io::Result<Option<UnixStream>> {
        let Some(stream) = connect_endpoint(paths).await? else {
            return Ok(None);
        };
        self.verify_socket(&stream)?;
        Ok(Some(stream))
    }

    pub(super) fn verify_socket(&self, stream: &UnixStream) -> io::Result<()> {
        self.verify_peer(socket_peer_pid(stream)?)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn connect_endpoint(paths: Vec<PathBuf>) -> io::Result<Option<UnixStream>> {
    for path in paths {
        match UnixStream::connect(path).await {
            Ok(stream) => return Ok(Some(stream)),
            // A missing/stale endpoint is not ownership evidence. Other errors must not
            // authorize reconciliation of a runtime whose socket cannot be inspected.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn socket_peer_pid(stream: &UnixStream) -> io::Result<i32> {
    stream
        .peer_cred()?
        .pid()
        .ok_or_else(|| io::Error::other("runtime endpoint did not report its process identity"))
}

#[cfg(target_os = "macos")]
fn socket_peer_pid(stream: &UnixStream) -> io::Result<i32> {
    use std::os::fd::AsRawFd;

    let mut pid: libc::pid_t = 0;
    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
    // getpeereid exposes only UID/GID. LOCAL_PEERPID identifies this connected server.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut size,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&pid) || pid <= 0 {
        return Err(io::Error::other(
            "invalid runtime endpoint process identity",
        ));
    }
    Ok(pid)
}
