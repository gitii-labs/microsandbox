//! Exec session management: spawning processes with PTY or pipe I/O.

use std::ffi::{CStr, CString, OsStr};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::Arc;

use nix::fcntl::OFlag;
use nix::pty;
use nix::sys::signal::Signal;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};

use microsandbox_protocol::exec::{ExecFailed, ExecFailureKind, ExecRequest};

use crate::config::SecurityProfile;
use crate::error::{AgentdError, AgentdResult};
use crate::process::{ProcessExitWatcher, ProcessIdentity, ProcessManager};
use crate::rlimit;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_WORD_BITS: u32 = 32;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;
const DEFAULT_USER_SPEC: &str = "0:0";

//--------------------------------------------------------------------------------------------------
// Functions: classify
//--------------------------------------------------------------------------------------------------

/// Map an `errno` integer to its standard symbolic name. Returns
/// `None` for unrecognized values; we only enumerate the ones that
/// can plausibly come out of fork/exec/setrlimit/setuid paths.
fn errno_name(e: i32) -> Option<&'static str> {
    match e {
        libc::E2BIG => Some("E2BIG"),
        libc::EACCES => Some("EACCES"),
        libc::EAGAIN => Some("EAGAIN"),
        libc::EBUSY => Some("EBUSY"),
        libc::EFAULT => Some("EFAULT"),
        libc::EINVAL => Some("EINVAL"),
        libc::EIO => Some("EIO"),
        libc::EISDIR => Some("EISDIR"),
        libc::ELOOP => Some("ELOOP"),
        libc::EMFILE => Some("EMFILE"),
        libc::ENAMETOOLONG => Some("ENAMETOOLONG"),
        libc::ENFILE => Some("ENFILE"),
        libc::ENOENT => Some("ENOENT"),
        libc::ENOEXEC => Some("ENOEXEC"),
        libc::ENOMEM => Some("ENOMEM"),
        libc::ENOSYS => Some("ENOSYS"),
        libc::ENOTDIR => Some("ENOTDIR"),
        libc::ENXIO => Some("ENXIO"),
        libc::EPERM => Some("EPERM"),
        libc::ETXTBSY => Some("ETXTBSY"),
        _ => None,
    }
}

/// Classify a fork/exec-time `errno` into one of the
/// `ExecFailureKind` buckets.
///
/// ENOENT is ambiguous (missing binary vs. missing cwd); the errno
/// alone is classified as the binary. [`spawn_process`] reclassifies a
/// failure as `BadCwd` when the requested cwd is not a directory.
fn classify_spawn_errno(errno: i32) -> ExecFailureKind {
    match errno {
        libc::ENOENT => ExecFailureKind::NotFound,
        libc::ENOTDIR => ExecFailureKind::BadCwd,
        libc::EACCES | libc::EPERM => ExecFailureKind::PermissionDenied,
        libc::ENOEXEC => ExecFailureKind::NotExecutable,
        libc::EISDIR => ExecFailureKind::NotExecutable,
        libc::ETXTBSY => ExecFailureKind::NotExecutable,
        libc::E2BIG | libc::ELOOP | libc::ENAMETOOLONG | libc::EFAULT => ExecFailureKind::BadArgs,
        libc::EMFILE | libc::ENFILE => ExecFailureKind::ResourceLimit,
        libc::EAGAIN => ExecFailureKind::ResourceLimit,
        libc::ENOMEM => ExecFailureKind::OutOfMemory,
        libc::EINVAL => ExecFailureKind::Other,
        _ => ExecFailureKind::Other,
    }
}

/// Build an `ExecFailed` payload for a setup step the child's `pre_exec`
/// hook reported as failed. The step, not the errno, picks the kind: an EPERM
/// from `setuid` is a user switch the sandbox refused, not a binary without
/// its execute bit.
fn exec_failed_from_setup_step(
    err: &std::io::Error,
    cmd: &str,
    step: SetupStep,
    stage: String,
) -> ExecFailed {
    let errno = err.raw_os_error();
    ExecFailed {
        kind: step.kind(),
        errno,
        errno_name: errno.and_then(errno_name).map(str::to_string),
        message: format!("spawn {cmd:?}: {stage} failed: {err}"),
        stage: Some(stage),
    }
}

/// Build a `ExecFailed` payload from a spawn-time `io::Error`.
fn exec_failed_from_io_error(err: &std::io::Error, cmd: &str, stage: &str) -> ExecFailed {
    let errno = err.raw_os_error();
    let kind = errno
        .map(classify_spawn_errno)
        .unwrap_or(ExecFailureKind::Other);
    let errno_name = errno.and_then(errno_name).map(str::to_string);
    let message = format!("spawn {cmd:?}: {err}");
    ExecFailed {
        kind,
        errno,
        errno_name,
        message,
        stage: Some(stage.to_string()),
    }
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An active exec session handle for sending input to a running process.
///
/// Output reading is handled by a background task that sends events
/// via the `mpsc` channel provided at spawn time.
#[derive(Debug)]
pub struct ExecSession {
    /// Stable identity for the spawned process registration.
    process_identity: ProcessIdentity,

    /// Owns process status and serializes signals with PID reuse.
    process_manager: Arc<ProcessManager>,

    /// The PTY master fd (only for PTY mode, used for writing and resize).
    pty_master: Option<OwnedFd>,

    /// The child's stdin (only for pipe mode).
    stdin: Option<tokio::process::ChildStdin>,

    /// Tells the reporter task no client waits for this session's output.
    detach: Option<oneshot::Sender<()>>,
}

/// Output from a session that the agent loop should forward to the host.
pub enum SessionOutput {
    /// Data from stdout (or PTY master).
    Stdout(Vec<u8>),

    /// Data from stderr (pipe mode only).
    Stderr(Vec<u8>),

    /// The process has exited with the given code.
    Exited(i32),

    /// Pre-encoded frame bytes to write directly to the serial output buffer.
    Raw(RawSessionOutput),
}

/// Pre-encoded session output plus the accounting metadata known by its producer.
pub struct RawSessionOutput {
    /// Encoded protocol frame bytes.
    pub frame: Vec<u8>,

    /// Activity represented by the frame.
    pub activity: RawActivity,

    /// Session table entry completed by the frame, if any.
    pub completion: Option<RawSessionCompletion>,
}

/// Activity represented by a pre-encoded session frame.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawActivity {
    /// Whether this frame is a meaningful guest-to-host protocol message.
    pub guest_message: bool,

    /// Filesystem bytes moved by this frame.
    pub fs_bytes: usize,

    /// TCP bytes moved by this frame.
    pub tcp_bytes: usize,
}

/// Session table entry completed by a pre-encoded session frame.
#[derive(Debug, Clone, Copy)]
pub enum RawSessionCompletion {
    /// A filesystem read stream completed.
    FsRead,

    /// A TCP stream completed.
    Tcp,
}

struct ResolvedUser {
    uid: libc::uid_t,
    gid: libc::gid_t,
    /// The passwd name, when the uid has an entry.
    name: Option<String>,
    /// Supplementary groups, resolved before fork: `initgroups` reads the
    /// group database, which a forked child must not do. Filled in only for
    /// a user the child switches to.
    groups: Vec<libc::gid_t>,
    home_dir: Option<CString>,
}

/// A command for an exec request, with the channel its `pre_exec` hook names
/// a failed setup step through.
struct ExecCommand {
    command: Command,
    setup: SetupReport,
}

/// The pipe an exec child reports a failed `pre_exec` setup step through.
///
/// std reports only the errno of a failed `pre_exec` hook, and the same errno
/// comes from different steps: EPERM from `setuid` and from `execve` mean
/// different things. Before failing, the child writes the step as two bytes
/// with `write(2)`, which is async-signal-safe and allocates nothing: the
/// [`SetupStep`] and a detail byte, the failed rlimit's `RLIMIT_*` id. std has
/// the child report its errno only after the hook returns, so once `spawn`
/// returns the error the bytes are already in the pipe. Both ends are
/// close-on-exec, so a child that reaches `exec` writes nothing.
struct SetupReport {
    read: OwnedFd,
    write: OwnedFd,
    /// The `RLIMIT_*` id and wire name of each rlimit the child sets.
    rlimits: Vec<(libc::c_int, String)>,
}

/// A `pre_exec` setup step, as the byte the child reports it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SetupStep {
    Setsid = 1,
    ControllingTerminal = 2,
    CapabilityDrop = 3,
    Setgroups = 4,
    Setgid = 5,
    Setuid = 6,
    Setrlimit = 7,
}

/// Whether the child gets a controlling terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChildTerminal {
    /// Its stdin is a PTY slave, made its controlling terminal.
    Pty,
    /// No controlling terminal.
    None,
}

struct PasswdEntry {
    name: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home_dir: Option<String>,
}

struct GroupEntry {
    gid: libc::gid_t,
}

/// A spawned process whose exit status is observed by [`ProcessManager`].
///
/// The stdio handles are present only for the streams spawned as pipes.
struct SpawnedProcess {
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    exit_watcher: ProcessExitWatcher,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RawSessionOutput {
    /// Creates pre-encoded output with activity metadata.
    pub fn new(
        frame: Vec<u8>,
        activity: RawActivity,
        completion: Option<RawSessionCompletion>,
    ) -> Self {
        Self {
            frame,
            activity,
            completion,
        }
    }
}

impl RawActivity {
    /// A guest-to-host frame with no byte counter.
    pub fn guest_message() -> Self {
        Self {
            guest_message: true,
            ..Self::default()
        }
    }

    /// A guest-to-host filesystem data frame.
    pub fn fs_bytes(len: usize) -> Self {
        Self {
            guest_message: true,
            fs_bytes: len,
            tcp_bytes: 0,
        }
    }

    /// A guest-to-host TCP data frame.
    pub fn tcp_bytes(len: usize) -> Self {
        Self {
            guest_message: true,
            fs_bytes: 0,
            tcp_bytes: len,
        }
    }
}

impl ExecSession {
    /// Spawns a new exec session.
    ///
    /// If `req.tty` is true, uses a PTY. Otherwise, uses piped stdin/stdout/stderr.
    /// A background task is spawned to read output and send events via `tx`.
    pub fn spawn(
        id: u32,
        req: &ExecRequest,
        tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
        default_user: Option<&str>,
        security_profile: SecurityProfile,
    ) -> AgentdResult<Self> {
        let process_manager = ProcessManager::get()?;
        if req.tty {
            Self::spawn_pty(
                id,
                req,
                tx,
                default_user,
                security_profile,
                &process_manager,
            )
        } else {
            Self::spawn_pipe(
                id,
                req,
                tx,
                default_user,
                security_profile,
                &process_manager,
            )
        }
    }

    /// Returns the PID of the spawned process (as u32 for the protocol).
    pub fn pid(&self) -> u32 {
        self.process_identity.pid() as u32
    }

    /// Writes data to the process's stdin (or PTY master).
    pub async fn write_stdin(&self, data: &[u8]) -> AgentdResult<()> {
        if let Some(ref master) = self.pty_master {
            blocking_write_fd(master.as_raw_fd(), data).await
        } else if let Some(ref stdin) = self.stdin {
            blocking_write_fd(stdin.as_raw_fd(), data).await
        } else {
            Ok(())
        }
    }

    /// Resizes the PTY (only applicable for TTY sessions).
    pub fn resize(&self, rows: u16, cols: u16) -> AgentdResult<()> {
        if let Some(ref master) = self.pty_master {
            let ws = libc::winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let ret = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Sends a signal to the spawned process and everything it started.
    ///
    /// The child is made a session leader at spawn (both pipe and PTY modes),
    /// so signalling the negative pid reaches its whole process group. A bare
    /// kill(pid) here leaked orphans: killing `sh -c "job &"` took out the
    /// shell while its backgrounded children survived reparented to init,
    /// silently accumulating load in the guest.
    pub fn send_signal(&self, signum: i32) -> AgentdResult<()> {
        let sig = Signal::try_from(signum)
            .map_err(|e| AgentdError::ExecSession(format!("invalid signal {signum}: {e}")))?;
        self.process_manager
            .signal_process_group(self.process_identity, sig as i32)
    }

    /// Closes the process's stdin.
    ///
    /// For pipe mode, drops the `ChildStdin` handle which closes the fd.
    /// For PTY mode, this is a no-op (the PTY master stays open for output).
    pub fn close_stdin(&mut self) {
        self.stdin.take();
    }

    /// Reports the session as exited once its direct child is reaped, and
    /// discards its output from then on.
    ///
    /// For a session whose client is gone: a descendant that left the process
    /// group can hold the output open for as long as it lives, and the
    /// session's ID must not wait for it.
    pub fn detach(&mut self) {
        if let Some(detach) = self.detach.take() {
            let _ = detach.send(());
        }
    }
}

impl SetupStep {
    fn from_byte(byte: u8) -> Option<Self> {
        [
            Self::Setsid,
            Self::ControllingTerminal,
            Self::CapabilityDrop,
            Self::Setgroups,
            Self::Setgid,
            Self::Setuid,
            Self::Setrlimit,
        ]
        .into_iter()
        .find(|step| *step as u8 == byte)
    }

    fn kind(self) -> ExecFailureKind {
        match self {
            Self::Setsid | Self::ControllingTerminal => ExecFailureKind::PtySetupFailed,
            Self::Setgroups | Self::Setgid | Self::Setuid => ExecFailureKind::UserSetupFailed,
            Self::Setrlimit => ExecFailureKind::ResourceLimit,
            // No kind names a privilege drop; the stage does.
            Self::CapabilityDrop => ExecFailureKind::Other,
        }
    }
}

impl SetupReport {
    fn new(rlimits: Vec<(libc::c_int, String)>) -> std::io::Result<Self> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: pipe2 just returned both fds, and nothing else owns them.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok(Self {
            read,
            write,
            rlimits,
        })
    }

    /// Runs in the forked child: reports `step` and passes `err` through.
    /// Makes one `write(2)` from the stack and nothing else.
    fn fail(fd: RawFd, step: SetupStep, detail: u8, err: std::io::Error) -> std::io::Error {
        let report = [step as u8, detail];
        // A failed write leaves the parent to classify by errno alone.
        let _ = unsafe { libc::write(fd, report.as_ptr().cast(), report.len()) };
        err
    }

    /// The step a failed spawn's child reported, with its stage name, or
    /// `None` when the spawn failed outside the `pre_exec` hook.
    fn failed_step(&self) -> Option<(SetupStep, String)> {
        let mut report = [0u8; 2];
        let n = unsafe {
            libc::read(
                self.read.as_raw_fd(),
                report.as_mut_ptr().cast(),
                report.len(),
            )
        };
        if n != report.len() as isize {
            return None;
        }
        let step = SetupStep::from_byte(report[0])?;
        let stage = match step {
            SetupStep::Setsid => "setsid".to_string(),
            SetupStep::ControllingTerminal => "ioctl(TIOCSCTTY)".to_string(),
            SetupStep::CapabilityDrop => "drop CAP_SYS_ADMIN".to_string(),
            SetupStep::Setgroups => "setgroups".to_string(),
            SetupStep::Setgid => "setgid".to_string(),
            SetupStep::Setuid => "setuid".to_string(),
            SetupStep::Setrlimit => match self
                .rlimits
                .iter()
                .find(|(id, _)| *id == libc::c_int::from(report[1]))
            {
                Some((_, name)) => format!("setrlimit(RLIMIT_{})", name.to_ascii_uppercase()),
                None => "setrlimit".to_string(),
            },
        };
        Some((step, stage))
    }
}

impl ExecSession {
    /// Spawns a process with a PTY.
    fn spawn_pty(
        id: u32,
        req: &ExecRequest,
        tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
        default_user: Option<&str>,
        security_profile: SecurityProfile,
        process_manager: &Arc<ProcessManager>,
    ) -> AgentdResult<Self> {
        let (master, slave) = open_pty()?;

        // Set initial window size.
        let ws = libc::winsize {
            ws_row: req.rows,
            ws_col: req.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut cmd = exec_command(req, default_user, security_profile, ChildTerminal::Pty)?;
        cmd.command
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));

        // `spawn_process` drops the command and with it the parent's slave
        // fds, so the master reads EIO once the session's processes close theirs.
        let SpawnedProcess { exit_watcher, .. } = spawn_process(cmd, process_manager)?;
        let process_identity = exit_watcher.identity();

        // A second master fd for the reader task.
        let reader_fd = match master.try_clone() {
            Ok(fd) => fd,
            Err(error) => {
                let _ =
                    process_manager.signal_process_group(process_identity, Signal::SIGKILL as i32);
                process_manager.release(process_identity);
                return Err(error.into());
            }
        };

        // Spawn background reader task.
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (detach, detached) = oneshot::channel();
        tokio::task::spawn_blocking(move || read_pty(reader_fd, output_tx));
        tokio::spawn(report_session(id, output_rx, exit_watcher, detached, tx));

        Ok(Self {
            process_identity,
            process_manager: Arc::clone(process_manager),
            pty_master: Some(master),
            stdin: None,
            detach: Some(detach),
        })
    }

    /// Spawns a process with piped stdio.
    fn spawn_pipe(
        id: u32,
        req: &ExecRequest,
        tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
        default_user: Option<&str>,
        security_profile: SecurityProfile,
        process_manager: &Arc<ProcessManager>,
    ) -> AgentdResult<Self> {
        let mut cmd = exec_command(req, default_user, security_profile, ChildTerminal::None)?;
        cmd.command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let SpawnedProcess {
            stdin,
            stdout,
            stderr,
            exit_watcher,
        } = spawn_process(cmd, process_manager)?;
        let process_identity = exit_watcher.identity();

        // Spawn background reader task.
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (detach, detached) = oneshot::channel();
        if let Some(stdout) = stdout {
            tokio::spawn(read_pipe(stdout, SessionOutput::Stdout, output_tx.clone()));
        }
        if let Some(stderr) = stderr {
            tokio::spawn(read_pipe(stderr, SessionOutput::Stderr, output_tx));
        }
        tokio::spawn(report_session(id, output_rx, exit_watcher, detached, tx));

        Ok(Self {
            process_identity,
            process_manager: Arc::clone(process_manager),
            pty_master: None,
            stdin,
            detach: Some(detach),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ExecSession {
    fn drop(&mut self) {
        // The registration deliberately outlives the direct child so signals
        // can still reach descendants while their output is being drained. A
        // detached session drops at the reap: no client is left to signal.
        self.process_manager.release(self.process_identity);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Builds the command for an exec request.
fn exec_command(
    req: &ExecRequest,
    default_user: Option<&str>,
    security_profile: SecurityProfile,
    terminal: ChildTerminal,
) -> AgentdResult<ExecCommand> {
    let resolved_user = resolve_requested_user(req, default_user)?;
    let home = default_home_dir(req, resolved_user.as_ref())?;
    build_command(req, resolved_user, home, security_profile, terminal)
}

/// Builds the command for an exec request whose user is already resolved.
///
/// Everything the child needs is prepared here, in the parent: std builds the
/// environment block and argv before it forks, and the `pre_exec` hook only
/// makes async-signal-safe system calls. A child forked from this
/// multithreaded process must not allocate or take a lock before `exec`, or
/// it can deadlock on a lock another thread held at the fork.
fn build_command(
    req: &ExecRequest,
    resolved_user: Option<ResolvedUser>,
    home: Option<CString>,
    security_profile: SecurityProfile,
    terminal: ChildTerminal,
) -> AgentdResult<ExecCommand> {
    let mut cmd = Command::new(&req.cmd);
    cmd.args(&req.args);

    for var in &req.env {
        if let Some((key, val)) = var.split_once('=') {
            cmd.env(key, val);
        }
    }

    if let Some(ref dir) = req.cwd {
        cmd.current_dir(dir);
    }

    if let Some(home) = home {
        cmd.env("HOME", OsStr::from_bytes(home.as_bytes()));
    }

    let (rlimit_names, rlimits): (Vec<_>, Vec<_>) = req
        .rlimits
        .iter()
        .filter_map(|rl| {
            let resource = rlimit::parse_rlimit_resource(&rl.resource)?;
            let limit = libc::rlimit {
                rlim_cur: rl.soft,
                rlim_max: rl.hard,
            };
            Some(((resource, rl.resource.clone()), (resource, limit)))
        })
        .unzip();
    let setup = SetupReport::new(rlimit_names)?;
    let report = setup.write.as_raw_fd();

    unsafe {
        cmd.pre_exec(move || {
            let fail = |step, detail, err| SetupReport::fail(report, step, detail, err);
            // Become a session (and process-group) leader so signals sent to
            // the group reach every descendant the command spawns, not just
            // the direct child.
            if libc::setsid() < 0 {
                return Err(fail(SetupStep::Setsid, 0, std::io::Error::last_os_error()));
            }
            // std has already made the PTY slave the child's stdin.
            if terminal == ChildTerminal::Pty && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                let err = std::io::Error::last_os_error();
                return Err(fail(SetupStep::ControllingTerminal, 0, err));
            }
            apply_exec_security_profile(security_profile)
                .map_err(|err| fail(SetupStep::CapabilityDrop, 0, err))?;
            if let Some(ref user) = resolved_user {
                apply_resolved_user(user).map_err(|(step, err)| fail(step, 0, err))?;
            }
            for (resource, limit) in &rlimits {
                if libc::setrlimit(*resource as _, limit) != 0 {
                    let err = std::io::Error::last_os_error();
                    // `RLIMIT_*` ids run from 0 to 15.
                    return Err(fail(SetupStep::Setrlimit, *resource as u8, err));
                }
            }
            Ok(())
        });
    }

    Ok(ExecCommand {
        command: cmd,
        setup,
    })
}

/// Opens a PTY pair with both ends close-on-exec, so no other session's
/// child inherits them. The child gets its slave as stdio through `dup2`,
/// which clears the flag on the copies.
fn open_pty() -> AgentdResult<(OwnedFd, OwnedFd)> {
    let master = pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC)?;
    pty::grantpt(&master)?;
    pty::unlockpt(&master)?;
    let slave_path = pty::ptsname_r(&master)?;
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(slave_path)?;
    Ok((master.into(), slave.into()))
}

fn spawn_process(
    command: ExecCommand,
    process_manager: &ProcessManager,
) -> AgentdResult<SpawnedProcess> {
    let ExecCommand { mut command, setup } = command;
    let cmd_label = command.get_program().to_string_lossy().into_owned();

    // Prevent the central reaper from observing this child before its PID and
    // generation are registered.
    let spawn_guard = process_manager.spawn_guard()?;
    let mut child = command.spawn().map_err(|error| {
        if let Some((step, stage)) = setup.failed_step() {
            return AgentdError::ExecSpawnFailed(exec_failed_from_setup_step(
                &error, &cmd_label, step, stage,
            ));
        }
        let mut failed = exec_failed_from_io_error(&error, &cmd_label, "Command::spawn");
        // std's chdir and execvp both fail with ENOENT or ENOTDIR; a missing
        // cwd is the one to name, since the binary was never looked up.
        if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
            && command.get_current_dir().is_some_and(|dir| !dir.is_dir())
        {
            failed.kind = ExecFailureKind::BadCwd;
        }
        AgentdError::ExecSpawnFailed(failed)
    })?;
    let pid = child.id() as i32;
    let exit_watcher = spawn_guard.track(pid)?;
    let process_identity = exit_watcher.identity();

    let stdio = (|| {
        let stdin = child
            .stdin
            .take()
            .map(tokio::process::ChildStdin::from_std)
            .transpose()?;
        let stdout = child
            .stdout
            .take()
            .map(tokio::process::ChildStdout::from_std)
            .transpose()?;
        let stderr = child
            .stderr
            .take()
            .map(tokio::process::ChildStderr::from_std)
            .transpose()?;
        Ok::<_, std::io::Error>((stdin, stdout, stderr))
    })();
    let (stdin, stdout, stderr) = stdio.map_err(|error| {
        // The command has already exec'd successfully. If an async stdio
        // adapter cannot be registered, do not leave an unreported process
        // group running after the host receives ExecFailed.
        let _ = process_manager.signal_process_group(process_identity, Signal::SIGKILL as i32);
        process_manager.release(process_identity);
        AgentdError::ExecSpawnFailed(exec_failed_from_io_error(
            &error,
            &cmd_label,
            "Command::spawn",
        ))
    })?;

    // `std::process::Child` has no asynchronous reaper on drop. Once the PID
    // is tracked, the process manager owns its exit status during normal
    // operation; terminal teardown may reap it directly as a fallback.
    drop(child);

    Ok(SpawnedProcess {
        stdin,
        stdout,
        stderr,
        exit_watcher,
    })
}

fn apply_exec_security_profile(profile: SecurityProfile) -> std::io::Result<()> {
    match profile {
        SecurityProfile::Default => Ok(()),
        SecurityProfile::Restricted => drop_mount_admin_privileges(),
    }
}

fn drop_mount_admin_privileges() -> std::io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let ret = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }

    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];

    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let index = (CAP_SYS_ADMIN / CAP_WORD_BITS) as usize;
    let mask = 1u32 << (CAP_SYS_ADMIN % CAP_WORD_BITS);
    let had_sys_admin = data[index].effective & mask != 0
        || data[index].permitted & mask != 0
        || data[index].inheritable & mask != 0;

    if had_sys_admin {
        data[index].effective &= !mask;
        data[index].permitted &= !mask;
        data[index].inheritable &= !mask;

        if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let ret = unsafe { libc::prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error();
        // Already-unprivileged callers may also lack CAP_SETPCAP for the bounding-set drop.
        let already_unprivileged = !had_sys_admin && errno == Some(libc::EPERM);
        if errno != Some(libc::EINVAL) && !already_unprivileged {
            return Err(err);
        }
    }

    Ok(())
}

pub(crate) fn resolve_default_user(default_user: Option<&str>) -> AgentdResult<(u32, u32)> {
    let Some(spec) = default_user
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok((0, 0));
    };

    let resolved = resolve_user_spec(spec)?;
    Ok((resolved.uid, resolved.gid))
}

fn resolve_requested_user(
    req: &ExecRequest,
    default_user: Option<&str>,
) -> AgentdResult<Option<ResolvedUser>> {
    let default_user = default_user
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let requested = req
        .user
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(default_user);

    requested
        .map(|spec| {
            let mut user = resolve_user_spec(spec)?;
            if let Some(ref name) = user.name {
                user.groups = lookup_group_list(name, user.gid)?;
            }
            Ok(user)
        })
        .transpose()
}

fn resolve_user_spec(spec: &str) -> AgentdResult<ResolvedUser> {
    let (user_part, group_part) = match spec.split_once(':') {
        Some((user, group)) => (user.trim(), Some(group.trim())),
        None => (spec.trim(), None),
    };

    if user_part.is_empty() {
        return Err(AgentdError::ExecSession("user spec has empty user".into()));
    }

    let passwd = if let Ok(uid) = parse_id(user_part) {
        lookup_passwd_by_uid(uid)?
    } else {
        lookup_passwd_by_name(user_part)?
            .ok_or_else(|| AgentdError::ExecSession(format!("guest user not found: {user_part}")))?
            .into()
    };

    let (uid, passwd_entry) = match passwd {
        ResolvedUserLookup::Known(entry) => (entry.uid, Some(entry)),
        ResolvedUserLookup::Numeric(uid) => (uid, None),
    };

    let gid = match group_part {
        Some("") => {
            return Err(AgentdError::ExecSession("user spec has empty group".into()));
        }
        Some(group) => resolve_group_spec(group)?,
        None => passwd_entry
            .as_ref()
            .map(|entry| entry.gid)
            .unwrap_or_else(|| unsafe { libc::getgid() }),
    };

    Ok(ResolvedUser {
        uid,
        gid,
        name: passwd_entry.as_ref().map(|entry| entry.name.clone()),
        groups: Vec::new(),
        home_dir: passwd_entry
            .as_ref()
            .and_then(|entry| entry.home_dir.as_deref())
            .map(CString::new)
            .transpose()
            .map_err(|e| AgentdError::ExecSession(format!("invalid guest home directory: {e}")))?,
    })
}

enum ResolvedUserLookup {
    Known(PasswdEntry),
    Numeric(libc::uid_t),
}

impl From<PasswdEntry> for ResolvedUserLookup {
    fn from(value: PasswdEntry) -> Self {
        Self::Known(value)
    }
}

fn resolve_group_spec(spec: &str) -> AgentdResult<libc::gid_t> {
    if let Ok(gid) = parse_id(spec) {
        return Ok(gid);
    }

    lookup_group_by_name(spec)?
        .map(|entry| entry.gid)
        .ok_or_else(|| AgentdError::ExecSession(format!("guest group not found: {spec}")))
}

fn parse_id(value: &str) -> Result<u32, std::num::ParseIntError> {
    value.parse::<u32>()
}

fn lookup_passwd_by_name(name: &str) -> AgentdResult<Option<PasswdEntry>> {
    let name = CString::new(name)
        .map_err(|e| AgentdError::ExecSession(format!("invalid guest user name: {e}")))?;
    let mut pwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = ptr::null_mut();
    let mut buf = vec![0u8; lookup_buffer_len()];
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(AgentdError::ExecSession(format!(
            "failed to resolve guest user {name:?}: {}",
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    if result.is_null() {
        return Ok(None);
    }

    let pwd = unsafe { pwd.assume_init() };
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    let home_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Ok(Some(PasswdEntry {
        name,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: (!home_dir.is_empty()).then_some(home_dir),
    }))
}

fn lookup_passwd_by_uid(uid: libc::uid_t) -> AgentdResult<ResolvedUserLookup> {
    let mut pwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = ptr::null_mut();
    let mut buf = vec![0u8; lookup_buffer_len()];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(AgentdError::ExecSession(format!(
            "failed to resolve guest uid {uid}: {}",
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    if result.is_null() {
        return Ok(ResolvedUserLookup::Numeric(uid));
    }

    let pwd = unsafe { pwd.assume_init() };
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    let home_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Ok(ResolvedUserLookup::Known(PasswdEntry {
        name,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: (!home_dir.is_empty()).then_some(home_dir),
    }))
}

fn lookup_group_by_name(name: &str) -> AgentdResult<Option<GroupEntry>> {
    let name = CString::new(name)
        .map_err(|e| AgentdError::ExecSession(format!("invalid guest group name: {e}")))?;
    let mut grp = MaybeUninit::<libc::group>::uninit();
    let mut result = ptr::null_mut();
    let mut buf = vec![0u8; lookup_buffer_len()];
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            grp.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(AgentdError::ExecSession(format!(
            "failed to resolve guest group {name:?}: {}",
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    if result.is_null() {
        return Ok(None);
    }

    let grp = unsafe { grp.assume_init() };
    Ok(Some(GroupEntry { gid: grp.gr_gid }))
}

/// The supplementary groups `initgroups(name, gid)` would set.
fn lookup_group_list(name: &str, gid: libc::gid_t) -> AgentdResult<Vec<libc::gid_t>> {
    const INITIAL_GROUPS: usize = 32;

    let c_name = CString::new(name)
        .map_err(|e| AgentdError::ExecSession(format!("invalid guest user name: {e}")))?;
    let mut groups: Vec<libc::gid_t> = vec![0; INITIAL_GROUPS];
    loop {
        let mut count = groups.len() as libc::c_int;
        let rc =
            unsafe { libc::getgrouplist(c_name.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
        if rc >= 0 {
            groups.truncate(count as usize);
            return Ok(groups);
        }
        // Too small: `count` now holds the number of groups the user has.
        // A count that does not grow the buffer means the lookup failed.
        let needed = count as usize;
        if needed <= groups.len() {
            return Err(AgentdError::ExecSession(format!(
                "failed to list groups of guest user {name:?}"
            )));
        }
        groups.resize(needed, 0);
    }
}

fn lookup_buffer_len() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if size > 0 { size as usize } else { 16 * 1024 }
}

/// Switches the calling process to `user`. Runs in a forked child: system
/// calls only.
fn apply_resolved_user(user: &ResolvedUser) -> Result<(), (SetupStep, std::io::Error)> {
    if unsafe { libc::setgroups(user.groups.len(), user.groups.as_ptr()) } != 0 {
        return Err((SetupStep::Setgroups, std::io::Error::last_os_error()));
    }
    if unsafe { libc::setgid(user.gid) } != 0 {
        return Err((SetupStep::Setgid, std::io::Error::last_os_error()));
    }
    if unsafe { libc::setuid(user.uid) } != 0 {
        return Err((SetupStep::Setuid, std::io::Error::last_os_error()));
    }

    Ok(())
}

fn default_home_dir(
    req: &ExecRequest,
    user: Option<&ResolvedUser>,
) -> AgentdResult<Option<CString>> {
    if env_contains_key(&req.env, "HOME") {
        return Ok(None);
    }

    if let Some(user) = user {
        return Ok(user.home_dir.clone());
    }

    Ok(resolve_user_spec(DEFAULT_USER_SPEC)?.home_dir)
}

fn env_contains_key(env: &[String], key: &str) -> bool {
    env.iter().any(|entry| {
        entry
            .split_once('=')
            .map(|(entry_key, _)| entry_key == key)
            .unwrap_or(false)
    })
}

/// Writes data to a raw fd using a blocking task, handling short writes.
async fn blocking_write_fd(fd: RawFd, data: &[u8]) -> AgentdResult<()> {
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut written = 0;
        while written < data.len() {
            let ptr = unsafe { data.as_ptr().add(written) as *const libc::c_void };
            let ret = unsafe { libc::write(fd, ptr, data.len() - written) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                let code = err.raw_os_error();
                if code == Some(libc::EAGAIN) || code == Some(libc::EWOULDBLOCK) {
                    wait_fd_writable(fd)?;
                    continue;
                }
                if code == Some(libc::EINTR) {
                    continue;
                }
                return Err(AgentdError::Io(err));
            }
            if ret == 0 {
                wait_fd_writable(fd)?;
                continue;
            }
            written += ret as usize;
        }
        Ok(())
    })
    .await
    .map_err(|e| AgentdError::ExecSession(format!("stdin write join error: {e}")))?
}

fn wait_fd_writable(fd: RawFd) -> AgentdResult<()> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };

    loop {
        let ret = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(AgentdError::Io(err));
        }
        if ret == 0 {
            continue;
        }
        // Any positive return means the fd is actionable: POLLOUT lets the
        // next write make progress, and POLLHUP/POLLERR/POLLNVAL will cause
        // the next write to fail with a real errno (typically EPIPE) which
        // is more meaningful than poll's revents.
        return Ok(());
    }
}

/// Blocking loop that reads a PTY master until EOF and forwards each chunk.
fn read_pty(master_fd: OwnedFd, output: mpsc::UnboundedSender<SessionOutput>) {
    // PTY masters are safer with a dedicated blocking read loop than with
    // edge-driven readiness. Fast writers followed by process exit can
    // strand the tail behind a missed wakeup/HUP transition.
    let raw = master_fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    }

    loop {
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n > 0 {
            if output
                .send(SessionOutput::Stdout(buf[..n as usize].to_vec()))
                .is_err()
            {
                break;
            }
            continue;
        }

        if n == 0 {
            break;
        }

        // EIO is the master's EOF once every slave fd has closed.
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
}

/// Reads one output pipe until EOF and forwards each chunk.
async fn read_pipe<R: tokio::io::AsyncRead + Unpin>(
    mut pipe: R,
    wrap: fn(Vec<u8>) -> SessionOutput,
    output: mpsc::UnboundedSender<SessionOutput>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if output.send(wrap(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        }
    }
}

/// Forwards a session's output, then its exit, as the session's only
/// reporter.
///
/// An attached session exits once its direct child is reaped and its output
/// has reached EOF, so output a background descendant writes still reaches
/// the client. A detached session exits as soon as its direct child is
/// reaped: its output is drained unreported after that, so no frame carrying
/// its ID follows the exit.
async fn report_session(
    id: u32,
    mut output: mpsc::UnboundedReceiver<SessionOutput>,
    mut exit_watcher: ProcessExitWatcher,
    mut detached: oneshot::Receiver<()>,
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let mut output_open = true;
    let mut is_detached = false;
    let mut code = None;
    loop {
        tokio::select! {
            chunk = output.recv(), if output_open => match chunk {
                Some(chunk) => {
                    let _ = tx.send((id, chunk));
                }
                None => output_open = false,
            },
            exited = &mut exit_watcher, if code.is_none() => code = Some(exited),
            // A dropped session has no client left either.
            _ = &mut detached, if !is_detached => is_detached = true,
        }
        if let Some(code) = code
            && (is_detached || !output_open)
        {
            let _ = tx.send((id, SessionOutput::Exited(code)));
            break;
        }
    }
    // Keep reading so a surviving descendant never blocks on, or is killed
    // by, a closed output.
    while output.recv().await.is_some() {}
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Read;
    use std::process::{Command as StdCommand, Stdio as StdStdio};
    use std::time::Duration;

    use tokio::time;

    use microsandbox_protocol::exec::{ExecRequest, ExecRlimit};

    use super::*;

    const REAP_HELPER_ENV: &str = "MSB_AGENTD_SESSION_REAP_HELPER";
    const REAP_HELPER_SENTINEL: &str = "session-reap-helper-passed";
    const REAP_TEST_NAME: &str = "session::tests::test_spawn_reaps_adopted_descendant";
    const CONCURRENT_HELPER_ENV: &str = "MSB_AGENTD_CONCURRENT_SPAWN_HELPER";
    const CONCURRENT_HELPER_SENTINEL: &str = "concurrent-spawn-helper-passed";
    const CONCURRENT_TEST_NAME: &str = "session::tests::test_concurrent_spawn_exit_codes";
    const RUNTIME_HELPER_ENV: &str = "MSB_AGENTD_RUNTIME_REPLACEMENT_HELPER";
    const RUNTIME_HELPER_SENTINEL: &str = "runtime-replacement-helper-passed";
    const RUNTIME_TEST_NAME: &str = "session::tests::test_spawn_survives_runtime_replacement";
    const PIPE_OWNER_HELPER_ENV: &str = "MSB_AGENTD_PIPE_OWNER_HELPER";
    const PIPE_OWNER_HELPER_SENTINEL: &str = "pipe-owner-helper-passed";
    const PIPE_OWNER_TEST_NAME: &str =
        "session::tests::test_piped_process_exit_outlives_spawning_runtime";
    const ENV_SPAWN_HELPER_ENV: &str = "MSB_AGENTD_ENV_SPAWN_HELPER";
    const ENV_SPAWN_HELPER_SENTINEL: &str = "env-spawn-helper-passed";
    const ENV_SPAWN_TEST_NAME: &str =
        "session::tests::test_concurrent_pty_spawns_with_env_while_env_changes";

    #[test]
    fn test_spawn_reaps_adopted_descendant() {
        if std::env::var_os(REAP_HELPER_ENV).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("session reap test runtime");
            runtime.block_on(run_adopted_descendant_scenario());
            println!("{REAP_HELPER_SENTINEL}");
            return;
        }

        let mut helper = StdCommand::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", REAP_TEST_NAME, "--nocapture"])
            .env(REAP_HELPER_ENV, "1")
            .stdout(StdStdio::piped())
            .spawn()
            .expect("spawn isolated session reap test");
        let mut output = String::new();
        helper
            .stdout
            .take()
            .expect("helper stdout")
            .read_to_string(&mut output)
            .expect("read helper stdout");

        match helper.wait() {
            Ok(status) => assert!(status.success(), "helper failed: {status}\n{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for helper: {error}"),
        }
        assert!(
            output.contains(REAP_HELPER_SENTINEL),
            "helper did not complete the session reap scenario:\n{output}"
        );
    }

    async fn run_adopted_descendant_scenario() {
        let ret = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };
        assert_eq!(
            ret,
            0,
            "set child subreaper: {}",
            std::io::Error::last_os_error()
        );

        let (tx, mut rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "sleep 30 & echo $!".to_string()],
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let session = ExecSession::spawn(17, &req, tx, None, SecurityProfile::Default)
            .expect("spawn background descendant session");
        let leader_pid = session.pid() as i32;
        let mut stdout = Vec::new();
        time::timeout(Duration::from_secs(10), async {
            while !stdout.contains(&b'\n') {
                let (id, output) = rx.recv().await.expect("session output");
                assert_eq!(id, 17);
                match output {
                    SessionOutput::Stdout(data) => stdout.extend_from_slice(&data),
                    SessionOutput::Exited(code) => panic!("session exited early with {code}"),
                    SessionOutput::Stderr(_) | SessionOutput::Raw(_) => {}
                }
            }
        })
        .await
        .expect("wait for background descendant session");

        let descendant_pid: i32 = String::from_utf8(stdout)
            .expect("descendant PID is UTF-8")
            .trim()
            .parse()
            .expect("parse descendant PID");
        let expected_parent = std::process::id().to_string();
        let status_path = format!("/proc/{descendant_pid}/status");
        time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(status) = std::fs::read_to_string(&status_path)
                    && status
                        .lines()
                        .find_map(|line| line.strip_prefix("PPid:"))
                        .is_some_and(|ppid| ppid.trim() == expected_parent)
                {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("descendant should be adopted by the helper subreaper");

        let leader_path = format!("/proc/{leader_pid}");
        time::timeout(Duration::from_secs(5), async {
            while std::path::Path::new(&leader_path).exists() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("direct child should be reaped before signalling its descendants");

        session
            .send_signal(libc::SIGTERM)
            .expect("signal descendants through completed process registration");
        let exit = time::timeout(Duration::from_secs(5), async {
            loop {
                let (id, output) = rx.recv().await.expect("session output after signal");
                assert_eq!(id, 17);
                if let SessionOutput::Exited(code) = output {
                    break code;
                }
            }
        })
        .await
        .expect("session should finish after its descendant is signalled");
        assert_eq!(exit, 0);

        let proc_path = format!("/proc/{descendant_pid}");
        time::timeout(Duration::from_secs(5), async {
            while std::path::Path::new(&proc_path).exists() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("descendant should be reaped");

        let ret = unsafe { libc::waitpid(descendant_pid, ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(ret, -1, "descendant {descendant_pid} was not reaped");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn test_concurrent_spawn_exit_codes() {
        if std::env::var_os(CONCURRENT_HELPER_ENV).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("concurrent spawn test runtime");
            runtime.block_on(run_concurrent_spawn_scenario());
            println!("{CONCURRENT_HELPER_SENTINEL}");
            return;
        }

        let mut helper = StdCommand::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", CONCURRENT_TEST_NAME, "--nocapture"])
            .env(CONCURRENT_HELPER_ENV, "1")
            .stdout(StdStdio::piped())
            .spawn()
            .expect("spawn isolated concurrent session test");
        let mut output = String::new();
        helper
            .stdout
            .take()
            .expect("helper stdout")
            .read_to_string(&mut output)
            .expect("read helper stdout");

        match helper.wait() {
            Ok(status) => assert!(status.success(), "helper failed: {status}\n{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for helper: {error}"),
        }
        assert!(
            output.contains(CONCURRENT_HELPER_SENTINEL),
            "helper did not complete the concurrent spawn scenario:\n{output}"
        );
    }

    async fn run_concurrent_spawn_scenario() {
        const PROCESS_COUNT: u32 = 12;

        let runtime_handle = tokio::runtime::Handle::current();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut spawn_threads = Vec::new();
        for offset in 0..PROCESS_COUNT {
            let handle = runtime_handle.clone();
            let tx = tx.clone();
            spawn_threads.push(std::thread::spawn(move || {
                let _runtime = handle.enter();
                let code = 20 + offset as i32;
                let req = ExecRequest {
                    cmd: "/bin/sh".to_string(),
                    args: vec!["-c".to_string(), format!("exit {code}")],
                    env: Vec::new(),
                    cwd: None,
                    user: None,
                    tty: offset % 2 == 1,
                    rows: 24,
                    cols: 80,
                    rlimits: Vec::new(),
                };
                ExecSession::spawn(100 + offset, &req, tx, None, SecurityProfile::Default)
            }));
        }
        drop(tx);

        let mut sessions = Vec::new();
        for thread in spawn_threads {
            sessions.push(
                thread
                    .join()
                    .expect("concurrent spawn thread")
                    .expect("concurrent process spawn"),
            );
        }

        let mut exits = HashMap::new();
        time::timeout(Duration::from_secs(15), async {
            while exits.len() < PROCESS_COUNT as usize {
                let (id, output) = rx.recv().await.expect("session output");
                if let SessionOutput::Exited(code) = output {
                    exits.insert(id, code);
                }
            }
        })
        .await
        .expect("wait for concurrent exits");

        for offset in 0..PROCESS_COUNT {
            assert_eq!(exits.get(&(100 + offset)), Some(&(20 + offset as i32)));
        }
        drop(sessions);
    }

    #[test]
    fn test_spawn_survives_runtime_replacement() {
        if std::env::var_os(RUNTIME_HELPER_ENV).is_some() {
            run_runtime_replacement_scenario();
            println!("{RUNTIME_HELPER_SENTINEL}");
            return;
        }

        let mut helper = StdCommand::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", RUNTIME_TEST_NAME, "--nocapture"])
            .env(RUNTIME_HELPER_ENV, "1")
            .stdout(StdStdio::piped())
            .spawn()
            .expect("spawn isolated runtime replacement test");
        let mut output = String::new();
        helper
            .stdout
            .take()
            .expect("helper stdout")
            .read_to_string(&mut output)
            .expect("read helper stdout");

        match helper.wait() {
            Ok(status) => assert!(status.success(), "helper failed: {status}\n{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for helper: {error}"),
        }
        assert!(
            output.contains(RUNTIME_HELPER_SENTINEL),
            "helper did not complete the runtime replacement scenario:\n{output}"
        );
    }

    fn run_runtime_replacement_scenario() {
        for (id, code) in [(201, 51), (202, 52)] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("replacement test runtime");
            runtime.block_on(run_single_pipe_spawn(id, code));
        }
    }

    async fn run_single_pipe_spawn(id: u32, code: i32) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), format!("exit {code}")],
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let _session = ExecSession::spawn(id, &req, tx, None, SecurityProfile::Default)
            .expect("spawn session on replacement runtime");

        let actual = time::timeout(Duration::from_secs(5), async {
            loop {
                let (actual_id, output) = rx.recv().await.expect("session output");
                assert_eq!(actual_id, id);
                if let SessionOutput::Exited(actual) = output {
                    break actual;
                }
            }
        })
        .await
        .expect("wait for exit on replacement runtime");
        assert_eq!(actual, code);
    }

    #[test]
    fn test_piped_process_exit_outlives_spawning_runtime() {
        if std::env::var_os(PIPE_OWNER_HELPER_ENV).is_some() {
            run_piped_process_exit_scenario();
            println!("{PIPE_OWNER_HELPER_SENTINEL}");
            return;
        }

        let mut helper = StdCommand::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", PIPE_OWNER_TEST_NAME, "--nocapture"])
            .env(PIPE_OWNER_HELPER_ENV, "1")
            .stdout(StdStdio::piped())
            .spawn()
            .expect("spawn isolated pipe owner test");
        let mut output = String::new();
        helper
            .stdout
            .take()
            .expect("helper stdout")
            .read_to_string(&mut output)
            .expect("read helper stdout");

        match helper.wait() {
            Ok(status) => assert!(status.success(), "helper failed: {status}\n{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for helper: {error}"),
        }
        assert!(
            output.contains(PIPE_OWNER_HELPER_SENTINEL),
            "helper did not complete the pipe owner scenario:\n{output}"
        );
    }

    fn run_piped_process_exit_scenario() {
        let process_manager = ProcessManager::get().expect("get process manager");
        let spawning_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("spawning runtime");
        let exit_watcher = {
            let _runtime_guard = spawning_runtime.enter();
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "exit 63"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let command = ExecCommand {
                command,
                setup: SetupReport::new(Vec::new()).expect("setup report pipe"),
            };
            let process = spawn_process(command, &process_manager).expect("spawn piped process");
            let SpawnedProcess { exit_watcher, .. } = process;
            exit_watcher
        };
        drop(spawning_runtime);

        let waiting_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("waiting runtime");
        let code = waiting_runtime.block_on(async {
            time::timeout(Duration::from_secs(5), exit_watcher)
                .await
                .expect("wait for piped process exit")
        });
        assert_eq!(code, 63);
    }

    #[tokio::test]
    async fn test_pty_reader_drains_ready_fd() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "i=0; while [ $i -lt 256 ]; do printf AAAA; i=$((i+1)); done; printf SECOND; sleep 0.1; printf '<END>\\n'; sleep 0.1; exit 0"
                    .to_string(),
            ],
            env: vec!["PATH=/usr/local/bin:/usr/bin:/bin".to_string()],
            cwd: None,
            user: None,
            tty: true,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let session = ExecSession::spawn(7, &req, tx, None, SecurityProfile::Default)
            .expect("spawn pty session");
        let mut stdout = Vec::new();
        let mut exit = None;

        let recv_result = time::timeout(Duration::from_secs(15), async {
            while let Some((id, output)) = rx.recv().await {
                assert_eq!(id, 7);
                match output {
                    SessionOutput::Stdout(data) => stdout.extend_from_slice(&data),
                    SessionOutput::Exited(code) => {
                        exit = Some(code);
                        break;
                    }
                    SessionOutput::Stderr(_) | SessionOutput::Raw(_) => {}
                }
            }
        })
        .await;

        if recv_result.is_err() {
            let _ = session.send_signal(libc::SIGKILL);
            panic!("timed out waiting for PTY output");
        }

        assert_eq!(exit, Some(0));

        let second = stdout
            .windows(b"SECOND".len())
            .position(|window| window == b"SECOND");
        let end = stdout
            .windows(b"<END>".len())
            .position(|window| window == b"<END>");

        assert!(
            matches!((second, end), (Some(second), Some(end)) if second < end),
            "expected immediate PTY write to arrive before later output; got {:?}",
            String::from_utf8_lossy(&stdout),
        );
    }

    #[test]
    fn test_resolve_user_spec_for_current_uid_gid() {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let resolved = resolve_user_spec(&format!("{uid}:{gid}")).expect("resolve numeric user");
        assert_eq!(resolved.uid, uid);
        assert_eq!(resolved.gid, gid);
    }

    #[test]
    fn test_request_user_overrides_config_default() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: Some("1:1".to_string()),
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let resolved = resolve_requested_user(&req, Some("0:0")).expect("resolve requested user");
        assert_eq!(resolved.unwrap().uid, 1);
    }

    #[test]
    fn test_config_default_user_used_when_request_has_none() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let resolved = resolve_requested_user(&req, Some(&format!("{uid}:{gid}")))
            .expect("resolve with config default");
        let resolved = resolved.expect("should resolve to a user");
        assert_eq!(resolved.uid, uid);
        assert_eq!(resolved.gid, gid);
    }

    #[test]
    fn test_request_without_user_does_not_apply_user_switch() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let resolved = resolve_requested_user(&req, None).expect("resolve absent user");
        assert!(resolved.is_none());
    }

    #[test]
    fn test_default_user_absent_resolves_to_root() {
        let resolved = resolve_default_user(None).expect("resolve absent default user");
        assert_eq!(resolved, (0, 0));
    }

    #[test]
    fn test_default_home_dir_uses_resolved_user_home() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let user = ResolvedUser {
            uid: 1000,
            gid: 1000,
            name: None,
            groups: Vec::new(),
            home_dir: Some(CString::new("/home/tester").unwrap()),
        };

        assert_eq!(
            default_home_dir(&req, Some(&user))
                .expect("resolve default home")
                .as_deref()
                .map(CStr::to_string_lossy),
            Some("/home/tester".into()),
        );
    }

    #[test]
    fn test_default_home_dir_uses_root_when_user_absent() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let root = resolve_user_spec(DEFAULT_USER_SPEC).expect("resolve implicit root");

        assert_eq!(
            default_home_dir(&req, None)
                .expect("resolve default home")
                .as_deref()
                .map(CStr::to_string_lossy),
            root.home_dir.as_deref().map(CStr::to_string_lossy),
        );
    }

    #[test]
    fn test_default_home_dir_respects_explicit_home_env() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: vec!["HOME=/tmp/custom".to_string()],
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let user = ResolvedUser {
            uid: 1000,
            gid: 1000,
            name: None,
            groups: Vec::new(),
            home_dir: Some(CString::new("/home/tester").unwrap()),
        };

        assert!(
            default_home_dir(&req, Some(&user))
                .expect("resolve default home")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_spawn_pipe_error_does_not_include_probe_details() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/definitely/not/a/real/binary".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        // Use the process-wide manager because other tests may have already
        // started its reaper thread. A private manager cannot guard this spawn
        // from the global `waitpid(-1, ...)` owner.
        let process_manager = ProcessManager::get().expect("get process manager");
        let err = ExecSession::spawn_pipe(
            9,
            &req,
            tx,
            None,
            SecurityProfile::Default,
            &process_manager,
        )
        .expect_err("spawn should fail");

        // Spawn failures now produce the typed `ExecSpawnFailed` so
        // the host can render a useful message + hint. The classifier
        // maps ENOENT on the binary path to `NotFound`.
        let payload = match &err {
            AgentdError::ExecSpawnFailed(p) => p,
            other => panic!("expected ExecSpawnFailed, got: {other:?}"),
        };
        assert_eq!(payload.kind, ExecFailureKind::NotFound);
        assert_eq!(payload.errno, Some(libc::ENOENT));
        assert_eq!(payload.errno_name.as_deref(), Some("ENOENT"));

        // The original intent of the test: probe internals leak into
        // the error message. The format is now
        // `spawn "<cmd>": <io::Error>` from
        // `exec_failed_from_io_error`. Verify that none of the old
        // probe-detail keys snuck back into the message.
        let message = &payload.message;
        assert!(message.contains("spawn"));
        assert!(!message.contains("symlink_metadata="));
        assert!(!message.contains("metadata="));
        assert!(!message.contains("magic="));
        assert!(!message.contains("path_probe="));
        assert!(!message.contains("cwd_probe="));
        assert!(!message.contains("target_probe="));
    }

    /// Spawns PTY sessions carrying env vars from several threads while
    /// another thread keeps rewriting the process environment. A child that
    /// runs `setenv` between fork and exec deadlocks once it is forked while
    /// the writer holds libc's environment lock; the helper's own deadline
    /// turns that hang into a failure.
    #[test]
    fn test_concurrent_pty_spawns_with_env_while_env_changes() {
        if std::env::var_os(ENV_SPAWN_HELPER_ENV).is_some() {
            run_concurrent_env_spawn_scenario();
            println!("{ENV_SPAWN_HELPER_SENTINEL}");
            return;
        }

        let mut helper = StdCommand::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", ENV_SPAWN_TEST_NAME, "--nocapture"])
            .env(ENV_SPAWN_HELPER_ENV, "1")
            .stdout(StdStdio::piped())
            .spawn()
            .expect("spawn isolated env spawn test");
        let mut output = String::new();
        helper
            .stdout
            .take()
            .expect("helper stdout")
            .read_to_string(&mut output)
            .expect("read helper stdout");

        match helper.wait() {
            Ok(status) => assert!(status.success(), "helper failed: {status}\n{output}"),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => panic!("wait for helper: {error}"),
        }
        assert!(
            output.contains(ENV_SPAWN_HELPER_SENTINEL),
            "helper did not complete the env spawn scenario:\n{output}"
        );
    }

    fn run_concurrent_env_spawn_scenario() {
        const SPAWN_THREADS: u32 = 8;
        const SPAWNS_PER_THREAD: u32 = 25;
        const SESSION_COUNT: usize = (SPAWN_THREADS * SPAWNS_PER_THREAD) as usize;
        const EXPECTED_EXIT: i32 = 23;
        const DEADLINE: Duration = Duration::from_secs(60);
        const ENV_WRITER_VAR: &str = "MSB_AGENTD_ENV_WRITER";

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("env spawn test runtime");
        let stop_writer = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let stop_writer = Arc::clone(&stop_writer);
            std::thread::spawn(move || {
                let mut round = 0u64;
                while !stop_writer.load(std::sync::atomic::Ordering::Relaxed) {
                    // SAFETY: the spawn path reads the environment through
                    // std's Command, which holds std's env lock across fork;
                    // libc's own readers in this helper (NSS lookups) only
                    // ever see a complete environ array.
                    unsafe { std::env::set_var(ENV_WRITER_VAR, round.to_string()) };
                    round += 1;
                }
            })
        };

        let (tx, mut rx) = mpsc::unbounded_channel();
        let (sessions_tx, sessions_rx) = std::sync::mpsc::channel();
        for thread in 0..SPAWN_THREADS {
            let handle = runtime.handle().clone();
            let tx = tx.clone();
            let sessions_tx = sessions_tx.clone();
            std::thread::spawn(move || {
                let _runtime = handle.enter();
                for n in 0..SPAWNS_PER_THREAD {
                    let id = thread * SPAWNS_PER_THREAD + n;
                    let req = ExecRequest {
                        cmd: "/bin/sh".to_string(),
                        args: vec![
                            "-c".to_string(),
                            format!("[ \"$SPAWN_MARK\" = mark-{id} ] && exit {EXPECTED_EXIT}"),
                        ],
                        env: vec![format!("SPAWN_MARK=mark-{id}")],
                        cwd: None,
                        user: None,
                        tty: true,
                        rows: 24,
                        cols: 80,
                        rlimits: Vec::new(),
                    };
                    let session =
                        ExecSession::spawn(id, &req, tx.clone(), None, SecurityProfile::Default)
                            .expect("spawn PTY session with env");
                    if sessions_tx.send(session).is_err() {
                        return;
                    }
                }
            });
        }
        drop(tx);
        drop(sessions_tx);

        let exits = runtime.block_on(async {
            time::timeout(DEADLINE, async {
                let mut exits = HashMap::new();
                while exits.len() < SESSION_COUNT {
                    let (id, output) = rx.recv().await.expect("session output");
                    if let SessionOutput::Exited(code) = output {
                        exits.insert(id, code);
                    }
                }
                exits
            })
            .await
        });
        let Ok(exits) = exits else {
            // A deadlocked child pins its spawning thread and the runtime's
            // PTY readers, so neither can be joined: leave without unwinding.
            eprintln!("PTY spawns with env did not all finish within {DEADLINE:?}");
            std::process::exit(1);
        };
        stop_writer.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().expect("env writer thread");

        for id in 0..SESSION_COUNT as u32 {
            assert_eq!(exits.get(&id), Some(&EXPECTED_EXIT), "session {id}");
        }
        drop(sessions_rx.into_iter().collect::<Vec<_>>());
        drop(runtime);
    }

    /// A session's PTY fds stay out of every other session's children, in
    /// both exec modes.
    #[tokio::test]
    async fn test_exec_session_does_not_inherit_other_session_pty_fds() {
        const HOLDER_ID: u32 = 40;
        const DEADLINE: Duration = Duration::from_secs(15);

        // Terminal fds this test process may itself have inherited from its
        // launcher reach every child; only more than those is a leak.
        let baseline_terminals = terminal_fds_above_stdio(&list_child_fds(39, false).await);

        let (holder_tx, mut holder_rx) = mpsc::unbounded_channel();
        let holder_req = ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "tty; read _".to_string()],
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: true,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let holder = KillOnDrop(
            ExecSession::spawn(
                HOLDER_ID,
                &holder_req,
                holder_tx,
                None,
                SecurityProfile::Default,
            )
            .expect("spawn PTY holder session"),
        );
        let mut holder_out = Vec::new();
        time::timeout(DEADLINE, async {
            while !holder_out.contains(&b'\n') {
                match holder_rx.recv().await.expect("holder output") {
                    (_, SessionOutput::Stdout(data)) => holder_out.extend_from_slice(&data),
                    (_, SessionOutput::Exited(code)) => panic!("holder exited with {code}"),
                    _ => {}
                }
            }
        })
        .await
        .expect("holder prints its terminal");
        let holder_tty = String::from_utf8(holder_out).expect("holder tty is UTF-8");
        let holder_tty = holder_tty.trim().to_string();
        assert!(
            holder_tty.starts_with("/dev/pts/"),
            "holder terminal: {holder_tty:?}"
        );

        for (id, tty) in [(41, true), (42, false)] {
            let fds = list_child_fds(id, tty).await;
            for (fd, target) in &fds {
                assert_ne!(
                    target, &holder_tty,
                    "tty={tty}: fd {fd} is the holder's slave"
                );
            }
            assert!(
                terminal_fds_above_stdio(&fds) <= baseline_terminals,
                "tty={tty}: terminal fds leaked beyond the {baseline_terminals} this process \
                 already passes on: {fds:?}"
            );
        }

        holder
            .0
            .send_signal(libc::SIGKILL)
            .expect("kill holder session");
        time::timeout(DEADLINE, async {
            while !matches!(
                holder_rx.recv().await.expect("holder output"),
                (_, SessionOutput::Exited(_))
            ) {}
        })
        .await
        .expect("holder exits");
    }

    #[test]
    fn test_resolved_user_groups_include_primary_group() {
        let uid = unsafe { libc::getuid() };
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: Some(uid.to_string()),
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let resolved = resolve_requested_user(&req, None)
            .expect("resolve current user")
            .expect("a requested user");
        assert!(
            resolved.groups.contains(&resolved.gid),
            "groups {:?} lack {}",
            resolved.groups,
            resolved.gid
        );
    }

    /// A PTY session with a missing working directory fails to spawn, as a
    /// pipe session does, instead of running in agentd's directory.
    #[tokio::test]
    async fn test_spawn_pty_rejects_missing_cwd() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: Some("/definitely/not/a/real/dir".to_string()),
            user: None,
            tty: true,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let err = ExecSession::spawn(43, &req, tx, None, SecurityProfile::Default)
            .expect_err("spawn with a missing cwd should fail");
        let AgentdError::ExecSpawnFailed(payload) = &err else {
            panic!("expected ExecSpawnFailed, got: {err:?}");
        };
        assert_eq!(payload.kind, ExecFailureKind::BadCwd);
        assert_eq!(payload.errno, Some(libc::ENOENT));
    }

    /// Spawns a pipe session for `req` and returns the `ExecFailed` it fails with.
    fn spawn_failure(id: u32, req: &ExecRequest) -> ExecFailed {
        let (tx, _rx) = mpsc::unbounded_channel();
        let err = ExecSession::spawn(id, req, tx, None, SecurityProfile::Default)
            .expect_err("spawn should fail");
        match err {
            AgentdError::ExecSpawnFailed(payload) => payload,
            other => panic!("expected ExecSpawnFailed, got: {other:?}"),
        }
    }

    fn true_request() -> ExecRequest {
        ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        }
    }

    /// A user switch the kernel refuses is a user setup failure naming the
    /// step, not a binary lacking its execute bit. More supplementary groups
    /// than `NGROUPS_MAX` fail `setgroups` with or without privilege: EPERM
    /// unprivileged, EINVAL as root.
    #[tokio::test]
    async fn test_user_switch_failure_names_step() {
        const NGROUPS_MAX: usize = 65536;
        let user = ResolvedUser {
            uid: 54321,
            gid: 54321,
            name: None,
            groups: vec![54321; NGROUPS_MAX + 1],
            home_dir: None,
        };
        let command = build_command(
            &true_request(),
            Some(user),
            None,
            SecurityProfile::Default,
            ChildTerminal::None,
        )
        .expect("build command");
        let process_manager = ProcessManager::get().expect("get process manager");
        let err = spawn_process(command, &process_manager)
            .err()
            .expect("the user switch should fail");
        let AgentdError::ExecSpawnFailed(payload) = &err else {
            panic!("expected ExecSpawnFailed, got: {err:?}");
        };

        assert_eq!(payload.kind, ExecFailureKind::UserSetupFailed);
        assert_eq!(payload.stage.as_deref(), Some("setgroups"));
        assert!(
            matches!(payload.errno, Some(libc::EPERM | libc::EINVAL)),
            "errno {:?}",
            payload.errno
        );
        assert!(
            payload.message.contains("setgroups failed"),
            "{}",
            payload.message
        );
    }

    /// A rejected rlimit is a resource limit failure naming the resource.
    #[tokio::test]
    async fn test_rlimit_failure_names_resource() {
        let mut req = true_request();
        // A soft limit above the hard limit is EINVAL for every caller.
        req.rlimits = vec![ExecRlimit {
            resource: "nofile".to_string(),
            soft: 64,
            hard: 32,
        }];

        let payload = spawn_failure(44, &req);

        assert_eq!(payload.kind, ExecFailureKind::ResourceLimit);
        assert_eq!(payload.stage.as_deref(), Some("setrlimit(RLIMIT_NOFILE)"));
        assert_eq!(payload.errno, Some(libc::EINVAL));
    }

    /// A file without its execute bit is still a permission failure of the
    /// binary: no setup step failed.
    #[tokio::test]
    async fn test_non_executable_file_is_permission_denied() {
        let path = std::env::temp_dir().join(format!(
            "agentd-not-executable-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, "#!/bin/sh\n").expect("write script");
        let mut req = true_request();
        req.cmd = path.to_string_lossy().into_owned();

        let payload = spawn_failure(45, &req);
        std::fs::remove_file(&path).expect("remove script");

        assert_eq!(payload.kind, ExecFailureKind::PermissionDenied);
        assert_eq!(payload.stage.as_deref(), Some("Command::spawn"));
        assert_eq!(payload.errno, Some(libc::EACCES));
    }

    /// Runs a shell session that lists its own open fds as `(fd, target)`.
    async fn list_child_fds(id: u32, tty: bool) -> Vec<(u32, String)> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                r#"for f in /proc/$$/fd/*; do echo "${f##*/} $(readlink "$f")"; done"#.to_string(),
            ],
            env: Vec::new(),
            cwd: None,
            user: None,
            tty,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let _session = ExecSession::spawn(id, &req, tx, None, SecurityProfile::Default)
            .expect("spawn fd listing session");
        let mut listing = Vec::new();
        let code = time::timeout(Duration::from_secs(15), async {
            loop {
                match rx.recv().await.expect("listing output") {
                    (_, SessionOutput::Stdout(data)) => listing.extend_from_slice(&data),
                    (_, SessionOutput::Exited(code)) => break code,
                    _ => {}
                }
            }
        })
        .await
        .expect("fd listing session exits");
        assert_eq!(code, 0);

        let listing = String::from_utf8(listing).expect("fd listing is UTF-8");
        let fds: Vec<(u32, String)> = listing
            .lines()
            .filter_map(|line| {
                let (fd, target) = line.trim_end_matches('\r').split_once(' ')?;
                Some((fd.parse().ok()?, target.to_string()))
            })
            .collect();
        assert!(
            fds.iter().any(|&(fd, _)| fd == 0),
            "tty={tty}: no fd listing:\n{listing}"
        );
        fds
    }

    /// Counts the fds above stdio that point at a terminal.
    fn terminal_fds_above_stdio(fds: &[(u32, String)]) -> usize {
        fds.iter()
            .filter(|(fd, target)| {
                *fd > 2 && (target == "/dev/ptmx" || target.starts_with("/dev/pts/"))
            })
            .count()
    }

    /// Kills a session's process group when a failing test unwinds, so the
    /// runtime's PTY reader sees EOF and the runtime can shut down.
    struct KillOnDrop(ExecSession);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.send_signal(libc::SIGKILL);
        }
    }
}
