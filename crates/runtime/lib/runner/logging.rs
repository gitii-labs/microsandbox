//! Log file management with rotation for capturing VM console output.
//!
//! A rotating log keeps its live file and the numbered chain `<file>.1` to
//! `<file>.4`, which SDK log readers walk. When the chain is full, the oldest
//! numbered file is moved to a timestamped archive (`<file>.<UTC timestamp>`)
//! instead of being overwritten, and a background thread compresses archives to
//! `<file>.<UTC timestamp>.gz`. microsandbox never deletes archives; the embedder
//! owns their retention.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    thread::JoinHandle,
};

use chrono::{DateTime, NaiveDateTime, Utc};
use flate2::{Compression, write::GzEncoder};

use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Highest numbered file that is shifted to the next index during rotation.
///
/// Rotation produces `<file>.1` to `<file>.{MAX_ROTATED_FILES + 1}`. SDK log
/// readers walk exactly this chain, so the count is part of the reader contract.
const MAX_ROTATED_FILES: u32 = 3;

/// Index of the oldest numbered file. It is archived instead of overwritten.
const OLDEST_ROTATED_INDEX: u32 = MAX_ROTATED_FILES + 1;

/// UTC timestamp format embedded in archive names, e.g. `20261018T143005Z`.
const ARCHIVE_TIMESTAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Extension of a compressed archive.
const COMPRESSED_EXTENSION: &str = "gz";

/// Extension of a compressed archive that is still being written.
const PARTIAL_EXTENSION: &str = "partial";

/// Name of the log file the kernel console writes. libkrun truncates it when
/// it opens the console at VM start.
pub(crate) const KERNEL_LOG_FILENAME: &str = "kernel.log";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A simple rotating log writer.
///
/// Writes to a log file and rotates when the file exceeds `max_bytes`.
/// Rotated files are renamed with a numeric suffix (e.g., `vm.log.1`). The
/// oldest numbered file is archived and compressed instead of overwritten.
pub struct RotatingLog {
    /// Directory holding the log file and its rotated siblings.
    log_dir: PathBuf,

    /// File name of the current log file.
    file_name: String,

    /// Path to the current log file.
    path: PathBuf,

    /// Open file handle for writing.
    file: File,

    /// Maximum file size in bytes before rotation.
    max_bytes: u64,

    /// Bytes written to the current file since it was opened or rotation was last attempted.
    written: u64,

    /// Background compression of this log's archives.
    archiver: LogArchiver,

    /// Whether the last rotation failed; only the first failure in a row is reported.
    rotation_failed: bool,
}

/// Background thread that compresses the archives of one log file.
///
/// Requests are coalesced: each pass compresses every uncompressed archive in
/// the directory, including archives left behind by an interrupted process.
/// Dropping the archiver lets the thread finish queued work and exit.
pub(crate) struct LogArchiver {
    /// Request channel; `None` when the worker thread could not be started.
    sender: Option<mpsc::Sender<ArchiverRequest>>,

    /// Worker thread handle, joined only by tests.
    #[cfg_attr(not(test), allow(dead_code))]
    worker: Option<JoinHandle<()>>,
}

/// Work for a [`LogArchiver`] thread.
enum ArchiverRequest {
    /// Compress every uncompressed archive.
    Compress,

    /// Report a failure from the writing thread.
    Warn(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RotatingLog {
    /// Create a new rotating log writer.
    ///
    /// The log file is created at `<log_dir>/<prefix>.log`. Archives left
    /// uncompressed by a previous process are compressed in the background.
    pub fn new(log_dir: &Path, prefix: &str, max_bytes: u64) -> RuntimeResult<Self> {
        fs::create_dir_all(log_dir)?;

        let file_name = format!("{prefix}.log");
        let path = log_dir.join(&file_name);
        let written = path.metadata().map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let archiver = LogArchiver::start(log_dir, &file_name);

        Ok(Self {
            log_dir: log_dir.to_path_buf(),
            file_name,
            path,
            file,
            max_bytes,
            written,
            archiver,
            rotation_failed: false,
        })
    }

    /// Write data to the log file, rotating if necessary.
    ///
    /// A failed rotation does not drop data: the data is appended to the
    /// current file, the failure is reported through the archiver thread, and
    /// rotation is retried after another `max_bytes`.
    pub fn write(&mut self, data: &[u8]) -> RuntimeResult<()> {
        if self.written + data.len() as u64 > self.max_bytes {
            match self.rotate() {
                Ok(()) => self.rotation_failed = false,
                Err(error) => {
                    if !self.rotation_failed {
                        self.archiver.warn(format!(
                            "failed to rotate {}; appending to the current file: {error}",
                            self.path.display()
                        ));
                    }
                    self.rotation_failed = true;
                    // Retry after another full file instead of on every write.
                    self.written = 0;
                }
            }
        }

        self.file.write_all(data)?;
        self.written += data.len() as u64;
        Ok(())
    }

    /// Flush the log file.
    pub fn flush(&mut self) -> RuntimeResult<()> {
        self.file.flush()?;
        Ok(())
    }
}

impl LogArchiver {
    /// Start the archiver thread for `<log_dir>/<file_name>` and queue one
    /// pass for archives left by a previous process.
    ///
    /// When the thread cannot be started, archives stay uncompressed.
    pub(crate) fn start(log_dir: &Path, file_name: &str) -> Self {
        let (sender, receiver) = mpsc::channel();
        let log_dir = log_dir.to_path_buf();
        let worker_file_name = file_name.to_string();
        let worker = std::thread::Builder::new()
            .name(format!("log-archive-{file_name}"))
            .spawn(move || run_archiver(&log_dir, &worker_file_name, &receiver));
        match worker {
            Ok(worker) => {
                let archiver = Self {
                    sender: Some(sender),
                    worker: Some(worker),
                };
                archiver.compress();
                archiver
            }
            Err(error) => {
                tracing::warn!(
                    file = file_name,
                    %error,
                    "failed to start the log archive thread; archives stay uncompressed"
                );
                Self {
                    sender: None,
                    worker: None,
                }
            }
        }
    }

    /// Request a compression pass.
    pub(crate) fn compress(&self) {
        self.send(ArchiverRequest::Compress);
    }

    /// Report a failure through the archiver thread.
    ///
    /// The thread writing `runtime.log` drains the runtime's stderr. It must not
    /// log through `tracing` itself, or it could block on its own pipe.
    fn warn(&self, message: String) {
        self.send(ArchiverRequest::Warn(message));
    }

    fn send(&self, request: ArchiverRequest) {
        if let Some(sender) = &self.sender {
            // The worker only exits after this sender is dropped, so sending cannot fail.
            let _ = sender.send(request);
        }
    }

    /// Stop accepting requests and wait for queued work to finish.
    #[cfg(test)]
    fn finish(mut self) {
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Helpers
//--------------------------------------------------------------------------------------------------

impl RotatingLog {
    fn rotate(&mut self) -> RuntimeResult<()> {
        self.file.flush()?;

        // Move the oldest numbered file out of the chain before it would be overwritten.
        let oldest = rotated_path(&self.path, OLDEST_ROTATED_INDEX);
        let archived = archive_file(&self.log_dir, &self.file_name, &oldest, Utc::now())?;

        // Shift existing rotated files: .log.3 → .log.4, .log.2 → .log.3, etc.
        // Each target was vacated by the previous step, so no rename overwrites data.
        for i in (1..=MAX_ROTATED_FILES).rev() {
            let from = rotated_path(&self.path, i);
            let to = rotated_path(&self.path, i + 1);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }

        // Rename current log to .log.1
        fs::rename(&self.path, rotated_path(&self.path, 1))?;

        // Open a fresh log file
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;

        if archived.is_some() {
            self.archiver.compress();
        }
        Ok(())
    }

    /// Stop the archiver and wait for queued compression.
    #[cfg(test)]
    fn finish(self) {
        self.archiver.finish();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Archive the previous `kernel.log` before libkrun opens and truncates it.
///
/// An empty or missing file is left alone. The returned archiver compresses
/// the archive, and any archive a previous process left uncompressed, in the
/// background; dropping it does not cancel that work.
pub(crate) fn archive_kernel_log(log_dir: &Path) -> io::Result<LogArchiver> {
    let path = log_dir.join(KERNEL_LOG_FILENAME);
    let has_content = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata.is_file() && metadata.len() > 0,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if has_content {
        archive_file(log_dir, KERNEL_LOG_FILENAME, &path, Utc::now())?;
    }
    Ok(LogArchiver::start(log_dir, KERNEL_LOG_FILENAME))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Path of the numbered rotation `index` of `path`.
fn rotated_path(path: &Path, index: u32) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

/// Move `source` to a new archive of `file_name` in `log_dir`.
///
/// Returns `None` when `source` does not exist. The archive name is
/// `<file_name>.<timestamp>`, with a `-<n>` suffix when that name, or its
/// compressed form, is already taken. One runtime owns a log directory at a
/// time and the archiver never creates uncompressed archive names, so the
/// existence check cannot race with another writer.
fn archive_file(
    log_dir: &Path,
    file_name: &str,
    source: &Path,
    now: DateTime<Utc>,
) -> io::Result<Option<PathBuf>> {
    if !path_exists(source)? {
        return Ok(None);
    }
    let target = unused_archive_path(log_dir, file_name, now)?;
    fs::rename(source, &target)?;
    Ok(Some(target))
}

/// Find an archive path of `file_name` that is not in use in either form.
fn unused_archive_path(log_dir: &Path, file_name: &str, now: DateTime<Utc>) -> io::Result<PathBuf> {
    let timestamp = now.format(ARCHIVE_TIMESTAMP_FORMAT).to_string();
    let mut attempt = 0u32;
    loop {
        let name = match attempt {
            0 => format!("{file_name}.{timestamp}"),
            n => format!("{file_name}.{timestamp}-{n}"),
        };
        let candidate = log_dir.join(name);
        if !path_exists(&candidate)? && !path_exists(&compressed_path(&candidate))? {
            return Ok(candidate);
        }
        attempt = attempt
            .checked_add(1)
            .ok_or_else(|| io::Error::other("no unused log archive name"))?;
    }
}

/// Whether `path` exists, without following a final symlink.
fn path_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether `name` is an uncompressed archive of `file_name`:
/// `<file_name>.<timestamp>` or `<file_name>.<timestamp>-<n>`.
fn is_uncompressed_archive(file_name: &str, name: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix(file_name)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let (timestamp, counter) = match suffix.split_once('-') {
        Some((timestamp, counter)) => (timestamp, Some(counter)),
        None => (suffix, None),
    };
    let counter_ok = counter
        .is_none_or(|counter| !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()));
    counter_ok && NaiveDateTime::parse_from_str(timestamp, ARCHIVE_TIMESTAMP_FORMAT).is_ok()
}

/// Path of the compressed form of `archive`.
fn compressed_path(archive: &Path) -> PathBuf {
    let mut name = archive.as_os_str().to_os_string();
    name.push(format!(".{COMPRESSED_EXTENSION}"));
    PathBuf::from(name)
}

/// Path of the in-progress compressed form of `archive`.
fn partial_path(archive: &Path) -> PathBuf {
    let mut name = compressed_path(archive).into_os_string();
    name.push(format!(".{PARTIAL_EXTENSION}"));
    PathBuf::from(name)
}

/// Archiver thread body: one compression pass per batch of requests.
fn run_archiver(log_dir: &Path, file_name: &str, receiver: &mpsc::Receiver<ArchiverRequest>) {
    while let Ok(request) = receiver.recv() {
        let mut compress = false;
        for request in std::iter::once(request).chain(receiver.try_iter()) {
            match request {
                ArchiverRequest::Compress => compress = true,
                ArchiverRequest::Warn(message) => tracing::warn!("{message}"),
            }
        }
        if compress {
            compress_archives(log_dir, file_name);
        }
    }
}

/// Compress every uncompressed archive of `file_name` in `log_dir`.
///
/// Failures are reported and leave the uncompressed archive in place.
fn compress_archives(log_dir: &Path, file_name: &str) {
    let entries = match fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(dir = %log_dir.display(), %error, "failed to list log archives");
            return;
        }
    };
    let mut archives: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| is_uncompressed_archive(file_name, name))
        })
        .map(|entry| entry.path())
        .collect();
    archives.sort();
    for archive in archives {
        if let Err(error) = compress_archive(&archive) {
            tracing::warn!(
                archive = %archive.display(),
                %error,
                "failed to compress log archive; keeping it uncompressed"
            );
            // The partial file is never published, so removing it loses nothing.
            let _ = fs::remove_file(partial_path(&archive));
        }
    }
}

/// Compress `archive` to `<archive>.gz` and remove `archive`.
///
/// The compressed data is written to `<archive>.gz.partial`, synced, and
/// renamed into place. The uncompressed archive is removed only afterwards.
/// The compressed file keeps the archive's modification time.
fn compress_archive(archive: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(archive)?;
    if !metadata.is_file() {
        return Err(io::Error::other("log archive is not a regular file"));
    }
    let compressed = compressed_path(archive);
    if fs::symlink_metadata(&compressed).is_ok_and(|m| m.is_file()) {
        // An earlier pass published the compressed file but was interrupted before removing
        // the source. Publication is synced first, so the compressed file is complete.
        return fs::remove_file(archive);
    }

    let partial = partial_path(archive);
    let mut source = File::open(archive)?;
    let output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&partial)?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    io::copy(&mut source, &mut encoder)?;
    let output = encoder.finish()?;
    output.set_modified(metadata.modified()?)?;
    output.sync_all()?;
    drop(output);

    fs::rename(&partial, &compressed)?;
    sync_parent_dir(archive)?;
    fs::remove_file(archive)
}

/// Make a rename in the parent directory of `path` durable.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) => File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

/// Windows cannot sync a directory handle opened through `std`.
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::time::{Duration, SystemTime};

    use chrono::TimeZone;
    use flate2::read::GzDecoder;

    use super::*;

    const LINE_BYTES: u64 = 10;

    /// Names in `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// Archives of `file_name` in `dir` that end in `extension` (empty for uncompressed).
    fn archives(dir: &Path, file_name: &str, extension: &str) -> Vec<PathBuf> {
        names(dir)
            .into_iter()
            .filter(|name| {
                name.strip_suffix(extension)
                    .is_some_and(|base| is_uncompressed_archive(file_name, base))
            })
            .map(|name| dir.join(name))
            .collect()
    }

    fn gunzip(path: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        GzDecoder::new(File::open(path).unwrap())
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// One fixed-size line per index, e.g. `line-0007\n`.
    fn line(index: usize) -> Vec<u8> {
        let line = format!("line-{index:04}\n").into_bytes();
        assert_eq!(line.len() as u64, LINE_BYTES);
        line
    }

    #[test]
    fn rotation_keeps_the_numbered_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::new(dir.path(), "exec", LINE_BYTES).unwrap();
        for index in 0..5 {
            log.write(&line(index)).unwrap();
        }
        log.finish();

        // Four rotations fill .1..=.4 exactly as before; nothing is archived yet.
        assert_eq!(
            names(dir.path()),
            [
                "exec.log",
                "exec.log.1",
                "exec.log.2",
                "exec.log.3",
                "exec.log.4"
            ]
        );
        assert_eq!(fs::read(dir.path().join("exec.log")).unwrap(), line(4));
        assert_eq!(fs::read(dir.path().join("exec.log.1")).unwrap(), line(3));
        assert_eq!(fs::read(dir.path().join("exec.log.4")).unwrap(), line(0));
    }

    #[test]
    fn rotation_past_the_chain_archives_and_compresses_the_oldest_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::new(dir.path(), "exec", LINE_BYTES).unwrap();
        // These rotations normally land in the same second, so archive names need suffixes.
        let total = 12;
        for index in 0..total {
            log.write(&line(index)).unwrap();
        }
        log.finish();

        // The chain matches the old behavior: newest in the live file, then .1..=.4.
        let live = dir.path().join("exec.log");
        assert_eq!(fs::read(&live).unwrap(), line(total - 1));
        for index in 1..=4 {
            assert_eq!(
                fs::read(rotated_path(&live, index as u32)).unwrap(),
                line(total - 1 - index)
            );
        }

        // Every file that left the chain is compressed and nothing was dropped.
        assert!(archives(dir.path(), "exec.log", "").is_empty());
        assert!(archives(dir.path(), "exec.log", ".gz.partial").is_empty());
        let compressed = archives(dir.path(), "exec.log", ".gz");
        assert_eq!(compressed.len(), total - 5);
        let mut archived: Vec<Vec<u8>> = compressed.iter().map(|path| gunzip(path)).collect();
        archived.sort();
        let expected: Vec<Vec<u8>> = (0..total - 5).map(line).collect();
        assert_eq!(archived, expected);
    }

    #[test]
    fn archive_names_never_collide_within_one_second() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc.with_ymd_and_hms(2026, 10, 18, 14, 30, 5).unwrap();
        let oldest = dir.path().join("exec.log.4");

        fs::write(&oldest, b"first").unwrap();
        let first = archive_file(dir.path(), "exec.log", &oldest, now)
            .unwrap()
            .unwrap();
        fs::write(&oldest, b"second").unwrap();
        let second = archive_file(dir.path(), "exec.log", &oldest, now)
            .unwrap()
            .unwrap();
        // A compressed archive still reserves its name.
        compress_archive(&second).unwrap();
        fs::write(&oldest, b"third").unwrap();
        let third = archive_file(dir.path(), "exec.log", &oldest, now)
            .unwrap()
            .unwrap();

        assert_eq!(first, dir.path().join("exec.log.20261018T143005Z"));
        assert_eq!(second, dir.path().join("exec.log.20261018T143005Z-1"));
        assert_eq!(third, dir.path().join("exec.log.20261018T143005Z-2"));
        assert_eq!(fs::read(&first).unwrap(), b"first");
        assert_eq!(gunzip(&compressed_path(&second)), b"second");
        assert_eq!(fs::read(&third).unwrap(), b"third");
    }

    #[test]
    fn archive_of_missing_file_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("exec.log.4");
        assert_eq!(
            archive_file(dir.path(), "exec.log", &missing, Utc::now()).unwrap(),
            None
        );
        assert!(names(dir.path()).is_empty());
    }

    #[test]
    fn compression_keeps_the_archive_modification_time() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("runtime.log.20261018T143005Z");
        fs::write(&archive, b"data").unwrap();
        let written = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        File::options()
            .write(true)
            .open(&archive)
            .unwrap()
            .set_modified(written)
            .unwrap();

        compress_archive(&archive).unwrap();

        let compressed = compressed_path(&archive);
        assert!(!archive.exists());
        assert_eq!(
            fs::metadata(&compressed).unwrap().modified().unwrap(),
            written
        );
        assert_eq!(gunzip(&compressed), b"data");
    }

    #[test]
    fn compression_failure_keeps_the_uncompressed_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("runtime.log.20261018T143005Z");
        fs::write(&archive, b"keep me").unwrap();
        // A non-empty directory in place of the partial file makes the output unwritable.
        let blocker = partial_path(&archive);
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("occupied"), b"").unwrap();

        compress_archives(dir.path(), "runtime.log");

        assert_eq!(fs::read(&archive).unwrap(), b"keep me");
        assert!(!compressed_path(&archive).exists());
    }

    #[test]
    fn interrupted_compression_is_finished_when_the_log_reopens() {
        let dir = tempfile::tempdir().unwrap();
        // Interrupted while writing: the archive and a stale partial file remain.
        let pending = dir.path().join("runtime.log.20261018T143005Z");
        fs::write(&pending, b"pending").unwrap();
        fs::write(partial_path(&pending), b"truncated").unwrap();
        // Interrupted after publication: the archive and its complete compressed form remain.
        let published = dir.path().join("runtime.log.20261018T143006Z");
        fs::write(&published, b"published").unwrap();
        compress_archive(&published).unwrap();
        fs::write(&published, b"published").unwrap();

        let mut log = RotatingLog::new(dir.path(), "runtime", 1024).unwrap();
        log.write(b"live\n").unwrap();
        log.finish();

        assert_eq!(gunzip(&compressed_path(&pending)), b"pending");
        assert!(!pending.exists());
        assert!(!partial_path(&pending).exists());
        assert_eq!(gunzip(&compressed_path(&published)), b"published");
        assert!(!published.exists());
    }

    #[test]
    fn archive_name_parsing_ignores_the_chain_and_other_files() {
        assert!(is_uncompressed_archive(
            "exec.log",
            "exec.log.20261018T143005Z"
        ));
        assert!(is_uncompressed_archive(
            "exec.log",
            "exec.log.20261018T143005Z-12"
        ));
        for name in [
            "exec.log",
            "exec.log.1",
            "exec.log.4",
            "exec.log.20261018T143005Z.gz",
            "exec.log.20261018T143005Z.gz.partial",
            "exec.log.20261018T143005Z-",
            "exec.log.20261318T143005Z",
            "runtime.log.20261018T143005Z",
            "boot-error.json",
        ] {
            assert!(!is_uncompressed_archive("exec.log", name), "{name}");
        }
    }

    #[test]
    fn kernel_log_is_archived_before_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join(KERNEL_LOG_FILENAME);
        fs::write(&kernel, b"previous boot\n").unwrap();

        archive_kernel_log(dir.path()).unwrap().finish();

        assert!(!kernel.exists());
        assert!(archives(dir.path(), KERNEL_LOG_FILENAME, "").is_empty());
        let compressed = archives(dir.path(), KERNEL_LOG_FILENAME, ".gz");
        assert_eq!(compressed.len(), 1);
        assert_eq!(gunzip(&compressed[0]), b"previous boot\n");
    }

    #[test]
    fn empty_kernel_log_is_not_archived() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(KERNEL_LOG_FILENAME), b"").unwrap();

        archive_kernel_log(dir.path()).unwrap().finish();

        assert_eq!(names(dir.path()), [KERNEL_LOG_FILENAME]);
    }
}
