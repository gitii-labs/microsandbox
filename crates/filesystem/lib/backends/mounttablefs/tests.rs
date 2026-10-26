//! Unit tests for the mount-table backend against real host directories.

use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};

use tempfile::TempDir;

use super::{MountTable, MountTableChild, MountTableFs, table};
use crate::{
    CachePolicy, Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, HostPermissions,
    OpenOptions, SetattrValid, StatVirtualization, ZeroCopyReader, ZeroCopyWriter, stat64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT: u64 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_EBADF: i32 = 9;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_EROFS: i32 = 30;
const LINUX_ENOSPC: i32 = 28;
const LINUX_ESTALE: i32 = 116;
const LINUX_O_WRONLY: u32 = 1;
const LINUX_O_RDWR: u32 = 2;
const LINUX_O_TRUNC: u32 = 0o1000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Fixture {
    table: MountTable,
    fs: MountTableFs,
    _dirs: Vec<TempDir>,
}

struct Reader(Vec<u8>);

struct Writer(Vec<u8>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Fixture {
    fn new() -> Self {
        let table = MountTable::new();
        let fs = table.filesystem();
        fs.init(FsOptions::empty()).unwrap();
        Self {
            table,
            fs,
            _dirs: Vec::new(),
        }
    }

    /// A fresh host directory, canonical so no component is a symlink.
    fn host_dir(&mut self) -> PathBuf {
        self.host_dir_in(&std::env::temp_dir())
    }

    fn host_dir_in(&mut self, parent: &Path) -> PathBuf {
        let dir = tempfile::tempdir_in(parent).unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        self._dirs.push(dir);
        path
    }

    fn attach(&self, name: &str, host_path: &Path, readonly: bool) {
        self.table.attach(child(name, host_path, readonly)).unwrap();
    }

    fn lookup(&self, parent: u64, name: &str) -> io::Result<Entry> {
        self.fs.lookup(ctx(), parent, &cstr(name))
    }

    fn create(&self, parent: u64, name: &str) -> io::Result<(Entry, u64)> {
        let (entry, handle, _) = self.fs.create(
            ctx(),
            parent,
            &cstr(name),
            0o644,
            false,
            LINUX_O_RDWR,
            0,
            Extensions::default(),
        )?;
        Ok((entry, handle.unwrap()))
    }

    fn write(&self, inode: u64, handle: u64, data: &[u8]) -> io::Result<usize> {
        self.fs.write(
            ctx(),
            inode,
            handle,
            &mut Reader(data.to_vec()),
            data.len() as u32,
            0,
            None,
            false,
            false,
            0,
        )
    }

    fn read(&self, inode: u64, handle: u64) -> io::Result<Vec<u8>> {
        let mut writer = Writer(Vec::new());
        self.fs
            .read(ctx(), inode, handle, &mut writer, 4096, 0, None, 0)?;
        Ok(writer.0)
    }

    fn root_names(&self) -> Vec<String> {
        let (handle, _) = self.fs.opendir(ctx(), ROOT, 0).unwrap();
        let handle = handle.unwrap();
        let mut names = Vec::new();
        self.fs
            .readdir_for_each(ctx(), ROOT, handle, 4096, 0, &mut |entry: DirEntry<'_>| {
                names.push(String::from_utf8(entry.name.to_vec()).unwrap());
                Ok(1)
            })
            .unwrap();
        self.fs.releasedir(ctx(), ROOT, 0, handle).unwrap();
        names
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ZeroCopyReader for Reader {
    fn read_to(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let count = count.min(self.0.len());
        let n = unsafe {
            libc::pwrite(
                f.as_raw_fd(),
                self.0.as_ptr() as *const libc::c_void,
                count,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.0.drain(..n as usize);
        Ok(n as usize)
    }
}

impl ZeroCopyWriter for Writer {
    fn write_from(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let mut buf = vec![0u8; count];
        let n = unsafe {
            libc::pread(
                f.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                count,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.0.extend_from_slice(&buf[..n as usize]);
        Ok(n as usize)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}

fn cstr(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn child(name: &str, host_path: &Path, readonly: bool) -> MountTableChild {
    MountTableChild {
        name: name.to_string(),
        host_path: host_path.to_path_buf(),
        readonly,
        quota_bytes: None,
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        cache_policy: CachePolicy::Auto,
        owner: None,
    }
}

fn errno<T>(result: io::Result<T>) -> i32 {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error.raw_os_error().unwrap(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn mutation_revisions_cover_repeated_held_writes_and_reconnect() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut f = Fixture::new();
        let dir = f.host_dir();
        f.attach("work", &dir, false);
        let initial = f.table.watch_writes(None).await;
        assert!(initial.reset);
        assert_eq!(initial.mounts[0].revision, 0);
        let root = f.lookup(ROOT, "work").unwrap();
        let (file, handle) = f.create(root.inode, "note").unwrap();
        assert_eq!(f.write(file.inode, handle, b"one").unwrap(), 3);
        let first = f.table.watch_writes(Some(initial.cursor)).await;
        assert!(!first.reset);
        assert!(first.mounts[0].revision > 0);
        // Keep the same backend handle open. No flush, release, fsync, or close
        // separates these writes, including while there is no waiting consumer.
        assert_eq!(
            f.fs.write(
                ctx(),
                file.inode,
                handle,
                &mut Reader(b"two".to_vec()),
                3,
                3,
                None,
                false,
                false,
                0
            )
            .unwrap(),
            3
        );
        let second = f.table.watch_writes(Some(first.cursor)).await;
        assert!(second.mounts[0].revision > first.mounts[0].revision);
        assert_eq!(second.mounts[0].attachment, first.mounts[0].attachment);
        assert_eq!(std::fs::read(dir.join("note")).unwrap(), b"onetwo");
        let mut waiting = Box::pin(f.table.watch_writes(Some(second.cursor.clone())));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                waiting.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        drop(waiting); // Cancellation leaves no retained subscriber or consumed event.
        f.table.set_readonly("work", true).unwrap();
        assert_eq!(
            f.write(file.inode, handle, b"bad")
                .unwrap_err()
                .raw_os_error(),
            Some(LINUX_EROFS)
        );
        let unchanged = f.table.watch_writes(None).await;
        assert_eq!(unchanged.cursor, second.cursor);
        assert_eq!(unchanged.mounts[0].revision, second.mounts[0].revision);
        f.table.detach("work").unwrap();
        f.attach("work", &dir, false);
        let replaced = f.table.watch_writes(Some(second.cursor)).await;
        assert_ne!(replaced.mounts[0].attachment, second.mounts[0].attachment);
        assert_eq!(replaced.mounts[0].revision, 0);
        assert_eq!(
            f.write(file.inode, handle, b"old")
                .unwrap_err()
                .raw_os_error(),
            Some(LINUX_ESTALE)
        );
        let another = MountTable::new().watch_writes(Some(replaced.cursor)).await;
        assert!(another.reset);
    })
    .await
    .expect("mount mutation notification did not arrive");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn mutation_revisions_cover_successful_copy_file_range_only() {
    let mut f = Fixture::new();
    let dir = f.host_dir();
    f.attach("work", &dir, false);
    let root = f.lookup(ROOT, "work").unwrap().inode;
    let (source, source_handle) = f.create(root, "source").unwrap();
    let (destination, destination_handle) = f.create(root, "destination").unwrap();
    assert_eq!(f.write(source.inode, source_handle, b"one").unwrap(), 3);
    let before = f.table.watch_writes(None).await;
    let copy = |offset, len, flags| {
        f.fs.copyfilerange(
            ctx(),
            source.inode,
            source_handle,
            offset,
            destination.inode,
            destination_handle,
            0,
            len,
            flags,
        )
    };
    assert_eq!(copy(0, 3, 0).unwrap(), 3);
    assert_eq!(std::fs::read(dir.join("destination")).unwrap(), b"one");
    let written = f.table.watch_writes(None).await;
    assert!(written.cursor.revision > before.cursor.revision);
    assert!(written.mounts[0].revision > before.mounts[0].revision);
    assert_eq!(written.mounts[0].attachment, before.mounts[0].attachment);

    assert_eq!(copy(0, 0, 0).unwrap(), 0);
    assert_eq!(f.table.watch_writes(None).await, written);
    assert_eq!(copy(3, 3, 0).unwrap(), 0); // EOF copies no bytes despite a positive length.
    assert_eq!(f.table.watch_writes(None).await, written);
    assert_eq!(
        copy(0, 3, 1).unwrap_err().raw_os_error(),
        Some(libc::EINVAL)
    );
    assert_eq!(f.table.watch_writes(None).await, written);
    assert_eq!(std::fs::read(dir.join("destination")).unwrap(), b"one");
}

#[tokio::test]
async fn mutation_revisions_cover_metadata_and_namespace_operations_only_after_success() {
    let mut f = Fixture::new();
    let dir = f.host_dir();
    f.attach("work", &dir, false);
    let root = f.lookup(ROOT, "work").unwrap().inode;
    let mut revision = f.table.watch_writes(None).await.cursor.revision;
    macro_rules! changed {
        ($operation:expr) => {{
            let result = $operation.unwrap();
            let next = f.table.watch_writes(None).await.cursor.revision;
            assert!(next > revision, "successful mutation was not reported");
            revision = next;
            result
        }};
    }
    let (entry, handle) = changed!(f.create(root, "note"));
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o600;
    changed!(f.fs.setattr(ctx(), entry.inode, attr, Some(handle), SetattrValid::MODE));
    changed!(f.fs.open(ctx(), entry.inode, false, LINUX_O_RDWR | LINUX_O_TRUNC));
    changed!(f.fs.link(ctx(), entry.inode, root, &cstr("hard")));
    changed!(f.fs.symlink(
        ctx(),
        &cstr("note"),
        root,
        &cstr("soft"),
        Extensions::default()
    ));
    changed!(f.fs.mkdir(ctx(), root, &cstr("sub"), 0o700, 0, Extensions::default()));
    changed!(f.fs.rename(ctx(), root, &cstr("note"), root, &cstr("renamed"), 0));
    changed!(f.fs.setxattr(
        ctx(),
        entry.inode,
        &cstr("user.notification_test"),
        b"test",
        0
    ));
    changed!(f.fs.removexattr(ctx(), entry.inode, &cstr("user.notification_test")));
    changed!(f.fs.unlink(ctx(), root, &cstr("soft")));
    changed!(f.fs.rmdir(ctx(), root, &cstr("sub")));
    assert!(f.fs.unlink(ctx(), root, &cstr("absent")).is_err());
    f.fs.getattr(ctx(), entry.inode, Some(handle)).unwrap();
    f.fs.fsync(ctx(), entry.inode, false, handle).unwrap();
    assert_eq!(
        f.table.watch_writes(None).await.cursor.revision,
        revision,
        "failed mutations, reads and fsync must not report writes"
    );
}

#[test]
fn guest_numbers_carry_the_attachment_id() {
    let guest = table::encode(7, 42).unwrap();
    assert_eq!(table::decode(guest), (7, 42));
    assert_eq!(table::decode(ROOT), (0, 1));
    assert!(table::encode(1, 1 << 40).is_err());
}

#[test]
fn root_lists_children_and_never_caches_their_entries() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.root_names(), [".", ".."]);
    let a = fixture.host_dir();
    let b = fixture.host_dir();
    fixture.attach("b", &b, false);
    fixture.attach("a", &a, true);

    assert_eq!(fixture.root_names(), [".", "..", "a", "b"]);
    let entry = fixture.lookup(ROOT, "a").unwrap();
    assert_eq!(entry.entry_timeout, Duration::ZERO);
    assert_eq!(entry.attr_timeout, Duration::ZERO);
    assert_eq!(table::decode(entry.inode).1, 1);
    let (root, ttl) = fixture.fs.getattr(ctx(), ROOT, None).unwrap();
    assert_eq!(ttl, Duration::ZERO);
    assert_eq!(u32::from(root.st_mode) & 0o777, 0o555);
    assert_eq!(errno(fixture.lookup(ROOT, "missing")), LINUX_ENOENT);

    // Readdirplus lists the same children with uncached entries.
    let (handle, _) = fixture.fs.opendir(ctx(), ROOT, 0).unwrap();
    let mut listed = Vec::new();
    fixture
        .fs
        .readdirplus_for_each(ctx(), ROOT, handle.unwrap(), 4096, 0, &mut |dir, entry| {
            assert_eq!(entry.entry_timeout, Duration::ZERO);
            listed.push((String::from_utf8(dir.name.to_vec()).unwrap(), entry.inode));
            Ok(1)
        })
        .unwrap();
    let names: Vec<_> = listed.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(listed[0].1, entry.inode);
}

#[test]
fn the_root_refuses_mutation() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    fixture.attach("data", &dir, false);
    assert_eq!(errno(fixture.create(ROOT, "file")), LINUX_EACCES);
    assert_eq!(
        errno(
            fixture
                .fs
                .mkdir(ctx(), ROOT, &cstr("dir"), 0o755, 0, Extensions::default())
        ),
        LINUX_EACCES
    );
    assert_eq!(
        errno(fixture.fs.rmdir(ctx(), ROOT, &cstr("data"))),
        LINUX_EACCES
    );
    assert_eq!(
        errno(
            fixture
                .fs
                .rename(ctx(), ROOT, &cstr("data"), ROOT, &cstr("other"), 0)
        ),
        LINUX_EACCES
    );
    assert_eq!(errno(fixture.fs.access(ctx(), ROOT, 2)), LINUX_EROFS);
}

#[test]
fn operations_reach_the_child_host_directory() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("existing"), b"from host").unwrap();
    fixture.attach("data", &dir, false);

    let root = fixture.lookup(ROOT, "data").unwrap().inode;
    let existing = fixture.lookup(root, "existing").unwrap();
    assert_eq!(table::decode(existing.inode).0, table::decode(root).0);
    let (handle, _) = fixture.fs.open(ctx(), existing.inode, false, 0).unwrap();
    let handle = handle.unwrap();
    assert_eq!(table::decode(handle).0, table::decode(root).0);
    assert_eq!(fixture.read(existing.inode, handle).unwrap(), b"from host");

    let (created, write_handle) = fixture.create(root, "new").unwrap();
    fixture
        .write(created.inode, write_handle, b"from guest")
        .unwrap();
    assert_eq!(std::fs::read(dir.join("new")).unwrap(), b"from guest");

    let sub = fixture
        .fs
        .mkdir(ctx(), root, &cstr("sub"), 0o755, 0, Extensions::default())
        .unwrap();
    fixture
        .fs
        .rename(ctx(), root, &cstr("new"), sub.inode, &cstr("moved"), 0)
        .unwrap();
    assert!(dir.join("sub/moved").is_file());

    // A handle of one child is not valid for another inode's child.
    let other = fixture.host_dir();
    fixture.attach("other", &other, false);
    let other_root = fixture.lookup(ROOT, "other").unwrap().inode;
    let (other_file, other_handle) = fixture.create(other_root, "file").unwrap();
    assert_eq!(
        errno(fixture.read(existing.inode, other_handle)),
        LINUX_EBADF
    );
    assert_eq!(
        errno(
            fixture
                .fs
                .rename(ctx(), root, &cstr("existing"), other_root, &cstr("x"), 0)
        ),
        LINUX_EXDEV
    );
    assert_eq!(
        errno(fixture.fs.link(ctx(), other_file.inode, root, &cstr("x"))),
        LINUX_EXDEV
    );
}

#[test]
fn read_only_switch_applies_to_handles_opened_before_it() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("file"), b"original").unwrap();
    fixture.attach("data", &dir, false);
    let root = fixture.lookup(ROOT, "data").unwrap().inode;
    let file = fixture.lookup(root, "file").unwrap();
    let (handle, _) = fixture
        .fs
        .open(ctx(), file.inode, false, LINUX_O_RDWR)
        .unwrap();
    let handle = handle.unwrap();
    fixture.write(file.inode, handle, b"changed!").unwrap();

    fixture.table.set_readonly("data", true).unwrap();
    assert_eq!(
        errno(fixture.write(file.inode, handle, b"refused")),
        LINUX_EROFS
    );
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 0;
    assert_eq!(
        errno(
            fixture
                .fs
                .setattr(ctx(), file.inode, attr, Some(handle), SetattrValid::SIZE)
        ),
        LINUX_EROFS
    );
    assert_eq!(
        errno(fixture.fs.open(ctx(), file.inode, false, LINUX_O_WRONLY)),
        LINUX_EROFS
    );
    assert_eq!(errno(fixture.create(root, "new")), LINUX_EROFS);
    assert_eq!(
        errno(fixture.fs.unlink(ctx(), root, &cstr("file"))),
        LINUX_EROFS
    );
    assert_eq!(errno(fixture.fs.access(ctx(), file.inode, 2)), LINUX_EROFS);
    // Reads still work.
    assert_eq!(fixture.read(file.inode, handle).unwrap(), b"changed!");
    assert_eq!(std::fs::read(dir.join("file")).unwrap(), b"changed!");

    fixture.table.set_readonly("data", false).unwrap();
    fixture.write(file.inode, handle, b"writable").unwrap();
    assert_eq!(std::fs::read(dir.join("file")).unwrap(), b"writable");
}

#[test]
fn a_read_only_child_refuses_writes_from_the_start() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("file"), b"data").unwrap();
    fixture.attach("ro", &dir, true);
    let root = fixture.lookup(ROOT, "ro").unwrap().inode;
    let file = fixture.lookup(root, "file").unwrap();
    assert_eq!(
        errno(fixture.fs.open(ctx(), file.inode, false, LINUX_O_RDWR)),
        LINUX_EROFS
    );
    assert_eq!(errno(fixture.create(root, "new")), LINUX_EROFS);
}

#[test]
fn detach_makes_held_inodes_and_handles_stale() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("file"), b"old").unwrap();
    fixture.attach("data", &dir, false);
    let root = fixture.lookup(ROOT, "data").unwrap().inode;
    let file = fixture.lookup(root, "file").unwrap();
    let (handle, _) = fixture.fs.open(ctx(), file.inode, false, 0).unwrap();
    let handle = handle.unwrap();

    fixture.table.detach("data").unwrap();
    assert_eq!(fixture.root_names(), [".", ".."]);
    assert_eq!(errno(fixture.lookup(ROOT, "data")), LINUX_ENOENT);
    // The device answers every request on a detached number with ESTALE
    // before dispatch; the operations themselves agree.
    assert_eq!(fixture.fs.request_error(file.inode), Some(LINUX_ESTALE));
    assert_eq!(fixture.fs.request_error(root), Some(LINUX_ESTALE));
    assert_eq!(fixture.fs.request_error(ROOT), None);
    assert_eq!(errno(fixture.read(file.inode, handle)), LINUX_ESTALE);
    assert_eq!(errno(fixture.lookup(root, "file")), LINUX_ESTALE);
    // Late forgets for the dead attachment are ignored.
    fixture.fs.forget(ctx(), file.inode, 1);
    fixture
        .fs
        .batch_forget(ctx(), vec![(file.inode, 1), (root, 1)]);
    assert_eq!(
        fixture.table.detach("data").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );

    // Re-attaching the name over new content never aliases the old numbers.
    let fresh = fixture.host_dir();
    std::fs::write(fresh.join("file"), b"new").unwrap();
    fixture.attach("data", &fresh, false);
    let new_root = fixture.lookup(ROOT, "data").unwrap().inode;
    assert_ne!(new_root, root);
    let new_file = fixture.lookup(new_root, "file").unwrap();
    assert_ne!(new_file.inode, file.inode);
    assert_eq!(fixture.fs.request_error(file.inode), Some(LINUX_ESTALE));
    let (new_handle, _) = fixture.fs.open(ctx(), new_file.inode, false, 0).unwrap();
    assert_eq!(
        fixture.read(new_file.inode, new_handle.unwrap()).unwrap(),
        b"new"
    );
}

#[test]
fn detach_drops_the_child_backend() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("file"), b"data").unwrap();
    fixture.attach("data", &dir, false);
    let root = fixture.lookup(ROOT, "data").unwrap().inode;
    let file = fixture.lookup(root, "file").unwrap();
    let (handle, _) = fixture.fs.open(ctx(), file.inode, false, 0).unwrap();
    assert!(handle.is_some());
    let (id, _) = table::decode(root);
    let child = std::sync::Arc::downgrade(&fixture.table.child_by_id(id).unwrap());

    fixture.table.detach("data").unwrap();
    // Nothing keeps the backend alive, so its root, inode and handle
    // descriptors are closed with it.
    assert!(child.upgrade().is_none());
}

#[test]
fn names_are_validated_and_unique() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    for name in ["", ".", "..", "a/b", "nul\0"] {
        assert!(fixture.table.attach(child(name, &dir, false)).is_err());
    }
    fixture.attach("data", &dir, false);
    let error = fixture
        .table
        .attach(child("data", &dir, false))
        .unwrap_err();
    assert_eq!(
        error.kind(),
        io::Error::from_raw_os_error(LINUX_EEXIST).kind()
    );
    assert!(fixture.table.set_readonly("missing", true).is_err());
    assert!(fixture.table.detach("missing").is_err());
    assert_eq!(fixture.table.names(), ["data"]);
}

#[test]
fn a_symlinked_host_path_is_refused() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    let target = dir.join("target");
    std::fs::create_dir(&target).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(fixture.table.attach(child("data", &link, false)).is_err());
}

#[test]
fn quota_is_per_child_and_optional() {
    let mut fixture = Fixture::new();
    let limited = fixture.host_dir();
    let unlimited = fixture.host_dir();
    fixture
        .table
        .attach(MountTableChild {
            quota_bytes: Some(4),
            ..child("limited", &limited, false)
        })
        .unwrap();
    fixture.attach("unlimited", &unlimited, false);

    let root = fixture.lookup(ROOT, "limited").unwrap().inode;
    let (file, handle) = fixture.create(root, "file").unwrap();
    assert_eq!(
        errno(fixture.write(file.inode, handle, b"more than four")),
        LINUX_ENOSPC
    );

    let root = fixture.lookup(ROOT, "unlimited").unwrap().inode;
    let (file, handle) = fixture.create(root, "file").unwrap();
    let data = vec![7u8; 1 << 20];
    assert_eq!(
        fixture.write(file.inode, handle, &data).unwrap(),
        data.len()
    );
}

#[test]
fn never_cached_children_use_direct_io_and_zero_timeouts() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("secret"), b"value").unwrap();
    fixture
        .table
        .attach(MountTableChild {
            cache_policy: CachePolicy::Never,
            ..child("secret", &dir, true)
        })
        .unwrap();
    let root = fixture.lookup(ROOT, "secret").unwrap().inode;
    let file = fixture.lookup(root, "secret").unwrap();
    assert_eq!(file.entry_timeout, Duration::ZERO);
    assert_eq!(file.attr_timeout, Duration::ZERO);
    let (_, options) = fixture.fs.open(ctx(), file.inode, false, 0).unwrap();
    assert!(options.contains(OpenOptions::DIRECT_IO));
}

#[cfg(target_os = "linux")]
#[test]
fn a_tmpfs_child_supports_strict_stat_virtualization() {
    let shm = Path::new("/dev/shm");
    assert!(shm.is_dir(), "/dev/shm must exist on Linux");
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir_in(shm);
    // Strict probes writable `user.*` xattrs; tmpfs has them since Linux 6.6.
    fixture.attach("secret", &dir, false);
    let root = fixture.lookup(ROOT, "secret").unwrap().inode;
    let (file, handle) = fixture.create(root, "token").unwrap();
    fixture.write(file.inode, handle, b"secret").unwrap();
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_mode = 0o400;
    let (stat, _) = fixture
        .fs
        .setattr(ctx(), file.inode, attr, None, SetattrValid::MODE)
        .unwrap();
    assert_eq!(u32::from(stat.st_mode) & 0o777, 0o400);
    assert_eq!(std::fs::read(dir.join("token")).unwrap(), b"secret");
}

#[test]
fn checkpoints_are_refused() {
    let fixture = Fixture::new();
    assert!(fixture.fs.capture_state().is_err());
    assert!(fixture.fs.validate_state(b"").is_err());
}

#[test]
fn a_cstr_name_that_is_not_utf8_is_not_found() {
    let fixture = Fixture::new();
    let name = CStr::from_bytes_with_nul(b"\xff\0").unwrap();
    assert_eq!(errno(fixture.fs.lookup(ctx(), ROOT, name)), LINUX_ENOENT);
}

#[test]
fn children_never_share_a_guest_inode_number() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("file"), b"data").unwrap();
    // Two children over the same host directory see the same host inodes.
    fixture.attach("a", &dir, false);
    fixture.attach("b", &dir, false);
    let a = fixture.lookup(ROOT, "a").unwrap();
    let b = fixture.lookup(ROOT, "b").unwrap();
    assert_ne!(a.attr.st_ino, b.attr.st_ino);
    let file_a = fixture.lookup(a.inode, "file").unwrap();
    let file_b = fixture.lookup(b.inode, "file").unwrap();
    assert_ne!(file_a.attr.st_ino, file_b.attr.st_ino);
    let host_ino = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(dir.join("file")).unwrap().ino()
    };
    assert_eq!(table::decode(file_a.attr.st_ino).1, host_ino);
    let (stat, _) = fixture.fs.getattr(ctx(), file_a.inode, None).unwrap();
    assert_eq!(stat.st_ino, file_a.attr.st_ino);

    // Directory entries report the same number a lookup does.
    let (handle, _) = fixture.fs.opendir(ctx(), a.inode, 0).unwrap();
    let mut listed = None;
    fixture
        .fs
        .readdir_for_each(ctx(), a.inode, handle.unwrap(), 4096, 0, &mut |entry| {
            if entry.name == b"file" {
                listed = Some(entry.ino);
            }
            Ok(1)
        })
        .unwrap();
    assert_eq!(listed, Some(file_a.attr.st_ino));
}

/// Run `operation` on another thread while this thread holds an in-flight
/// operation guard; return once `applied` shows the change took effect,
/// asserting the reply is still withheld, then release the guard.
fn assert_waits_for_in_flight_operations(
    fixture: &Fixture,
    operation: impl FnOnce(MountTable) + Send + 'static,
    applied: impl Fn() -> bool,
) {
    let in_flight = fixture.table.begin();
    let table = fixture.table.clone();
    let (replied, reply) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        operation(table);
        replied.send(()).unwrap();
    });
    while !applied() {
        std::thread::yield_now();
    }
    assert!(
        reply.try_recv().is_err(),
        "the change must not reply while an operation is in flight"
    );
    drop(in_flight);
    reply.recv().unwrap();
    worker.join().unwrap();
}

#[test]
fn set_readonly_replies_after_in_flight_operations() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    fixture.attach("data", &dir, false);
    let child = fixture.table.child_by_name("data").unwrap();
    assert_waits_for_in_flight_operations(
        &fixture,
        |table| table.set_readonly("data", true).unwrap(),
        || child.fs.readonly(),
    );
}

#[test]
fn detach_replies_after_in_flight_operations_and_drops_the_backend() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    fixture.attach("data", &dir, false);
    let child = std::sync::Arc::downgrade(&fixture.table.child_by_name("data").unwrap());
    let table = fixture.table.clone();
    assert_waits_for_in_flight_operations(
        &fixture,
        |table| table.detach("data").unwrap(),
        move || table.names().is_empty(),
    );
    assert!(child.upgrade().is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests: file children
//--------------------------------------------------------------------------------------------------

const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

impl Fixture {
    /// A fresh host file with `content`, in its own canonical directory.
    fn host_file(&mut self, content: &[u8]) -> PathBuf {
        let path = self.host_dir().join("item");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn open(&self, inode: u64, flags: u32) -> io::Result<u64> {
        let (handle, _) = self.fs.open(ctx(), inode, false, flags)?;
        Ok(handle.unwrap())
    }

    /// Root entries as `(name, type)` from plain readdir and from readdirplus.
    fn root_types(&self) -> (Vec<(String, u32)>, Vec<(String, u32, u64)>) {
        let (handle, _) = self.fs.opendir(ctx(), ROOT, 0).unwrap();
        let handle = handle.unwrap();
        let mut plain = Vec::new();
        self.fs
            .readdir_for_each(ctx(), ROOT, handle, 4096, 0, &mut |entry: DirEntry<'_>| {
                plain.push((String::from_utf8(entry.name.to_vec()).unwrap(), entry.type_));
                Ok(1)
            })
            .unwrap();
        let mut plus = Vec::new();
        self.fs
            .readdirplus_for_each(ctx(), ROOT, handle, 4096, 0, &mut |dir, entry| {
                assert_eq!(dir.ino, entry.attr.st_ino);
                plus.push((
                    String::from_utf8(dir.name.to_vec()).unwrap(),
                    dir.type_,
                    entry.inode,
                ));
                Ok(1)
            })
            .unwrap();
        self.fs.releasedir(ctx(), ROOT, 0, handle).unwrap();
        (plain, plus)
    }
}

/// Replace `path` the way the node does: write a sibling, rename it into place.
fn replace_by_rename(path: &Path, content: &[u8]) {
    let staged = path.with_extension("staged");
    std::fs::write(&staged, content).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

#[test]
fn a_file_child_is_one_regular_file_at_the_root() {
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"text item");
    std::fs::write(file.with_file_name("sibling"), b"hidden").unwrap();
    let dir = fixture.host_dir();
    fixture.attach("item", &file, false);
    fixture.attach("dir", &dir, false);

    let entry = fixture.lookup(ROOT, "item").unwrap();
    assert_eq!(u32::from(entry.attr.st_mode) & S_IFMT, S_IFREG);
    assert_eq!(entry.entry_timeout, Duration::ZERO);
    assert_eq!(entry.attr_timeout, Duration::ZERO);
    let (id, local) = table::decode(entry.inode);
    assert_ne!(id, 0);
    assert_ne!(local, 1, "the synthetic directory is never handed out");
    let host_ino = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&file).unwrap().ino()
    };
    assert_eq!(table::decode(entry.attr.st_ino), (id, host_ino));
    let (stat, _) = fixture.fs.getattr(ctx(), entry.inode, None).unwrap();
    assert_eq!(stat.st_ino, entry.attr.st_ino);

    let handle = fixture.open(entry.inode, LINUX_O_RDWR).unwrap();
    assert_eq!(table::decode(handle).0, id);
    assert_eq!(fixture.read(entry.inode, handle).unwrap(), b"text item");
    fixture.write(entry.inode, handle, b"TEXT").unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"TEXT item");

    // Nothing beside the file is reachable through it.
    assert_eq!(errno(fixture.lookup(entry.inode, "sibling")), LINUX_ENOTDIR);
    assert_eq!(errno(fixture.lookup(entry.inode, "..")), LINUX_ENOTDIR);
    assert_eq!(
        errno(fixture.fs.opendir(ctx(), entry.inode, 0)),
        LINUX_ENOTDIR
    );
    assert_eq!(
        errno(fixture.fs.unlink(ctx(), ROOT, &cstr("item"))),
        LINUX_EACCES
    );
    // A forged number for the child's synthetic directory shows only the file.
    let synthetic = table::encode(id, 1).unwrap();
    assert_eq!(errno(fixture.lookup(synthetic, "sibling")), LINUX_ENOENT);
    assert_eq!(errno(fixture.lookup(synthetic, "..")), LINUX_ENOENT);
    assert!(fixture.create(synthetic, "new").is_err());
    assert!(!file.with_file_name("new").exists());

    // Both listings type the file child as a regular file and agree on its number.
    let (plain, plus) = fixture.root_types();
    assert_eq!(
        plain,
        [
            (".".into(), DT_DIR),
            ("..".into(), DT_DIR),
            ("dir".into(), DT_DIR),
            ("item".into(), DT_REG)
        ]
    );
    assert_eq!(plus[1].0, "item");
    assert_eq!(plus[1].1, DT_REG);
    assert_eq!(plus[1].2, entry.inode);
    // Only directory children count as root links.
    let (root, _) = fixture.fs.getattr(ctx(), ROOT, None).unwrap();
    assert_eq!(root.st_nlink, 3);
}

#[test]
fn a_file_child_follows_its_path_across_a_rename_into_place() {
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"first");
    fixture.attach("item", &file, true);
    let old = fixture.lookup(ROOT, "item").unwrap();
    let old_handle = fixture.open(old.inode, 0).unwrap();

    replace_by_rename(&file, b"second version");

    // A new lookup resolves the path again: a new inode with the new content.
    let new = fixture.lookup(ROOT, "item").unwrap();
    assert_ne!(new.inode, old.inode);
    assert_ne!(new.attr.st_ino, old.attr.st_ino);
    let new_handle = fixture.open(new.inode, 0).unwrap();
    assert_eq!(
        fixture.read(new.inode, new_handle).unwrap(),
        b"second version"
    );
    // An open through the inode the guest already has also follows the path.
    let reopened = fixture.open(old.inode, 0).unwrap();
    assert_eq!(
        fixture.read(old.inode, reopened).unwrap(),
        b"second version"
    );
    // A handle opened before the replacement keeps the replaced file.
    assert_eq!(fixture.read(old.inode, old_handle).unwrap(), b"first");
    // The forgets the guest kernel sends for both lookups are accepted.
    fixture.fs.forget(ctx(), old.inode, 1);
    fixture.fs.forget(ctx(), new.inode, 1);
    assert_eq!(fixture.root_types().0.len(), 3);
}

#[test]
fn a_file_child_read_only_switch_applies_to_handles_opened_before_it() {
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"original");
    fixture.attach("item", &file, false);
    let entry = fixture.lookup(ROOT, "item").unwrap();
    let handle = fixture.open(entry.inode, LINUX_O_RDWR).unwrap();
    fixture.write(entry.inode, handle, b"changed!").unwrap();

    fixture.table.set_readonly("item", true).unwrap();
    assert!(fixture.table.child_by_name("item").unwrap().fs.readonly());
    assert_eq!(
        errno(fixture.write(entry.inode, handle, b"refused")),
        LINUX_EROFS
    );
    let mut attr: stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 0;
    assert_eq!(
        errno(
            fixture
                .fs
                .setattr(ctx(), entry.inode, attr, Some(handle), SetattrValid::SIZE)
        ),
        LINUX_EROFS
    );
    assert_eq!(
        errno(fixture.open(entry.inode, LINUX_O_WRONLY)),
        LINUX_EROFS
    );
    assert_eq!(errno(fixture.fs.access(ctx(), entry.inode, 2)), LINUX_EROFS);
    assert_eq!(fixture.read(entry.inode, handle).unwrap(), b"changed!");

    fixture.table.set_readonly("item", false).unwrap();
    fixture.write(entry.inode, handle, b"writable").unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"writable");
}

#[test]
fn a_read_only_file_child_needs_only_read_access_on_the_host() {
    use std::os::unix::fs::PermissionsExt;
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"secret");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
    fixture.attach("secret", &file, true);
    let entry = fixture.lookup(ROOT, "secret").unwrap();
    let handle = fixture.open(entry.inode, 0).unwrap();
    assert_eq!(fixture.read(entry.inode, handle).unwrap(), b"secret");
    assert_eq!(errno(fixture.open(entry.inode, LINUX_O_RDWR)), LINUX_EROFS);
}

#[test]
fn detaching_a_file_child_makes_its_inode_and_handles_stale() {
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"old");
    fixture.attach("item", &file, false);
    let entry = fixture.lookup(ROOT, "item").unwrap();
    let handle = fixture.open(entry.inode, 0).unwrap();
    let child = std::sync::Arc::downgrade(&fixture.table.child_by_name("item").unwrap());

    fixture.table.detach("item").unwrap();
    assert!(child.upgrade().is_none());
    assert_eq!(fixture.root_names(), [".", ".."]);
    assert_eq!(fixture.fs.request_error(entry.inode), Some(LINUX_ESTALE));
    assert_eq!(errno(fixture.read(entry.inode, handle)), LINUX_ESTALE);
    assert_eq!(
        errno(fixture.fs.getattr(ctx(), entry.inode, None)),
        LINUX_ESTALE
    );
    fixture.fs.forget(ctx(), entry.inode, 1);

    // Re-attaching the name never aliases the old numbers.
    replace_by_rename(&file, b"new");
    fixture.attach("item", &file, false);
    let fresh = fixture.lookup(ROOT, "item").unwrap();
    assert_ne!(table::decode(fresh.inode).0, table::decode(entry.inode).0);
    let handle = fixture.open(fresh.inode, 0).unwrap();
    assert_eq!(fixture.read(fresh.inode, handle).unwrap(), b"new");
}

#[test]
fn a_never_cached_file_child_uses_direct_io_and_zero_timeouts() {
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"value");
    fixture
        .table
        .attach(MountTableChild {
            cache_policy: CachePolicy::Never,
            ..child("secret", &file, true)
        })
        .unwrap();
    let entry = fixture.lookup(ROOT, "secret").unwrap();
    assert_eq!(entry.entry_timeout, Duration::ZERO);
    assert_eq!(entry.attr_timeout, Duration::ZERO);
    let (_, options) = fixture.fs.open(ctx(), entry.inode, false, 0).unwrap();
    assert!(options.contains(OpenOptions::DIRECT_IO));
}

#[test]
fn a_file_child_whose_host_file_is_gone_is_left_out_of_listings() {
    let mut fixture = Fixture::new();
    let file = fixture.host_file(b"item");
    let dir = fixture.host_dir();
    fixture.attach("item", &file, false);
    fixture.attach("dir", &dir, false);
    std::fs::remove_file(&file).unwrap();

    assert_eq!(errno(fixture.lookup(ROOT, "item")), LINUX_ENOENT);
    let (plain, plus) = fixture.root_types();
    assert_eq!(
        plain,
        [
            (".".into(), DT_DIR),
            ("..".into(), DT_DIR),
            ("dir".into(), DT_DIR)
        ]
    );
    assert_eq!(plus.len(), 1);
    assert_eq!(fixture.table.names(), ["dir", "item"]);

    // The file shows again once the host path exists.
    std::fs::write(&file, b"back").unwrap();
    let entry = fixture.lookup(ROOT, "item").unwrap();
    let handle = fixture.open(entry.inode, 0).unwrap();
    assert_eq!(fixture.read(entry.inode, handle).unwrap(), b"back");
}

fn kernel_refs(fixture: &Fixture, name: &str, guest_inode: u64) -> u64 {
    let child = fixture.table.child_by_name(name).unwrap();
    let super::table::ChildFs::File(fs) = &child.fs else {
        panic!("{name} is not a file child");
    };
    fs.kernel_refs(table::decode(guest_inode).1)
}

#[test]
fn root_readdirplus_releases_file_references_the_guest_never_receives() {
    let mut fixture = Fixture::new();
    let a = fixture.host_file(b"a");
    let b = fixture.host_file(b"b");
    fixture.attach("a", &a, false);
    fixture.attach("b", &b, false);
    let a_inode = fixture.lookup(ROOT, "a").unwrap().inode;
    let b_inode = fixture.lookup(ROOT, "b").unwrap().inode;
    fixture.fs.forget(ctx(), a_inode, 1);
    fixture.fs.forget(ctx(), b_inode, 1);
    assert_eq!(kernel_refs(&fixture, "a", a_inode), 0);

    let readdirplus = |reply: &mut dyn FnMut(usize) -> io::Result<usize>| {
        let (handle, _) = fixture.fs.opendir(ctx(), ROOT, 0).unwrap();
        let handle = handle.unwrap();
        let mut index = 0;
        let result = fixture
            .fs
            .readdirplus_for_each(ctx(), ROOT, handle, 4096, 0, &mut |_, _| {
                index += 1;
                reply(index)
            });
        fixture.fs.releasedir(ctx(), ROOT, 0, handle).unwrap();
        result
    };

    // Delivered entries keep their reference for the kernel to forget.
    readdirplus(&mut |_| Ok(1)).unwrap();
    assert_eq!(kernel_refs(&fixture, "a", a_inode), 1);
    assert_eq!(kernel_refs(&fixture, "b", b_inode), 1);
    fixture.fs.forget(ctx(), a_inode, 1);
    fixture.fs.forget(ctx(), b_inode, 1);

    // A full reply releases the entry it could not hold.
    readdirplus(&mut |index| Ok(usize::from(index == 1))).unwrap();
    assert_eq!(kernel_refs(&fixture, "a", a_inode), 1);
    assert_eq!(kernel_refs(&fixture, "b", b_inode), 0);
    fixture.fs.forget(ctx(), a_inode, 1);

    // A failed reply is dropped whole, so every reference is released.
    let error = readdirplus(&mut |index| {
        if index == 2 {
            Err(io::Error::from_raw_os_error(LINUX_EBADF))
        } else {
            Ok(1)
        }
    });
    assert_eq!(errno(error), LINUX_EBADF);
    assert_eq!(kernel_refs(&fixture, "a", a_inode), 0);
    assert_eq!(kernel_refs(&fixture, "b", b_inode), 0);
}

#[test]
fn only_directories_and_regular_files_are_children() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    let fifo = dir.join("fifo");
    let path = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let error = fixture
        .table
        .attach(child("fifo", &fifo, false))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");

    let file = fixture.host_file(b"target");
    let link = dir.join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(fixture.table.attach(child("link", &link, false)).is_err());
    assert!(
        fixture
            .table
            .attach(child("missing", &dir.join("missing"), false))
            .is_err()
    );
    assert!(fixture.table.is_empty());
}

//--------------------------------------------------------------------------------------------------
// Tests: owner
//--------------------------------------------------------------------------------------------------

const GUEST_UID: u32 = 4242;
const GUEST_GID: u32 = 4343;

fn guest_ctx() -> Context {
    Context {
        uid: GUEST_UID,
        gid: GUEST_GID,
        pid: 1,
    }
}

fn owned(name: &str, host_path: &Path, stat_virtualization: StatVirtualization) -> MountTableChild {
    MountTableChild {
        stat_virtualization,
        host_permissions: HostPermissions::Mirror,
        owner: Some((GUEST_UID, GUEST_GID)),
        ..child(name, host_path, false)
    }
}

fn owner_of(stat: &stat64) -> (u32, u32) {
    (stat.st_uid, stat.st_gid)
}

fn host_owner(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).unwrap();
    (metadata.uid(), metadata.gid())
}

#[test]
fn an_owner_presents_host_owned_entries_as_the_guest_owner() {
    for stat_virtualization in [StatVirtualization::Strict, StatVirtualization::Relaxed] {
        let mut fixture = Fixture::new();
        let dir = fixture.host_dir();
        std::fs::write(dir.join("from-host"), b"host").unwrap();
        let file = fixture.host_file(b"item");
        fixture
            .table
            .attach(owned("dir", &dir, stat_virtualization))
            .unwrap();
        fixture
            .table
            .attach(owned("item", &file, stat_virtualization))
            .unwrap();

        let root = fixture.lookup(ROOT, "dir").unwrap();
        assert_eq!(owner_of(&root.attr), (GUEST_UID, GUEST_GID));
        let from_host = fixture.lookup(root.inode, "from-host").unwrap();
        assert_eq!(owner_of(&from_host.attr), (GUEST_UID, GUEST_GID));
        let item = fixture.lookup(ROOT, "item").unwrap();
        assert_eq!(owner_of(&item.attr), (GUEST_UID, GUEST_GID));
        let (stat, _) = fixture.fs.getattr(ctx(), item.inode, None).unwrap();
        assert_eq!(owner_of(&stat), (GUEST_UID, GUEST_GID));

        // The guest owner may write; the host inode keeps this process's user.
        assert!(fixture.fs.access(guest_ctx(), from_host.inode, 2).is_ok());
        let (created, _, _) = fixture
            .fs
            .create(
                guest_ctx(),
                root.inode,
                &cstr("from-guest"),
                0o644,
                false,
                LINUX_O_RDWR,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(owner_of(&created.attr), (GUEST_UID, GUEST_GID));
        let me = host_owner(&dir);
        assert_eq!(host_owner(&dir.join("from-guest")), me);
        assert_eq!(host_owner(&dir.join("from-host")), me);
        assert_eq!(host_owner(&file), me);
    }
}

#[test]
fn without_an_owner_the_guest_sees_the_host_owner() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    std::fs::write(dir.join("from-host"), b"host").unwrap();
    fixture
        .table
        .attach(MountTableChild {
            owner: None,
            ..owned("dir", &dir, StatVirtualization::Relaxed)
        })
        .unwrap();
    let root = fixture.lookup(ROOT, "dir").unwrap();
    let file = fixture.lookup(root.inode, "from-host").unwrap();
    assert_eq!(owner_of(&file.attr), host_owner(&dir.join("from-host")));
}

#[test]
fn an_owner_requires_stat_virtualization() {
    let mut fixture = Fixture::new();
    let dir = fixture.host_dir();
    let error = fixture
        .table
        .attach(owned("dir", &dir, StatVirtualization::Off))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    assert!(error.to_string().contains("owner"), "{error}");
}
