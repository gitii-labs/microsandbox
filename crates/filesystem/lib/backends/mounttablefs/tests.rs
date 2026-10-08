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
const LINUX_EACCES: i32 = 13;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_EROFS: i32 = 30;
const LINUX_ENOSPC: i32 = 28;
const LINUX_ESTALE: i32 = 116;
const LINUX_O_WRONLY: u32 = 1;
const LINUX_O_RDWR: u32 = 2;

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
