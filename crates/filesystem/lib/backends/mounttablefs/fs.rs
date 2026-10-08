//! The virtio-fs device backend that serves a [`MountTable`].
//!
//! Guest inode and handle numbers are `attachment id << 40 | child-local
//! number`. Attachment id 0 is the synthetic root. Every request on a child
//! number is routed to that child's passthrough backend with the child-local
//! number; a number whose attachment is gone fails with `ESTALE` before it
//! reaches any backend.

use std::{
    collections::HashMap,
    ffi::CStr,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use super::table::{self, Child, LINUX_ENOENT, LINUX_ESTALE, MountTable};
use crate::{
    AddDirEntry, AddDirEntryPlus, Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions,
    GetxattrReply, ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
    stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const CHILD_ROOT_INODE: u64 = 1;

const DT_DIR: u32 = 4;
const S_IFDIR: u32 = 0o040000;
const ACCESS_W_OK: u32 = 2;

const LINUX_EPERM: i32 = 1;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EXDEV: i32 = 18;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOSYS: i32 = 38;
const LINUX_ENODATA: i32 = 61;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A virtio-fs backend presenting a [`MountTable`] under one synthetic root.
///
/// The root is read-only and lists the attached children. Its entries and
/// attributes have zero cache timeouts, so the guest sees an attach or detach
/// at its next path lookup without remounting.
pub struct MountTableFs {
    table: MountTable,
    next_root_handle: AtomicU64,
    /// Root directory handles, each with the children listed when it opened.
    root_handles: Mutex<HashMap<u64, Vec<(String, u64)>>>,
}

/// A resolved child-local target.
struct Target {
    child: Arc<Child>,
    inode: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountTableFs {
    pub(super) fn new(table: MountTable) -> Self {
        Self {
            table,
            next_root_handle: AtomicU64::new(1),
            root_handles: Mutex::new(HashMap::new()),
        }
    }

    /// The table this device serves.
    pub fn table(&self) -> &MountTable {
        &self.table
    }

    /// Resolve a guest inode inside a live child.
    fn target(&self, inode: u64) -> io::Result<Target> {
        let (id, local) = table::decode(inode);
        if id == 0 {
            // The only id-0 inode is the synthetic root, which callers handle.
            return Err(errno(LINUX_ENOENT));
        }
        let child = self
            .table
            .child_by_id(id)
            .ok_or_else(|| errno(LINUX_ESTALE))?;
        Ok(Target {
            child,
            inode: local,
        })
    }

    /// Resolve a guest handle that must belong to the same child as `target`.
    fn handle(&self, target: &Target, handle: u64) -> io::Result<u64> {
        let (id, local) = table::decode(handle);
        if id != target.child.id {
            return Err(errno(LINUX_EBADF));
        }
        Ok(local)
    }

    /// Resolve two inodes that one operation needs inside the same child.
    fn same_child(&self, first: u64, second: u64) -> io::Result<(Target, u64)> {
        let first = self.target(first)?;
        let second = self.target(second)?;
        if first.child.id != second.child.id {
            return Err(errno(LINUX_EXDEV));
        }
        Ok((first, second.inode))
    }

    fn guest_inode(&self, child: &Child, local: u64) -> io::Result<u64> {
        // Readdirplus reports an unresolvable name with inode 0; keep it 0.
        if local == 0 {
            return Ok(0);
        }
        table::encode(child.id, local)
    }

    fn guest_entry(&self, child: &Child, mut entry: Entry) -> io::Result<Entry> {
        entry.inode = self.guest_inode(child, entry.inode)?;
        Ok(entry)
    }

    fn guest_handle(&self, child: &Child, handle: Option<u64>) -> io::Result<Option<u64>> {
        handle
            .map(|handle| table::encode(child.id, handle))
            .transpose()
    }

    /// The root's entry for a child: its root inode, never cached by the guest.
    fn child_root_entry(&self, ctx: Context, child: &Child) -> io::Result<Entry> {
        let (attr, _) = child.fs.getattr(ctx, CHILD_ROOT_INODE, None)?;
        Ok(Entry {
            inode: table::encode(child.id, CHILD_ROOT_INODE)?,
            generation: 0,
            attr,
            attr_flags: 0,
            attr_timeout: Duration::ZERO,
            entry_timeout: Duration::ZERO,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for MountTableFs {
    fn capture_state(&self) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a sandbox with a mount table cannot be checkpointed",
        ))
    }

    fn validate_state(&self, _state: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a mount table cannot be restored from a checkpoint",
        ))
    }

    fn request_error(&self, inode: u64) -> Option<i32> {
        let (id, local) = table::decode(inode);
        if id == 0 {
            return None;
        }
        match self.table.child_by_id(id) {
            Some(child) => child.fs.request_error(local),
            // Detached: the guest still holds this inode or handle.
            None => Some(LINUX_ESTALE),
        }
    }

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // A remount after destroy needs every child's root registered again.
        for child in self.table.all() {
            child.fs.init(FsOptions::empty())?;
        }
        // The options a passthrough child negotiates without writeback caching,
        // plus data invalidation: the host changes child contents directly.
        let wanted = FsOptions::DONT_MASK
            | FsOptions::BIG_WRITES
            | FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::MAX_PAGES
            | FsOptions::HANDLE_KILLPRIV_V2
            | FsOptions::DO_READDIRPLUS
            | FsOptions::AUTO_INVAL_DATA;
        Ok(capable & wanted)
    }

    fn destroy(&self) {
        self.root_handles.lock().unwrap().clear();
        for child in self.table.all() {
            child.fs.destroy();
        }
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        if parent == ROOT_INODE {
            let name = name.to_str().map_err(|_| errno(LINUX_ENOENT))?;
            let id = self
                .table
                .entries()
                .into_iter()
                .find_map(|(entry, id)| (entry == name).then_some(id))
                .ok_or_else(|| errno(LINUX_ENOENT))?;
            let child = self
                .table
                .child_by_id(id)
                .ok_or_else(|| errno(LINUX_ENOENT))?;
            return self.child_root_entry(ctx, &child);
        }
        let target = self.target(parent)?;
        let entry = target.child.fs.lookup(ctx, target.inode, name)?;
        self.guest_entry(&target.child, entry)
    }

    fn forget(&self, ctx: Context, inode: u64, count: u64) {
        let (id, local) = table::decode(inode);
        // The child root is pinned by its backend and never looked up through
        // it, so its forgets carry no backend reference. A forget for a
        // detached child has nothing left to release.
        if id == 0 || local == CHILD_ROOT_INODE {
            return;
        }
        if let Some(child) = self.table.child_by_id(id) {
            child.fs.forget(ctx, local, count);
        }
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        let mut by_child: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for (inode, count) in requests {
            let (id, local) = table::decode(inode);
            if id != 0 && local != CHILD_ROOT_INODE {
                by_child.entry(id).or_default().push((local, count));
            }
        }
        for (id, requests) in by_child {
            if let Some(child) = self.table.child_by_id(id) {
                child.fs.batch_forget(ctx, requests);
            }
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        if inode == ROOT_INODE {
            return Ok((root_stat(self.table.entries().len()), Duration::ZERO));
        }
        let target = self.target(inode)?;
        let handle = handle.map(|h| self.handle(&target, h)).transpose()?;
        target.child.fs.getattr(ctx, target.inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        if inode == ROOT_INODE {
            return Err(errno(LINUX_EPERM));
        }
        let target = self.target(inode)?;
        let handle = handle.map(|h| self.handle(&target, h)).transpose()?;
        target
            .child
            .fs
            .setattr(ctx, target.inode, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, inode: u64) -> io::Result<Vec<u8>> {
        if inode == ROOT_INODE {
            return Err(errno(LINUX_EINVAL));
        }
        let target = self.target(inode)?;
        target.child.fs.readlink(ctx, target.inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if parent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let target = self.target(parent)?;
        let entry = target
            .child
            .fs
            .symlink(ctx, linkname, target.inode, name, extensions)?;
        self.guest_entry(&target.child, entry)
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if parent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let target = self.target(parent)?;
        let entry =
            target
                .child
                .fs
                .mknod(ctx, target.inode, name, mode, rdev, umask, extensions)?;
        self.guest_entry(&target.child, entry)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if parent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let target = self.target(parent)?;
        let entry = target
            .child
            .fs
            .mkdir(ctx, target.inode, name, mode, umask, extensions)?;
        self.guest_entry(&target.child, entry)
    }

    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        if parent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let target = self.target(parent)?;
        target.child.fs.unlink(ctx, target.inode, name)
    }

    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        if parent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let target = self.target(parent)?;
        target.child.fs.rmdir(ctx, target.inode, name)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        if olddir == ROOT_INODE || newdir == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let (old, new_local) = self.same_child(olddir, newdir)?;
        old.child
            .fs
            .rename(ctx, old.inode, oldname, new_local, newname, flags)
    }

    fn link(&self, ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        if inode == ROOT_INODE || newparent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let (source, parent_local) = self.same_child(inode, newparent)?;
        let entry = source
            .child
            .fs
            .link(ctx, source.inode, parent_local, newname)?;
        self.guest_entry(&source.child, entry)
    }

    fn open(
        &self,
        ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            return Err(errno(LINUX_EISDIR));
        }
        let target = self.target(inode)?;
        let (handle, options) = target.child.fs.open(ctx, target.inode, kill_priv, flags)?;
        Ok((self.guest_handle(&target.child, handle)?, options))
    }

    fn create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        if parent == ROOT_INODE {
            return Err(errno(LINUX_EACCES));
        }
        let target = self.target(parent)?;
        let (entry, handle, options) = target.child.fs.create(
            ctx,
            target.inode,
            name,
            mode,
            kill_priv,
            flags,
            umask,
            extensions,
        )?;
        Ok((
            self.guest_entry(&target.child, entry)?,
            self.guest_handle(&target.child, handle)?,
            options,
        ))
    }

    fn read(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target.child.fs.read(
            ctx,
            target.inode,
            handle,
            w,
            size,
            offset,
            lock_owner,
            flags,
        )
    }

    fn write(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target.child.fs.write(
            ctx,
            target.inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target.child.fs.flush(ctx, target.inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target.child.fs.fsync(ctx, target.inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target
            .child
            .fs
            .fallocate(ctx, target.inode, handle, mode, offset, length)
    }

    fn release(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target.child.fs.release(
            ctx,
            target.inode,
            flags,
            handle,
            flush,
            flock_release,
            lock_owner,
        )
    }

    fn statfs(&self, ctx: Context, inode: u64) -> io::Result<statvfs64> {
        if inode == ROOT_INODE {
            let mut st: statvfs64 = unsafe { std::mem::zeroed() };
            st.f_bsize = 4096;
            st.f_frsize = 4096;
            st.f_namemax = 255;
            return Ok(st);
        }
        let target = self.target(inode)?;
        target.child.fs.statfs(ctx, target.inode)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if inode == ROOT_INODE {
            return Err(errno(LINUX_EPERM));
        }
        let target = self.target(inode)?;
        target
            .child
            .fs
            .setxattr(ctx, target.inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if inode == ROOT_INODE {
            return Err(errno(LINUX_ENODATA));
        }
        let target = self.target(inode)?;
        target.child.fs.getxattr(ctx, target.inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        if inode == ROOT_INODE {
            return Ok(if size == 0 {
                ListxattrReply::Count(0)
            } else {
                ListxattrReply::Names(Vec::new())
            });
        }
        let target = self.target(inode)?;
        target.child.fs.listxattr(ctx, target.inode, size)
    }

    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> io::Result<()> {
        if inode == ROOT_INODE {
            return Err(errno(LINUX_EPERM));
        }
        let target = self.target(inode)?;
        target.child.fs.removexattr(ctx, target.inode, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            let handle = self.next_root_handle.fetch_add(1, Ordering::Relaxed);
            self.root_handles
                .lock()
                .unwrap()
                .insert(handle, self.table.entries());
            return Ok((Some(table::encode(0, handle)?), OpenOptions::empty()));
        }
        let target = self.target(inode)?;
        let (handle, options) = target.child.fs.opendir(ctx, target.inode, flags)?;
        Ok((self.guest_handle(&target.child, handle)?, options))
    }

    fn readdir(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        if inode == ROOT_INODE {
            // Root names are owned by the table and cannot be lent as
            // 'static. The device dispatches through `readdir_for_each`.
            return Err(errno(LINUX_ENOSYS));
        }
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target
            .child
            .fs
            .readdir(ctx, target.inode, handle, size, offset)
    }

    fn readdir_for_each(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut AddDirEntry<'_>,
    ) -> io::Result<()> {
        if inode == ROOT_INODE {
            let listed = self
                .root_handles
                .lock()
                .unwrap()
                .get(&handle)
                .cloned()
                .ok_or_else(|| errno(LINUX_EBADF))?;
            let mut position = 0;
            for name in [".", ".."] {
                position += 1;
                if position > offset {
                    let entry = DirEntry {
                        ino: ROOT_INODE,
                        offset: position,
                        type_: DT_DIR,
                        name: name.as_bytes(),
                    };
                    if add_entry(entry)? == 0 {
                        return Ok(());
                    }
                }
            }
            for (name, id) in &listed {
                position += 1;
                if position <= offset {
                    continue;
                }
                // A child detached after this handle opened is no longer listed.
                let Some(child) = self.table.child_by_id(*id) else {
                    continue;
                };
                // `ino` matches the `st_ino` a lookup of the name returns.
                let (attr, _) = child.fs.getattr(ctx, CHILD_ROOT_INODE, None)?;
                let entry = DirEntry {
                    ino: attr.st_ino,
                    offset: position,
                    type_: DT_DIR,
                    name: name.as_bytes(),
                };
                if add_entry(entry)? == 0 {
                    break;
                }
            }
            return Ok(());
        }
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target
            .child
            .fs
            .readdir_for_each(ctx, target.inode, handle, size, offset, add_entry)
    }

    fn readdirplus(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        if inode == ROOT_INODE {
            // See `readdir`: the device dispatches through `readdirplus_for_each`.
            return Err(errno(LINUX_ENOSYS));
        }
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target
            .child
            .fs
            .readdirplus(ctx, target.inode, handle, size, offset)?
            .into_iter()
            .map(|(dir_entry, entry)| Ok((dir_entry, self.guest_entry(&target.child, entry)?)))
            .collect()
    }

    fn readdirplus_for_each(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut AddDirEntryPlus<'_>,
    ) -> io::Result<()> {
        if inode == ROOT_INODE {
            let listed = self
                .root_handles
                .lock()
                .unwrap()
                .get(&handle)
                .cloned()
                .ok_or_else(|| errno(LINUX_EBADF))?;
            // Offsets match `readdir_for_each`: 1 and 2 are the dot entries,
            // which readdirplus omits like the passthrough backend does.
            for (index, (name, id)) in listed.iter().enumerate() {
                let position = index as u64 + 3;
                if position <= offset {
                    continue;
                }
                // A child detached after this handle opened is no longer listed.
                let Some(child) = self.table.child_by_id(*id) else {
                    continue;
                };
                let entry = self.child_root_entry(ctx, &child)?;
                let dir_entry = DirEntry {
                    ino: entry.attr.st_ino,
                    offset: position,
                    type_: DT_DIR,
                    name: name.as_bytes(),
                };
                if add_entry(dir_entry, entry)? == 0 {
                    break;
                }
            }
            return Ok(());
        }
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        let child = Arc::clone(&target.child);
        let mut map_entry = |dir_entry: DirEntry<'_>, entry: Entry| {
            add_entry(dir_entry, self.guest_entry(&child, entry)?)
        };
        target.child.fs.readdirplus_for_each(
            ctx,
            target.inode,
            handle,
            size,
            offset,
            &mut map_entry,
        )
    }

    fn fsyncdir(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        if inode == ROOT_INODE {
            return Ok(());
        }
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target
            .child
            .fs
            .fsyncdir(ctx, target.inode, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, inode: u64, flags: u32, handle: u64) -> io::Result<()> {
        if inode == ROOT_INODE {
            let (_, local) = table::decode(handle);
            self.root_handles.lock().unwrap().remove(&local);
            return Ok(());
        }
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target.child.fs.releasedir(ctx, target.inode, flags, handle)
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        if inode == ROOT_INODE {
            return if mask & ACCESS_W_OK == 0 {
                Ok(())
            } else {
                Err(errno(LINUX_EACCES))
            };
        }
        let target = self.target(inode)?;
        target.child.fs.access(ctx, target.inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let target = self.target(inode)?;
        let handle = self.handle(&target, handle)?;
        target
            .child
            .fs
            .lseek(ctx, target.inode, handle, offset, whence)
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: u64,
        handle_in: u64,
        offset_in: u64,
        inode_out: u64,
        handle_out: u64,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        let (source, local_out) = self.same_child(inode_in, inode_out)?;
        let handle_in = self.handle(&source, handle_in)?;
        let handle_out = self.handle(&source, handle_out)?;
        source.child.fs.copyfilerange(
            ctx,
            source.inode,
            handle_in,
            offset_in,
            local_out,
            handle_out,
            offset_out,
            len,
            flags,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn root_stat(children: usize) -> stat64 {
    let mut stat: stat64 = unsafe { std::mem::zeroed() };
    stat.st_ino = ROOT_INODE;
    stat.st_mode = (S_IFDIR | 0o555) as _;
    stat.st_nlink = (2 + children) as _;
    stat.st_blksize = 4096;
    stat
}

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}
