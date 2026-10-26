//! The shared, runtime-updatable table of mount children.

use std::{
    collections::{BTreeMap, HashMap},
    io,
    path::PathBuf,
    sync::{
        Arc, OnceLock, RwLock, RwLockReadGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use microsandbox_types::{MountWriteCursor, MountWriteRevision, MountWrites};
use tokio::sync::watch;

use super::MountTableFs;
use crate::{
    DynFileSystem, FsOptions,
    backends::{
        passthroughfs::{
            BindIdentityMap, CachePolicy, HostPermissions, PassthroughConfig, PassthroughFs,
            StatVirtualization,
        },
        singlefilefs::SingleFileFs,
    },
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Guest inode and handle numbers carry the attachment id above this bit.
const ID_SHIFT: u32 = 40;

/// Largest inode or handle number a child backend may hand out.
const INNER_MASK: u64 = (1 << ID_SHIFT) - 1;

/// Largest attachment id; ids are never reused, so this bounds attaches per VM.
const MAX_ATTACHMENT_ID: u64 = (1 << (64 - ID_SHIFT)) - 1;

/// Longest child name, the Linux `NAME_MAX`.
const MAX_NAME_BYTES: usize = 255;

pub(super) const LINUX_ENOENT: i32 = 2;
pub(super) const LINUX_EEXIST: i32 = 17;
pub(super) const LINUX_EOVERFLOW: i32 = 75;
pub(super) const LINUX_ESTALE: i32 = 116;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One child to attach: a guest-visible name over a host directory or a
/// regular host file.
#[derive(Debug, Clone)]
pub struct MountTableChild {
    /// Guest-visible name, one path component.
    pub name: String,

    /// Absolute, symlink-free host directory or regular file; its type at
    /// attach selects the child kind. Every path component is opened without
    /// following symlinks, so callers canonicalize a legitimately symlinked
    /// prefix (such as `/var` on macOS) first.
    ///
    /// A file child follows the path, not the inode: every guest lookup and
    /// open resolves the host path again, so a file the host replaces by
    /// renaming a new one into place shows the new content at the guest's
    /// next open. Files the guest already holds open keep the replaced inode.
    /// While the host path is missing, the child is left out of root listings
    /// and a lookup of its name fails with `ENOENT`.
    pub host_path: PathBuf,

    /// Whether the child starts read-only. [`MountTable::set_readonly`] changes it later.
    pub readonly: bool,

    /// Guest-write byte budget for the child's directory or file; `None` is unlimited.
    pub quota_bytes: Option<u64>,

    /// Guest-visible metadata policy.
    ///
    /// [`StatVirtualization::Strict`] requires writable `user.*` xattrs on a
    /// directory child even when it is read-only, because the child can be
    /// switched to read-write later. A file child is probed for the access it
    /// starts with, under every policy: a read-only file child needs read
    /// access only, and a read-write one must be writable by this process.
    /// Switching a file child to read-write later does not probe again.
    pub stat_virtualization: StatVirtualization,

    /// Whether guest permission changes reach the host inode.
    pub host_permissions: HostPermissions,

    /// Guest caching. [`CachePolicy::Never`] also sets zero entry and
    /// attribute timeouts, for content that must not linger in guest memory.
    pub cache_policy: CachePolicy,

    /// Guest `(uid, gid)` presented for entries this process owns on the host.
    ///
    /// Applies where an entry carries no per-file stat override; entries
    /// owned by any other host user show as 65534. The host inodes are not
    /// changed: guest-created entries are created by this process and owned
    /// by its user, and the host kernel still checks every access against
    /// that user. Only the owner the guest sees is rewritten, so a guest user
    /// with this uid passes the guest kernel's permission checks on files the
    /// node owns. Requires stat virtualization (`Strict` or `Relaxed`).
    pub owner: Option<(u32, u32)>,
}

/// Shared handle to a mount table.
///
/// The device backend ([`MountTableFs`]) and the runtime's control path hold
/// clones of the same table, so attach, detach and mode changes take effect on
/// the running device.
#[derive(Clone, Default)]
pub struct MountTable {
    pub(super) state: Arc<TableState>,
}

pub(super) struct TableState {
    pub(super) children: RwLock<Children>,
    /// Held shared by every device operation on a child. A mode switch or
    /// detach takes it exclusively before replying, so no operation that
    /// began under the old state is still running when the caller proceeds.
    /// The wait lasts as long as the longest operation in flight, so a slow
    /// host filesystem under a child also delays mode switches and detaches.
    pub(super) ops: RwLock<()>,
    pub(super) writes: watch::Sender<u64>,
    epoch: String,
}

#[derive(Default)]
pub(super) struct Children {
    pub(super) by_name: BTreeMap<String, u64>,
    pub(super) by_id: HashMap<u64, Arc<Child>>,
    last_id: u64,
}

/// One attached child backend.
pub(super) struct Child {
    pub(super) id: u64,
    pub(super) fs: ChildFs,
    pub(super) revision: AtomicU64,
}

/// A child's backend, by the kind of its host path.
pub(super) enum ChildFs {
    /// A host directory; the child root is the directory itself.
    Directory(PassthroughFs),
    /// A regular host file behind a synthetic directory that holds only it;
    /// the child root is the file.
    File(SingleFileFs),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The device backend serving this table.
    pub fn filesystem(&self) -> MountTableFs {
        MountTableFs::new(self.clone())
    }

    /// Attach a child under a new name.
    ///
    /// Fails with `EEXIST` when the name is attached, and with `EINVAL` when
    /// it is not one path component, when the host path is neither a
    /// directory nor a regular file, or when an owner is given without stat
    /// virtualization. The child's inode numbers carry an attachment
    /// id that is never reused, so a name detached and attached again never
    /// resolves to the inodes the guest holds from the earlier attachment.
    pub fn attach(&self, child: MountTableChild) -> io::Result<()> {
        validate_name(&child.name)?;
        if self
            .state
            .children
            .read()
            .unwrap()
            .by_name
            .contains_key(&child.name)
        {
            return Err(name_error(LINUX_EEXIST, &child.name, "is already attached"));
        }

        let fs = open_child(&child)?;
        fs.set_readonly(child.readonly);
        // Registers the child's root inode. The negotiated options belong to
        // the table device; a child never enables writeback caching.
        fs.as_dyn().init(FsOptions::empty())?;

        let mut children = self.state.children.write().unwrap();
        if children.by_name.contains_key(&child.name) {
            return Err(name_error(LINUX_EEXIST, &child.name, "is already attached"));
        }
        if children.last_id == MAX_ATTACHMENT_ID {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("mount table attachment limit of {MAX_ATTACHMENT_ID} reached"),
            ));
        }
        children.last_id += 1;
        let id = children.last_id;
        children.by_name.insert(child.name, id);
        children.by_id.insert(
            id,
            Arc::new(Child {
                id,
                fs,
                revision: AtomicU64::new(0),
            }),
        );
        self.state.writes.send_modify(|revision| *revision += 1);
        Ok(())
    }

    /// Detach a child and drop its backend.
    ///
    /// Dropping the backend closes every host descriptor it holds. Guest
    /// inodes and handles of the child then fail with `ESTALE`, including open
    /// files and working directories inside it.
    pub fn detach(&self, name: &str) -> io::Result<()> {
        let removed = {
            let mut children = self.state.children.write().unwrap();
            let id = children
                .by_name
                .remove(name)
                .ok_or_else(|| name_error(LINUX_ENOENT, name, "is not attached"))?;
            children.by_id.remove(&id)
        };
        // Wait for operations that resolved the child before it was removed.
        // Afterwards only FUSE init or destroy, which walk every child without
        // the guard, can still hold a reference; otherwise dropping this one
        // closes every descriptor before the caller is told it is detached.
        drop(self.state.ops.write().unwrap());
        drop(removed);
        self.state.writes.send_modify(|revision| *revision += 1);
        Ok(())
    }

    /// Switch a child between read-only and read-write.
    ///
    /// The flag is checked on every mutating operation, so it also applies to
    /// files the guest opened for writing before the switch.
    pub fn set_readonly(&self, name: &str, readonly: bool) -> io::Result<()> {
        let child = self
            .child_by_name(name)
            .ok_or_else(|| name_error(LINUX_ENOENT, name, "is not attached"))?;
        child.fs.set_readonly(readonly);
        // A write that checked the flag before the switch finishes before the
        // caller is told the switch applies.
        drop(child);
        drop(self.state.ops.write().unwrap());
        Ok(())
    }

    /// Names of the attached children, sorted.
    pub fn names(&self) -> Vec<String> {
        self.state
            .children
            .read()
            .unwrap()
            .by_name
            .keys()
            .cloned()
            .collect()
    }

    /// Whether any child is attached.
    pub fn is_empty(&self) -> bool {
        self.state.children.read().unwrap().by_name.is_empty()
    }

    /// Wait for a changed mutation cursor, or return the initial attachment snapshot.
    /// State is retained per live attachment, so reconnects and slow consumers lose no writes.
    /// Dropping this future releases its receiver without a background worker.
    pub async fn watch_writes(&self, cursor: Option<MountWriteCursor>) -> MountWrites {
        let mut receiver = self.state.writes.subscribe();
        let reset = cursor
            .as_ref()
            .is_none_or(|cursor| cursor.epoch != self.state.epoch);
        loop {
            // Lock order matches attach: children before the watch value. Mutations
            // publish the child's revision under the watch lock before waking waiters.
            let snapshot = {
                let children = self.state.children.read().unwrap();
                let revision = receiver.borrow_and_update();
                if reset
                    || cursor
                        .as_ref()
                        .is_some_and(|cursor| cursor.revision != *revision)
                {
                    Some(MountWrites {
                        cursor: MountWriteCursor {
                            epoch: self.state.epoch.clone(),
                            revision: *revision,
                        },
                        reset,
                        mounts: children
                            .by_name
                            .iter()
                            .map(|(name, id)| MountWriteRevision {
                                name: name.clone(),
                                attachment: *id,
                                revision: children.by_id[id].revision.load(Ordering::Acquire),
                            })
                            .collect(),
                    })
                } else {
                    None
                }
            };
            if let Some(snapshot) = snapshot {
                return snapshot;
            }
            // The table owns the sender for the full wait, so it cannot close.
            receiver
                .changed()
                .await
                .expect("mount table owns its mutation sender");
        }
    }

    pub(super) fn written(&self, child: &Child) {
        self.state.writes.send_modify(|revision| {
            *revision += 1;
            child.revision.store(*revision, Ordering::Release);
        });
    }

    /// Begin one device operation; see [`TableState::ops`]. Never nest it:
    /// a waiting writer blocks new readers.
    pub(super) fn begin(&self) -> RwLockReadGuard<'_, ()> {
        self.state.ops.read().unwrap()
    }

    pub(super) fn child_by_name(&self, name: &str) -> Option<Arc<Child>> {
        let children = self.state.children.read().unwrap();
        let id = children.by_name.get(name)?;
        children.by_id.get(id).cloned()
    }

    pub(super) fn child_by_id(&self, id: u64) -> Option<Arc<Child>> {
        self.state.children.read().unwrap().by_id.get(&id).cloned()
    }

    /// Attached children as `(name, id)`, sorted by name.
    pub(super) fn entries(&self) -> Vec<(String, u64)> {
        self.state
            .children
            .read()
            .unwrap()
            .by_name
            .iter()
            .map(|(name, id)| (name.clone(), *id))
            .collect()
    }

    /// Every attached child, for device-wide init and destroy.
    pub(super) fn all(&self) -> Vec<Arc<Child>> {
        self.state
            .children
            .read()
            .unwrap()
            .by_id
            .values()
            .cloned()
            .collect()
    }
}

impl ChildFs {
    pub(super) fn as_dyn(&self) -> &dyn DynFileSystem {
        match self {
            Self::Directory(fs) => fs,
            Self::File(fs) => fs,
        }
    }

    pub(super) fn set_readonly(&self, readonly: bool) {
        match self {
            Self::Directory(fs) => fs.set_readonly(readonly),
            Self::File(fs) => fs.set_readonly(readonly),
        }
    }

    #[cfg(test)]
    pub(super) fn readonly(&self) -> bool {
        match self {
            Self::Directory(fs) => fs.readonly(),
            Self::File(fs) => fs.readonly(),
        }
    }

    pub(super) fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for TableState {
    fn default() -> Self {
        Self {
            children: RwLock::default(),
            ops: RwLock::default(),
            writes: watch::channel(0).0,
            epoch: format!("{:032x}", rand::random::<u128>()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open the backend for a child, by the type of its host path.
fn open_child(child: &MountTableChild) -> io::Result<ChildFs> {
    let open_error = |what: &str, error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "mount {:?}: cannot open host {what} {}: {error}",
                child.name,
                child.host_path.display()
            ),
        )
    };
    // Does not follow a symlink at the last component; the backends refuse
    // symlinks in the other components when they open the path.
    let metadata =
        std::fs::symlink_metadata(&child.host_path).map_err(|error| open_error("path", error))?;
    let timeout = match child.cache_policy {
        CachePolicy::Never => Duration::ZERO,
        CachePolicy::Auto | CachePolicy::Always => PassthroughConfig::default().attr_timeout,
    };
    let bind_identity_map = match child.owner {
        None => None,
        // Caller validation: without stat virtualization the backend shows
        // raw host metadata and has no place to apply the map.
        Some(_) if matches!(child.stat_virtualization, StatVirtualization::Off) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "mount {:?}: an owner requires stat virtualization strict or relaxed",
                    child.name
                ),
            ));
        }
        Some((uid, gid)) => {
            // Only entries this process owns take the guest owner. Entries
            // of another host user (say root) show as 65534, so the guest
            // does not see as its own a file the host would refuse it.
            // SAFETY: geteuid has no preconditions and cannot fail.
            let host_uid = unsafe { libc::geteuid() };
            Some(Arc::new(OnceLock::from(BindIdentityMap::new(
                host_uid, uid, gid,
            ))))
        }
    };
    let cfg = PassthroughConfig {
        root_dir: child.host_path.clone(),
        no_symlink_root: true,
        stat_virtualization: child.stat_virtualization,
        host_permissions: child.host_permissions,
        // A directory is probed for the strongest access the child can later
        // be switched to. A file is probed for the access it starts with, so
        // a read-only file the host keeps at mode 0400, such as a secret, can
        // be attached; switching it to read-write later does not probe again.
        readonly: metadata.is_file() && child.readonly,
        entry_timeout: timeout,
        attr_timeout: timeout,
        cache_policy: child.cache_policy,
        writeback: false,
        inject_init: false,
        quota_bytes: child.quota_bytes,
        bind_identity_map,
        ..Default::default()
    };
    if metadata.is_dir() {
        PassthroughFs::new(cfg)
            .map(ChildFs::Directory)
            .map_err(|error| open_error("directory", error))
    } else if metadata.is_file() {
        SingleFileFs::for_mount_table(&child.host_path, cfg)
            .map(ChildFs::File)
            .map_err(|error| open_error("file", error))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "mount {:?}: host path {} is neither a directory nor a regular file",
                child.name,
                child.host_path.display()
            ),
        ))
    }
}

/// Combine an attachment id and a child-local inode or handle number.
pub(super) fn encode(id: u64, inner: u64) -> io::Result<u64> {
    if inner > INNER_MASK {
        return Err(io::Error::from_raw_os_error(LINUX_EOVERFLOW));
    }
    Ok((id << ID_SHIFT) | inner)
}

/// Split a guest inode or handle number into attachment id and child-local number.
pub(super) fn decode(guest: u64) -> (u64, u64) {
    (guest >> ID_SHIFT, guest & INNER_MASK)
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || name.len() > MAX_NAME_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "mount name {name:?} must be one path component of at most {MAX_NAME_BYTES} bytes"
            ),
        ));
    }
    Ok(())
}

fn name_error(errno: i32, name: &str, what: &str) -> io::Error {
    let kind = io::Error::from_raw_os_error(errno).kind();
    io::Error::new(kind, format!("mount {name:?} {what}"))
}
