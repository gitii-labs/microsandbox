//! The shared, runtime-updatable table of mount children.

use std::{
    collections::{BTreeMap, HashMap},
    io,
    path::PathBuf,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::Duration,
};

use super::MountTableFs;
use crate::{
    DynFileSystem, FsOptions,
    backends::passthroughfs::{
        CachePolicy, HostPermissions, PassthroughConfig, PassthroughFs, StatVirtualization,
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

/// One child to attach: a guest-visible name over a host directory.
#[derive(Debug, Clone)]
pub struct MountTableChild {
    /// Guest-visible name, one path component.
    pub name: String,

    /// Absolute, symlink-free host directory. Every path component is opened
    /// without following symlinks, so callers canonicalize a legitimately
    /// symlinked prefix (such as `/var` on macOS) first.
    pub host_path: PathBuf,

    /// Whether the child starts read-only. [`MountTable::set_readonly`] changes it later.
    pub readonly: bool,

    /// Guest-write byte budget for the child's directory; `None` is unlimited.
    pub quota_bytes: Option<u64>,

    /// Guest-visible metadata policy.
    ///
    /// [`StatVirtualization::Strict`] requires writable `user.*` xattrs on the
    /// host directory even for a read-only child, because the child can be
    /// switched to read-write later.
    pub stat_virtualization: StatVirtualization,

    /// Whether guest permission changes reach the host inode.
    pub host_permissions: HostPermissions,

    /// Guest caching. [`CachePolicy::Never`] also sets zero entry and
    /// attribute timeouts, for content that must not linger in guest memory.
    pub cache_policy: CachePolicy,
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

#[derive(Default)]
pub(super) struct TableState {
    pub(super) children: RwLock<Children>,
    /// Held shared by every device operation on a child. A mode switch or
    /// detach takes it exclusively before replying, so no operation that
    /// began under the old state is still running when the caller proceeds.
    /// The wait lasts as long as the longest operation in flight, so a slow
    /// host filesystem under a child also delays mode switches and detaches.
    pub(super) ops: RwLock<()>,
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
    pub(super) fs: PassthroughFs,
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
    /// Fails with `EEXIST` when the name is attached and `EINVAL` when it is
    /// not one path component. The child's inode numbers carry an attachment
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

        let timeout = match child.cache_policy {
            CachePolicy::Never => Duration::ZERO,
            CachePolicy::Auto | CachePolicy::Always => PassthroughConfig::default().attr_timeout,
        };
        let cfg = PassthroughConfig {
            root_dir: child.host_path.clone(),
            no_symlink_root: true,
            stat_virtualization: child.stat_virtualization,
            host_permissions: child.host_permissions,
            // Probe for the strongest access the child can later be switched to.
            readonly: false,
            entry_timeout: timeout,
            attr_timeout: timeout,
            cache_policy: child.cache_policy,
            writeback: false,
            inject_init: false,
            quota_bytes: child.quota_bytes,
            ..Default::default()
        };
        let fs = PassthroughFs::new(cfg).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "mount {:?}: cannot open host directory {}: {error}",
                    child.name,
                    child.host_path.display()
                ),
            )
        })?;
        fs.set_readonly(child.readonly);
        // Registers the child's root inode. The negotiated options belong to
        // the table device; a child never enables writeback caching.
        fs.init(FsOptions::empty())?;

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
        children.by_id.insert(id, Arc::new(Child { id, fs }));
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
