//! Live mount-table filesystem backend.
//!
//! `MountTableFs` serves one virtio-fs device whose root is a synthetic,
//! read-only directory. Each entry of the root is a child: a name mapped to
//! its own passthrough backend over a host directory. Children are attached,
//! detached and switched between read-only and read-write while the guest
//! runs, through a shared [`MountTable`] handle.

mod fs;
mod table;

#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use fs::MountTableFs;
pub use table::{MountTable, MountTableChild};
