//! Live changes to a running sandbox's mount table.

use microsandbox_control_client::{MountsResult, UpdateMounts};
use microsandbox_protocol::control::{MountChange, MountsUpdate};
use microsandbox_types::{MountTableChild, MountWriteCursor, MountWrites};

use crate::backend::sandbox::SandboxIdentity;
use crate::backend::{Backend, LocalBackend};
use crate::error::{Operation, UnsupportedReason};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Sandbox, SandboxHandle, modify};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Wait for successful guest mount mutations without waiting for close or fsync.
    /// None returns an initial snapshot; reuse its cursor for event-driven waits.
    /// Dropping the future cancels the connection. Older runtimes reject this operation.
    pub async fn watch_mount_writes(
        &self,
        cursor: Option<MountWriteCursor>,
    ) -> MicrosandboxResult<MountWrites> {
        watch_mount_writes(
            self.name(),
            self.identity(),
            self.backend().as_ref(),
            cursor,
        )
        .await
    }

    /// Apply mount-table changes in order while the sandbox runs.
    ///
    /// The batch stops at the first failed change with
    /// [`MicrosandboxError::ControlMountBatch`]; earlier changes stay applied.
    /// Changes are not written back to the sandbox's configuration, so a
    /// restart attaches only the children it was created with.
    pub async fn update_mounts(&self, changes: Vec<MountChange>) -> MicrosandboxResult<()> {
        update_mounts(
            self.name(),
            self.identity(),
            self.backend().as_ref(),
            changes,
        )
        .await
    }

    /// Attach a child to the mount table under a name that is not attached.
    pub async fn attach_mount(&self, child: MountTableChild) -> MicrosandboxResult<()> {
        self.update_mounts(vec![MountChange::Attach { child }])
            .await
    }

    /// Detach a child. Files and directories the guest holds in it fail with `ESTALE`.
    pub async fn detach_mount(&self, name: impl Into<String>) -> MicrosandboxResult<()> {
        self.update_mounts(vec![MountChange::Detach { name: name.into() }])
            .await
    }

    /// Switch a child between read-only and read-write. Read-only also
    /// refuses writes through files the guest opened before the switch.
    pub async fn set_mount_readonly(
        &self,
        name: impl Into<String>,
        readonly: bool,
    ) -> MicrosandboxResult<()> {
        self.update_mounts(vec![MountChange::SetMode {
            name: name.into(),
            readonly,
        }])
        .await
    }
}

impl SandboxHandle {
    /// Wait for retained mount mutations; see [`Sandbox::watch_mount_writes`].
    pub async fn watch_mount_writes(
        &self,
        cursor: Option<MountWriteCursor>,
    ) -> MicrosandboxResult<MountWrites> {
        watch_mount_writes(self.name(), self.identity(), self.backend.as_ref(), cursor).await
    }

    /// Apply mount-table changes in order without connecting to the guest.
    /// See [`Sandbox::update_mounts`].
    pub async fn update_mounts(&self, changes: Vec<MountChange>) -> MicrosandboxResult<()> {
        update_mounts(self.name(), self.identity(), self.backend.as_ref(), changes).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn watch_mount_writes(
    name: &str,
    identity: SandboxIdentity,
    backend: &dyn Backend,
    cursor: Option<MountWriteCursor>,
) -> MicrosandboxResult<MountWrites> {
    let operation = Operation::SandboxWatchMountWrites;
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(operation))?;
    let SandboxIdentity::Local(expected_id) = identity else {
        return Err(MicrosandboxError::local_only(operation));
    };
    let session = {
        let _transition =
            LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), name).await?;
        let run = local.control_run_identity(name, expected_id).await?;
        modify::control_session_for_run(local, name, run).await?
    };
    // Do not retain a lifecycle guard while waiting: stop and mount changes must proceed.
    match session.watch_mount_writes(cursor).await {
        Ok(writes) => Ok(writes),
        Err(error)
            if matches!(
                error.as_ref(),
                microsandbox_control_client::ControlClientError::LegacyRemote { .. }
            ) =>
        {
            Err(MicrosandboxError::unsupported(
                operation,
                UnsupportedReason::NotAvailable(
                    "mount mutation notifications require an updated runtime with a mount table"
                        .into(),
                ),
            ))
        }
        Err(error) => Err(MicrosandboxError::ControlClient(error)),
    }
}

async fn update_mounts(
    name: &str,
    identity: SandboxIdentity,
    backend: &dyn Backend,
    changes: Vec<MountChange>,
) -> MicrosandboxResult<()> {
    let operation = Operation::SandboxUpdateMounts;
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(operation))?;
    let SandboxIdentity::Local(expected_id) = identity else {
        return Err(MicrosandboxError::local_only(operation));
    };
    let _transition =
        LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), name).await?;
    let run = local.control_run_identity(name, expected_id).await?;
    let session = modify::control_session_for_run(local, name, run).await?;
    // Runtimes that predate mount tables, and sandboxes started without one,
    // report no capability; the request would otherwise fail less clearly.
    if !session.capabilities().mounts_update {
        return Err(MicrosandboxError::unsupported(
            operation,
            UnsupportedReason::NotAvailable(
                "the sandbox was started without a mount table, or by a runtime without mount-table support".into(),
            ),
        ));
    }
    match session
        .request(&UpdateMounts(MountsUpdate { changes }))
        .await
        .map_err(MicrosandboxError::ControlClient)?
    {
        MountsResult::Complete { .. } => Ok(()),
        MountsResult::Failed {
            applied_count,
            failed_index,
            error,
        } => Err(MicrosandboxError::ControlMountBatch {
            applied_count,
            failed_index,
            error,
        }),
    }
}
