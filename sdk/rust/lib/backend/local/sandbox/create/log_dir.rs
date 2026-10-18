//! Caller-chosen log directory: admission checks and the `<sandbox>/logs` link.
//!
//! The runtime, `msb logs` and every SDK reach a sandbox's logs through the
//! deterministic `<sandbox>/logs` path. A caller-chosen directory is linked
//! there with a symlink, so releases that predate the option follow it too.

use std::path::{Component, Path, PathBuf};

use microsandbox_types::{RootDisk, RootfsSource, VolumeMount};

use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check the caller-chosen `log_dir` and create it.
///
/// The directory must not overlap host storage that is removed with a sandbox
/// (the sandboxes directory) or that a guest can write (the volumes directory,
/// and this sandbox's bind and disk sources). A guest that can write the log
/// directory could plant symlinks that make the runtime or libkrun write
/// through them. Both sides are compared as canonical paths: the log
/// directory before it is created, using its nearest existing ancestor, and
/// again after creation.
pub(super) fn prepare_log_dir(
    config: &SandboxConfig,
    sandboxes_dir: &Path,
    volumes_dir: &Path,
    log_dir: &Path,
) -> MicrosandboxResult<()> {
    let protected = protected_host_paths(config, sandboxes_dir, volumes_dir)?;
    check_overlap(log_dir, &canonical_target(log_dir)?, &protected)?;
    std::fs::create_dir_all(log_dir).map_err(|error| {
        MicrosandboxError::InvalidConfig(format!(
            "cannot create log directory {}: {error}",
            log_dir.display()
        ))
    })?;
    check_overlap(log_dir, &std::fs::canonicalize(log_dir)?, &protected)
}

/// Make `<sandbox_dir>/logs` a symlink to the caller-chosen `log_dir`.
///
/// The symlink is the durable record of the choice. Removing the sandbox
/// directory unlinks it without following it. A `boot-error.json` left by an
/// earlier sandbox that used the same directory is removed, so a startup
/// failure of this sandbox is not confused with it.
#[cfg(unix)]
pub(super) fn link_log_dir(sandbox_dir: &Path, log_dir: &Path) -> MicrosandboxResult<()> {
    let link = sandbox_dir.join("logs");
    std::fs::create_dir_all(sandbox_dir)
        .and_then(|()| std::os::unix::fs::symlink(log_dir, &link))
        .map_err(|error| {
            MicrosandboxError::Runtime(format!(
                "cannot link {} to log directory {}: {error}",
                link.display(),
                log_dir.display()
            ))
        })?;
    microsandbox_runtime::boot_error::BootError::delete(log_dir)?;
    Ok(())
}

/// Caller-chosen log directories are rejected on Windows during path resolution.
#[cfg(not(unix))]
pub(super) fn link_log_dir(_sandbox_dir: &Path, log_dir: &Path) -> MicrosandboxResult<()> {
    Err(MicrosandboxError::InvalidConfig(format!(
        "log directory {} is not supported on this platform",
        log_dir.display()
    )))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Host paths a log directory must neither be inside nor contain, canonicalized and labelled.
fn protected_host_paths(
    config: &SandboxConfig,
    sandboxes_dir: &Path,
    volumes_dir: &Path,
) -> MicrosandboxResult<Vec<(PathBuf, &'static str)>> {
    let mut paths: Vec<(&Path, &'static str)> = vec![
        (sandboxes_dir, "sandboxes directory"),
        (volumes_dir, "volumes directory"),
    ];
    match &config.spec.image {
        RootfsSource::Bind { path, .. } => paths.push((path, "bind rootfs")),
        RootfsSource::DiskImage { path, .. } => paths.push((path, "root disk image")),
        RootfsSource::Oci(oci) => {
            if let Some(RootDisk::DiskImage { path, .. }) = &oci.root_disk {
                paths.push((path, "root disk image"));
            }
        }
    }
    for mount in &config.spec.mounts {
        match mount {
            VolumeMount::Bind { host, .. } => paths.push((host, "bind mount source")),
            VolumeMount::DiskImage { host, .. } => paths.push((host, "disk mount source")),
            VolumeMount::Owned { .. } | VolumeMount::Named { .. } | VolumeMount::Tmpfs { .. } => {}
        }
    }
    if let Some(table) = &config.spec.mount_table {
        for child in &table.children {
            paths.push((&child.host, "mount-table source"));
        }
    }
    paths
        .into_iter()
        .map(|(path, label)| Ok((canonical_target(path)?, label)))
        .collect()
}

/// Reject `canonical`, the canonical form of `log_dir`, when it is inside or contains a protected path.
fn check_overlap(
    log_dir: &Path,
    canonical: &Path,
    protected: &[(PathBuf, &'static str)],
) -> MicrosandboxResult<()> {
    for (path, label) in protected {
        if canonical.starts_with(path) || path.starts_with(canonical) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "log directory {} overlaps the {label} {}; choose a directory outside sandbox and guest-writable storage",
                log_dir.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

/// Canonical form of `path`, which need not exist yet.
///
/// The nearest existing ancestor is canonicalized, resolving symlinks and `..`
/// in it. The missing remainder cannot contain symlinks, so it is appended
/// lexically, with `..` removing the previous component as directory creation
/// would.
fn canonical_target(path: &Path) -> MicrosandboxResult<PathBuf> {
    let components: Vec<Component<'_>> = path.components().collect();
    for split in (1..=components.len()).rev() {
        let prefix: PathBuf = components[..split].iter().collect();
        match std::fs::canonicalize(&prefix) {
            Ok(mut resolved) => {
                for component in &components[split..] {
                    match component {
                        Component::Normal(name) => resolved.push(name),
                        Component::ParentDir => {
                            resolved.pop();
                        }
                        Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
                    }
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "cannot resolve {}: {error}",
                    prefix.display()
                )));
            }
        }
    }
    Err(MicrosandboxError::InvalidConfig(format!(
        "cannot resolve {}: no existing ancestor",
        path.display()
    )))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use microsandbox_types::{HostPermissions, StatVirtualization};
    use tempfile::tempdir;

    use super::*;

    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
        sandboxes: PathBuf,
        volumes: PathBuf,
    }

    fn fixture() -> Fixture {
        let root = tempdir().unwrap();
        let canonical = fs::canonicalize(root.path()).unwrap();
        let sandboxes = canonical.join("home/sandboxes");
        let volumes = canonical.join("home/volumes");
        fs::create_dir_all(&sandboxes).unwrap();
        fs::create_dir_all(&volumes).unwrap();
        Fixture {
            _root: root,
            root: canonical,
            sandboxes,
            volumes,
        }
    }

    fn prepare(
        fixture: &Fixture,
        config: &SandboxConfig,
        log_dir: &Path,
    ) -> MicrosandboxResult<()> {
        prepare_log_dir(config, &fixture.sandboxes, &fixture.volumes, log_dir)
    }

    fn assert_rejected(fixture: &Fixture, config: &SandboxConfig, log_dir: &Path, label: &str) {
        let existed = log_dir.exists();
        let error = prepare(fixture, config, log_dir).unwrap_err().to_string();
        assert!(error.contains(label), "{log_dir:?}: {error}");
        assert!(
            existed || !log_dir.exists(),
            "{log_dir:?} was created before rejection"
        );
    }

    fn bind(host: PathBuf) -> VolumeMount {
        VolumeMount::Bind {
            host,
            guest: "/data".into(),
            options: Default::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: None,
        }
    }

    #[test]
    fn accepts_and_creates_an_unrelated_directory() {
        let fixture = fixture();
        let log_dir = fixture.root.join("node/logs/topic");

        prepare(&fixture, &SandboxConfig::default(), &log_dir).unwrap();

        assert!(log_dir.is_dir());
    }

    #[test]
    fn rejects_the_sandbox_directory_and_anything_under_the_sandboxes_directory() {
        let fixture = fixture();
        let config = SandboxConfig::default();
        let own = fixture.sandboxes.join("topic");
        for log_dir in [
            own.clone(),
            own.join("logs"),
            fixture.sandboxes.join("other-topic"),
            fixture.root.join("home"),
        ] {
            assert_rejected(&fixture, &config, &log_dir, "sandboxes directory");
        }
    }

    #[test]
    fn rejects_dot_dot_paths_that_lead_into_the_sandboxes_directory() {
        let fixture = fixture();
        let log_dir = fixture.root.join("missing/../home/sandboxes/topic/logs");

        let error = prepare(&fixture, &SandboxConfig::default(), &log_dir).unwrap_err();

        assert!(error.to_string().contains("sandboxes directory"), "{error}");
        assert!(!fixture.sandboxes.join("topic").exists());
    }

    #[test]
    fn rejects_a_symlinked_parent_that_leads_into_the_sandboxes_directory() {
        let fixture = fixture();
        let alias = fixture.root.join("alias");
        std::os::unix::fs::symlink(&fixture.sandboxes, &alias).unwrap();
        let log_dir = alias.join("topic");

        let error = prepare(&fixture, &SandboxConfig::default(), &log_dir).unwrap_err();

        assert!(error.to_string().contains("sandboxes directory"), "{error}");
        assert!(!fixture.sandboxes.join("topic").exists());
    }

    #[test]
    fn rejects_guest_writable_storage() {
        let fixture = fixture();
        let share = fixture.root.join("outer/share");
        fs::create_dir_all(&share).unwrap();
        let mut config = SandboxConfig::default();
        config.spec.mounts.push(bind(share.clone()));

        assert_rejected(&fixture, &config, &share.join("logs"), "bind mount source");
        // A log directory containing the share would expose it too.
        let parent = fixture.root.join("outer");
        let error = prepare(&fixture, &config, &parent).unwrap_err().to_string();
        assert!(error.contains("bind mount source"), "{error}");
        assert_rejected(
            &fixture,
            &SandboxConfig::default(),
            &fixture.volumes.join("data/logs"),
            "volumes directory",
        );
    }

    #[test]
    fn reports_an_uncreatable_directory_with_its_path() {
        let fixture = fixture();
        let blocker = fixture.root.join("file");
        fs::write(&blocker, b"").unwrap();
        let log_dir = blocker.join("logs");

        let error = prepare(&fixture, &SandboxConfig::default(), &log_dir).unwrap_err();

        assert!(
            error.to_string().contains(&blocker.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn link_routes_logs_and_survives_sandbox_removal() {
        let fixture = fixture();
        let sandbox_dir = fixture.sandboxes.join("topic");
        let log_dir = fixture.root.join("node/logs/topic");
        prepare(&fixture, &SandboxConfig::default(), &log_dir).unwrap();
        // A boot error from an earlier sandbox that used this directory is stale.
        fs::write(log_dir.join("boot-error.json"), b"{}").unwrap();

        link_log_dir(&sandbox_dir, &log_dir).unwrap();
        assert!(!log_dir.join("boot-error.json").exists());
        // Writers and readers use the deterministic path; the bytes land in the chosen directory.
        fs::write(sandbox_dir.join("logs/runtime.log"), b"boot\n").unwrap();
        assert_eq!(fs::read(log_dir.join("runtime.log")).unwrap(), b"boot\n");
        assert_eq!(fs::read_link(sandbox_dir.join("logs")).unwrap(), log_dir);

        crate::sandbox::remove_dir_if_exists(&sandbox_dir).unwrap();

        assert!(!sandbox_dir.exists());
        assert_eq!(fs::read(log_dir.join("runtime.log")).unwrap(), b"boot\n");
    }

    #[test]
    fn link_refuses_an_existing_logs_entry() {
        let fixture = fixture();
        let sandbox_dir = fixture.sandboxes.join("topic");
        fs::create_dir_all(sandbox_dir.join("logs")).unwrap();
        fs::write(sandbox_dir.join("logs/runtime.log"), b"old").unwrap();

        let error = link_log_dir(&sandbox_dir, &fixture.root.join("elsewhere")).unwrap_err();

        assert!(error.to_string().contains("cannot link"), "{error}");
        assert_eq!(
            fs::read(sandbox_dir.join("logs/runtime.log")).unwrap(),
            b"old"
        );
    }
}
