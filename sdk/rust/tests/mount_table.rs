//! Live mount-table behavior proven from inside a booted guest.
//!
//! One VM serves a mount table with a disk-backed child and a tmpfs-backed
//! child. The test attaches, switches and detaches children over the control
//! socket while guest processes hold files and a working directory inside
//! them. `#[ignore]`-gated via `#[msb_test]`; needs KVM (Linux) or
//! Hypervisor.framework (macOS):
//!
//!     cargo nextest run -p microsandbox --test mount_table --run-ignored=only

#![cfg(unix)]

use std::path::{Path, PathBuf};

use microsandbox::Sandbox;
use microsandbox::sandbox::{
    MountChange, MountTableCache, MountTableChild, MountTableSpec, StatVirtualization,
};
use test_utils::msb_test;

const IMAGE: &str = "mirror.gcr.io/library/alpine";
const ROOT: &str = "/mnt/distributed";

/// Holds write handles in both children, a read handle and a working
/// directory in the disk child, then reports each operation's exit status
/// after the host switches modes and detaches. `dd` writes to the inherited
/// descriptor, so the guest kernel never reopens the file.
const HOLDER: &str = r#"
set -u
cd /mnt/distributed/disk/dir
exec 3>>/mnt/distributed/disk/held
exec 4>>/mnt/distributed/shm/held
exec 5</mnt/distributed/disk/marker
printf abcd > /tmp/payload
wait_for() { while [ ! -f "$1" ]; do sleep 0.05; done; }
touch /tmp/ready

wait_for /tmp/go-readonly
dd if=/tmp/payload bs=4 count=1 1>&3 2>/tmp/disk-write.err; echo "disk_write=$?" >> /tmp/readonly
dd if=/dev/null conv=fsync 1>&3 2>/tmp/disk-fsync.err; echo "disk_fsync=$?" >> /tmp/readonly
dd if=/tmp/payload bs=4 count=1 1>&4 2>/tmp/shm-write.err; echo "shm_write=$?" >> /tmp/readonly
dd if=/dev/null conv=fsync 1>&4 2>/tmp/shm-fsync.err; echo "shm_fsync=$?" >> /tmp/readonly
touch /tmp/done-readonly

wait_for /tmp/go-detach
cat <&5 >/tmp/held-read 2>/tmp/held-read.err; echo "held_read=$?" >> /tmp/detach
ls . >/dev/null 2>/tmp/cwd.err; echo "cwd_ls=$?" >> /tmp/detach
cat ./inside >/dev/null 2>/tmp/cwd-cat.err; echo "cwd_cat=$?" >> /tmp/detach
touch /tmp/done-detach
"#;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn mount_table_changes_apply_live_inside_the_guest() {
    let name = "mount-table-live";
    let disk = HostDir::new(&disk_root());
    let shm = HostDir::new(Path::new("/dev/shm"));
    std::fs::create_dir(disk.path.join("dir")).unwrap();
    std::fs::write(disk.path.join("dir/inside"), b"inside").unwrap();
    std::fs::write(disk.path.join("marker"), b"first attachment").unwrap();

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .replace()
        .mount_table(MountTableSpec {
            guest: ROOT.into(),
            children: vec![
                child("disk", &disk.path, false, MountTableCache::Auto),
                child("shm", &shm.path, false, MountTableCache::Never),
            ],
        })
        .create()
        .await
        .expect("create sandbox with a mount table");

    // Launch children are listed; the root is read-only and mounted nosuid,nodev.
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "disk\nshm");
    let mounts = sh(&sandbox, &format!("grep ' {ROOT} ' /proc/mounts")).await;
    assert!(mounts.contains("virtiofs"), "{mounts}");
    assert!(
        mounts.contains("nosuid") && mounts.contains("nodev"),
        "{mounts}"
    );
    let refused = sh_status(&sandbox, &format!("mkdir {ROOT}/new")).await;
    assert!(!refused.0, "the table root must refuse mkdir");

    // Guest writes reach the host directories; Strict stat virtualization
    // works on the tmpfs child (user.* xattrs).
    sh(&sandbox, &format!("echo guest > {ROOT}/disk/written")).await;
    sh(
        &sandbox,
        &format!("echo secret > {ROOT}/shm/token && chmod 0400 {ROOT}/shm/token"),
    )
    .await;
    assert_eq!(
        std::fs::read(disk.path.join("written")).unwrap(),
        b"guest\n"
    );
    assert_eq!(std::fs::read(shm.path.join("token")).unwrap(), b"secret\n");
    assert_eq!(
        sh(&sandbox, &format!("stat -c %a {ROOT}/shm/token")).await,
        "400"
    );

    // Attach is visible without a reboot; a read-only child refuses with EROFS.
    let ro = HostDir::new(&disk_root());
    std::fs::write(ro.path.join("existing"), b"read me").unwrap();
    sandbox
        .attach_mount(child("ro", &ro.path, true, MountTableCache::Auto))
        .await
        .expect("attach read-only child");
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "disk\nro\nshm");
    assert_eq!(
        sh(&sandbox, &format!("cat {ROOT}/ro/existing")).await,
        "read me"
    );
    let (ok, output) = sh_status(&sandbox, &format!("echo x > {ROOT}/ro/new")).await;
    assert!(!ok && output.contains("Read-only file system"), "{output}");
    let (ok, output) = sh_status(&sandbox, &format!("rm {ROOT}/ro/existing")).await;
    assert!(!ok && output.contains("Read-only file system"), "{output}");

    // Start the holder, then switch both writable children to read-only.
    sh(
        &sandbox,
        &format!(
            "cat > /tmp/holder.sh <<'EOF'\n{HOLDER}\nEOF\n\
             setsid sh /tmp/holder.sh >/tmp/holder.log 2>&1 </dev/null &\n\
             while [ ! -f /tmp/ready ]; do sleep 0.05; done"
        ),
    )
    .await;
    sandbox
        .update_mounts(vec![
            MountChange::SetMode {
                name: "disk".into(),
                readonly: true,
            },
            MountChange::SetMode {
                name: "shm".into(),
                readonly: true,
            },
        ])
        .await
        .expect("switch to read-only");
    let readonly = run_step(&sandbox, "readonly").await;
    println!("held write handles after the read-only switch:\n{readonly}");
    // Writes through handles opened before the switch fail at write(), for
    // the cached child and for the never-cached child alike.
    assert!(readonly.contains("disk_write=1"), "{readonly}");
    assert!(readonly.contains("shm_write=1"), "{readonly}");
    assert!(
        sh(&sandbox, "cat /tmp/disk-write.err /tmp/shm-write.err")
            .await
            .contains("Read-only file system")
    );
    assert_eq!(std::fs::read(disk.path.join("held")).unwrap(), b"");
    assert_eq!(std::fs::read(shm.path.join("held")).unwrap(), b"");

    // Detach while the holder keeps a read handle and its cwd in the child.
    sandbox
        .detach_mount("disk")
        .await
        .expect("detach disk child");
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "ro\nshm");
    let detach = run_step(&sandbox, "detach").await;
    println!("held handles after detach:\n{detach}");
    assert!(detach.contains("held_read=1"), "{detach}");
    assert!(detach.contains("cwd_ls=1"), "{detach}");
    assert!(detach.contains("cwd_cat=1"), "{detach}");
    let errors = sh(
        &sandbox,
        "cat /tmp/held-read.err /tmp/cwd.err /tmp/cwd-cat.err",
    )
    .await;
    assert_eq!(
        errors.matches("Stale file handle").count(),
        3,
        "every held access must fail with ESTALE:\n{errors}"
    );

    // Re-attaching the name over new content shows the new content and never
    // the old inodes.
    let fresh = HostDir::new(&disk_root());
    std::fs::write(fresh.path.join("marker"), b"second attachment").unwrap();
    sandbox
        .attach_mount(child("disk", &fresh.path, false, MountTableCache::Auto))
        .await
        .expect("re-attach disk child");
    assert_eq!(
        sh(&sandbox, &format!("cat {ROOT}/disk/marker")).await,
        "second attachment"
    );
    let (ok, _) = sh_status(&sandbox, &format!("test -e {ROOT}/disk/dir")).await;
    assert!(!ok, "the re-attached child must not show the old directory");

    // A failed change stops the batch and keeps earlier changes applied.
    let error = sandbox
        .update_mounts(vec![
            MountChange::Detach { name: "ro".into() },
            MountChange::Detach {
                name: "missing".into(),
            },
        ])
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            microsandbox::MicrosandboxError::ControlMountBatch {
                applied_count: 1,
                failed_index: 1,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "disk\nshm");

    // The table's children cannot be captured, so a live fork is refused up front.
    let Err(error) = sandbox.fork("mount-table-live-fork").fork().await else {
        panic!("a live fork of a sandbox with a mount table must be refused");
    };
    assert!(
        error.to_string().contains("checkpoint") || error.to_string().contains("branch"),
        "{error}"
    );
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "disk\nshm");

    sandbox.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A canonical host directory removed when the test ends.
struct HostDir {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl HostDir {
    fn new(parent: &Path) -> Self {
        let dir = tempfile::tempdir_in(parent).unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        Self { path, _dir: dir }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Cargo's per-target scratch directory, on the build disk rather than tmpfs.
fn disk_root() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

fn child(name: &str, host: &Path, readonly: bool, cache: MountTableCache) -> MountTableChild {
    MountTableChild {
        name: name.into(),
        host: host.into(),
        readonly,
        quota_bytes: None,
        stat_virtualization: StatVirtualization::Strict,
        cache,
    }
}

async fn sh(sandbox: &Sandbox, script: &str) -> String {
    let (ok, output) = sh_status(sandbox, script).await;
    assert!(ok, "guest command failed: {script}\n{output}");
    output
}

async fn sh_status(sandbox: &Sandbox, script: &str) -> (bool, String) {
    let output = sandbox.shell(script).await.expect("exec");
    let text = format!(
        "{}{}",
        output.stdout().unwrap_or_default(),
        output.stderr().unwrap_or_default()
    );
    (output.status().success, text.trim().to_string())
}

/// Release one holder step and wait in the guest until it has reported.
async fn run_step(sandbox: &Sandbox, step: &str) -> String {
    sh(
        sandbox,
        &format!(
            "touch /tmp/go-{step}; while [ ! -f /tmp/done-{step} ]; do sleep 0.05; done; cat /tmp/{step}"
        ),
    )
    .await
}
