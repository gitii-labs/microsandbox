//! Live mount-table behavior proven from inside a booted guest.
//!
//! One VM serves a mount table with a disk-backed child and a tmpfs-backed
//! child. The test attaches, switches and detaches children over the control
//! socket while guest processes hold files and a working directory inside
//! them. A second VM serves file children, replaced on the host by rename,
//! and children with an owner, written by a guest user whose uid differs
//! from the host user's. `#[ignore]`-gated via `#[msb_test]`; needs KVM (Linux) or
//! Hypervisor.framework (macOS):
//!
//!     cargo nextest run -p microsandbox --test mount_table --run-ignored=only

#![cfg(unix)]

use std::path::{Path, PathBuf};

use microsandbox::Sandbox;
use microsandbox::sandbox::{
    HostPermissions, MountChange, MountTableCache, MountTableChild, MountTableOwner,
    MountTableSpec, StatVirtualization,
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
# Give up after 60 s so a stuck step fails the test instead of hanging it.
wait_for() { i=0; while [ ! -f "$1" ]; do i=$((i+1)); [ "$i" -gt 1200 ] && exit 1; sleep 0.05; done; }
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
    // Mirror host permissions: a guest chmod reaches the host inode.
    sh(&sandbox, &format!("chmod 0750 {ROOT}/disk/written")).await;
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(disk.path.join("written"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o750);
    }
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
             {}",
            bounded_wait("/tmp/ready")
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
    for file in ["/tmp/disk-write.err", "/tmp/shm-write.err"] {
        let error = sh(&sandbox, &format!("cat {file}")).await;
        assert!(error.contains("Read-only file system"), "{file}: {error}");
    }
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
    for file in ["/tmp/held-read.err", "/tmp/cwd.err", "/tmp/cwd-cat.err"] {
        let error = sh(&sandbox, &format!("cat {file}")).await;
        assert!(error.contains("Stale file handle"), "{file}: {error}");
    }

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

    // Mount updates never touch the VM, so they apply while it is user-paused.
    sandbox.pause().await.expect("pause");
    sandbox
        .set_mount_readonly("shm", false)
        .await
        .expect("update while paused");
    sandbox.resume().await.expect("resume");
    sh(&sandbox, &format!("echo again > {ROOT}/shm/after-pause")).await;

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

/// Holds a write handle on the text file child and a read handle on the
/// secret file child, then reports each operation's exit status after the
/// host switches the text child to read-only and detaches the secret child.
const FILE_HOLDER: &str = r#"
set -u
exec 3>>/mnt/distributed/text
exec 4</mnt/distributed/secret
printf abcd > /tmp/payload
wait_for() { i=0; while [ ! -f "$1" ]; do i=$((i+1)); [ "$i" -gt 1200 ] && exit 1; sleep 0.05; done; }
touch /tmp/ready

wait_for /tmp/go-readonly
dd if=/tmp/payload bs=4 count=1 1>&3 2>/tmp/text-write.err; echo "text_write=$?" >> /tmp/readonly
touch /tmp/done-readonly

wait_for /tmp/go-detach
cat <&4 >/dev/null 2>/tmp/secret-read.err; echo "secret_read=$?" >> /tmp/detach
touch /tmp/done-detach
"#;

/// The guest user that writes into owned children. It differs from the host
/// user running the test, as uid 1000 in the guest differs from uid 501 on a
/// macOS node.
const AGENT_UID: u32 = 2000;

#[msb_test]
async fn mount_table_file_children_and_owners_inside_the_guest() {
    let name = "mount-table-files";
    let disk = HostDir::new(&disk_root());
    let shm = HostDir::new(Path::new("/dev/shm"));
    let text = disk.path.join("text");
    std::fs::write(&text, b"first").unwrap();
    let secret = shm.path.join("secret");
    std::fs::write(&secret, b"s3cret").unwrap();
    let host_uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&text).unwrap().uid()
    };
    assert_ne!(
        host_uid, AGENT_UID,
        "the agent uid must differ from the host user"
    );

    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .replace()
        .mount_table(MountTableSpec {
            guest: ROOT.into(),
            children: vec![file_child("text", &text, false, MountTableCache::Auto)],
        })
        .create()
        .await
        .expect("create sandbox with a file child");
    sandbox
        .attach_mount(file_child("secret", &secret, true, MountTableCache::Never))
        .await
        .expect("attach secret file child");

    // Both children are regular files at the table root.
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "secret\ntext");
    assert_eq!(
        sh(&sandbox, &format!("stat -c %F {ROOT}/text {ROOT}/secret")).await,
        "regular file\nregular file"
    );
    assert_eq!(sh(&sandbox, &format!("cat {ROOT}/text")).await, "first");
    assert_eq!(sh(&sandbox, &format!("cat {ROOT}/secret")).await, "s3cret");
    let (ok, output) = sh_status(&sandbox, &format!("echo x > {ROOT}/secret")).await;
    assert!(!ok && output.contains("Read-only file system"), "{output}");

    // A guest write reaches the host file.
    sh(&sandbox, &format!("printf guest > {ROOT}/text")).await;
    assert_eq!(std::fs::read(&text).unwrap(), b"guest");

    // The child follows the path: after the host renames a new file into
    // place, the guest's next open shows the new content, each time.
    for content in ["second", "third, and longer than before"] {
        replace_by_rename(&text, content.as_bytes());
        assert_eq!(sh(&sandbox, &format!("cat {ROOT}/text")).await, content);
    }
    replace_by_rename(&secret, b"rotated");
    assert_eq!(sh(&sandbox, &format!("cat {ROOT}/secret")).await, "rotated");

    // Switch the text child to read-only while a write handle is held, then
    // detach the secret child while a read handle is held.
    sh(
        &sandbox,
        &format!(
            "cat > /tmp/holder.sh <<'EOF'\n{FILE_HOLDER}\nEOF\n\
             setsid sh /tmp/holder.sh >/tmp/holder.log 2>&1 </dev/null &\n\
             {}",
            bounded_wait("/tmp/ready")
        ),
    )
    .await;
    sandbox
        .set_mount_readonly("text", true)
        .await
        .expect("switch text child to read-only");
    let readonly = run_step(&sandbox, "readonly").await;
    assert!(readonly.contains("text_write=1"), "{readonly}");
    let error = sh(&sandbox, "cat /tmp/text-write.err").await;
    assert!(error.contains("Read-only file system"), "{error}");
    assert_eq!(
        std::fs::read(&text).unwrap(),
        b"third, and longer than before"
    );

    sandbox
        .detach_mount("secret")
        .await
        .expect("detach secret child");
    assert_eq!(sh(&sandbox, &format!("ls {ROOT}")).await, "text");
    let detach = run_step(&sandbox, "detach").await;
    assert!(detach.contains("secret_read=1"), "{detach}");
    let error = sh(&sandbox, "cat /tmp/secret-read.err").await;
    assert!(error.contains("Stale file handle"), "{error}");

    // Owner: host entries owned by the host user show as the agent, who can
    // write them; the same directory without an owner refuses the agent.
    let work = HostDir::new(&disk_root());
    std::fs::write(work.path.join("existing"), b"host\n").unwrap();
    let plain = HostDir::new(&disk_root());
    let item = disk.path.join("item");
    std::fs::write(&item, b"item\n").unwrap();
    let owner = Some(MountTableOwner {
        uid: AGENT_UID,
        gid: AGENT_UID,
    });
    sandbox
        .update_mounts(vec![
            MountChange::Attach {
                child: MountTableChild {
                    owner,
                    ..file_child("work", &work.path, false, MountTableCache::Auto)
                },
            },
            MountChange::Attach {
                child: MountTableChild {
                    owner,
                    ..file_child("item", &item, false, MountTableCache::Auto)
                },
            },
            MountChange::Attach {
                child: file_child("plain", &plain.path, false, MountTableCache::Auto),
            },
        ])
        .await
        .expect("attach owned children");
    let agent = format!("{AGENT_UID}:{AGENT_UID}");
    let owners = sh_as(
        &sandbox,
        &agent,
        &format!(
            "set -e; cd {ROOT}; echo guest > work/new; echo more >> work/existing; \
             mkdir work/sub; echo nested > work/sub/file; echo agent >> item; \
             stat -c %u:%g work work/existing work/new work/sub/file item"
        ),
    )
    .await;
    assert_eq!(owners, [agent.as_str(); 5].join("\n"));
    let (ok, output) = sh_status_as(&sandbox, &agent, &format!("echo x > {ROOT}/plain/new")).await;
    assert!(!ok && output.contains("Permission denied"), "{output}");
    assert_eq!(
        sh(&sandbox, &format!("stat -c %u {ROOT}/plain")).await,
        host_uid.to_string()
    );

    // The host files keep the host user as owner, created ones included.
    for path in [
        work.path.join("new"),
        work.path.join("existing"),
        work.path.join("sub/file"),
        item.clone(),
    ] {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().uid(),
            host_uid,
            "{path:?}"
        );
    }
    assert_eq!(std::fs::read(work.path.join("new")).unwrap(), b"guest\n");
    assert_eq!(
        std::fs::read(work.path.join("existing")).unwrap(),
        b"host\nmore\n"
    );
    assert_eq!(std::fs::read(&item).unwrap(), b"item\nagent\n");

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
        host_permissions: HostPermissions::Mirror,
        cache,
        owner: None,
    }
}

/// A child as Distributed attaches one: relaxed stat virtualization, mirrored
/// host permissions.
fn file_child(name: &str, host: &Path, readonly: bool, cache: MountTableCache) -> MountTableChild {
    MountTableChild {
        stat_virtualization: StatVirtualization::Relaxed,
        ..child(name, host, readonly, cache)
    }
}

/// Replace `path` the way the node does: write a sibling, rename it into place.
fn replace_by_rename(path: &Path, content: &[u8]) {
    let staged = path.with_extension("staged");
    std::fs::write(&staged, content).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

async fn sh_as(sandbox: &Sandbox, user: &str, script: &str) -> String {
    let (ok, output) = sh_status_as(sandbox, user, script).await;
    assert!(ok, "guest command as {user} failed: {script}\n{output}");
    output
}

async fn sh_status_as(sandbox: &Sandbox, user: &str, script: &str) -> (bool, String) {
    let output = sandbox
        .shell_with(script, |exec| exec.user(user))
        .await
        .expect("exec");
    let text = format!(
        "{}{}",
        output.stdout().unwrap_or_default(),
        output.stderr().unwrap_or_default()
    );
    (output.status().success, text.trim().to_string())
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
            "touch /tmp/go-{step}; {}; cat /tmp/{step}",
            bounded_wait(&format!("/tmp/done-{step}"))
        ),
    )
    .await
}

/// A guest shell loop waiting at most 60 s for `path`, printing the holder log on timeout.
fn bounded_wait(path: &str) -> String {
    format!(
        "i=0; while [ ! -f {path} ]; do i=$((i+1)); if [ \"$i\" -gt 1200 ]; then \
         echo \"timed out waiting for {path}\"; cat /tmp/holder.log; exit 1; fi; sleep 0.05; done"
    )
}
