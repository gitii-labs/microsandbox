//! End-to-end tests for log capture against a real microVM.
//!
//! Unlike `log_stream.rs` (which drives the engine against synthetic
//! on-disk layouts), these tests boot an alpine sandbox, run a real
//! exec session, and validate that the relay tap → `exec.log` →
//! `log_stream` / `read_logs` pipeline carries the produced bytes
//! through to a consumer with the right source tag, session id, and
//! cursor semantics.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test log_stream_e2e --run-ignored=only

use std::time::Duration;

use futures::{StreamExt, TryStreamExt};
use microsandbox::Sandbox;
use microsandbox::logs::{LogOptions, LogSource, LogStreamOptions, LogStreamStart};
use test_utils::msb_test;

const ALPINE: &str = "mirror.gcr.io/library/alpine";

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");
}

/// Snapshot path: after exec returns, the relay tap should have
/// flushed the session's stdout into `exec.log`, and `read_logs`
/// should surface it with `source = Stdout` and a real `session_id`.
#[msb_test]
async fn logs_captures_exec_stdout_from_running_sandbox() {
    let name = "log-stream-e2e-snapshot";
    let marker = "log-e2e-snapshot-marker-9f3a";

    let sandbox = Sandbox::builder(name)
        .image(ALPINE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    sandbox
        .exec("sh", ["-c", &format!("echo {marker}")])
        .await
        .expect("exec");

    let entries = sandbox
        .logs(&LogOptions::default())
        .await
        .expect("read logs");

    stop_and_remove(name).await;

    let matched: Vec<_> = entries.iter().filter(|e| contains(e, marker)).collect();
    assert!(
        !matched.is_empty(),
        "expected marker {marker:?} in snapshot logs; saw {} entries",
        entries.len(),
    );
    let entry = matched[0];
    assert_eq!(
        entry.source,
        LogSource::Stdout,
        "marker came in on the wrong source: {:?}",
        entry.source,
    );
    assert!(
        entry.session_id.is_some(),
        "exec-captured entry should carry a session id; got None",
    );
}

/// Follow path: open the stream first, then exec. The follower
/// must wake on the new write (via filesystem notify) and yield
/// the marker entry within a short timeout.
#[msb_test]
async fn log_stream_follow_catches_live_writes() {
    let name = "log-stream-e2e-follow";
    let marker = "log-e2e-follow-marker-7a4b";

    let sandbox = Sandbox::builder(name)
        .image(ALPINE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    // Start the stream at "now" so the boot-lifecycle entries are
    // skipped and the only matching entry should be from the exec
    // we run below.
    let cutoff = chrono::Utc::now();
    let stream = sandbox
        .log_stream(&LogStreamOptions {
            sources: Vec::new(),
            start: LogStreamStart::Since(cutoff),
            until: None,
            follow: true,
        })
        .await
        .expect("open log stream");

    sandbox
        .exec("sh", ["-c", &format!("echo {marker}")])
        .await
        .expect("exec");

    let found = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = std::pin::pin!(stream);
        while let Some(item) = stream.next().await {
            let entry = item.expect("stream item");
            if contains(&entry, marker) {
                return entry;
            }
        }
        panic!("stream ended without ever seeing marker {marker:?}");
    })
    .await
    .expect("marker arrived within timeout");

    stop_and_remove(name).await;

    assert_eq!(found.source, LogSource::Stdout);
}

/// Cursor resume: run exec A, capture its cursor from a snapshot,
/// run exec B, then open a fresh stream from that cursor. The
/// resumed stream must see B but not replay A.
#[msb_test]
async fn log_stream_resume_from_cursor_excludes_replayed_entries() {
    let name = "log-stream-e2e-resume";
    let marker_a = "log-e2e-resume-marker-A-3f9d";
    let marker_b = "log-e2e-resume-marker-B-8c2e";

    let sandbox = Sandbox::builder(name)
        .image(ALPINE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    sandbox
        .exec("sh", ["-c", &format!("echo {marker_a}")])
        .await
        .expect("exec A");

    let snapshot = sandbox
        .logs(&LogOptions::default())
        .await
        .expect("snapshot after exec A");
    let cursor_at_a = snapshot
        .iter()
        .rev()
        .find(|e| contains(e, marker_a))
        .expect("snapshot contained marker A")
        .cursor
        .clone();

    sandbox
        .exec("sh", ["-c", &format!("echo {marker_b}")])
        .await
        .expect("exec B");

    let resumed: Vec<_> = sandbox
        .log_stream(&LogStreamOptions {
            sources: Vec::new(),
            start: LogStreamStart::From(cursor_at_a),
            until: None,
            follow: false,
        })
        .await
        .expect("open resumed stream")
        .try_collect()
        .await
        .expect("drain resumed stream");

    stop_and_remove(name).await;

    let saw_a = resumed.iter().any(|e| contains(e, marker_a));
    let saw_b = resumed.iter().any(|e| contains(e, marker_b));
    assert!(
        saw_b,
        "resumed stream missing marker B (saw {} entries)",
        resumed.len()
    );
    assert!(
        !saw_a,
        "resumed stream replayed marker A from before the cursor"
    );
}

/// Caller-chosen log directory: logs land there, a restart keeps the
/// previous boot's kernel.log as an archive, readers see the files through
/// `<sandbox>/logs`, and removing the sandbox leaves the directory.
#[cfg(unix)]
#[msb_test]
async fn log_dir_receives_logs_and_survives_removal() {
    let name = "log-stream-e2e-log-dir";
    let marker = "log-e2e-log-dir-marker-5d1c";
    let chosen = tempfile::tempdir().expect("log dir");
    let log_dir = chosen.path().join("topic");

    let sandbox = Sandbox::builder(name)
        .image(ALPINE)
        .cpus(1)
        .memory(512)
        .log_dir(&log_dir)
        .replace()
        .create()
        .await
        .expect("create sandbox");
    sandbox
        .exec("sh", ["-c", &format!("echo {marker}")])
        .await
        .expect("exec");
    sandbox.stop().await.expect("stop");
    drop(sandbox);

    let kernel_first_boot = std::fs::read(log_dir.join("kernel.log")).expect("kernel.log");
    assert!(
        !kernel_first_boot.is_empty(),
        "first boot wrote no kernel output"
    );

    let restarted = Sandbox::start(name).await.expect("restart");
    let entries = restarted
        .logs(&LogOptions::default())
        .await
        .expect("read logs");
    restarted.stop().await.expect("stop restarted");
    drop(restarted);
    assert!(
        entries.iter().any(|e| contains(e, marker)),
        "marker from the first boot missing after restart"
    );

    // The first boot's kernel output survives the restart as an archive.
    let kernel_archives: Vec<_> = std::fs::read_dir(&log_dir)
        .expect("list log dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        .filter(|name| name.starts_with("kernel.log.") && name.contains('T'))
        .collect();
    assert_eq!(
        kernel_archives.len(),
        1,
        "kernel archives: {kernel_archives:?}"
    );

    // A removed log directory is reported by name instead of being recreated elsewhere.
    let moved = chosen.path().join("moved");
    std::fs::rename(&log_dir, &moved).expect("move log dir away");
    let error = Sandbox::start(name)
        .await
        .err()
        .expect("start without its log directory must fail");
    assert!(error.to_string().contains("is missing"), "{error}");
    std::fs::rename(&moved, &log_dir).expect("restore log dir");

    Sandbox::remove(name).await.expect("remove");
    let exec_log = std::fs::read_to_string(log_dir.join("exec.log")).expect("exec.log kept");
    assert!(
        exec_log.contains(marker),
        "exec.log lost the marker after removal"
    );
}

fn contains(entry: &microsandbox::logs::LogEntry, needle: &str) -> bool {
    std::str::from_utf8(&entry.data)
        .map(|s| s.contains(needle))
        .unwrap_or(false)
}
