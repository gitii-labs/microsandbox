//! Catalog writes the VM exit observer makes before the runtime process exits.
//!
//! The observer runs once, on the VMM thread, right before `_exit()`. A write
//! it loses is never made by this process again: dead-runtime cleanup can only
//! mark the run terminated without its exit code. So the run's own result is
//! written first, together with a handoff of a `Running` sandbox to
//! `Draining`. From that commit on, the catalog is in a state that
//! dead-runtime cleanup finishes (`Draining` without an active run) if the
//! process dies before it publishes `Stopped` itself.

use std::future::Future;
use std::time::Duration;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::run as run_entity;
use microsandbox_db::entity::sandbox as sandbox_entity;
use microsandbox_db::entity::sandbox::SandboxStatus;
use microsandbox_db::retry::IsSqliteBusy;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Attempts per exit write. SQLite busy/locked errors are already retried
/// inside [`DbWriteConnection`]; a busy error that still reaches this loop has
/// exhausted those retries and is not attempted again. The attempts here
/// cover other failures, such as a timed-out pool acquire.
const EXIT_WRITE_ATTEMPTS: u32 = 3;

/// Pause between exit-write attempts.
const EXIT_WRITE_RETRY_DELAY: Duration = Duration::from_millis(100);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result of one run, as its exit observer records it.
#[derive(Debug, Clone)]
pub(crate) struct RunExit {
    /// The `run` row of this runtime process.
    pub run_id: i32,
    /// The sandbox the run belongs to.
    pub sandbox_id: i32,
    /// Why the run ended.
    pub reason: run_entity::TerminationReason,
    /// Extra detail, such as a forced exit.
    pub detail: Option<String>,
    /// The VM's exit code.
    pub exit_code: i32,
    /// When the run ended.
    pub terminated_at: chrono::NaiveDateTime,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Write the catalog state of a VM exit in the order that keeps every crash
/// point reapable: record the run and hand the sandbox to reaping, then
/// `release` allocations, then `remove_endpoints`, then publish `Stopped`.
///
/// `Stopped` is published only when the run's exit was recorded and the
/// endpoints are gone. Otherwise the sandbox stays active, and dead-runtime
/// cleanup finishes it after this process exits. Returns whether the sandbox
/// was marked stopped.
pub(crate) async fn finish_vm_exit<R, RFut>(
    db: &DbWriteConnection,
    exit: &RunExit,
    sandbox_name: &str,
    release: R,
    remove_endpoints: impl FnOnce() -> std::io::Result<()>,
) -> bool
where
    R: FnOnce() -> RFut,
    RFut: Future<Output = ()>,
{
    let recorded = record_run_exit(db, exit, EXIT_WRITE_RETRY_DELAY).await;

    release().await;
    let endpoints = remove_endpoints();

    if !recorded {
        tracing::error!(
            sandbox = %sandbox_name,
            run_id = exit.run_id,
            "run exit not recorded; leaving the sandbox active for reaping"
        );
        return false;
    }
    if let Err(error) = endpoints {
        tracing::warn!(
            sandbox = %sandbox_name,
            %error,
            "runtime exit socket cleanup failed; leaving the sandbox active for reaping"
        );
        return false;
    }

    publish_stopped(db, exit, EXIT_WRITE_RETRY_DELAY).await
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Record the run's exit and move a `Running` sandbox to `Draining`, in one
/// transaction. Either both are written or neither: a recorded run under a
/// `Running` sandbox is a state no reaper finishes. Returns whether the run
/// row now holds the exit.
async fn record_run_exit(db: &DbWriteConnection, exit: &RunExit, delay: Duration) -> bool {
    retry_exit_write("record run exit", exit.run_id, delay, || async {
        db.transaction(|txn| {
            let exit = exit.clone();
            async move {
                // Unconditional: the exit this process observed is the run's
                // real result and replaces anything a reaper could have written.
                let result = run_entity::Entity::update_many()
                    .col_expr(
                        run_entity::Column::Status,
                        Expr::value(run_entity::RunStatus::Terminated),
                    )
                    .col_expr(
                        run_entity::Column::TerminationReason,
                        Expr::value(exit.reason),
                    )
                    .col_expr(
                        run_entity::Column::TerminationDetail,
                        Expr::value(exit.detail.clone()),
                    )
                    .col_expr(run_entity::Column::ExitCode, Expr::value(exit.exit_code))
                    .col_expr(
                        run_entity::Column::TerminatedAt,
                        Expr::value(exit.terminated_at),
                    )
                    .filter(run_entity::Column::Id.eq(exit.run_id))
                    .exec(&txn)
                    .await?;
                if result.rows_affected != 1 {
                    return Err(RuntimeError::Custom(format!(
                        "run {} has no catalog row",
                        exit.run_id
                    )));
                }

                // Draining without an active run is the state SDK
                // reconciliation and maintenance finish as Stopped once this
                // process has released its lifecycle lock.
                sandbox_entity::Entity::update_many()
                    .col_expr(
                        sandbox_entity::Column::Status,
                        Expr::value(SandboxStatus::Draining),
                    )
                    .col_expr(
                        sandbox_entity::Column::UpdatedAt,
                        Expr::value(exit.terminated_at),
                    )
                    .filter(sandbox_entity::Column::Id.eq(exit.sandbox_id))
                    .filter(sandbox_entity::Column::Status.eq(SandboxStatus::Running))
                    .exec(&txn)
                    .await?;

                Ok((txn, ()))
            }
        })
        .await
    })
    .await
}

/// Mark the sandbox stopped after its exit was recorded and its endpoints
/// removed.
async fn publish_stopped(db: &DbWriteConnection, exit: &RunExit, delay: Duration) -> bool {
    retry_exit_write("mark sandbox stopped", exit.run_id, delay, || async {
        // Preserve old catalogs while releasing current runtime-owned fields.
        crate::maintenance::terminal_sandbox_update(db)
            .await?
            .col_expr(
                sandbox_entity::Column::Status,
                Expr::value(SandboxStatus::Stopped),
            )
            .col_expr(
                sandbox_entity::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(sandbox_entity::Column::Id.eq(exit.sandbox_id))
            .exec(db)
            .await?;
        Ok(())
    })
    .await
}

/// Run `write` up to [`EXIT_WRITE_ATTEMPTS`] times, logging each failure.
/// A busy/locked error already exhausted the connection's own retries and
/// ends the loop. Returns whether a write succeeded.
async fn retry_exit_write<F, Fut>(
    operation: &'static str,
    run_id: i32,
    delay: Duration,
    mut write: F,
) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RuntimeResult<()>>,
{
    for attempt in 1..=EXIT_WRITE_ATTEMPTS {
        let error = match write().await {
            Ok(()) => return true,
            Err(error) => error,
        };
        let busy = error.is_sqlite_busy();
        tracing::error!(
            operation,
            run_id,
            attempt,
            attempts = EXIT_WRITE_ATTEMPTS,
            busy,
            %error,
            "VM exit catalog write failed"
        );
        if busy {
            return false;
        }

        if attempt < EXIT_WRITE_ATTEMPTS {
            tokio::time::sleep(delay).await;
        }
    }
    false
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, ConnectionTrait, DbBackend, Set, Statement, TransactionTrait};
    use tempfile::TempDir;

    use super::*;
    use crate::maintenance::{MaintenanceLimits, run_sandbox_lifecycle_maintenance};

    /// A PID that is essentially certain not to map to a live process.
    const DEAD_PID: i32 = 2_000_000_000;

    async fn test_db() -> (TempDir, DbWriteConnection) {
        // Keep socket paths under maintenance within the Unix length limit.
        #[cfg(unix)]
        let dir = tempfile::Builder::new()
            .prefix("msb-exit")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let dir = tempfile::tempdir().unwrap();
        let db = DbWriteConnection::open(
            &dir.path().join("test.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(db.inner(), None).await.unwrap();
        (dir, db)
    }

    async fn insert_running(db: &DbWriteConnection, name: &str) -> (i32, i32) {
        let now = chrono::Utc::now().naive_utc();
        let sandbox_id = sandbox_entity::ActiveModel {
            name: Set(name.to_string()),
            config: Set("{}".to_string()),
            status: Set(SandboxStatus::Running),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap()
        .id;
        let run_id = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(DEAD_PID)),
            status: Set(run_entity::RunStatus::Running),
            started_at: Set(Some(now)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap()
        .id;
        (sandbox_id, run_id)
    }

    /// An exit whose reason is unclean although libkrun reported status zero.
    fn signal_exit(sandbox_id: i32, run_id: i32) -> RunExit {
        RunExit {
            run_id,
            sandbox_id,
            reason: run_entity::TerminationReason::Signal,
            detail: None,
            exit_code: 0,
            terminated_at: chrono::Utc::now().naive_utc(),
        }
    }

    async fn run_of(db: &DbWriteConnection, run_id: i32) -> run_entity::Model {
        run_entity::Entity::find_by_id(run_id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
    }

    async fn status_of(db: &DbWriteConnection, sandbox_id: i32) -> SandboxStatus {
        sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .status
    }

    fn assert_recorded(run: &run_entity::Model) {
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(run.exit_code, Some(0));
        assert_eq!(
            run.termination_reason,
            Some(run_entity::TerminationReason::Signal)
        );
        assert_eq!(run.termination_detail, None);
    }

    async fn reap(db: &DbWriteConnection, dir: &TempDir) -> u64 {
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let report = run_sandbox_lifecycle_maintenance(
            db,
            dir.path(),
            &run_dir,
            MaintenanceLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.errors, 0);
        report.reconciled
    }

    async fn execute(db: &DbWriteConnection, statements: &[&str]) {
        for sql in statements {
            db.execute_raw(Statement::from_string(DbBackend::Sqlite, *sql))
                .await
                .unwrap();
        }
    }

    #[derive(Clone, Default)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLog {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLog {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            let log = self.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || log.clone())
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_default(subscriber)
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[tokio::test]
    async fn exit_steps_run_in_reapable_order() {
        let (_dir, db) = test_db().await;
        let (sandbox_id, run_id) = insert_running(&db, "ordered").await;
        let exit = signal_exit(sandbox_id, run_id);
        let released = AtomicU32::new(0);

        let stopped = finish_vm_exit(
            &db,
            &exit,
            "ordered",
            || async {
                // Allocations are released only after the exit is recorded
                // and the sandbox handed to reaping.
                assert_recorded(&run_of(&db, run_id).await);
                assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Draining);
                released.fetch_add(1, Ordering::SeqCst);
            },
            || {
                assert_eq!(released.load(Ordering::SeqCst), 1);
                Ok(())
            },
        )
        .await;

        assert!(stopped);
        assert_recorded(&run_of(&db, run_id).await);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn process_death_after_the_exit_record_is_reaped_with_the_exit_kept() {
        let (dir, db) = test_db().await;
        let (sandbox_id, run_id) = insert_running(&db, "died").await;

        // The process dies right after the combined write.
        assert!(record_run_exit(&db, &signal_exit(sandbox_id, run_id), Duration::ZERO).await);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Draining);

        // While the runtime still holds its lifecycle lock, nothing reaps it.
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let lifecycle = crate::ipc::acquire_lifecycle_guard(&run_dir, "died").unwrap();
        assert_eq!(reap(&db, &dir).await, 0);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Draining);
        drop(lifecycle);

        assert_eq!(reap(&db, &dir).await, 1);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Stopped);
        assert_recorded(&run_of(&db, run_id).await);
    }

    #[tokio::test]
    async fn socket_cleanup_failure_leaves_the_sandbox_to_reaping() {
        let (dir, db) = test_db().await;
        let (sandbox_id, run_id) = insert_running(&db, "sockets-stuck").await;

        let stopped = finish_vm_exit(
            &db,
            &signal_exit(sandbox_id, run_id),
            "sockets-stuck",
            || async {},
            || Err(io::Error::other("endpoint busy")),
        )
        .await;

        assert!(!stopped);
        assert_recorded(&run_of(&db, run_id).await);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Draining);
        assert_eq!(reap(&db, &dir).await, 1);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Stopped);
        assert_recorded(&run_of(&db, run_id).await);
    }

    #[tokio::test]
    async fn unrecorded_exit_is_not_published_and_is_reaped_as_unrecorded() {
        let (dir, db) = test_db().await;
        let (sandbox_id, run_id) = insert_running(&db, "atomic").await;
        // The sandbox half of the combined write fails every time.
        execute(
            &db,
            &["CREATE TRIGGER refuse_handoff BEFORE UPDATE ON sandbox \
               WHEN NEW.status = 'Draining' \
               BEGIN SELECT RAISE(ABORT, 'injected handoff failure'); END"],
        )
        .await;

        let stopped = finish_vm_exit(
            &db,
            &signal_exit(sandbox_id, run_id),
            "atomic",
            || async {},
            || Ok(()),
        )
        .await;

        // Atomic: the run update rolled back with the failed sandbox update,
        // and Stopped was not published over a Running run.
        assert!(!stopped);
        let run = run_of(&db, run_id).await;
        assert_eq!(run.status, run_entity::RunStatus::Running);
        assert_eq!(run.exit_code, None);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Running);

        assert_eq!(reap(&db, &dir).await, 1);
        let run = run_of(&db, run_id).await;
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(run.exit_code, None);
        assert_eq!(
            run.termination_detail.as_deref(),
            Some(run_entity::UNRECORDED_EXIT_DETAIL)
        );
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Crashed);
    }

    #[tokio::test]
    async fn failed_exit_write_is_logged_and_retried() {
        let attempts = AtomicU32::new(0);
        let log = CapturedLog::default();
        let _default = log.install();

        let written = retry_exit_write("record run exit", 7, Duration::ZERO, || async {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(RuntimeError::Custom("injected run exit failure".into()));
            }
            Ok(())
        })
        .await;

        assert!(written);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let text = log.text();
        assert!(text.contains("VM exit catalog write failed"), "{text}");
        assert!(text.contains("injected run exit failure"), "{text}");
        assert!(text.contains("run_id=7"), "{text}");
        assert!(text.contains("attempt=1"), "{text}");
        assert!(!text.contains("attempt=2"), "{text}");
    }

    #[tokio::test]
    async fn exit_write_gives_up_after_bounded_attempts() {
        let attempts = AtomicU32::new(0);

        let written = retry_exit_write("test write", 7, Duration::ZERO, || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::Custom("always fails".into()))
        })
        .await;

        assert!(!written);
        assert_eq!(attempts.load(Ordering::SeqCst), EXIT_WRITE_ATTEMPTS);
    }

    #[tokio::test]
    async fn busy_exhaustion_is_not_attempted_again() {
        let (dir, holder) = test_db().await;
        execute(
            &holder,
            &["CREATE TABLE contended (id INTEGER PRIMARY KEY)"],
        )
        .await;
        // Hold the write lock, and produce one real busy error through a
        // connection that bypasses the connection-level retry.
        let lock = holder.inner().begin().await.unwrap();
        lock.execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO contended (id) VALUES (1)",
        ))
        .await
        .unwrap();
        let contender = DbWriteConnection::open(
            &dir.path().join("test.db"),
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        let attempts = AtomicU32::new(0);

        let written = retry_exit_write("test write", 7, Duration::ZERO, || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            contender
                .inner()
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "INSERT INTO contended (id) VALUES (2)",
                ))
                .await?;
            Ok(())
        })
        .await;

        assert!(!written);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        lock.rollback().await.unwrap();
    }
}
