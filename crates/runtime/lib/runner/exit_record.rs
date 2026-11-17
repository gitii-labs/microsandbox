//! Catalog writes the VM exit observer makes before the runtime process exits.
//!
//! The observer runs once, on the VMM thread, right before `_exit()`. A write
//! it loses is never made by this process again: dead-runtime cleanup can only
//! mark the run terminated without its exit code. So the run's own result is
//! written first, each write is retried a bounded number of times, and every
//! failure is logged.

use std::future::Future;
use std::time::Duration;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::run as run_entity;
use microsandbox_db::entity::sandbox as sandbox_entity;
use microsandbox_db::entity::sandbox::SandboxStatus;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Attempts per exit write. Each attempt already retries SQLite busy/locked
/// errors inside [`DbWriteConnection`]; these attempts cover other transient
/// failures such as a timed-out pool acquire.
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

/// Record the run's exit. Returns whether the run row now holds it.
pub(crate) async fn record_run_exit(db: &DbWriteConnection, exit: &RunExit) -> bool {
    retry_exit_write("record run exit", exit.run_id, || async {
        // Unconditional: the exit this process observed is the run's real
        // result and replaces anything a reaper could have written.
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
            .exec(db)
            .await?;
        if result.rows_affected != 1 {
            return Err(RuntimeError::Custom(format!(
                "run {} has no catalog row",
                exit.run_id
            )));
        }
        Ok(())
    })
    .await
    .is_some()
}

/// Publish the sandbox's state after the run's exit was recorded.
///
/// `socket_cleanup` is the result of removing the runtime's endpoints. A
/// sandbox whose endpoints are still present must not become restartable, so
/// it is left active for dead-runtime cleanup to finish once this process is
/// gone. A `Running` sandbox moves to `Draining`, the active status that
/// cleanup finishes without a running run. Returns whether the sandbox was
/// marked stopped.
pub(crate) async fn publish_sandbox_exit(
    db: &DbWriteConnection,
    run_id: i32,
    sandbox_id: i32,
    sandbox_name: &str,
    socket_cleanup: std::io::Result<()>,
) -> bool {
    if let Err(error) = socket_cleanup {
        tracing::warn!(
            sandbox = %sandbox_name,
            %error,
            "runtime exit socket cleanup failed; leaving the sandbox active for reaping"
        );
        retry_exit_write("hand sandbox to reaping", run_id, || async {
            sandbox_entity::Entity::update_many()
                .col_expr(
                    sandbox_entity::Column::Status,
                    Expr::value(SandboxStatus::Draining),
                )
                .col_expr(
                    sandbox_entity::Column::UpdatedAt,
                    Expr::value(chrono::Utc::now().naive_utc()),
                )
                .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                .filter(sandbox_entity::Column::Status.eq(SandboxStatus::Running))
                .exec(db)
                .await?;
            Ok(())
        })
        .await;
        return false;
    }

    retry_exit_write("mark sandbox stopped", run_id, || async {
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
            .filter(sandbox_entity::Column::Id.eq(sandbox_id))
            .exec(db)
            .await?;
        Ok(())
    })
    .await
    .is_some()
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Run `write` up to [`EXIT_WRITE_ATTEMPTS`] times, logging each failure.
async fn retry_exit_write<F, Fut>(operation: &'static str, run_id: i32, mut write: F) -> Option<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RuntimeResult<()>>,
{
    for attempt in 1..=EXIT_WRITE_ATTEMPTS {
        match write().await {
            Ok(()) => return Some(()),
            Err(error) => {
                tracing::error!(
                    operation,
                    run_id,
                    attempt,
                    attempts = EXIT_WRITE_ATTEMPTS,
                    %error,
                    "VM exit catalog write failed"
                );
            }
        }
        if attempt < EXIT_WRITE_ATTEMPTS {
            tokio::time::sleep(EXIT_WRITE_RETRY_DELAY).await;
        }
    }
    None
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, ConnectionTrait, DbBackend, Set, Statement};
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

    fn clean_exit(run_id: i32) -> RunExit {
        RunExit {
            run_id,
            reason: run_entity::TerminationReason::ShutdownRequested,
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

    fn assert_clean_exit(run: &run_entity::Model) {
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(run.exit_code, Some(0));
        assert_eq!(
            run.termination_reason,
            Some(run_entity::TerminationReason::ShutdownRequested)
        );
        assert_eq!(run.termination_detail, None);
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
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[tokio::test]
    async fn exit_is_recorded_when_socket_cleanup_fails() {
        let (dir, db) = test_db().await;
        let (sandbox_id, run_id) = insert_running(&db, "sockets-stuck").await;

        assert!(record_run_exit(&db, &clean_exit(run_id)).await);
        let published = publish_sandbox_exit(
            &db,
            run_id,
            sandbox_id,
            "sockets-stuck",
            Err(io::Error::other("endpoint busy")),
        )
        .await;

        assert!(!published);
        assert_clean_exit(&run_of(&db, run_id).await);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Draining);

        // Once the process is gone, dead-runtime cleanup removes the endpoints,
        // stops the sandbox and keeps the exit the runtime recorded.
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let report = run_sandbox_lifecycle_maintenance(
            &db,
            dir.path(),
            &run_dir,
            MaintenanceLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.errors, 0);
        assert_eq!(report.reconciled, 1);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Stopped);
        assert_clean_exit(&run_of(&db, run_id).await);
    }

    #[tokio::test]
    async fn exit_publishes_stopped_after_socket_cleanup() {
        let (_dir, db) = test_db().await;
        let (sandbox_id, run_id) = insert_running(&db, "clean").await;

        assert!(record_run_exit(&db, &clean_exit(run_id)).await);
        assert!(publish_sandbox_exit(&db, run_id, sandbox_id, "clean", Ok(())).await);

        assert_clean_exit(&run_of(&db, run_id).await);
        assert_eq!(status_of(&db, sandbox_id).await, SandboxStatus::Stopped);
    }

    #[tokio::test]
    async fn failed_exit_write_is_logged_and_retried() {
        let (_dir, db) = test_db().await;
        let (_sandbox_id, run_id) = insert_running(&db, "flaky").await;

        // The first update of the run fails inside SQLite; RAISE(FAIL) keeps
        // the trigger's own write, so the second attempt succeeds.
        for sql in [
            "CREATE TABLE exit_write_failures (remaining INTEGER NOT NULL)",
            "INSERT INTO exit_write_failures VALUES (1)",
            "CREATE TRIGGER fail_run_exit BEFORE UPDATE ON run \
             WHEN (SELECT remaining FROM exit_write_failures) > 0 \
             BEGIN \
               UPDATE exit_write_failures SET remaining = remaining - 1; \
               SELECT RAISE(FAIL, 'injected run exit failure'); \
             END",
        ] {
            db.execute_raw(Statement::from_string(DbBackend::Sqlite, sql))
                .await
                .unwrap();
        }
        let log = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let log = log.clone();
                move || log.clone()
            })
            .with_ansi(false)
            .finish();
        let _default = tracing::subscriber::set_default(subscriber);

        assert!(record_run_exit(&db, &clean_exit(run_id)).await);

        assert_clean_exit(&run_of(&db, run_id).await);
        let text = log.text();
        assert!(text.contains("VM exit catalog write failed"), "{text}");
        assert!(text.contains("injected run exit failure"), "{text}");
        assert!(text.contains(&format!("run_id={run_id}")), "{text}");
        assert!(text.contains("attempt=1"), "{text}");
        assert!(!text.contains("attempt=2"), "{text}");
    }

    #[tokio::test]
    async fn exit_write_gives_up_after_bounded_attempts() {
        let (_dir, db) = test_db().await;

        // No catalog row for this run: every attempt fails.
        assert!(!record_run_exit(&db, &clean_exit(4242)).await);
    }
}
