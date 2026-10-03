//! Shared bounded and unbounded graceful-stop contract.

use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, sandbox::SandboxIdentity};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn stop(
    backend: Arc<dyn Backend>,
    name: &str,
    identity: SandboxIdentity,
    _ephemeral: bool,
    timeout: Option<Duration>,
) -> MicrosandboxResult<()> {
    let timed_out = || MicrosandboxError::StopTimeout {
        name: name.to_string(),
        identity: format!("{identity:?}"),
        timeout: timeout.expect("only timed stops can expire"),
    };
    // A zero budget must not dispatch shutdown, and in particular must never select Kill.
    if timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(timed_out());
    }
    let operation = async {
        #[cfg(feature = "local")]
        if let (Some(local), SandboxIdentity::Local(id)) = (backend.as_local(), &identity) {
            return local.stop_complete(name, *id, _ephemeral).await;
        }
        // The cloud control-plane's terminal status is its completion authority. Local process
        // locks have no meaning there; keep the backend identity checks on every observation.
        let handle = backend.sandboxes().get(backend.clone(), name).await?;
        if handle.identity() != identity {
            return Err(MicrosandboxError::SandboxReplaced {
                name: name.to_string(),
                expected: format!("{identity:?}"),
                actual: handle.id().to_string(),
            });
        }
        // A sandbox already terminal before this call was not stopped by it,
        // so there is no shutdown of ours to judge.
        if matches!(
            handle.status_snapshot(),
            crate::sandbox::SandboxStatus::Stopped | crate::sandbox::SandboxStatus::Crashed
        ) {
            return Ok(());
        }
        handle.request_stop().await?;
        // A crash is terminal too, but it is not the shutdown this call asked
        // for; only `Stopped` vouches for a clean one.
        let observed = handle.wait_until_stopped().await?;
        if observed.status != crate::sandbox::SandboxStatus::Stopped {
            return Err(MicrosandboxError::Runtime(format!(
                "sandbox '{name}' stopped uncleanly: {:?}",
                observed.status
            )));
        }
        Ok(())
    };
    match timeout {
        // This single deadline includes transition locks, dispatch and ownership observation.
        Some(timeout) => tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| timed_out())?,
        None => operation.await,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use microsandbox_types::{CloudCreateSandboxResponse, CloudSandboxStatus};

    use super::*;

    const SANDBOX_ID: &str = "00000000-0000-0000-0000-000000000002";

    #[tokio::test]
    async fn stopping_an_already_crashed_cloud_sandbox_succeeds_without_a_stop_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let body = serde_json::to_string(&CloudCreateSandboxResponse {
            id: SANDBOX_ID.into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            slug: "brave-otter".into(),
            status: CloudSandboxStatus::Failed,
            status_reason: None,
            spec: None,
            ephemeral: false,
            created_at: chrono::Utc::now(),
            started_at: None,
            stopped_at: None,
            last_failure_message: Some("guest crashed".into()),
        })
        .unwrap();
        let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).await.unwrap();
                loop {
                    let mut header = String::new();
                    assert_ne!(reader.read_line(&mut header).await.unwrap(), 0);
                    if header == "\r\n" {
                        break;
                    }
                }
                requests_tx.send(request_line).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                reader
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        let backend: Arc<dyn Backend> =
            Arc::new(crate::test_support::cloud_backend(&url, "test-key").unwrap());

        stop(
            backend,
            "agent-1",
            SandboxIdentity::Cloud(SANDBOX_ID.into()),
            false,
            None,
        )
        .await
        .unwrap();

        server.abort();
        let mut methods = Vec::new();
        while let Ok(line) = requests.try_recv() {
            methods.push(line.split(' ').next().unwrap().to_string());
        }
        assert!(!methods.is_empty());
        assert!(methods.iter().all(|method| method == "GET"), "{methods:?}");
    }
}
