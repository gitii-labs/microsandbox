//! Regression coverage for secret policy diagnostics at the request boundary.

#![cfg(feature = "engine")]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_network::config::builder::SecretBuilder;
use microsandbox_network::conn::ProxyConnectState;
use microsandbox_network::policy::NetworkPolicy;
use microsandbox_network::secrets::config::{SecretViolationAction, SecretsConfig};
use microsandbox_network::secrets::handle::SecretsHandle;
use microsandbox_network::secrets::handler::SecretsHandler;
use microsandbox_network::shared::{ResolvedHostnameFamily, SharedState};
use microsandbox_network::tcp::proxy::spawn_tcp_proxy;
use microsandbox_network::tls::state::TlsState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{EnvFilter, Layer};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<CapturedEvent>>>);

struct CapturedEvent {
    level: Level,
    fields: BTreeMap<String, String>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Visit for CapturedEvent {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.fields
            .insert(field.name().into(), format!("{value:?}"));
    }
}

impl<S: Subscriber> Layer<S> for CapturedLogs {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut captured = CapturedEvent {
            level: *event.metadata().level(),
            fields: BTreeMap::new(),
        };
        event.record(&mut captured);
        self.0.lock().unwrap().push(captured);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn capture_subscriber(logs: CapturedLogs, diagnostics: &str) -> impl Subscriber {
    tracing_subscriber::registry()
        .with(
            EnvFilter::new(diagnostics).add_directive(
                "microsandbox::network::policy::rejection=warn"
                    .parse()
                    .unwrap(),
            ),
        )
        .with(logs)
}

async fn assert_proxy_violation_logs(logs: &CapturedLogs) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndLog,
        SecretViolationAction::BlockAndTerminate,
    ] {
        for path in [
            "first flight",
            "first flight body",
            "body relay",
            "early body response",
            "expect continue",
            "CONNECT",
            "CONNECT HTTP1.0",
            "CONNECT HTTP1.2",
            "CONNECT HTTP2.0",
            "opaque",
            "HTTP2",
            "ordinary EOF",
            "placeholder host",
            "credential host",
            "CONNECT placeholder host",
            "CONNECT credential host",
            "unknown version",
            "HTTP1.2",
            "HTTP1.0",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = SecretsConfig {
                secrets: vec![
                    SecretBuilder::new()
                        .env("API_KEY")
                        .value("Real-Secret")
                        .placeholder("$KEY")
                        .allow("allowed.example.com")
                        .build(),
                ],
                violation_action: action.clone(),
                ..Default::default()
            };
            let tls_state = path.starts_with("CONNECT").then(|| {
                Arc::new(
                    TlsState::new(Default::default(), SecretsHandle::new(config.clone())).unwrap(),
                )
            });
            let shared = Arc::new(SharedState::new(4));
            shared.cache_resolved_hostname(
                "api.example.com",
                ResolvedHostnameFamily::Ipv4,
                [addr.ip()],
                Duration::from_secs(60),
            );
            let terminated = Arc::new(AtomicBool::new(false));
            let termination_flag = terminated.clone();
            shared.set_termination_hook(Arc::new(move || {
                termination_flag.store(true, Ordering::SeqCst);
            }));
            let (from_tx, from_rx) = mpsc::channel(8);
            let (to_tx, mut to_rx) = mpsc::channel(8);
            let request = match path {
                "first flight" => {
                    "GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $KEY\r\n\r\n"
                }
                "first flight body" => {
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY"
                }
                "body relay" | "early body response" => {
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n"
                }
                "expect continue" => {
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n"
                }
                "CONNECT" => {
                    "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Bearer $KEY\r\n\r\n"
                }
                "CONNECT HTTP1.0" => {
                    "CONNECT api.example.com:443 HTTP/1.0\r\nHost: api.example.com:443\r\nProxy-Authorization: Bearer $KEY\r\n\r\n"
                }
                "CONNECT HTTP1.2" => {
                    "CONNECT api.example.com:443 HTTP/1.2\r\nHost: api.example.com:443\r\nProxy-Authorization: Bearer $KEY\r\n\r\n"
                }
                "CONNECT HTTP2.0" => {
                    "CONNECT api.example.com:443 HTTP/2.0\r\nHost: api.example.com:443\r\nProxy-Authorization: Bearer $KEY\r\n\r\n"
                }
                "opaque" => "SSH-2.0-$KEY\r\n",
                "HTTP2" => "",
                "ordinary EOF" => "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                "placeholder host" => "GET / HTTP/1.1\r\nHost: $KEY\r\nX-Key: $KEY\r\n\r\n",
                "credential host" => "GET / HTTP/1.1\r\nHost: Real-Secret\r\nX-Key: $KEY\r\n\r\n",
                "CONNECT placeholder host" => {
                    "CONNECT $KEY:443 HTTP/1.1\r\nHost: $KEY:443\r\nX-Key: $KEY\r\n\r\n"
                }
                "CONNECT credential host" => {
                    "CONNECT Real-Secret:443 HTTP/1.1\r\nHost: Real-Secret:443\r\nX-Key: $KEY\r\n\r\n"
                }
                "unknown version" => "GET / SMTP\r\nX-Key: $KEY\r\n\r\n",
                "HTTP1.2" => "GET / HTTP/1.2\r\nHost: api.example.com\r\nX-Key: $KEY\r\n\r\n",
                "HTTP1.0" => "GET / HTTP/1.0\r\nX-Key: $KEY\r\n\r\n",
                _ => unreachable!(),
            };
            let request = if path == "HTTP2" {
                let mut encoder = httlib_hpack::Encoder::with_dynamic_size(4096);
                let mut headers = Vec::new();
                for (name, value) in [
                    (b":method".as_slice(), b"GET".as_slice()),
                    (b":path", b"/"),
                    (b":authority", b"api.example.com"),
                    (b"authorization", b"Bearer $KEY"),
                ] {
                    encoder
                        .encode(
                            (
                                name.to_vec(),
                                value.to_vec(),
                                httlib_hpack::Encoder::NEVER_INDEXED,
                            ),
                            &mut headers,
                        )
                        .unwrap();
                }
                let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
                let length = (headers.len() as u32).to_be_bytes();
                request.extend_from_slice(&length[1..]);
                request.extend_from_slice(&[1, 5, 0, 0, 0, 1]);
                request.extend_from_slice(&headers);
                request
            } else {
                request.as_bytes().to_vec()
            };
            from_tx.send(Bytes::from(request.clone())).await.unwrap();
            logs.0.lock().unwrap().clear();
            spawn_tcp_proxy(
                &tokio::runtime::Handle::current(),
                addr,
                addr,
                from_rx,
                to_tx,
                shared,
                Arc::new(NetworkPolicy::default()),
                Arc::new(config),
                tls_state,
                false,
                Arc::new(ProxyConnectState::new()),
                None,
            );
            let (mut server, _) = listener.accept().await.unwrap();
            let mut early_response = None;
            if path == "body relay" || path == "early body response" || path == "expect continue" {
                // Observing the headers upstream proves the placeholder arrives
                // in the relay loop, after first-flight inspection has finished.
                let mut headers = vec![0; request.len()];
                server.read_exact(&mut headers).await.unwrap();
                assert_eq!(headers, request);
                if path == "early body response" || path == "expect continue" {
                    // A real upstream can answer before consuming the body.
                    // Synchronize on delivery, not a timer, to expose an invalid
                    // appended 403 if the proxy has already sent this response.
                    let response = if path == "expect continue" {
                        b"HTTP/1.1 100 Continue\r\n\r\n".as_slice()
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice()
                    };
                    server.write_all(response).await.unwrap();
                    early_response = Some(to_rx.recv().await.unwrap());
                }
                from_tx.send(Bytes::from_static(b"$KEY")).await.unwrap();
            }
            drop(from_tx);
            let mut blocked_bytes = Vec::new();
            server.read_to_end(&mut blocked_bytes).await.unwrap();
            if path == "ordinary EOF" {
                assert_eq!(blocked_bytes, request);
                drop(server);
                assert!(to_rx.recv().await.is_none());
                assert!(!terminated.load(Ordering::SeqCst));
                assert!(
                    logs.0.lock().unwrap().is_empty(),
                    "ordinary EOF is not a policy rejection"
                );
                continue;
            }
            assert!(
                blocked_bytes.is_empty(),
                "{path}: blocked data reached upstream"
            );
            if matches!(
                path,
                "first flight"
                    | "first flight body"
                    | "CONNECT"
                    | "CONNECT HTTP1.0"
                    | "placeholder host"
                    | "credential host"
                    | "CONNECT placeholder host"
                    | "CONNECT credential host"
                    | "HTTP1.0"
            ) {
                let response = to_rx.recv().await.expect("HTTP/1 rejection response");
                assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
                assert!(response.ends_with(b"Secret not permitted on this connection\n"));
            }
            assert!(to_rx.recv().await.is_none(), "{path}: proxy must close");
            if path == "early body response" {
                assert_eq!(
                    early_response.as_deref().unwrap(),
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                );
            }
            if path == "expect continue" {
                assert_eq!(
                    early_response.as_deref().unwrap(),
                    b"HTTP/1.1 100 Continue\r\n\r\n"
                );
            }
            assert_eq!(
                terminated.load(Ordering::SeqCst),
                action == SecretViolationAction::BlockAndTerminate
            );

            let events = logs.0.lock().unwrap();
            let violations: Vec<_> = events
                .iter()
                .filter(|event| event.fields.contains_key("policy_rejection"))
                .collect();
            assert_eq!(violations.len(), 1, "{path}: log each violation once");
            assert_eq!(violations[0].level, Level::WARN);
            let event: serde_json::Value =
                serde_json::from_str(&violations[0].fields["policy_rejection"]).unwrap();
            assert_eq!(event["reason"], "secret_not_permitted");
            assert_eq!(event["secret_env_var"], "API_KEY");
            assert_eq!(
                event["protocol"],
                match path {
                    "opaque" | "unknown version" | "HTTP1.2" | "CONNECT HTTP1.2"
                    | "CONNECT HTTP2.0" => "opaque",
                    "HTTP2" => "http/2",
                    _ => "http/1.1",
                }
            );
            assert_eq!(event["dest_port"], addr.port());
            assert_eq!(
                event["host"],
                if matches!(
                    path,
                    "opaque"
                        | "HTTP2"
                        | "placeholder host"
                        | "credential host"
                        | "CONNECT placeholder host"
                        | "CONNECT credential host"
                        | "unknown version"
                        | "HTTP1.2"
                        | "HTTP1.0"
                ) {
                    "127.0.0.1"
                } else {
                    "api.example.com"
                },
                "{path}"
            );
            for value in violations[0].fields.values() {
                assert!(!value.contains("$KEY"));
                assert!(!value.contains("$key"));
                assert!(!value.contains("Real-Secret"));
                assert!(!value.contains("real-secret"));
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn secret_violation_logs_distinguish_blocking_from_allowed_placeholders() {
    // Keep tracing capture in its own integration-test process so concurrent
    // unit tests cannot change callsite interest while these events are emitted.
    let logs = CapturedLogs::default();
    let _subscriber = tracing::subscriber::set_default(capture_subscriber(logs.clone(), "off"));

    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndLog,
        SecretViolationAction::BlockAndTerminate,
    ] {
        for tls_intercepted in [false, true] {
            for (location, request) in [
                (
                    "header",
                    "GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $KEY\r\n\r\n",
                ),
                (
                    "body",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                ),
            ] {
                logs.0.lock().unwrap().clear();
                let config = SecretsConfig {
                    secrets: vec![
                        SecretBuilder::new()
                            .env("API_KEY")
                            .value("real-secret")
                            .placeholder("$KEY")
                            .allow("api.example.com")
                            .build(),
                    ],
                    violation_action: action.clone(),
                    ..Default::default()
                };
                let mut handler = SecretsHandler::new(&config, "api.example.com", tls_intercepted);
                let result = handler.substitute(request.as_bytes());
                let events = logs.0.lock().unwrap();

                if tls_intercepted {
                    let expected = if location == "header" {
                        request.replace("$KEY", "real-secret")
                    } else {
                        request.to_string()
                    };
                    assert_eq!(result.unwrap().as_ref(), expected.as_bytes());
                    assert!(
                        events.is_empty(),
                        "permitted requests must not log violations"
                    );
                    continue;
                }

                assert_eq!(result.unwrap_err(), action);
                assert_eq!(events.len(), 1);
                let event = &events[0];
                assert_eq!(event.fields["message"], "policy rejected request");
                assert_eq!(event.level, Level::WARN);
                let metadata: serde_json::Value =
                    serde_json::from_str(&event.fields["policy_rejection"]).unwrap();
                assert_eq!(metadata["host"], "api.example.com");
                assert_eq!(metadata["location"], location);
                assert_eq!(metadata["secret_env_var"], "API_KEY");
                assert!(
                    event
                        .fields
                        .values()
                        .all(|value| !value.contains("real-secret") && !value.contains("$KEY"))
                );
            }
        }
    }

    // Repeated equivalent rejections have canonical metadata, independent of
    // request paths, queries, headers and bodies supplied by the guest.
    logs.0.lock().unwrap().clear();
    let config = SecretsConfig {
        secrets: vec![
            SecretBuilder::new()
                .env("API_KEY\n\"name")
                .value("real-secret")
                .placeholder("$KEY")
                .allow("allowed.example")
                .build(),
        ],
        violation_action: SecretViolationAction::Block,
        ..Default::default()
    };
    for payload in ["arbitrary-one", "arbitrary-two"] {
        let mut handler =
            SecretsHandler::new(&config, &format!("{}\nforged", "x".repeat(300)), false);
        let body = format!("{payload}$KEY");
        let request = format!(
            "POST /{payload}?credential={payload} HTTP/1.1\r\nHost: wrong.example\r\nX-Payload: {payload}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            handler.substitute(request.as_bytes()).unwrap_err(),
            SecretViolationAction::Block
        );
    }
    {
        let events = logs.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].fields["policy_rejection"],
            events[1].fields["policy_rejection"]
        );
        let encoded = &events[0].fields["policy_rejection"];
        assert!(!encoded.contains('\n'));
        assert!(!encoded.contains("arbitrary-"));
        assert!(!encoded.contains("$KEY"));
        assert!(!encoded.contains("real-secret"));
        let metadata: serde_json::Value = serde_json::from_str(encoded).unwrap();
        assert_eq!(metadata["host"].as_str().unwrap().chars().count(), 253);
        assert_eq!(metadata["secret_env_var"], "API_KEY\n\"name");
    }

    // Even metadata fields must not echo a configured placeholder or value.
    for host in ["$KEY", "real-secret"] {
        logs.0.lock().unwrap().clear();
        let mut handler = SecretsHandler::new(&config, host, false)
            .with_guest_dst("127.0.0.1:80".parse().unwrap());
        assert!(
            handler
                .substitute(
                    b"GET / HTTP/1.1\r\nHost: wrong.example\r\nAuthorization: Bearer $KEY\r\n\r\n"
                )
                .is_err()
        );
        let events = logs.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let encoded = &events[0].fields["policy_rejection"];
        assert!(!encoded.contains("$KEY"));
        assert!(!encoded.contains("real-secret"));
        let metadata: serde_json::Value = serde_json::from_str(encoded).unwrap();
        assert_eq!(metadata["host"], "127.0.0.1");
    }

    logs.0.lock().unwrap().clear();
    let mut long_env = config.clone();
    long_env.secrets[0].env_var = "E".repeat(300);
    let mut handler = SecretsHandler::new(&long_env, "wrong.example", false);
    assert!(
        handler
            .substitute(b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n")
            .is_err()
    );
    {
        let events = logs.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let metadata: serde_json::Value =
            serde_json::from_str(&events[0].fields["policy_rejection"]).unwrap();
        assert_eq!(
            metadata["secret_env_var"].as_str().unwrap().chars().count(),
            128
        );
    }

    // Use the same isolated process and subscriber to cover the real proxy's
    // logging and termination, not just the handler's returned action.
    for diagnostics in ["off", "error"] {
        let logs = CapturedLogs::default();
        let _subscriber =
            tracing::subscriber::set_default(capture_subscriber(logs.clone(), diagnostics));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(10), assert_proxy_violation_logs(&logs))
                    .await
                    .expect("proxy violation checks timed out");
            });
    }
}
