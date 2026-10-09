//! Channel-based TLS proxy task.
//!
//! Intercepts TLS connections by terminating the guest's TLS with a
//! generated per-domain certificate (MITM) and re-originating a TLS
//! connection to the real server. Bypass mode replays buffered bytes and
//! splices the connection without termination.

use std::fmt::{self, Write as _};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::sni;
use super::state::TlsState;
use crate::engine::http_deny::{classify_http_request, http_forbidden_response};
use crate::netstack::shared::SharedState;
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::proxy::ResolvedOutboundProxy;
use crate::secrets::config::SecretViolationAction;
use crate::secrets::detector::CredentialDetector;
use crate::secrets::handler::SecretsHandler;
use crate::secrets::oauth::OAuthConnection;
use crate::tcp::{connection::ProxyConnectState, upstream::UpstreamTcpTarget};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Buffer size for bidirectional relay.
const RELAY_BUF_SIZE: usize = 16384;

/// Trace target for complete intercepted traffic, including credentials.
const TRAFFIC_LOG_TARGET: &str = "microsandbox::network::traffic";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection TLS proxy task and the state it owns.
pub(crate) struct TlsProxy {
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    network_policy: Arc<NetworkPolicy>,
    strict: bool,
    proxy_connect: Arc<ProxyConnectState>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
    /// Pre-connected upstream; when `Some`, skips dialing `connect_target`.
    upstream_stream: Option<TcpStream>,
    /// Hostname from a CONNECT authority that must match the ClientHello SNI.
    expected_sni: Option<String>,
    /// `true` when the connection arrived via HTTP CONNECT; skips the DNS-cache pin check.
    via_connect: bool,
    /// ClientHello bytes already consumed from the guest stream.
    initial_buf: Vec<u8>,
}

struct TrafficTrace<'a> {
    enabled: bool,
    connection: u64,
    sequence: u64,
    sni: &'a str,
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
}

struct EscapedPayload<'a>(&'a [u8]);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> TrafficTrace<'a> {
    fn new(sni: &'a str, guest_dst: SocketAddr, connect_dst: SocketAddr) -> Self {
        let enabled = tracing::enabled!(target: TRAFFIC_LOG_TARGET, tracing::Level::TRACE);
        Self {
            enabled,
            connection: if enabled { rand::random() } else { 0 },
            sequence: 0,
            sni,
            guest_dst,
            connect_dst,
        }
    }

    fn record(&mut self, direction: &'static str, payload: &[u8]) {
        if !self.enabled {
            return;
        }
        self.sequence = self.sequence.wrapping_add(1);
        tracing::trace!(
            target: TRAFFIC_LOG_TARGET,
            connection = self.connection,
            sequence = self.sequence,
            direction,
            sni = self.sni,
            guest_dst = %self.guest_dst,
            connect_dst = %self.connect_dst,
            bytes = payload.len(),
            payload = %EscapedPayload(payload),
            "intercepted traffic; payload is not sanitized or redacted",
        );
    }
}

impl fmt::Display for EscapedPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.escape_ascii() {
            f.write_char(char::from(byte))?;
        }
        Ok(())
    }
}

impl TlsProxy {
    /// Build a proxy for a newly established guest TLS connection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        guest_dst: SocketAddr,
        connect_target: UpstreamTcpTarget,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        shared: Arc<SharedState>,
        tls_state: Arc<TlsState>,
        network_policy: Arc<NetworkPolicy>,
        strict: bool,
        proxy_connect: Arc<ProxyConnectState>,
        outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
    ) -> Self {
        Self {
            guest_dst,
            connect_target,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            strict,
            proxy_connect,
            outbound_proxy,
            upstream_stream: None,
            expected_sni: None,
            via_connect: false,
            initial_buf: Vec::new(),
        }
    }

    /// Reuse an already connected upstream stream.
    pub(crate) fn with_upstream(mut self, upstream_stream: TcpStream) -> Self {
        self.upstream_stream = Some(upstream_stream);
        self
    }

    /// Require the ClientHello SNI to match an HTTP CONNECT authority.
    pub(crate) fn with_expected_sni(mut self, expected_sni: Option<String>) -> Self {
        self.via_connect = expected_sni.is_some();
        self.expected_sni = expected_sni;
        self
    }

    /// Seed the proxy with ClientHello bytes already read from the guest.
    pub(crate) fn with_initial_buf(mut self, initial_buf: Vec<u8>) -> Self {
        self.initial_buf = initial_buf;
        self
    }

    /// Run the TLS proxy task to completion.
    ///
    /// See [`crate::tcp::proxy::spawn_tcp_proxy`] for the `proxy_connect`
    /// contract.
    pub(crate) async fn run(self) {
        let guest_dst = self.guest_dst;
        let connect_dst = self.connect_target.primary();

        if let Err(error) = self.try_run().await {
            tracing::debug!(
                dst = %connect_dst,
                %guest_dst,
                %error,
                "TLS proxy task ended",
            );
        }
    }

    /// Drive the TLS proxy to completion, returning operational failures.
    pub(crate) async fn try_run(self) -> io::Result<()> {
        let Self {
            guest_dst,
            connect_target,
            mut from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            strict,
            proxy_connect,
            upstream_stream,
            outbound_proxy,
            expected_sni,
            via_connect,
            initial_buf,
        } = self;
        let connect_dst = connect_target.primary();

        // Buffer initial data to extract SNI from ClientHello. Timeout prevents a
        // slow/malicious guest from holding a proxy slot indefinitely.
        let sni_name = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            extract_sni_from_channel(&mut from_smoltcp, initial_buf),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SNI extraction timed out"))?;
        let (sni_name, initial_buf) = sni_name?;

        // Canonicalize so byte equality against rule destinations works.
        let sni_name = sni_name.trim_end_matches('.').to_ascii_lowercase();

        if let Some(expected) = expected_sni.as_deref()
            && !sni_name.eq_ignore_ascii_case(expected.trim_end_matches('.'))
        {
            tracing::debug!(
                sni = %sni_name,
                expected = %expected,
                dst = %connect_dst,
                "TLS SNI did not match CONNECT authority",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        // Apply Domain / DomainSuffix rules against the SNI.
        let eval = network_policy.evaluate_egress_with_source(
            guest_dst,
            Protocol::Tcp,
            &shared,
            HostnameSource::Sni(&sni_name),
        );
        if !matches!(eval, EgressEvaluation::Allow) {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS egress denied by domain policy",
            );
            // Bypassed names cannot be answered in-tunnel (the guest expects
            // the real server's certificate); they still get a plain close.
            if !tls_state.should_bypass(&sni_name) {
                let denied = serve_tls_deny(
                    &sni_name,
                    initial_buf,
                    &mut from_smoltcp,
                    &to_smoltcp,
                    &shared,
                    &tls_state,
                )
                .await;
                if let Err(error) = denied {
                    tracing::debug!(sni = %sni_name, %error, "TLS deny response not delivered");
                }
            }
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        let should_bypass = tls_state.should_bypass(&sni_name);
        if strict
            && should_bypass
            && network_policy.allows_egress_via_hostname(
                guest_dst,
                Protocol::Tcp,
                &shared,
                HostnameSource::Sni(&sni_name),
            )
        {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS bypass denied by strict hostname policy",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        if should_bypass {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS bypass");
            bypass_relay(
                connect_target,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                proxy_connect,
                upstream_stream,
                outbound_proxy,
            )
            .await
        } else {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS intercept");
            intercept_relay(
                guest_dst,
                connect_target,
                &sni_name,
                via_connect,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                tls_state,
                proxy_connect,
                upstream_stream,
                outbound_proxy,
            )
            .await
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Answer a policy-denied HTTPS connection with `403 Forbidden`.
///
/// Terminates the guest's TLS with the intercept cert for `sni_name`, reads
/// the first request so the client is not mid-write when the close lands,
/// then writes the deny body and a `close_notify`. No upstream connection
/// is ever opened.
pub(crate) async fn serve_tls_deny(
    sni_name: &str,
    initial_buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_state: &TlsState,
) -> io::Result<()> {
    if !shared.http_deny_response_enabled() {
        return Ok(());
    }

    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    complete_guest_handshake(
        &mut guest_tls,
        initial_buf,
        from_smoltcp,
        to_smoltcp,
        shared,
        &mut tls_buf,
    )
    .await?;

    // Only HTTP/1.x can receive our HTTP/1.1 response. Buffer across TLS
    // records; EOF, malformed input, and timeout are not evidence of HTTP.
    let is_http = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut request = Vec::new();
        let mut scratch = [0u8; RELAY_BUF_SIZE];
        loop {
            match guest_tls.reader().read(&mut scratch) {
                Ok(0) => return false,
                Ok(n) => {
                    let remaining = RELAY_BUF_SIZE - request.len();
                    request.extend_from_slice(&scratch[..n.min(remaining)]);
                    if let Some(is_http) = classify_http_request(&request) {
                        return is_http;
                    }
                    if request.len() == RELAY_BUF_SIZE {
                        return false;
                    }
                    continue;
                }
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return false,
            }
            let Some(data) = from_smoltcp.recv().await else {
                return false;
            };
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                if !matches!(guest_tls.read_tls(&mut remaining), Ok(n) if n > 0)
                    || guest_tls.process_new_packets().is_err()
                {
                    return false;
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    if !is_http {
        return Ok(());
    }

    let body = shared.http_deny_body(sni_name);
    guest_tls
        .writer()
        .write_all(&http_forbidden_response(&body))
        .map_err(io::Error::other)?;
    guest_tls.send_close_notify();
    flush_to_guest(&mut guest_tls, to_smoltcp, shared, &mut tls_buf).await
}

/// Feed the buffered ClientHello and drive the guest-facing handshake to
/// completion, bounded by a 10s timeout.
async fn complete_guest_handshake(
    guest_tls: &mut rustls::ServerConnection,
    initial_buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_buf: &mut Vec<u8>,
) -> io::Result<()> {
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Send ServerHello etc. back to guest.
    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while guest_tls.is_handshaking() {
            let data = from_smoltcp
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                guest_tls
                    .read_tls(&mut remaining)
                    .map_err(io::Error::other)?;
                guest_tls.process_new_packets().map_err(io::Error::other)?;
            }
            flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
}

/// Bypass mode: plain TCP splice, no TLS termination.
#[allow(clippy::too_many_arguments)]
async fn bypass_relay(
    connect_target: UpstreamTcpTarget,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
) -> io::Result<()> {
    let mut server = match upstream_stream {
        Some(s) => s,
        None => {
            connect_target
                .connect(&proxy_connect, &shared, outbound_proxy.as_deref())
                .await?
        }
    };
    server.write_all(&initial_buf).await?;

    let (mut server_rx, mut server_tx) = server.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    let mut guest_eof = false;
    loop {
        tokio::select! {
            data = from_smoltcp.recv(), if !guest_eof => {
                match data {
                    Some(bytes) => server_tx.write_all(&bytes).await?,
                    // Guest half-closed (FIN): stop sending upstream but
                    // keep relaying server → guest until the server closes.
                    None => {
                        guest_eof = true;
                        if server_tx.shutdown().await.is_err() {
                            break;
                        }
                    }
                }
            }
            result = server_rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_smoltcp.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Intercept mode: MITM with guest-facing rustls + server-facing tokio_rustls.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn intercept_relay(
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    sni_name: &str,
    via_connect: bool,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
) -> io::Result<()> {
    // Per-connection snapshot: live secret updates apply to later connections.
    let secrets = tls_state.secrets.load();
    let mut secrets_handler = if via_connect {
        SecretsHandler::new_tls_intercepted_via_connect(&secrets, sni_name)
    } else {
        SecretsHandler::new_tls_intercepted(&secrets, sni_name, guest_dst.ip(), &shared)
    }
    .with_guest_dst(guest_dst);
    let connect_dst = connect_target.primary();
    let mut oauth = if via_connect {
        OAuthConnection::new_tls_intercepted_via_connect(
            &secrets.oauth,
            sni_name,
            connect_dst.port(),
        )
        .await?
    } else {
        OAuthConnection::new_tls_intercepted(
            &secrets.oauth,
            sni_name,
            connect_dst.port(),
            guest_dst.ip(),
            &shared,
        )
        .await?
    };

    // Nothing on this connection substitutes or sanitizes when no grant is
    // relevant to it, so that is exactly where a credential-shaped response
    // means the catalogue is missing an endpoint.
    let mut detector = CredentialDetector::new(
        &secrets.oauth,
        sni_name,
        connect_dst.port(),
        oauth.is_empty(),
    );

    // Get or generate per-domain certificate (includes cached ServerConfig).
    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Reuse cached ServerConfig — avoids cert chain clone + key clone + rebuild per connection.
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Feed the buffered ClientHello and complete the guest-facing handshake
    // (bounded, to prevent resource exhaustion).
    complete_guest_handshake(
        &mut guest_tls,
        initial_buf,
        &mut from_smoltcp,
        &to_smoltcp,
        &shared,
        &mut tls_buf,
    )
    .await?;

    // Connect to real server with TLS.
    let server_stream = match upstream_stream {
        Some(s) => s,
        None => {
            connect_target
                .connect(&proxy_connect, &shared, outbound_proxy.as_deref())
                .await?
        }
    };
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut server_tls = tls_state
        .upstream_connector_for(sni_name)
        .connect(server_name, server_stream)
        .await
        .map_err(io::Error::other)?;

    // Phase 2: Bidirectional plaintext relay.
    let mut server_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut plaintext_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut traffic = TrafficTrace::new(sni_name, guest_dst, connect_dst);

    // Drain any application data already buffered during the TLS handshake.
    // In TLS 1.3, the client sends Finished + application data in the same
    // flight, so process_new_packets() during the handshake loop may have
    // already decrypted the first HTTP request into the plaintext buffer.
    forward_plaintext(
        &mut guest_tls,
        &mut server_tls,
        &mut secrets_handler,
        &mut oauth,
        &mut detector,
        &mut traffic,
        &shared,
        &mut plaintext_buf,
    )
    .await?;

    let mut guest_eof = false;
    loop {
        tokio::select! {
            // Guest → server: receive encrypted, decrypt, forward plaintext.
            data = from_smoltcp.recv(), if !guest_eof => {
                let data = match data {
                    Some(d) => d,
                    // Guest half-closed (TCP FIN): propagate as a TLS
                    // close_notify + FIN upstream, but keep relaying
                    // server → guest until the server closes. (A TLS 1.3
                    // server may keep sending; a TLS 1.2 server responds
                    // with its own close_notify, ending the relay.)
                    None => {
                        guest_eof = true;
                        if server_tls.shutdown().await.is_err() {
                            break;
                        }
                        continue;
                    }
                };
                // Feed all data to rustls.
                let mut remaining = &data[..];
                while !remaining.is_empty() {
                    guest_tls
                        .read_tls(&mut remaining)
                        .map_err(io::Error::other)?;
                    guest_tls
                        .process_new_packets()
                        .map_err(io::Error::other)?;
                    forward_plaintext(
                        &mut guest_tls,
                        &mut server_tls,
                        &mut secrets_handler,
                        &mut oauth,
                        &mut detector,
                        &mut traffic,
                        &shared,
                        &mut plaintext_buf,
                    )
                    .await?;
                }
            }

            // Server → guest: read plaintext, encrypt, send via channel.
            result = server_tls.read(&mut server_buf) => {
                match result {
                    Ok(0) => {
                        let tail = oauth.finish_response_scrubbing()?;
                        if !tail.is_empty() {
                            guest_tls.writer().write_all(&tail).map_err(io::Error::other)?;
                            traffic.record("guest-response", &tail);
                            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                        }
                        break;
                    },
                    Ok(n) => {
                        traffic.record("upstream-response", &server_buf[..n]);
                        let data = if oauth.is_token_host() {
                            oauth.transform_responses(&server_buf[..n]).await?
                        } else if !oauth.is_empty() {
                            oauth.scrub_response_chunk(&server_buf[..n]).await?
                        } else {
                            detector.observe_response(&server_buf[..n]);
                            server_buf[..n].to_vec()
                        };
                        if data.is_empty() {
                            continue;
                        }
                        guest_tls.writer().write_all(&data).map_err(io::Error::other)?;
                        traffic.record("guest-response", &data);
                        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Buffer channel data until a complete ClientHello with SNI is received.
///
/// `seed` carries bytes already read from the channel before this call
/// (e.g. bytes trailing a CONNECT request). Pass an empty `Vec` when no
/// bytes have been pre-consumed.
pub(crate) async fn extract_sni_from_channel(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    seed: Vec<u8>,
) -> io::Result<(String, Vec<u8>)> {
    let mut initial_buf = seed;
    initial_buf.reserve(CLIENT_HELLO_BUF_SIZE.saturating_sub(initial_buf.len()));
    loop {
        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);

        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
    }
}

/// Read all available decrypted plaintext from the guest-facing TLS
/// connection and forward it to the upstream server, applying secret
/// substitution when configured.
#[allow(clippy::too_many_arguments)]
async fn forward_plaintext(
    guest_tls: &mut rustls::ServerConnection,
    server_tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    secrets_handler: &mut SecretsHandler,
    oauth: &mut OAuthConnection,
    detector: &mut CredentialDetector,
    traffic: &mut TrafficTrace<'_>,
    shared: &SharedState,
    buf: &mut [u8],
) -> io::Result<()> {
    let mut wrote_plaintext = false;

    loop {
        let n = match guest_tls.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };

        // OAuth routing headers can span reads. Raw guest tracing would record
        // private markers before validation/removal; trace only the transformed
        // upstream request for OAuth connections.
        if oauth.is_empty() {
            traffic.record("guest-request", &buf[..n]);
        }
        detector.observe_request(&buf[..n]);

        if secrets_handler.is_empty() && oauth.is_empty() {
            server_tls.write_all(&buf[..n]).await?;
            traffic.record("upstream-request", &buf[..n]);
            wrote_plaintext = true;
            continue;
        }

        match secrets_handler.substitute(&buf[..n]) {
            Ok(data) => {
                let data = oauth.transform_requests(&data, traffic.sni).await?;
                if !data.is_empty() {
                    server_tls.write_all(&data).await?;
                    traffic.record("upstream-request", &data);
                    wrote_plaintext = true;
                }
            }
            Err(action) => {
                // Secret policy rejected the request. Drop the connection.
                if matches!(action, SecretViolationAction::BlockAndTerminate) {
                    shared.trigger_termination();
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret violation: request blocked by secret policy",
                ));
            }
        }
    }

    // tokio-rustls buffers writes; flush each drained plaintext batch so
    // upstream servers waiting for the full request body can respond.
    if wrote_plaintext {
        server_tls.flush().await?;
    }

    Ok(())
}

/// Flush pending TLS output from the guest-facing rustls connection
/// to the smoltcp channel.
///
/// Reuses `buf` across calls to avoid per-flush heap allocation. The
/// buffer grows to steady-state capacity on the first call and stays there.
async fn flush_to_guest(
    guest_tls: &mut rustls::ServerConnection,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    if guest_tls.wants_write() {
        buf.clear();
        guest_tls.write_tls(buf)?;
        if !buf.is_empty() {
            to_smoltcp
                .send(Bytes::copy_from_slice(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            shared.proxy_wake.wake();
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::secrets::{config::SecretsConfig, handle::SecretsHandle};

    async fn tls_denial_response(chunks: &[&[u8]], close_input: bool, enabled: bool) -> Vec<u8> {
        let state = TlsState::new(
            microsandbox_types::TlsConfig::default(),
            SecretsHandle::new(SecretsConfig::default()),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(state.intercept_ca.cert_der.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("blocked.example").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let (from_tx, mut from_rx) = mpsc::channel(16);
        let (to_tx, mut to_rx) = mpsc::channel(16);
        let server = tokio::spawn(async move {
            let shared = SharedState::new(16);
            shared.set_http_config(microsandbox_types::HttpConfig {
                deny_response: enabled,
                ..Default::default()
            });
            serve_tls_deny(
                "blocked.example",
                hello,
                &mut from_rx,
                &to_tx,
                &shared,
                &state,
            )
            .await
            .unwrap();
        });
        let mut sent = false;
        let mut sender = Some(from_tx);
        let mut response = Vec::new();
        while let Some(data) = to_rx.recv().await {
            assert!(
                enabled,
                "disabled responses must not complete a TLS handshake"
            );
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                client.read_tls(&mut remaining).unwrap();
                client.process_new_packets().unwrap();
            }
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            if !wire.is_empty() {
                sender
                    .as_ref()
                    .unwrap()
                    .send(Bytes::from(wire))
                    .await
                    .unwrap();
            }
            if !client.is_handshaking() && !sent {
                for chunk in chunks {
                    client.writer().write_all(chunk).unwrap();
                    let mut wire = Vec::new();
                    client.write_tls(&mut wire).unwrap();
                    sender
                        .as_ref()
                        .unwrap()
                        .send(Bytes::from(wire))
                        .await
                        .unwrap();
                }
                sent = true;
                if close_input {
                    sender.take();
                }
            }
            let mut plain = [0; 4096];
            loop {
                match client.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&plain[..n]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("unexpected TLS read error: {error}"),
                }
            }
        }
        server.await.unwrap();
        response
    }

    #[tokio::test]
    async fn tls_denial_is_silent_without_opt_in() {
        assert!(
            tls_denial_response(&[b"GET / HTTP/1.1\r\n\r\n"], true, false)
                .await
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_answers_fragmented_http1() {
        let response = tls_denial_response(
            &[
                b"\r",
                b"\nGE",
                b"T / HTTP/1.1\r",
                b"\nHost: blocked.example\r\n\r\n",
            ],
            true,
            true,
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert!(String::from_utf8_lossy(&response).contains("blocked.example"));
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_closes_non_http_and_incomplete_streams_silently() {
        for chunks in [
            vec![b"SSH-2.0-OpenSSH\r\n".as_slice()],
            vec![b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()],
            vec![b"GE".as_slice()],
            vec![],
        ] {
            assert!(tls_denial_response(&chunks, true, true).await.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_does_not_answer_after_timeout() {
        assert!(
            tls_denial_response(&[b"GET /"], false, true)
                .await
                .is_empty()
        );
    }

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn record_at(level: tracing::Level) -> (TrafficTrace<'static>, String) {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(buffer.clone())
            .with_max_level(level)
            .finish();
        let trace = tracing::subscriber::with_default(subscriber, || {
            let mut trace = TrafficTrace::new(
                "api.example.com",
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            );
            trace.record(
                "guest-request",
                b"POST /token HTTP/1.1\r\nAuthorization: Bearer sentinel\r\n\r\nbody\0",
            );
            trace.record(
                "upstream-request",
                b"POST /token HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\nbody\0",
            );
            trace.record(
                "upstream-response",
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nnew-secret",
            );
            trace.record(
                "guest-response",
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsentinel",
            );
            trace
        });
        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (trace, logged)
    }

    #[test]
    fn complete_intercepted_payload_is_logged_only_at_trace() {
        let (disabled, logged) = record_at(tracing::Level::DEBUG);
        assert!(!disabled.enabled);
        assert_eq!(disabled.connection, 0);
        assert_eq!(disabled.sequence, 0);
        assert!(logged.is_empty());

        let (enabled, logged) = record_at(tracing::Level::TRACE);
        assert!(enabled.enabled);
        assert_eq!(enabled.sequence, 4);
        assert_eq!(
            logged
                .matches(&format!("connection={}", enabled.connection))
                .count(),
            4
        );
        assert_eq!(logged.matches("guest_dst=192.0.2.1:443").count(), 4);
        assert_eq!(logged.matches("connect_dst=192.0.2.2:443").count(), 4);
        assert!(logged.contains("sequence=1 direction=\"guest-request\""));
        assert!(logged.contains("sequence=2 direction=\"upstream-request\""));
        assert!(logged.contains("sequence=3 direction=\"upstream-response\""));
        assert!(logged.contains("sequence=4 direction=\"guest-response\""));
        assert!(logged.contains("sni=\"api.example.com\""));
        assert!(logged.contains("Authorization: Bearer sentinel"));
        assert!(logged.contains(
            "payload=POST /token HTTP/1.1\\r\\nAuthorization: Bearer secret\\r\\n\\r\\nbody\\x00"
        ));
        assert!(
            logged
                .contains("payload=HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nnew-secret")
        );
        assert!(
            logged.contains("payload=HTTP/1.1 200 OK\\r\\nContent-Length: 8\\r\\n\\r\\nsentinel")
        );
    }
}
