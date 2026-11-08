//! Dependency regressions through the production CA loader and upstream TLS connectors.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use futures::FutureExt;
use pem::{EncodeConfig, LineEnding, Pem};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::ServerName;
use rustls::{CertificateError, Error as TlsError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::{TlsState, build_upstream_connector};
use crate::engine::tls::{ca::CertAuthority, certgen};
use crate::secrets::{config::SecretsConfig, handle::SecretsHandle};
use microsandbox_types::{ScopedUpstreamCaCert, TlsConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct TestDirectory {
    path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for TestDirectory {
    fn drop(&mut self) {
        // Cleanup errors must not cause a second panic while an assertion unwinds.
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            eprintln!(
                "failed to remove TLS fixture directory {}: {error}",
                self.path.display()
            );
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn directory() -> TestDirectory {
    assert!(
        rustls::crypto::ring::default_provider()
            .install_default()
            .is_ok()
            || rustls::crypto::CryptoProvider::get_default().is_some()
    );
    let path = std::env::temp_dir().join(format!(
        "msb-tls-dependency-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&path).expect("create private, exclusive TLS fixture directory");
    TestDirectory { path }
}

fn encoded_ca(ca: &CertAuthority, ending: LineEnding) -> Vec<u8> {
    pem::encode_many_config(
        &[Pem::new("CERTIFICATE", ca.cert_der.as_ref())],
        EncodeConfig::new().set_line_ending(ending),
    )
    .into_bytes()
}

fn unrelated_ca() -> CertAuthority {
    let mut params = CertificateParams::default();
    // Distinct issuer identity: two generated microsandbox CAs share a subject and
    // intentionally produce BadSignature, not UnknownIssuer, when their keys differ.
    params
        .distinguished_name
        .push(DnType::CommonName, "unrelated test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    CertAuthority::load(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
}

async fn exchange(
    connector: &TlsConnector,
    ca: &CertAuthority,
    name: &'static str,
) -> io::Result<()> {
    let leaf = certgen::generate_domain_cert("upstream.test", ca, 1).unwrap();
    let acceptor = TlsAcceptor::from(leaf.server_config);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    let serving = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut tls = acceptor.accept(socket).await?;
        let mut request = [0; 4];
        tls.read_exact(&mut request).await?;
        assert_eq!(&request, b"ping");
        tls.write_all(b"pong").await?;
        tls.shutdown().await
    });
    let socket = TcpStream::connect(address).await.unwrap();
    match connector
        .connect(ServerName::try_from(name).unwrap(), socket)
        .await
    {
        Ok(mut tls) => {
            assert!(
                tls.get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|certs| certs.len() == 2)
            );
            assert!(tls.get_ref().1.negotiated_cipher_suite().is_some());
            tls.write_all(b"ping").await.unwrap();
            let mut response = [0; 4];
            tls.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
            tls.shutdown().await.unwrap();
            serving.await.unwrap().unwrap();
            Ok(())
        }
        Err(error) => {
            assert!(
                serving.await.unwrap().is_err(),
                "server must observe the rejected connection"
            );
            Err(error)
        }
    }
}

fn unknown_issuer(error: &io::Error) {
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<TlsError>()),
            Some(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        ),
        "{error:?}"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn directory_owner_cleans_up_on_unwind_and_future_cancellation() {
    let owner = directory();
    let path = owner.path.clone();
    std::fs::write(path.join("ca.key"), b"unwind fixture key").unwrap();
    assert!(path.join("ca.key").is_file());
    let unwound = std::panic::catch_unwind(move || {
        let _owner = owner;
        panic!("exercise TLS fixture unwinding");
    });
    assert!(unwound.is_err());
    assert!(
        !path.exists(),
        "unwinding must remove the directory and key file"
    );

    let owner = directory();
    let path = owner.path.clone();
    std::fs::write(path.join("ca.key"), b"cancellation fixture key").unwrap();
    assert!(path.join("ca.key").is_file());
    let mut suspended = Box::pin(async move {
        let _owner = owner;
        std::future::pending::<()>().await;
    });
    assert!(suspended.as_mut().now_or_never().is_none());
    assert!(
        path.join("ca.key").is_file(),
        "suspended fixture must retain its key file"
    );
    // Cancellation drops the pending future and its directory owner without a process signal.
    drop(suspended);
    assert!(
        !path.exists(),
        "cancellation must remove the directory and key file"
    );
}

#[tokio::test]
async fn pem4_ca_bundle_verifies_real_tls_and_rejects_unknown_ca_name_and_malformed_pem() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let directory = directory();
        let ca = CertAuthority::generate();
        let pem = encoded_ca(&ca, LineEnding::CRLF);
        let loaded = CertAuthority::load(&pem, &ca.key_pem()).unwrap();
        assert_eq!(loaded.cert_der, ca.cert_der);
        assert_eq!(
            loaded.cert_pem(),
            pem,
            "persisted CA bytes must not be normalized"
        );
        let path = directory.path.join("roots.pem");
        let mut bundle = loaded.key_pem();
        bundle.extend_from_slice(b"text between PEM sections\n");
        bundle.extend_from_slice(&pem);
        std::fs::write(&path, bundle).unwrap();
        let mut config = TlsConfig::default();
        config.verify_upstream = true;
        config.upstream_ca_cert = vec![path.clone()];
        let trusted = build_upstream_connector(&config, true, &[]);
        exchange(&trusted, &loaded, "upstream.test").await.unwrap();

        let wrong_name = exchange(&trusted, &loaded, "wrong.test").await.unwrap_err();
        assert!(
            matches!(
                wrong_name
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<TlsError>()),
                Some(TlsError::InvalidCertificate(
                    CertificateError::NotValidForName
                        | CertificateError::NotValidForNameContext { .. }
                ))
            ),
            "{wrong_name:?}"
        );

        std::fs::write(&path, encoded_ca(&unrelated_ca(), LineEnding::LF)).unwrap();
        let unknown = build_upstream_connector(&config, true, &[]);
        unknown_issuer(
            &exchange(&unknown, &loaded, "upstream.test")
                .await
                .unwrap_err(),
        );

        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\n%%%invalid%%%\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let malformed = build_upstream_connector(&config, true, &[]);
        unknown_issuer(
            &exchange(&malformed, &loaded, "upstream.test")
                .await
                .unwrap_err(),
        );
        assert!(CertAuthority::load(b"not a certificate", &loaded.key_pem()).is_err());
        assert!(CertAuthority::load(&pem, b"not a key").is_err());
    })
    .await
    .expect("TLS CA trust regression did not finish");
}

#[tokio::test]
async fn scoped_ca_trust_is_enforced_by_real_tls_not_only_connector_selection() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let directory = directory();
        let ca = CertAuthority::generate();
        let cert = directory.path.join("ca.pem");
        let key = directory.path.join("ca.key");
        std::fs::write(&cert, encoded_ca(&ca, LineEnding::LF)).unwrap();
        std::fs::write(&key, ca.key_pem()).unwrap();
        let mut config = TlsConfig::default();
        config.verify_upstream = true;
        config.intercept_ca.cert_path = Some(cert.clone());
        config.intercept_ca.key_path = Some(key);
        config.scoped_upstream_ca_cert = vec![ScopedUpstreamCaCert {
            pattern: "upstream.test".into(),
            path: cert,
        }];
        let state = TlsState::new(config, SecretsHandle::new(SecretsConfig::default())).unwrap();
        exchange(
            state.upstream_connector_for("upstream.test"),
            &ca,
            "upstream.test",
        )
        .await
        .unwrap();
        // The default connector must not inherit the scoped CA, even for the same signed leaf.
        unknown_issuer(
            &exchange(
                state.upstream_connector_for("outside.test"),
                &ca,
                "upstream.test",
            )
            .await
            .unwrap_err(),
        );
    })
    .await
    .expect("scoped TLS CA trust regression did not finish");
}
