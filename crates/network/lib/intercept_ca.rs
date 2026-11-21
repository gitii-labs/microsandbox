//! Shared certificate-authority loading for launch admission and the TLS engine.

use std::path::PathBuf;

use microsandbox_types::TlsConfig;
#[cfg(feature = "engine")]
use rcgen::{CertificateParams, DistinguishedName, IsCa};
use rcgen::{Issuer, KeyPair, PublicKeyData};
use rustls::pki_types::CertificateDer;
use rustls::server::ParsedCertificate;
use zeroize::Zeroizing;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A certificate authority for signing per-domain certificates.
pub struct CertAuthority {
    /// CA issuer handle for signing leaf certificates.
    pub issuer: Issuer<'static, KeyPair>,
    /// DER-encoded CA certificate.
    pub cert_der: CertificateDer<'static>,
    /// PEM-encoded CA certificate (for guest installation).
    #[cfg(feature = "engine")]
    cert_pem: String,
}

/// Errors that prevent TLS interception state from being initialized safely.
#[derive(Debug, thiserror::Error)]
pub enum TlsStateError {
    /// Exactly one of the intercept CA certificate/key paths was configured.
    #[error("intercept CA config is incomplete; set both cert_path and key_path")]
    IncompleteInterceptCaConfig,

    /// The configured intercept CA certificate could not be read.
    #[error("failed to read intercept CA certificate `{path}`: {source}")]
    ReadInterceptCaCert {
        /// Certificate path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configured intercept CA private key could not be read.
    #[error("failed to read intercept CA key `{path}`: {source}")]
    ReadInterceptCaKey {
        /// Private-key path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configured intercept CA files were readable but did not form a usable CA.
    #[error("failed to load intercept CA `{cert_path}` / `{key_path}`: {reason}")]
    InvalidInterceptCa {
        /// Certificate path that was loaded.
        cert_path: PathBuf,
        /// Private-key path that was loaded.
        key_path: PathBuf,
        /// Validation or parsing failure from the CA loader.
        reason: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CertAuthority {
    /// Generate a new self-signed CA.
    #[cfg(feature = "engine")]
    pub fn generate() -> Self {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "microsandbox CA");
        dn.push(rcgen::DnType::OrganizationName, "microsandbox");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let key_pair = KeyPair::generate().expect("failed to generate CA key pair");
        let cert = params
            .self_signed(&key_pair)
            .expect("failed to self-sign CA certificate");

        let cert_pem = cert.pem();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let issuer = Issuer::new(params, key_pair);

        Self {
            issuer,
            cert_der,
            cert_pem,
        }
    }

    /// Load a CA from PEM-encoded certificate and private key bytes.
    ///
    /// The original PEM/DER bytes are preserved for `cert_pem()`/`cert_der`
    /// so the identity served to guests matches the persisted file exactly.
    pub fn load(cert_pem_bytes: &[u8], key_pem_bytes: &[u8]) -> Result<Self, String> {
        let cert_pem_str =
            std::str::from_utf8(cert_pem_bytes).map_err(|e| format!("invalid cert PEM: {e}"))?;
        let key_pem_str =
            std::str::from_utf8(key_pem_bytes).map_err(|e| format!("invalid key PEM: {e}"))?;

        let key_pair =
            KeyPair::from_pem(key_pem_str).map_err(|e| format!("failed to parse CA key: {e}"))?;

        let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair)
            .map_err(|e| format!("failed to parse CA cert: {e}"))?;

        let original_der = pem_to_der(cert_pem_str)?;

        Ok(Self {
            issuer,
            cert_der: CertificateDer::from(original_der),
            #[cfg(feature = "engine")]
            cert_pem: cert_pem_str.to_string(),
        })
    }

    /// Get the CA certificate as PEM bytes (for guest installation).
    #[cfg(feature = "engine")]
    pub fn cert_pem(&self) -> Vec<u8> {
        self.cert_pem.as_bytes().to_vec()
    }

    /// Get the CA private key as PEM bytes (for persistence).
    #[cfg(feature = "engine")]
    pub fn key_pem(&self) -> Vec<u8> {
        self.issuer.key().serialize_pem().as_bytes().to_vec()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Load and validate explicitly configured signing inputs without touching the default CA.
pub fn validate_explicit_intercept_ca(config: &TlsConfig) -> Result<(), TlsStateError> {
    load_explicit_ca(config, true).map(|_| ())
}

pub(crate) fn load_explicit_ca(
    config: &TlsConfig,
    require_matching_key: bool,
) -> Result<Option<CertAuthority>, TlsStateError> {
    let (cert_path, key_path) = match (
        &config.intercept_ca.cert_path,
        &config.intercept_ca.key_path,
    ) {
        (None, None) => return Ok(None),
        (Some(cert_path), Some(key_path)) => (cert_path, key_path),
        _ => return Err(TlsStateError::IncompleteInterceptCaConfig),
    };

    let cert = std::fs::read(cert_path).map_err(|source| TlsStateError::ReadInterceptCaCert {
        path: cert_path.clone(),
        source,
    })?;
    let key = Zeroizing::new(std::fs::read(key_path).map_err(|source| {
        TlsStateError::ReadInterceptCaKey {
            path: key_path.clone(),
            source,
        }
    })?);
    let invalid_pair = |reason| TlsStateError::InvalidInterceptCa {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        reason,
    };
    let ca = CertAuthority::load(&cert, &key).map_err(invalid_pair)?;
    if require_matching_key {
        let parsed = ParsedCertificate::try_from(&ca.cert_der)
            .map_err(|err| invalid_pair(format!("failed to parse CA public key: {err}")))?;
        if parsed.subject_public_key_info().as_ref() != ca.issuer.key().subject_public_key_info() {
            return Err(invalid_pair(
                "certificate and signing key do not match".into(),
            ));
        }
    }
    Ok(Some(ca))
}

/// Extract DER bytes from a PEM-encoded certificate string.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map(|cert| cert.to_vec())
        .map_err(|e| format!("failed to parse PEM: {e}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "engine"))]
mod tests {
    use super::*;

    #[test]
    fn matching_signing_inputs_are_required_only_when_requested() {
        let dir = std::env::temp_dir().join(format!(
            "msb-intercept-ca-{}-{}",
            std::process::id(),
            rand::random::<u64>(),
        ));
        std::fs::create_dir(&dir).unwrap();
        let cert = dir.join("ca.crt");
        let key = dir.join("ca.key");
        let ca = CertAuthority::generate();
        std::fs::write(&cert, ca.cert_pem()).unwrap();
        std::fs::write(&key, ca.key_pem()).unwrap();
        let mut config = TlsConfig::default();
        config.intercept_ca.cert_path = Some(cert);
        config.intercept_ca.key_path = Some(key.clone());

        let matching = validate_explicit_intercept_ca(&config);
        std::fs::write(&key, CertAuthority::generate().key_pem()).unwrap();
        let mismatched = validate_explicit_intercept_ca(&config);
        let ordinary = load_explicit_ca(&config, false);
        std::fs::remove_dir_all(&dir).unwrap();

        matching.unwrap();
        assert!(
            matches!(mismatched, Err(TlsStateError::InvalidInterceptCa { reason, .. })
                if reason == "certificate and signing key do not match")
        );
        assert!(ordinary.unwrap().is_some());
        assert!(
            load_explicit_ca(&TlsConfig::default(), true)
                .unwrap()
                .is_none()
        );
    }
}
