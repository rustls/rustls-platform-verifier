use std::fmt::Debug;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::server::ParsedCertificate;
use rustls::{
    crypto::CryptoProvider, CertificateError, DigitallySignedStruct, Error as TlsError, OtherError,
    SignatureScheme,
};
use rustls::{pki_types, RootCertStore};

use crate::verification::HostnameVerification;

use super::log_server_cert;

/// A TLS certificate verifier that uses the system's root store and WebPKI.
#[derive(Debug)]
pub struct Verifier {
    roots: RootCertStore,
    signature_algorithms: WebPkiSupportedAlgorithms,
    hostname_verification: HostnameVerification,
}

impl Verifier {
    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform.
    pub fn new(crypto_provider: Arc<CryptoProvider>) -> Result<Self, TlsError> {
        Self::new_inner([], None, crypto_provider, HostnameVerification::Verify)
    }

    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform and augmented by
    /// the provided extra root certificates.
    pub fn new_with_extra_roots(
        extra_roots: impl IntoIterator<Item = pki_types::CertificateDer<'static>>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Result<Self, TlsError> {
        Self::new_inner(
            extra_roots,
            None,
            crypto_provider,
            HostnameVerification::Verify,
        )
    }

    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform and augmented by
    /// the provided extra root certificates.
    ///
    /// The hostname verification is set to the provided value.
    pub fn new_with_hostname_verification(
        extra_roots: impl IntoIterator<Item = pki_types::CertificateDer<'static>>,
        crypto_provider: Arc<CryptoProvider>,
        hostname_verification: HostnameVerification,
    ) -> Result<Self, TlsError> {
        Self::new_inner(extra_roots, None, crypto_provider, hostname_verification)
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(
        root: pki_types::CertificateDer<'static>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        Self::new_inner(
            [],
            Some(root),
            crypto_provider,
            HostnameVerification::Verify,
        )
        .expect("failed to create verifier with fake root")
    }

    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform and augmented by
    /// the provided extra root certificates.
    fn new_inner(
        extra_roots: impl IntoIterator<Item = pki_types::CertificateDer<'static>>,
        #[allow(unused)] // test_root is only used in tests
        test_root: Option<pki_types::CertificateDer<'static>>,
        crypto_provider: Arc<CryptoProvider>,
        hostname_verification: HostnameVerification,
    ) -> Result<Self, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();

        // For testing only: load fake root cert, instead of native/WebPKI roots
        #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
        {
            if let Some(test_root) = test_root {
                root_store.add(test_root)?;
                return Ok(Self {
                    roots: root_store,
                    signature_algorithms: crypto_provider.signature_verification_algorithms,
                    hostname_verification,
                });
            }
        }

        // While we ignore invalid certificates from the system, we forward errors from
        // parsing the extra roots to the caller.
        for cert in extra_roots {
            root_store.add(cert)?;
        }

        #[cfg(all(
            unix,
            not(target_os = "android"),
            not(target_vendor = "apple"),
            not(target_arch = "wasm32"),
        ))]
        {
            let result = rustls_native_certs::load_native_certs();
            let (added, ignored) = root_store.add_parsable_certificates(result.certs);
            if ignored > 0 {
                log::warn!("{ignored} platform CA root certificates were ignored due to errors");
            }

            for error in result.errors {
                log::warn!("Error loading CA root certificate: {error}");
            }

            // Don't return an error if this fails when other roots have already been loaded via
            // `new_with_extra_roots`. It leads to extra failure cases where connections would otherwise still work.
            if root_store.is_empty() {
                return Err(rustls::Error::General(
                    "No CA certificates were loaded from the system".to_owned(),
                ));
            } else {
                log::debug!("Loaded {added} CA root certificates from the system");
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            root_store.add_parsable_certificates(
                webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
            );
        };

        Ok(Self {
            roots: root_store,
            signature_algorithms: crypto_provider.signature_verification_algorithms,
            hostname_verification,
        })
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        intermediates: &[pki_types::CertificateDer<'_>],
        server_name: &pki_types::ServerName,
        ocsp_response: &[u8],
        now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        log_server_cert(end_entity);
        let cert = ParsedCertificate::try_from(end_entity)?;

        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.signature_algorithms.all,
        )
        .map_err(map_webpki_errors)?;

        if !ocsp_response.is_empty() {
            log::trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        if self.hostname_verification.is_verify() {
            rustls::client::verify_server_name(&cert, server_name).map_err(map_webpki_errors)?;
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_algorithms.supported_schemes()
    }
}

fn map_webpki_errors(err: TlsError) -> TlsError {
    let err = match &err {
        TlsError::InvalidCertificate(CertificateError::InvalidPurpose)
        | TlsError::InvalidCertificate(CertificateError::InvalidPurposeContext { .. }) => {
            TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
                super::EkuError,
            ))))
        }
        _ => err,
    };

    log::error!("failed to verify TLS certificate: {}", err);
    err
}
