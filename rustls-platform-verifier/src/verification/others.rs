use super::log_server_cert;
use once_cell::sync::OnceCell;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types;
use rustls::{
    crypto::CryptoProvider, CertificateError, DigitallySignedStruct, Error as TlsError, OtherError,
    SignatureScheme,
};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

/// A TLS certificate verifier that uses the system's root store and WebPKI.
#[derive(Debug)]
pub struct Verifier {
    // We use a `OnceCell` so we only need
    // to try loading native root certs once per verifier.
    //
    // We currently keep one set of certificates per-verifier so that
    // locking and unlocking the application will pull fresh root
    // certificates from disk, picking up on any changes
    // that might have been made since.
    inner: OnceCell<Arc<WebPkiServerVerifier>>,

    // Extra trust anchors to add to the verifier above and beyond those provided by the
    // platform via rustls-native-certs.
    extra_roots: Mutex<Vec<pki_types::TrustAnchor<'static>>>,

    /// Testing only: an additional root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    test_only_root_ca_override: Option<Vec<u8>>,

    pub(super) crypto_provider: OnceCell<Arc<CryptoProvider>>,
}

impl Verifier {
    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform.
    ///
    /// A [`CryptoProvider`] must be set with
    /// [`set_provider`][Verifier::set_provider]/[`with_provider`][Verifier::with_provider] or
    /// [`CryptoProvider::install_default`] before the verifier can be used.
    pub fn new() -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: Vec::new().into(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
            crypto_provider: OnceCell::new(),
        }
    }

    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform and augmented by
    /// the provided extra root certificates.
    pub fn new_with_extra_roots(
        roots: impl IntoIterator<Item = pki_types::TrustAnchor<'static>>,
    ) -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: roots.into_iter().collect::<Vec<_>>().into(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
            crypto_provider: OnceCell::new(),
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: Vec::new().into(),
            test_only_root_ca_override: Some(root.into()),
            crypto_provider: OnceCell::new(),
        }
    }

    fn get_or_init_verifier(&self) -> Result<&Arc<WebPkiServerVerifier>, TlsError> {
        self.inner.get_or_try_init(|| self.init_verifier())
    }

    // Attempt to load CA root certificates present on system, fallback to WebPKI roots if error
    fn init_verifier(&self) -> Result<Arc<WebPkiServerVerifier>, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();

        // For testing only: load fake root cert, instead of native/WebPKI roots
        #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
        {
            if let Some(test_root) = &self.test_only_root_ca_override {
                let (added, ignored) =
                    root_store.add_parsable_certificates([pki_types::CertificateDer::from(
                        test_root.as_ref(),
                    )]);
                if (added != 1) || (ignored != 0) {
                    panic!("Failed to insert fake, test-only root trust anchor");
                }
                return Ok(WebPkiServerVerifier::builder_with_provider(
                    root_store.into(),
                    Arc::clone(self.get_provider()),
                )
                .build()
                .unwrap());
            }
        }

        // Safety: There's no way for the mutex to be locked multiple times, so this is
        // an infallible operation.
        let mut extra_roots = self.extra_roots.try_lock().unwrap();
        if !extra_roots.is_empty() {
            let count = extra_roots.len();
            root_store.extend(extra_roots.drain(..));
            log::debug!(
                "Loaded {count} extra CA certificates in addition to possible system roots",
            );
        }

        #[cfg(all(
            unix,
            not(target_os = "android"),
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "tvos"),
            not(target_arch = "wasm32"),
        ))]
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                let (added, ignored) = root_store.add_parsable_certificates(certs);

                if ignored != 0 {
                    log::warn!("Some CA root certificates were ignored due to errors");
                }

                if root_store.is_empty() {
                    log::error!("No CA certificates were loaded from the system");
                } else {
                    log::debug!("Loaded {added} CA certificates from the system");
                }
            }
            Err(err) => {
                // This only contains a path to a system directory:
                // https://github.com/rustls/rustls-native-certs/blob/bc13b9a6bfc2e1eec881597055ca49accddd972a/src/lib.rs#L91-L94
                const MSG: &str = "failed to load system root certificates: ";

                // Don't return an error if this fails when other roots have already been loaded via
                // `new_with_extra_roots`. It leads to extra failure cases where connections would otherwise still work.
                if root_store.is_empty() {
                    return Err(rustls::Error::General(format!("{MSG}{err}")));
                } else {
                    log::error!("{MSG}{err}");
                }
            }
        };

        #[cfg(target_arch = "wasm32")]
        {
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|root| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    root.subject,
                    root.spki,
                    root.name_constraints,
                )
            }));
        };

        WebPkiServerVerifier::builder_with_provider(
            root_store.into(),
            Arc::clone(self.get_provider()),
        )
        .build()
        .map_err(|e| TlsError::Other(OtherError(Arc::new(e))))
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

        self.get_or_init_verifier()?
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map_err(map_webpki_errors)
            // This only contains information from the system or other public
            // bits of the TLS handshake, so it can't leak anything.
            .map_err(|e| {
                log::error!("failed to verify TLS certificate: {}", e);
                e
            })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.get_or_init_verifier()?
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.get_or_init_verifier()?
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match self.get_or_init_verifier() {
            Ok(v) => v.supported_verify_schemes(),
            Err(_) => Vec::default(),
        }
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

fn map_webpki_errors(err: TlsError) -> TlsError {
    if let TlsError::InvalidCertificate(CertificateError::Other(other_err)) = &err {
        if let Some(webpki::Error::RequiredEkuNotFound) =
            other_err.0.downcast_ref::<webpki::Error>()
        {
            return TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
                super::EkuError,
            ))));
        }
    }

    err
}
