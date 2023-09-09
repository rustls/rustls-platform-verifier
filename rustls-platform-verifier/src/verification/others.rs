use super::log_server_cert;
use once_cell::sync::OnceCell;
use rustls::{
    client::{ServerCertVerifier, WebPkiVerifier},
    CertificateError, Error as TlsError,
};
use std::sync::Mutex;

/// A TLS certificate verifier that uses the system's root store and WebPKI.
#[derive(Default)]
pub struct Verifier {
    // We use a `OnceCell` so we only need
    // to try loading native root certs once per verifier.
    //
    // We currently keep one set of certificates per-verifier so that
    // locking and unlocking the application will pull fresh root
    // certificates from disk, picking up on any changes
    // that might have been made since.
    inner: OnceCell<WebPkiVerifier>,

    // Extra trust anchors to add to the verifier above and beyond those provided by the
    // platform via rustls-native-certs.
    extra_roots: Mutex<Vec<rustls::OwnedTrustAnchor>>,

    /// Testing only: an additional root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    test_only_root_ca_override: Option<Vec<u8>>,
}

impl Verifier {
    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform.
    pub fn new() -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: Vec::new().into(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform and augmented by
    /// the provided extra root certificates.
    pub fn new_with_extra_roots(roots: impl IntoIterator<Item = rustls::OwnedTrustAnchor>) -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: roots.into_iter().collect::<Vec<_>>().into(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: Vec::new().into(),
            test_only_root_ca_override: Some(root.into()),
        }
    }

    // Attempt to load CA root certificates present on system, fallback to WebPKI roots if error
    fn init_verifier(&self) -> Result<WebPkiVerifier, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();

        // For testing only: load fake root cert, instead of native/WebPKI roots
        #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
        {
            if let Some(test_root) = &self.test_only_root_ca_override {
                let (added, ignored) = root_store.add_parsable_certificates(&[test_root.clone()]);
                if (added != 1) || (ignored != 0) {
                    panic!("Failed to insert fake, test-only root trust anchor");
                }
                return Ok(WebPkiVerifier::new(root_store, None));
            }
        }

        #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                let certs: Vec<Vec<u8>> = certs.into_iter().map(|c| c.0).collect();
                let (added, ignored) = root_store.add_parsable_certificates(&certs);

                if ignored != 0 {
                    log::warn!("Some CA root certificates were ignored due to errors");
                }

                if root_store.is_empty() {
                    log::error!("No CA certificates were loaded from the system");
                } else {
                    log::debug!("Loaded {added} CA certificates from the system");
                }

                // Safety: There's no way for the mutex to be locked multiple times, so this is
                //         an infallible operation.
                let mut extra_roots = self.extra_roots.try_lock().unwrap();
                if !extra_roots.is_empty() {
                    let count = extra_roots.len();
                    root_store.add_trust_anchors(&mut extra_roots.drain(..));
                    log::debug!(
                        "Loaded {count} extra CA certificates in addition to roots from the system",
                    );
                }
            }
            Err(err) => {
                // This only contains a path to a system directory:
                // https://github.com/rustls/rustls-native-certs/blob/bc13b9a6bfc2e1eec881597055ca49accddd972a/src/lib.rs#L91-L94
                return Err(rustls::Error::General(format!(
                    "failed to load system root certificates: {}",
                    err
                )));
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

        Ok(WebPkiVerifier::new(root_store, None))
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, TlsError> {
        log_server_cert(end_entity);

        let verifier = self.inner.get_or_try_init(|| self.init_verifier())?;

        verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                // We currently ignore certificate transparency data so that
                // WebPKI doesn't verify it. Since none of the other platforms currently
                // don't want possibly-bad CT data to cause problems on one platform but not
                // others. On top of that, rustls's verification of it is currently "best effort."
                &mut std::iter::empty(),
                ocsp_response,
                now,
            )
            .map_err(map_webpki_errors)
            // This only contains information from the system or other public
            // bits of the TLS handshake, so it can't leak anything.
            .map_err(|e| {
                log::error!("failed to verify TLS certificate: {}", e);
                e
            })
    }
}

fn map_webpki_errors(err: TlsError) -> TlsError {
    if let TlsError::InvalidCertificate(CertificateError::Other(other_err)) = &err {
        if let Some(webpki::Error::RequiredEkuNotFound) = other_err.downcast_ref::<webpki::Error>()
        {
            return TlsError::InvalidCertificate(CertificateError::Other(std::sync::Arc::new(
                super::EkuError,
            )));
        }
    }

    err
}
