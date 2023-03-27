use super::log_server_cert;
use once_cell::sync::OnceCell;
use rustls::{
    client::{ServerCertVerifier, WebPkiVerifier},
    CertificateError, Error as TlsError, RootCertStore,
};

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

    /// Testing only: an additional root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    test_only_root_ca_override: Option<Vec<u8>>,
}

impl Verifier {
    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI.
    pub fn new() -> Self {
        Self {
            inner: OnceCell::new(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            inner: OnceCell::new(),
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

                // While we load webpki-roots anyway, this can be helpful to know for troubleshooting.
                if root_store.is_empty() {
                    log::error!("No CA certificates were loaded from the system");
                }

                // Finding TLS roots on Linux is not reliable enough to always depend on it
                // across various distributions. Instead, we always load the WebPKI roots in
                // addition so that a valid trust anchor is more likely to be available.
                load_webpki_roots(&mut root_store);

                log::debug!(
                    "Loaded WebPKI roots in addition to {} roots from the system",
                    added
                );
            }
            Err(err) => {
                // This only contains a path to a system directory:
                // https://github.com/rustls/rustls-native-certs/blob/main/src/lib.rs#L71
                log::error!(
                    "No CA certificates were loaded: {}. Falling back to WebPKI roots",
                    err,
                );
                load_webpki_roots(&mut root_store);
            }
        };

        #[cfg(target_arch = "wasm32")]
        {
            load_webpki_roots(&mut root_store);
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

/// Loads the static `webpki-roots` into the provided certificate store.
fn load_webpki_roots(store: &mut RootCertStore) {
    use rustls::OwnedTrustAnchor;

    store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|root| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            root.subject,
            root.spki,
            root.name_constraints,
        )
    }));
}
