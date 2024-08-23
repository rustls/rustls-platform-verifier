use rustls::crypto::CryptoProvider;
use std::sync::Arc;

#[cfg(all(
    any(unix, target_arch = "wasm32"),
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "tvos")
))]
mod others;

#[cfg(all(
    any(unix, target_arch = "wasm32"),
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "tvos")
))]
pub use others::Verifier;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
mod apple;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
pub use apple::Verifier;

#[cfg(target_os = "android")]
pub(crate) mod android;

#[cfg(target_os = "android")]
pub use android::Verifier;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::Verifier;

/// An EKU was invalid for the use case of verifying a server certificate.
///
/// This error is used primarily for tests.
#[cfg_attr(windows, allow(dead_code))] // not used by windows verifier
#[derive(Debug, PartialEq)]
pub(crate) struct EkuError;

impl std::fmt::Display for EkuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate had invalid extensions")
    }
}

impl std::error::Error for EkuError {}

// Log the certificate we are verifying so that we can try and find what may be wrong with it
// if we need to debug a user's situation.
fn log_server_cert(_end_entity: &rustls::pki_types::CertificateDer<'_>) {
    #[cfg(feature = "cert-logging")]
    {
        use base64::Engine;
        log::debug!(
            "verifying certificate: {}",
            base64::engine::general_purpose::STANDARD.encode(_end_entity.as_ref())
        );
    }
}

// Unknown certificate error shorthand. Used when we need to construct an "Other" certificate
// error with a platform specific error message.
#[cfg(any(windows, target_os = "macos", target_os = "ios", target_os = "tvos"))]
fn invalid_certificate(reason: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::from(Box::from(reason.into())),
    )))
}

/// List of EKUs that one or more of that *must* be in the end-entity certificate.
///
/// Legacy server-gated crypto OIDs are assumed to no longer be in use.
///
/// Currently supported:
/// - id-kp-serverAuth
// TODO: Chromium also allows for `OID_ANY_EKU` on Android.
#[cfg(target_os = "windows")]
// XXX: Windows requires that we NUL terminate EKU strings and we want to make sure that only the
// data part of the `&str` pointer (using `.as_ptr()`), not all of its metadata.
// This can be cleaned up when our MSRV is increased to 1.77 and C-string literals are available.
// See https://github.com/rustls/rustls-platform-verifier/issues/126#issuecomment-2306232794.
const ALLOWED_EKUS: &[*mut u8] = &["1.3.6.1.5.5.7.3.1\0".as_ptr() as *mut u8];
#[cfg(target_os = "android")]
pub const ALLOWED_EKUS: &[&str] = &["1.3.6.1.5.5.7.3.1"];

impl Verifier {
    /// Chainable setter to configure the [`CryptoProvider`] for this `Verifier`.
    ///
    /// This will be used instead of the rustls processs-default `CryptoProvider`, even if one has
    /// been installed.
    pub fn with_provider(mut self, crypto_provider: Arc<CryptoProvider>) -> Self {
        self.set_provider(crypto_provider);
        self
    }

    /// Configures the [`CryptoProvider`] for this `Verifier`.
    ///
    /// This will be used instead of the rustls processs-default `CryptoProvider`, even if one has
    /// been installed.
    pub fn set_provider(&mut self, crypto_provider: Arc<CryptoProvider>) {
        self.crypto_provider = crypto_provider.into();
    }

    fn get_provider(&self) -> &Arc<CryptoProvider> {
        self.crypto_provider.get_or_init(|| {
            CryptoProvider::get_default()
                .expect("rustls default CryptoProvider not set")
                .clone()
        })
    }
}
