#[cfg(all(
    any(unix, target_arch = "wasm32"),
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "ios")
))]
mod others;

#[cfg(all(
    any(unix, target_arch = "wasm32"),
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "ios")
))]
pub use others::Verifier;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;

#[cfg(any(target_os = "macos", target_os = "ios"))]
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
fn log_server_cert(_end_entity: &rustls::Certificate) {
    #[cfg(feature = "cert-logging")]
    {
        use base64::Engine;
        log::debug!(
            "verifying certificate: {}",
            base64::engine::general_purpose::STANDARD.encode(&_end_entity.0)
        );
    }
}

#[cfg(any(windows, target_os = "android", target_os = "macos", target_os = "ios"))]
fn unsupported_server_name() -> rustls::Error {
    log::error!("TLS error: unsupported name type");
    rustls::Error::UnsupportedNameType
}

// Unknown certificate error shorthand. Used when we need to construct an "Other" certificate
// error with a platform specific error message.
#[cfg(any(windows, target_os = "macos", target_os = "ios"))]
fn invalid_certificate(reason: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(std::sync::Arc::from(
        Box::from(reason.into()),
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
