#[cfg(any(target_os = "linux", target_arch = "wasm32"))]
mod others;

#[cfg(any(target_os = "linux", target_arch = "wasm32"))]
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
    log::debug!("verifying certificate: {}", base64::encode(&_end_entity.0));
}

#[cfg(any(windows, target_os = "android", target_os = "macos", target_os = "ios"))]
fn unsupported_server_name() -> rustls::Error {
    log::error!("TLS error: unsupported name type");
    rustls::Error::UnsupportedNameType
}

// Unknown certificate error shorthand. Used when we need to construct an "Other" certificate
// error with a platform specific error message.
#[cfg(any(windows, target_os = "android", target_os = "macos", target_os = "ios"))]
fn invalid_certificate(reason: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(std::sync::Arc::from(
        Box::from(reason.into()),
    )))
}

#[cfg(any(windows, target_os = "android"))]
/// List of EKUs that one or more of that *must* be in the end-entity certificate.
///
/// Legacy server-gated crypto OIDs are assumed to no longer be in use.
///
/// Currently supported:
/// - id-kp-serverAuth
// TODO: Chromium also allows for `OID_ANY_EKU` on Android.
pub const ALLOWED_EKUS: &[&str] = &["1.3.6.1.5.5.7.3.1"];

#[cfg(test)]
mod tests {
    use crate::tls_config;
    use reqwest::ClientBuilder;

    #[tokio::test]
    async fn can_verify_server_cert() {
        let builder = ClientBuilder::new().use_preconfigured_tls(tls_config());

        let client = builder.build().expect("TLS builder should be accepted");

        client
            .get("https://my.1password.com/signin")
            .send()
            .await
            .expect("tls verification should pass");
    }
}
