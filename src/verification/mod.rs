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

#[cfg(any(windows, target_os = "android", target_os = "macos", target_os = "ios"))]
/// Error messages for errors that are the same across non-WebPKI verification platforms.
pub mod error_messages {
    pub const INVALID_EXTENSIONS: &str = "certificate had invalid extensions";
    #[allow(dead_code)] // Not used on Apple platforms yet.
    pub const EXPIRED: &str = "certificate has expired";
    pub const UNKNOWN_CERT: &str = "no trust chain found for certificate";
    pub const WRONG_NAME: &str = "certificate CN does not match the provided name";
    pub const REVOKED: &str = "certificate has been revoked";
}

#[cfg(all(any(test, feature = "ffi-testing"), target_os = "linux"))]
/// Error messages for WebPKI verification platforms (used only for testing).
pub mod error_messages {
    pub const INVALID_EXTENSIONS: &str = "invalid peer certificate: RequiredEkuNotFound"; // Specific to current test case.
    #[allow(dead_code)] // Not covered by test cases yet, due to lack of support on Apple platforms.
    pub const EXPIRED: &str = "certificate has expired";
    pub const UNKNOWN_CERT: &str = "invalid peer certificate: UnknownIssuer";
    pub const WRONG_NAME: &str = "invalid peer certificate: CertNotValidForName";
    #[allow(dead_code)] // Not supported by `WebPkiVerifier` yet.
    pub const REVOKED: &str = "certificate has been revoked";
}

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

// Certificate data error shorthand
#[cfg(any(windows, target_os = "android", target_os = "macos", target_os = "ios"))]
fn invalid_certificate(reason: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificateData(reason.into())
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
