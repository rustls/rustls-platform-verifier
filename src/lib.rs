#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use rustls::ClientConfig;
use std::sync::Arc;

mod verification;
use verification::Verifier;

// Build the Android module when generating docs so that
// the Android-specific functions are included.
#[cfg_attr(docsrs, cfg(any(target_os = "android", doc)))]
#[cfg_attr(not(docsrs), cfg(target_os = "android"))]
pub mod android;

#[cfg(windows)]
mod windows;

/// Fixures and data to support testing the server
/// certificate verifier.
#[cfg(any(test, feature = "ffi-testing"))]
mod tests;

// Re-export any exported functions that are required for
// tests to run in a platform-native environment.
#[cfg(feature = "ffi-testing")]
pub use tests::ffi::*;

/// Creates and returns a `rustls` configuration that verifies TLS
/// certificates in the best way for the underlying OS platform.
///
/// # Example
///
/// This example shows how to use the custom verifier with the `reqwest` crate:
/// ```no_run
/// # use reqwest::ClientBuilder;
/// #[tokio::main]
/// async fn main() {
///     let client = ClientBuilder::new()
///         .use_preconfigured_tls(platform_tls::tls_config())
///         .build()
///         .expect("nothing should fail");
///
///     let _response = client.get("https://example.com").send().await;
/// }
/// ```
///
/// Refer to the crate level documentation to see what platforms
/// are currently supported.
pub fn tls_config() -> ClientConfig {
    rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier_for_testing())
        .with_no_client_auth()
}

/// Exposed for test usage. Don't use this, use [tls_config] instead.
///
/// This verifier must be exactly equivalent to the verifier used in the `ClientConfig` returned by [tls_config].
pub(crate) fn verifier_for_testing() -> Arc<dyn rustls::client::ServerCertVerifier> {
    Arc::new(Verifier::new())
}

/// Exposed for debugging customer certificate issues. Don't use this, use [tls_config] instead.
#[cfg(feature = "dbg")]
pub fn verifier_for_dbg(root: &[u8]) -> Arc<dyn rustls::client::ServerCertVerifier> {
    Arc::new(Verifier::new_with_fake_root(root))
}
