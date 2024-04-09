#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use rustls::ClientConfig;
use std::sync::Arc;

mod verification;
pub use verification::Verifier;

// Build the Android module when generating docs so that
// the Android-specific functions are included regardless of
// the host.
#[cfg(any(all(doc, docsrs), target_os = "android"))]
#[cfg_attr(docsrs, doc(cfg(target_os = "android")))]
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
#[cfg_attr(feature = "ffi-testing", allow(unused_imports))]
pub use tests::ffi::*;

/// Creates and returns a `rustls` configuration that verifies TLS
/// certificates in the best way for the underlying OS platform, using
/// safe defaults for the `rustls` configuration.
///
/// # Example
///
/// This example shows how to use the custom verifier with the `reqwest` crate:
/// ```ignore
/// # use reqwest::ClientBuilder;
/// #[tokio::main]
/// async fn main() {
///     let client = ClientBuilder::new()
///         .use_preconfigured_tls(rustls_platform_verifier::tls_config())
///         .build()
///         .expect("nothing should fail");
///
///     let _response = client.get("https://example.com").send().await;
/// }
/// ```
///
/// **Important:** You must ensure that your `reqwest` version is using the same Rustls
/// version as this crate or it will panic when downcasting the `&dyn Any` verifier.
///
/// If you require more control over the rustls `ClientConfig`, you can
/// instantiate a [Verifier] with [Verifier::default] and then use it
/// with [`DangerousClientConfigBuilder::with_custom_certificate_verifier`][rustls::client::danger::DangerousClientConfigBuilder::with_custom_certificate_verifier].
///
/// Refer to the crate level documentation to see what platforms
/// are currently supported.
pub fn tls_config() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier::new()))
        .with_no_client_auth()
}

/// Attempts to construct a `rustls` configuration that verifies TLS certificates in the best way
/// for the underlying OS platform, using the provided
/// [`CryptoProvider`][rustls::crypto::CryptoProvider].
///
/// See [`tls_config`] for further documentation.
///
/// # Errors
///
/// Propagates any error returned by [`rustls::ConfigBuilder::with_safe_default_protocol_versions`].
pub fn tls_config_with_provider(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier::new().with_provider(provider)))
        .with_no_client_auth())
}

/// Exposed for debugging certificate issues with standalone tools.
///
/// This is not intended for production use, you should use [tls_config] instead.
#[cfg(feature = "dbg")]
pub fn verifier_for_dbg(root: &[u8]) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
    Arc::new(Verifier::new_with_fake_root(root))
}
