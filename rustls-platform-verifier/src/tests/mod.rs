#[cfg(feature = "ffi-testing")]
pub mod ffi;

#[cfg(all(test, not(target_os = "android")))]
use std::hash::{DefaultHasher, Hasher};
use std::{error::Error as StdError, sync::Arc};

mod verification_real_world;

mod verification_mock;

#[cfg(all(test, not(target_os = "android")))]
use rustls::client::danger::ServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::error::CertificateError;
use rustls::{
    pki_types,
    Error::{self as TlsError, InvalidCertificate},
};

struct TestCase<'a, E: StdError> {
    /// The name of the server we're connecting to.
    pub reference_id: &'a str,

    /// The certificates presented by the TLS server, in the same order.
    pub chain: &'a [&'a [u8]],

    /// The stapled OCSP response given to us by Rustls, if any.
    pub stapled_ocsp: Option<&'a [u8]>,

    /// The time to use as the current time for verification.
    pub verification_time: pki_types::UnixTime,

    pub expected_result: Result<(), TlsError>,

    /// An error that should be present inside an expected `CertificateError::Other` variant.
    ///
    /// Set this if the error being tested uses `CertificateError::Other` and not statically known
    /// variants in [TlsError]
    #[allow(dead_code)]
    pub other_error: Option<E>,
}

pub fn assert_cert_error_eq<E: StdError + PartialEq + 'static>(
    result: &Result<(), TlsError>,
    expected: &Result<(), TlsError>,
    expected_err: Option<&E>,
) {
    // If the expected error is an "Other" CertificateError we can't directly assert equality, we rely
    // on the test caller to provide the correct value to compare.
    if let (
        Err(InvalidCertificate(CertificateError::Other(err))),
        Err(InvalidCertificate(CertificateError::Other(_))),
    ) = (result, expected)
    {
        let expected_err = expected_err.expect("error not provided for `Other` case handling");
        let err: &E = err
            .source()
            .and_then(|source| source.downcast_ref())
            .expect("incorrect `Other` inner error kind");
        assert_eq!(err, expected_err);
    } else {
        assert_eq!(result, expected);
    }
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn certificate_error_assertion_rejects_success() {
    use crate::verification::EkuError;
    let expected = Err(InvalidCertificate(CertificateError::Other(
        rustls::error::OtherError::new(EkuError),
    )));
    assert_cert_error_eq(&Ok(()), &expected, Some(&EkuError));
}

#[test]
#[should_panic(expected = "incorrect `Other` inner error kind")]
fn certificate_error_assertion_checks_actual_error() {
    use crate::verification::EkuError;
    let expected = Err(InvalidCertificate(CertificateError::Other(
        rustls::error::OtherError::new(EkuError),
    )));
    let actual = Err(InvalidCertificate(CertificateError::Other(
        rustls::error::OtherError::new(std::io::Error::other("unexpected error")),
    )));
    assert_cert_error_eq(&actual, &expected, Some(&EkuError));
}

#[cfg(not(target_os = "android"))]
#[test]
fn configuration_hash_distinguishes_extra_roots() {
    let provider = test_provider();
    let first = crate::Verifier::new_with_extra_roots(
        [pki_types::CertificateDer::from(
            include_bytes!("verification_mock/root1.crt").as_slice(),
        )],
        provider.clone(),
    )
    .unwrap();
    let second = crate::Verifier::new_with_extra_roots(
        [pki_types::CertificateDer::from(
            include_bytes!("verification_mock/root1-int1.crt").as_slice(),
        )],
        provider,
    )
    .unwrap();
    assert_eq!(configuration_hash(&first), configuration_hash(&first));
    assert_ne!(configuration_hash(&first), configuration_hash(&second));
}

#[cfg(not(target_os = "android"))]
#[test]
fn configuration_hash_distinguishes_root_overrides() {
    let provider = test_provider();
    let first = crate::Verifier::new_with_fake_root(
        pki_types::CertificateDer::from(include_bytes!("verification_mock/root1.crt").as_slice()),
        provider.clone(),
    );
    let second = crate::Verifier::new_with_fake_root(
        pki_types::CertificateDer::from(
            include_bytes!("verification_mock/root1-int1.crt").as_slice(),
        ),
        provider,
    );
    assert_ne!(configuration_hash(&first), configuration_hash(&second));
}

#[cfg(not(target_os = "android"))]
#[test]
fn configuration_hash_distinguishes_signature_algorithms() {
    let provider = test_provider();
    let mut restricted = provider.as_ref().clone();
    restricted.signature_verification_algorithms = rustls::crypto::WebPkiSupportedAlgorithms::new(
        &[],
        &provider.signature_verification_algorithms.mapping()[1..],
    )
    .unwrap();
    let root =
        pki_types::CertificateDer::from(include_bytes!("verification_mock/root1.crt").as_slice());
    let first = crate::Verifier::new_with_fake_root(root.clone(), provider);
    let second = crate::Verifier::new_with_fake_root(root, Arc::new(restricted));
    assert_ne!(configuration_hash(&first), configuration_hash(&second));
}

fn test_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_ring::DEFAULT_PROVIDER.clone())
}

#[cfg(all(test, not(target_os = "android")))]
fn configuration_hash(verifier: &crate::Verifier) -> u64 {
    let mut hasher = DefaultHasher::new();
    verifier.hash_config(&mut hasher);
    hasher.finish()
}
