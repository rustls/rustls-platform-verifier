#[cfg(feature = "ffi-testing")]
pub mod ffi;

mod verification_real_world;

mod verification_mock;

struct TestCase<'a> {
    /// The name of the server we're connecting to.
    pub reference_id: &'a str,

    /// The certificates presented by the TLS server, in the same order.
    pub chain: &'a [&'a [u8]],

    /// The stapled OCSP response given to us by Rustls, if any.
    pub stapled_ocsp: Option<&'a [u8]>,

    pub expected_result: Result<(), rustls::Error>,
}
