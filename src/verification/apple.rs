use super::{log_server_cert, unsupported_server_name};
use crate::verification::invalid_certificate;
use core_foundation::date::CFDate;
use core_foundation_sys::date::kCFAbsoluteTimeIntervalSince1970;
use rustls::{client::ServerCertVerifier, CertificateError, Error as TlsError};
use security_framework::{
    certificate::SecCertificate, policy::SecPolicy, secure_transport::SslProtocolSide,
    trust::SecTrust,
};
use std::time::SystemTime;

mod errors {
    pub(super) use security_framework_sys::base::{
        errSecCertificateRevoked, errSecCreateChainFailed, errSecHostNameMismatch,
        errSecInvalidExtendedKeyUsage,
    };
}

fn system_time_to_cfdate(time: SystemTime) -> Result<CFDate, TlsError> {
    // SAFETY: The interval is defined by macOS externally, but is always present and never modified at runtime
    // since its a global variable.
    //
    // See https://developer.apple.com/documentation/corefoundation/kcfabsolutetimeintervalsince1970.
    let unix_adjustment = unsafe {
        #[allow(clippy::as_conversions)]
        std::time::Duration::from_secs(kCFAbsoluteTimeIntervalSince1970 as u64)
    };

    // Convert a system timestamp based off the UNIX epoch into the
    // Apple epoch used by all `CFAbsoluteTime` values.
    // Subtracting Durations with sub() will panic on overflow
    #[allow(clippy::as_conversions)]
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| TlsError::FailedToGetCurrentTime)?
        .checked_sub(unix_adjustment)
        .ok_or(TlsError::FailedToGetCurrentTime)
        .map(|epoch| CFDate::new(epoch.as_secs() as f64))
}

#[derive(Default)]
pub struct Verifier {
    /// Testing only: The root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    test_only_root_ca_override: Option<Vec<u8>>,
}

impl Verifier {
    /// Creates a new instance of a TLS certificate verifier that utilizes the
    /// macOS certificate facilities.
    pub fn new() -> Self {
        Self {
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            test_only_root_ca_override: Some(root.into()),
        }
    }

    fn verify_certificate(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &str,
        ocsp_response: Option<&[u8]>,
        now: SystemTime,
    ) -> Result<(), TlsError> {
        let certificates: Vec<SecCertificate> = std::iter::once(end_entity.0.as_slice())
            .chain(intermediates.iter().map(|cert| cert.0.as_slice()))
            .map(|cert| {
                SecCertificate::from_der(cert)
                    .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))
            })
            .collect::<Result<Vec<SecCertificate>, _>>()?;

        // Create our verification policy suitable for verifying TLS chains.
        // This uses the "default" verification engine and parameters, the same as Windows.
        //
        // The protocol side should be set to `server` for a client to verify server TLS
        // certificates.
        //
        // The server name will be required to match what the end-entity certificate reports
        //
        // Ref: https://developer.apple.com/documentation/security/1392592-secpolicycreatessl
        let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, Some(server_name));

        // Create our trust evaluation context/chain.
        //
        // Apple requires that the certificate to be verified is always first in the array, and we
        // always place the end-entity certificate at the start.
        //
        // Ref: https://developer.apple.com/documentation/security/1401555-sectrustcreatewithcertificates
        let mut trust_evaluation = SecTrust::create_with_certificates(&certificates, &[policy])
            .map_err(|e| TlsError::General(e.to_string()))?;

        // Tell the system that we want to consider the certificates evaluation at the point
        // in time that `rustls` provided.
        let now = system_time_to_cfdate(now)?;
        trust_evaluation
            .set_trust_verify_date(&now)
            .map_err(|e| invalid_certificate(e.to_string()))?;

        // If we have OCSP response data, make sure the system makes use of it.
        if let Some(ocsp_response) = ocsp_response {
            trust_evaluation
                .set_trust_ocsp_response(std::iter::once(ocsp_response))
                .map_err(|e| invalid_certificate(e.to_string()))?;
        }

        // When testing, support using fake roots and ignoring values present on the system.
        //
        // XXX: This does not currently limit revocation from fetching information online, or prevent
        // the downloading of root CAs.
        #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
        {
            // If these panicked, it would be a programmer bug in the tests.
            if let Some(test_root) = &self.test_only_root_ca_override {
                let test_root =
                    SecCertificate::from_der(test_root).expect("failed to parse test root");

                // Supply the custom root, which will be the only one trusted during evaluation.
                trust_evaluation
                    .set_anchor_certificates(&[test_root])
                    .expect("failed to set anchors");

                // As per [Apple's docs], building and verifying a certificate chain will
                // search through the system and keychain to find certificates that it
                // needs to try and construct a trust chain back to the root.
                //
                // `SecTrustSetAnchorCertificatesOnly` must be called after setting custom
                // anchor certificates, which "disables trusting any other anchors than the ones passed in
                // with the `SecTrustSetAnchorCertificates` function".
                //
                // [Apple's docs]: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/trust/creating_a_trust_object
                trust_evaluation
                    .set_trust_anchor_certificates_only(true)
                    .expect("failed to tell trust to only use provided anchors");
            }
        }

        let trust_error = match trust_evaluation.evaluate_with_error() {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };

        let err_code = trust_error.code();

        let err = err_code
            .try_into()
            .map_err(|_| ())
            .and_then(|code| {
                // Only map the errors we need for tests.
                match code {
                    errors::errSecHostNameMismatch => Ok(TlsError::InvalidCertificate(
                        CertificateError::NotValidForName,
                    )),
                    errors::errSecCreateChainFailed => Ok(TlsError::InvalidCertificate(
                        CertificateError::UnknownIssuer,
                    )),
                    errors::errSecInvalidExtendedKeyUsage => Ok(TlsError::InvalidCertificate(
                        CertificateError::Other(std::sync::Arc::new(super::EkuError)),
                    )),
                    errors::errSecCertificateRevoked => {
                        Ok(TlsError::InvalidCertificate(CertificateError::Revoked))
                    }
                    _ => Err(()),
                }
            })
            // Fallback to an error containing the description and specific error code so that
            // the exact error cause can be looked up easily.
            .unwrap_or_else(|_| invalid_certificate(format!("{}: {}", trust_error, err_code)));

        Err(err)
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
        now: SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, TlsError> {
        log_server_cert(end_entity);

        // Convert IP addresses to name strings to ensure match check on leaf certificate.
        // Ref: https://developer.apple.com/documentation/security/1392592-secpolicycreatessl
        let ip_name;

        let server = match server_name {
            rustls::ServerName::DnsName(name) => name.as_ref(),
            rustls::ServerName::IpAddress(addr) => {
                ip_name = addr.to_string();
                &ip_name
            }
            _ => return Err(unsupported_server_name()),
        };

        let ocsp_data = if !ocsp_response.is_empty() {
            Some(ocsp_response)
        } else {
            None
        };

        match self.verify_certificate(end_entity, intermediates, server, ocsp_data, now) {
            Ok(()) => Ok(rustls::client::ServerCertVerified::assertion()),
            Err(e) => {
                // This error only tells us what the system errored with, so it doesn't leak anything
                // sensitive.
                log::error!("failed to verify TLS certificate: {}", e);
                Err(e)
            }
        }
    }
}
