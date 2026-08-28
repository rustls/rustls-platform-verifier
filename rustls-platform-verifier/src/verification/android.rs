use core::hash::Hasher;
use jni::{
    jni_sig, jni_str,
    objects::{JByteArray, JObject, JObjectArray, JString, JValue},
    signature::MethodSignature,
    Env,
};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerIdentity, ServerVerifier, SignatureVerificationInput,
};
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CertificateIdentity, CryptoProvider, Identity,
    SignatureScheme, VerifiedIdentity,
};
use rustls::error::{CertificateError, OtherError};
use rustls::pki_types;
use rustls::Error as TlsError;
use rustls::Error::InvalidCertificate;
use std::{iter, sync::Arc};

use super::{log_server_cert, ALLOWED_EKUS};
use crate::android::{with_context, CachedClass};

static CERT_VERIFIER_CLASS: CachedClass =
    CachedClass::new(jni_str!("org.rustls.platformverifier.CertificateVerifier"));

// Note: Keep these in sync with the Kotlin enum.
#[derive(Debug)]
enum VerifierStatus {
    Ok,
    Unavailable,
    Expired,
    UnknownCert,
    Revoked,
    InvalidEncoding,
    InvalidExtension,
}

// Android's certificate verifier ignores this outright and this is considered the
// official recommendation. See https://bugs.chromium.org/p/chromium/issues/detail?id=627154.
const AUTH_TYPE: &str = "RSA";

/// A TLS certificate verifier that utilizes the Android platform verifier.
#[derive(Debug)]
pub struct Verifier {
    /// Testing only: The root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing"))]
    test_only_root_ca_override: Option<pki_types::CertificateDer<'static>>,
    crypto_provider: Arc<CryptoProvider>,
}

#[cfg(any(test, feature = "ffi-testing"))]
impl Drop for Verifier {
    fn drop(&mut self) {
        with_context::<_, ()>(|cx| {
            let cert_verifier_class = CERT_VERIFIER_CLASS.get(cx)?;
            cx.env
                .call_static_method(
                    cert_verifier_class,
                    jni_str!("clearMockRoots"),
                    jni_sig!(() -> void),
                    &[],
                )?
                .v()?;
            Ok(())
        })
        .expect("failed to clear test roots")
    }
}

impl Verifier {
    /// Creates a new instance of a TLS certificate verifier that utilizes the
    /// Android certificate facilities.
    #[cfg_attr(docsrs, doc(cfg(all())))]
    pub fn new(crypto_provider: Arc<CryptoProvider>) -> Result<Self, TlsError> {
        Ok(Self {
            #[cfg(any(test, feature = "ffi-testing"))]
            test_only_root_ca_override: None,
            crypto_provider,
        })
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing"))]
    pub(crate) fn new_with_fake_root(
        root: pki_types::CertificateDer<'static>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            test_only_root_ca_override: Some(root),
            crypto_provider,
        }
    }

    fn verify_certificate(
        &self,
        certificates: &CertificateIdentity<'_>,
        identity: &ServerIdentity<'_, '_>,
    ) -> Result<(), TlsError> {
        let certificate_chain = iter::once(&certificates.end_entity)
            .chain(&certificates.intermediates)
            .map(|cert| cert.as_ref())
            .enumerate();

        // Convert the unix timestamp into milliseconds, expressed as
        // an i64 to later be converted into a Java Long used for a Date
        // constructor.
        let now: i64 = (identity.now.as_secs() * 1000)
            .try_into()
            .map_err(|_| TlsError::FailedToGetCurrentTime)?;

        let verification_result = with_context(|cx| {
            let cert_verifier_class = CERT_VERIFIER_CLASS.get(cx)?;

            let cert_list = {
                let array = JObjectArray::<JByteArray>::new(
                    cx.env,
                    certificates.intermediates.len() + 1,
                    &JByteArray::null(),
                )?;

                for (idx, cert) in certificate_chain {
                    let cert_buffer = cx.env.byte_array_from_slice(cert)?;
                    array.set_element(cx.env, idx, cert_buffer)?;
                }

                array
            };

            let allowed_ekus = {
                let array =
                    JObjectArray::<JString>::new(cx.env, ALLOWED_EKUS.len(), &JString::null())?;

                for (idx, eku) in ALLOWED_EKUS.iter().enumerate() {
                    let eku = cx.env.new_string(eku.to_str().expect(
                        "ALLOWED_EKUS entries are ASCII constants -- always valid UTF-8",
                    ))?;
                    array.set_element(cx.env, idx, eku)?
                }

                array
            };

            let ocsp_response = if identity.ocsp_response.is_empty() {
                JByteArray::null()
            } else {
                cx.env.byte_array_from_slice(identity.ocsp_response)?
            };

            #[cfg(any(test, feature = "ffi-testing"))]
            {
                if let Some(mock_root) = &self.test_only_root_ca_override {
                    let mock_root = cx.env.byte_array_from_slice(mock_root)?;
                    cx.env
                        .call_static_method(
                            cert_verifier_class,
                            jni_str!("addMockRoot"),
                            jni_sig!((byte[]) -> void),
                            &[JValue::from(&mock_root)],
                        )?
                        .v()
                        .expect("failed to add test root")
                }
            }

            const VERIFIER_CALL: MethodSignature<'static, 'static> = jni_sig!(
                (
                    android.content.Context,
                    JString,
                    JString,
                    JString[],
                    byte[],
                    jlong,
                    byte[][]
                ) -> org.rustls.platformverifier.VerificationResult
            );

            let server_name = identity.server_name.to_str();
            // Android's verifier doesn't require this but trim trailing `.` labels for consistency across platforms.
            let server_name = server_name.strip_suffix('.').unwrap_or(&server_name);

            let server_name = cx.env.new_string(server_name)?;
            let auth_type = cx.env.new_string(AUTH_TYPE)?;

            let result = cx
                .env
                .call_static_method(
                    cert_verifier_class,
                    jni_str!("verifyCertificateChain"),
                    VERIFIER_CALL,
                    &[
                        JValue::from(cx.global.context.as_ref()),
                        JValue::from(&server_name),
                        JValue::from(&auth_type),
                        JValue::from(&JObject::from(allowed_ekus)),
                        JValue::from(&ocsp_response),
                        JValue::Long(now),
                        JValue::from(&JObject::from(cert_list)),
                    ],
                )?
                .l()?;

            Ok(extract_result_info(cx.env, result))
        });

        match verification_result {
            Ok((status, maybe_msg)) => {
                // `maybe_msg` is safe to log as its exactly what the system told us.
                //
                // The branches which unwrap it will never fail since the Kotlin side always sets it
                // for the variants.
                match status {
                    VerifierStatus::Ok => {
                        // If everything else was OK, check the hostname.
                        rustls::client::verify_server_name(
                            &rustls::server::ParsedCertificate::try_from(&certificates.end_entity)?,
                            identity.server_name,
                        )
                    }
                    VerifierStatus::Unavailable => Err(TlsError::General(String::from(
                        "No system trust stores available",
                    ))),
                    VerifierStatus::Expired => Err(InvalidCertificate(CertificateError::Expired)),
                    VerifierStatus::UnknownCert => {
                        log::warn!("certificate was not trusted: {}", maybe_msg.unwrap());
                        Err(InvalidCertificate(CertificateError::UnknownIssuer))
                    }
                    VerifierStatus::Revoked => {
                        log::warn!("certificate was revoked: {}", maybe_msg.unwrap());
                        Err(InvalidCertificate(CertificateError::Revoked))
                    }
                    VerifierStatus::InvalidEncoding => {
                        Err(InvalidCertificate(CertificateError::BadEncoding))
                    }
                    VerifierStatus::InvalidExtension => Err(InvalidCertificate(
                        CertificateError::Other(OtherError::new(super::EkuError)),
                    )),
                }
            }
            Err(e) => Err(TlsError::General(format!(
                "failed to call native verifier: {e:?}",
            ))),
        }
    }
}

fn extract_result_info(env: &mut Env<'_>, result: JObject<'_>) -> (VerifierStatus, Option<String>) {
    let status_code = env
        .get_field(&result, jni_str!("code"), jni_sig!(jint))
        .and_then(|code| code.i())
        .unwrap();

    let status = match status_code {
        0 => VerifierStatus::Ok,
        1 => VerifierStatus::Unavailable,
        2 => VerifierStatus::Expired,
        3 => VerifierStatus::UnknownCert,
        4 => VerifierStatus::Revoked,
        5 => VerifierStatus::InvalidEncoding,
        6 => VerifierStatus::InvalidExtension,
        i => unreachable!("unknown status code: {i}"),
    };

    // Extract the `String?`.
    let msg = env
        .get_field(result, jni_str!("message"), jni_sig!(java.lang.String))
        .and_then(|m| m.l())
        .map(|s| {
            if s.is_null() {
                None
            } else {
                env.cast_local::<JString>(s)
                    .and_then(|s| s.try_to_string(env))
                    .ok()
            }
        })
        .unwrap();
    (status, msg)
}

#[cfg_attr(docsrs, doc(cfg(all())))]
impl ServerVerifier for Verifier {
    fn verify_identity<'a>(
        &self,
        identity: &ServerIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, TlsError> {
        let Identity::X509(certificates) = identity.identity else {
            return Err(InvalidCertificate(CertificateError::Other(
                OtherError::new(std::io::Error::other(
                    "platform verifier only supports X.509 certificates",
                )),
            )));
        };

        log_server_cert(&certificates.end_entity);

        match self.verify_certificate(certificates, identity) {
            Ok(()) => Ok(VerifiedIdentity::assertion(identity.identity.clone())),
            Err(e) => {
                // This error only tells us what the system errored with, so it doesn't leak anything
                // sensitive.
                log::error!("failed to verify TLS certificate: {}", e);
                Err(e)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            input,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            input,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        true
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        h.write(b"rustls-platform-verifier-android");
        #[cfg(any(test, feature = "ffi-testing"))]
        h.write_u8(u8::from(self.test_only_root_ca_override.is_some()));
    }
}
