use jni::{
    objects::{JObject, JValue},
    strings::JavaStr,
    JNIEnv,
};
use rustls::Error::InvalidCertificate;
use rustls::{client::danger::ServerCertVerifier, CertificateError, Error as TlsError, ServerName, DigitallySignedStruct};
use rustls::client::danger::HandshakeSignatureValid;
use rustls_pki_types::CertificateDer;
use crate::android::Error as AndroidError;

use super::{log_server_cert, unsupported_server_name, ALLOWED_EKUS};
use crate::android::{with_context, CachedClass};

pub(crate) static CERT_VERIFIER_CLASS: CachedClass =
    CachedClass::new("org/rustls/platformverifier/CertificateVerifier");

// Find the `ByteArray (Uint8 [])` class.
static BYTE_ARRAY_CLASS: CachedClass = CachedClass::new("[B");

static STRING_CLASS: CachedClass = CachedClass::new("java/lang/String");

// Note: Keep these in sync with the Kotlin enum.
#[derive(Debug)]
pub(crate) enum VerifierStatus {
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
#[derive(Default)]
pub struct Verifier {
    /// Testing only: The root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing"))]
    test_only_root_ca_override: Option<Vec<u8>>,
}

#[cfg(any(test, feature = "ffi-testing"))]
impl Drop for Verifier {
    fn drop(&mut self) {
        with_context::<_, ()>(|cx| {
            let env = cx.env();
            env.call_static_method(CERT_VERIFIER_CLASS.get(cx)?, "clearMockRoots", "()V", &[])?
                .v()?;
            Ok(())
        })
            .expect("failed to clear test roots")
    }
}

impl Verifier {
    /// Creates a new instance of a TLS certificate verifier that utilizes the
    /// Android certificate facilities
    pub fn new() -> Self {
        Self {
            #[cfg(any(test, feature = "ffi-testing"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            test_only_root_ca_override: Some(root.into()),
        }
    }

    fn verify_certificate(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &rustls::ServerName,
        server_name_str: &str,
        ocsp_response: Option<&[u8]>,
        now: rustls_pki_types::UnixTime,
    ) -> Result<(), TlsError> {
        let certificate_chain = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|cert| cert.as_ref())
            .enumerate();

        let now = (now.as_secs() * 1000).try_into().unwrap();

        let verification_result = with_context(|cx| {
            let env = cx.env();
            // We don't provide an initial element so that the array filling can be cleaner.
            // It's valid to provide a `null` value. Ref: https://docs.oracle.com/en/java/javase/13/docs/specs/jni/functions.html -> NewObjectArray
            let cert_list = {
                let array = env.new_object_array(
                    (intermediates.len() + 1).try_into().unwrap(),
                    BYTE_ARRAY_CLASS.get(cx)?,
                    JObject::null(),
                )?;

                for (idx, cert) in certificate_chain {
                    let idx = idx.try_into().unwrap();
                    let cert_buffer = env.byte_array_from_slice(cert)?;
                    env.set_object_array_element(array, idx, cert_buffer)?
                }

                array
            };

            let allowed_ekus = {
                let array = env.new_object_array(
                    ALLOWED_EKUS.len().try_into().unwrap(),
                    STRING_CLASS.get(cx)?,
                    JObject::null(),
                )?;

                for (idx, eku) in ALLOWED_EKUS.iter().enumerate() {
                    let idx = idx.try_into().unwrap();
                    let eku = env.new_string(eku)?;
                    env.set_object_array_element(array, idx, eku)?;
                }

                array
            };

            let ocsp_response = ocsp_response
                .map(|b| env.byte_array_from_slice(b))
                .transpose()?
                .map(JObject::from)
                .unwrap_or_else(JObject::null);

            #[cfg(any(test, feature = "ffi-testing"))]
            {
                if let Some(mock_root) = &self.test_only_root_ca_override {
                    let mock_root = env.byte_array_from_slice(mock_root)?;
                    env.call_static_method(
                        CERT_VERIFIER_CLASS.get(cx)?,
                        "addMockRoot",
                        "([B)V",
                        &[JValue::from(mock_root)],
                    )?
                        .v()
                        .expect("failed to add test root")
                }
            }

            const VERIFIER_CALL: &str = concat!(
            '(',
            "Landroid/content/Context;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "[Ljava/lang/String;",
            "[B",
            'J',
            "[[B",
            ')',
            "Lorg/rustls/platformverifier/VerificationResult;"
            );

            let result = env
                .call_static_method(
                    CERT_VERIFIER_CLASS.get(cx)?,
                    "verifyCertificateChain",
                    VERIFIER_CALL,
                    &[
                        JValue::from(*cx.application_context()),
                        JValue::from(env.new_string(server_name_str)?),
                        JValue::from(env.new_string(AUTH_TYPE)?),
                        JValue::from(JObject::from(allowed_ekus)),
                        JValue::from(ocsp_response),
                        JValue::Long(now),
                        JValue::from(JObject::from(cert_list)),
                    ],
                )?
                .l()?;

            Ok(extract_result_info(env, result))
        });

        Self::map_verification_result(verification_result, Some(end_entity), Some(&server_name))
    }

    pub(crate) fn map_verification_result(verification_result: Result<(VerifierStatus, Option<String>), AndroidError>, end_entity: Option<&CertificateDer>, server_name: Option<&ServerName>) -> Result<(), TlsError> {
        match verification_result {
            Ok((status, maybe_msg)) => {
                // `maybe_msg` is safe to log as its exactly what the system told us.
                //
                // The branches which unwrap it will never fail since the Kotlin side always sets it
                // for the variants.
                match status {
                    VerifierStatus::Ok => {
                        // If everything else was OK, check the hostname.
                        if let Some((end_entity, server_name)) = end_entity.zip(server_name) {
                            rustls::client::verify_server_name(
                                &rustls::server::ParsedCertificate::try_from(end_entity)?,
                                server_name,
                            )
                        } else { Ok(()) }
                    }
                    VerifierStatus::Unavailable => Err(TlsError::General(String::from(
                        "No system trust stores available",
                    ))),
                    VerifierStatus::Expired => Err(InvalidCertificate(CertificateError::Expired)),
                    VerifierStatus::UnknownCert => {
                        log::warn!("certificate was not trusted: {maybe_msg:?}");
                        Err(InvalidCertificate(CertificateError::UnknownIssuer))
                    }
                    VerifierStatus::Revoked => {
                        log::warn!("certificate was revoked: {maybe_msg:?}");
                        Err(InvalidCertificate(CertificateError::Revoked))
                    }
                    VerifierStatus::InvalidEncoding => {
                        Err(InvalidCertificate(CertificateError::BadEncoding))
                    }
                    VerifierStatus::InvalidExtension => Err(InvalidCertificate(
                        CertificateError::Other(std::sync::Arc::new(super::EkuError)),
                    )),
                }
            }
            Err(e) => Err(TlsError::General(format!("failed to call native verifier: {e:?}"))),
        }
    }
}

pub(crate) fn extract_result_info(env: &JNIEnv<'_>, result: JObject<'_>) -> (VerifierStatus, Option<String>) {
    let status_code = env
        .get_field(result, "code", "I")
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
        .get_field(result, "message", "Ljava/lang/String;")
        .and_then(|m| m.l())
        .map(|o| (!o.is_null()).then_some(o))
        .and_then(|s| s.map(|s| JavaStr::from_env(env, s.into())).transpose())
        .unwrap();

    (status, msg.map(String::from))
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &rustls::ServerName,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        log_server_cert(end_entity);

        // Verify the server name is one that we support and extract a string to use
        // for the platform verifier call.
        let ip_name;
        let server_name_str = match server_name {
            ServerName::DnsName(dns_name) => dns_name.as_ref(),
            ServerName::IpAddress(ip_addr) => {
                ip_name = ip_addr.to_string();
                &ip_name
            }
            _ => return Err(unsupported_server_name()),
        };

        let ocsp_data = if !ocsp_response.is_empty() {
            Some(ocsp_response)
        } else {
            None
        };

        match self.verify_certificate(
            end_entity,
            intermediates,
            server_name,
            server_name_str,
            ocsp_data,
            now,
        ) {
            Ok(()) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            Err(e) => {
                // This error only tells us what the system errored with, so it doesn't leak anything
                // sensitive.
                log::error!("failed to verify TLS certificate: {}", e);
                Err(e)
            }
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        unimplemented!("Will never be used with TLS in @Wire context")
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> { unimplemented!("Will never be used with TLS in @Wire context") }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> { unimplemented!("Will never be used with TLS in @Wire context") }
}
