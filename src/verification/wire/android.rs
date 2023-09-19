use jni::objects::JValue;
use crate::verification::android::{CERT_VERIFIER_CLASS, Verifier as DelegateVerifier};
use once_cell::sync::OnceCell;
use rustls::{
    server::{danger::ClientCertVerifier, WebPkiClientVerifier},
    Error as TlsError,
};
use rustls_pki_types::CertificateDer;
use crate::android::with_context;
use crate::WireX509Error;

/// A client certificate verifier that uses the system's root store and WebPKI.
#[derive(Default)]
pub struct WireClientVerifier {
    // We use a `OnceCell` so we only need
    // to try loading native root certs once per verifier.
    //
    // We currently keep one set of certificates per-verifier so that
    // locking and unlocking the application will pull fresh root
    // certificates from disk, picking up on any changes
    // that might have been made since.
    inner: OnceCell<WebPkiClientVerifier>,

    delegate: DelegateVerifier,
}

impl DelegateVerifier {
    fn get_system_trust_store(&self) -> Result<rustls::RootCertStore, WireX509Error> {
        let certs = with_context(|cx| {
            const GET_SYSTEM_ROOTS_CALL: &str = concat!("()Ljava/util/List");

            let env = cx.env();
            let result = env
                .call_static_method(CERT_VERIFIER_CLASS.get(cx)?, "getSystemRootCAsDer", GET_SYSTEM_ROOTS_CALL, &[])?
                .l()?;

            Self::j_extract_trust_anchors(env, result)
        })?;
        let mut store = rustls::RootCertStore::empty();
        for c in certs {
            let cert = rustls_pki_types::CertificateDer::from(c);
            store.add(cert)?;
        }
        Ok(store)
    }

    pub(crate) fn verify_certificate_revocation(&self, certificate: impl AsRef<[u8]>) -> Result<(), WireX509Error> {
        let verification_result = with_context(|cx| {
            const VERIFY_CERT_REVOCATION_CALL: &str = concat!("([B)", "Lorg/rustls/platformverifier/VerificationResult;");

            let env = cx.env();

            let cert = env.byte_array_from_slice(certificate.as_ref())?;

            let result = env
                .call_static_method(CERT_VERIFIER_CLASS.get(cx)?, "verifyCertificateRevocation", VERIFY_CERT_REVOCATION_CALL, &[JValue::from(cert)])?
                .l()?;

            Ok(crate::verification::android::extract_result_info(env, result))
        });
        DelegateVerifier::map_verification_result(verification_result, None, None)?;
        Ok(())
    }

    fn j_extract_trust_anchors(env: &jni::JNIEnv<'_>, result: jni::objects::JObject<'_>) -> Result<Vec<Vec<u8>>, crate::android::Error> {
        let mut certs = vec![];
        let jlist = jni::objects::JList::from_env(env, result)?;
        for cert in jlist.iter()? {
            let j_array: jni::sys::jbyteArray = cert.into_inner();
            let rs_array = env.convert_byte_array(j_array)?;
            certs.push(rs_array);
        }
        Ok(certs)
    }
}

impl WireClientVerifier {
    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform.
    pub fn new() -> Self {
        Self {
            inner: OnceCell::new(),
            delegate: DelegateVerifier::new(),
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            inner: OnceCell::new(),
            delegate: DelegateVerifier::new_with_fake_root(root),
        }
    }

    // Attempt to load CA root certificates present on system, fallback to WebPKI roots if error
    fn init_client_verifier(&self) -> Result<WebPkiClientVerifier, WireX509Error> {
        let root_store = self.delegate.get_system_trust_store()?;
        super::build_client_verifier(root_store)
    }
}

impl super::WireVerifier for WireClientVerifier {
    fn verify_client_cert(&mut self, end_entity: impl AsRef<[u8]>, intermediates: &[impl AsRef<[u8]>], options: super::VerifyOptions) -> Result<rustls::server::danger::ClientCertVerified, WireX509Error> {
        let end_entity = CertificateDer::from(end_entity.as_ref());
        let intermediates = intermediates.into_iter().map(|i| CertificateDer::from(i.as_ref())).collect::<Vec<_>>();
        let now = rustls_pki_types::UnixTime::now();

        let verifier = self.inner.get_or_try_init(|| self.init_client_verifier())?;
        Ok(verifier
            .verify_client_cert(&end_entity, &intermediates[..], now)
            .map_err(super::map_webpki_errors)?)
    }

    fn check_revocation(&self, cert: impl AsRef<[u8]>) -> Result<(), WireX509Error> {
        self.delegate.verify_certificate_revocation(cert)
    }
}
