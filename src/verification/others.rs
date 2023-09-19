use std::sync::Mutex;

use once_cell::sync::OnceCell;
use rustls::{
    CertificateError,
    client::{
        danger::{
            ServerCertVerifier,
            HandshakeSignatureValid,
        },
        WebPkiServerVerifier,
    },
    DigitallySignedStruct,
    Error as TlsError,
    SignatureScheme,
};
use rustls_pki_types::CertificateDer;

use super::log_server_cert;

/// A TLS certificate verifier that uses the system's root store and WebPKI.
#[derive(Default)]
pub struct Verifier<'a> {
    // We use a `OnceCell` so we only need
    // to try loading native root certs once per verifier.
    //
    // We currently keep one set of certificates per-verifier so that
    // locking and unlocking the application will pull fresh root
    // certificates from disk, picking up on any changes
    // that might have been made since.
    inner: OnceCell<WebPkiServerVerifier>,

    // Extra trust anchors to add to the verifier above and beyond those provided by the
    // platform via rustls-native-certs.
    #[allow(unused)]
    extra_roots: Mutex<Vec<rustls_pki_types::TrustAnchor<'a>>>,

    /// Testing only: an additional root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    test_only_root_ca_override: Option<Vec<u8>>,
}

impl<'a> Verifier<'a> {
    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform.
    pub fn new() -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: Vec::new().into(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a new verifier whose certificate validation is provided by
    /// WebPKI, using root certificates provided by the platform and augmented by
    /// the provided extra root certificates.
    pub fn new_with_extra_roots(roots: impl IntoIterator<Item=rustls_pki_types::TrustAnchor<'a>>) -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: roots.into_iter().collect::<Vec<_>>().into(),
            #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
            test_only_root_ca_override: None,
        }
    }

    /// Creates a test-only TLS certificate verifier which trusts our fake root CA cert.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    pub(crate) fn new_with_fake_root(root: &[u8]) -> Self {
        Self {
            inner: OnceCell::new(),
            extra_roots: Vec::new().into(),
            test_only_root_ca_override: Some(root.into()),
        }
    }

    // Attempt to load CA root certificates present on system, fallback to WebPKI roots if error
    fn init_server_verifier(&self) -> Result<WebPkiServerVerifier, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();

        // For testing only: load fake root cert, instead of native/WebPKI roots
        #[cfg(all(feature = "ring", any(test, feature = "ffi-testing", feature = "dbg")))] {
            if let Some(test_root) = &self.test_only_root_ca_override {
                let test_root = rustls_pki_types::CertificateDer::from(&test_root[..]);
                let (added, ignored) = root_store.add_parsable_certificates(vec![test_root]);
                if (added != 1) || (ignored != 0) {
                    panic!("Failed to insert fake, test-only root trust anchor");
                }
                return Ok(WebPkiServerVerifier::new(root_store));
            }
        }

        #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                let certs: Vec<Vec<u8>> = certs.into_iter().map(|c| c.0).collect();
                let (added, ignored) = root_store.add_parsable_certificates(&certs);

                if ignored != 0 {
                    log::warn!("Some CA root certificates were ignored due to errors");
                }

                if root_store.is_empty() {
                    log::error!("No CA certificates were loaded from the system");
                } else {
                    log::debug!("Loaded {added} CA certificates from the system");
                }

                // Safety: There's no way for the mutex to be locked multiple times, so this is
                //         an infallible operation.
                let mut extra_roots = self.extra_roots.try_lock().unwrap();
                if !extra_roots.is_empty() {
                    let count = extra_roots.len();
                    root_store.add_trust_anchors(&mut extra_roots.drain(..));
                    log::debug!(
                        "Loaded {count} extra CA certificates in addition to roots from the system",
                    );
                }
            }
            Err(err) => {
                // This only contains a path to a system directory:
                // https://github.com/rustls/rustls-native-certs/blob/bc13b9a6bfc2e1eec881597055ca49accddd972a/src/lib.rs#L91-L94
                return Err(rustls::Error::General(format!(
                    "failed to load system root certificates: {}",
                    err
                )));
            }
        };

        #[cfg(target_arch = "wasm32")] {
            unimplemented!("Will never be used on WASM")
        };

        #[cfg(not(target_arch = "wasm32"))] {
            Ok(WebPkiServerVerifier::new(root_store).into())
        };
    }
}

impl<'a> ServerCertVerifier for Verifier<'a> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &rustls::ServerName,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        log_server_cert(end_entity);

        let verifier = self.inner.get_or_try_init(|| self.init_server_verifier())?;

        verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map_err(map_webpki_errors)
            // This only contains information from the system or other public
            // bits of the TLS handshake, so it can't leak anything.
            .map_err(|e| {
                log::error!("failed to verify TLS certificate: {}", e);
                e
            })
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("Will never be used with TLS in @Wire context")
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unimplemented!("Will never be used with TLS in @Wire context")
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        unimplemented!("Will never be used with TLS in @Wire context")
    }
}

fn map_webpki_errors(err: TlsError) -> TlsError {
    if let TlsError::InvalidCertificate(CertificateError::Other(other_err)) = &err {
        if let Some(webpki::Error::RequiredEkuNotFound) = other_err.downcast_ref::<webpki::Error>()
        {
            return TlsError::InvalidCertificate(CertificateError::Other(std::sync::Arc::new(
                super::EkuError,
            )));
        }
    }

    err
}
