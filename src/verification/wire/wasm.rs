use std::sync::Mutex;

use once_cell::sync::OnceCell;
use rustls::{
    Error as TlsError,
    server::{
        danger::ClientCertVerifier,
        WebPkiClientVerifier,
    },
};
use rustls_pki_types::CertificateDer;
use crate::WireX509Error;
use super::RevocationCallbacks;

/// A client certificate verifier that uses the provided root store and WebPKI.
#[derive(Default)]
pub struct WireClientVerifier<'a> {
    // We use a `OnceCell` so we only need
    // to try loading native root certs once per verifier.
    //
    // We currently keep one set of certificates per-verifier so that
    // locking and unlocking the application will pull fresh root
    // certificates from disk, picking up on any changes
    // that might have been made since.
    inner: OnceCell<WebPkiClientVerifier>,

    // Extra trust anchors to add to the verifier above and beyond those provided by the
    // platform via rustls-native-certs.
    extra_roots: Mutex<Vec<rustls_pki_types::TrustAnchor<'a>>>,

    /// Testing only: an additional root CA certificate to trust.
    #[cfg(any(test, feature = "ffi-testing", feature = "dbg"))]
    test_only_root_ca_override: Option<Vec<u8>>,
}

impl<'a> WireClientVerifier<'a> {
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
    fn init_client_verifier(&self) -> Result<WebPkiClientVerifier, WireX509Error> {
        let root_store = rustls::RootCertStore::empty();
        super::build_client_verifier(root_store)
    }
}

impl<'a> super::WireVerifier for WireClientVerifier<'a> {
    fn verify_client_cert(&mut self, end_entity: impl AsRef<[u8]>, intermediates: &[impl AsRef<[u8]>], _options: super::VerifyOptions) -> Result<rustls::server::danger::ClientCertVerified, WireX509Error> {
        let end_entity = CertificateDer::from(end_entity.as_ref());
        let intermediates = intermediates.into_iter().map(|i| CertificateDer::from(i.as_ref())).collect::<Vec<_>>();
        let now = rustls_pki_types::UnixTime::now();

        let verifier = self.inner.get_or_try_init(|| self.init_client_verifier())?;
        Ok(verifier
            .verify_client_cert(&end_entity, &intermediates[..], now)
            .map_err(super::map_webpki_errors)?)
    }

    fn check_revocation(&self, cert: impl AsRef<[u8]>, fetch_crl: &dyn RevocationCallbacks) -> Result<(), WireX509Error> {
        let cert = CertificateDer::from(cert.as_ref());
        let cert = rustls::server::ParsedCertificate::try_from(&cert)?;


        Ok(())
    }
}
