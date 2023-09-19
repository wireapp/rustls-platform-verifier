use certval::{CertificationPath, CertificationPathResults, CertificationPathSettings, PDVCertificate, PkiEnvironment};
use core_foundation::{date::CFDate, error::CFError};
use once_cell::sync::OnceCell;
use rustls::{RootCertStore, server::{danger::{ClientCertVerified, ClientCertVerifier}, WebPkiClientVerifier}};
use rustls_pki_types::{CertificateDer, UnixTime};
use security_framework::{
    certificate::SecCertificate, policy::SecPolicy,
    trust::SecTrust,
};
use security_framework::policy::RevocationPolicy;

use crate::verification::{
    apple::Verifier as DelegateVerifier,
    wire::{error::WireX509Error, VerifyOptions},
};

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
    fn init_client_verifier(&self, intermediates: &[CertificateDer]) -> Result<WebPkiClientVerifier, WireX509Error> {
        let root_store = self.delegate.get_system_trust_store(intermediates)?;
        super::build_client_verifier(root_store)
    }
}

impl DelegateVerifier {
    /// Since getting the truststore is available on macos but not on iOS, we are gonna do the following:
    /// * Validate the partial chain without the end entity certificate (which might cause issues e.g. Ed25519)
    /// * Evaluate this partial chain which should be valid
    /// * Get the trust anchor from that chain
    /// * Create a store from it
    fn get_system_trust_store(&self, intermediates: &[CertificateDer]) -> Result<RootCertStore, WireX509Error> {
        let intermediates = intermediates.iter()
            .map(AsRef::as_ref)
            .map(SecCertificate::from_der)
            .collect::<Result<Vec<_>, _>>()?;

        let x509_policy = SecPolicy::create_x509();
        let mut trust_evaluation = SecTrust::create_with_certificates(&intermediates[..], &[x509_policy])?;

        // We do not care about certificates validity here. It is going to be determined in [DelegateVerifier::verify_certificate].
        // We just build this `trust_evaluation` to get the trust anchor otherwise it's prevented by iOS
        let now = CFDate::now();
        trust_evaluation.set_trust_verify_date(&now)?;

        // All the certificates we are looking for should already be on the system's truststore, no need to fetch them remotely
        trust_evaluation.set_network_fetch_allowed(false)?;

        trust_evaluation.evaluate_with_error().map_err(Self::map_sec_error)?;

        let mut store = RootCertStore::empty();
        let count = trust_evaluation.certificate_count();
        for i in 0..count {
            // Pending https://github.com/kornelski/rust-security-framework/issues/153 resolved for iOS 15+
            #[allow(deprecated)]
                let anchor = trust_evaluation.certificate_at_index(i)
                .ok_or(WireX509Error::SystemError)?;

            let anchor = rustls_pki_types::CertificateDer::from(anchor.to_der());
            store.add(anchor)?;
        }

        Ok(store)
    }

    pub(crate) fn map_sec_error(e: CFError) -> WireX509Error {
        e.code()
            .try_into()
            .map_err(|_| ())
            .map(|e| match e {
                security_framework_sys::base::errSecHostNameMismatch => WireX509Error::InvalidForName,
                security_framework_sys::base::errSecCreateChainFailed => WireX509Error::UnknownIssuer,
                security_framework_sys::base::errSecInvalidExtendedKeyUsage => WireX509Error::InvalidExtendedKeyUsage,
                security_framework_sys::base::errSecCertificateRevoked => WireX509Error::Revoked,
                _ => security_framework::base::Error::from_code(e).into(),
            })
            .unwrap_or_else(|_| security_framework::base::Error::from_code(e.code() as _).into())
    }
}

impl super::WireVerifier for WireClientVerifier {
    fn verify_client_cert(&mut self,
                          end_entity: impl AsRef<[u8]>,
                          intermediates: &[impl AsRef<[u8]>],
                          bag_of_certificates: &[Vec<impl AsRef<[u8]>>],
                          options: VerifyOptions<'_>) -> Result<ClientCertVerified, WireX509Error> {

        let mut env = PkiEnvironment::new();

        for ta in bag_of_certificates {
            let ta = certval::source::ta_source::TaSource::new_from_unparsed(ta.as_slice())?;
            env.add_trust_anchor_source(Box::new(ta));
        }

        let target = PDVCertificate::try_from(end_entity.as_ref())?;
        let mut paths = vec![];
        env.get_paths_for_target(&env, &target, &mut paths, 0, 0)?;

        let mut path = if paths.len() == 1 {
            paths.remove(0)
        } else {
            return Err(WireX509Error::ImplementationError)
        };

        let cps = CertificationPathSettings::new();
        let mut result = CertificationPathResults::new();

        env.validate_path(&env, &cps, &mut path, &mut result)?;

        todo!()
    }

    /*fn verify_client_cert(&mut self,
                          end_entity: impl AsRef<[u8]>,
                          intermediates: &[impl AsRef<[u8]>],
                          bag_of_certificates: &[Vec<impl AsRef<[u8]>>],
                          options: VerifyOptions<'_>) -> Result<ClientCertVerified, WireX509Error> {
        let end_entity = CertificateDer::from(end_entity.as_ref());

        let end_entity_cert = rustls::server::ParsedCertificate::try_from(&end_entity)?;

        // If we want to completely ignore validity and since we cannot turn off a flag to do so
        // we have to find a timestamp in the middle of the maximum of all 'not_before' and the
        // minimum of all 'not_after' of all the certificates in the chain, not just the end
        // entity certificate.
        let mut validity = if !options.verify_expired {
            Some(self.try_get_validity(&end_entity_cert)?)
        } else {
            None
        };

        // Try to find the narrowest validity window among intermediates
        let intermediates = intermediates.into_iter().map(|i| {
            let cert = CertificateDer::from(i.as_ref());
            if !options.verify_expired {
                let cert = rustls::server::ParsedCertificate::try_from(&cert)?;
                if let Some(validity) = validity.as_mut() {
                    validity.update(self.try_get_validity(&cert)?);
                };
            }
            Ok(cert)
        }).collect::<Result<Vec<_>, WireX509Error>>()?;

        let now = if let Some(validity) = validity {
            // This is ok if this fails: it means there is no point in time where this certificate
            // chain would have been valid
            validity.try_mean()?
        } else {
            UnixTime::now()
        };

        // Init the verifier only once then memoize it
        if self.inner.get().is_none() {
            self.inner.get_or_try_init(|| self.init_client_verifier(&intermediates[..]))?;
        };
        let verifier = self.inner.get_mut().ok_or(WireX509Error::ImplementationError)?;

        let crls = options.crls.into_iter().map(|crl| crl.to_owned()).collect::<Result<Vec<_>, _>>()?;
        verifier.update_crls(crls);

        Ok(verifier
            .verify_client_cert(&end_entity, &intermediates[..], now)
            .map_err(super::map_webpki_errors)?)
    }*/

    fn check_revocation(&self, cert: impl AsRef<[u8]>) -> Result<(), WireX509Error> {
        // see https://developer.apple.com/documentation/security/certificate_key_and_trust_services/policies/1563600-revocation_policy_constants
        const REVOCATION_POLICY: RevocationPolicy = RevocationPolicy::PREFER_CRL.union(RevocationPolicy::REQUIRE_POSITIVE_RESPONSE);

        let cert = SecCertificate::from_der(cert.as_ref())?;

        let revocation_policy = SecPolicy::create_revocation(REVOCATION_POLICY)?;

        let mut trust_evaluation = SecTrust::create_with_certificates(&[cert], &[revocation_policy])?;

        trust_evaluation.set_network_fetch_allowed(true)?;

        trust_evaluation.evaluate_with_error().map_err(DelegateVerifier::map_sec_error)?;

        Ok(())
    }
}
