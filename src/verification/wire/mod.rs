#[cfg(target_family = "wasm")]
pub mod wasm;

#[cfg(target_os = "android")]
pub mod android;

mod bag_of_certificates;

pub mod error;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod ios;

use rustls::{
    CertificateError,
    Error as TlsError,
    RootCertStore,
    server::{ClientCertVerifierBuilderError::NoSupportedAlgorithms, WebPkiClientVerifier},
};
use std::sync::Arc;
use rustls_pki_types::UnixTime;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use crate::verification::{EkuError, wire::error::WireX509Error};

/// Wire's view of x509 certificate verification. Suited for MLS needs.
pub trait WireVerifier {
    /// Custom x509 client certificate verification with lenient options suited for MLS
    fn verify_client_cert(
        &mut self,
        end_entity: impl AsRef<[u8]>,
        intermediates: &[impl AsRef<[u8]>],
        bag_of_certificates: &[Vec<impl AsRef<[u8]>>],
        options: VerifyOptions,
    ) -> Result<rustls::server::danger::ClientCertVerified, WireX509Error>;

    /// Reads validity claims from a Certificate
    fn try_get_validity(&self, cert: &rustls::server::ParsedCertificate) -> Result<Validity, WireX509Error> {
        cert.0.validity.read_all(WireX509Error::DerDecodingError, |value| {
            use webpki::der::FromDer as _;
            let not_before = UnixTime::from_der(value)?;
            let not_after = UnixTime::from_der(value)?;
            Ok(Validity { not_before, not_after })
        })
    }

    /// Reads validity claims from a Certificate
    fn try_get_crl_distribution_points(&self, cert: &impl AsRef<[u8]>) -> Result<Vec<String>, WireX509Error> {
        use x509_cert::der::Decode as _;
        let cert = x509_cert::Certificate::from_der(cert.as_ref())?;

        // Maybe use certval here instead...

        // see reference impl here: https://github.com/carl-wallace/rust-pki/blob/e1caaa432105f527df6478df539f6d17f9a067ff/certval/src/revocation/crl.rs#L360-L380
        let distribution_points = cert.tbs_certificate
            .filter::<CrlDistributionPoints>()
            .map(|r| r.map(|(_, cdp)| cdp))
            .map(|cdp| cdp.map(|cdp| {
                cdp.as_ref().iter()
                    .filter_map(|dp| dp.distribution_point.as_ref())
                    .flat_map(|dp| {
                        if let DistributionPointName::FullName(gn) = dp {
                            gn.iter()
                                .filter_map(|n| {
                                    if let GeneralName::UniformResourceIdentifier(uri) = n {
                                        Some(uri.as_str().to_string())
                                    } else {
                                        None
                                    }
                                }).collect::<Vec<_>>()
                        } else {
                            vec![]
                        }
                    }).collect()
            }))
            .collect::<Result<Vec<String>, x509_cert::der::Error>>()?;
        if distribution_points.is_empty() {
            Err(WireX509Error::MissingCrlDistributionPoint)
        } else {
            Ok(distribution_points)
        }
    }

    /// Verifies if a given certificate chain is revoked or not by using the network
    fn check_revocation(
        &self,
        cert: impl AsRef<[u8]>,
        #[cfg(target_family = "wasm")]
        fetch_crl: &dyn RevocationCallbacks,
    ) -> Result<(), WireX509Error>;
}

pub struct Validity {
    not_before: UnixTime,
    not_after: UnixTime,
}

impl Validity {
    pub fn update(&mut self, other: Self) {
        if other.not_before > self.not_before {
            self.not_before = other.not_before;
        }
        if other.not_after < self.not_after {
            self.not_after = other.not_after;
        }
    }

    pub fn try_mean(&self) -> Result<UnixTime, WireX509Error> {
        let (nbf, naf) = (self.not_before.as_secs(), self.not_after.as_secs());
        let delta = naf.checked_sub(nbf).ok_or(WireX509Error::MathError)?;
        let offset = delta.checked_div(2).ok_or(WireX509Error::MathError)?;

        let lenient_now = naf.checked_sub(offset).ok_or(WireX509Error::MathError)?;
        let epoch_duration = core::time::Duration::from_secs(lenient_now);
        Ok(UnixTime::since_unix_epoch(epoch_duration))
    }
}

/// Options to turn off expiration & revocation checks
#[derive(Debug, Default)]
pub struct VerifyOptions<'a> {
    /// When this is true, we do not check if any certificate is expired
    verify_expired: bool,
    /// When this is true, we do not check if any certificate is revoked
    crls: Vec<webpki::BorrowedCertRevocationList<'a>>,
}

impl<'a> VerifyOptions<'a> {
    /// Builds a new [VerifyOptions] by parsing provided CRLs (one per domain)
    pub fn try_new(verify_expired: bool, crls: &'a [&[u8]]) -> Result<Self, WireX509Error> {
        let crls = crls.into_iter()
            .map(|der| webpki::BorrowedCertRevocationList::from_der(der))
            .collect::<Result<_, _>>()?;
        Ok(Self { verify_expired, crls })
    }
}

pub fn map_webpki_errors(err: TlsError) -> TlsError {
    if let TlsError::InvalidCertificate(CertificateError::Other(other_err)) = &err {
        if let Some(webpki::Error::RequiredEkuNotFound) = other_err.downcast_ref::<webpki::Error>() {
            return TlsError::InvalidCertificate(CertificateError::Other(Arc::new(EkuError)));
        }
    }
    err
}

pub fn build_client_verifier(root_store: RootCertStore) -> Result<WebPkiClientVerifier, WireX509Error> {
    let builder = WebPkiClientVerifier::builder(root_store.into());
    let verifier = builder
        .build()
        .map_err(|e| match e {
            rustls::server::ClientCertVerifierBuilderError::NoRootAnchors => TlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            rustls::server::ClientCertVerifierBuilderError::InvalidCrl(e) => TlsError::InvalidCertRevocationList(e),
            NoSupportedAlgorithms => TlsError::InvalidCertificate(rustls::CertificateError::BadSignature),
            _ => TlsError::General("Unknown client cert verification error".to_string()),
        })?;
    let verifier = Arc::try_unwrap(verifier).map_err(|_| WireX509Error::ImplementationError)?;
    Ok(verifier)
}

#[cfg(target_family = "wasm")]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(? Send))]
pub trait RevocationCallbacks: std::fmt::Debug + Send + Sync {
    async fn fetch_crl(&self, url: String) -> Vec<u8>;
}
