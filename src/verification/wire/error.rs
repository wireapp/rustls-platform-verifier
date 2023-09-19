/// Error for all the x509 verification errors in Wire's additional code
#[derive(Debug, thiserror::Error)]
pub enum WireX509Error {
    /// "The certificate is revoked"
    #[error("The certificate is revoked")]
    Revoked,
    /// "Unknown certificate issuer"
    #[error("Unknown certificate issuer")]
    UnknownIssuer,
    /// "Domain name mismatches"
    #[error("Domain name mismatches")]
    InvalidForName,
    /// "Invalid extended Key Usage"
    #[error("Invalid extended Key Usage")]
    InvalidExtendedKeyUsage,
    /// "Error while decoding a DER document"
    #[error("Error while decoding a DER document")]
    DerDecodingError,
    /// A certificate is missing a CRL distribution point
    #[error("A certificate is missing a CRL distribution point")]
    MissingCrlDistributionPoint,
    /// "An error in the platform's firmware"
    #[error("An error in the platform's firmware")]
    SystemError,
    /// Rustls error
    #[error(transparent)]
    RustlsError(#[from] rustls::Error),
    /// x509_cert DER error
    #[error(transparent)]
    X509DerError(#[from] x509_cert::der::Error),
    /// Rustls-webpki error
    #[error(transparent)]
    WebpkiError(#[from] webpki::Error),
    /// Certval error
    #[error(transparent)]
    CertvalError(#[from] certval::Error),
    /// "An internal error occurred"
    #[error("An internal error occurred")]
    ImplementationError,
    /// "Math error"
    #[error("Math error")]
    MathError,
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    /// iOS internal error
    #[error(transparent)]
    AppleError(#[from] security_framework::base::Error),
    #[cfg(target_os = "android")]
    /// Android internal error
    #[error(transparent)]
    AndroidError(#[from] crate::android::Error),
}