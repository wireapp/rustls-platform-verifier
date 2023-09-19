use rustls::crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup};
use rustls::SupportedCipherSuite;

#[derive(Debug)]
pub struct RustCrypto;

impl CryptoProvider for RustCrypto {
    fn fill_random(&self, _buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        unimplemented!()
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        unimplemented!()
    }

    /// Return all supported key exchange groups.
    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup] {
        unimplemented!()
    }
}