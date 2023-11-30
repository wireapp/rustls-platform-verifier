//! Tests of certificate verification that require our own test CA to be
//! trusted.
//!
//! # Re-generating the test data
//!
//! `cd src/tests/verification_mock && go run ca.go`
//!
//! # Repeatability and Self-containedness
//!
//! These tests are only supported on platforms where we have implemented the
//! ability to trust a CA (only) for the duration of a test, without modifying
//! the operating system's trust store--i.e. without affecting the security of
//! any parts of the system outside of these tests. See the `#![cfg(...)]`
//! immediately below to see which platforms run these tests.

#![cfg(any(
windows,
target_os = "android",
target_os = "macos",
target_os = "linux",
target_family = "wasm"
))]

use super::TestCase;
use crate::tests::assert_cert_error_eq;
use crate::verification::{EkuError, Verifier};
use rustls::{client::danger::ServerCertVerifier, CertificateError, Error as TlsError};
use std::convert::TryFrom;
use std::net::IpAddr;
use std::sync::Arc;

macro_rules! mock_root_test_cases {
    { $( $name:ident [ $target:meta ] => $test_case:expr ),+ , } => {
        mock_root_test_cases!(@ $($name [ $target ] => $test_case),+,);

        #[cfg(test)]
        mod tests {
            $(
                #[cfg($target)]
                #[test]
                // #[wasm_bindgen_test::wasm_bindgen_test]
                pub fn $name() {
                    super::$name()
                }
            )+

        }

        #[cfg(feature = "ffi-testing")]
        pub static ALL_TEST_CASES: &'static [fn()] = &[
            $(
                #[cfg($target)]
                $name
            ),+
        ];
    };

    {@ $( $name:ident [ $target:meta ] => $test_case:expr ),+ , } => {
        $(
            #[cfg($target)]
            // #[wasm_bindgen_test::wasm_bindgen_test]
            pub(super) fn $name() {
                test_with_mock_root(&$test_case);
            }
        )+
    };
}

macro_rules! no_error {
    () => {
        None::<std::convert::Infallible>
    };
}

const ROOT1: &[u8] = include_bytes!("root1.crt");
const ROOT1_INT1: &[u8] = include_bytes!("root1-int1.crt");
const ROOT1_INT1_EXAMPLE_COM_GOOD: &[u8] = include_bytes!("root1-int1-ee_example.com-good.crt");
const ROOT1_INT1_LOCALHOST_IPV4_GOOD: &[u8] = include_bytes!("root1-int1-ee_127.0.0.1-good.crt");
const ROOT1_INT1_LOCALHOST_IPV6_GOOD: &[u8] = include_bytes!("root1-int1-ee_1-good.crt");

const EXAMPLE_COM: &str = "example.com";
const LOCALHOST_IPV4: &str = "127.0.0.1";
const LOCALHOST_IPV6: &str = "::1";

#[cfg(any(test, feature = "ffi-testing"))]
#[cfg_attr(feature = "ffi-testing", allow(dead_code))]
pub(super) fn verification_without_mock_root() {
    let verifier = crate::verifier_for_testing();

    let server_name = rustls::client::ServerName::try_from(EXAMPLE_COM).unwrap();
    let end_entity = rustls_pki_types::CertificateDer::from(ROOT1_INT1_EXAMPLE_COM_GOOD.to_vec());
    let intermediates = [rustls_pki_types::CertificateDer::from(ROOT1_INT1.to_vec())];

    // Fails because the server cert has no trust root in Windows, and can't since it uses a self-signed CA.
    let result = verifier.verify_server_cert(
        &end_entity,
        &intermediates,
        &server_name,
        &[],
        rustls_pki_types::UnixTime::now(),
    );

    assert_eq!(
        result.map(|_| ()),
        Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    );
}

#[test]
fn test_verification_without_mock_root() {
    verification_without_mock_root()
}

// Note: Android does not currently support IP address hosts, so these tests are disabled for
// Android.
// Verifies that our test trust anchor(s) are not trusted when `Verifier::new()`
// is used.
mock_root_test_cases! {
    valid_no_stapling_dns [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: EXAMPLE_COM,
        chain: &[ROOT1_INT1_EXAMPLE_COM_GOOD, ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Ok(()),
        other_error: no_error!(),
    },
    valid_no_stapling_ipv4 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV4,
        chain: &[ROOT1_INT1_LOCALHOST_IPV4_GOOD, ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Ok(()),
        other_error: no_error!(),
    },
    valid_no_stapling_ipv6 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV6,
        chain: &[ROOT1_INT1_LOCALHOST_IPV6_GOOD, ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Ok(()),
        other_error: no_error!(),
    },
    valid_stapled_good_dns [ any(windows, target_os = "android", target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: EXAMPLE_COM,
        chain: &[ROOT1_INT1_EXAMPLE_COM_GOOD, ROOT1_INT1],
        stapled_ocsp: Some(include_bytes!("root1-int1-ee_example.com-good.ocsp")),
        expected_result: Ok(()),
        other_error: no_error!(),
    },
    valid_stapled_good_ipv4 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV4,
        chain: &[ROOT1_INT1_LOCALHOST_IPV4_GOOD, ROOT1_INT1],
        stapled_ocsp: Some(include_bytes!("root1-int1-ee_127.0.0.1-good.ocsp")),
        expected_result: Ok(()),
        other_error: no_error!(),
    },
    valid_stapled_good_ipv6 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV6,
        chain: &[ROOT1_INT1_LOCALHOST_IPV6_GOOD, ROOT1_INT1],
        stapled_ocsp: Some(include_bytes!("root1-int1-ee_1-good.ocsp")),
        expected_result: Ok(()),
        other_error: no_error!(),
    },
    // Uses a separate certificate from the one used in the "good" case to deal
    // with operating systems with validation data caches (e.g. Windows).
    // Linux is not included, since the webpki verifier does not presently support OCSP revocation
    // checking.
    stapled_revoked_dns [ any(windows, target_os = "android", target_os = "macos") ] => TestCase {
        reference_id: EXAMPLE_COM,
        chain: &[include_bytes!("root1-int1-ee_example.com-revoked.crt"), ROOT1_INT1],
        stapled_ocsp: Some(include_bytes!("root1-int1-ee_example.com-revoked.ocsp")),
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::Revoked)),
        other_error: no_error!(),
    },
    stapled_revoked_ipv4 [ any(windows, target_os = "android", target_os = "macos") ] => TestCase {
        reference_id: LOCALHOST_IPV4,
        chain: &[include_bytes!("root1-int1-ee_127.0.0.1-revoked.crt"), ROOT1_INT1],
        stapled_ocsp: Some(include_bytes!("root1-int1-ee_127.0.0.1-revoked.ocsp")),
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::Revoked)),
        other_error: no_error!(),
    },
    stapled_revoked_ipv6 [ any(windows, target_os = "android", target_os = "macos") ] => TestCase {
        reference_id: LOCALHOST_IPV6,
        chain: &[include_bytes!("root1-int1-ee_1-revoked.crt"), ROOT1_INT1],
        stapled_ocsp: Some(include_bytes!("root1-int1-ee_1-revoked.ocsp")),
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::Revoked)),
        other_error: no_error!(),
    },
    // Validation fails with no intermediate (that can't be fetched
    // with AIA because there's no AIA issuer field in the certificate).
    // (AIA is an extension that allows downloading of missing data,
    // like missing certificates, during validation; see
    // https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.7).
    ee_only_dns [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: EXAMPLE_COM,
        chain: &[ROOT1_INT1_EXAMPLE_COM_GOOD],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer)),
        other_error: no_error!(),
    },
    ee_only_ipv4 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV4,
        chain: &[ROOT1_INT1_LOCALHOST_IPV4_GOOD],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer)),
        other_error: no_error!(),
    },
    ee_only_ipv6 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV6,
        chain: &[ROOT1_INT1_LOCALHOST_IPV6_GOOD],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer)),
        other_error: no_error!(),
    },
    // Validation fails when the certificate isn't valid for the reference ID.
    domain_mismatch_dns [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: "example.org",
        chain: &[ROOT1_INT1_EXAMPLE_COM_GOOD, ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::NotValidForName)),
        other_error: no_error!(),
    },
    domain_mismatch_ipv4 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: "198.168.0.1",
        chain: &[ROOT1_INT1_LOCALHOST_IPV4_GOOD, ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::NotValidForName)),
        other_error: no_error!(),
    },
    domain_mismatch_ipv6 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: "::ffff:c6a8:1",
        chain: &[ROOT1_INT1_LOCALHOST_IPV6_GOOD, ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(CertificateError::NotValidForName)),
        other_error: no_error!(),
    },
    wrong_eku_dns [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: EXAMPLE_COM,
        chain: &[include_bytes!("root1-int1-ee_example.com-wrong_eku.crt"), ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(
            CertificateError::Other(Arc::from(EkuError)))),
        other_error: Some(EkuError),
    },
    wrong_eku_ipv4 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV4,
        chain: &[include_bytes!("root1-int1-ee_127.0.0.1-wrong_eku.crt"), ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(
            CertificateError::Other(Arc::from(EkuError)))),
        other_error: Some(EkuError),
    },
    wrong_eku_ipv6 [ any(windows, target_os = "android", target_os = "macos", target_os = "linux") ] => TestCase {
        reference_id: LOCALHOST_IPV6,
        chain: &[include_bytes!("root1-int1-ee_1-wrong_eku.crt"), ROOT1_INT1],
        stapled_ocsp: None,
        expected_result: Err(TlsError::InvalidCertificate(
            CertificateError::Other(Arc::from(EkuError)))),
        other_error: Some(EkuError),
    },
}

fn test_with_mock_root<E: std::error::Error + PartialEq + 'static>(test_case: &TestCase<E>) {
    log::info!("verifying {:?}", test_case.expected_result);

    let verifier = Verifier::new_with_fake_root(ROOT1); // TODO: time
    let mut chain = test_case
        .chain
        .iter()
        .map(|bytes| rustls_pki_types::CertificateDer::from(bytes.to_vec()));

    let end_entity = chain.next().unwrap();
    let intermediates: Vec<rustls_pki_types::CertificateDer> = chain.collect();

    let server_name = rustls::client::ServerName::try_from(test_case.reference_id).unwrap();

    if test_case.reference_id.parse::<IpAddr>().is_ok() {
        assert!(matches!(
            server_name,
            rustls::client::ServerName::IpAddress(_)
        ));
    } else {
        assert!(matches!(
            server_name,
            rustls::client::ServerName::DnsName(_)
        ));
    }

    let result = verifier.verify_server_cert(
        &end_entity,
        &intermediates,
        &server_name,
        test_case.stapled_ocsp.unwrap_or(&[]),
        rustls_pki_types::UnixTime::now(),
    );

    assert_cert_error_eq(
        &result.map(|_| ()),
        &test_case.expected_result,
        test_case.other_error.as_ref(),
    );
    // TODO: get into specifics of errors returned when it fails.
}
