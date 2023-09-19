use certval::{PDVCertificate, PkiEnvironment, TrustAnchorSource};
use crate::WireX509Error;

fn find_verification_path(subject: &[u8], bag_of_certificates: &[&[u8]]) -> Result<(), WireX509Error> {
    let ta_source = certval::source::ta_source::TaSource::new_from_unparsed(bag_of_certificates)?;
    let target = PDVCertificate::try_from(subject)?;
    let ta_choice = ta_source.get_trust_anchor_for_target(&target)?;

    let mut env = PkiEnvironment::new();
    env.add_trust_anchor_source(Box::new(ta_source));

    // env.validate_path()

    Ok(())
}