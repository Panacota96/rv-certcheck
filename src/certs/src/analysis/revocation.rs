//! OWNER: A. CRL and OCSP evaluation (offline; online fetching later, audited by core).
use crate::model::*;

pub fn check_revocation(
    _cert_der: &[u8],
    _issuer_der: &[u8],
    _crls: &[LabeledDer],
    _ocsp: &[LabeledDer],
    _at: &str,
) -> CertResult<RevocationStatus> {
    Err(CertError::not_implemented("check_revocation"))
}
