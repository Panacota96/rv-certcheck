//! OWNER: A. Private key ↔ certificate matching (in memory only).
use crate::model::*;

pub fn match_key(
    _key: &[u8],
    _password: Option<&Secret>,
    _cert_der: &[u8],
) -> CertResult<KeyMatch> {
    Err(CertError::not_implemented("match_key"))
}
