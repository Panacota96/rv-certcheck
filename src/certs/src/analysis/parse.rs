//! OWNER: A. Field extraction into CertInfo / CrlInfo / OcspInfo / TimestampInfo / KeyInfo / CsrInfo.
use crate::model::*;

pub fn parse_any(_data: &[u8], _password: Option<&Secret>) -> CertResult<ParsedInput> {
    Err(CertError::not_implemented("parse_any"))
}
