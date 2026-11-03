//! OWNER: A. OpenSSL-style text dump (certificate.txt).
use crate::model::*;

pub fn certificate_text(_der: &[u8]) -> CertResult<String> {
    Err(CertError::not_implemented("certificate_text"))
}
