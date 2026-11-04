//! OWNER: A. OpenSSL-style text dump (certificate.txt): `X509_print`, the same text as
//! `openssl x509 -text -noout`.
use super::util::parse_err;
use crate::model::*;

pub fn certificate_text(der: &[u8]) -> CertResult<String> {
    let x = openssl::x509::X509::from_der(der)
        .or_else(|_| openssl::x509::X509::from_pem(der))
        .map_err(|e| parse_err("certificate", e))?;
    let t = x.to_text().map_err(|e| parse_err("certificate text", e))?;
    Ok(String::from_utf8_lossy(&t).into_owned())
}
