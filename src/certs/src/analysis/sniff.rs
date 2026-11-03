//! OWNER: A. Content sniffing: PEM labels, DER outer tags and OIDs (PKCS#7 / TST / OCSP / PKCS#12 / CRL / CSR).
use crate::model::*;

pub fn sniff(_data: &[u8]) -> CertResult<Sniffed> {
    Err(CertError::not_implemented("sniff"))
}
