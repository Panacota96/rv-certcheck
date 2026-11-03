//! OWNER: B. PKCS#10 creation and display.
use crate::model::*;

pub fn new(_req: &CsrRequest) -> CertResult<CsrResult> {
    Err(CertError::not_implemented("csr::new"))
}

pub fn show(_data: &[u8]) -> CertResult<CsrInfo> {
    Err(CertError::not_implemented("csr::show"))
}
