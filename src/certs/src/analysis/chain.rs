//! OWNER: A. Path building and verification with OpenSSL's X509_STORE_CTX.
use crate::model::*;

pub fn validate_chain(_req: &ChainRequest, _opts: &ValidationOptions) -> CertResult<ChainVerdict> {
    Err(CertError::not_implemented("validate_chain"))
}
