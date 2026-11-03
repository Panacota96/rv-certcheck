//! OWNER: A. RFC 3161 token verification (CMS via OpenSSL, TSTInfo via x509-tsp).
use crate::model::*;

pub fn verify_timestamp_token(
    _token: &[u8],
    _data: Option<&[u8]>,
    _req: &ChainRequest,
    _opts: &ValidationOptions,
) -> CertResult<TimestampVerdict> {
    Err(CertError::not_implemented("verify_timestamp_token"))
}
