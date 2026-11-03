//! OWNER: A. ETSI TS 119 612 LOTL/TL XML (quick-xml).
use crate::model::*;
use std::path::Path;

pub fn import_eu(
    _xml: &[u8],
    _source: &str,
    _fetched_utc: &str,
    _store_dir: &Path,
) -> CertResult<TrustListSnapshot> {
    Err(CertError::not_implemented("trust_list::import_eu"))
}
