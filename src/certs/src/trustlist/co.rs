//! OWNER: A. Curated Colombian CSV of ONAC-accredited ECDs.
use crate::model::*;
use std::path::Path;

pub fn import_co_csv(
    _csv: &[u8],
    _source: &str,
    _fetched_utc: &str,
    _store_dir: &Path,
) -> CertResult<TrustListSnapshot> {
    Err(CertError::not_implemented("trust_list::import_co_csv"))
}
