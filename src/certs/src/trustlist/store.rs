//! OWNER: A. Snapshot storage (`<store>/<list>/<id>.json`), listing and lookup.
use crate::model::*;
use std::path::Path;

pub fn load(_store_dir: &Path, _list: TrustListKind, _id: &str) -> CertResult<TrustListSnapshot> {
    Err(CertError::not_implemented("trust_list::load"))
}

pub fn list(_store_dir: &Path) -> CertResult<Vec<TrustListSummary>> {
    Err(CertError::not_implemented("trust_list::list"))
}

pub fn lookup(
    _snapshot: &TrustListSnapshot,
    _cert: &CertInfo,
    _at: &str,
) -> Option<TrustListMatch> {
    None
}
