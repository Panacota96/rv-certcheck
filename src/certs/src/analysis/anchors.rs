//! OWNER: A. `--anchor` resolution (file, bundled Rakvor root, system store, trust-list snapshot).
use crate::model::*;
use std::path::Path;

pub fn resolve_anchors(
    _specs: &[AnchorSpec],
    _trust_list_dir: Option<&Path>,
) -> CertResult<Vec<ResolvedAnchor>> {
    Err(CertError::not_implemented("resolve_anchors"))
}
