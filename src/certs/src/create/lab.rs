//! OWNER: B. Seeded, byte-identical lab sets with expected_findings.json.
use crate::model::*;

pub fn make(_spec: &LabSetSpec) -> CertResult<LabSetManifest> {
    Err(CertError::not_implemented("lab::make"))
}
