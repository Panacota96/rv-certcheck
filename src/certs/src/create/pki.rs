//! OWNER: B. CA folders (`rakvor.ca/1`): root, import, issue, revoke, CRL, OCSP.
use crate::model::*;
use std::path::Path;

pub fn init_root(_req: &InitRootRequest) -> CertResult<CaFolder> {
    Err(CertError::not_implemented("pki::init_root"))
}

pub fn import_ca(_req: &ImportCaRequest) -> CertResult<CaFolder> {
    Err(CertError::not_implemented("pki::import_ca"))
}

pub fn open(_ca_dir: &Path) -> CertResult<CaFolder> {
    Err(CertError::not_implemented("pki::open"))
}

pub fn issue(_req: &IssueRequest) -> CertResult<IssueResult> {
    Err(CertError::not_implemented("pki::issue"))
}

pub fn revoke(_req: &RevokeRequest) -> CertResult<IssuedRecord> {
    Err(CertError::not_implemented("pki::revoke"))
}

pub fn make_crl(_req: &CrlRequest) -> CertResult<CrlResult> {
    Err(CertError::not_implemented("pki::make_crl"))
}

pub fn sign_ocsp(_req: &OcspSignRequest) -> CertResult<OcspSignResult> {
    Err(CertError::not_implemented("pki::sign_ocsp"))
}
