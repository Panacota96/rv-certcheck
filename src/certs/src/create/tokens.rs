//! OWNER: B. PKCS#11 through cryptoki (SoftHSM2 in CI, YubiKey ykcs11 manually).
use crate::model::*;
use std::path::Path;

/// A logged-in session on one token. Internals are agent B's; the methods below are the frozen surface pki uses.
pub struct TokenSession {
    _private: (),
}

impl TokenSession {
    /// Key pairs on the token (public facts only).
    pub fn keys(&self) -> CertResult<Vec<TokenKeyInfo>> {
        Err(CertError::not_implemented("tokens::TokenSession::keys"))
    }
    /// DER SubjectPublicKeyInfo of the key with this CKA_ID.
    pub fn public_key_der(&self, _key_id_hex: &str) -> CertResult<Vec<u8>> {
        Err(CertError::not_implemented(
            "tokens::TokenSession::public_key_der",
        ))
    }
    /// Signs `data` with the key (`scheme`: `rsa-pkcs1-sha256`, `rsa-pkcs1-sha384`, `ecdsa-sha256`,
    /// `ecdsa-sha384`, `ed25519`); returns the signature as X.509 expects it (ECDSA DER-encoded).
    pub fn sign(&self, _key_id_hex: &str, _scheme: &str, _data: &[u8]) -> CertResult<Vec<u8>> {
        Err(CertError::not_implemented("tokens::TokenSession::sign"))
    }
}

pub fn list(_module: &Path) -> CertResult<Vec<TokenInfo>> {
    Err(CertError::not_implemented("tokens::list"))
}

pub fn generate_key(
    _module: &Path,
    _token_serial: &str,
    _pin: &Secret,
    _spec: KeySpec,
    _label: &str,
    _confirm_root: bool,
) -> CertResult<KeyLocation> {
    Err(CertError::not_implemented("tokens::generate_key"))
}

pub fn open(_module: &Path, _token_serial: &str, _pin: &Secret) -> CertResult<TokenSession> {
    Err(CertError::not_implemented("tokens::open"))
}
