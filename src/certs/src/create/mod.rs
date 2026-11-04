//! Creation side (OWNER: agent B). Implementation modules behind the frozen facades in lib.rs.
//!
//! ```text
//! derw     DER writer (every signed byte is decided here)       build    TBS cert / CRL / CSR / OCSP + extensions
//! rng      OS CSPRNG or seeded ChaCha20 (lab only)              keys     key generation, encrypted PKCS#8, PKCS#12
//! signer   one signing interface: OpenSSL key or PKCS#11 key    issued   hash-chained issued.jsonl + folder lock
//! pki      CA folders                                           csr      PKCS#10        lab   seeded lab sets
//! tokens   PKCS#11 (cryptoki)
//! ```
//! rcgen is not used: without its `crypto` and `x509-parser` features it cannot take an issuer from an existing CA
//! certificate (needed for `pki import`), mark an EKU critical (TSA profile, RFC 3161 2.3), write user-notice
//! policy qualifiers, or sign with SHA-1 / MD5 (lab sets). The DER is written by `derw` and checked against
//! OpenSSL (parse + verify) in every operation and test.

pub mod build;
pub mod csr;
pub mod derw;
pub mod issued;
pub mod keys;
pub mod lab;
pub mod pki;
pub mod rng;
pub mod signer;
pub mod tokens;

/// The product version (version.txt), recorded in ca.json, issued.jsonl and lab manifests.
pub fn tool_version() -> &'static str {
    include_str!("../../../../version.txt").trim()
}
