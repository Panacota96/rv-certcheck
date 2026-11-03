//! Creation side (OWNER: agent B). Implementation modules behind the frozen facades in lib.rs; split or add
//! files freely inside `create/` (keys.rs for key generation / encrypted PKCS#8, signer.rs for the rcgen
//! SigningKey over OpenSSL and PKCS#11, issued.rs for the hash-chained issued.jsonl, rng.rs for the seeded
//! ChaCha20 lab RNG...), keep the facade signatures.

pub mod csr;
pub mod lab;
pub mod pki;
pub mod tokens;
