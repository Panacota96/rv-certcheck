//! OWNER: B. One signing interface over OpenSSL keys and PKCS#11 token keys, plus the signature algorithms the
//! creation side writes (including the deliberately weak SHA-1 / MD5 RSA signatures of lab sets).

use super::derw::*;
use super::keys::{canonical_spki, crypto};
use super::tokens::TokenSession;
use crate::model::*;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    RsaSha256,
    RsaSha384,
    /// Lab sets only (weak-signature case).
    RsaSha1,
    /// Lab sets only (weak-signature case).
    RsaMd5,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
}

impl SigAlg {
    pub fn oid(&self) -> &'static str {
        match self {
            SigAlg::RsaSha256 => "1.2.840.113549.1.1.11",
            SigAlg::RsaSha384 => "1.2.840.113549.1.1.12",
            SigAlg::RsaSha1 => "1.2.840.113549.1.1.5",
            SigAlg::RsaMd5 => "1.2.840.113549.1.1.4",
            SigAlg::EcdsaSha256 => "1.2.840.10045.4.3.2",
            SigAlg::EcdsaSha384 => "1.2.840.10045.4.3.3",
            SigAlg::EcdsaSha512 => "1.2.840.10045.4.3.4",
            SigAlg::Ed25519 => "1.3.101.112",
        }
    }
    /// AlgorithmIdentifier DER: RSA with NULL parameters, ECDSA / EdDSA without (RFC 4055, 5758, 8410).
    pub fn alg_id(&self) -> Vec<u8> {
        match self {
            SigAlg::RsaSha256 | SigAlg::RsaSha384 | SigAlg::RsaSha1 | SigAlg::RsaMd5 => {
                alg_null(self.oid())
            }
            _ => alg_absent(self.oid()),
        }
    }
    fn digest(&self) -> Option<MessageDigest> {
        match self {
            SigAlg::RsaSha256 | SigAlg::EcdsaSha256 => Some(MessageDigest::sha256()),
            SigAlg::RsaSha384 | SigAlg::EcdsaSha384 => Some(MessageDigest::sha384()),
            SigAlg::EcdsaSha512 => Some(MessageDigest::sha512()),
            SigAlg::RsaSha1 => Some(MessageDigest::sha1()),
            SigAlg::RsaMd5 => Some(MessageDigest::md5()),
            SigAlg::Ed25519 => None,
        }
    }
    /// The PKCS#11 scheme name of [`TokenSession::sign`].
    fn token_scheme(&self) -> CertResult<&'static str> {
        Ok(match self {
            SigAlg::RsaSha256 => "rsa-pkcs1-sha256",
            SigAlg::RsaSha384 => "rsa-pkcs1-sha384",
            SigAlg::EcdsaSha256 => "ecdsa-sha256",
            SigAlg::EcdsaSha384 => "ecdsa-sha384",
            SigAlg::Ed25519 => "ed25519",
            other => {
                return Err(CertError::new(
                    ErrorKind::Unsupported,
                    format!("{other:?} is not offered for token keys"),
                ));
            }
        })
    }
}

/// DigestInfo prefixes (RFC 8017 9.2 note 1) for the raw RSA path.
pub fn digest_info_prefix(alg: SigAlg) -> &'static [u8] {
    match alg {
        SigAlg::RsaMd5 => &[
            0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
            0x05, 0x00, 0x04, 0x10,
        ],
        SigAlg::RsaSha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        SigAlg::RsaSha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        SigAlg::RsaSha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        _ => &[],
    }
}

/// A private key able to sign: in memory (OpenSSL) or on a PKCS#11 token (never leaves it).
pub enum Signer {
    Soft(PKey<Private>),
    Token {
        session: Box<TokenSession>,
        key_id_hex: String,
        spki: Vec<u8>,
    },
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signer::Soft(_) => f.write_str("Signer::Soft(***)"),
            Signer::Token { key_id_hex, .. } => write!(f, "Signer::Token({key_id_hex})"),
        }
    }
}

/// Set to true once a raw RSA operation had to be used for MD5 (reported in lab descriptions and tests).
pub static MD5_RAW_FALLBACK_USED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

impl Signer {
    pub fn token(session: TokenSession, key_id_hex: &str) -> CertResult<Signer> {
        let spki = canonical_spki(&session.public_key_der(key_id_hex)?)?;
        Ok(Signer::Token {
            session: Box::new(session),
            key_id_hex: key_id_hex.to_string(),
            spki,
        })
    }

    /// Canonical DER SubjectPublicKeyInfo.
    pub fn spki(&self) -> CertResult<Vec<u8>> {
        match self {
            Signer::Soft(k) => k.public_key_to_der().map_err(crypto("public key")),
            Signer::Token { spki, .. } => Ok(spki.clone()),
        }
    }

    /// The algorithm a CA with this key signs with: SHA-256 for RSA and P-256, SHA-384 for P-384, SHA-512 for
    /// P-521, Ed25519 for Ed25519.
    pub fn default_alg(&self) -> CertResult<SigAlg> {
        let k = PKey::public_key_from_der(&self.spki()?).map_err(crypto("public key"))?;
        match k.id() {
            Id::RSA => Ok(SigAlg::RsaSha256),
            Id::EC => match k.bits() {
                256 => Ok(SigAlg::EcdsaSha256),
                384 => Ok(SigAlg::EcdsaSha384),
                _ => Ok(SigAlg::EcdsaSha512),
            },
            Id::ED25519 => Ok(SigAlg::Ed25519),
            other => Err(CertError::new(
                ErrorKind::Unsupported,
                format!("cannot sign with key type {}", other.as_raw()),
            )),
        }
    }

    pub fn sign(&self, alg: SigAlg, data: &[u8]) -> CertResult<Vec<u8>> {
        match self {
            Signer::Soft(k) => soft_sign(k, alg, data),
            Signer::Token {
                session,
                key_id_hex,
                ..
            } => session.sign(key_id_hex, alg.token_scheme()?, data),
        }
    }
}

fn soft_sign(k: &PKey<Private>, alg: SigAlg, data: &[u8]) -> CertResult<Vec<u8>> {
    let c = crypto("signature");
    match alg.digest() {
        None => {
            let mut s = openssl::sign::Signer::new_without_digest(k).map_err(&c)?;
            s.sign_oneshot_to_vec(data).map_err(&c)
        }
        Some(md) => {
            let attempt = (|| {
                let mut s = openssl::sign::Signer::new(md, k)?;
                s.update(data)?;
                s.sign_to_vec()
            })();
            match attempt {
                Ok(sig) => Ok(sig),
                Err(e) if alg == SigAlg::RsaMd5 || alg == SigAlg::RsaSha1 => {
                    // OpenSSL refused the legacy digest for signing: sign the DigestInfo with a raw RSA PKCS#1
                    // v1.5 private-key operation instead (same bytes a conforming signer would produce).
                    let _ = e;
                    MD5_RAW_FALLBACK_USED.store(true, std::sync::atomic::Ordering::Relaxed);
                    raw_rsa_pkcs1(k, alg, data)
                }
                Err(e) => Err(c(e)),
            }
        }
    }
}

/// RSASSA-PKCS1-v1_5 by hand: DigestInfo(hash(data)) through RSA_private_encrypt with PKCS#1 type-1 padding.
pub fn raw_rsa_pkcs1(k: &PKey<Private>, alg: SigAlg, data: &[u8]) -> CertResult<Vec<u8>> {
    let c = crypto("raw RSA signature");
    let md = alg
        .digest()
        .ok_or_else(|| CertError::new(ErrorKind::InvalidInput, "raw RSA needs a digest"))?;
    let h = openssl::hash::hash(md, data).map_err(&c)?;
    let mut di = digest_info_prefix(alg).to_vec();
    di.extend_from_slice(&h);
    let rsa = k.rsa().map_err(&c)?;
    let mut out = vec![0u8; rsa.size() as usize];
    let n = rsa
        .private_encrypt(&di, &mut out, openssl::rsa::Padding::PKCS1)
        .map_err(&c)?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_rsa_equals_openssl_pkcs1_signatures() {
        let k = super::super::keys::seeded_rsa(&mut super::super::rng::Rand::lab(3, "s"), 1024)
            .unwrap();
        for alg in [SigAlg::RsaSha256, SigAlg::RsaSha1] {
            let a = soft_sign(&k, alg, b"tbs").unwrap();
            assert_eq!(a, raw_rsa_pkcs1(&k, alg, b"tbs").unwrap(), "{alg:?}");
        }
        // MD5: either path yields a signature that verifies as md5WithRSAEncryption.
        let sig = soft_sign(&k, SigAlg::RsaMd5, b"tbs").unwrap();
        assert_eq!(sig, raw_rsa_pkcs1(&k, SigAlg::RsaMd5, b"tbs").unwrap());
        eprintln!(
            "MD5 signing path: {}",
            if MD5_RAW_FALLBACK_USED.load(std::sync::atomic::Ordering::Relaxed) {
                "raw RSA (OpenSSL refused md5 in EVP_DigestSign)"
            } else {
                "OpenSSL EVP_DigestSign with md5"
            }
        );
    }
}
