//! OWNER: A. Private key ↔ certificate matching (in memory only).
//!
//! The key is opened with OpenSSL only long enough to compare its public half with the certificate's public
//! key: RSA by modulus and public exponent, EC by curve and point, Ed25519/Ed448 by the raw public key, any
//! other algorithm by its DER SubjectPublicKeyInfo. Nothing of the key is returned except public facts.
use super::parse::pubkey_facts;
use super::sniff::{base64_body, is_encrypted_pkcs8, looks_pem};
use super::util::*;
use crate::model::*;
use openssl::pkey::{Id, PKey, PKeyRef, Private, Public};
use openssl::x509::X509;
use zeroize::Zeroizing;

fn need_password() -> CertError {
    CertError::new(
        ErrorKind::Password,
        "encrypted private key: a password is needed to open it and none was supplied",
    )
}

fn wrong_password() -> CertError {
    CertError::new(
        ErrorKind::Password,
        "the private key could not be opened: wrong password or unsupported encryption",
    )
}

/// Opens a private key: PEM or DER, PKCS#8 (plain or encrypted), PKCS#1 RSA, SEC1 EC, legacy encrypted PEM, or
/// the key of a PKCS#12. Returns the key and whether it was stored encrypted.
pub(crate) fn load_private_key(
    data: &[u8],
    password: Option<&Secret>,
) -> CertResult<(PKey<Private>, bool)> {
    let pw = password.map(|s| s.expose().as_bytes());
    if looks_pem(data) {
        let encrypted = pem::parse_many(data).is_ok_and(|blocks| {
            blocks.iter().any(|b| {
                b.tag() == "ENCRYPTED PRIVATE KEY"
                    || b.headers()
                        .get("Proc-Type")
                        .is_some_and(|v| v.contains("ENCRYPTED"))
            })
        });
        if encrypted {
            let pw = pw.ok_or_else(need_password)?;
            return PKey::private_key_from_pem_passphrase(data, pw)
                .map(|k| (k, true))
                .map_err(|_| wrong_password());
        }
        return PKey::private_key_from_pem(data)
            .map(|k| (k, false))
            .map_err(|e| parse_err("private key (PEM)", e));
    }
    if let Ok(p12) = openssl::pkcs12::Pkcs12::from_der(data) {
        let pws = password.map(|s| s.expose()).unwrap_or("");
        let parsed = p12.parse2(pws).map_err(|_| {
            if password.is_none() {
                need_password()
            } else {
                wrong_password()
            }
        })?;
        return parsed
            .pkey
            .map(|k| (k, !pws.is_empty()))
            .ok_or_else(|| CertError::new(ErrorKind::Parse, "the PKCS#12 holds no private key"));
    }
    if is_encrypted_pkcs8(data) {
        let pw = pw.ok_or_else(need_password)?;
        return PKey::private_key_from_pkcs8_passphrase(data, pw)
            .map(|k| (k, true))
            .map_err(|_| wrong_password());
    }
    if let Ok(k) = PKey::private_key_from_der(data) {
        return Ok((k, false));
    }
    if let Some(der) = base64_body(data) {
        let der = Zeroizing::new(der);
        if !looks_pem(&der) {
            return load_private_key(&der, password);
        }
    }
    Err(CertError::new(
        ErrorKind::Parse,
        "not a private key (PKCS#8, PKCS#1, SEC1 or PKCS#12, PEM or DER)",
    ))
}

/// Public facts of a private key.
pub(crate) fn key_facts(k: &PKeyRef<Private>, encrypted: bool) -> CertResult<KeyInfo> {
    Ok(KeyInfo {
        encrypted,
        ..pubkey_facts(k)
    })
}

/// The certificate's public key equals the private key's public half.
pub(crate) fn same_public_key(k: &PKeyRef<Private>, c: &PKeyRef<Public>) -> bool {
    if k.id() != c.id() {
        return false;
    }
    match k.id() {
        Id::RSA => match (k.rsa(), c.rsa()) {
            (Ok(a), Ok(b)) => a.n() == b.n() && a.e() == b.e(),
            _ => false,
        },
        Id::EC => match (k.ec_key(), c.ec_key()) {
            (Ok(a), Ok(b)) => {
                let same_curve = a.group().curve_name().is_some()
                    && a.group().curve_name() == b.group().curve_name();
                let Ok(mut ctx) = openssl::bn::BigNumContext::new() else {
                    return false;
                };
                same_curve
                    && a.public_key()
                        .eq(a.group(), b.public_key(), &mut ctx)
                        .unwrap_or(false)
            }
            _ => false,
        },
        Id::ED25519 | Id::ED448 | Id::X25519 | Id::X448 => {
            match (k.raw_public_key(), c.raw_public_key()) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        }
        Id::DSA => match (k.dsa(), c.dsa()) {
            (Ok(a), Ok(b)) => a.pub_key() == b.pub_key() && a.p() == b.p() && a.g() == b.g(),
            _ => false,
        },
        _ => match (k.public_key_to_der(), c.public_key_to_der()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        },
    }
}

pub fn match_key(key: &[u8], password: Option<&Secret>, cert_der: &[u8]) -> CertResult<KeyMatch> {
    let (k, encrypted) = load_private_key(key, password)?;
    let cert = X509::from_der(cert_der)
        .or_else(|_| X509::from_pem(cert_der))
        .map_err(|e| parse_err("certificate", e))?;
    let pubkey = cert.public_key().map_err(|e| {
        CertError::new(
            ErrorKind::Unsupported,
            format!("certificate public key: {e}"),
        )
    })?;
    let der = cert.to_der().map_err(|e| parse_err("certificate", e))?;
    Ok(KeyMatch {
        matches: same_public_key(&k, &pubkey),
        key: key_facts(&k, encrypted)?,
        cert_sha256: sha256_hex(&der),
        cert_subject: name_string(cert.subject_name()),
    })
}
