//! OWNER: A. Content sniffing: PEM labels, DER outer tags and OIDs (PKCS#7 / TST / OCSP / PKCS#12 / CRL / CSR).
//!
//! Decided from the bytes only, never from the extension. DER objects are recognised by OpenSSL's own decoders
//! (d2i_X509, d2i_X509_CRL, d2i_X509_REQ, d2i_OCSP_RESPONSE, d2i_PKCS12, d2i_AutoPrivateKey) plus a bounds-checked
//! walk of the CMS ContentInfo to tell an RFC 3161 token (eContentType id-ct-TSTInfo) from a PKCS#7 bundle.
//! Hostile input gives `Unknown`, never an error.
use super::util::*;
use crate::model::*;

pub fn sniff(data: &[u8]) -> CertResult<Sniffed> {
    Ok(sniff_inner(data))
}

pub(crate) fn sniff_inner(data: &[u8]) -> Sniffed {
    if looks_pem(data) {
        return sniff_pem(data);
    }
    if let Some((kind, encrypted)) = der_kind(data) {
        return Sniffed {
            kind: InputKindOrUnknown(kind),
            encoding: Encoding::Der,
            pem_labels: vec![],
            encrypted,
        };
    }
    if let Some(der) = base64_body(data)
        && let Some((kind, encrypted)) = der_kind(&der)
    {
        return Sniffed {
            kind: InputKindOrUnknown(kind),
            encoding: Encoding::Base64,
            pem_labels: vec![],
            encrypted,
        };
    }
    Sniffed::default()
}

pub(crate) fn looks_pem(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"-----BEGIN ")
}

/// The kind a PEM label stands for (None = a block this tool does not analyse, e.g. PUBLIC KEY).
pub(crate) fn label_kind(label: &str, contents: &[u8]) -> Option<InputKind> {
    Some(match label {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => InputKind::Certificate,
        "X509 CRL" => InputKind::Crl,
        "PKCS7" | "CMS" => {
            if signed_data_econtent_type(contents).as_deref() == Some(OID_TST_INFO) {
                InputKind::TimestampToken
            } else {
                InputKind::Pkcs7
            }
        }
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => InputKind::Csr,
        "PRIVATE KEY"
        | "RSA PRIVATE KEY"
        | "EC PRIVATE KEY"
        | "DSA PRIVATE KEY"
        | "ENCRYPTED PRIVATE KEY" => InputKind::PrivateKey,
        "OCSP RESPONSE" => InputKind::OcspResponse,
        "PKCS12" => InputKind::Pkcs12,
        _ => return None,
    })
}

fn sniff_pem(data: &[u8]) -> Sniffed {
    let blocks = match pem::parse_many(data) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            return Sniffed {
                encoding: Encoding::Pem,
                ..Default::default()
            };
        }
    };
    let labels: Vec<String> = blocks.iter().map(|b| b.tag().to_string()).collect();
    let kinds: Vec<InputKind> = blocks
        .iter()
        .filter_map(|b| label_kind(b.tag(), b.contents()))
        .collect();
    let certs = kinds
        .iter()
        .filter(|k| **k == InputKind::Certificate)
        .count();
    let kind = match (certs, kinds.first()) {
        (0, Some(k)) => *k,
        (1, _) => InputKind::Certificate,
        (0, None) => InputKind::Unknown,
        _ => InputKind::CertBundle,
    };
    let encrypted = blocks.iter().any(|b| {
        b.tag() == "ENCRYPTED PRIVATE KEY"
            || b.headers()
                .get("Proc-Type")
                .is_some_and(|v| v.contains("ENCRYPTED"))
    });
    Sniffed {
        kind: InputKindOrUnknown(kind),
        encoding: Encoding::Pem,
        pem_labels: labels,
        encrypted,
    }
}

const PBE_PREFIXES: [&str; 2] = ["1.2.840.113549.1.5.", "1.2.840.113549.1.12.1."];

/// EncryptedPrivateKeyInfo: `SEQUENCE { AlgorithmIdentifier (PBES2 / PKCS#12 PBE), OCTET STRING }`.
pub(crate) fn is_encrypted_pkcs8(der: &[u8]) -> bool {
    let Some((outer, rest)) = tlv(der) else {
        return false;
    };
    if outer.tag != 0x30 || !rest.is_empty() {
        return false;
    }
    let f = children(outer.content);
    if f.len() != 2 || f[0].tag != 0x30 || f[1].tag != 0x04 {
        return false;
    }
    let Some((oid, _)) = tlv(f[0].content) else {
        return false;
    };
    oid.tag == 0x06
        && oid_text(oid.content).is_some_and(|o| PBE_PREFIXES.iter().any(|p| o.starts_with(p)))
}

/// (kind, encrypted) of a DER object, None when it is none of the supported structures.
pub(crate) fn der_kind(der: &[u8]) -> Option<(InputKind, bool)> {
    if der.first() != Some(&0x30) || tlv(der).is_none() {
        return None;
    }
    use openssl::x509::{X509, X509Crl, X509Req};
    if X509::from_der(der).is_ok() {
        return Some((InputKind::Certificate, false));
    }
    if X509Crl::from_der(der).is_ok() {
        return Some((InputKind::Crl, false));
    }
    if X509Req::from_der(der).is_ok() {
        return Some((InputKind::Csr, false));
    }
    if openssl::ocsp::OcspResponse::from_der(der).is_ok() {
        return Some((InputKind::OcspResponse, false));
    }
    match signed_data_econtent_type(der) {
        Some(t) if t == OID_TST_INFO => return Some((InputKind::TimestampToken, false)),
        Some(_) if openssl::pkcs7::Pkcs7::from_der(der).is_ok() => {
            return Some((InputKind::Pkcs7, false));
        }
        _ => {}
    }
    if tsr_parts(der).is_some() {
        return Some((InputKind::TimestampToken, false));
    }
    if let Ok(p12) = openssl::pkcs12::Pkcs12::from_der(der) {
        return Some((InputKind::Pkcs12, p12.parse2("").is_err()));
    }
    if is_encrypted_pkcs8(der) {
        return Some((InputKind::PrivateKey, true));
    }
    if openssl::pkey::PKey::private_key_from_der(der).is_ok() {
        return Some((InputKind::PrivateKey, false));
    }
    None
}

/// Base64 without armour (some exports): the decoded bytes, when the whole input is base64.
pub(crate) fn base64_body(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 || data.len() > 32 * 1024 * 1024 {
        return None;
    }
    let mut s = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => s.push(b as char),
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => return None,
        }
    }
    if !s.len().is_multiple_of(4) {
        return None;
    }
    openssl::base64::decode_block(&s).ok()
}
