//! OWNER: B. TBS structures (certificate, CRL, CSR, OCSP response) and the extensions of every profile.

use super::derw::*;
use super::signer::{SigAlg, Signer};
use crate::model::*;
use chrono::{DateTime, Utc};

pub const OID_EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const OID_EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
pub const OID_EKU_EMAIL: &str = "1.3.6.1.5.5.7.3.4";
pub const OID_EKU_TIMESTAMPING: &str = "1.3.6.1.5.5.7.3.8";
/// id-kp-documentSigning (RFC 9336).
pub const OID_EKU_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";
/// Microsoft Document Signing (szOID_KP_DOCUMENT_SIGNING): what Adobe Acrobat and Windows look for.
pub const OID_EKU_MS_DOCUMENT_SIGNING: &str = "1.3.6.1.4.1.311.10.3.12";

/// Key usage bit numbers (RFC 5280 4.2.1.3).
pub mod ku {
    pub const DIGITAL_SIGNATURE: usize = 0;
    pub const NON_REPUDIATION: usize = 1;
    pub const KEY_ENCIPHERMENT: usize = 2;
    pub const KEY_CERT_SIGN: usize = 5;
    pub const CRL_SIGN: usize = 6;
}

pub fn ext_basic_constraints(ca: bool, path_len: Option<u32>) -> Vec<u8> {
    let mut v = vec![];
    if ca {
        v.push(boolean(true));
        if let Some(p) = path_len {
            v.push(int(p as u64));
        }
    }
    extension("2.5.29.19", true, &seq(&v))
}

pub fn ext_key_usage(bits: &[usize]) -> Vec<u8> {
    extension("2.5.29.15", true, &named_bits(bits))
}

pub fn ext_eku(oids: &[&str], critical: bool) -> Vec<u8> {
    let v: Vec<Vec<u8>> = oids.iter().map(|o| oid(o)).collect();
    extension("2.5.29.37", critical, &seq(&v))
}

pub fn ext_ski(id: &[u8]) -> Vec<u8> {
    extension("2.5.29.14", false, &octet(id))
}

pub fn ext_aki(id: &[u8]) -> Vec<u8> {
    extension("2.5.29.35", false, &seq(&[implicit_prim(0, id)]))
}

pub fn ext_san(names: &[GeneralName]) -> CertResult<Vec<u8>> {
    let v: Vec<Vec<u8>> = names.iter().map(general_name).collect::<CertResult<_>>()?;
    Ok(extension("2.5.29.17", false, &seq(&v)))
}

/// certificatePolicies with one policy and an explicitText user notice (RFC 5280 4.2.1.4).
pub fn ext_policy(policy_oid: &str, notice: &str) -> CertResult<Vec<u8>> {
    let qualifier = seq(&[oid("1.3.6.1.5.5.7.2.2"), seq(&[utf8(notice)])]);
    let info = seq(&[tlv(0x06, &oid_content(policy_oid)?), seq(&[qualifier])]);
    Ok(extension("2.5.29.32", false, &seq(&[info])))
}

/// cRLDistributionPoints with one fullName URI.
pub fn ext_cdp(url: &str) -> Vec<u8> {
    let dp = seq(&[explicit(
        0,
        &implicit_cons(0, &implicit_prim(6, url.as_bytes())),
    )]);
    extension("2.5.29.31", false, &seq(&[dp]))
}

/// nameConstraints with permitted subtrees only (critical, RFC 5280 4.2.1.10).
pub fn ext_name_constraints(permitted: &[GeneralName]) -> CertResult<Vec<u8>> {
    let subtrees: Vec<Vec<u8>> = permitted
        .iter()
        .map(|g| general_name(g).map(|n| seq(&[n])))
        .collect::<CertResult<_>>()?;
    Ok(extension(
        "2.5.29.30",
        true,
        &seq(&[implicit_cons(0, &subtrees.concat())]),
    ))
}

/// Everything a certificate needs except the signature.
pub struct CertTemplate {
    /// Serial magnitude (positive).
    pub serial: Vec<u8>,
    /// Issuer Name DER (the CA certificate's subject, byte for byte).
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub spki: Vec<u8>,
    pub extensions: Vec<Vec<u8>>,
}

pub fn tbs_certificate(t: &CertTemplate, alg: SigAlg) -> Vec<u8> {
    seq(&[
        explicit(0, &int(2)),
        uint(&t.serial),
        alg.alg_id(),
        t.issuer.clone(),
        seq(&[time(t.not_before), time(t.not_after)]),
        t.subject.clone(),
        t.spki.clone(),
        explicit(3, &seq(&t.extensions)),
    ])
}

/// TBS + signature → Certificate / CertificateList / CertificationRequest / BasicOCSPResponse body.
pub fn signed(tbs: Vec<u8>, alg: SigAlg, signer: &Signer) -> CertResult<Vec<u8>> {
    let sig = signer.sign(alg, &tbs)?;
    Ok(seq(&[tbs, alg.alg_id(), bits(&sig)]))
}

pub fn certificate(t: &CertTemplate, alg: SigAlg, signer: &Signer) -> CertResult<Vec<u8>> {
    signed(tbs_certificate(t, alg), alg, signer)
}

/// RFC 5280 CRLReason code of a reason name.
pub fn reason_code(name: &str) -> CertResult<u8> {
    Ok(match name {
        "unspecified" => 0,
        "keyCompromise" => 1,
        "cACompromise" => 2,
        "affiliationChanged" => 3,
        "superseded" => 4,
        "cessationOfOperation" => 5,
        "certificateHold" => 6,
        "privilegeWithdrawn" => 9,
        "aACompromise" => 10,
        other => {
            return Err(CertError::new(
                ErrorKind::InvalidInput,
                format!(
                    "unknown revocation reason '{other}': use one of {}",
                    REVOCATION_REASONS.join(", ")
                ),
            ));
        }
    })
}

pub struct RevokedSpec {
    pub serial: Vec<u8>,
    pub at: DateTime<Utc>,
    pub reason: String,
}

/// A v2 CRL with AKI and cRLNumber (reasonCode entry extension unless `unspecified`, as RFC 5280 5.3.1 asks).
#[allow(clippy::too_many_arguments)]
pub fn crl(
    issuer: &[u8],
    issuer_key_id: &[u8],
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
    number: u64,
    revoked: &[RevokedSpec],
    alg: SigAlg,
    signer: &Signer,
) -> CertResult<Vec<u8>> {
    let mut parts = vec![
        int(1),
        alg.alg_id(),
        issuer.to_vec(),
        time(this_update),
        time(next_update),
    ];
    if !revoked.is_empty() {
        let mut entries = vec![];
        for r in revoked {
            let mut e = vec![uint(&r.serial), time(r.at)];
            let code = reason_code(&r.reason)?;
            if code != 0 {
                e.push(seq(&[extension("2.5.29.21", false, &enumerated(code))]));
            }
            entries.push(seq(&e));
        }
        parts.push(seq(&entries));
    }
    parts.push(explicit(
        0,
        &seq(&[
            ext_aki(issuer_key_id),
            extension("2.5.29.20", false, &int(number)),
        ]),
    ));
    signed(seq(&parts), alg, signer)
}

/// PKCS#10 with an extensionRequest for the SANs (RFC 2986, RFC 2985 5.4.2).
pub fn csr(
    subject: &[u8],
    spki: &[u8],
    sans: &[GeneralName],
    alg: SigAlg,
    signer: &Signer,
) -> CertResult<Vec<u8>> {
    let attrs = if sans.is_empty() {
        implicit_cons(0, &[])
    } else {
        let exts = seq(&[ext_san(sans)?]);
        implicit_cons(0, &seq(&[oid("1.2.840.113549.1.9.14"), set_of(&[exts])]))
    };
    let info = seq(&[int(0), subject.to_vec(), spki.to_vec(), attrs]);
    signed(info, alg, signer)
}

pub enum OcspCertStatus {
    Good,
    Revoked { at: DateTime<Utc>, reason: String },
    Unknown,
}

/// OCSPResponse (successful, id-pkix-ocsp-basic) for one certificate, responder by name, the responder certificate
/// embedded. CertID uses SHA-1 (RFC 6960 4.1.1; what every client sends).
#[allow(clippy::too_many_arguments)]
pub fn ocsp_response(
    responder_name: &[u8],
    responder_cert: &[u8],
    issuer_name: &[u8],
    issuer_key_bits: &[u8],
    serial: &[u8],
    status: &OcspCertStatus,
    produced_at: DateTime<Utc>,
    next_update: Option<DateTime<Utc>>,
    alg: SigAlg,
    signer: &Signer,
) -> CertResult<Vec<u8>> {
    let cert_id = seq(&[
        alg_null("1.3.14.3.2.26"),
        octet(&openssl::sha::sha1(issuer_name)),
        octet(&openssl::sha::sha1(issuer_key_bits)),
        uint(serial),
    ]);
    let st = match status {
        OcspCertStatus::Good => implicit_prim(0, &[]),
        OcspCertStatus::Revoked { at, reason } => {
            let mut v = vec![gentime(*at)];
            let code = reason_code(reason)?;
            if code != 0 {
                v.push(explicit(0, &enumerated(code)));
            }
            implicit_cons(1, &v.concat())
        }
        OcspCertStatus::Unknown => implicit_prim(2, &[]),
    };
    let mut single = vec![cert_id, st, gentime(produced_at)];
    if let Some(n) = next_update {
        single.push(explicit(0, &gentime(n)));
    }
    let tbs = seq(&[
        explicit(1, responder_name),
        gentime(produced_at),
        seq(&[seq(&single)]),
    ]);
    let sig = signer.sign(alg, &tbs)?;
    let basic = seq(&[
        tbs,
        alg.alg_id(),
        bits(&sig),
        explicit(0, &seq(&[responder_cert.to_vec()])),
    ]);
    Ok(seq(&[
        enumerated(0),
        explicit(0, &seq(&[oid("1.3.6.1.5.5.7.48.1.1"), octet(&basic)])),
    ]))
}
