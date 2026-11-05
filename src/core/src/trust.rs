//! Trust features: RFC 3161 timestamps of the audit chain and digital signatures on PDF reports.
//!
//! Timestamp: the head of the audit chain (the last entry_hash, itself a SHA-256) is sent to a
//! time-stamping authority. The token proves the log — and every evidence hash, finding and report
//! digest recorded before it — existed at that time. Stored next to the log:
//!   timestamp-<seq>.tsr   DER response (verify: openssl ts -verify -digest <head> -in … -CAfile …)
//!   timestamp-<seq>.json  tsa, gen_time, covers_seq, head, token_sha256
//! Offline: the run completes, `timestamp_pending` is logged, `<tool> timestamp <log-dir>` adds it later.
//!
//! `verify-log` re-checks each token: imprint, nonce-free status, and the CMS signature of the TSA (signer
//! certificate in the token, ESS signing-certificate binding, message digest over TSTInfo, RSA signature,
//! timeStamping EKU); with a CA bundle (`--tsa-ca`) also the certificate chain at genTime. Revocation is not
//! checked.
//!
//! PDF signature: CMS detached signature (adbe.pkcs7.detached) with the examiner's .p12/.pfx (RSA keys).
//! The password is never logged.

use crate::hash::{HashAlgo, hash_bytes};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder, create_signing_time_attribute};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::{Int, OctetString};
use der::{Any, Decode, Encode};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use serde_json::{Value, json};
use sha2_legacy::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use std::collections::BTreeMap;
use std::path::Path;
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion};

pub const DEFAULT_TSA: &str = "http://timestamp.digicert.com";

#[derive(Clone, Debug, PartialEq)]
pub struct Timestamp {
    pub tsa: String,
    pub gen_time: String,
    pub covers_seq: u64,
    pub head: String,
    pub token_sha256: String,
    pub file: String,
}

impl Timestamp {
    pub fn to_json(&self) -> Value {
        json!({"tsa": self.tsa, "gen_time": self.gen_time, "covers_seq": self.covers_seq, "head": self.head,
               "token_sha256": self.token_sha256, "file": self.file})
    }
}

fn sha256_alg() -> spki::AlgorithmIdentifier<Any> {
    spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: Some(Any::null()),
    }
}

fn nonce() -> Vec<u8> {
    let seed = format!("{:?}-{}", std::time::SystemTime::now(), std::process::id());
    let mut n = crate::hash::hex_decode(&hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..16])
        .unwrap_or_default();
    n[0] &= 0x7f; // positive INTEGER
    n
}

pub fn build_request(digest: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: sha256_alg(),
            hashed_message: OctetString::new(digest).map_err(|e| e.to_string())?,
        },
        req_policy: None,
        nonce: Some(Int::new(nonce).map_err(|e| e.to_string())?),
        cert_req: true,
        extensions: None,
    };
    req.to_der().map_err(|e| e.to_string())
}

/// Checks a TSA response; returns gen_time (UTC, ISO 8601).
pub fn parse_response(der: &[u8], digest: &[u8], nonce: Option<&[u8]>) -> Result<String, String> {
    let resp =
        TimeStampResp::from_der(der).map_err(|e| format!("not a time-stamp response: {}", e))?;
    let status = format!("{:?}", resp.status.status);
    if !(status == "Accepted" || status == "GrantedWithMods") {
        return Err(format!("TSA refused the request: {}", status));
    }
    let token = resp.time_stamp_token.ok_or("TSA response has no token")?;
    let sd: SignedData = token
        .content
        .decode_as()
        .map_err(|e| format!("bad token: {}", e))?;
    let econtent = sd
        .encap_content_info
        .econtent
        .ok_or("token without TSTInfo")?;
    let octets: OctetString = econtent
        .decode_as()
        .map_err(|e| format!("bad TSTInfo: {}", e))?;
    let info = parse_tst_info(octets.as_bytes())?;
    if info.imprint != digest {
        return Err("the token does not cover the requested digest".into());
    }
    if let (Some(want), Some(got)) = (nonce, info.nonce.as_ref()) {
        let want = Int::new(want).map_err(|e| e.to_string())?;
        if got.as_slice() != want.as_bytes() {
            return Err("nonce mismatch (possible replay)".into());
        }
    }
    Ok(info.gen_time)
}

struct TstFields {
    imprint: Vec<u8>,
    gen_time: String,
    nonce: Option<Vec<u8>>,
}

/// Minimal DER walk over TSTInfo. Done by hand on purpose: many TSAs put fractional seconds in
/// genTime ("20261020182422.123Z"), which strict GeneralizedTime decoders reject.
/// One DER TLV at `pos` (definite length, at most 4 length bytes): (tag, content start, content end).
fn der_tlv(b: &[u8], pos: usize) -> Result<(u8, usize, usize), String> {
    let bad = || "bad DER encoding".to_string();
    let tag = *b.get(pos).ok_or_else(bad)?;
    let first = *b.get(pos + 1).ok_or_else(bad)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return Err(bad());
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *b.get(pos + 2 + i).ok_or_else(bad)? as usize;
        }
        (l, 2 + n)
    };
    let start = pos + hdr;
    if start.checked_add(len).is_none_or(|e| e > b.len()) {
        return Err(bad());
    }
    Ok((tag, start, start + len))
}

fn parse_tst_info(der: &[u8]) -> Result<TstFields, String> {
    let tlv = der_tlv;
    let (tag, start, end) = tlv(der, 0)?;
    if tag != 0x30 {
        return Err("TSTInfo is not a SEQUENCE".into());
    }
    let mut fields = Vec::new();
    let mut pos = start;
    while pos < end {
        let (t, s, e) = tlv(der, pos)?;
        fields.push((t, s, e));
        pos = e;
    }
    let (t, s, e) = *fields.get(2).ok_or("TSTInfo too short")?;
    if t != 0x30 {
        return Err("bad messageImprint".into());
    }
    let (_, _, alg_end) = tlv(der, s)?;
    let (ot, os, oe) = tlv(der, alg_end)?;
    if ot != 0x04 || oe > e {
        return Err("bad messageImprint".into());
    }
    let imprint = der[os..oe].to_vec();
    let (gt, gs, ge) = *fields.get(4).ok_or("TSTInfo without genTime")?;
    if gt != 0x18 {
        return Err("bad genTime".into());
    }
    let raw = std::str::from_utf8(&der[gs..ge]).map_err(|_| "bad genTime")?;
    if raw.len() < 14 || !raw[..14].chars().all(|c| c.is_ascii_digit()) {
        return Err("bad genTime".into());
    }
    let gen_time = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &raw[0..4],
        &raw[4..6],
        &raw[6..8],
        &raw[8..10],
        &raw[10..12],
        &raw[12..14]
    );
    let nonce = fields
        .iter()
        .skip(5)
        .find(|(t, _, _)| *t == 0x02)
        .map(|(_, s, e)| der[*s..*e].to_vec());
    Ok(TstFields {
        imprint,
        gen_time,
        nonce,
    })
}

pub fn request_timestamp(digest: &[u8], url: &str) -> Result<(String, Vec<u8>), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("unsupported TSA URL scheme: {}", url));
    }
    let n = nonce();
    let body = build_request(digest, &n)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .send(&body[..])
        .map_err(|e| format!("cannot reach {}: {}", url, e))?;
    let der = resp
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()
        .map_err(|e| format!("cannot read TSA response: {}", e))?;
    let gen_time = parse_response(&der, digest, Some(&n))?;
    Ok((gen_time, der))
}

pub fn timestamp_head(
    log_dir: &Path,
    seq: u64,
    head: &str,
    url: &str,
) -> Result<Timestamp, String> {
    let digest = crate::hash::hex_decode(head).ok_or("bad chain head")?;
    let (gen_time, der) = request_timestamp(&digest, url)?;
    let file = format!("timestamp-{:05}.tsr", seq);
    std::fs::write(log_dir.join(&file), &der).map_err(|e| e.to_string())?;
    let ts = Timestamp {
        tsa: url.into(),
        gen_time,
        covers_seq: seq,
        head: head.into(),
        token_sha256: hash_bytes(&der, HashAlgo::Sha256),
        file,
    };
    let mut text = serde_json::to_string_pretty(&ts.to_json()).expect("json");
    text.push('\n');
    std::fs::write(log_dir.join(format!("timestamp-{:05}.json", seq)), text)
        .map_err(|e| e.to_string())?;
    Ok(ts)
}

/// Checks every timestamp-*.json/.tsr pair against the chain heads (seq -> entry_hash), including the TSA's
/// CMS signature (no trust anchors: the chain is not validated). Returns the problems only.
pub fn verify_timestamps(log_dir: &Path, heads: &BTreeMap<u64, String>) -> Vec<String> {
    verify_timestamps_with(log_dir, heads, None).problems
}

/// Outcome of `verify_timestamps_with`: problems (any → the log does not verify) and one line per token.
#[derive(Debug, Default)]
pub struct TimestampVerification {
    pub problems: Vec<String>,
    pub tokens: Vec<String>,
}

/// Like [`verify_timestamps`], and with `anchors` (a CA bundle, `--tsa-ca`) also validates the TSA
/// certificate chain up to one of them at the token's genTime.
pub fn verify_timestamps_with(
    log_dir: &Path,
    heads: &BTreeMap<u64, String>,
    anchors: Option<&[Certificate]>,
) -> TimestampVerification {
    let mut out = TimestampVerification::default();
    let mut metas: Vec<_> = std::fs::read_dir(log_dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("timestamp-") && n.ends_with(".json"))
                })
                .collect()
        })
        .unwrap_or_default();
    metas.sort();
    for m in metas {
        let meta: Value = match std::fs::read_to_string(&m)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
        {
            Some(v) => v,
            None => {
                out.problems.push(format!("{}: unreadable", m.display()));
                continue;
            }
        };
        let file = meta["file"].as_str().unwrap_or_default();
        let seq = meta["covers_seq"].as_u64().unwrap_or(0);
        let Some(head) = heads.get(&seq).and_then(|h| crate::hash::hex_decode(h)) else {
            out.problems.push(format!(
                "truncated: {} covers entry #{}, which is not in the log (entries removed from the end)",
                file, seq
            ));
            continue;
        };
        let der = std::fs::read(log_dir.join(file)).unwrap_or_default();
        if hash_bytes(&der, HashAlgo::Sha256) != meta["token_sha256"].as_str().unwrap_or_default() {
            out.problems
                .push(format!("{}: token file missing or altered", file));
            continue;
        }
        match verify_token(&der, &head, anchors) {
            Ok(c) => out.tokens.push(format!(
                "timestamp {} by {} covers entry #{}: {}",
                c.gen_time,
                meta["tsa"].as_str().unwrap_or("?"),
                seq,
                c.describe()
            )),
            Err(e) => out
                .problems
                .push(format!("{}: {} (entry #{})", file, e, seq)),
        }
    }
    out
}

// ---------------------------------------------------------------- TSA token signature (RFC 3161 / RFC 5652)

const OID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_ATTR_SIGNING_CERT: &str = "1.2.840.113549.1.9.16.2.12";
const OID_ATTR_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
const OID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const OID_EXT_EKU: &str = "2.5.29.37";
const OID_EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_EXT_SKI: &str = "2.5.29.14";
const OID_SHA1: &str = "1.3.14.3.2.26";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";

fn oid(s: &str) -> const_oid::ObjectIdentifier {
    const_oid::ObjectIdentifier::new_unwrap(s)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Md {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

fn md_of(o: &const_oid::ObjectIdentifier) -> Option<Md> {
    match o.to_string().as_str() {
        OID_SHA1 => Some(Md::Sha1),
        OID_SHA256 => Some(Md::Sha256),
        OID_SHA384 => Some(Md::Sha384),
        OID_SHA512 => Some(Md::Sha512),
        _ => None,
    }
}

fn md_digest(md: Md, data: &[u8]) -> Vec<u8> {
    use sha2_legacy::{Sha384, Sha512};
    match md {
        Md::Sha1 => crate::hash::hex_decode(&hash_bytes(data, HashAlgo::Sha1)).unwrap_or_default(),
        Md::Sha256 => Sha256::digest(data).to_vec(),
        Md::Sha384 => Sha384::digest(data).to_vec(),
        Md::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// RSA PKCS#1 v1.5 verification of `sig` over `data` hashed with `md`.
fn rsa_verify(
    spki: &spki::SubjectPublicKeyInfoOwned,
    md: Md,
    data: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    use rsa::pkcs8::DecodePublicKey;
    let spki_der = spki.to_der().map_err(|e| e.to_string())?;
    let key = rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(|_| {
        "the signer key is not RSA (not supported: signature not checked)".to_string()
    })?;
    let scheme = match md {
        Md::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
        Md::Sha384 => rsa::Pkcs1v15Sign::new::<sha2_legacy::Sha384>(),
        Md::Sha512 => rsa::Pkcs1v15Sign::new::<sha2_legacy::Sha512>(),
        Md::Sha1 => return Err("SHA-1 signatures are not supported (signature not checked)".into()),
    };
    key.verify(scheme, &md_digest(md, data), sig)
        .map_err(|_| "signature value does not verify".to_string())
}

/// Hash used by a signature algorithm: `rsaEncryption` takes the SignerInfo digest algorithm.
fn sig_md(alg: &const_oid::ObjectIdentifier, digest_md: Option<Md>) -> Result<Md, String> {
    match alg.to_string().as_str() {
        OID_RSA => digest_md.ok_or_else(|| "unsupported digest algorithm".to_string()),
        OID_RSA_SHA256 => Ok(Md::Sha256),
        OID_RSA_SHA384 => Ok(Md::Sha384),
        OID_RSA_SHA512 => Ok(Md::Sha512),
        other => Err(format!(
            "signature algorithm {} not supported (signature not checked)",
            other
        )),
    }
}

/// Children of a DER constructed value: (tag, content).
fn der_children(mut b: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (tag, s, e) = der_tlv(b, 0)?;
        out.push((tag, &b[s..e]));
        b = &b[e..];
    }
    Ok(out)
}

fn ext<'c>(cert: &'c Certificate, id: &str) -> Option<&'c x509_cert::ext::Extension> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid(id))
}

fn subject(cert: &Certificate) -> String {
    cert.tbs_certificate.subject.to_string()
}

/// What `verify_token` established about one token.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenCheck {
    pub gen_time: String,
    pub tsa_subject: String,
    /// Subject of the trust anchor the TSA certificate chains to; None = chain not validated.
    pub anchor: Option<String>,
}

impl TokenCheck {
    pub fn describe(&self) -> String {
        match &self.anchor {
            Some(a) => format!(
                "TSA signature valid (signer: {}); chain validated to {} (revocation not checked)",
                self.tsa_subject, a
            ),
            None => format!(
                "TSA signature valid (signer: {}); chain not checked (pass --tsa-ca <CA bundle> to validate it)",
                self.tsa_subject
            ),
        }
    }
}

/// Full check of a stored TSA response: status, message imprint = `digest`, then the CMS SignedData of the
/// token — eContentType id-ct-TSTInfo, one SignerInfo whose certificate is in the token, signed attributes
/// with content-type, message-digest over the TSTInfo, ESS signing-certificate (v1 or v2) binding that
/// certificate, the signature value (RSA PKCS#1 v1.5) and the timeStamping extended key usage. With
/// `anchors`, the certificate chain is also validated at genTime (signatures, validity, CA flag); revocation
/// is never checked.
pub fn verify_token(
    der: &[u8],
    digest: &[u8],
    anchors: Option<&[Certificate]>,
) -> Result<TokenCheck, String> {
    let gen_time = parse_response(der, digest, None)?;
    let resp =
        TimeStampResp::from_der(der).map_err(|e| format!("not a time-stamp response: {}", e))?;
    let token = resp.time_stamp_token.ok_or("TSA response has no token")?;
    let sd: SignedData = token
        .content
        .decode_as()
        .map_err(|e| format!("bad token: {}", e))?;
    if sd.encap_content_info.econtent_type != oid(OID_CT_TSTINFO) {
        return Err("token content is not a TSTInfo".into());
    }
    let tst: OctetString = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("token without TSTInfo")?
        .decode_as()
        .map_err(|e| format!("bad TSTInfo: {}", e))?;
    let tst = tst.as_bytes();
    let si = match sd.signer_infos.0.as_slice() {
        [one] => one,
        [] => return Err("token has no SignerInfo".into()),
        _ => return Err("token has more than one SignerInfo".into()),
    };
    let certs: Vec<Certificate> = sd
        .certificates
        .as_ref()
        .map(|cs| {
            cs.0.iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let signer = certs
        .iter()
        .find(|c| match &si.sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => ext(c, OID_EXT_SKI)
                .and_then(|e| OctetString::from_der(e.extn_value.as_bytes()).ok())
                .is_some_and(|v| v.as_bytes() == ski.0.as_bytes()),
        })
        .ok_or("the TSA certificate is not in the token (signature not checked)")?;
    let tsa_subject = subject(signer);
    let digest_md = md_of(&si.digest_alg.oid);
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or("token SignerInfo has no signed attributes")?;
    let attr = |id: &str| {
        attrs
            .iter()
            .find(|a| a.oid == oid(id))
            .and_then(|a| a.values.iter().next())
    };
    // content-type
    let ct = attr(OID_ATTR_CONTENT_TYPE).ok_or("signed attributes lack content-type")?;
    let ct: const_oid::ObjectIdentifier = ct
        .decode_as()
        .map_err(|e| format!("bad content-type: {}", e))?;
    if ct != oid(OID_CT_TSTINFO) {
        return Err("signed content-type is not id-ct-TSTInfo".into());
    }
    // message-digest over the TSTInfo
    let md =
        digest_md.ok_or_else(|| format!("digest algorithm {} not supported", si.digest_alg.oid))?;
    let want: OctetString = attr(OID_ATTR_MESSAGE_DIGEST)
        .ok_or("signed attributes lack message-digest")?
        .decode_as()
        .map_err(|e| format!("bad message-digest: {}", e))?;
    if want.as_bytes() != md_digest(md, tst).as_slice() {
        return Err("message-digest does not match the TSTInfo (token altered)".into());
    }
    // ESS signing-certificate (v2 preferred, else v1) binds the TSA certificate.
    let cert_der = signer.to_der().map_err(|e| e.to_string())?;
    let (ess, v2) = match (attr(OID_ATTR_SIGNING_CERT_V2), attr(OID_ATTR_SIGNING_CERT)) {
        (Some(a), _) => (a, true),
        (None, Some(a)) => (a, false),
        (None, None) => {
            return Err(
                "signed attributes lack the ESS signing-certificate (RFC 5816/2634)".into(),
            );
        }
    };
    let ess = ess.to_der().map_err(|e| e.to_string())?;
    let (_, s, e) = der_tlv(&ess, 0)?;
    let seq = der_children(&ess[s..e])?;
    let (_, ids) = seq.first().ok_or("empty ESS signing-certificate")?;
    let (_, first) = *der_children(ids)?
        .first()
        .ok_or("ESS signing-certificate lists no certificate")?;
    let fields = der_children(first)?;
    let (hash_md, hash) = if v2 {
        match fields.as_slice() {
            [(0x30, alg), (0x04, h), ..] => {
                let (_, os, oe) = der_tlv(alg, 0)?;
                let o = const_oid::ObjectIdentifier::from_bytes(&alg[os..oe])
                    .map_err(|e| format!("bad ESSCertIDv2 algorithm: {}", e))?;
                (
                    md_of(&o).ok_or("ESSCertIDv2 hash algorithm not supported")?,
                    *h,
                )
            }
            [(0x04, h), ..] => (Md::Sha256, *h),
            _ => return Err("bad ESSCertIDv2".into()),
        }
    } else {
        match fields.as_slice() {
            [(0x04, h), ..] => (Md::Sha1, *h),
            _ => return Err("bad ESSCertID".into()),
        }
    };
    if hash != md_digest(hash_md, &cert_der).as_slice() {
        return Err(
            "ESS signing-certificate does not match the TSA certificate in the token".into(),
        );
    }
    // Signature over the DER of the signed attributes (SET OF).
    let signed = attrs.to_der().map_err(|e| e.to_string())?;
    let smd = sig_md(&si.signature_algorithm.oid, digest_md)?;
    rsa_verify(
        &signer.tbs_certificate.subject_public_key_info,
        smd,
        &signed,
        si.signature.as_bytes(),
    )
    .map_err(|e| format!("TSA {}", e))?;
    // RFC 3161 §2.3: the TSA certificate has extendedKeyUsage id-kp-timeStamping.
    let eku_ok = ext(signer, OID_EXT_EKU)
        .and_then(|e| {
            x509_cert::ext::pkix::ExtendedKeyUsage::from_der(e.extn_value.as_bytes()).ok()
        })
        .is_some_and(|eku| eku.0.contains(&oid(OID_KP_TIME_STAMPING)));
    if !eku_ok {
        return Err("the TSA certificate lacks the timeStamping extended key usage".into());
    }
    let anchor = match anchors {
        None => None,
        Some(a) => Some(validate_chain(signer, &certs, a, &gen_time)?),
    };
    Ok(TokenCheck {
        gen_time,
        tsa_subject,
        anchor,
    })
}

fn unix_of(gen_time: &str) -> Result<u64, String> {
    chrono::DateTime::parse_from_rfc3339(gen_time)
        .map(|d| d.timestamp().max(0) as u64)
        .map_err(|e| format!("bad genTime {}: {}", gen_time, e))
}

fn check_validity(c: &Certificate, at: u64) -> Result<(), String> {
    let v = &c.tbs_certificate.validity;
    let (nb, na) = (
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    );
    if at < nb || at > na {
        return Err(format!(
            "certificate {} was not valid at the token's genTime",
            subject(c)
        ));
    }
    Ok(())
}

/// Verifies that `issuer` signed `cert`.
fn signed_by(cert: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = cert.tbs_certificate.to_der() else {
        return false;
    };
    let Ok(md) = sig_md(&cert.signature_algorithm.oid, None) else {
        return false;
    };
    let Some(sig) = cert.signature.as_bytes() else {
        return false;
    };
    rsa_verify(
        &issuer.tbs_certificate.subject_public_key_info,
        md,
        &tbs,
        sig,
    )
    .is_ok()
}

fn is_ca(c: &Certificate) -> bool {
    ext(c, OID_EXT_BASIC_CONSTRAINTS)
        .and_then(|e| {
            x509_cert::ext::pkix::BasicConstraints::from_der(e.extn_value.as_bytes()).ok()
        })
        .is_some_and(|b| b.ca)
}

/// Builds and checks a path from the TSA certificate to one of `anchors`: each signature (RSA), validity at
/// genTime, and the CA flag of every issuer. Returns the anchor's subject.
fn validate_chain(
    leaf: &Certificate,
    token_certs: &[Certificate],
    anchors: &[Certificate],
    gen_time: &str,
) -> Result<String, String> {
    let at = unix_of(gen_time)?;
    let anchor_ders: Vec<Vec<u8>> = anchors.iter().filter_map(|a| a.to_der().ok()).collect();
    let mut cur = leaf.clone();
    for _ in 0..8 {
        check_validity(&cur, at)?;
        let cur_der = cur.to_der().map_err(|e| e.to_string())?;
        if anchor_ders.contains(&cur_der) {
            return Ok(subject(&cur));
        }
        if let Some(a) = anchors
            .iter()
            .find(|a| a.tbs_certificate.subject == cur.tbs_certificate.issuer && signed_by(&cur, a))
        {
            check_validity(a, at)?;
            return Ok(subject(a));
        }
        let next = token_certs
            .iter()
            .find(|c| {
                c.tbs_certificate.subject == cur.tbs_certificate.issuer
                    && c.tbs_certificate.subject != cur.tbs_certificate.subject
                    && is_ca(c)
                    && signed_by(&cur, c)
            })
            .cloned();
        match next {
            Some(n) => cur = n,
            None => {
                return Err(format!(
                    "TSA certificate chain not validated: no trusted issuer for {} in the CA bundle",
                    subject(&cur)
                ));
            }
        }
    }
    Err("TSA certificate chain too long".into())
}

/// Reads a CA bundle for `--tsa-ca`: PEM (one or more certificates) or a single DER certificate.
pub fn load_ca_bundle(path: &Path) -> Result<Vec<Certificate>, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let certs = if data.starts_with(b"-----") || data.windows(11).any(|w| w == b"-----BEGIN ") {
        Certificate::load_pem_chain(&data)
            .map_err(|e| format!("{}: bad PEM: {}", path.display(), e))?
    } else {
        vec![
            Certificate::from_der(&data)
                .map_err(|e| format!("{}: bad DER certificate: {}", path.display(), e))?,
        ]
    };
    if certs.is_empty() {
        return Err(format!("{}: no certificate", path.display()));
    }
    Ok(certs)
}

// ---------------------------------------------------------------- PDF signatures

pub struct PdfSigner {
    key: SigningKey<Sha256>,
    certs: Vec<Certificate>,
    pub subject: String,
    pub fingerprint_sha256: String,
}

impl PdfSigner {
    pub fn load(path: &Path, password: &str) -> Result<PdfSigner, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("cannot read signing certificate {}: {}", path.display(), e))?;
        let ks = p12_keystore::KeyStore::from_pkcs12(
            &data,
            password,
            p12_keystore::Pkcs12ImportPolicy::Relaxed,
        )
        .map_err(|e| {
            format!(
                "cannot load signing certificate {}: wrong password or unsupported file ({})",
                path.display(),
                e
            )
        })?;
        let (_, chain) = ks
            .private_key_chain()
            .ok_or("the certificate file contains no private key")?;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(chain.key().as_der())
            .map_err(|_| "only RSA signing certificates are supported".to_string())?;
        let certs = chain
            .certs()
            .iter()
            .map(|c| Certificate::from_der(c.as_der()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let first = chain.certs().first().ok_or("no certificate in the file")?;
        Ok(PdfSigner {
            key: SigningKey::<Sha256>::new(key),
            certs,
            subject: first.subject().to_string(),
            fingerprint_sha256: hash_bytes(first.as_der(), HashAlgo::Sha256),
        })
    }

    /// CMS SignedData (detached) over `content`, DER-encoded.
    pub fn sign_detached(&self, content: &[u8]) -> Result<Vec<u8>, String> {
        let digest = Sha256::digest(content);
        let cert = &self.certs[0];
        let eci = EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        };
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });
        let dalg = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };
        fn err<E: std::fmt::Debug>(e: E) -> String {
            format!("{:?}", e)
        }
        let mut sib = SignerInfoBuilder::new(&self.key, sid, dalg.clone(), &eci, Some(&digest))
            .map_err(err)?;
        sib.add_signed_attribute(create_signing_time_attribute().map_err(err)?)
            .map_err(err)?;
        let mut b = SignedDataBuilder::new(&eci);
        b.add_digest_algorithm(dalg).map_err(err)?;
        for c in &self.certs {
            b.add_certificate(CertificateChoices::Certificate(c.clone()))
                .map_err(err)?;
        }
        b.add_signer_info::<_, Signature>(sib).map_err(err)?;
        b.build().map_err(err)?.to_der().map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_valid_der_and_bad_responses_are_rejected() {
        let req = build_request(&[7u8; 32], &[1, 2, 3]).unwrap();
        assert_eq!(req[0], 0x30);
        assert!(TimeStampReq::from_der(&req).is_ok());
        assert!(parse_response(b"garbage", &[0u8; 32], None).is_err());
        assert!(request_timestamp(&[0u8; 32], "file:///etc/passwd").is_err());
        assert!(request_timestamp(&[0u8; 32], "http://127.0.0.1:9/tsr").is_err());
    }

    #[test]
    fn token_and_ca_bundle_inputs_are_checked() {
        assert!(verify_token(b"garbage", &[0u8; 32], None).is_err());
        // Truncated or oversized DER lengths are rejected, not read past the end.
        assert!(der_tlv(&[0x30, 0x05, 0x01], 0).is_err());
        assert!(der_tlv(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], 0).is_err());
        assert_eq!(der_tlv(&[0x04, 0x01, 0xaa], 0), Ok((0x04, 2, 3)));
        let dir = tempfile::tempdir().unwrap();
        assert!(load_ca_bundle(&dir.path().join("missing.pem")).is_err());
        std::fs::write(dir.path().join("empty.pem"), b"-----BEGIN NOTHING-----\n").unwrap();
        assert!(load_ca_bundle(&dir.path().join("empty.pem")).is_err());
        assert_eq!(md_of(&oid(OID_SHA256)), Some(Md::Sha256));
        assert!(sig_md(&oid("1.2.840.10045.4.3.2"), Some(Md::Sha256)).is_err());
    }
}
