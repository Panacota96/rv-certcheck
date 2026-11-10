//! OWNER: A. RFC 3161 token verification (CMS via OpenSSL, TSTInfo by a lenient DER walk).
//!
//! TSTInfo is read with the same lenient approach as the template's parser in `rv-certcheck-core::trust`
//! (`parse_tst_info`: a bounds-checked DER walk, genTime accepted with fractional seconds, which strict
//! GeneralizedTime decoders such as x509-tsp's reject). That parser is private to core and core depends on this
//! crate, so it cannot be called from here; this one covers the same fields plus policy, serial, accuracy,
//! ordering, nonce and TSA name, and core can switch to it.
//!
//! Verification steps, each reported separately:
//! 1. TimeStampResp status is granted / grantedWithMods (a bare token has none);
//! 2. the CMS SignedData signature over TSTInfo verifies (`PKCS7_verify`, chain not checked here);
//! 3. the ESS signing-certificate(-v2) attribute names the signer certificate (hash compared);
//! 4. the TSA certificate's chain is valid at genTime for the purpose timestamping (OpenSSL's
//!    X509_PURPOSE_TIMESTAMP_SIGN: critical EKU timeStamping only), via [`super::chain::validate_chain`];
//! 5. genTime is inside the TSA certificate's validity period;
//! 6. with data (or a caller's [`ImprintCheck`] against a paired evidence file): its digest equals the message
//!    imprint. Without it the token is valid but not linked to any file (`imprint_checked=no`).
use super::parse::cert_info;
use super::util::*;
use crate::model::*;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;

const OID_ESS_SIGNING_CERT: &str = "1.2.840.113549.1.9.16.2.12";
const OID_ESS_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA1: &str = "1.3.14.3.2.26";

fn pki_status(n: i64) -> String {
    match n {
        0 => "granted",
        1 => "grantedWithMods",
        2 => "rejection",
        3 => "waiting",
        4 => "revocationWarning",
        5 => "revocationNotification",
        _ => return format!("status-{n}"),
    }
    .into()
}

/// What the SignerInfo says about its signer and its ESS attribute.
#[derive(Default)]
struct SignerFacts {
    /// (issuer as text, serial hex) or SKI hex.
    issuer_serial: Option<(String, String)>,
    ski_hex: Option<String>,
    /// (hash algorithm OID, hash) from signingCertificate(V2).
    ess: Option<(String, Vec<u8>)>,
}

fn signer_facts(token: &[u8]) -> (Vec<Vec<u8>>, SignerFacts) {
    use der::{Decode, Encode};
    let mut certs = vec![];
    let mut f = SignerFacts::default();
    let Some(sd) = cms::content_info::ContentInfo::from_der(token)
        .ok()
        .and_then(|ci| ci.content.decode_as::<cms::signed_data::SignedData>().ok())
    else {
        return (certs, f);
    };
    for c in sd.certificates.iter().flat_map(|s| s.0.iter()) {
        if let cms::cert::CertificateChoices::Certificate(c) = c
            && let Ok(d) = c.to_der()
        {
            certs.push(d);
        }
    }
    let Some(si) = sd.signer_infos.0.iter().next() else {
        return (certs, f);
    };
    match &si.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(is) => {
            let issuer = is
                .issuer
                .to_der()
                .map(|d| name_der_string(&d))
                .unwrap_or_default();
            f.issuer_serial = Some((issuer, int_hex(is.serial_number.as_bytes())));
        }
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(k) => {
            f.ski_hex = Some(hex(k.0.as_bytes()));
        }
    }
    for attr in si.signed_attrs.iter().flat_map(|a| a.iter()) {
        let oid = attr.oid.to_string();
        let v2 = oid == OID_ESS_SIGNING_CERT_V2;
        if !(v2 || oid == OID_ESS_SIGNING_CERT) {
            continue;
        }
        let Some(val) = attr.values.iter().next().and_then(|v| v.to_der().ok()) else {
            continue;
        };
        // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }
        // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256, certHash OCTET STRING, ... }
        // ESSCertID   ::= SEQUENCE { certHash OCTET STRING (SHA-1), issuerSerial OPTIONAL }
        let parsed = (|| {
            let (outer, _) = tlv(&val)?;
            let (list, _) = tlv(outer.content)?;
            let (first, _) = tlv(list.content)?;
            let fields = children(first.content);
            let mut alg = if v2 {
                OID_SHA256.to_string()
            } else {
                OID_SHA1.to_string()
            };
            let mut i = 0;
            if fields.first()?.tag == 0x30 {
                let (o, _) = tlv(fields[0].content)?;
                alg = oid_text(o.content)?;
                i = 1;
            }
            let h = fields.get(i)?;
            (h.tag == 0x04).then(|| (alg, h.content.to_vec()))
        })();
        if parsed.is_some() {
            f.ess = parsed;
            break;
        }
    }
    (certs, f)
}

/// Index of the signer among `certs`.
fn signer_index(certs: &[CertInfo], f: &SignerFacts) -> Option<usize> {
    certs.iter().position(|c| {
        f.issuer_serial
            .as_ref()
            .is_some_and(|(i, s)| &c.issuer == i && &c.serial_hex == s)
            || f.ski_hex
                .as_ref()
                .is_some_and(|k| c.ski_hex.as_ref() == Some(k))
    })
}

/// Parses a TimeStampResp or a bare TimeStampToken. Returns the facts and the token (ContentInfo) bytes.
pub(crate) fn parse_token(der: &[u8]) -> CertResult<(TimestampInfo, Option<Vec<u8>>)> {
    let mut info = TimestampInfo {
        sha256: sha256_hex(der),
        ..Default::default()
    };
    let token: Option<&[u8]> = if let Some((status, tok)) = tsr_parts(der) {
        info.response_status = Some(pki_status(status));
        tok
    } else if signed_data_econtent_type(der).as_deref() == Some(OID_TST_INFO) {
        Some(tlv(der).map(|(t, _)| t.raw).unwrap_or(der))
    } else {
        return Err(parse_err(
            "timestamp",
            "neither a TimeStampResp nor a TimeStampToken",
        ));
    };
    let Some(token) = token else {
        return Ok((info, None));
    };
    let tst = signed_data_econtent(token).ok_or_else(|| parse_err("timestamp", "no TSTInfo"))?;
    fill_tst_info(tst, &mut info)?;
    let (cert_ders, facts) = signer_facts(token);
    let mut certs = vec![];
    for d in cert_ders {
        certs.push(cert_info(&d)?);
    }
    if let Some(i) = signer_index(&certs, &facts) {
        let s = certs.remove(i);
        certs.insert(0, s);
    }
    info.certificates = certs;
    Ok((info, Some(token.to_vec())))
}

fn fill_tst_info(der: &[u8], info: &mut TimestampInfo) -> CertResult<()> {
    let bad = |w: &str| parse_err("TSTInfo", w);
    let (seq, _) = tlv(der).ok_or_else(|| bad("not DER"))?;
    if seq.tag != 0x30 {
        return Err(bad("not a SEQUENCE"));
    }
    let f = children(seq.content);
    if f.len() < 5 {
        return Err(bad("too short"));
    }
    if f[1].tag != 0x06 {
        return Err(bad("bad policy"));
    }
    info.policy_oid = oid_text(f[1].content).ok_or_else(|| bad("bad policy"))?;
    if f[2].tag != 0x30 {
        return Err(bad("bad messageImprint"));
    }
    let mi = children(f[2].content);
    let alg = mi
        .first()
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| bad("bad messageImprint"))?;
    let (alg_oid, _) = tlv(alg.content).ok_or_else(|| bad("bad hash algorithm"))?;
    let hash_oid = oid_text(alg_oid.content).ok_or_else(|| bad("bad hash algorithm"))?;
    info.hash_algorithm = oid_long_name(&hash_oid).to_ascii_lowercase();
    let imprint = mi
        .get(1)
        .filter(|t| t.tag == 0x04)
        .ok_or_else(|| bad("bad imprint"))?;
    info.message_imprint_hex = hex(imprint.content);
    if f[3].tag != 0x02 {
        return Err(bad("bad serialNumber"));
    }
    info.serial_hex = int_hex(f[3].content);
    if f[4].tag != 0x18 {
        return Err(bad("bad genTime"));
    }
    info.gen_time = generalized_time(f[4].content).ok_or_else(|| bad("bad genTime"))?;
    for t in &f[5..] {
        match t.tag {
            0x30 => {
                let mut parts = vec![];
                for a in children(t.content) {
                    let n = a
                        .content
                        .iter()
                        .take(8)
                        .fold(0u64, |x, &b| (x << 8) | b as u64);
                    match a.tag {
                        0x02 => parts.push(format!("{n}s")),
                        0x80 => parts.push(format!("{n}ms")),
                        0x81 => parts.push(format!("{n}us")),
                        _ => {}
                    }
                }
                info.accuracy = Some(parts.join(" "));
            }
            0x01 => info.ordering = t.content.first().is_some_and(|b| *b != 0),
            0x02 => info.nonce_hex = Some(int_hex(t.content)),
            0xa0 => {
                info.tsa_name = tlv(t.content).map(|(g, _)| match g.tag {
                    0xa4 => format!("DirName:{}", name_der_string(g.content)),
                    0x86 => format!("URI:{}", String::from_utf8_lossy(g.content)),
                    0x82 => format!("DNS:{}", String::from_utf8_lossy(g.content)),
                    0x81 => format!("email:{}", String::from_utf8_lossy(g.content)),
                    _ => format!("#{}", hex(g.raw)),
                })
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn verify_timestamp_token(
    token: &[u8],
    data: Option<&[u8]>,
    req: &ChainRequest,
    opts: &ValidationOptions,
) -> CertResult<TimestampVerdict> {
    let check = match data {
        Some(d) => {
            let (info, _) = parse_token(token)?;
            let md = openssl::hash::MessageDigest::from_name(&info.hash_algorithm);
            let matches = md
                .and_then(|md| openssl::hash::hash(md, d).ok())
                .is_some_and(|h| hex(&h) == info.message_imprint_hex);
            Some(ImprintCheck {
                file: "the data supplied".into(),
                matches,
            })
        }
        None => None,
    };
    verify_timestamp_token_checked(token, check.as_ref(), req, opts)
}

pub fn verify_timestamp_token_checked(
    token: &[u8],
    imprint: Option<&ImprintCheck>,
    req: &ChainRequest,
    opts: &ValidationOptions,
) -> CertResult<TimestampVerdict> {
    let (info, tok) = parse_token(token)?;
    let mut problems: Vec<String> = vec![];
    let mut v = TimestampVerdict {
        info: info.clone(),
        ..Default::default()
    };
    if let Some(s) = &info.response_status
        && s != "granted"
        && s != "grantedWithMods"
    {
        problems.push(format!("the TSA did not grant the request (status {s})"));
    }
    if let Some(tok) = &tok {
        // 2. CMS signature (signer found among the embedded and the run's certificates).
        let p7 = Pkcs7::from_der(tok).map_err(|e| parse_err("timestamp token", e))?;
        let mut extra = Stack::new().map_err(|e| crypto_err("stack", e))?;
        for d in req.untrusted_der {
            if let Ok(x) = X509::from_der(d) {
                let _ = extra.push(x);
            }
        }
        let store = X509StoreBuilder::new()
            .map_err(|e| crypto_err("store", e))?
            .build();
        let mut content = vec![];
        v.signature_valid = p7
            .verify(
                &extra,
                &store,
                None,
                Some(&mut content),
                Pkcs7Flags::NOVERIFY,
            )
            .is_ok();
        if !v.signature_valid {
            problems.push("the CMS signature over TSTInfo does not verify".into());
        } else if Some(&content[..]) != signed_data_econtent(tok) {
            v.signature_valid = false;
            problems.push("the signed content is not the token's TSTInfo".into());
        }
        // 3. ESS signing certificate.
        let (_, facts) = signer_facts(tok);
        let signer = info
            .certificates
            .first()
            .filter(|c| signer_index(std::slice::from_ref(*c), &facts) == Some(0));
        let signer: Option<CertInfo> = match signer {
            Some(c) => Some(c.clone()),
            None => {
                // Signer certificate not embedded: look among the run's certificates.
                let mut found = None;
                for d in req.untrusted_der {
                    if let Ok(c) = cert_info(d)
                        && signer_index(std::slice::from_ref(&c), &facts) == Some(0)
                    {
                        found = Some(c);
                        break;
                    }
                }
                found
            }
        };
        match (&signer, &facts.ess) {
            (None, _) => problems.push(
                "the TSA certificate is not in the token or among the material examined".into(),
            ),
            (Some(_), None) => {
                problems.push("the token has no ESS signing-certificate attribute".into())
            }
            (Some(c), Some((alg, h))) => {
                let md = openssl::asn1::Asn1Object::from_str(alg)
                    .ok()
                    .and_then(|o| openssl::hash::MessageDigest::from_nid(o.nid()));
                let ok = md
                    .and_then(|md| openssl::hash::hash(md, &c.der).ok())
                    .is_some_and(|d| d[..] == h[..]);
                if !ok {
                    problems.push("the ESS signing-certificate attribute does not name the signer certificate".into());
                }
            }
        }
        if let Some(c) = &signer {
            // 4. TSA chain at genTime, purpose timestamping.
            let mut untrusted: Vec<Vec<u8>> =
                info.certificates.iter().map(|c| c.der.clone()).collect();
            untrusted.extend(req.untrusted_der.iter().cloned());
            let creq = ChainRequest {
                target_der: &c.der,
                untrusted_der: &untrusted,
                anchors: req.anchors,
                crls: req.crls,
                ocsp: req.ocsp,
                signing_time: Some(info.gen_time.clone()),
            };
            let copts = ValidationOptions {
                at: AtTime::Fixed(info.gen_time.clone()),
                purpose: Purpose::Timestamping,
                ..opts.clone()
            };
            let chain = super::chain::validate_chain(&creq, &copts)?;
            if chain.status != ChainStatus::Valid {
                problems.push(format!(
                    "the TSA certificate chain is not valid at genTime {} for timestamping: {} (OpenSSL code {})",
                    info.gen_time,
                    chain
                        .errors
                        .iter()
                        .map(|e| format!("{} at depth {}", e.reason, e.depth))
                        .chain(
                            chain
                                .nodes
                                .iter()
                                .filter(|n| matches!(n.revocation, Some(RevocationStatus::Revoked { .. })))
                                .map(|n| format!("{} revoked", n.cert.subject))
                        )
                        .collect::<Vec<_>>()
                        .join("; "),
                    chain.openssl_code
                ));
            }
            // 5. genTime inside the TSA certificate's validity.
            let g = rfc3339_to_epoch(&info.gen_time)?;
            if g < rfc3339_to_epoch(&c.not_before)? || g > rfc3339_to_epoch(&c.not_after)? {
                problems.push(format!(
                    "genTime {} is outside the TSA certificate's validity ({} to {})",
                    info.gen_time, c.not_before, c.not_after
                ));
            }
            v.signer_chain = Some(chain);
        }
    } else {
        problems.push("the response holds no timestamp token".into());
    }
    // 6. Message imprint (compared by the caller with the paired file).
    if let Some(c) = imprint {
        v.imprint_matches = Some(c.matches);
        v.imprint_file = Some(c.file.clone());
        if !c.matches {
            problems.push(format!(
                "imprint does not match {} (its {} digest differs from the token's message imprint)",
                c.file, info.hash_algorithm
            ));
        }
    }
    let tsa = info
        .certificates
        .first()
        .map(|c| c.subject.clone())
        .or_else(|| info.tsa_name.clone())
        .unwrap_or_else(|| "an unidentified TSA".into());
    if problems.is_empty() {
        v.signals.push(
            Signal::of(codes::TIMESTAMP_TOKEN_VALID)
                .with("gen_time", &info.gen_time)
                .with("tsa", tsa)
                .with("policy", &info.policy_oid)
                .with("hash_algorithm", &info.hash_algorithm)
                .with(
                    "imprint_checked",
                    if imprint.is_some() { "yes" } else { "no" },
                )
                .with(
                    "imprint_file",
                    imprint
                        .map(|c| c.file.clone())
                        .unwrap_or_else(|| "none".into()),
                ),
        );
    } else {
        v.signals
            .push(Signal::of(codes::TIMESTAMP_TOKEN_INVALID).with("reason", problems.join("; ")));
    }
    if let Some(c) = &v.signer_chain {
        for s in &c.signals {
            if !v.signals.contains(s) {
                v.signals.push(s.clone());
            }
        }
    }
    Ok(v)
}
