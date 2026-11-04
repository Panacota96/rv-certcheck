//! OWNER: A. CRL and OCSP evaluation (offline; `--online` fetching lives in `online.rs`, audited by core).
//!
//! Rules, so the report can state exactly why a status was given:
//! - A CRL covers the certificate when its issuer name equals the certificate's issuer and its signature
//!   verifies with the issuer's public key (an issuer whose keyUsage lacks cRLSign is refused). Indirect CRLs,
//!   delta CRLs and delegated CRL signers are not supported in v0.1.
//! - An OCSP response covers it when it is `successful`, OpenSSL's `OCSP_basic_verify` accepts its signature
//!   (by the issuer itself or a responder the issuer delegated with id-kp-OCSPSigning; the responder's
//!   certificate is judged at producedAt) and it holds a SingleResponse for the certificate's CertID (SHA-1 or
//!   SHA-256).
//! - Revoked on or before the date checked → `Revoked`. Revoked after it → `Good` at that date, with a note.
//! - Not listed, information current at the date (thisUpdate ≤ at ≤ nextUpdate) or issued after it → `Good`.
//!   Information whose nextUpdate is before the date (and issued before it) is stale → not used.
//! - Nothing usable → `Unknown`, with every reason.
use super::parse::{cert_info, crl_info, ocsp_info, reason_name};
use super::util::*;
use crate::model::*;
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509Crl};

pub fn check_revocation(
    cert_der: &[u8],
    issuer_der: &[u8],
    crls: &[LabeledDer],
    ocsp: &[LabeledDer],
    at: &str,
) -> CertResult<RevocationStatus> {
    Ok(check_detailed(cert_der, issuer_der, crls, ocsp, at)?.status)
}

/// The status plus a human note when it needs one (revoked after the date; information issued after it).
#[derive(Clone, Debug)]
pub(crate) struct RevResult {
    pub status: RevocationStatus,
    pub note: Option<String>,
}

enum Outcome {
    Revoked {
        reason: String,
        revoked_at: String,
        source: RevocationSource,
    },
    Good {
        source: RevocationSource,
        note: Option<String>,
    },
}

fn x509(der: &[u8], what: &str) -> CertResult<X509> {
    X509::from_der(der)
        .or_else(|_| X509::from_pem(der))
        .map_err(|e| parse_err(what, e))
}

/// Judges one revocation answer at `at`. `revoked` = Some((reason, revoked_at)) when listed as revoked.
fn judge(
    source: RevocationSource,
    revoked: Option<(String, String)>,
    at_e: i64,
    at: &str,
    what: &str,
    reasons: &mut Vec<String>,
) -> CertResult<Option<Outcome>> {
    let this_e = source
        .this_update
        .as_deref()
        .map(rfc3339_to_epoch)
        .transpose()?;
    let next_e = source
        .next_update
        .as_deref()
        .map(rfc3339_to_epoch)
        .transpose()?;
    if let Some((reason, revoked_at)) = revoked {
        if reason != "removeFromCRL" {
            if rfc3339_to_epoch(&revoked_at)? <= at_e {
                return Ok(Some(Outcome::Revoked {
                    reason,
                    revoked_at,
                    source,
                }));
            }
            let note = format!(
                "{what} {} lists the certificate as revoked on {revoked_at} ({reason}), after the date checked ({at}): it was not revoked at that date",
                source.origin
            );
            return Ok(Some(Outcome::Good {
                source,
                note: Some(note),
            }));
        }
    }
    let issued_after = this_e.is_some_and(|t| t > at_e);
    if !issued_after && next_e.is_some_and(|n| n < at_e) {
        reasons.push(format!(
            "{what} {} expired at the validation time (nextUpdate {} is before {at})",
            source.origin,
            source.next_update.as_deref().unwrap_or("?")
        ));
        return Ok(None);
    }
    let note = issued_after.then(|| {
        format!(
            "{what} {} was issued on {}, after the date checked ({at}), and lists no revocation of this certificate",
            source.origin,
            source.this_update.as_deref().unwrap_or("?")
        )
    });
    Ok(Some(Outcome::Good { source, note }))
}

pub(crate) fn check_detailed(
    cert_der: &[u8],
    issuer_der: &[u8],
    crls: &[LabeledDer],
    ocsp: &[LabeledDer],
    at: &str,
) -> CertResult<RevResult> {
    let at_e = rfc3339_to_epoch(at)?;
    let cert = x509(cert_der, "certificate")?;
    let issuer = x509(issuer_der, "issuer certificate")?;
    let issuer_info = cert_info(&issuer.to_der().map_err(|e| parse_err("issuer", e))?)?;
    let issuer_key = issuer
        .public_key()
        .map_err(|e| crypto_err("issuer public key", e))?;
    let serial = cert_info(&cert.to_der().map_err(|e| parse_err("certificate", e))?)?.serial_hex;
    let mut reasons: Vec<String> = vec![];
    let mut outcomes: Vec<Outcome> = vec![];

    for l in crls {
        let crl = match X509Crl::from_der(&l.der).or_else(|_| X509Crl::from_pem(&l.der)) {
            Ok(c) => c,
            Err(_) => {
                reasons.push(format!("CRL {} could not be read", l.origin));
                continue;
            }
        };
        if crl.issuer_name().try_cmp(cert.issuer_name()).ok() != Some(std::cmp::Ordering::Equal) {
            continue; // another CA's CRL: does not cover this certificate
        }
        if !crl.verify(&issuer_key).unwrap_or(false) {
            reasons.push(format!(
                "CRL {}: its signature does not verify with the issuer's public key",
                l.origin
            ));
            continue;
        }
        if !issuer_info.key_usage.is_empty()
            && !issuer_info.key_usage.iter().any(|k| k == "cRLSign")
        {
            reasons.push(format!(
                "CRL {}: the issuer's key usage does not include cRLSign",
                l.origin
            ));
            continue;
        }
        let info = crl_info(&crl.to_der().map_err(|e| parse_err("CRL", e))?)?;
        let source = RevocationSource {
            kind: RevocationSourceKind::Crl,
            origin: l.origin.clone(),
            sha256: l.sha256.clone(),
            this_update: Some(info.this_update.clone()),
            next_update: info.next_update.clone(),
        };
        let revoked = info
            .revoked
            .iter()
            .find(|r| r.serial_hex == serial)
            .map(|r| (r.reason.clone(), r.revoked_at.clone()));
        if let Some(o) = judge(source, revoked, at_e, at, "CRL", &mut reasons)? {
            outcomes.push(o);
        }
    }

    for l in ocsp {
        match ocsp_one(l, &cert, &issuer, at_e, at, &mut reasons) {
            Ok(Some(o)) => outcomes.push(o),
            Ok(None) => {}
            Err(e) => reasons.push(format!("OCSP {}: {}", l.origin, e.message)),
        }
    }

    // Revoked evidence wins; then a good answer; else unknown with every reason.
    if let Some(pos) = outcomes
        .iter()
        .position(|o| matches!(o, Outcome::Revoked { .. }))
    {
        if let Outcome::Revoked {
            reason,
            revoked_at,
            source,
        } = outcomes.swap_remove(pos)
        {
            return Ok(RevResult {
                status: RevocationStatus::Revoked {
                    reason,
                    revoked_at,
                    source,
                },
                note: None,
            });
        }
    }
    let mut notes = vec![];
    let mut good = None;
    for o in outcomes {
        if let Outcome::Good { source, note } = o {
            notes.extend(note);
            good.get_or_insert(source);
        }
    }
    if let Some(source) = good {
        return Ok(RevResult {
            status: RevocationStatus::Good { source },
            note: (!notes.is_empty()).then(|| notes.join("; ")),
        });
    }
    let source = if reasons.is_empty() {
        if crls.is_empty() && ocsp.is_empty() {
            "no CRL or OCSP response supplied".to_string()
        } else {
            format!(
                "none of the {} CRL(s) and {} OCSP response(s) supplied covers this certificate (issuer {})",
                crls.len(),
                ocsp.len(),
                name_string(cert.issuer_name())
            )
        }
    } else {
        reasons.join("; ")
    };
    Ok(RevResult {
        status: RevocationStatus::Unknown { source },
        note: None,
    })
}

fn ocsp_one(
    l: &LabeledDer,
    cert: &X509,
    issuer: &X509,
    at_e: i64,
    at: &str,
    reasons: &mut Vec<String>,
) -> CertResult<Option<Outcome>> {
    let resp = OcspResponse::from_der(&l.der).map_err(|e| parse_err("not an OCSP response", e))?;
    if resp.status() != OcspResponseStatus::SUCCESSFUL {
        reasons.push(format!(
            "OCSP {}: response status {}",
            l.origin,
            super::parse::ocsp_status_name(resp.status().as_raw())
        ));
        return Ok(None);
    }
    let basic = resp
        .basic()
        .map_err(|e| parse_err("OCSP basic response", e))?;
    let digests = [MessageDigest::sha1(), MessageDigest::sha256()];
    let mut found = None;
    for md in digests {
        let id =
            OcspCertId::from_cert(md, cert, issuer).map_err(|e| crypto_err("OCSP CertID", e))?;
        if let Some(st) = basic.find_status(&id) {
            let rev = (st.status == OcspCertStatus::REVOKED).then(|| {
                let reason = if st.reason.as_raw() < 0 {
                    "unspecified".to_string()
                } else {
                    reason_name(st.reason.as_raw() as u8)
                };
                let t = st
                    .revocation_time
                    .and_then(|t| printed_time_to_rfc3339(&t.to_string()))
                    .unwrap_or_default();
                (reason, t)
            });
            found = Some((
                st.status,
                rev,
                printed_time_to_rfc3339(&st.this_update.to_string()),
                st.next_update()
                    .and_then(|t| printed_time_to_rfc3339(&t.to_string())),
            ));
            break;
        }
    }
    let Some((status, revoked, this_update, next_update)) = found else {
        reasons.push(format!(
            "OCSP {}: no answer for serial {} of this issuer",
            l.origin,
            cert.serial_number()
                .to_bn()
                .and_then(|b| b.to_hex_str().map(|s| s.to_ascii_lowercase()))
                .unwrap_or_default()
        ));
        return Ok(None);
    };
    // Signature: the issuer itself or a delegated responder, the responder's certificate judged at producedAt.
    let produced = ocsp_info(&l.der)
        .ok()
        .and_then(|i| i.produced_at)
        .and_then(|p| rfc3339_to_epoch(&p).ok())
        .unwrap_or(at_e);
    let mut sb = X509StoreBuilder::new().map_err(|e| crypto_err("store", e))?;
    sb.add_cert(issuer.clone())
        .map_err(|e| crypto_err("store", e))?;
    let mut param = X509VerifyParam::new().map_err(|e| crypto_err("store", e))?;
    param
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|e| crypto_err("store", e))?;
    param.set_time(produced as _);
    sb.set_param(&param).map_err(|e| crypto_err("store", e))?;
    let store = sb.build();
    let mut certs = Stack::new().map_err(|e| crypto_err("stack", e))?;
    certs
        .push(issuer.clone())
        .map_err(|e| crypto_err("stack", e))?;
    if basic.verify(&certs, &store, OcspFlag::empty()).is_err() {
        reasons.push(format!(
            "OCSP {}: its signature does not verify with the issuer or a responder it delegated",
            l.origin
        ));
        return Ok(None);
    }
    if status == OcspCertStatus::UNKNOWN {
        reasons.push(format!("OCSP {}: the responder said unknown", l.origin));
        return Ok(None);
    }
    let source = RevocationSource {
        kind: RevocationSourceKind::Ocsp,
        origin: l.origin.clone(),
        sha256: l.sha256.clone(),
        this_update,
        next_update,
    };
    judge(source, revoked, at_e, at, "OCSP response", reasons)
}
