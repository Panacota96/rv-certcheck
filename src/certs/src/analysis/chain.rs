//! OWNER: A. Path building and verification with OpenSSL's X509_STORE_CTX.
//!
//! How every error is collected. The `openssl` crate exposes no safe X509_STORE verify callback and this crate
//! forbids `unsafe`, so the "callback that records the error and continues" is reproduced by re-running
//! `X509_verify_cert` with the class of the error just reported switched off, exactly what returning 1 from
//! the callback does for that class:
//!
//! | OpenSSL reported (X509_V_ERR_…)                         | next run                                          |
//! |---------------------------------------------------------|---------------------------------------------------|
//! | 2, 18, 19, 20, 21 (path does not reach an anchor)       | the top of the built path is trusted (PARTIAL_CHAIN), never marked as an anchor |
//! | 9, 10, 11, 12 (certificate or CRL not yet valid / expired) | X509_V_FLAG_NO_CHECK_TIME (certificate dates are then compared per depth with OpenSSL's ASN1_TIME comparison) |
//! | 26, 39 (purpose / key usage for the purpose)            | no purpose                                        |
//! | 3, 5, 8, 11, 12, 15, 16, 23, 33, 35, 36, 44, 54 (CRL)   | CRL checking off (revocation is still judged by the tool's own check) |
//! | anything else (signature, name constraints, ...)        | the walk stops: recorded in `notes`               |
//!
//! The first error is therefore OpenSSL's own first answer (what `openssl verify` prints), `errors` lists every
//! error found, in order, with its depth, and the verdict stays failed whenever any error was found.
//!
//! CRLs given to OpenSSL: X509_V_FLAG_CRL_CHECK when a CRL by the target's issuer is supplied, plus
//! X509_V_FLAG_CRL_CHECK_ALL when every certificate of the path below the anchor has a CRL by its issuer. The
//! tool's own revocation check (`revocation.rs`, CRL and OCSP) runs for every depth whatever the flags.
//!
//! Policy checks of this tool, not OpenSSL's (reported as such): weak keys and signature algorithms
//! (`parse.rs`), the `document-signing` purpose (OpenSSL has none: EKU absent, documentSigning, emailProtection
//! or anyExtendedKeyUsage, and key usage absent or with digitalSignature / nonRepudiation), Rakvor internal
//! certificates (the bundled Rakvor root or the Rakvor policy OID arc) and trust-list membership.
use super::parse::{cert_info, cert_signals};
use super::revocation::check_detailed;
use super::util::*;
use crate::model::*;
use openssl::stack::Stack;
use openssl::x509::store::{X509Lookup, X509StoreBuilder};
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509PurposeId, X509StoreContext, X509VerifyResult};

pub fn validate_chain(req: &ChainRequest, opts: &ValidationOptions) -> CertResult<ChainVerdict> {
    let target = X509::from_der(req.target_der)
        .or_else(|_| X509::from_pem(req.target_der))
        .map_err(|e| parse_err("target certificate", e))?;
    let mut notes = vec![];
    let (at, at_source) = match &opts.at {
        AtTime::Now => (now_rfc3339(), "now".to_string()),
        AtTime::Fixed(t) => (epoch_to_rfc3339(rfc3339_to_epoch(t)?), "given".to_string()),
        AtTime::SigningTime => match &req.signing_time {
            Some(t) => {
                let t = epoch_to_rfc3339(rfc3339_to_epoch(t)?);
                notes.push(format!(
                    "--at signing-time: judged at {t}, the signing time supplied with the request (not read from the certificate)"
                ));
                (t, "signing-time".to_string())
            }
            None => {
                let t = now_rfc3339();
                notes.push(format!(
                    "--at signing-time: the item has no signing time, so the chain was judged now ({t})"
                ));
                (t, "signing-time-unavailable-now".to_string())
            }
        },
    };
    let at_e = rfc3339_to_epoch(&at)?;

    let mut anchors: Vec<(X509, String)> = vec![];
    for a in req.anchors {
        for c in &a.certificates {
            if let Ok(x) = X509::from_der(&c.der) {
                anchors.push((x, a.spec.clone()));
            }
        }
    }
    let target_der = target.to_der().map_err(|e| parse_err("target", e))?;
    let mut untrusted: Vec<X509> = vec![];
    for d in req.untrusted_der {
        if let Ok(x) = X509::from_der(d) {
            if x.to_der().ok().as_deref() != Some(&target_der[..]) {
                untrusted.push(x);
            }
        }
    }
    let mut crls = req.crls.to_vec();
    let mut ocsp = req.ocsp.to_vec();
    let mut fetches = vec![];

    let mut walk = run_walk(&target, &anchors, &untrusted, &crls, at_e, opts.purpose)?;
    if opts.online {
        let (more_crls, more_ocsp, f) = super::online::fetch_for_chain(&walk.chain);
        fetches = f;
        if !more_crls.is_empty() || !more_ocsp.is_empty() {
            crls.extend(more_crls);
            ocsp.extend(more_ocsp);
            walk = run_walk(&target, &anchors, &untrusted, &crls, at_e, opts.purpose)?;
        }
    }
    notes.extend(walk.notes.iter().cloned());

    // Nodes, depth 0 first.
    let mut nodes: Vec<ChainNode> = vec![];
    for (d, x) in walk.chain.iter().enumerate() {
        let der = x.to_der().map_err(|e| parse_err("chain certificate", e))?;
        let anchor = anchors
            .iter()
            .find(|(a, _)| a.to_der().ok().as_deref() == Some(&der[..]))
            .map(|(_, s)| s.clone());
        let first = walk.errors.iter().find(|e| e.depth as usize == d);
        let untrusted_top = d + 1 == walk.chain.len()
            && anchor.is_none()
            && walk.errors.iter().any(|e| is_untrusted_code(e.code));
        nodes.push(ChainNode {
            depth: d as u32,
            cert: cert_info(&der)?,
            status: if untrusted_top {
                NodeStatus::Incomplete
            } else if first.is_some() {
                NodeStatus::Error
            } else {
                NodeStatus::Ok
            },
            openssl_code: first.map(|e| e.code).unwrap_or(0),
            openssl_reason: first
                .map(|e| e.reason.clone())
                .unwrap_or_else(|| X509VerifyResult::OK.error_string().to_string()),
            anchor,
            revocation: None,
            trust_list: None,
            revocation_note: None,
        });
    }
    if nodes.is_empty() {
        nodes.push(ChainNode {
            cert: cert_info(&target_der)?,
            status: NodeStatus::Incomplete,
            openssl_code: walk.first_code,
            openssl_reason: walk.first_reason.clone(),
            ..Default::default()
        });
    }

    // Revocation of every non-anchor node, by the tool's own CRL/OCSP evaluation.
    for i in 0..nodes.len() {
        if nodes[i].anchor.is_some() {
            continue;
        }
        let rev = match nodes.get(i + 1) {
            Some(issuer) => {
                let r = check_detailed(&nodes[i].cert.der, &issuer.cert.der, &crls, &ocsp, &at)?;
                nodes[i].revocation_note = r.note;
                r.status
            }
            None if nodes[i].cert.self_signed => continue,
            None => RevocationStatus::Unknown {
                source: "the issuer certificate is not among the material examined".into(),
            },
        };
        nodes[i].revocation = Some(rev);
    }

    // Trust lists.
    for a in req.anchors {
        if let Some(snap) = &a.snapshot {
            for n in nodes.iter_mut() {
                if n.trust_list.is_none() {
                    n.trust_list = crate::trustlist::store::lookup(snap, &n.cert, &at);
                }
            }
        }
    }

    let mut signals = vec![];
    let mut failed = false;
    let mut untrusted_chain = false;
    let target_subject = nodes[0].cert.subject.clone();
    for e in &walk.errors {
        let n = nodes.get(e.depth as usize).unwrap_or(&nodes[0]);
        let subj = n.cert.subject.clone();
        failed = true;
        let sig = match e.code {
            c if is_untrusted_code(c) => {
                untrusted_chain = true;
                Signal::of(codes::CERT_CHAIN_UNTRUSTED)
                    .with("subject", &target_subject)
                    .with("reason", &e.reason)
                    .with("code", e.code.to_string())
            }
            4 | 6 | 7 => Signal::of(codes::CERT_SIGNATURE_INVALID)
                .with("subject", subj)
                .with("reason", &e.reason),
            10 => Signal::of(codes::CERT_EXPIRED_AT_DATE)
                .with("subject", subj)
                .with("not_after", &n.cert.not_after)
                .with("at", &at),
            9 => Signal::of(codes::CERT_NOT_YET_VALID_AT_DATE)
                .with("subject", subj)
                .with("not_before", &n.cert.not_before)
                .with("at", &at),
            23 => {
                match &n.revocation {
                    Some(RevocationStatus::Revoked { .. }) => continue, // reported below with reason and date
                    Some(RevocationStatus::Good { .. }) => {
                        notes.push(format!(
                            "OpenSSL reports code 23 at depth {} because a CRL lists the certificate; OpenSSL does not compare the revocation date with the validation time: {}",
                            e.depth,
                            n.revocation_note.as_deref().unwrap_or("not revoked at the date checked")
                        ));
                        continue;
                    }
                    _ => {}
                }
                Signal::of(codes::CERT_REVOKED)
                    .with("subject", subj)
                    .with("serial", &n.cert.serial_hex)
                    .with("reason", "listed in a CRL")
                    .with("revoked_at", "see the CRL")
                    .with("source", "OpenSSL CRL check")
            }
            26 | 39 => purpose_signal(&n.cert, opts.purpose),
            47..=49 | 51..=53 => name_constraint_signal(&nodes, e.depth as usize),
            c if is_crl_code(c) => Signal::of(codes::REVOCATION_UNKNOWN)
                .with("subject", subj)
                .with("source", format!("OpenSSL: {} (code {c})", e.reason)),
            _ => Signal::of(codes::CERT_CHAIN_UNTRUSTED)
                .with("subject", &target_subject)
                .with("reason", &e.reason)
                .with("code", e.code.to_string()),
        };
        signals.push(sig.with("depth", e.depth.to_string()));
    }

    // Revocation signals: CERT_REVOKED at any depth, REVOCATION_UNKNOWN for the target only.
    for n in &nodes {
        match &n.revocation {
            Some(RevocationStatus::Revoked {
                reason,
                revoked_at,
                source,
            }) => {
                failed = true;
                signals.push(
                    Signal::of(codes::CERT_REVOKED)
                        .with("subject", &n.cert.subject)
                        .with("serial", &n.cert.serial_hex)
                        .with("reason", reason)
                        .with("revoked_at", revoked_at)
                        .with("source", &source.origin)
                        .with("depth", n.depth.to_string()),
                );
            }
            Some(RevocationStatus::Unknown { source }) if n.depth == 0 => signals.push(
                Signal::of(codes::REVOCATION_UNKNOWN)
                    .with("subject", &n.cert.subject)
                    .with("source", source),
            ),
            _ => {}
        }
    }

    // document-signing: the tool's own purpose check (OpenSSL has no such purpose).
    if opts.purpose == Purpose::DocumentSigning && !document_signing_ok(&nodes[0].cert) {
        failed = true;
        notes.push("document-signing purpose checked by rv-certcheck (OpenSSL has no such purpose): EKU must be absent or include documentSigning, emailProtection or anyExtendedKeyUsage; key usage absent or with digitalSignature or nonRepudiation".into());
        signals.push(purpose_signal(&nodes[0].cert, opts.purpose).with("depth", "0"));
    }

    // Policy signals of every certificate of the path (same params as parse time, so core de-duplicates).
    // CERT_SELF_SIGNED only for the target: a self-signed anchor above it is the normal case.
    for n in &nodes {
        let mut s = vec![];
        cert_signals(&n.cert, &mut s);
        signals.extend(
            s.into_iter()
                .filter(|s| n.depth == 0 || s.code != codes::CERT_SELF_SIGNED),
        );
    }
    let top = nodes.last().map(|n| n.cert.der.clone()).unwrap_or_default();
    if top == crate::RAKVOR_ROOT_DER {
        signals.push(
            Signal::of(codes::CERT_ISSUED_BY_RAKVOR_INTERNAL)
                .with("subject", &target_subject)
                .with("policy", "chain ends in the bundled Rakvor root"),
        );
    }

    // Trust-list membership.
    for a in req.anchors {
        if let Some(snap) = &a.snapshot {
            let mut any = false;
            for n in &nodes {
                if let Some(m) = &n.trust_list {
                    if m.snapshot_id == snap.id {
                        any = true;
                        signals.push(
                            Signal::of(codes::CERT_IN_TRUST_LIST)
                                .with("subject", &n.cert.subject)
                                .with("list", &m.list)
                                .with("snapshot", &m.snapshot_id)
                                .with("service", &m.service_name)
                                .with("status", &m.status_at)
                                .with("at", &m.at),
                        );
                    }
                }
            }
            if !any {
                signals.push(
                    Signal::of(codes::CERT_NOT_IN_TRUST_LIST)
                        .with("subject", &target_subject)
                        .with("list", &snap.list)
                        .with("snapshot", &snap.id),
                );
            }
        }
    }

    let status = if untrusted_chain {
        ChainStatus::Untrusted
    } else if failed {
        ChainStatus::Invalid
    } else {
        ChainStatus::Valid
    };
    if status == ChainStatus::Valid {
        let anchor = nodes
            .iter()
            .rev()
            .find_map(|n| n.anchor.clone())
            .unwrap_or_default();
        signals.insert(
            0,
            Signal::of(codes::CERT_CHAIN_VALID)
                .with("subject", &target_subject)
                .with("anchor", anchor)
                .with("at", &at),
        );
    }
    let mut seen: Vec<Signal> = vec![];
    signals.retain(|s| {
        let new = !seen.contains(s);
        if new {
            seen.push(s.clone());
        }
        new
    });
    let mut anchor_specs: Vec<String> = vec![];
    for (_, s) in &anchors {
        if !anchor_specs.contains(s) {
            anchor_specs.push(s.clone());
        }
    }
    Ok(ChainVerdict {
        status,
        at,
        at_source,
        purpose: opts.purpose,
        anchors: anchor_specs,
        nodes,
        openssl_code: walk.first_code,
        openssl_reason: walk.first_reason,
        errors: walk.errors,
        signals,
        openssl_version: crate::openssl_version().to_string(),
        online_fetches: fetches,
        notes,
    })
}

fn is_untrusted_code(c: i32) -> bool {
    matches!(c, 2 | 18 | 19 | 20 | 21 | 27 | 28)
}

fn is_crl_code(c: i32) -> bool {
    matches!(c, 3 | 5 | 8 | 11 | 12 | 15 | 16 | 33 | 35 | 36 | 44 | 54)
}

fn list_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

fn purpose_signal(c: &CertInfo, p: Purpose) -> Signal {
    Signal::of(codes::CERT_PURPOSE_MISMATCH)
        .with("subject", &c.subject)
        .with("purpose", p.name())
        .with("key_usage", list_or_none(&c.key_usage))
        .with("eku", list_or_none(&c.eku))
}

pub(crate) fn document_signing_ok(c: &CertInfo) -> bool {
    let eku_ok = c.eku.is_empty()
        || c.eku.iter().any(|e| {
            matches!(
                e.as_str(),
                "documentSigning" | "emailProtection" | "anyExtendedKeyUsage"
            )
        });
    let ku_ok = c.key_usage.is_empty()
        || c.key_usage
            .iter()
            .any(|k| k == "digitalSignature" || k == "nonRepudiation");
    eku_ok && ku_ok
}

/// The name of the certificate at `depth` that the constraints of a CA above it exclude or do not permit.
fn name_constraint_signal(nodes: &[ChainNode], depth: usize) -> Signal {
    let c = &nodes[depth].cert;
    let mut names: Vec<GeneralName> = c.sans.clone();
    for (k, v) in &c.subject_rdns {
        match k.as_str() {
            "CN" if c.sans.iter().all(|s| s.kind != "dns") => names.push(GeneralName {
                kind: "dns".into(),
                value: v.clone(),
            }),
            "emailAddress" => names.push(GeneralName {
                kind: "email".into(),
                value: v.clone(),
            }),
            _ => {}
        }
    }
    for ca in nodes.iter().skip(depth + 1) {
        let Some(nc) = &ca.cert.name_constraints else {
            continue;
        };
        for n in &names {
            let excluded = nc
                .excluded
                .iter()
                .any(|b| b.kind == n.kind && name_within(n, b));
            let permitted_of_kind: Vec<_> =
                nc.permitted.iter().filter(|b| b.kind == n.kind).collect();
            let not_permitted = !permitted_of_kind.is_empty()
                && !permitted_of_kind.iter().any(|b| name_within(n, b));
            if excluded || not_permitted {
                return Signal::of(codes::CERT_NAME_CONSTRAINT_VIOLATION)
                    .with("subject", &c.subject)
                    .with("name", format!("{}:{}", n.kind, n.value))
                    .with("constraint_by", &ca.cert.subject);
            }
        }
    }
    let by = nodes
        .iter()
        .skip(depth + 1)
        .find(|n| n.cert.name_constraints.is_some())
        .map(|n| n.cert.subject.clone())
        .unwrap_or_else(|| "a CA of the chain".into());
    Signal::of(codes::CERT_NAME_CONSTRAINT_VIOLATION)
        .with("subject", &c.subject)
        .with(
            "name",
            names
                .iter()
                .map(|n| format!("{}:{}", n.kind, n.value))
                .collect::<Vec<_>>()
                .join(", "),
        )
        .with("constraint_by", by)
}

/// RFC 5280 §4.2.1.10 matching for dns / email / ip (enough to name the offending entry; OpenSSL decides).
fn name_within(n: &GeneralName, base: &GeneralName) -> bool {
    let (v, b) = (
        n.value.to_ascii_lowercase(),
        base.value.to_ascii_lowercase(),
    );
    match n.kind.as_str() {
        "dns" => {
            let b = b.trim_start_matches('.');
            v == b || v.ends_with(&format!(".{b}"))
        }
        "email" => {
            if b.contains('@') {
                v == b
            } else if let Some(stripped) = b.strip_prefix('.') {
                v.rsplit_once('@')
                    .is_some_and(|(_, d)| d.ends_with(&format!(".{stripped}")))
            } else {
                v.rsplit_once('@').is_some_and(|(_, d)| d == b)
            }
        }
        "ip" => ip_in(&v, &b),
        _ => false,
    }
}

fn ip_in(ip: &str, cidr: &str) -> bool {
    let Some((net, len)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(ip), Ok(net), Ok(len)) = (
        ip.parse::<std::net::IpAddr>(),
        net.parse::<std::net::IpAddr>(),
        len.parse::<u32>(),
    ) else {
        return false;
    };
    let (a, b, bits): (u128, u128, u32) = match (ip, net) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            (u32::from(a) as u128, u32::from(b) as u128, 32)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return false,
    };
    if len > bits {
        return false;
    }
    let shift = bits - len;
    if shift >= 128 {
        return true;
    }
    (a >> shift) == (b >> shift)
}

// ------------------------------------------------------------------------------------------------ OpenSSL walk

pub(crate) struct Walk {
    /// The path as OpenSSL built it (depth 0 first), from the most complete run.
    pub chain: Vec<X509>,
    pub errors: Vec<ChainError>,
    pub first_code: i32,
    pub first_reason: String,
    pub notes: Vec<String>,
}

#[derive(Clone, Default)]
struct Relax {
    no_time: bool,
    no_purpose: bool,
    no_crl: bool,
    extra_trust: Vec<X509>,
}

fn purpose_id(p: Purpose) -> Option<X509PurposeId> {
    match p {
        Purpose::Any | Purpose::DocumentSigning => None,
        Purpose::TlsServer => Some(X509PurposeId::SSL_SERVER),
        Purpose::TlsClient => Some(X509PurposeId::SSL_CLIENT),
        Purpose::CodeSigning => Some(X509PurposeId::CODE_SIGN),
        Purpose::Email => Some(X509PurposeId::SMIME_SIGN),
        Purpose::Timestamping => Some(X509PurposeId::TIMESTAMP_SIGN),
    }
}

/// A CRL issued (by name) by the issuer of `x` is among `crls`.
fn has_crl_for(x: &X509, crls: &[openssl::x509::X509Crl]) -> bool {
    crls.iter()
        .any(|c| c.issuer_name().try_cmp(x.issuer_name()).ok() == Some(std::cmp::Ordering::Equal))
}

struct CrlFile(Option<std::path::PathBuf>);

impl Drop for CrlFile {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// The `openssl` crate can add CRLs to a store only through a file lookup: the supplied CRLs (public data) are
/// written as PEM to a private temporary file for the duration of the call.
fn crl_file(crls: &[openssl::x509::X509Crl]) -> CertResult<CrlFile> {
    use std::io::Write;
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut pem = vec![];
    for c in crls {
        pem.extend(c.to_pem().map_err(|e| crypto_err("CRL", e))?);
    }
    let name = format!(
        "rv-certcheck-crl-{}-{}-{}.pem",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let path = std::env::temp_dir().join(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| CertError::new(ErrorKind::Io, format!("temporary CRL file: {e}")))?;
    let guard = CrlFile(Some(path));
    f.write_all(&pem)
        .map_err(|e| CertError::new(ErrorKind::Io, format!("temporary CRL file: {e}")))?;
    Ok(guard)
}

struct Once {
    ok: bool,
    code: i32,
    reason: String,
    depth: u32,
    chain: Vec<X509>,
}

#[allow(clippy::too_many_arguments)]
fn verify_once(
    target: &X509,
    anchors: &[(X509, String)],
    untrusted: &[X509],
    crl_path: Option<&std::path::Path>,
    crl_flags: X509VerifyFlags,
    at_e: i64,
    purpose: Option<X509PurposeId>,
    relax: &Relax,
) -> CertResult<Once> {
    let e = |e| crypto_err("X509_STORE", e);
    let mut sb = X509StoreBuilder::new().map_err(e)?;
    for (a, _) in anchors {
        sb.add_cert(a.clone()).map_err(e)?;
    }
    for a in &relax.extra_trust {
        let _ = sb.add_cert(a.clone());
    }
    let mut flags = X509VerifyFlags::empty();
    if let (Some(p), false) = (crl_path, relax.no_crl) {
        let lookup = sb.add_lookup(X509Lookup::file()).map_err(e)?;
        lookup
            .load_crl_file(p, openssl::ssl::SslFiletype::PEM)
            .map_err(e)?;
        flags |= crl_flags;
    }
    if !relax.extra_trust.is_empty() {
        flags |= X509VerifyFlags::PARTIAL_CHAIN;
    }
    let mut param = X509VerifyParam::new().map_err(e)?;
    // set_time also sets X509_V_FLAG_USE_CHECK_TIME, which OpenSSL honours before NO_CHECK_TIME.
    if relax.no_time {
        flags |= X509VerifyFlags::NO_CHECK_TIME;
    } else {
        param.set_time(at_e as _);
    }
    param.set_flags(flags).map_err(e)?;
    if let (Some(p), false) = (purpose, relax.no_purpose) {
        param.set_purpose(p).map_err(e)?;
    }
    sb.set_param(&param).map_err(e)?;
    let store = sb.build();
    let mut stack = Stack::new().map_err(e)?;
    for u in untrusted {
        stack.push(u.clone()).map_err(e)?;
    }
    let mut ctx = X509StoreContext::new().map_err(e)?;
    ctx.init(&store, target, &stack, |c| {
        let ok = c.verify_cert()?;
        let err = c.error();
        let chain = c
            .chain()
            .map(|s| s.iter().map(|x| x.to_owned()).collect())
            .unwrap_or_default();
        Ok(Once {
            ok,
            code: err.as_raw(),
            reason: err.error_string().to_string(),
            depth: c.error_depth(),
            chain,
        })
    })
    .map_err(e)
}

pub(crate) fn run_walk(
    target: &X509,
    anchors: &[(X509, String)],
    untrusted: &[X509],
    crl_ders: &[LabeledDer],
    at_e: i64,
    purpose: Purpose,
) -> CertResult<Walk> {
    let pid = purpose_id(purpose);
    let crls: Vec<openssl::x509::X509Crl> = crl_ders
        .iter()
        .filter_map(|l| {
            openssl::x509::X509Crl::from_der(&l.der)
                .or_else(|_| openssl::x509::X509Crl::from_pem(&l.der))
                .ok()
        })
        .collect();
    let mut notes = vec![];
    // Pass 0 (no CRL) only to learn the path and decide the CRL flags.
    let probe = verify_once(
        target,
        anchors,
        untrusted,
        None,
        X509VerifyFlags::empty(),
        at_e,
        pid,
        &Relax::default(),
    )?;
    let mut crl_flags = X509VerifyFlags::empty();
    let file = if !crls.is_empty() && has_crl_for(target, &crls) {
        crl_flags |= X509VerifyFlags::CRL_CHECK;
        let path_below_anchor: Vec<&X509> = probe
            .chain
            .iter()
            .filter(|x| {
                !anchors
                    .iter()
                    .any(|(a, _)| a.to_der().ok() == x.to_der().ok())
            })
            .collect();
        if !path_below_anchor.is_empty() && path_below_anchor.iter().all(|x| has_crl_for(x, &crls))
        {
            crl_flags |= X509VerifyFlags::CRL_CHECK_ALL;
            notes.push("OpenSSL CRL checking: CRL_CHECK + CRL_CHECK_ALL (a CRL was supplied for every certificate below the anchor)".into());
        } else {
            notes.push("OpenSSL CRL checking: CRL_CHECK (end-entity certificate; not every CA of the path has a CRL among those supplied)".into());
        }
        Some(crl_file(&crls)?)
    } else {
        if !crls.is_empty() {
            notes.push(
                "OpenSSL CRL checking: off (no CRL by the target's issuer among those supplied)"
                    .into(),
            );
        }
        None
    };
    let crl_path = file.as_ref().and_then(|f| f.0.as_deref());

    let mut relax = Relax::default();
    let mut errors: Vec<ChainError> = vec![];
    let mut first: Option<(i32, String)> = None;
    let mut chain = probe.chain;
    for _ in 0..12 {
        let r = verify_once(
            target, anchors, untrusted, crl_path, crl_flags, at_e, pid, &relax,
        )?;
        if !r.chain.is_empty() {
            chain = r.chain.clone();
        }
        if first.is_none() {
            first = Some((r.code, r.reason.clone()));
        }
        if r.ok {
            break;
        }
        if !errors
            .iter()
            .any(|e| e.code == r.code && e.depth == r.depth)
        {
            errors.push(ChainError {
                depth: r.depth,
                code: r.code,
                reason: r.reason.clone(),
            });
        }
        let progressed = match r.code {
            c if is_untrusted_code(c) => match r.chain.last() {
                Some(top)
                    if !relax
                        .extra_trust
                        .iter()
                        .any(|t| t.to_der().ok() == top.to_der().ok()) =>
                {
                    relax.extra_trust.push(top.clone());
                    true
                }
                _ => false,
            },
            // CRL not yet valid / expired: OpenSSL's CLI callback continues and still applies the CRL, so the
            // time check (not the CRL) is what is switched off; certificate dates are re-checked below.
            9..=12 if !relax.no_time => {
                relax.no_time = true;
                true
            }
            26 | 39 if !relax.no_purpose && pid.is_some() => {
                relax.no_purpose = true;
                true
            }
            c if (is_crl_code(c) || c == 23) && !relax.no_crl && crl_path.is_some() => {
                relax.no_crl = true;
                true
            }
            _ => false,
        };
        if !progressed {
            notes.push(format!(
                "OpenSSL walk stopped after error {} at depth {} ({}): later checks of the path could not be run",
                r.code, r.depth, r.reason
            ));
            break;
        }
    }
    // A continuing callback reports a time error at every depth; once NO_CHECK_TIME is set OpenSSL reports
    // none after the first, so the other depths are compared here with OpenSSL's own ASN1_TIME comparison.
    if relax.no_time {
        let at =
            openssl::asn1::Asn1Time::from_unix(at_e as _).map_err(|e| crypto_err("time", e))?;
        for (d, x) in chain.iter().enumerate() {
            let code = if x
                .not_before()
                .compare(&at)
                .map_err(|e| crypto_err("time", e))?
                == std::cmp::Ordering::Greater
            {
                9
            } else if x
                .not_after()
                .compare(&at)
                .map_err(|e| crypto_err("time", e))?
                == std::cmp::Ordering::Less
            {
                10
            } else {
                continue;
            };
            if !errors.iter().any(|e| e.depth == d as u32 && e.code == code) {
                errors.push(ChainError {
                    depth: d as u32,
                    code,
                    // X509_verify_cert_error_string() of 9 and 10 (X509VerifyResult::from_raw is unsafe).
                    reason: if code == 9 {
                        "certificate is not yet valid"
                    } else {
                        "certificate has expired"
                    }
                    .to_string(),
                });
                notes.push(format!(
                    "error {code} at depth {d}: from the certificate's dates at the validation time (OpenSSL stops reporting time errors once its time check is switched off to continue the walk)"
                ));
            }
        }
    }
    let (first_code, first_reason) = first.unwrap_or((0, "ok".into()));
    Ok(Walk {
        chain,
        errors,
        first_code,
        first_reason,
        notes,
    })
}
