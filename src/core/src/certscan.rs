//! Certificate analysis glue: calls the frozen certificate-layer API (`rv_certcheck_certs`) for every item and
//! turns its signals into findings. Two stages, both driven by `run.rs`:
//!
//! ```text
//! per item (in the hashing loop)   read the item again (read-only, ≤ 16 MiB) ─► re-hash = first pass? ─► sniff
//!                                   ─► Unknown: inventory analysis (type by signature) + CRYPTO_INPUT_NOT_RECOGNISED
//!                                   ─► known kind: parse_any ─► parse-time signals → findings
//! after the loop (cross-item)       pool = every certificate of the run; CRLs/OCSP = --crl/--ocsp + evidence items
//!                                   validate_chain per end-entity certificate, verify_timestamp_token, key ↔ cert
//!                                   ─► findings + items/<NNNNN-name>/chain.json and certificate.txt (hashed, audited)
//! ```
//!
//! A certificate-layer call that fails becomes the medium finding `ANALYSIS_STEP_FAILED` with the operation and
//! the reason (the layer has no stubs any more; `ANALYSIS_NOT_IMPLEMENTED` stays in the catalogue, unused).
//! `--online`: every URL the layer fetched (CRL distribution points, OCSP responders) is listed with its
//! response SHA-256 and time in the item's audit entry (`online_fetches`) and in chain.json.

use crate::analyzer::{Analysis, Finding, Severity, analyze};
use crate::hash::{HashAlgo, hash_bytes};
use rv_certcheck_certs::{
    self as certs, CertError, ChainRequest, ErrorKind, InputKind, LabeledDer, ParsedInput,
    ResolvedAnchor, Secret, Signal, ValidationOptions, codes,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Items larger than this are not read a second time for cryptographic analysis (certificates, CRLs, tokens and
/// key stores are kilobytes; a large CRL is a few MiB).
pub const MAX_CRYPTO_BYTES: u64 = 16 * 1024 * 1024;
/// Schema id of chain.json.
pub const SCHEMA_CHAIN: &str = "rakvor.cert-chain/1";

/// The certificate options of a run (`analyze --anchor --at --purpose --crl --ocsp --online`, PKCS#12 password).
#[derive(Clone, Debug, Default)]
pub struct CertOptions {
    pub validation: ValidationOptions,
    /// Opens PKCS#12 items and encrypted keys. Never logged.
    pub p12_password: Option<Secret>,
}

/// Run-level inputs resolved once before the items: anchors and `--crl` / `--ocsp` files, all hashed.
#[derive(Clone, Debug, Default)]
pub struct Prepared {
    pub anchors: Vec<ResolvedAnchor>,
    /// Set when `--anchor` was given but could not be resolved (stub or error): reported per item.
    pub anchor_error: Option<CertError>,
    pub crls: Vec<LabeledDer>,
    pub ocsp: Vec<LabeledDer>,
}

/// Checks the certificate options before a run. Everything is supported; `--online` fetches are audited.
pub fn check_options(_opts: &CertOptions) -> Result<(), String> {
    Ok(())
}

/// Reads and hashes `--crl` / `--ocsp` files and resolves `--anchor`. The audit details list every file with its
/// SHA-256 so the run can be repeated with the same inputs.
pub fn prepare(opts: &CertOptions) -> Result<(Prepared, Value), String> {
    check_options(opts)?;
    let v = &opts.validation;
    let read = |p: &PathBuf| -> Result<LabeledDer, String> {
        std::fs::read(p)
            .map(|b| LabeledDer::new(format!("file:{}", p.display()), b))
            .map_err(|e| format!("cannot read {}: {}", p.display(), e))
    };
    let crls = v
        .crl_files
        .iter()
        .map(read)
        .collect::<Result<Vec<_>, _>>()?;
    let ocsp = v
        .ocsp_files
        .iter()
        .map(read)
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared = Prepared {
        crls,
        ocsp,
        ..Default::default()
    };
    let mut anchor_files = vec![];
    for a in &v.anchors {
        if let certs::AnchorSpec::File { path } = a {
            let data = std::fs::read(path)
                .map_err(|e| format!("cannot read anchor {}: {}", path.display(), e))?;
            anchor_files.push(
                json!({"path": path.display().to_string(), "sha256": hash_bytes(&data, HashAlgo::Sha256)}),
            );
        }
    }
    let mut resolved = Value::Null;
    if !v.anchors.is_empty() {
        match certs::resolve_anchors(&v.anchors, v.trust_list_dir.as_deref()) {
            Ok(a) => {
                resolved = json!(
                    a.iter()
                        .map(|r| json!({"spec": r.spec, "source_sha256": r.source_sha256,
                                    "certificates": r.certificates.iter().map(|c| &c.sha256).collect::<Vec<_>>()}))
                        .collect::<Vec<_>>()
                );
                prepared.anchors = a;
            }
            Err(e) => {
                resolved = json!({"error": e.message, "kind": e.kind});
                prepared.anchor_error = Some(e);
            }
        }
    }
    let audit = json!({
        "anchors": v.anchors.iter().map(|a| a.describe()).collect::<Vec<_>>(),
        "anchor_files": anchor_files,
        "anchors_resolved": resolved,
        "at": v.at.describe(),
        "purpose": v.purpose.name(),
        "crl_files": prepared.crls.iter().map(|c| json!({"origin": c.origin, "sha256": c.sha256})).collect::<Vec<_>>(),
        "ocsp_files": prepared.ocsp.iter().map(|c| json!({"origin": c.origin, "sha256": c.sha256})).collect::<Vec<_>>(),
        "online": v.online,
        "p12_password": if opts.p12_password.is_some() { "supplied (not recorded)" } else { "none" },
        "openssl": certs::openssl_version(),
    });
    Ok((prepared, audit))
}

/// What the per-item stage found; kept until the cross-item stage.
#[derive(Clone, Debug, Default)]
pub struct ItemScan {
    pub kind: Option<InputKind>,
    pub parsed: Option<ParsedInput>,
    /// The item's bytes, kept only for timestamp tokens (verified in the cross-item stage).
    pub token: Option<Vec<u8>>,
    /// True when the item takes part in the certificate stage (chain.json is written for it).
    pub crypto: bool,
    /// (operation, error) of every certificate-layer call that failed or is not implemented.
    pub errors: Vec<(String, String)>,
    /// For the audit entry: second-pass re-hash.
    pub rehash: Value,
}

pub fn severity(s: &str) -> Severity {
    match s {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// A certificate-layer signal as a finding (codes and parameters are worded in i18n).
pub fn finding(sig: &Signal) -> Finding {
    let mut f = Finding::new(&sig.code, severity(&sig.severity));
    for (k, v) in &sig.params {
        f = f.with(k, v.clone());
    }
    f
}

fn push_unique(findings: &mut Vec<Finding>, f: Finding) {
    if !findings.contains(&f) {
        findings.push(f);
    }
}

/// A failed call → ANALYSIS_STEP_FAILED, and an entry in chain.json.
fn failed(scan: &mut ItemScan, findings: &mut Vec<Finding>, operation: &str, e: &CertError) {
    scan.errors.push((operation.to_string(), e.message.clone()));
    push_unique(
        findings,
        Finding::new(codes::ANALYSIS_STEP_FAILED, Severity::Medium)
            .with("operation", operation)
            .with("error", e.message.clone()),
    );
}

/// Per-item stage. `expected` = the first-pass digest the second read must reproduce.
pub fn analyze_item(
    path: &Path,
    file_name: &str,
    size: u64,
    head: &[u8],
    expected: Option<(HashAlgo, &str)>,
    opts: &CertOptions,
) -> (Analysis, ItemScan) {
    let mut a = analyze(file_name, size, head);
    let mut scan = ItemScan::default();
    if size == 0 {
        return (a, scan);
    }
    if size > MAX_CRYPTO_BYTES {
        a.findings.push(
            Finding::new(codes::CRYPTO_INPUT_NOT_RECOGNISED, Severity::Info).with(
                "kind",
                format!("larger than {} MiB, not read", MAX_CRYPTO_BYTES >> 20),
            ),
        );
        return (a, scan);
    }
    // Second, read-only pass: the whole item is needed to parse it. Re-hashed and compared with the first pass.
    let mut data = Vec::with_capacity(size as usize);
    let read =
        std::fs::File::open(path).and_then(|f| f.take(MAX_CRYPTO_BYTES + 1).read_to_end(&mut data));
    if let Err(e) = read {
        let ce = CertError::new(ErrorKind::Io, e.to_string());
        failed(&mut scan, &mut a.findings, "read", &ce);
        return (a, scan);
    }
    if let Some((algo, want)) = expected {
        let got = hash_bytes(&data, algo);
        scan.rehash = json!({"algorithm": algo.name(), "bytes": data.len(), "matches_first_pass": got == want});
        if got != want {
            a.findings.push(
                Finding::new(codes::EVIDENCE_CHANGED_DURING_READ, Severity::High)
                    .with("algorithm", algo.name())
                    .with("expected", want)
                    .with("actual", got),
            );
        }
    }
    let sniffed = match certs::sniff(&data) {
        Ok(s) => s,
        Err(e) => {
            scan.crypto = true;
            failed(&mut scan, &mut a.findings, "sniff", &e);
            return (a, scan);
        }
    };
    let kind = sniffed.kind.0;
    scan.kind = Some(kind);
    if kind == InputKind::Unknown {
        a.findings.push(
            Finding::new(codes::CRYPTO_INPUT_NOT_RECOGNISED, Severity::Info).with(
                "kind",
                a.detected_type.clone().unwrap_or_else(|| "unknown".into()),
            ),
        );
        return (a, scan);
    }
    scan.crypto = true;
    a.detected_type = Some(kind.label().to_string());
    // The inventory checks (extension vs content) do not apply to cryptographic objects (.cer/.crt/.pem/.p7b...).
    a.findings
        .retain(|f| f.code != "EXTENSION_MISMATCH" && f.code != "EXECUTABLE_CONTENT");
    match certs::parse_any(&data, opts.p12_password.as_ref()) {
        Ok(p) => {
            for s in &p.signals {
                push_unique(&mut a.findings, finding(s));
            }
            if kind == InputKind::TimestampToken {
                scan.token = Some(data);
            }
            scan.parsed = Some(p);
        }
        Err(e) if e.kind == ErrorKind::Password && kind == InputKind::Pkcs12 => {
            scan.errors.push(("parse_any".into(), e.message.clone()));
            push_unique(
                &mut a.findings,
                Finding::new(codes::PKCS12_UNREADABLE, Severity::Medium)
                    .with("reason", e.message.clone()),
            );
        }
        Err(e) if e.kind == ErrorKind::Parse => {
            scan.errors.push(("parse_any".into(), e.message.clone()));
            push_unique(
                &mut a.findings,
                Finding::new(codes::CRYPTO_INPUT_UNPARSABLE, Severity::Medium)
                    .with("kind", kind.label())
                    .with("error", e.message.clone()),
            );
        }
        Err(e) => failed(&mut scan, &mut a.findings, "parse_any", &e),
    }
    (a, scan)
}

/// One item as the cross-item stage sees it.
pub struct StageItem<'a> {
    pub index: u64,
    pub file_name: String,
    pub scan: &'a mut ItemScan,
    pub findings: &'a mut Vec<Finding>,
}

/// Result of the cross-item stage for one item: what to write into its folder.
#[derive(Debug, Default)]
pub struct StageOutput {
    /// (file name, bytes): chain.json always for a crypto item, certificate.txt when certificates were parsed.
    pub files: Vec<(String, Vec<u8>)>,
    /// Small summary for the audit entry and technical.json.
    pub details: Value,
}

/// End-entity certificates of an item: those that issue no other certificate of the same item (a single
/// certificate is its own target).
fn targets(p: &ParsedInput) -> Vec<usize> {
    let certs = &p.certificates;
    (0..certs.len())
        .filter(|&i| {
            !certs.iter().enumerate().any(|(j, c)| {
                j != i && c.issuer == certs[i].subject && c.subject != certs[i].subject
            })
        })
        .collect()
}

fn stem(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Cross-item stage: chains, timestamp tokens and key matching, with every certificate of the run as untrusted
/// pool and every CRL / OCSP response of the run as revocation source.
pub fn cross_item_stage(
    items: &mut [StageItem],
    prepared: &Prepared,
    opts: &CertOptions,
) -> Vec<StageOutput> {
    let mut pool: Vec<Vec<u8>> = vec![];
    let mut crls = prepared.crls.clone();
    let mut ocsp = prepared.ocsp.clone();
    // (spki sha256, item index, file name, subject) of every certificate, for key matching.
    let mut cert_keys: Vec<(String, u64, String, String)> = vec![];
    for it in items.iter() {
        if let Some(p) = &it.scan.parsed {
            let embedded = p
                .ocsp
                .iter()
                .flat_map(|o| &o.certificates)
                .chain(p.timestamp.iter().flat_map(|t| &t.certificates));
            for c in p.certificates.iter().chain(embedded) {
                if !c.der.is_empty() && !pool.contains(&c.der) {
                    pool.push(c.der.clone());
                }
            }
            for c in &p.certificates {
                cert_keys.push((
                    c.key.spki_sha256.clone(),
                    it.index,
                    it.file_name.clone(),
                    c.subject.clone(),
                ));
            }
            for c in &p.crls {
                crls.push(LabeledDer::new(format!("item:{}", it.index), c.der.clone()));
            }
            if let Some(o) = &p.ocsp {
                ocsp.push(LabeledDer::new(format!("item:{}", it.index), o.der.clone()));
            }
        }
    }
    let v = &opts.validation;
    let mut out = vec![];
    for it in items.iter_mut() {
        if !it.scan.crypto {
            out.push(StageOutput::default());
            continue;
        }
        let mut verdicts = vec![];
        let mut texts = vec![];
        let mut timestamp = Value::Null;
        let mut key_match = Value::Null;
        if let (Some(e), Some(_)) = (&prepared.anchor_error, &it.scan.parsed) {
            let e = e.clone();
            failed(it.scan, it.findings, "resolve_anchors", &e);
        }
        let parsed = it.scan.parsed.clone();
        if let Some(p) = &parsed {
            for &t in &targets(p) {
                let req = ChainRequest {
                    target_der: &p.certificates[t].der,
                    untrusted_der: &pool,
                    anchors: &prepared.anchors,
                    crls: &crls,
                    ocsp: &ocsp,
                    signing_time: None,
                };
                match certs::validate_chain(&req, v) {
                    Ok(verdict) => {
                        for s in &verdict.signals {
                            push_unique(it.findings, finding(s));
                        }
                        verdicts.push(verdict);
                    }
                    Err(e) => {
                        failed(it.scan, it.findings, "validate_chain", &e);
                        break;
                    }
                }
            }
            for (n, c) in p.certificates.iter().enumerate() {
                match certs::certificate_text(&c.der) {
                    Ok(t) => texts.push(format!(
                        "# Certificate {} of {}  SHA-256 {}\n{}",
                        n + 1,
                        p.certificates.len(),
                        c.sha256,
                        t
                    )),
                    Err(e) => {
                        failed(it.scan, it.findings, "certificate_text", &e);
                        break;
                    }
                }
            }
            if let Some(token) = it.scan.token.clone() {
                let req = ChainRequest {
                    untrusted_der: &pool,
                    anchors: &prepared.anchors,
                    crls: &crls,
                    ocsp: &ocsp,
                    ..Default::default()
                };
                match certs::verify_timestamp_token(&token, None, &req, v) {
                    Ok(tv) => {
                        for s in &tv.signals {
                            push_unique(it.findings, finding(s));
                        }
                        timestamp = json!(tv);
                    }
                    Err(e) => failed(it.scan, it.findings, "verify_timestamp_token", &e),
                }
            }
            if let Some(k) = &p.private_key {
                key_match = key_findings(k, it.index, &it.file_name, &cert_keys, it.findings);
            }
        }
        let codes: Vec<&str> = it.findings.iter().map(|f| f.code.as_str()).collect();
        // --online: every URL fetched for this item (its chains and its timestamp's TSA chain).
        let mut fetches: Vec<&certs::OnlineFetch> =
            verdicts.iter().flat_map(|v| &v.online_fetches).collect();
        let ts_fetches: Vec<certs::OnlineFetch> = timestamp
            .pointer("/signer_chain/online_fetches")
            .and_then(|f| serde_json::from_value(f.clone()).ok())
            .unwrap_or_default();
        fetches.extend(ts_fetches.iter());
        let chain = json!({
            "schema": SCHEMA_CHAIN,
            "item": it.index,
            "kind": it.scan.kind.map(|k| k.name()),
            "at": v.at.describe(),
            "purpose": v.purpose.name(),
            "anchors": v.anchors.iter().map(|a| a.describe()).collect::<Vec<_>>(),
            "openssl": certs::openssl_version(),
            "certificates": parsed.as_ref().map(|p| &p.certificates),
            "verdicts": verdicts,
            "timestamp": timestamp,
            "key_match": key_match,
            "errors": it.scan.errors.iter().map(|(o, e)| json!({"operation": o, "error": e})).collect::<Vec<_>>(),
        });
        let mut files = vec![(
            "chain.json".to_string(),
            crate::report::pretty(&chain).to_vec(),
        )];
        if !texts.is_empty() {
            files.push(("certificate.txt".into(), texts.join("\n").into_bytes()));
        }
        let details = json!({
            "kind": it.scan.kind.map(|k| k.name()),
            "certificates": parsed.as_ref().map(|p| p.certificates.len()).unwrap_or(0),
            "verdicts": verdicts.iter().map(|v| json!({"status": v.status, "openssl_code": v.openssl_code, "openssl_reason": v.openssl_reason, "depths": v.nodes.len()})).collect::<Vec<_>>(),
            "errors": it.scan.errors.iter().map(|(o, _)| o).collect::<Vec<_>>(),
            "codes": codes,
            "online_fetches": fetches,
        });
        out.push(StageOutput { files, details });
    }
    out
}

/// KEY_MATCHES_CERTIFICATE (any certificate of the run has the key's SPKI), else KEY_DOES_NOT_MATCH against the
/// certificate supplied with it (same item, or an item with the same file stem: `leaf.key` + `leaf.crt`), else
/// KEY_NOT_PAIRED.
fn key_findings(
    k: &certs::KeyInfo,
    index: u64,
    file_name: &str,
    cert_keys: &[(String, u64, String, String)],
    findings: &mut Vec<Finding>,
) -> Value {
    let matching: Vec<String> = cert_keys
        .iter()
        .filter(|(spki, ..)| !spki.is_empty() && *spki == k.spki_sha256)
        .map(|(_, _, f, s)| format!("{} ({})", s, f))
        .collect();
    if !matching.is_empty() {
        push_unique(
            findings,
            Finding::new(codes::KEY_MATCHES_CERTIFICATE, Severity::Info)
                .with("key", file_name)
                .with("certificates", crate::report::capped_list(&matching, 10)),
        );
        return json!({"matches": true, "certificates": matching});
    }
    let paired: Vec<String> = cert_keys
        .iter()
        .filter(|(_, i, f, _)| *i == index || stem(f) == stem(file_name))
        .map(|(_, _, f, s)| format!("{} ({})", s, f))
        .collect();
    if let Some(first) = paired.first() {
        push_unique(
            findings,
            Finding::new(codes::KEY_DOES_NOT_MATCH, Severity::High)
                .with("key", file_name)
                .with("certificate", first.clone()),
        );
        json!({"matches": false, "paired_with": paired})
    } else {
        push_unique(
            findings,
            Finding::new(codes::KEY_NOT_PAIRED, Severity::Info).with("key", file_name),
        );
        json!({"matches": false, "paired_with": []})
    }
}

/// The certificate layer's run-level facts for environment.json.
pub fn environment() -> Value {
    json!({"openssl": certs::openssl_version(), "certs_layer": "rv-certcheck-certs"})
}

/// Codes worded in the catalogue (for the completeness test and the GUI legend).
pub fn catalogue_codes() -> BTreeMap<&'static str, &'static str> {
    codes::FINDINGS.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_certcheck_certs::{CertInfo, KeyInfo};

    #[test]
    fn catalogue_is_complete_in_every_language() {
        for lang in crate::i18n::LANGS {
            let c = crate::i18n::catalog(lang);
            for (code, _) in codes::FINDINGS {
                let (title, shows, dnp) = c.finding(code, &BTreeMap::new());
                assert!(
                    title != *code && shows != *code && dnp != *code,
                    "{lang}: finding {code} lacks title / shows / does_not_prove"
                );
            }
            for l in codes::LIMITATIONS {
                assert!(
                    c.limitation(l) != *l && !c.limitation(l).is_empty(),
                    "{lang}: limitation {l} is not worded"
                );
            }
            let (_, rakvor, _) = c.finding(codes::CERT_ISSUED_BY_RAKVOR_INTERNAL, &BTreeMap::new());
            assert!(
                rakvor.contains("527") && rakvor.contains("28") && rakvor.contains("eIDAS"),
                "{lang}: CERT_ISSUED_BY_RAKVOR_INTERNAL must cite Ley 527 art. 28 and eIDAS"
            );
        }
    }

    #[test]
    fn online_is_accepted_and_recorded() {
        let mut o = CertOptions::default();
        o.validation.online = true;
        assert!(check_options(&o).is_ok());
        let (_, audit) = prepare(&o).unwrap();
        assert_eq!(audit["online"], true);
    }

    #[test]
    fn unparsable_crypto_items_are_reported_not_skipped() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("leaf.crt");
        std::fs::write(
            &p,
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let data = std::fs::read(&p).unwrap();
        let want = hash_bytes(&data, HashAlgo::Sha256);
        let (a, scan) = analyze_item(
            &p,
            "leaf.crt",
            data.len() as u64,
            &data,
            Some((HashAlgo::Sha256, &want)),
            &CertOptions::default(),
        );
        assert_eq!(scan.rehash["matches_first_pass"], true);
        assert!(scan.crypto);
        assert!(
            a.findings
                .iter()
                .any(|f| f.code == codes::CRYPTO_INPUT_UNPARSABLE),
            "{:?}",
            a.findings
        );
        assert!(
            !a.findings
                .iter()
                .any(|f| f.code == codes::ANALYSIS_NOT_IMPLEMENTED)
        );
    }

    #[test]
    fn key_matching_rules() {
        let k = KeyInfo {
            spki_sha256: "aa".into(),
            ..Default::default()
        };
        let mut f = vec![];
        key_findings(
            &k,
            2,
            "leaf.key",
            &[("aa".into(), 1, "leaf.crt".into(), "CN=leaf".into())],
            &mut f,
        );
        assert_eq!(f[0].code, codes::KEY_MATCHES_CERTIFICATE);
        let mut f = vec![];
        key_findings(
            &k,
            2,
            "leaf.key",
            &[("bb".into(), 1, "leaf.crt".into(), "CN=leaf".into())],
            &mut f,
        );
        assert_eq!(f[0].code, codes::KEY_DOES_NOT_MATCH);
        let mut f = vec![];
        key_findings(
            &k,
            2,
            "other.key",
            &[("bb".into(), 1, "leaf.crt".into(), "CN=leaf".into())],
            &mut f,
        );
        assert_eq!(f[0].code, codes::KEY_NOT_PAIRED);
        let _ = CertInfo::default();
    }

    #[test]
    fn end_entity_targets() {
        let c = |s: &str, i: &str| CertInfo {
            subject: s.into(),
            issuer: i.into(),
            ..Default::default()
        };
        let p = ParsedInput {
            certificates: vec![
                c("CN=root", "CN=root"),
                c("CN=leaf", "CN=int"),
                c("CN=int", "CN=root"),
            ],
            ..Default::default()
        };
        assert_eq!(targets(&p), vec![1]);
    }
}
