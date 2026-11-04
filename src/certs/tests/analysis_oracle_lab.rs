//! Agent A: agent B's seeded lab set as a third oracle. `lab::make --set full --seed 1` writes 13 cases, each
//! with the validation settings to use and the codes the analysis must (`expected_codes`) and must not
//! (`forbidden_codes`) report, plus what `openssl verify` answers (`openssl_verify_code`). The analysis is run
//! here exactly as core runs it for a case: parse-time signals of the first file, `validate_chain` with the
//! case's anchors / CRLs / OCSP / purpose / date and its other `.crt` files as untrusted, and `match_key` for a
//! key shipped with the certificate (core reports KEY_MATCHES_CERTIFICATE / KEY_DOES_NOT_MATCH from it).

use rv_certcheck_certs::*;
use std::collections::BTreeSet;

#[test]
fn every_lab_case_gives_its_expected_codes_and_openssl_code() {
    let dir = tempfile::tempdir().unwrap();
    let set = dir.path().join("full");
    let m = lab::make(&LabSetSpec {
        name: "full".into(),
        seed: 1,
        base_time: "2026-01-01T00:00:00Z".into(),
        out_dir: set.clone(),
    })
    .unwrap();
    assert_eq!(m.cases.len(), 13);
    let read = |rel: &str| std::fs::read(set.join(rel)).unwrap();
    let pem_or_der = |rel: &str| {
        let b = read(rel);
        openssl::x509::X509::from_pem(&b)
            .or_else(|_| openssl::x509::X509::from_der(&b))
            .unwrap()
            .to_der()
            .unwrap()
    };
    let mut problems = vec![];
    let mut table = vec![];
    for c in &m.cases {
        let v = &c.validation;
        let mut got: BTreeSet<String> = BTreeSet::new();
        let first = read(&c.files[0]);
        let parsed = parse_any(&first, None).unwrap();
        got.extend(parsed.signals.iter().map(|s| s.code.clone()));
        let target = pem_or_der(&c.files[0]);
        let anchors = resolve_anchors(
            &v.anchors
                .iter()
                .map(|a| AnchorSpec::File { path: set.join(a) })
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        let untrusted: Vec<Vec<u8>> = c.files[1..]
            .iter()
            .filter(|f| f.ends_with(".crt"))
            .map(|f| pem_or_der(f))
            .collect();
        let crls: Vec<LabeledDer> = v
            .crls
            .iter()
            .map(|f| LabeledDer::new(format!("file:{f}"), read(f)))
            .collect();
        let ocsp: Vec<LabeledDer> = v
            .ocsp
            .iter()
            .map(|f| LabeledDer::new(format!("file:{f}"), read(f)))
            .collect();
        let verdict = validate_chain(
            &ChainRequest {
                target_der: &target,
                untrusted_der: &untrusted,
                anchors: &anchors,
                crls: &crls,
                ocsp: &ocsp,
                ..Default::default()
            },
            &ValidationOptions {
                at: AtTime::parse(&v.at).unwrap(),
                purpose: v.purpose,
                ..Default::default()
            },
        )
        .unwrap();
        got.extend(verdict.signals.iter().map(|s| s.code.clone()));
        for k in c.files.iter().filter(|f| f.ends_with(".key")) {
            let km = match_key(&read(k), None, &target).unwrap();
            got.insert(
                if km.matches {
                    codes::KEY_MATCHES_CERTIFICATE
                } else {
                    codes::KEY_DOES_NOT_MATCH
                }
                .to_string(),
            );
        }
        // Every lab certificate carries RAKVOR_POLICY_LAB (2.25.<UUID>.9.1), under the Rakvor arc.
        let rakvor = parsed
            .signals
            .iter()
            .find(|s| s.code == codes::CERT_ISSUED_BY_RAKVOR_INTERNAL);
        match rakvor {
            Some(s) if s.params["policy"] == RAKVOR_POLICY_LAB => {}
            other => problems.push(format!(
                "{}: Rakvor lab policy not detected ({other:?})",
                c.id
            )),
        }
        for e in &c.expected_codes {
            if !got.contains(e) {
                problems.push(format!("{}: missing {e} (got {got:?})", c.id));
            }
        }
        for f in &c.forbidden_codes {
            if got.contains(f) {
                problems.push(format!("{}: must not report {f} (got {got:?})", c.id));
            }
        }
        if verdict.openssl_code != c.openssl_verify_code {
            problems.push(format!(
                "{}: openssl code {} ({}), lab set says {}",
                c.id, verdict.openssl_code, verdict.openssl_reason, c.openssl_verify_code
            ));
        }
        table.push(format!(
            "{}\t{:?}\t{}\t{:?}",
            c.id, verdict.status, verdict.openssl_code, got
        ));
    }
    eprintln!("{}", table.join("\n"));
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
