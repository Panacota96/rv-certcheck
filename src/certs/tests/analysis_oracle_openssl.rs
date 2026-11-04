//! Agent A: the OpenSSL command line as an independent oracle (no rv-certcheck code builds its inputs).
//!
//! For every certificate fixture × validation time × purpose × with/without the CRL, `validate_chain` must give
//! the same first code as `openssl verify -attime -purpose [-crl_check[_all] -CRLfile] -CAfile -untrusted`, the
//! same success/failure (exit status), and every error the CLI prints (its callback continues on some errors)
//! must be among the verdict's `errors`. The CRL flags passed to the CLI are the ones the verdict says it used.
//! Also: `openssl crl -text`, `openssl ocsp -respin -resp_text` and `openssl ts -verify` against parse_any,
//! check_revocation and verify_timestamp_token.
//!
//! Needs the `openssl` binary (RV_OPENSSL overrides the path). Skipped with a message when it is missing,
//! except in CI (`CI` set), where a missing binary fails the test.

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openssl")
        .join(name)
}
fn der(name: &str) -> Vec<u8> {
    openssl::x509::X509::from_pem(&std::fs::read(fx(name)).unwrap())
        .unwrap()
        .to_der()
        .unwrap()
}

fn openssl_bin() -> Option<String> {
    let bin = std::env::var("RV_OPENSSL").unwrap_or_else(|_| "openssl".into());
    match Command::new(&bin).arg("version").output() {
        Ok(o) if o.status.success() => Some(bin),
        _ => {
            if std::env::var_os("CI").is_some() {
                panic!("the openssl command line is required in CI for the oracle test");
            }
            eprintln!("skipping: no openssl command line ({bin})");
            None
        }
    }
}

/// (exit ok, [(depth, code)]) from `openssl verify` output.
fn cli_verify(bin: &str, args: &[String]) -> (bool, Vec<(u32, i32)>) {
    let o = Command::new(bin).arg("verify").args(args).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    let mut errs = vec![];
    for l in text.lines() {
        // error 10 at 0 depth lookup: certificate has expired
        if let Some(rest) = l.strip_prefix("error ") {
            let mut it = rest.split_whitespace();
            if let (Some(c), Some("at"), Some(d)) = (it.next(), it.next(), it.next()) {
                if let (Ok(c), Ok(d)) = (c.parse(), d.parse()) {
                    errs.push((d, c));
                }
            }
        }
    }
    (o.status.success(), errs)
}

fn supports_purpose(bin: &str, p: &str) -> bool {
    let o = Command::new(bin)
        .args(["verify", "-purpose", p, "-CAfile"])
        .arg(fx("root.crt"))
        .arg(fx("root.crt"))
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&o.stderr).to_lowercase();
    !(t.contains("invalid purpose") || t.contains("unknown purpose"))
}

#[test]
fn validate_chain_agrees_with_openssl_verify_on_every_fixture() {
    let Some(bin) = openssl_bin() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let crl_der = std::fs::read(fx("intermediate.crl")).unwrap();
    let crl_pem = tmp.path().join("crl.pem");
    std::fs::write(
        &crl_pem,
        openssl::x509::X509Crl::from_der(&crl_der)
            .unwrap()
            .to_pem()
            .unwrap(),
    )
    .unwrap();
    let anchors = vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", der("root.crt"))],
        ..Default::default()
    }];
    let untrusted = vec![der("intermediate.crt")];
    let crls = vec![LabeledDer::new("file:intermediate.crl", crl_der)];
    let targets = [
        "leaf.crt",
        "leaf-expired.crt",
        "leaf-not-yet-valid.crt",
        "leaf-revoked.crt",
        "leaf-rsa1024.crt",
        "leaf-sha1.crt",
        "leaf-mismatch.crt",
        "leaf-wrong-root.crt",
        "tsa.crt",
        "intermediate.crt",
        "root.crt",
        "other-root.crt",
    ];
    let times = [
        ("2026-06-01T00:00:00Z", 1_780_272_000i64),
        ("2024-06-01T00:00:00Z", 1_717_200_000),
        ("2026-02-15T00:00:00Z", 1_771_113_600),
        ("2028-06-01T00:00:00Z", 1_843_430_400),
    ];
    let mut purposes = vec![
        Purpose::Any,
        Purpose::TlsServer,
        Purpose::TlsClient,
        Purpose::Email,
        Purpose::Timestamping,
    ];
    if supports_purpose(&bin, "codesign") {
        purposes.push(Purpose::CodeSigning);
    } else {
        eprintln!(
            "note: this openssl CLI has no -purpose codesign (OpenSSL < 3.2): code-signing not compared"
        );
    }
    let mut rows = vec![];
    let mut problems = vec![];
    for t in targets {
        for (at, epoch) in times {
            for &p in &purposes {
                for with_crl in [false, true] {
                    let target = der(t);
                    let req = ChainRequest {
                        target_der: &target,
                        untrusted_der: &untrusted,
                        anchors: &anchors,
                        crls: if with_crl { &crls } else { &[] },
                        ..Default::default()
                    };
                    let v = validate_chain(
                        &req,
                        &ValidationOptions {
                            at: AtTime::Fixed(at.into()),
                            purpose: p,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    let mut args: Vec<String> = vec!["-attime".into(), epoch.to_string()];
                    if let Some(n) = p.openssl_name() {
                        args.extend(["-purpose".into(), n.into()]);
                    }
                    let crl_note = v
                        .notes
                        .iter()
                        .find(|n| n.starts_with("OpenSSL CRL checking:"))
                        .cloned()
                        .unwrap_or_default();
                    if crl_note.contains("CRL_CHECK_ALL") {
                        args.push("-crl_check_all".into());
                    } else if crl_note.contains("CRL_CHECK") {
                        args.push("-crl_check".into());
                    }
                    if args.iter().any(|a| a.starts_with("-crl_check")) {
                        args.extend(["-CRLfile".into(), crl_pem.display().to_string()]);
                    }
                    args.extend([
                        "-CAfile".into(),
                        fx("root.crt").display().to_string(),
                        "-untrusted".into(),
                        fx("intermediate.crt").display().to_string(),
                        fx(t).display().to_string(),
                    ]);
                    let (ok, cli) = cli_verify(&bin, &args);
                    let cli_first = cli.first().map(|e| e.1).unwrap_or(0);
                    let mine: Vec<(u32, i32)> =
                        v.errors.iter().map(|e| (e.depth, e.code)).collect();
                    let case = format!("{t} at {at} purpose {} crl {with_crl}", p.name());
                    if v.openssl_code != cli_first {
                        problems.push(format!(
                            "{case}: first code {} vs openssl {cli_first} ({cli:?})",
                            v.openssl_code
                        ));
                    }
                    if ok != mine.is_empty() {
                        problems.push(format!(
                            "{case}: openssl exit ok={ok}, verdict errors {mine:?}"
                        ));
                    }
                    for e in &cli {
                        if !mine.contains(e) {
                            problems
                                .push(format!("{case}: openssl reported {e:?}, not in {mine:?}"));
                        }
                    }
                    rows.push(format!(
                        "{t}\t{at}\t{}\t{with_crl}\t{}\t{:?}\t{cli_first}\t{cli:?}\t{:?}",
                        p.name(),
                        v.openssl_code,
                        mine,
                        v.status
                    ));
                }
            }
        }
    }
    let out = std::env::var_os("RV_ORACLE_TSV").map(PathBuf::from);
    if let Some(o) = out {
        std::fs::write(
            o,
            format!(
                "file\tat\tpurpose\tcrl\tverdict_first\tverdict_errors\topenssl_first\topenssl_errors\tstatus\n{}\n",
                rows.join("\n")
            ),
        )
        .unwrap();
    }
    assert!(rows.len() >= 12 * 4 * 5 * 2);
    assert!(
        problems.is_empty(),
        "{} disagreements:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn crl_ocsp_and_ts_agree_with_the_openssl_cli() {
    let Some(bin) = openssl_bin() else { return };
    // openssl crl -text: serial, revocation date, reason.
    let o = Command::new(&bin)
        .args(["crl", "-inform", "DER", "-noout", "-text", "-in"])
        .arg(fx("intermediate.crl"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    let p = parse_any(&std::fs::read(fx("intermediate.crl")).unwrap(), None).unwrap();
    let c = &p.crls[0];
    for r in &c.revoked {
        assert!(
            text.to_lowercase()
                .contains(&format!("serial number: {}", r.serial_hex)),
            "{text}"
        );
    }
    assert!(text.contains("Revocation Date: Feb  1 00:00:00 2026 GMT"));
    assert!(text.contains("Key Compromise") && c.revoked[0].reason == "keyCompromise");
    assert!(
        text.contains("Last Update: Mar  1 00:00:00 2026 GMT")
            && c.this_update == "2026-03-01T00:00:00Z"
    );
    assert!(text.contains("Next Update: Jan  1 00:00:00 2027 GMT"));
    assert_eq!(c.next_update.as_deref(), Some("2027-01-01T00:00:00Z"));
    assert!(
        text.contains(&format!(
            "X509v3 CRL Number: \n                {}",
            c.crl_number.clone().unwrap()
        )) || text.contains(&c.crl_number.clone().unwrap())
    );

    // openssl ocsp -respin, verified against the issuer: revoked, with time and reason.
    let o = Command::new(&bin)
        .args(["ocsp", "-respin"])
        .arg(fx("leaf-revoked.ocsp"))
        .args(["-resp_text", "-issuer"])
        .arg(fx("intermediate.crt"))
        .arg("-cert")
        .arg(fx("leaf-revoked.crt"))
        .arg("-no_nonce")
        .arg("-CAfile")
        .arg(fx("intermediate.crt"))
        .arg("-partial_chain")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(text.contains("Response verify OK"), "{text}");
    assert!(text.contains(": revoked"), "{text}");
    let r = check_revocation(
        &der("leaf-revoked.crt"),
        &der("intermediate.crt"),
        &[],
        &[LabeledDer::new(
            "file:leaf-revoked.ocsp",
            std::fs::read(fx("leaf-revoked.ocsp")).unwrap(),
        )],
        "2026-06-01T00:00:00Z",
    )
    .unwrap();
    match r {
        RevocationStatus::Revoked {
            revoked_at, reason, ..
        } => {
            assert!(text.contains("Revocation Time: Feb  1 00:00:00 2026 GMT"));
            assert_eq!(revoked_at, "2026-02-01T00:00:00Z");
            assert!(text.contains("keyCompromise") && reason == "keyCompromise");
        }
        other => panic!("{other:?}"),
    }

    // openssl ts -verify with the right and the wrong data.
    let anchors = vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", der("root.crt"))],
        ..Default::default()
    }];
    let untrusted = vec![der("intermediate.crt")];
    let tmp = tempfile::tempdir().unwrap();
    let other = tmp.path().join("other.txt");
    std::fs::write(&other, b"other data").unwrap();
    for (data, want_ok) in [(fx("data.txt"), true), (other.clone(), false)] {
        for tok in ["data.tsr", "data.tst"] {
            let mut cmd = Command::new(&bin);
            cmd.args(["ts", "-verify", "-data"]).arg(&data);
            if tok.ends_with(".tst") {
                cmd.arg("-token_in");
            }
            let o = cmd
                .arg("-in")
                .arg(fx(tok))
                .arg("-CAfile")
                .arg(fx("root.crt"))
                .arg("-untrusted")
                .arg(fx("intermediate.crt"))
                .output()
                .unwrap();
            let cli_ok = String::from_utf8_lossy(&o.stdout).contains("Verification: OK");
            let v = verify_timestamp_token(
                &std::fs::read(fx(tok)).unwrap(),
                Some(&std::fs::read(&data).unwrap()),
                &ChainRequest {
                    untrusted_der: &untrusted,
                    anchors: &anchors,
                    ..Default::default()
                },
                &ValidationOptions::default(),
            )
            .unwrap();
            let mine_ok = v
                .signals
                .iter()
                .any(|s| s.code == codes::TIMESTAMP_TOKEN_VALID);
            assert_eq!(
                (cli_ok, mine_ok),
                (want_ok, want_ok),
                "{tok} with {}: {:?}",
                data.display(),
                v.signals
            );
        }
    }
}
