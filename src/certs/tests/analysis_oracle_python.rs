//! Agent A: Python `cryptography`'s path validator as a second, non-OpenSSL oracle (tests/oracle_chain.py; the
//! agreement rule is in its docstring). Verdicts are computed here without revocation data (cryptography does
//! not check revocation) for every certificate fixture at four dates, written to JSON and judged by the script.
//! Optional locally (skipped with a message when `cryptography` is missing); in CI (`CI` set) a missing Python
//! or `cryptography` fails the test. `RV_TEST_PYTHON` picks the interpreter (default python3).

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn der(name: &str) -> Vec<u8> {
    let p = root().join("tests/fixtures/openssl").join(name);
    openssl::x509::X509::from_pem(&std::fs::read(p).unwrap())
        .unwrap()
        .to_der()
        .unwrap()
}

#[test]
fn verdicts_agree_with_python_cryptography() {
    let anchors = vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", der("root.crt"))],
        ..Default::default()
    }];
    let untrusted = vec![der("intermediate.crt")];
    let mut cases = vec![];
    for f in [
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
    ] {
        for at in [
            "2026-06-01T00:00:00Z",
            "2024-06-01T00:00:00Z",
            "2028-06-01T00:00:00Z",
            "2031-06-01T00:00:00Z",
        ] {
            let t = der(f);
            let v = validate_chain(
                &ChainRequest {
                    target_der: &t,
                    untrusted_der: &untrusted,
                    anchors: &anchors,
                    ..Default::default()
                },
                &ValidationOptions {
                    at: AtTime::Fixed(at.into()),
                    ..Default::default()
                },
            )
            .unwrap();
            cases.push(serde_json::json!({
                "file": f,
                "at": at,
                "status": v.status,
                "codes": v.signals.iter().map(|s| s.code.clone()).collect::<Vec<_>>(),
                "errors": v.errors.iter().map(|e| (e.depth, e.code)).collect::<Vec<_>>(),
            }));
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("verdicts.json");
    std::fs::write(&json, serde_json::to_vec_pretty(&cases).unwrap()).unwrap();
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let ci = std::env::var_os("CI").is_some();
    let out = match std::process::Command::new(&py)
        .arg(root().join("tests/oracle_chain.py"))
        .arg(&json)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            assert!(!ci, "python ({py}) is required in CI: {e}");
            eprintln!("skipping: no python ({py}): {e}");
            return;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    match out.status.code() {
        Some(0) => eprintln!("{text}"),
        Some(4) if !ci => eprintln!("skipping: python cryptography is not installed ({text})"),
        _ => panic!("python cryptography oracle disagrees:\n{text}"),
    }
}
