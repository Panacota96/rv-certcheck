//! `analyze` pairs a timestamp token with the evidence file of the same stem (data.tsr ↔ data.txt) and checks
//! the message imprint against it; a lone token is valid but not linked to any file (imprint_checked=no);
//! `--at signing-time` adds a run-level note to the reports and the audit log.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Copies the sample's TSA chain and token (plus `extra` files) into a fresh evidence folder and analyzes it.
/// Returns (reports folder, findings of data.tsr).
fn run(extra: &[(&str, &[u8])], at: &str) -> (tempfile::TempDir, PathBuf, Vec<Value>) {
    let ev = root().join("examples/sample/evidence");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in");
    std::fs::create_dir(&input).unwrap();
    for f in ["data.tsr", "tsa.crt", "intermediate.crt"] {
        std::fs::copy(ev.join(f), input.join(f)).unwrap();
    }
    for (name, data) in extra {
        std::fs::write(input.join(name), data).unwrap();
    }
    let out = dir.path().join("out");
    let o = Command::cargo_bin("rv-certcheck")
        .unwrap()
        .env("RV_NO_TIMESTAMP", "1")
        .arg("analyze")
        .arg("-i")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["--progress", "none", "--at", at, "--anchor"])
        .arg(root().join("examples/sample/anchors/rakvor-lab-root.crt"))
        .output()
        .unwrap();
    assert!(
        matches!(o.status.code(), Some(0) | Some(3)),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let reports = std::fs::read_dir(out.join("reports"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut findings = vec![];
    for item in std::fs::read_dir(reports.join("items")).unwrap() {
        let tech: Value = serde_json::from_str(
            &std::fs::read_to_string(item.unwrap().path().join("technical.json")).unwrap(),
        )
        .unwrap();
        if tech["item"]["file_name"] == "data.tsr" {
            findings = tech["findings"].as_array().unwrap().clone();
        }
    }
    (dir, reports, findings)
}

fn find<'a>(f: &'a [Value], code: &str) -> Option<&'a Value> {
    f.iter().find(|x| x["code"] == code)
}

const AT: &str = "2026-06-01T00:00:00Z";

#[test]
fn token_paired_with_its_data_file_checks_the_imprint() {
    let data = std::fs::read(root().join("examples/sample/evidence/data.txt")).unwrap();
    let (_d, _r, f) = run(&[("data.txt", &data)], AT);
    let v = find(&f, "TIMESTAMP_TOKEN_VALID").unwrap_or_else(|| panic!("{f:#?}"));
    assert_eq!(v["params"]["imprint_checked"], "yes");
    assert_eq!(v["params"]["imprint_file"], "data.txt");
    assert!(find(&f, "TIMESTAMP_TOKEN_INVALID").is_none());
    assert!(
        !v["text"]["en"]["shows"].as_str().unwrap().contains("%{"),
        "{v:#?}"
    );
}

#[test]
fn token_paired_with_a_different_file_is_invalid() {
    let (_d, _r, f) = run(&[("data.bin", b"not the timestamped data\n")], AT);
    let v = find(&f, "TIMESTAMP_TOKEN_INVALID").unwrap_or_else(|| panic!("{f:#?}"));
    assert!(
        v["params"]["reason"]
            .as_str()
            .unwrap()
            .contains("imprint does not match data.bin"),
        "{v:#?}"
    );
    assert!(find(&f, "TIMESTAMP_TOKEN_VALID").is_none());
}

#[test]
fn lone_token_is_valid_but_not_linked_to_a_file() {
    let (_d, _r, f) = run(&[], AT);
    let v = find(&f, "TIMESTAMP_TOKEN_VALID").unwrap_or_else(|| panic!("{f:#?}"));
    assert_eq!(v["params"]["imprint_checked"], "no");
    assert_eq!(v["params"]["imprint_file"], "none");
    assert!(
        v["text"]["en"]["shows"]
            .as_str()
            .unwrap()
            .contains("not linked to any file")
    );
}

#[test]
fn signing_time_adds_a_run_level_note() {
    let (_d, reports, f) = run(&[], "signing-time");
    // The token's TSA chain is judged at its genTime.
    assert!(find(&f, "TIMESTAMP_TOKEN_VALID").is_some(), "{f:#?}");
    let stats: Value =
        serde_json::from_str(&std::fs::read_to_string(reports.join("statistics.json")).unwrap())
            .unwrap();
    assert!(
        stats["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "AT_SIGNING_TIME_TOKENS_ONLY_V01"),
        "{}",
        stats["limitations"]
    );
    let (_d2, reports2, _) = run(&[], AT);
    let stats2 = std::fs::read_to_string(reports2.join("statistics.json")).unwrap();
    assert!(!stats2.contains("AT_SIGNING_TIME_TOKENS_ONLY_V01"));
}
