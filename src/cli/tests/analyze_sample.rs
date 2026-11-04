//! Acceptance test of the analysis (agent A, through core): `analyze` on examples/sample must report the findings
//! listed in examples/sample/expected_findings.json (made independently with the OpenSSL CLI). Fails if the
//! certificate layer answers ANALYSIS_NOT_IMPLEMENTED (both sides are implemented). Architect-owned: do not
//! weaken. (Regenerate the file with RV_BLESS=1 python3 tests/bless_expected_findings.py BIN and review it.)

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

#[test]
fn sample_findings_match_the_independent_expectations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("examples/sample/expected_findings.json")).unwrap(),
    )
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("rv-certcheck").unwrap();
    cmd.current_dir(&root)
        .env("RV_NO_TIMESTAMP", "1")
        .args([
            "analyze",
            "-i",
            "examples/sample/evidence",
            "--progress",
            "none",
            "-o",
        ])
        .arg(out.path());
    for a in expected["args"].as_array().unwrap() {
        cmd.arg(a.as_str().unwrap());
    }
    let o = cmd.output().unwrap();
    let code = o.status.code();
    assert!(
        matches!(code, Some(0) | Some(3)),
        "exit {:?}: {}",
        code,
        String::from_utf8_lossy(&o.stderr)
    );
    let reports = std::fs::read_dir(out.path().join("reports"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut codes_by_file = std::collections::BTreeMap::new();
    for item in std::fs::read_dir(reports.join("items")).unwrap() {
        let tech: Value = serde_json::from_str(
            &std::fs::read_to_string(item.unwrap().path().join("technical.json")).unwrap(),
        )
        .unwrap();
        let codes: Vec<String> = tech["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["code"].as_str().unwrap().to_string())
            .collect();
        codes_by_file.insert(
            tech["item"]["file_name"].as_str().unwrap().to_string(),
            codes,
        );
    }
    // The certificate layer has no stub any more: a NotImplemented answer is a failure, not a skip.
    assert!(
        !codes_by_file
            .values()
            .flatten()
            .any(|c| c == "ANALYSIS_NOT_IMPLEMENTED"),
        "ANALYSIS_NOT_IMPLEMENTED in {codes_by_file:?}"
    );
    let mut problems = vec![];
    for (file, want) in expected["items"].as_object().unwrap() {
        let got = codes_by_file.get(file).cloned().unwrap_or_default();
        for c in want["expected"].as_array().unwrap() {
            if !got.iter().any(|g| g == c.as_str().unwrap()) {
                problems.push(format!("{file}: missing {c} (got {got:?})"));
            }
        }
        for c in want["forbidden"].as_array().unwrap() {
            if got.iter().any(|g| g == c.as_str().unwrap()) {
                problems.push(format!("{file}: must not report {c} (got {got:?})"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert_eq!(
        code,
        Some(3),
        "the sample has high findings (expired, revoked...)"
    );
}
