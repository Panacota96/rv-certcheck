//! The worked examples in each command's `--help` (EXAMPLES:) really work: they run, in a temporary folder,
//! against copies of the repository's sample evidence and lab material. The sample paths of the examples
//! (D:\evidence, E:\CASE-014, E:\pki\..., the example run id, the example serial 5f3a09c1, the trust-list files,
//! ...) are mapped to that folder. Every subcommand that `docs-cli` documents (nested pki, csr, lab, keys, tokens
//! and trust-list commands included), plus `docs-cli` itself, is run in that order, so the PKI examples build on
//! each other: a root, an intermediate managed as its own CA folder, an examiner certificate, its revocation and
//! a CRL. The exceptions are in PARSE_ONLY (whole commands) and NEEDS (single examples that need a PKCS#11 token
//! or the network); they are parsed by the unit test of src/main.rs, which also fails when a hidden subcommand is
//! added that this list does not see. Key, CA and .p12 passwords are synthetic test values; the trust-list
//! snapshots go to the temporary folder (RV_CERTCHECK_DATA).

use assert_cmd::Command;
use rv_certcheck_core::{CASE_ROLE, CaseRole, HashAlgo, RunConfig, run};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

const TOOL: &str = "rv-certcheck";
/// Subcommands whose examples are not run here, with the reason. They are parsed by the unit test in src/main.rs.
const PARSE_ONLY: &[(&str, &str)] = &[
    ("timestamp", "needs an RFC 3161 TSA on the network"),
    ("tokens list", "needs a PKCS#11 token"),
];
/// Single examples that are not run, by an option they carry, with the reason (parsed by the unit test).
const NEEDS: &[(&str, &str)] = &[
    ("--pkcs11-module", "needs a PKCS#11 token"),
    ("--online", "needs the network"),
];
/// The run id the examples use; replaced by a real run id of the same folder.
const EXAMPLE_RUN: &str = "20261019T101500Z-a1b2c3";
/// The serial the examples use; replaced by the serial of the certificate last issued by the CA folder named.
const EXAMPLE_SERIAL: &str = "5f3a09c1";
/// Synthetic test password for every key file, CA key and .p12 of the examples (never a real secret).
const TEST_PASSWORD: &str = "examples-pass T3 (cli test)";
/// `analyze` exits 3 when a high-severity finding is raised: the sample evidence is built to raise some.
const EXIT_FINDINGS: i32 = 3;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bin(cwd: &Path) -> Command {
    let mut c = Command::cargo_bin(TOOL).unwrap();
    c.current_dir(cwd)
        .env("RV_NO_TIMESTAMP", "1") // offline: the examples must not depend on a TSA
        .env("RV_NO_UPDATE_CHECK", "1") // update-check answers "turned off" (exit 0) without the network
        .env("RV_CERTCHECK_DATA", cwd.join("certcheck-data")) // trust-list snapshots of this test only
        .env("RV_KEY_PASSWORD", TEST_PASSWORD)
        .env("RV_CA_PASSWORD", TEST_PASSWORD)
        .env("RV_P12_PASSWORD", TEST_PASSWORD)
        .env_remove("RV_TOKEN_PIN");
    c
}

fn help(sub: &str) -> String {
    let mut args: Vec<&str> = sub.split(' ').collect();
    args.push("--help");
    let out = Command::cargo_bin(TOOL)
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// Command lines under EXAMPLES: (same rule as the unit test in src/main.rs).
fn examples(help: &str) -> Vec<String> {
    let Some(section) = help.split("EXAMPLES:\n").nth(1) else {
        return vec![];
    };
    // Commands are indented by 4. clap wraps a long one onto further lines with the same indent: those lines
    // continue the command.
    let prefix = format!("{} ", TOOL);
    let mut out: Vec<String> = vec![];
    let mut in_command = false;
    for l in section
        .lines()
        .take_while(|l| l.is_empty() || l.starts_with(' '))
    {
        let t = l.trim();
        if t.starts_with(&prefix) {
            out.push(t.to_string());
            in_command = true;
        } else if in_command && l.starts_with("    ") && !t.is_empty() {
            if let Some(last) = out.last_mut() {
                last.push(' ');
                last.push_str(t);
            }
        } else {
            in_command = false;
        }
    }
    out
}

fn split_args(line: &str) -> Vec<String> {
    let (mut args, mut cur, mut quoted, mut any) = (vec![], String::new(), false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    args.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        args.push(cur);
    }
    if let Some(i) = args.iter().position(|a| a == ">") {
        args.truncate(i);
    }
    args
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// The first run folder name under `dir` (a logs/ or runs/<tool>/ folder).
fn a_run(dir: &Path) -> String {
    let mut runs: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {}", dir.display(), e))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    runs.sort();
    runs.into_iter()
        .next()
        .unwrap_or_else(|| panic!("no run in {}", dir.display()))
}

/// The serial of the certificate the CA folder issued last (its last `issued` record in issued.jsonl).
fn last_issued_serial(ca: &Path) -> String {
    let log = std::fs::read_to_string(ca.join("issued.jsonl"))
        .unwrap_or_else(|e| panic!("{}: {}", ca.display(), e));
    log.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| r["action"] == "issued")
        .filter_map(|r| r["serial_hex"].as_str().map(str::to_string))
        .next_back()
        .unwrap_or_else(|| panic!("no issued certificate in {}", ca.display()))
}

/// Maps the sample paths of an example argument to the temporary folder. `ca` is the example's --ca folder (for
/// the example serial).
fn localize(arg: &str, t: &Path, ca: Option<&Path>) -> String {
    let unix = arg.replace('\\', "/");
    let fixtures = repo().join("tests/fixtures/trustlists");
    for (sample, file) in [
        ("D:/trust/TL-ES.xml", "tl-sample.xml"),
        ("D:/trust/TL-FR.xml", "tl-sample.xml"),
        ("D:/trust/co-ecd.csv", "co-sample.csv"),
    ] {
        if unix == sample {
            return fixtures.join(file).display().to_string();
        }
    }
    if unix == EXAMPLE_SERIAL {
        return last_issued_serial(ca.expect("an example serial needs --ca"));
    }
    if let Some(rest) = unix.strip_prefix("E:/pki/") {
        let local = t.join("E-pki").join(rest);
        if rest.contains(&format!("certs/{}.crt", EXAMPLE_SERIAL)) {
            let ca_dir = t.join("E-pki").join(rest.split("/certs/").next().unwrap());
            let serial = last_issued_serial(&ca_dir);
            return ca_dir
                .join("certs")
                .join(format!("{}.crt", serial))
                .display()
                .to_string();
        }
        return local.display().to_string();
    }
    for (sample, local) in [
        ("D:/evidence", "D-evidence"),
        ("D:/trust-snapshots", "trust-snapshots"),
    ] {
        if let Some(rest) = unix.strip_prefix(sample) {
            return format!("{}{}", t.join(local).display(), rest);
        }
    }
    if let Some(rest) = unix.strip_prefix("E:/CASE-014") {
        let rest = if rest.contains(EXAMPLE_RUN) {
            let run = a_run(&t.join("CASE-014/runs").join(TOOL));
            rest.replace(EXAMPLE_RUN, &run)
        } else {
            rest.to_string()
        };
        return format!("{}{}", t.join("CASE-014").display(), rest);
    }
    if unix.starts_with("rakvor-out/logs/") && unix.contains(EXAMPLE_RUN) {
        return unix.replace(EXAMPLE_RUN, &a_run(&t.join("rakvor-out/logs")));
    }
    if unix == "digicert-tsa-roots.pem" {
        // Any CA certificate will do: the offline runs have no timestamp token to chain to it.
        return repo()
            .join("packaging/signing/rakvor-code-signing-root.cer")
            .display()
            .to_string();
    }
    arg.to_string()
}

#[test]
fn help_examples_run_against_the_sample_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let sample = repo().join("examples/sample");
    copy_dir(&sample.join("evidence"), &t.join("D-evidence"));
    for d in ["evidence", "roots"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    for (from, to) in [
        ("evidence/leaf.crt", "evidence/signer.cer"),
        ("anchors/rakvor-lab-root.crt", "roots/ca-root.pem"),
        ("evidence/intermediate.crl", "ca.crl"),
    ] {
        std::fs::copy(sample.join(from), t.join(to)).unwrap();
    }
    std::fs::write(t.join("files.txt"), "# sample list\nevidence/signer.cer\n").unwrap();
    // The OCSP response of the analyze example comes from a lab set; the EU snapshot of `--anchor tl:eu@latest`
    // from the trust-list fixture. Both are made before the analyze examples run.
    for args in [
        vec![
            "lab",
            "make",
            "--set",
            "full",
            "--seed",
            "1",
            "--lab-out",
            "lab-setup",
        ],
        vec!["trust-list", "import", "--list", "eu"],
    ] {
        let mut c = bin(t);
        c.args(&args);
        if args[0] == "trust-list" {
            c.arg(repo().join("tests/fixtures/trustlists/tl-sample.xml"));
        }
        let out = c.output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{:?}: {:?}", args, out);
    }
    std::fs::copy(
        t.join("lab-setup/revoked-by-ocsp/leaf.ocsp"),
        t.join("leaf.ocsp"),
    )
    .unwrap();
    if CASE_ROLE != CaseRole::Intake {
        // An analysis tool does not register evidence: register the sample in the example case first, through
        // the core with the intake role (what rv-hashinv does), so `--evidence E0001,E0002` exists.
        let cfg = RunConfig {
            inputs: vec![t.join("D-evidence")],
            algorithms: vec![HashAlgo::Sha256],
            actor: "seed".into(),
            case_id: Some("CASE-014".into()),
            jurisdiction: "fr".into(),
            case_dir: Some(t.join("CASE-014")),
            case_role: CaseRole::Intake,
            ..Default::default()
        };
        run(&cfg, &mut |_| {}, &AtomicBool::new(false)).unwrap();
    }

    // Every documented subcommand (docs-cli lists them, nested ones under their parent; analyze comes first),
    // then docs-cli itself (hidden from the list, its example only prints).
    let (top, nested) = (format!("## {} ", TOOL), format!("### {} ", TOOL));
    let docs = bin(t).arg("docs-cli").output().unwrap();
    let mut order: Vec<String> = String::from_utf8_lossy(&docs.stdout)
        .lines()
        .filter_map(|l| {
            l.strip_prefix(&top)
                .or_else(|| l.strip_prefix(&nested))
                .map(str::to_string)
        })
        .collect();
    assert_eq!(
        order.first().map(String::as_str),
        Some("analyze"),
        "{:?}",
        order
    );
    assert!(order.iter().any(|c| c == "pki issue"), "{:?}", order);
    order.push("docs-cli".into());
    let mut ran = 0;
    for sub in &order {
        if PARSE_ONLY.iter().any(|(p, _)| p == sub) {
            continue;
        }
        let words: Vec<&str> = sub.split(' ').collect();
        let lines = examples(&help(sub));
        assert!(!lines.is_empty(), "`{} {}` has no EXAMPLES", TOOL, sub);
        for line in lines {
            let args = split_args(&line);
            if args.get(1..=words.len()).is_none_or(|w| *w != words[..]) {
                // analyze's help also shows how to verify afterwards; that command runs with its own help.
                continue;
            }
            if NEEDS.iter().any(|(o, _)| args.iter().any(|a| a == o)) {
                continue;
            }
            let ca = args
                .iter()
                .position(|a| a == "--ca")
                .map(|i| PathBuf::from(localize(&args[i + 1], t, None)));
            let local: Vec<String> = args[1..]
                .iter()
                .map(|a| localize(a, t, ca.as_deref()))
                .collect();
            let out = bin(t).args(&local).output().unwrap();
            let ok = match out.status.code() {
                Some(0) => true,
                Some(EXIT_FINDINGS) => sub == "analyze",
                _ => false,
            };
            assert!(
                ok,
                "example `{}` (run as {:?}) failed with {:?}:\n{}{}",
                line,
                local,
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            ran += 1;
        }
    }
    assert!(ran >= 35, "{} examples ran", ran);
    // The case examples analysed the registered sample and recorded their runs in the case log.
    let case_log = std::fs::read_to_string(t.join("CASE-014/case-log.jsonl")).unwrap();
    assert!(case_log.contains("\"rv-certcheck\""), "{}", case_log);
    // The PKI examples built on each other: the issuing CA verifies and holds a CRL with the revoked examiner.
    assert!(t.join("E-pki/issuing/crl/latest.crl").is_file());
    // No example password reached a file the examples wrote.
    let mut stack = vec![t.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(text) = std::fs::read(&p) {
                assert!(
                    !String::from_utf8_lossy(&text).contains(TEST_PASSWORD),
                    "{} holds the test password",
                    p.display()
                );
            }
        }
    }
    // Every timestamp example names a log folder the examples above created (it is only parsed: no TSA).
    for line in examples(&help("timestamp")) {
        let args = split_args(&line);
        assert!(
            t.join(localize(&args[2], t, None))
                .join("audit.jsonl")
                .is_file(),
            "{}",
            line
        );
    }
}
