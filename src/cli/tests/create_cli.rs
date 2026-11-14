//! End-to-end tests of the creation commands (agent B): a full company PKI flow through the binary, judged by
//! the OpenSSL command line, with every run audited and no secret in any file written.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

const ROOT_PW: &str = "root-pass Q7 (cli test)";
const ISSUING_PW: &str = "issuing-pass K2 (cli test)";
const LEAF_PW: &str = "leaf-pass M4 (cli test)";
const P12_PW: &str = "p12-pass Z9 (cli test)";

fn bin(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("rv-certcheck").unwrap();
    c.current_dir(dir);
    for v in [
        "RV_KEY_PASSWORD",
        "RV_CA_PASSWORD",
        "RV_P12_PASSWORD",
        "RV_TOKEN_PIN",
    ] {
        c.env_remove(v);
    }
    c
}

fn have_openssl() -> bool {
    std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn openssl(dir: &Path, args: &[&str]) -> (bool, String) {
    let o = std::process::Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr),
    )
}

/// Runs a command that must succeed with --json and returns the JSON result.
fn ok_json(cmd: &mut Command) -> Value {
    let o = cmd.arg("--json").output().unwrap();
    assert!(
        o.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    serde_json::from_slice(&o.stdout).unwrap()
}

fn all_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let b = std::fs::read(&p).unwrap();
                out.push((p, b));
            }
        }
    }
    out
}

fn every_run_log_verifies(dir: &Path) -> usize {
    let logs = dir.join("rakvor-out").join("logs");
    let mut n = 0;
    for e in std::fs::read_dir(&logs).unwrap() {
        let run = e.unwrap().path();
        let o = bin(dir).arg("verify-log").arg(&run).output().unwrap();
        assert!(
            o.status.success(),
            "{}: {}",
            run.display(),
            String::from_utf8_lossy(&o.stdout)
        );
        let text = std::fs::read_to_string(run.join("audit.jsonl")).unwrap();
        assert!(text.lines().next().unwrap().contains("\"run_started\""));
        assert!(text.lines().last().unwrap().contains("\"run_finished\""));
        n += 1;
    }
    n
}

fn no_secret_anywhere(dir: &Path, secrets: &[&str]) {
    for (p, b) in all_files(dir) {
        let s = String::from_utf8_lossy(&b);
        for secret in secrets {
            assert!(!s.contains(secret), "secret found in {}", p.display());
        }
    }
}

#[test]
fn creation_help_documents_every_option() {
    let d = tempfile::tempdir().unwrap();
    for cmd in [
        vec!["pki", "init-root"],
        vec!["pki", "import"],
        vec!["pki", "issue"],
        vec!["pki", "revoke"],
        vec!["pki", "crl"],
        vec!["pki", "ocsp-sign"],
        vec!["pki", "show"],
        vec!["pki", "set"],
        vec!["pki", "verify"],
        vec!["csr", "new"],
        vec!["csr", "show"],
        vec!["lab", "make"],
        vec!["keys", "match"],
        vec!["tokens", "list"],
        vec!["trust-list", "import"],
        vec!["trust-list", "list"],
        vec!["trust-list", "show"],
    ] {
        let o = bin(d.path()).args(&cmd).arg("--help").output().unwrap();
        let text = String::from_utf8(o.stdout).unwrap();
        // Option lines of the Options: block only (it ends at the first unindented heading).
        let options_block: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.starts_with("Options:") && !l.starts_with("Arguments:"))
            .take_while(|l| {
                l.is_empty() || l.starts_with(' ') || *l == "Options:" || *l == "Arguments:"
            })
            .collect();
        let options = options_block
            .iter()
            .filter(|l| {
                let t = l.trim_start();
                // Option headers are indented by at most 6 columns; their help text by 10.
                l.len() - t.len() <= 6
                    && (t.starts_with("--") || t.starts_with('<'))
                    && !t.starts_with("--help")
                    && !t.starts_with("--version")
            })
            .count();
        assert!(options > 0, "{cmd:?}");
        let block_text = options_block.join("\n");
        assert!(
            block_text.matches("Default:").count() >= options,
            "{cmd:?}: every option needs Default:\n{text}"
        );
        assert!(
            block_text.matches("Example:").count() >= options,
            "{cmd:?}: every option needs Example:\n{text}"
        );
        assert!(
            text.matches("Default:").count() >= options,
            "{cmd:?}: every option needs Default:\n{text}"
        );
        assert!(
            text.matches("Example:").count() >= options,
            "{cmd:?}: every option needs Example:\n{text}"
        );
        assert!(text.contains("EXIT CODES:"), "{cmd:?}");
        assert!(text.contains("FILES WRITTEN"), "{cmd:?}");
    }
    let o = bin(d.path()).args(["pki", "--help"]).output().unwrap();
    let text = String::from_utf8(o.stdout).unwrap();
    assert!(text.contains("not a firma digital") && text.contains("rv-certcheck#2"));
    // A password is never a command-line value.
    bin(d.path())
        .args(["pki", "crl", "--ca", "x", "--password", "secret"])
        .assert()
        .code(2);
}

#[test]
fn company_pki_flow_file_root() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    // 1. Root (file key).
    let root = ok_json(
        bin(dir)
            .env("RV_KEY_PASSWORD", ROOT_PW)
            .args([
                "pki",
                "init-root",
                "--ca",
                "root",
                "--ca-id",
                "rakvor-root-test",
            ])
            .args([
                "--subject",
                "C=CO,O=Rakvor,CN=Rakvor Root CA (test)",
                "--key-type",
                "p-384",
            ]),
    );
    assert_eq!(root["kind"], "root");
    // 2. Intermediate (its key in a file), then managed as its own CA folder.
    let inter = ok_json(
        bin(dir)
            .env("RV_CA_PASSWORD", ROOT_PW)
            .env("RV_KEY_PASSWORD", ISSUING_PW)
            .args([
                "pki",
                "issue",
                "--ca",
                "root",
                "--profile",
                "intermediate",
                "--key-type",
                "p-256",
            ])
            .args([
                "--subject",
                "C=CO,O=Rakvor,CN=Rakvor Issuing CA (test)",
                "--key-file",
                "issuing.key.p8",
            ]),
    );
    let inter_crt = PathBuf::from(inter["cert_path"].as_str().unwrap());
    ok_json(
        bin(dir)
            .env("ISSUING_PASS", ISSUING_PW)
            .args([
                "pki",
                "import",
                "--ca",
                "issuing",
                "--ca-id",
                "rakvor-issuing-test",
            ])
            .arg("--cert")
            .arg(&inter_crt)
            .args(["--key-file", "issuing.key.p8", "--pass-env", "ISSUING_PASS"]),
    );
    let issue = |profile: &str, subject: &str, extra: &[&str]| -> Value {
        ok_json(
            bin(dir)
                .env("ISSUING_PASS", ISSUING_PW)
                .env("RV_KEY_PASSWORD", LEAF_PW)
                .env("RV_P12_PASSWORD", P12_PW)
                .args([
                    "pki",
                    "issue",
                    "--ca",
                    "issuing",
                    "--ca-pass-env",
                    "ISSUING_PASS",
                    "--profile",
                    profile,
                ])
                .args(["--subject", subject])
                .args(extra),
        )
    };
    // 3-5. Code signing, examiner (.p12), TLS server with SANs.
    let cs = issue(
        "code-signing",
        "C=CO,O=Rakvor,CN=Rakvor Release Signing (test)",
        &[],
    );
    let ex = issue(
        "examiner",
        "C=CO,O=Rakvor,CN=Ana Ruiz",
        &[
            "--san",
            "email:ana.ruiz@rakvor.test",
            "--key-type",
            "rsa-2048",
        ],
    );
    let tls = issue(
        "tls-server",
        "C=CO,O=Rakvor,CN=hub.rakvor.test",
        &[
            "--san",
            "dns:hub.rakvor.test",
            "--san",
            "ip:192.0.2.10",
            "--key-type",
            "p-256",
        ],
    );
    let p12 = dir.join(ex["p12_path"].as_str().unwrap());
    assert!(p12.is_file());
    // 6. CSR for a public CA.
    let csr = ok_json(
        bin(dir)
            .env("RV_KEY_PASSWORD", LEAF_PW)
            .args([
                "csr",
                "new",
                "--subject",
                "C=CO,O=Rakvor SAS,CN=www.rakvor.test",
            ])
            .args([
                "--san",
                "dns:www.rakvor.test",
                "--key-type",
                "p-256",
                "--csr-out",
                "www.csr",
            ]),
    );
    assert_eq!(csr["csr"]["signature_valid"], true);
    assert!(dir.join("www.key.p8").is_file());
    // csr show of a forged CSR: exit 3.
    let mut der = pem::parse(std::fs::read(dir.join("www.csr")).unwrap())
        .unwrap()
        .into_contents();
    let n = der.len() - 1;
    der[n] ^= 1;
    std::fs::write(dir.join("forged.csr"), der).unwrap();
    bin(dir)
        .args(["csr", "show", "forged.csr"])
        .assert()
        .code(3);
    // 7. Revoke the code-signing certificate, then a CRL.
    let cs_serial = cs["record"]["serial_hex"].as_str().unwrap().to_string();
    ok_json(bin(dir).args([
        "pki",
        "revoke",
        "--ca",
        "issuing",
        "--serial",
        &cs_serial,
        "--reason",
        "keyCompromise",
    ]));
    let crl = ok_json(bin(dir).env("ISSUING_PASS", ISSUING_PW).args([
        "pki",
        "crl",
        "--ca",
        "issuing",
        "--ca-pass-env",
        "ISSUING_PASS",
        "--next-update-days",
        "7",
    ]));
    assert_eq!(crl["crl_number"], 1);
    // Unknown serial: usage error; disabled profile: refused; wrong password: runtime error. All audited.
    bin(dir)
        .args(["pki", "revoke", "--ca", "issuing", "--serial", "0102"])
        .assert()
        .code(2);
    bin(dir)
        .args([
            "pki",
            "issue",
            "--ca",
            "issuing",
            "--profile",
            "client-internal",
            "--subject",
            "CN=Client",
        ])
        .assert()
        .code(3);
    bin(dir)
        .env("RV_CA_PASSWORD", "wrong")
        .args(["pki", "crl", "--ca", "issuing"])
        .assert()
        .code(1);
    // show / verify.
    let shown = ok_json(bin(dir).args(["pki", "show", "--ca", "issuing"]));
    let issued = shown["issued"].as_array().unwrap();
    assert_eq!(issued.len(), 3);
    assert!(
        issued
            .iter()
            .any(|i| i["serial"] == cs_serial.as_str() && i["revoked"] == "keyCompromise")
    );
    bin(dir)
        .args(["pki", "verify", "--ca", "issuing"])
        .assert()
        .code(0);

    if have_openssl() {
        let root_crt = "root/certs/ca.crt";
        let inter_s = inter_crt.to_str().unwrap();
        let path = |v: &Value| v["cert_path"].as_str().unwrap().to_string();
        let (ok, t) = openssl(dir, &["verify", "-CAfile", root_crt, inter_s]);
        assert!(ok, "{t}");
        for (leaf, purpose) in [
            (&cs, None),
            (&ex, Some("smimesign")),
            (&tls, Some("sslserver")),
        ] {
            let mut a = vec!["verify", "-CAfile", root_crt, "-untrusted", inter_s];
            if let Some(p) = purpose {
                a.extend(["-purpose", p]);
            }
            let p = path(leaf);
            a.push(&p);
            let (ok, t) = openssl(dir, &a);
            assert!(ok, "{p}: {t}");
        }
        let (_, t) = openssl(
            dir,
            &[
                "x509",
                "-noout",
                "-ext",
                "subjectAltName",
                "-in",
                &path(&tls),
            ],
        );
        assert!(
            t.contains("DNS:hub.rakvor.test") && t.contains("IP Address:192.0.2.10"),
            "{t}"
        );
        let (ok, t) = openssl(dir, &["req", "-verify", "-noout", "-in", "www.csr"]);
        assert!(ok, "{t}");
        let (ok, t) = openssl(
            dir,
            &[
                "pkcs12",
                "-in",
                p12.to_str().unwrap(),
                "-noout",
                "-passin",
                &format!("pass:{P12_PW}"),
            ],
        );
        assert!(ok, "{t}");
        // With the CRL: the revoked code-signing certificate is rejected (error 23), the TLS one accepted.
        assert!(
            openssl(
                dir,
                &[
                    "crl",
                    "-inform",
                    "DER",
                    "-in",
                    "issuing/crl/latest.crl",
                    "-out",
                    "issuing.crl.pem"
                ]
            )
            .0
        );
        let (_, t) = openssl(
            dir,
            &[
                "verify",
                "-crl_check",
                "-CAfile",
                root_crt,
                "-untrusted",
                inter_s,
                "-CRLfile",
                "issuing.crl.pem",
                &path(&cs),
            ],
        );
        assert!(t.contains("error 23"), "{t}");
        let (ok, t) = openssl(
            dir,
            &[
                "verify",
                "-crl_check",
                "-CAfile",
                root_crt,
                "-untrusted",
                inter_s,
                "-CRLfile",
                "issuing.crl.pem",
                &path(&tls),
            ],
        );
        assert!(ok, "{t}");
    }

    // Every run is an intact audit log; no password anywhere (CA folders, keys, runs, reports).
    let runs = every_run_log_verifies(dir);
    assert!(runs >= 14, "{runs} runs");
    no_secret_anywhere(dir, &[ROOT_PW, ISSUING_PW, LEAF_PW, P12_PW]);
    // Every pki report carries the internal-use notice (directory order is arbitrary: check them all).
    let reports = dir.join("rakvor-out").join("reports");
    let mut pki_reports = 0;
    for e in std::fs::read_dir(&reports).unwrap() {
        let rep: Value =
            serde_json::from_slice(&std::fs::read(e.unwrap().path().join("report.json")).unwrap())
                .unwrap();
        if rep["command"]
            .as_str()
            .unwrap_or_default()
            .starts_with("pki ")
        {
            pki_reports += 1;
            let notice = rep["notice"].as_str().unwrap_or_default();
            assert!(
                notice.contains("firma digital") && notice.contains("rv-certcheck#2"),
                "{rep}"
            );
        }
    }
    assert!(pki_reports >= 9, "{pki_reports} pki reports");

    // Tampering with issued.jsonl stops the CA: pki verify exits 3, nothing more is issued.
    let log = dir.join("issuing").join("issued.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, text.replacen("keyCompromise", "superseded", 1)).unwrap();
    bin(dir)
        .args(["pki", "verify", "--ca", "issuing"])
        .assert()
        .code(3);
    bin(dir)
        .env("ISSUING_PASS", ISSUING_PW)
        .args([
            "pki",
            "crl",
            "--ca",
            "issuing",
            "--ca-pass-env",
            "ISSUING_PASS",
        ])
        .assert()
        .code(3);
}

#[test]
fn lab_make_and_keys_match() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let m = ok_json(bin(dir).args([
        "lab",
        "make",
        "--set",
        "minimal",
        "--seed",
        "3",
        "--lab-out",
        "lab",
    ]));
    assert_eq!(m["cases"].as_array().unwrap().len(), 4);
    // Same seed again: byte-identical manifest.
    let m2 = ok_json(bin(dir).args([
        "lab",
        "make",
        "--set",
        "minimal",
        "--seed",
        "3",
        "--lab-out",
        "lab2",
    ]));
    assert_eq!(m, m2);
    bin(dir)
        .args(["lab", "make", "--set", "minimal", "--lab-out", "lab"])
        .assert()
        .code(3);
    bin(dir)
        .args(["lab", "make", "--set", "huge", "--lab-out", "x"])
        .assert()
        .code(2);
    // keys match: the lab key-mismatch key against its certificate (exit 3), or `not implemented` (exit 1)
    // while the analysis side's match_key is still a stub.
    let o = bin(dir)
        .args([
            "keys",
            "match",
            "lab/key-mismatch/leaf.key",
            "lab/key-mismatch/leaf.crt",
        ])
        .output()
        .unwrap();
    assert!(matches!(o.status.code(), Some(3) | Some(1)), "{o:?}");
    every_run_log_verifies(dir);
}

/// The same company flow with the root key on a SoftHSM2 token (env-gated like the certificate-layer tests:
/// RV_TEST_PKCS11_MODULE, RV_TEST_PKCS11_SERIAL, RV_TEST_PKCS11_PIN; SOFTHSM2_CONF is inherited).
#[test]
fn company_pki_flow_token_root() {
    let (Ok(module), Ok(serial), Ok(pin)) = (
        std::env::var("RV_TEST_PKCS11_MODULE"),
        std::env::var("RV_TEST_PKCS11_SERIAL"),
        std::env::var("RV_TEST_PKCS11_PIN"),
    ) else {
        eprintln!("skipping: RV_TEST_PKCS11_MODULE / _SERIAL / _PIN not set (SoftHSM2)");
        return;
    };
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let token = |c: &mut Command| {
        c.env("TOKEN_PIN", &pin).args([
            "--pkcs11-module",
            &module,
            "--token-serial",
            &serial,
            "--pin-env",
            "TOKEN_PIN",
        ]);
    };
    // Without --confirm-root: refused (exit 3), no PIN asked, nothing created.
    let mut c = bin(dir);
    c.args([
        "pki",
        "init-root",
        "--ca",
        "root",
        "--ca-id",
        "cli-token-root",
        "--subject",
        "O=Rakvor,CN=CLI Token Root",
    ]);
    token(&mut c);
    c.assert().code(3);
    assert!(!dir.join("root").join("ca.json").exists());
    let mut c = bin(dir);
    c.args([
        "pki",
        "init-root",
        "--ca",
        "root",
        "--ca-id",
        "cli-token-root",
        "--subject",
        "O=Rakvor,CN=CLI Token Root",
    ])
    .args([
        "--key-type",
        "p-384",
        "--confirm-root",
        "--key-label",
        "cli-token-root",
    ]);
    token(&mut c);
    let root = ok_json(&mut c);
    assert_eq!(root["key"]["type"], "pkcs11");
    // tokens list after login shows the root key.
    let mut c = bin(dir);
    c.args(["tokens", "list"]);
    token(&mut c);
    let listed = ok_json(&mut c);
    let key_id = root["key"]["key_id_hex"].as_str().unwrap();
    assert!(listed.as_array().unwrap().iter().any(|t| {
        t["keys"]
            .as_array()
            .is_some_and(|k| k.iter().any(|k| k["key_id_hex"] == key_id))
    }));
    // The root (on the token) issues the intermediate; the intermediate issues the leaves.
    let inter = ok_json(
        bin(dir)
            .env("TOKEN_PIN", &pin)
            .env("RV_KEY_PASSWORD", ISSUING_PW)
            .args([
                "pki",
                "issue",
                "--ca",
                "root",
                "--ca-pass-env",
                "TOKEN_PIN",
                "--profile",
                "intermediate",
            ])
            .args([
                "--subject",
                "O=Rakvor,CN=CLI Issuing",
                "--key-type",
                "p-256",
                "--key-file",
                "issuing.key.p8",
            ]),
    );
    let inter_crt = inter["cert_path"].as_str().unwrap().to_string();
    ok_json(
        bin(dir)
            .env("RV_KEY_PASSWORD", ISSUING_PW)
            .args([
                "pki",
                "import",
                "--ca",
                "issuing",
                "--ca-id",
                "cli-issuing",
                "--cert",
                &inter_crt,
            ])
            .args(["--key-file", "issuing.key.p8"]),
    );
    let issue = |profile: &str, subject: &str, extra: &[&str]| -> Value {
        ok_json(
            bin(dir)
                .env("RV_CA_PASSWORD", ISSUING_PW)
                .env("RV_KEY_PASSWORD", LEAF_PW)
                .env("RV_P12_PASSWORD", P12_PW)
                .args([
                    "pki",
                    "issue",
                    "--ca",
                    "issuing",
                    "--profile",
                    profile,
                    "--subject",
                    subject,
                ])
                .args(extra),
        )
    };
    let cs = issue(
        "code-signing",
        "O=Rakvor,CN=CLI Release",
        &["--key-type", "p-256"],
    );
    let ex = issue(
        "examiner",
        "O=Rakvor,CN=Ana Ruiz",
        &["--key-type", "rsa-2048", "--san", "email:ana@rakvor.test"],
    );
    let tls = issue(
        "tls-server",
        "O=Rakvor,CN=hub.rakvor.test",
        &["--san", "dns:hub.rakvor.test", "--key-type", "p-256"],
    );
    let mut c = bin(dir);
    c.args([
        "csr",
        "new",
        "--subject",
        "O=Rakvor,CN=token csr",
        "--key-type",
        "p-256",
        "--csr-out",
        "token.csr",
        "--key-label",
        "cli-csr",
    ]);
    token(&mut c);
    ok_json(&mut c);
    // Revoke the intermediate's code-signing leaf, CRL from the intermediate; also a CRL from the token root.
    ok_json(bin(dir).args([
        "pki",
        "revoke",
        "--ca",
        "issuing",
        "--serial",
        cs["record"]["serial_hex"].as_str().unwrap(),
        "--reason",
        "superseded",
    ]));
    ok_json(
        bin(dir)
            .env("RV_CA_PASSWORD", ISSUING_PW)
            .args(["pki", "crl", "--ca", "issuing"]),
    );
    ok_json(bin(dir).env("TOKEN_PIN", &pin).args([
        "pki",
        "crl",
        "--ca",
        "root",
        "--ca-pass-env",
        "TOKEN_PIN",
    ]));
    if have_openssl() {
        let root_crt = "root/certs/ca.crt";
        let (ok, t) = openssl(dir, &["verify", "-CAfile", root_crt, &inter_crt]);
        assert!(ok, "{t}");
        for leaf in [&cs, &ex, &tls] {
            let p = leaf["cert_path"].as_str().unwrap();
            let (ok, t) = openssl(
                dir,
                &["verify", "-CAfile", root_crt, "-untrusted", &inter_crt, p],
            );
            assert!(ok, "{p}: {t}");
        }
        assert!(
            openssl(
                dir,
                &[
                    "crl",
                    "-inform",
                    "DER",
                    "-in",
                    "issuing/crl/latest.crl",
                    "-out",
                    "i.crl.pem"
                ]
            )
            .0
        );
        let (_, t) = openssl(
            dir,
            &[
                "verify",
                "-crl_check",
                "-CAfile",
                root_crt,
                "-untrusted",
                &inter_crt,
                "-CRLfile",
                "i.crl.pem",
                cs["cert_path"].as_str().unwrap(),
            ],
        );
        assert!(t.contains("error 23"), "{t}");
        assert!(
            openssl(
                dir,
                &[
                    "crl",
                    "-inform",
                    "DER",
                    "-in",
                    "root/crl/latest.crl",
                    "-out",
                    "r.crl.pem"
                ]
            )
            .0
        );
        let (ok, t) = openssl(
            dir,
            &["crl", "-in", "r.crl.pem", "-CAfile", root_crt, "-noout"],
        );
        assert!(ok && t.contains("verify OK"), "{t}");
    }
    every_run_log_verifies(dir);
    no_secret_anywhere(dir, &[&pin, ISSUING_PW, LEAF_PW, P12_PW]);
}

fn key_of(cert_path: &str) -> (String, Option<u32>, Option<String>) {
    let p = rv_certcheck_core::certs::parse_any(&std::fs::read(cert_path).unwrap(), None).unwrap();
    let k = &p.certificates[0].key;
    (k.algorithm.clone(), k.bits, k.curve.clone())
}

fn small_root(dir: &Path) {
    ok_json(
        bin(dir)
            .env("RV_KEY_PASSWORD", ROOT_PW)
            .args(["pki", "init-root", "--ca", "root", "--ca-id", "root-test"])
            .args([
                "--subject",
                "O=Rakvor,CN=Integrity Root (test)",
                "--key-type",
                "p-256",
            ]),
    );
}

fn verify_code(dir: &Path) -> Option<i32> {
    bin(dir)
        .args(["pki", "verify", "--ca", "root"])
        .output()
        .unwrap()
        .status
        .code()
}

/// A creation run's own reports (report_written) are re-hashed by verify-log; the files it wrote at paths the
/// operator chose (file_written: key, certificate, CA files) are listed as not re-hashed.
#[test]
fn creation_run_reports_are_rehashed_by_verify_log() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    small_root(dir);
    let out = dir.join("rakvor-out");
    let run = std::fs::read_dir(out.join("logs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let id = run.file_name().unwrap().to_owned();
    let o = bin(dir).arg("verify-log").arg(&run).output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(o.status.code(), Some(0), "{}", text);
    assert!(
        text.contains("outputs: 3 verified of ") && text.contains("(sha256)"),
        "{}",
        text
    );
    assert!(
        text.contains("written outside the run folder, at a path the operator chose"),
        "{}",
        text
    );
    let reports = out.join("reports").join(&id);
    let json = reports.join("report.json");
    let saved = std::fs::read(&json).unwrap();
    std::fs::write(&json, b"{\"edited\": true}\n").unwrap();
    let txt = reports.join("report.txt");
    let saved_txt = std::fs::read(&txt).unwrap();
    std::fs::remove_file(&txt).unwrap();
    let o = bin(dir).arg("verify-log").arg(&run).output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(o.status.code(), Some(3), "{}", text);
    assert!(
        text.contains("output reports/report.json: sha256 differs from audit entry #")
            && text.contains("output reports/report.txt: missing")
            && text.contains("1 missing, 1 changed"),
        "{}",
        text
    );
    std::fs::write(&json, saved).unwrap();
    std::fs::write(&txt, saved_txt).unwrap();
    assert_eq!(
        bin(dir)
            .arg("verify-log")
            .arg(&run)
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn ca_folder_tampering_exits_3_and_pki_set_keeps_it_verified() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    small_root(dir);
    ok_json(
        bin(dir)
            .env("RV_CA_PASSWORD", ROOT_PW)
            .args(["pki", "crl", "--ca", "root"]),
    );
    assert_eq!(verify_code(dir), Some(0));
    // pki set: the recorded change verifies.
    let r = ok_json(bin(dir).args([
        "pki",
        "set",
        "--ca",
        "root",
        "--crl-url",
        "http://pki.rakvor.test/root.crl",
    ]));
    assert_eq!(r["ca"]["crl_url"], "http://pki.rakvor.test/root.crl");
    assert_eq!(verify_code(dir), Some(0));
    // ca.json edited by hand: verify and every operation exit 3.
    let ca_json = dir.join("root/ca.json");
    let good = std::fs::read_to_string(&ca_json).unwrap();
    std::fs::write(
        &ca_json,
        good.replace("http://pki.rakvor.test/root.crl", "http://evil.test/x.crl"),
    )
    .unwrap();
    assert_eq!(verify_code(dir), Some(3));
    let o = bin(dir)
        .env("RV_CA_PASSWORD", ROOT_PW)
        .env("RV_KEY_PASSWORD", LEAF_PW)
        .args(["pki", "issue", "--ca", "root", "--profile", "tsa"])
        .args([
            "--subject",
            "O=Rakvor,CN=TSA (test)",
            "--key-file",
            "tsa.key.p8",
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("ca.json"));
    std::fs::write(&ca_json, &good).unwrap();
    assert_eq!(verify_code(dir), Some(0));
    // crl/latest.crl altered: exit 3.
    let latest = dir.join("root/crl/latest.crl");
    let mut b = std::fs::read(&latest).unwrap();
    let n = b.len() - 2;
    b[n] ^= 0x01;
    std::fs::write(&latest, b).unwrap();
    assert_eq!(verify_code(dir), Some(3));
}

#[test]
fn key_type_defaults_per_profile_and_examiner_must_be_rsa() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    small_root(dir);
    let issue = |profile: &str, cn: &str, extra: &[&str]| {
        bin(dir)
            .env("RV_CA_PASSWORD", ROOT_PW)
            .env("RV_KEY_PASSWORD", LEAF_PW)
            .env("RV_P12_PASSWORD", P12_PW)
            .args(["pki", "issue", "--ca", "root", "--profile", profile])
            .args(["--subject", &format!("O=Rakvor,CN={cn}")])
            .args(["--key-file", &format!("{cn}.key.p8")])
            .args(extra)
            .arg("--json")
            .output()
            .unwrap()
    };
    let cert = |o: &std::process::Output| -> String {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        dir.join(v["cert_path"].as_str().unwrap())
            .display()
            .to_string()
    };
    // Defaults: P-256 tsa, P-384 intermediate, RSA-3072 examiner.
    let (alg, _, curve) = key_of(&cert(&issue("tsa", "tsa", &[])));
    assert!(alg.contains("EC") || alg.contains("ec"), "{alg}");
    assert!(curve.unwrap_or_default().contains("256"));
    let (_, _, curve) = key_of(&cert(&issue("intermediate", "int", &[])));
    assert!(curve.unwrap_or_default().contains("384"));
    let (alg, bits, _) = key_of(&cert(&issue("examiner", "exam", &[])));
    assert_eq!(
        (alg.to_ascii_lowercase().contains("rsa"), bits),
        (true, Some(3072))
    );
    // EC examiner: refused (exit 3, nothing created) unless explicitly allowed.
    let o = issue("examiner", "exam-ec", &["--key-type", "p-256"]);
    assert_eq!(o.status.code(), Some(3));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("RSA") && err.contains("--allow-non-rsa-examiner"),
        "{err}"
    );
    assert!(!dir.join("exam-ec.key.p8").exists());
    let o = issue(
        "examiner",
        "exam-ec2",
        &["--key-type", "p-256", "--allow-non-rsa-examiner"],
    );
    cert(&o);
    // The help shows the per-profile defaults.
    let o = bin(dir).args(["pki", "issue", "--help"]).output().unwrap();
    let h = String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        h.contains("p-384 intermediate") && h.contains("rsa-3072 code-signing, examiner"),
        "{h}"
    );
}

#[test]
fn trust_list_commands_write_audited_runs() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let xml = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/trustlists/tl-withdrawn.xml");
    let snap = ok_json(
        bin(dir)
            .args(["trust-list", "import", "--list", "eu", "--store", "store"])
            .arg(&xml),
    );
    let id = snap["id"].as_str().unwrap().to_string();
    let shown = ok_json(bin(dir).args([
        "trust-list",
        "show",
        "--list",
        "eu",
        "latest",
        "--store",
        "store",
    ]));
    assert_eq!(shown["id"], id.as_str());
    let listed = ok_json(bin(dir).args(["trust-list", "list", "--store", "store"]));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    // Three runs, each with a verifying audit log that names the command.
    assert_eq!(every_run_log_verifies(dir), 3);
    let logs: Vec<String> = std::fs::read_dir(dir.join("rakvor-out/logs"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path().join("audit.jsonl")).unwrap())
        .collect();
    for cmd in ["trust-list import", "trust-list show", "trust-list list"] {
        assert!(logs.iter().any(|l| l.contains(cmd)), "{cmd}");
    }
    assert!(logs.iter().any(|l| l.contains("trust_list_imported")));
    // An altered snapshot is refused (exit 3) and the refusal is audited.
    let p = dir.join("store/eu").join(format!("{id}.json"));
    let t = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, t.replacen("withdrawn", "granted", 1)).unwrap();
    let o = bin(dir)
        .args([
            "trust-list",
            "show",
            "--list",
            "eu",
            &id,
            "--store",
            "store",
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("altered"));
}
