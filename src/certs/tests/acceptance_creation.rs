//! Acceptance tests for agent B (creation). Architect-owned: make them pass, do not weaken them. Each test skips,
//! with a message, while the function it exercises is still a stub (ErrorKind::NotImplemented).
//!
//! Independent oracle: the OpenSSL command line (`openssl verify`, `openssl x509`, `openssl crl`), skipped when no
//! `openssl` is on PATH. Lab-set conventions checked here: certificates and CRLs are PEM, OCSP responses DER;
//! `LabCase::files[0]` is the target, the other certificate files of the case are untrusted intermediates;
//! `validation.anchors` / `validation.crls` are paths relative to the set folder.

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};
use std::process::Command;

macro_rules! or_skip {
    ($e:expr, $what:expr) => {
        match $e {
            Err(e) if e.is_not_implemented() => {
                eprintln!("skipping: {} is not implemented yet", $what);
                return;
            }
            r => r,
        }
    };
}

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

fn sha256(b: &[u8]) -> String {
    hex(&openssl::sha::sha256(b))
}

fn epoch(t: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(t)
        .unwrap()
        .timestamp()
        .to_string()
}

#[test]
fn lab_set_is_byte_identical_for_a_seed_and_agrees_with_openssl_verify() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let spec = |d: &Path| LabSetSpec {
        name: "full".into(),
        seed: 1,
        base_time: "2026-01-01T00:00:00Z".into(),
        out_dir: d.join("set"),
    };
    let m = or_skip!(lab::make(&spec(a.path())), "lab::make").unwrap();
    let m2 = lab::make(&spec(b.path())).unwrap();
    assert_eq!(m, m2);
    assert_eq!(
        files(&a.path().join("set")),
        files(&b.path().join("set")),
        "not byte-identical"
    );
    assert_eq!(m.schema, LAB_SET_SCHEMA);
    for kind in LabCaseKind::ALL {
        assert!(m.cases.iter().any(|c| c.kind == kind), "{kind:?} missing");
    }
    let set = a.path().join("set");
    let manifest: LabSetManifest =
        serde_json::from_slice(&std::fs::read(set.join("expected_findings.json")).unwrap())
            .unwrap();
    assert_eq!(manifest, m);
    for (rel, sha) in &m.files {
        assert_eq!(
            &sha256(&std::fs::read(set.join(rel)).unwrap()),
            sha,
            "{rel}"
        );
    }
    // A different seed gives different keys.
    let c = tempfile::tempdir().unwrap();
    let mut s3 = spec(c.path());
    s3.seed = 2;
    assert_ne!(lab::make(&s3).unwrap().files, m.files);

    if !have_openssl() {
        eprintln!("skipping the openssl verify oracle: no openssl on PATH");
        return;
    }
    for case in &m.cases {
        let target = set.join(&case.files[0]);
        let untrusted: Vec<PathBuf> = case.files[1..]
            .iter()
            .filter(|f| f.ends_with(".crt") || f.ends_with(".pem"))
            .map(|f| set.join(f))
            .collect();
        let mut cmd = Command::new("openssl");
        cmd.arg("verify")
            .args(["-attime", &epoch(&case.validation.at)]);
        for a in &case.validation.anchors {
            cmd.arg("-CAfile").arg(set.join(a));
        }
        if !untrusted.is_empty() {
            let bundle = a.path().join(format!("{}-untrusted.pem", case.id));
            let mut all = vec![];
            for u in &untrusted {
                all.extend(std::fs::read(u).unwrap());
            }
            std::fs::write(&bundle, all).unwrap();
            cmd.arg("-untrusted").arg(&bundle);
        }
        if !case.validation.crls.is_empty() {
            cmd.arg("-crl_check");
            for c in &case.validation.crls {
                cmd.arg("-CRLfile").arg(set.join(c));
            }
        }
        if let Some(p) = case.validation.purpose.openssl_name() {
            cmd.args(["-purpose", p]);
        }
        let o = cmd.arg(&target).output().unwrap();
        let text =
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
        let code = text
            .lines()
            .find_map(|l| {
                l.strip_prefix("error ")
                    .and_then(|r| r.split_whitespace().next())
            })
            .and_then(|c| c.parse::<i32>().ok())
            .unwrap_or(if o.status.success() { 0 } else { -1 });
        assert_eq!(code, case.openssl_verify_code, "case {}: {}", case.id, text);
    }
}

#[test]
fn pki_round_trip_root_examiner_revoke_crl() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("root");
    let password = "correct horse battery staple 42";
    let root = or_skip!(
        pki::init_root(&InitRootRequest {
            ca_dir: ca.clone(),
            ca_id: "lab-root".into(),
            subject: SubjectSpec {
                rdns: vec![
                    ("O".into(), "Rakvor Test".into()),
                    ("CN".into(), "Test Root".into())
                ],
                sans: vec![],
            },
            key_spec: KeySpec::P256,
            key_target: KeyTarget::EncryptedFile {
                path: ca.join("keys").join("lab-root.key.p8"),
                password: Secret::new(password),
            },
            validity_days: 3650,
            confirm_root: false,
            actor: "test".into(),
        }),
        "pki::init_root"
    )
    .unwrap();
    assert_eq!(root.schema, CA_SCHEMA);
    assert_eq!(root.policy_oid, RAKVOR_POLICY_INTERNAL);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(ca.join("keys").join("lab-root.key.p8"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "key file must be owner-only");
    }
    let unlock = || KeyUnlock {
        secret: Secret::new(password),
    };
    let issued = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(),
        profile: IssueProfile::Examiner,
        subject: SubjectSpec {
            rdns: vec![("CN".into(), "Ana Ruiz".into())],
            sans: vec![GeneralName {
                kind: "email".into(),
                value: "ana@lab.test".into(),
            }],
        },
        csr_der: None,
        key_spec: Some(KeySpec::Rsa2048),
        key_target: Some(KeyTarget::EncryptedFile {
            path: d.path().join("ana.key.p8"),
            password: Secret::new("examiner pass"),
        }),
        p12_password: Some(Secret::new("examiner pass")),
        validity_days: 365,
        actor: "test".into(),
    })
    .unwrap();
    assert!(issued.p12_path.as_ref().is_some_and(|p| p.is_file()));
    // client-internal is disabled in v0.1.
    let refused = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(),
        profile: IssueProfile::ClientInternal,
        subject: SubjectSpec {
            rdns: vec![("CN".into(), "Client".into())],
            sans: vec![],
        },
        csr_der: None,
        key_spec: Some(KeySpec::P256),
        key_target: Some(KeyTarget::EncryptedFile {
            path: d.path().join("client.key.p8"),
            password: Secret::new("x"),
        }),
        p12_password: None,
        validity_days: 30,
        actor: "test".into(),
    });
    assert_eq!(refused.unwrap_err().kind, ErrorKind::Policy);
    let serial = issued.record.serial_hex.clone().unwrap();
    pki::revoke(&RevokeRequest {
        ca_dir: ca.clone(),
        serial_hex: serial.clone(),
        reason: "keyCompromise".into(),
        revoked_at: None,
        actor: "test".into(),
    })
    .unwrap();
    let crl = pki::make_crl(&CrlRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(),
        this_update: None,
        next_update_days: 30,
        actor: "test".into(),
    })
    .unwrap();
    // issued.jsonl: hash chain like audit.jsonl (canonical JSON, sorted keys, no whitespace).
    let mut prev = "0".repeat(64);
    let text = std::fs::read_to_string(ca.join("issued.jsonl")).unwrap();
    for (n, line) in text.lines().enumerate() {
        let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
        let stored = v["entry_hash"].as_str().unwrap().to_string();
        v.as_object_mut().unwrap().remove("entry_hash");
        assert_eq!(v["seq"], n as u64 + 1, "seq");
        assert_eq!(v["prev_entry_hash"], prev, "line {}", n + 1);
        assert_eq!(
            sha256(serde_json::to_string(&v).unwrap().as_bytes()),
            stored,
            "line {}",
            n + 1
        );
        prev = stored;
    }
    assert!(pki::open(&ca).is_ok());
    // No secret anywhere in the CA folder.
    for (rel, bytes) in files(&ca) {
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            !s.contains(password) && !s.contains("examiner pass"),
            "secret in {rel}"
        );
    }
    if !have_openssl() {
        eprintln!("skipping the openssl oracle: no openssl on PATH");
        return;
    }
    let ca_crt = ca.join(&root.certificate_file);
    let text = Command::new("openssl")
        .args(["x509", "-noout", "-text", "-in"])
        .arg(&issued.cert_path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains(RAKVOR_POLICY_INTERNAL), "policy OID missing");
    let crl_pem = d.path().join("crl.pem");
    let c = Command::new("openssl")
        .args(["crl", "-inform", "DER", "-in"])
        .arg(&crl.path)
        .arg("-out")
        .arg(&crl_pem)
        .status()
        .unwrap();
    assert!(c.success());
    let o = Command::new("openssl")
        .args(["verify", "-crl_check", "-CAfile"])
        .arg(&ca_crt)
        .arg("-CRLfile")
        .arg(&crl_pem)
        .arg(&issued.cert_path)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
    assert!(
        out.contains("error 23"),
        "revoked certificate not reported by openssl: {out}"
    );
}

#[test]
fn csr_new_and_show() {
    let d = tempfile::tempdir().unwrap();
    let r = or_skip!(
        csr::new(&CsrRequest {
            subject: SubjectSpec {
                rdns: vec![("C".into(), "CO".into()), ("CN".into(), "Ana Ruiz".into())],
                sans: vec![GeneralName {
                    kind: "email".into(),
                    value: "ana@lab.test".into()
                }],
            },
            key_spec: KeySpec::P384,
            key_target: KeyTarget::EncryptedFile {
                path: d.path().join("ana.key.p8"),
                password: Secret::new("pw"),
            },
            out: d.path().join("ana.csr"),
        }),
        "csr::new"
    )
    .unwrap();
    let shown = csr::show(&std::fs::read(&r.csr_path).unwrap()).unwrap();
    assert!(shown.signature_valid);
    assert_eq!(shown.key.curve.as_deref(), Some("P-384"));
    assert_eq!(shown, r.csr);
    if have_openssl() {
        let o = Command::new("openssl")
            .args(["req", "-verify", "-noout", "-in"])
            .arg(&r.csr_path)
            .output()
            .unwrap();
        assert!(o.status.success());
    }
}

/// SoftHSM2 (CI): set RV_TEST_PKCS11_MODULE to libsofthsm2.so / softhsm2.dll, with a token initialised with
/// serial in RV_TEST_PKCS11_SERIAL and user PIN in RV_TEST_PKCS11_PIN.
#[test]
fn tokens_with_softhsm2() {
    let (Ok(module), Ok(serial), Ok(pin)) = (
        std::env::var("RV_TEST_PKCS11_MODULE"),
        std::env::var("RV_TEST_PKCS11_SERIAL"),
        std::env::var("RV_TEST_PKCS11_PIN"),
    ) else {
        eprintln!("skipping: RV_TEST_PKCS11_MODULE / _SERIAL / _PIN not set (SoftHSM2)");
        return;
    };
    let module = PathBuf::from(module);
    let list = or_skip!(tokens::list(&module), "tokens::list").unwrap();
    assert!(
        list.iter()
            .any(|t| t.serial.as_deref() == Some(serial.as_str()))
    );
    let pin = Secret::new(pin);
    // A root CA key on a token needs --confirm-root.
    let d = tempfile::tempdir().unwrap();
    let refused = pki::init_root(&InitRootRequest {
        ca_dir: d.path().join("root"),
        ca_id: "ci-root".into(),
        subject: SubjectSpec {
            rdns: vec![("CN".into(), "CI Root".into())],
            sans: vec![],
        },
        key_spec: KeySpec::P256,
        key_target: KeyTarget::Pkcs11 {
            module: module.clone(),
            token_serial: serial.clone(),
            pin: pin.clone(),
            key_label: "ci-root".into(),
        },
        validity_days: 30,
        confirm_root: false,
        actor: "test".into(),
    });
    assert_eq!(refused.unwrap_err().kind, ErrorKind::Policy);
    let loc = tokens::generate_key(&module, &serial, &pin, KeySpec::P256, "ci-key", true).unwrap();
    let KeyLocation::Pkcs11 { key_id_hex, .. } = loc else {
        panic!("not a token key")
    };
    let s = tokens::open(&module, &serial, &pin).unwrap();
    let spki = s.public_key_der(&key_id_hex).unwrap();
    let sig = s.sign(&key_id_hex, "ecdsa-sha256", b"data").unwrap();
    let pkey = openssl::pkey::PKey::public_key_from_der(&spki).unwrap();
    let mut v =
        openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
    v.update(b"data").unwrap();
    assert!(v.verify(&sig).unwrap());
}
