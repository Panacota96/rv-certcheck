//! Agent B's own tests of lab sets (beyond the acceptance byte-identity / openssl verify test) and of PKCS#11
//! tokens with SoftHSM2 (env-gated like the acceptance test: RV_TEST_PKCS11_MODULE / _SERIAL / _PIN).

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn openssl(args: &[&str]) -> Option<(bool, String)> {
    let o = Command::new("openssl").args(args).output().ok()?;
    Some((
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr),
    ))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn spec(dir: &Path, name: &str, seed: u64, base: &str) -> LabSetSpec {
    LabSetSpec {
        name: name.into(),
        seed,
        base_time: base.into(),
        out_dir: dir.to_path_buf(),
    }
}

#[test]
fn lab_sets_minimal_base_time_refusals_and_ocsp_oracle() {
    let d = tempfile::tempdir().unwrap();
    let m = lab::make(&spec(
        &d.path().join("min"),
        "minimal",
        1,
        "2026-01-01T00:00:00Z",
    ))
    .unwrap();
    let kinds: Vec<LabCaseKind> = m.cases.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [
            LabCaseKind::ValidChain,
            LabCaseKind::Expired,
            LabCaseKind::RevokedByCrl,
            LabCaseKind::KeyMismatch
        ]
    );
    // Same seed, other base time: other bytes. The set name is in every subject (OU), so full != minimal.
    let other = lab::make(&spec(&d.path().join("min2"), "minimal", 1, "2027-01-01")).unwrap();
    assert_eq!(other.base_time, "2027-01-01T00:00:00Z");
    assert_ne!(other.files, m.files);
    let full = lab::make(&spec(
        &d.path().join("full"),
        "full",
        1,
        "2026-01-01T00:00:00Z",
    ))
    .unwrap();
    assert_ne!(full.files["ca/root.crt"], m.files["ca/root.crt"]);
    // Refusals.
    assert_eq!(
        lab::make(&spec(&d.path().join("full"), "full", 1, "2026-01-01"))
            .unwrap_err()
            .kind,
        ErrorKind::Policy
    );
    assert_eq!(
        lab::make(&spec(&d.path().join("x"), "huge", 1, "2026-01-01"))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidInput
    );
    assert!(lab::make(&spec(&d.path().join("y"), "full", 1, "now")).is_err());
    // Every case's files exist; every written file is in the manifest.
    let set = d.path().join("full");
    for c in &full.cases {
        for f in &c.files {
            assert!(full.files.contains_key(f), "{}: {f}", c.id);
        }
        assert!(!c.expected_codes.is_empty(), "{}", c.id);
        for code in c.expected_codes.iter().chain(&c.forbidden_codes) {
            assert!(
                codes::severity(code).is_some(),
                "{code} is not a catalogue code"
            );
        }
    }
    // The lab PKCS#12 opens with the documented password; the policy is the lab one, never the internal one.
    let p12 = std::fs::read(set.join("valid-chain/leaf.p12")).unwrap();
    let parsed = openssl::pkcs12::Pkcs12::from_der(&p12)
        .unwrap()
        .parse2("rakvor-lab")
        .unwrap();
    assert_eq!(parsed.ca.map(|c| c.len()), Some(2));
    let leaf = std::fs::read(set.join("valid-chain/leaf.crt")).unwrap();
    let leaf_der = pem::parse(&leaf).unwrap().into_contents();
    let lab_oid = openssl::asn1::Asn1Object::from_str(RAKVOR_POLICY_LAB).unwrap();
    let int_oid = openssl::asn1::Asn1Object::from_str(RAKVOR_POLICY_INTERNAL).unwrap();
    assert!(
        leaf_der
            .windows(lab_oid.as_slice().len())
            .any(|w| w == lab_oid.as_slice())
    );
    assert!(
        !leaf_der
            .windows(int_oid.as_slice().len())
            .any(|w| w == int_oid.as_slice())
    );
    // The key-mismatch key really is a different key.
    let key = std::fs::read(set.join("key-mismatch/leaf.key")).unwrap();
    let k = openssl::pkey::PKey::private_key_from_pem(&key).unwrap();
    let c =
        openssl::x509::X509::from_pem(&std::fs::read(set.join("key-mismatch/leaf.crt")).unwrap())
            .unwrap();
    assert!(!c.public_key().unwrap().public_eq(&k));
    // The MD5 / SHA-1 cases really carry those algorithms.
    for (case, alg) in [
        ("md5-signed", "md5WithRSAEncryption"),
        ("sha1-signed", "sha1WithRSAEncryption"),
    ] {
        let c = openssl::x509::X509::from_pem(
            &std::fs::read(set.join(format!("{case}/leaf.crt"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            c.signature_algorithm().object().nid().long_name().unwrap(),
            alg
        );
    }

    let Some((_, _)) = openssl(&["version"]) else {
        eprintln!("skipping the openssl ocsp oracle: no openssl on PATH");
        return;
    };
    // OCSP oracle: the response verifies against the lab root and says revoked.
    let (ok, text) = openssl(&[
        "ocsp",
        "-respin",
        s(&set.join("revoked-by-ocsp/leaf.ocsp")),
        "-issuer",
        s(&set.join("ca/intermediate.crt")),
        "-CAfile",
        s(&set.join("ca/root.crt")),
        "-cert",
        s(&set.join("revoked-by-ocsp/leaf.crt")),
        "-no_nonce",
        "-attime",
        &chrono::DateTime::parse_from_rfc3339(&full.base_time)
            .unwrap()
            .timestamp()
            .to_string(),
        // `openssl ocsp` judges thisUpdate/nextUpdate against the wall clock (not -attime): the lab set is dated
        // from its base time, so allow ten years of skew.
        "-validity_period",
        "315360000",
    ])
    .unwrap();
    assert!(
        ok && text.contains("Response verify OK") && text.contains(": revoked"),
        "{text}"
    );
    assert!(text.contains("Reason: keyCompromise"), "{text}");
    // CRL oracle: the intermediate CRL lists exactly the revoked-by-crl leaf.
    let (_, text) = openssl(&[
        "crl",
        "-in",
        s(&set.join("ca/intermediate.crl")),
        "-noout",
        "-text",
    ])
    .unwrap();
    let serial =
        openssl::x509::X509::from_pem(&std::fs::read(set.join("revoked-by-crl/leaf.crt")).unwrap())
            .unwrap()
            .serial_number()
            .to_bn()
            .unwrap()
            .to_hex_str()
            .unwrap()
            .to_string();
    assert!(
        text.to_uppercase().contains(&serial.to_uppercase()),
        "{text}"
    );
    assert_eq!(text.matches("Serial Number:").count(), 1, "{text}");
}

fn token_env() -> Option<(PathBuf, String, Secret)> {
    let (Ok(m), Ok(s), Ok(p)) = (
        std::env::var("RV_TEST_PKCS11_MODULE"),
        std::env::var("RV_TEST_PKCS11_SERIAL"),
        std::env::var("RV_TEST_PKCS11_PIN"),
    ) else {
        eprintln!("skipping: RV_TEST_PKCS11_MODULE / _SERIAL / _PIN not set (SoftHSM2)");
        return None;
    };
    Some((PathBuf::from(m), s, Secret::new(p)))
}

/// A root generated on the token (with --confirm-root) issues an intermediate (file key) and a TSA certificate
/// under it is accepted by `openssl verify`; CRL and OCSP are signed on the token; a CSR key on the token too.
#[test]
fn softhsm_root_issues_an_intermediate_that_openssl_accepts() {
    let Some((module, serial, pin)) = token_env() else {
        return;
    };
    let d = tempfile::tempdir().unwrap();
    for (spec, label) in [
        (KeySpec::P256, "p256"),
        (KeySpec::Rsa2048, "rsa"),
        (KeySpec::P384, "p384"),
    ] {
        let ca = d.path().join(format!("token-root-{label}"));
        let root = pki::init_root(&InitRootRequest {
            ca_dir: ca.clone(),
            ca_id: format!("token-root-{label}"),
            subject: SubjectSpec {
                rdns: vec![
                    ("O".into(), "Rakvor CI".into()),
                    ("CN".into(), format!("Token Root {label}")),
                ],
                sans: vec![],
            },
            key_spec: spec,
            key_target: KeyTarget::Pkcs11 {
                module: module.clone(),
                token_serial: serial.clone(),
                pin: pin.clone(),
                key_label: format!("ci-root-{label}"),
            },
            validity_days: 365,
            confirm_root: true,
            actor: "ci".into(),
        })
        .unwrap();
        let KeyLocation::Pkcs11 {
            key_id_hex,
            key_label,
            token_serial,
            ..
        } = &root.key
        else {
            panic!("root key not on the token")
        };
        assert_eq!(token_serial, &serial);
        assert!(key_label.as_deref().unwrap().contains("--confirm-root"));
        // The key is visible (public facts only) and non-extractable.
        let session = tokens::open(&module, &serial, &pin).unwrap();
        let keys = session.keys().unwrap();
        assert!(keys.iter().any(|k| &k.key_id_hex == key_id_hex));
        drop(session);
        let unlock = KeyUnlock {
            secret: pin.clone(),
        };
        let inter = pki::issue(&IssueRequest {
            ca_dir: ca.clone(),
            ca_unlock: unlock.clone(),
            profile: IssueProfile::Intermediate,
            subject: SubjectSpec {
                rdns: vec![("CN".into(), format!("Token Intermediate {label}"))],
                sans: vec![],
            },
            csr_der: None,
            key_spec: Some(KeySpec::P256),
            key_target: Some(KeyTarget::EncryptedFile {
                path: d.path().join(format!("inter-{label}.key.p8")),
                password: Secret::new("inter pass"),
            }),
            p12_password: None,
            validity_days: 30,
            actor: "ci".into(),
        })
        .unwrap();
        // Manage the intermediate as its own CA folder and issue a TSA certificate under it.
        let sub = d.path().join(format!("sub-{label}"));
        let sub_ca = pki::import_ca(&ImportCaRequest {
            ca_dir: sub.clone(),
            ca_id: format!("sub-{label}"),
            certificate: std::fs::read(&inter.cert_path).unwrap(),
            key: inter.key.clone().unwrap(),
            unlock: KeyUnlock {
                secret: Secret::new("inter pass"),
            },
            actor: "ci".into(),
        });
        // The key location is relative to the root's CA folder? No: outside it, so absolute.
        let sub_ca = sub_ca.unwrap();
        assert_eq!(sub_ca.kind, CaKind::Intermediate);
        let tsa = pki::issue(&IssueRequest {
            ca_dir: sub.clone(),
            ca_unlock: KeyUnlock {
                secret: Secret::new("inter pass"),
            },
            profile: IssueProfile::Tsa,
            subject: SubjectSpec {
                rdns: vec![("CN".into(), "Token TSA".into())],
                sans: vec![],
            },
            csr_der: None,
            key_spec: Some(KeySpec::P256),
            key_target: Some(KeyTarget::EncryptedFile {
                path: d.path().join(format!("tsa-{label}.key.p8")),
                password: Secret::new("tsa pass"),
            }),
            p12_password: None,
            validity_days: 10,
            actor: "ci".into(),
        })
        .unwrap();
        pki::revoke(&RevokeRequest {
            ca_dir: ca.clone(),
            serial_hex: inter.record.serial_hex.clone().unwrap(),
            reason: "superseded".into(),
            revoked_at: None,
            actor: "ci".into(),
        })
        .unwrap();
        let crl = pki::make_crl(&CrlRequest {
            ca_dir: ca.clone(),
            ca_unlock: unlock.clone(),
            this_update: None,
            next_update_days: 3,
            actor: "ci".into(),
        })
        .unwrap();
        pki::sign_ocsp(&OcspSignRequest {
            ca_dir: ca.clone(),
            ca_unlock: unlock.clone(),
            serial_hex: inter.record.serial_hex.clone().unwrap(),
            produced_at: None,
            next_update_days: Some(1),
            out: d.path().join(format!("inter-{label}.ocsp")),
            actor: "ci".into(),
        })
        .unwrap();
        assert!(pki::open(&ca).is_ok());
        // A wrong PIN is a Password error.
        let bad = pki::make_crl(&CrlRequest {
            ca_dir: ca.clone(),
            ca_unlock: KeyUnlock {
                secret: Secret::new("000000-wrong"),
            },
            this_update: None,
            next_update_days: 3,
            actor: "ci".into(),
        });
        assert_eq!(bad.unwrap_err().kind, ErrorKind::Password);
        // No PIN in any file.
        let mut stack = vec![ca.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let b = std::fs::read(&p).unwrap();
                    assert!(
                        !String::from_utf8_lossy(&b).contains(pin.expose()),
                        "PIN in {}",
                        p.display()
                    );
                }
            }
        }
        if let Some((_, _)) = openssl(&["version"]) {
            let root_crt = ca.join("certs/ca.crt");
            let (ok, text) =
                openssl(&["verify", "-CAfile", s(&root_crt), s(&inter.cert_path)]).unwrap();
            assert!(ok, "{label}: {text}");
            let (ok, text) = openssl(&[
                "verify",
                "-CAfile",
                s(&root_crt),
                "-untrusted",
                s(&inter.cert_path),
                "-purpose",
                "timestampsign",
                s(&tsa.cert_path),
            ])
            .unwrap();
            assert!(ok, "{label}: {text}");
            let crl_pem = d.path().join(format!("{label}.crl.pem"));
            assert!(
                openssl(&[
                    "crl",
                    "-inform",
                    "DER",
                    "-in",
                    s(&crl.path),
                    "-out",
                    s(&crl_pem)
                ])
                .unwrap()
                .0
            );
            let (_, text) = openssl(&[
                "verify",
                "-crl_check",
                "-CAfile",
                s(&root_crt),
                "-CRLfile",
                s(&crl_pem),
                s(&inter.cert_path),
            ])
            .unwrap();
            assert!(text.contains("error 23"), "{label}: {text}");
            let (ok, text) = openssl(&[
                "ocsp",
                "-respin",
                s(&d.path().join(format!("inter-{label}.ocsp"))),
                "-issuer",
                s(&root_crt),
                "-CAfile",
                s(&root_crt),
                "-cert",
                s(&inter.cert_path),
                "-no_nonce",
            ])
            .unwrap();
            assert!(
                ok && text.contains("Response verify OK") && text.contains(": revoked"),
                "{label}: {text}"
            );
        }
    }
    // A CSR whose key is generated on the token.
    let c = csr::new(&CsrRequest {
        subject: SubjectSpec {
            rdns: vec![("CN".into(), "token csr".into())],
            sans: vec![],
        },
        key_spec: KeySpec::P256,
        key_target: KeyTarget::Pkcs11 {
            module: module.clone(),
            token_serial: serial.clone(),
            pin: pin.clone(),
            key_label: "ci-csr".into(),
        },
        out: d.path().join("token.csr"),
    })
    .unwrap();
    assert!(c.csr.signature_valid);
    assert!(matches!(c.key, KeyLocation::Pkcs11 { .. }));
    let listed = tokens::list(&module).unwrap();
    assert!(
        listed
            .iter()
            .any(|t| t.serial.as_deref() == Some(serial.as_str()) && t.login_required)
    );
    // Debug of a session never shows the PIN.
    let sess = tokens::open(&module, &serial, &pin).unwrap();
    assert!(!format!("{sess:?}").contains(pin.expose()));
}
