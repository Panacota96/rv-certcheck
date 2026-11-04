//! Agent B's own tests of the Rakvor PKI (beyond acceptance_creation.rs): every profile judged by the OpenSSL
//! command line, revocation through CRL and OCSP, the tamper-evident issuance log, import of an existing CA, and
//! a grep of every written file and Debug output for secrets.

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const ROOT_PW: &str = "Root-Pass phrase 0x51 (test only)";
const LEAF_PW: &str = "leaf-key-pass 7d2c";
const P12_PW: &str = "examiner-p12-pass 9b1e";

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
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

fn subject(cn: &str) -> SubjectSpec {
    SubjectSpec {
        rdns: vec![
            ("C".into(), "CO".into()),
            ("O".into(), "Rakvor Test".into()),
            ("CN".into(), cn.into()),
        ],
        sans: vec![],
    }
}

fn unlock(p: &str) -> KeyUnlock {
    KeyUnlock {
        secret: Secret::new(p),
    }
}

fn issue(
    ca: &Path,
    dir: &Path,
    profile: IssueProfile,
    cn: &str,
    sans: Vec<GeneralName>,
) -> IssueResult {
    pki::issue(&IssueRequest {
        ca_dir: ca.to_path_buf(),
        ca_unlock: unlock(ROOT_PW),
        profile,
        subject: SubjectSpec {
            sans,
            ..subject(cn)
        },
        csr_der: None,
        key_spec: Some(if profile == IssueProfile::Examiner {
            KeySpec::Rsa2048
        } else {
            KeySpec::P256
        }),
        key_target: Some(KeyTarget::EncryptedFile {
            path: dir.join(format!("{}.key.p8", profile.name())),
            password: Secret::new(LEAF_PW),
        }),
        p12_password: (profile == IssueProfile::Examiner).then(|| Secret::new(P12_PW)),
        validity_days: 365,
        actor: "tester".into(),
    })
    .unwrap()
}

fn openssl(args: &[&str]) -> (bool, String) {
    let o = Command::new("openssl").args(args).output().unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn round_trip_every_profile_revocation_and_tamper_evidence() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("rakvor-root");
    let out = d.path().join("issued");
    std::fs::create_dir_all(&out).unwrap();
    let root = pki::init_root(&InitRootRequest {
        ca_dir: ca.clone(),
        ca_id: "rakvor-test-root".into(),
        subject: subject("Rakvor Test Root CA"),
        key_spec: KeySpec::Rsa3072,
        key_target: KeyTarget::EncryptedFile {
            path: ca.join("keys").join("root.key.p8"),
            password: Secret::new(ROOT_PW),
        },
        validity_days: 3650,
        confirm_root: false,
        actor: "tester".into(),
    })
    .unwrap();
    assert_eq!(root.kind, CaKind::Root);
    assert_eq!(
        root.key,
        KeyLocation::EncryptedFile {
            path: "keys/root.key.p8".into(),
            format: "pkcs8-encrypted".into()
        }
    );
    // A second root in the same folder is refused.
    let again = pki::init_root(&InitRootRequest {
        ca_dir: ca.clone(),
        ca_id: "x".into(),
        subject: subject("X"),
        key_spec: KeySpec::P256,
        key_target: KeyTarget::EncryptedFile {
            path: d.path().join("x.key"),
            password: Secret::new("x"),
        },
        validity_days: 1,
        confirm_root: false,
        actor: "t".into(),
    });
    assert_eq!(again.unwrap_err().kind, ErrorKind::Policy);
    // A wrong CA password is a Password error and issues nothing.
    let bad = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock("not the password"),
        profile: IssueProfile::CodeSigning,
        subject: subject("Nope"),
        csr_der: None,
        key_spec: Some(KeySpec::P256),
        key_target: Some(KeyTarget::EncryptedFile {
            path: out.join("nope.key.p8"),
            password: Secret::new(LEAF_PW),
        }),
        p12_password: None,
        validity_days: 30,
        actor: "t".into(),
    });
    assert_eq!(bad.unwrap_err().kind, ErrorKind::Password);

    let dns = |v: &str| GeneralName {
        kind: "dns".into(),
        value: v.into(),
    };
    let inter = issue(
        &ca,
        &out,
        IssueProfile::Intermediate,
        "Rakvor Test Intermediate",
        vec![],
    );
    let code = issue(
        &ca,
        &out,
        IssueProfile::CodeSigning,
        "Rakvor Release Signing",
        vec![],
    );
    let exam = issue(
        &ca,
        &out,
        IssueProfile::Examiner,
        "Ana Ruiz",
        vec![GeneralName {
            kind: "email".into(),
            value: "ana@lab.test".into(),
        }],
    );
    let tsa = issue(&ca, &out, IssueProfile::Tsa, "Rakvor Test TSA", vec![]);
    let tls = issue(
        &ca,
        &out,
        IssueProfile::TlsServer,
        "hub.lab.test",
        vec![dns("hub.lab.test")],
    );
    // TLS without a SAN is refused before a key is made.
    let no_san = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        profile: IssueProfile::TlsServer,
        subject: subject("nosan"),
        csr_der: None,
        key_spec: None,
        key_target: Some(KeyTarget::EncryptedFile {
            path: out.join("nosan.key.p8"),
            password: Secret::new(LEAF_PW),
        }),
        p12_password: None,
        validity_days: 30,
        actor: "t".into(),
    });
    assert_eq!(no_san.unwrap_err().kind, ErrorKind::InvalidInput);
    assert!(!out.join("nosan.key.p8").exists());

    // Certificate contents.
    let ca_der = pem::parse(std::fs::read(ca.join("certs/ca.crt")).unwrap())
        .unwrap()
        .into_contents();
    let (_, ca_x) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
    let ca_ski = match ca_x
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .unwrap()
        .unwrap()
        .parsed_extension()
    {
        x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(k) => k.0.to_vec(),
        _ => panic!(),
    };
    let policy_oid = openssl::asn1::Asn1Object::from_str(RAKVOR_POLICY_INTERNAL).unwrap();
    for r in [&inter, &code, &exam, &tsa, &tls] {
        let der = pem::parse(std::fs::read(&r.cert_path).unwrap())
            .unwrap()
            .into_contents();
        let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
        // Serial: 16 octets, positive.
        let raw = x.raw_serial();
        assert_eq!(raw.len(), 16, "{:?}", r.record.profile);
        assert!(raw[0] < 0x80 && raw[0] != 0);
        assert_eq!(
            x.issuer().as_raw(),
            ca_x.subject().as_raw(),
            "issuer = CA subject, byte for byte"
        );
        let mut aki = None;
        let mut ski = false;
        let mut policy = false;
        let mut eku_critical = None;
        for e in x.extensions() {
            match e.parsed_extension() {
                x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(a) => {
                    aki = a.key_identifier.as_ref().map(|k| k.0.to_vec())
                }
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(_) => ski = true,
                x509_parser::extensions::ParsedExtension::CertificatePolicies(p) => {
                    // x509-parser's to_id_string() cannot print arcs above 64 bits (the 2.25 UUID arc): compare bytes.
                    policy = p
                        .iter()
                        .any(|i| i.policy_id.as_bytes() == policy_oid.as_slice())
                }
                x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(_) => {
                    eku_critical = Some(e.critical)
                }
                _ => {}
            }
        }
        assert_eq!(aki.as_deref(), Some(&ca_ski[..]));
        assert!(ski && policy);
        if r.record.profile == Some(IssueProfile::Tsa) {
            assert_eq!(eku_critical, Some(true), "TSA EKU must be critical");
        }
        if r.record.profile == Some(IssueProfile::Intermediate) {
            let bc = x.basic_constraints().unwrap().unwrap().value;
            assert!(bc.ca && bc.path_len_constraint == Some(0));
        }
    }
    // The examiner .p12 loads like rv-hashinv loads `--sign-cert` (p12-keystore, RSA key, chain to the root).
    let p12 = std::fs::read(exam.p12_path.as_ref().unwrap()).unwrap();
    let ks = p12_keystore::KeyStore::from_pkcs12(
        &p12,
        P12_PW,
        p12_keystore::Pkcs12ImportPolicy::Relaxed,
    )
    .unwrap();
    let (_, chain) = ks.private_key_chain().unwrap();
    assert_eq!(chain.certs().len(), 2);
    let k = openssl::pkey::PKey::private_key_from_pkcs8(chain.key().as_der()).unwrap();
    assert_eq!(k.id(), openssl::pkey::Id::RSA);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [
            exam.p12_path.clone().unwrap(),
            out.join("examiner.key.p8"),
            ca.join("keys/root.key.p8"),
        ] {
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o077,
                0,
                "{}",
                p.display()
            );
        }
        assert_eq!(
            std::fs::metadata(ca.join("keys"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    // Revoke the code-signing certificate, CRL, OCSP for revoked and good serials.
    let cs_serial = code.record.serial_hex.clone().unwrap();
    pki::revoke(&RevokeRequest {
        ca_dir: ca.clone(),
        serial_hex: cs_serial.to_uppercase(),
        reason: "keyCompromise".into(),
        revoked_at: Some("2026-01-02T03:04:05Z".into()),
        actor: "tester".into(),
    })
    .unwrap();
    let twice = pki::revoke(&RevokeRequest {
        ca_dir: ca.clone(),
        serial_hex: cs_serial.clone(),
        reason: "superseded".into(),
        revoked_at: None,
        actor: "tester".into(),
    });
    assert_eq!(twice.unwrap_err().kind, ErrorKind::Policy);
    let unknown = pki::revoke(&RevokeRequest {
        ca_dir: ca.clone(),
        serial_hex: "0102".into(),
        reason: "keyCompromise".into(),
        revoked_at: None,
        actor: "tester".into(),
    });
    assert_eq!(unknown.unwrap_err().kind, ErrorKind::InvalidInput);
    let crl1 = pki::make_crl(&CrlRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        this_update: None,
        next_update_days: 7,
        actor: "tester".into(),
    })
    .unwrap();
    assert_eq!(crl1.crl_number, 1);
    let crl2 = pki::make_crl(&CrlRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        this_update: None,
        next_update_days: 7,
        actor: "tester".into(),
    })
    .unwrap();
    assert_eq!(crl2.crl_number, 2);
    assert_eq!(pki::open(&ca).unwrap().next_crl_number, 3);
    let ocsp_rev = pki::sign_ocsp(&OcspSignRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        serial_hex: cs_serial.clone(),
        produced_at: None,
        next_update_days: Some(1),
        out: out.join("code.ocsp"),
        actor: "tester".into(),
    })
    .unwrap();
    assert!(
        matches!(&ocsp_rev.status, RevocationStatus::Revoked { reason, revoked_at, .. }
        if reason == "keyCompromise" && revoked_at == "2026-01-02T03:04:05Z")
    );
    let ocsp_good = pki::sign_ocsp(&OcspSignRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        serial_hex: tls.record.serial_hex.clone().unwrap(),
        produced_at: None,
        next_update_days: Some(1),
        out: out.join("tls.ocsp"),
        actor: "tester".into(),
    })
    .unwrap();
    assert!(matches!(ocsp_good.status, RevocationStatus::Good { .. }));
    // The OCSP response parses with the RustCrypto types too.
    {
        use der::Decode;
        let r = x509_ocsp::OcspResponse::from_der(&std::fs::read(out.join("code.ocsp")).unwrap())
            .unwrap();
        assert_eq!(r.response_status, x509_ocsp::OcspResponseStatus::Successful);
    }

    // issued.jsonl: root + its ca.json, 5 issued, 1 revoked, 2 CRLs each followed by the ca.json it rewrote,
    // 2 OCSP = 14 records, chain intact.
    let log = std::fs::read_to_string(ca.join("issued.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 14);
    assert!(pki::open(&ca).is_ok());
    let actions: Vec<String> = log
        .lines()
        .map(|l| serde_json::from_str::<IssuedRecord>(l).unwrap().action)
        .collect();
    assert_eq!(
        actions,
        [
            "ca_created",
            "ca_json_written",
            "issued",
            "issued",
            "issued",
            "issued",
            "issued",
            "revoked",
            "crl_issued",
            "ca_json_written",
            "crl_issued",
            "ca_json_written",
            "ocsp_signed",
            "ocsp_signed"
        ]
    );
    for l in log.lines() {
        let r: IssuedRecord = serde_json::from_str(l).unwrap();
        assert_eq!(r.actor, "tester");
        if r.action == "issued" {
            assert!(
                r.serial_hex.is_some()
                    && r.profile.is_some()
                    && r.subject.is_some()
                    && r.cert_sha256.is_some()
            );
        }
    }

    // No secret in any file written, nor in Debug output.
    let root_key = std::fs::read(ca.join("keys/root.key.p8")).unwrap();
    let root_der = pem::parse(&root_key).unwrap().into_contents();
    let root_pk =
        openssl::pkey::PKey::private_key_from_pkcs8_passphrase(&root_der, ROOT_PW.as_bytes())
            .unwrap();
    let plain = root_pk.private_key_to_pkcs8().unwrap();
    let d_bytes = root_pk.rsa().unwrap().d().to_vec();
    let exam_key = pem::parse(std::fs::read(out.join("examiner.key.p8")).unwrap())
        .unwrap()
        .into_contents();
    let exam_pk =
        openssl::pkey::PKey::private_key_from_pkcs8_passphrase(&exam_key, LEAF_PW.as_bytes())
            .unwrap();
    let exam_plain = exam_pk.private_key_to_pkcs8().unwrap();
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("root password", ROOT_PW.as_bytes().to_vec()),
        ("leaf password", LEAF_PW.as_bytes().to_vec()),
        ("p12 password", P12_PW.as_bytes().to_vec()),
        ("root PKCS#8", plain[plain.len() - 64..].to_vec()),
        ("root d", d_bytes[..32].to_vec()),
        (
            "root d hex",
            rv_certcheck_certs::hex(&d_bytes[..32]).into_bytes(),
        ),
        (
            "examiner PKCS#8",
            exam_plain[exam_plain.len() - 64..].to_vec(),
        ),
    ];
    let b64 = |b: &[u8]| pem::encode(&pem::Pem::new("X", b.to_vec()));
    let plain_b64 = b64(&plain);
    let plain_line = plain_b64.lines().nth(3).unwrap().to_string();
    for (p, bytes) in files(d.path()) {
        for (what, n) in &needles {
            assert!(
                !bytes.windows(n.len()).any(|w| w == &n[..]),
                "{what} found in {}",
                p.display()
            );
        }
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&plain_line),
            "root key base64 in {}",
            p.display()
        );
    }
    let debug = format!(
        "{:?}{:?}{:?}{:?}{:?}{:?}",
        root,
        exam,
        crl1,
        ocsp_rev,
        unlock(ROOT_PW),
        IssueRequest {
            ca_dir: ca.clone(),
            ca_unlock: unlock(ROOT_PW),
            profile: IssueProfile::Examiner,
            subject: subject("x"),
            csr_der: None,
            key_spec: None,
            key_target: Some(KeyTarget::EncryptedFile {
                path: out.join("x"),
                password: Secret::new(LEAF_PW)
            }),
            p12_password: Some(Secret::new(P12_PW)),
            validity_days: 1,
            actor: "t".into()
        }
    );
    for (what, n) in &needles[..3] {
        assert!(
            !debug.contains(std::str::from_utf8(n).unwrap()),
            "{what} in Debug output"
        );
    }

    if have_openssl() {
        let ca_crt = ca.join("certs/ca.crt");
        // `-purpose codesign` exists from OpenSSL 3.2; older CLIs check the chain without it.
        let codesign = if openssl(&[
            "verify",
            "-purpose",
            "codesign",
            "-CAfile",
            s(&ca_crt),
            s(&ca_crt),
        ])
        .1
        .contains("Invalid purpose")
        {
            None
        } else {
            Some("codesign")
        };
        for (r, purpose) in [
            (&inter, None),
            (&code, codesign),
            (&exam, Some("smimesign")),
            (&tsa, Some("timestampsign")),
            (&tls, Some("sslserver")),
        ] {
            let mut a = vec!["verify", "-CAfile", s(&ca_crt)];
            if let Some(p) = purpose {
                a.extend(["-purpose", p]);
            }
            a.push(s(&r.cert_path));
            let (ok, text) = openssl(&a);
            assert!(
                ok && text.contains(": OK"),
                "{:?}: {text}",
                r.record.profile
            );
        }
        // With the CRL: the revoked code-signing certificate is error 23, the TLS one still OK.
        let crl_pem = d.path().join("crl.pem");
        assert!(
            openssl(&[
                "crl",
                "-inform",
                "DER",
                "-in",
                s(&crl2.path),
                "-out",
                s(&crl_pem)
            ])
            .0
        );
        let (_, text) = openssl(&[
            "verify",
            "-crl_check",
            "-CAfile",
            s(&ca_crt),
            "-CRLfile",
            s(&crl_pem),
            s(&code.cert_path),
        ]);
        assert!(text.contains("error 23"), "{text}");
        let (ok, text) = openssl(&[
            "verify",
            "-crl_check",
            "-CAfile",
            s(&ca_crt),
            "-CRLfile",
            s(&crl_pem),
            s(&tls.cert_path),
        ]);
        assert!(ok, "{text}");
        let (_, text) = openssl(&[
            "crl",
            "-inform",
            "DER",
            "-in",
            s(&crl2.path),
            "-noout",
            "-text",
        ]);
        assert!(
            text.contains("X509v3 CRL Number") && text.contains("Key Compromise"),
            "{text}"
        );
        // OCSP: the response verifies against the CA and says revoked / good.
        let (ok, text) = openssl(&[
            "ocsp",
            "-respin",
            s(&out.join("code.ocsp")),
            "-issuer",
            s(&ca_crt),
            "-CAfile",
            s(&ca_crt),
            "-cert",
            s(&code.cert_path),
            "-no_nonce",
        ]);
        assert!(
            ok && text.contains("Response verify OK") && text.contains(": revoked"),
            "{text}"
        );
        let (ok, text) = openssl(&[
            "ocsp",
            "-respin",
            s(&out.join("tls.ocsp")),
            "-issuer",
            s(&ca_crt),
            "-CAfile",
            s(&ca_crt),
            "-cert",
            s(&tls.cert_path),
            "-no_nonce",
        ]);
        assert!(
            ok && text.contains("Response verify OK") && text.contains(": good"),
            "{text}"
        );
        // The examiner .p12 opens with the OpenSSL CLI (AES-256-CBC / PBKDF2 / SHA-256 MAC).
        let (ok, text) = openssl(&[
            "pkcs12",
            "-in",
            s(exam.p12_path.as_ref().unwrap()),
            "-noout",
            "-passin",
            &format!("pass:{P12_PW}"),
        ]);
        assert!(ok, "{text}");
        // The encrypted key files open with the OpenSSL CLI.
        let (ok, text) = openssl(&[
            "pkey",
            "-in",
            s(&ca.join("keys/root.key.p8")),
            "-noout",
            "-passin",
            &format!("pass:{ROOT_PW}"),
        ]);
        assert!(ok, "{text}");
        let (_, text) = openssl(&["asn1parse", "-in", s(&ca.join("keys/root.key.p8"))]);
        assert!(
            text.contains("PBES2")
                && text.contains("PBKDF2")
                && text.contains("aes-256-cbc")
                && text.contains("hmacWithSHA256"),
            "{text}"
        );
    }

    // Tampering: edit one line, delete one line, change a recorded file. Each is detected and blocks issuance.
    let path = ca.join("issued.jsonl");
    let orig = std::fs::read_to_string(&path).unwrap();
    let edited = orig.replacen(
        "\"profile\":\"code-signing\"",
        "\"profile\":\"tls-server\"",
        1,
    );
    assert_ne!(edited, orig);
    std::fs::write(&path, &edited).unwrap();
    let e = pki::open(&ca).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Policy);
    assert!(e.message.contains("edited record"), "{}", e.message);
    let blocked = pki::make_crl(&CrlRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        this_update: None,
        next_update_days: 7,
        actor: "t".into(),
    });
    assert_eq!(blocked.unwrap_err().kind, ErrorKind::Policy);
    let lines: Vec<&str> = orig.lines().collect();
    let deleted: String = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 3)
        .map(|(_, l)| format!("{l}\n"))
        .collect();
    std::fs::write(&path, deleted).unwrap();
    assert!(pki::open(&ca).unwrap_err().message.contains("sequence"));
    std::fs::write(&path, &orig).unwrap();
    assert!(pki::open(&ca).is_ok());
    let crt = code.cert_path.clone();
    let keep = std::fs::read(&crt).unwrap();
    std::fs::write(&crt, std::fs::read(&tls.cert_path).unwrap()).unwrap();
    assert!(pki::open(&ca).unwrap_err().message.contains("modified"));
    std::fs::write(&crt, keep).unwrap();
    assert!(pki::open(&ca).is_ok());
}

#[test]
fn issue_from_a_csr_and_refuse_a_forged_one() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca");
    pki::init_root(&InitRootRequest {
        ca_dir: ca.clone(),
        ca_id: "csr-root".into(),
        subject: subject("CSR Root"),
        key_spec: KeySpec::P384,
        key_target: KeyTarget::EncryptedFile {
            path: ca.join("keys/ca.key.p8"),
            password: Secret::new(ROOT_PW),
        },
        validity_days: 100,
        confirm_root: false,
        actor: "t".into(),
    })
    .unwrap();
    let c = csr::new(&CsrRequest {
        subject: SubjectSpec {
            rdns: vec![("CN".into(), "svc.lab.test".into())],
            sans: vec![
                GeneralName {
                    kind: "dns".into(),
                    value: "svc.lab.test".into(),
                },
                GeneralName {
                    kind: "ip".into(),
                    value: "192.0.2.10".into(),
                },
            ],
        },
        key_spec: KeySpec::Rsa2048,
        key_target: KeyTarget::EncryptedFile {
            path: d.path().join("svc.key.p8"),
            password: Secret::new(LEAF_PW),
        },
        out: d.path().join("svc.csr"),
    })
    .unwrap();
    assert_eq!(c.csr.sans.len(), 2);
    assert_eq!(c.csr.sans[1].value, "192.0.2.10");
    assert_eq!(c.csr.requested_extensions[0].name, "subjectAltName");
    assert_eq!(c.csr.signature_algorithm, "sha256WithRSAEncryption");
    let csr_bytes = std::fs::read(&c.csr_path).unwrap();
    let r = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        profile: IssueProfile::TlsServer,
        subject: SubjectSpec::default(),
        csr_der: Some(csr_bytes.clone()),
        key_spec: Some(KeySpec::P256),
        key_target: None,
        p12_password: None,
        validity_days: 10,
        actor: "t".into(),
    })
    .unwrap();
    assert!(r.key.is_none() && r.record.key.is_none());
    assert_eq!(r.record.subject.as_deref(), Some("CN=svc.lab.test"));
    let cert = openssl::x509::X509::from_pem(&std::fs::read(&r.cert_path).unwrap()).unwrap();
    let csr_key = openssl::x509::X509Req::from_pem(&csr_bytes)
        .unwrap()
        .public_key()
        .unwrap();
    assert!(cert.public_key().unwrap().public_eq(&csr_key));
    assert_eq!(cert.subject_alt_names().unwrap().len(), 2);
    // Forged: flip a bit of the CSR signature.
    let mut der = pem::parse(&csr_bytes).unwrap().into_contents();
    let n = der.len() - 1;
    der[n] ^= 1;
    assert!(!csr::show(&der).unwrap().signature_valid);
    let forged = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        profile: IssueProfile::TlsServer,
        subject: SubjectSpec::default(),
        csr_der: Some(der),
        key_spec: None,
        key_target: None,
        p12_password: None,
        validity_days: 10,
        actor: "t".into(),
    });
    assert_eq!(forged.unwrap_err().kind, ErrorKind::Policy);
    // Validity is capped at the CA's notAfter.
    let long = pki::issue(&IssueRequest {
        ca_dir: ca.clone(),
        ca_unlock: unlock(ROOT_PW),
        profile: IssueProfile::CodeSigning,
        subject: subject("Long"),
        csr_der: None,
        key_spec: Some(KeySpec::P256),
        key_target: Some(KeyTarget::EncryptedFile {
            path: d.path().join("long.key.p8"),
            password: Secret::new(LEAF_PW),
        }),
        p12_password: None,
        validity_days: 10_000,
        actor: "t".into(),
    })
    .unwrap();
    assert_eq!(
        long.record.not_after,
        Some(pki::open(&ca).unwrap().not_after)
    );
}

/// An existing CA made with the OpenSSL CLI the way Rakvor's code-signing root is (RSA 4096 → 2048 here for speed,
/// UTF8String names, pathlen 0, keyCertSign + cRLSign, SKI), its key as PKCS#12 and as encrypted PKCS#8.
#[test]
fn import_an_existing_ca_and_refuse_a_foreign_key() {
    if !have_openssl() {
        eprintln!("skipping: no openssl on PATH");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let p = |n: &str| d.path().join(n);
    let cnf = p("ca.cnf");
    std::fs::write(
        &cnf,
        "[req]\ndistinguished_name=dn\nprompt=no\nstring_mask=utf8only\n[dn]\nCN=Rakvor Internal Code Signing Root CA\nO=Rakvor\n[v3]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
    )
    .unwrap();
    assert!(
        openssl(&[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            s(&p("k.pem"))
        ])
        .0
    );
    assert!(
        openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            s(&p("k.pem")),
            "-config",
            s(&cnf),
            "-extensions",
            "v3",
            "-days",
            "3650",
            "-outform",
            "DER",
            "-out",
            s(&p("root.cer"))
        ])
        .0
    );
    assert!(
        openssl(&[
            "x509",
            "-inform",
            "DER",
            "-in",
            s(&p("root.cer")),
            "-out",
            s(&p("root.pem"))
        ])
        .0
    );
    assert!(
        openssl(&[
            "pkcs12",
            "-export",
            "-inkey",
            s(&p("k.pem")),
            "-in",
            s(&p("root.pem")),
            "-passout",
            "pass:offline-pfx",
            "-out",
            s(&p("root.pfx"))
        ])
        .0
    );
    assert!(
        openssl(&[
            "pkcs8",
            "-topk8",
            "-in",
            s(&p("k.pem")),
            "-v2",
            "aes-256-cbc",
            "-passout",
            "pass:offline-p8",
            "-out",
            s(&p("k.p8"))
        ])
        .0
    );
    let cert = std::fs::read(p("root.cer")).unwrap();

    // The bundled Rakvor root with a key that is not its key: refused, nothing written.
    let foreign = pki::import_ca(&ImportCaRequest {
        ca_dir: p("rakvor"),
        ca_id: "rakvor-code-signing-root".into(),
        certificate: RAKVOR_ROOT_DER.to_vec(),
        key: KeyLocation::EncryptedFile {
            path: s(&p("k.p8")).into(),
            format: "pkcs8-encrypted".into(),
        },
        unlock: unlock("offline-p8"),
        actor: "t".into(),
    });
    let e = foreign.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Policy);
    assert!(e.message.contains("does not match"));
    assert!(!p("rakvor").join("ca.json").exists());

    for (dir, key, pw, fmt) in [
        ("imp-pfx", "root.pfx", "offline-pfx", "pkcs12"),
        ("imp-p8", "k.p8", "offline-p8", "pkcs8-encrypted"),
    ] {
        let f = pki::import_ca(&ImportCaRequest {
            ca_dir: p(dir),
            ca_id: "rakvor-code-signing-root".into(),
            certificate: cert.clone(),
            key: KeyLocation::EncryptedFile {
                path: s(&p(key)).into(),
                format: "pkcs8-encrypted".into(),
            },
            unlock: unlock(pw),
            actor: "t".into(),
        })
        .unwrap();
        assert_eq!(f.kind, CaKind::Imported);
        assert!(
            matches!(&f.key, KeyLocation::EncryptedFile { format, path } if format == fmt && Path::new(path).is_absolute())
        );
        assert!(
            !f.allowed_profiles.contains(&IssueProfile::Intermediate),
            "pathlen 0"
        );
        let inter = pki::issue(&IssueRequest {
            ca_dir: p(dir),
            ca_unlock: unlock(pw),
            profile: IssueProfile::Intermediate,
            subject: subject("Sub CA"),
            csr_der: None,
            key_spec: Some(KeySpec::P256),
            key_target: Some(KeyTarget::EncryptedFile {
                path: p(&format!("{dir}-sub.key.p8")),
                password: Secret::new(LEAF_PW),
            }),
            p12_password: None,
            validity_days: 30,
            actor: "t".into(),
        });
        assert!(inter.unwrap_err().message.contains("pathLenConstraint 0"));
        let cs = pki::issue(&IssueRequest {
            ca_dir: p(dir),
            ca_unlock: unlock(pw),
            profile: IssueProfile::CodeSigning,
            subject: SubjectSpec {
                rdns: vec![
                    ("O".into(), "Rakvor".into()),
                    ("CN".into(), "Rakvor Release 2026".into()),
                ],
                sans: vec![],
            },
            csr_der: None,
            key_spec: Some(KeySpec::Rsa3072),
            key_target: Some(KeyTarget::EncryptedFile {
                path: p(&format!("{dir}-cs.key.p8")),
                password: Secret::new(LEAF_PW),
            }),
            p12_password: None,
            validity_days: 365,
            actor: "t".into(),
        })
        .unwrap();
        let (ok, text) = openssl(&[
            "verify",
            "-CAfile",
            s(&p(dir).join("certs/ca.crt")),
            s(&cs.cert_path),
        ]);
        assert!(ok, "{text}");
        let leaf = openssl::x509::X509::from_pem(&std::fs::read(&cs.cert_path).unwrap()).unwrap();
        let root = openssl::x509::X509::from_der(&cert).unwrap();
        assert_eq!(
            leaf.issuer_name().to_der().unwrap(),
            root.subject_name().to_der().unwrap()
        );
        assert_eq!(
            leaf.authority_key_id().unwrap().as_slice(),
            root.subject_key_id().unwrap().as_slice()
        );
    }
}
