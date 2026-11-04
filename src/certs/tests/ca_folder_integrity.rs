//! CA folder integrity: ca.json and crl/latest.crl are covered by issued.jsonl (an edit outside the tool fails
//! every operation), `pki set --crl-url` is the recorded way to change ca.json, imported intermediates name
//! their parent, and the examiner profile keeps an RSA key.

use rv_certcheck_certs::*;
use std::path::Path;

const PW: &str = "integrity-test-pass";

fn subject(cn: &str) -> SubjectSpec {
    SubjectSpec {
        rdns: vec![("O".into(), "Rakvor Test".into()), ("CN".into(), cn.into())],
        sans: vec![],
    }
}

fn root(dir: &Path) -> CaFolder {
    pki::init_root(&InitRootRequest {
        ca_dir: dir.to_path_buf(),
        ca_id: "root".into(),
        subject: subject("Integrity Root"),
        key_spec: KeySpec::P256,
        key_target: KeyTarget::EncryptedFile {
            path: dir.join("keys/root.key.p8"),
            password: Secret::new(PW),
        },
        validity_days: 30,
        confirm_root: false,
        actor: "t".into(),
    })
    .unwrap()
}

fn crl(dir: &Path) -> CrlResult {
    pki::make_crl(&CrlRequest {
        ca_dir: dir.to_path_buf(),
        ca_unlock: KeyUnlock {
            secret: Secret::new(PW),
        },
        this_update: None,
        next_update_days: 7,
        actor: "t".into(),
    })
    .unwrap()
}

fn issue_req(dir: &Path, out: &Path, profile: IssueProfile, spec: Option<KeySpec>) -> IssueRequest {
    IssueRequest {
        ca_dir: dir.to_path_buf(),
        ca_unlock: KeyUnlock {
            secret: Secret::new(PW),
        },
        profile,
        subject: subject("Subject"),
        csr_der: None,
        key_spec: spec,
        key_target: Some(KeyTarget::EncryptedFile {
            path: out.join(format!("{}.key.p8", profile.name())),
            password: Secret::new(PW),
        }),
        p12_password: (profile == IssueProfile::Examiner).then(|| Secret::new(PW)),
        validity_days: 10,
        actor: "t".into(),
    }
}

fn refused(dir: &Path, what: &str) {
    let e = pki::open(dir).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Policy, "{e}");
    assert!(e.message.contains(what), "{e}");
}

#[test]
fn every_ca_json_written_is_recorded_and_verifies() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca");
    root(&ca);
    crl(&ca);
    let log = std::fs::read_to_string(ca.join("issued.jsonl")).unwrap();
    let recs: Vec<IssuedRecord> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let ca_json: Vec<_> = recs
        .iter()
        .filter(|r| r.action == "ca_json_written")
        .collect();
    assert_eq!(ca_json.len(), 2, "init-root and the CRL's next_crl_number");
    let sha = openssl::sha::sha256(&std::fs::read(ca.join("ca.json")).unwrap());
    assert_eq!(ca_json[1].file_sha256.as_deref(), Some(hex(&sha).as_str()));
    assert!(pki::open(&ca).is_ok());
}

#[test]
fn an_edited_ca_json_is_detected_by_every_operation() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca");
    root(&ca);
    let p = ca.join("ca.json");
    let t = std::fs::read_to_string(&p).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&t).unwrap();
    v["crl_url"] = "http://attacker.example/crl".into();
    std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    refused(&ca, "ca.json");
    let e = pki::issue(&issue_req(&ca, d.path(), IssueProfile::Tsa, None)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Policy);
    assert!(e.message.contains("ca.json"), "{e}");
    assert!(
        !d.path().join("tsa.key.p8").exists(),
        "refused before any key is made"
    );
    // allowed_profiles narrowed by hand: detected too.
    std::fs::write(&p, &t).unwrap();
    assert!(
        pki::open(&ca).is_ok(),
        "the recorded content verifies again"
    );
    v = serde_json::from_str(&t).unwrap();
    v["allowed_profiles"] = serde_json::json!(["tsa"]);
    std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    refused(&ca, "ca.json");
}

#[test]
fn an_edited_or_replaced_latest_crl_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca");
    root(&ca);
    let first = crl(&ca);
    let _second = crl(&ca);
    // latest.crl replaced by the older (validly signed) CRL.
    std::fs::copy(&first.path, ca.join("crl/latest.crl")).unwrap();
    refused(&ca, "latest.crl");
    // A recorded CRL altered.
    let d2 = tempfile::tempdir().unwrap();
    let ca2 = d2.path().join("ca");
    root(&ca2);
    let c = crl(&ca2);
    let mut b = std::fs::read(&c.path).unwrap();
    let n = b.len() - 3;
    b[n] ^= 1;
    std::fs::write(&c.path, b).unwrap();
    refused(&ca2, "crl/1.crl");
    // latest.crl removed.
    let d3 = tempfile::tempdir().unwrap();
    let ca3 = d3.path().join("ca");
    root(&ca3);
    crl(&ca3);
    std::fs::remove_file(ca3.join("crl/latest.crl")).unwrap();
    refused(&ca3, "latest.crl");
}

#[test]
fn pki_set_crl_url_is_recorded_and_used() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca");
    root(&ca);
    let (f, rec) = pki::set_crl_url(&ca, Some("http://pki.rakvor.test/root.crl"), "t").unwrap();
    assert_eq!(
        f.crl_url.as_deref(),
        Some("http://pki.rakvor.test/root.crl")
    );
    assert_eq!(rec.action, "ca_json_written");
    assert!(pki::open(&ca).is_ok());
    let r = pki::issue(&issue_req(&ca, d.path(), IssueProfile::Tsa, None)).unwrap();
    let pem = std::fs::read_to_string(&r.cert_path).unwrap();
    let x = openssl::x509::X509::from_pem(pem.as_bytes()).unwrap();
    let text = String::from_utf8(x.to_text().unwrap()).unwrap();
    assert!(text.contains("http://pki.rakvor.test/root.crl"), "{text}");
    // Clearing works; a bad URL is refused and changes nothing.
    pki::set_crl_url(&ca, None, "t").unwrap();
    assert_eq!(pki::open(&ca).unwrap().crl_url, None);
    let e = pki::set_crl_url(&ca, Some("file:///etc/passwd"), "t").unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidInput);
    assert!(pki::open(&ca).is_ok());
}

#[test]
fn imported_intermediate_names_its_parent() {
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("root");
    let rf = root(&ca);
    let inter = pki::issue(&issue_req(&ca, d.path(), IssueProfile::Intermediate, None)).unwrap();
    let int_cert = std::fs::read(&inter.cert_path).unwrap();
    let root_cert = std::fs::read(ca.join("certs/ca.crt")).unwrap();
    let key = match inter.key.clone().unwrap() {
        KeyLocation::EncryptedFile { path, .. } => path,
        k => panic!("{k:?}"),
    };
    let req = |dir: &str| ImportCaRequest {
        ca_dir: d.path().join(dir),
        ca_id: "issuing".into(),
        certificate: int_cert.clone(),
        key: KeyLocation::EncryptedFile {
            path: if Path::new(&key).is_absolute() {
                key.clone()
            } else {
                ca.join(&key).display().to_string()
            },
            format: "pkcs8-encrypted".into(),
        },
        unlock: KeyUnlock {
            secret: Secret::new(PW),
        },
        actor: "t".into(),
    };
    // Without --issuer-cert: subject and key id from the certificate.
    let f = pki::import_ca(&req("a")).unwrap();
    assert_eq!(f.kind, CaKind::Intermediate);
    assert_eq!(f.parent_subject.as_deref(), Some(rf.subject.as_str()));
    let root_x = openssl::x509::X509::from_pem(&root_cert).unwrap();
    assert_eq!(
        f.parent_key_id_hex.as_deref(),
        Some(hex(root_x.subject_key_id().unwrap().as_slice()).as_str())
    );
    assert_eq!(f.parent_certificate_sha256, None);
    // With it: the issuer certificate's SHA-256.
    let f = pki::import_ca_with_issuer(&req("b"), Some(&root_cert)).unwrap();
    assert_eq!(
        f.parent_certificate_sha256.as_deref(),
        Some(rf.certificate_sha256.as_str())
    );
    assert!(pki::open(&d.path().join("b")).is_ok());
    // A certificate that did not issue it is refused.
    let e = pki::import_ca_with_issuer(&req("c"), Some(&int_cert)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Policy);
    assert!(!d.path().join("c/ca.json").exists());
}

#[test]
fn examiner_keys_are_rsa_by_default_and_ec_is_refused_unless_allowed() {
    assert_eq!(
        pki::default_key_spec(IssueProfile::Examiner),
        KeySpec::Rsa3072
    );
    assert_eq!(
        pki::default_key_spec(IssueProfile::CodeSigning),
        KeySpec::Rsa3072
    );
    assert_eq!(
        pki::default_key_spec(IssueProfile::Intermediate),
        KeySpec::P384
    );
    assert_eq!(pki::default_key_spec(IssueProfile::Tsa), KeySpec::P256);
    assert_eq!(
        pki::default_key_spec(IssueProfile::TlsServer),
        KeySpec::P256
    );
    assert_eq!(pki::ROOT_DEFAULT_KEY_SPEC, KeySpec::Rsa4096);
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca");
    root(&ca);
    for spec in [KeySpec::P256, KeySpec::P384, KeySpec::Ed25519] {
        let e = pki::issue(&issue_req(
            &ca,
            d.path(),
            IssueProfile::Examiner,
            Some(spec),
        ))
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Policy, "{spec:?}");
        assert!(e.message.contains("rv-hashinv"), "{e}");
    }
    assert!(!d.path().join("examiner.key.p8").exists());
    let ok = pki::issue_with(
        &issue_req(&ca, d.path(), IssueProfile::Examiner, Some(KeySpec::P256)),
        &IssueOptions {
            allow_non_rsa_examiner: true,
        },
    );
    assert!(ok.is_ok(), "{ok:?}");
}
