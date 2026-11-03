//! Acceptance tests for agent A (analysis). Architect-owned: make them pass, do not weaken them. Each test skips,
//! with a message, while the function it exercises is still a stub (ErrorKind::NotImplemented).
//!
//! Oracle: tests/fixtures/openssl, made by tests/fixtures/make_with_openssl.sh with the OpenSSL CLI only, and
//! openssl-verify.tsv, which records `openssl verify -attime 2026-06-01 -CAfile root.crt -untrusted
//! intermediate.crt -crl_check -CRLfile intermediate.crl` for every leaf.

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};

const AT: &str = "2026-06-01T00:00:00Z";

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openssl")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fx(name)).unwrap()
}

/// PEM certificate fixture → DER (the fixtures are PEM; the request takes DER).
fn der(name: &str) -> Vec<u8> {
    openssl::x509::X509::from_pem(&read(name))
        .unwrap()
        .to_der()
        .unwrap()
}

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

#[test]
fn sniff_recognises_every_fixture_by_content() {
    let cases = [
        ("root.crt", InputKind::Certificate),
        ("leaf.crt", InputKind::Certificate),
        ("chain-bundle.pem", InputKind::CertBundle),
        ("chain.p7b", InputKind::Pkcs7),
        ("leaf.p12", InputKind::Pkcs12),
        ("intermediate.crl", InputKind::Crl),
        ("leaf-revoked.ocsp", InputKind::OcspResponse),
        ("data.tsr", InputKind::TimestampToken),
        ("data.tst", InputKind::TimestampToken),
        ("leaf.key", InputKind::PrivateKey),
        ("leaf.csr", InputKind::Csr),
        ("data.txt", InputKind::Unknown),
        ("openssl-verify.tsv", InputKind::Unknown),
    ];
    for (f, kind) in cases {
        let s = or_skip!(sniff(&read(f)), "sniff").unwrap();
        assert_eq!(s.kind.0, kind, "{f}");
    }
    // Hostile input never fails: empty, truncated DER, garbage.
    for junk in [
        &b""[..],
        b"\x30\x82\xff\xff",
        b"-----BEGIN CERTIFICATE-----\n!!\n",
    ] {
        assert!(sniff(junk).is_ok());
    }
}

#[test]
fn parse_any_reads_the_fields_openssl_reads() {
    let p = or_skip!(parse_any(&read("leaf.crt"), None), "parse_any").unwrap();
    let c = &p.certificates[0];
    assert_eq!(c.serial_hex, "2001");
    assert_eq!(c.not_before, "2026-01-01T00:00:00Z");
    assert_eq!(c.not_after, "2028-01-01T00:00:00Z");
    assert_eq!(c.subject, "C=CO, O=Rakvor Lab, CN=leaf.lab.rakvor.test");
    assert_eq!(
        c.issuer,
        "C=CO, O=Rakvor Lab, CN=Rakvor Lab Intermediate CA"
    );
    assert!(
        c.sans
            .iter()
            .any(|s| s.kind == "dns" && s.value == "leaf.lab.rakvor.test")
    );
    assert_eq!((c.key.algorithm.as_str(), c.key.bits), ("rsa", Some(2048)));
    assert_eq!(c.signature_algorithm, "sha256WithRSAEncryption");
    assert!(c.eku.contains(&"serverAuth".to_string()));
    assert_eq!(
        c.crl_dps,
        vec!["http://pki.lab.rakvor.test/intermediate.crl".to_string()]
    );
    assert_eq!(c.aia_ocsp, vec!["http://ocsp.lab.rakvor.test".to_string()]);
    let x = openssl::x509::X509::from_pem(&read("leaf.crt")).unwrap();
    let fp = |m| hex(&x.digest(m).unwrap());
    assert_eq!(c.sha256, fp(openssl::hash::MessageDigest::sha256()));
    assert_eq!(c.sha1, fp(openssl::hash::MessageDigest::sha1()));
    assert!(!c.self_signed);
    let root = parse_any(&read("root.crt"), None).unwrap();
    assert!(root.certificates[0].self_signed);
    assert!(
        root.signals
            .iter()
            .any(|s| s.code == codes::CERT_SELF_SIGNED)
    );
    let weak = parse_any(&read("leaf-rsa1024.crt"), None).unwrap();
    assert!(weak.signals.iter().any(|s| s.code == codes::CERT_WEAK_KEY));
    let sha1 = parse_any(&read("leaf-sha1.crt"), None).unwrap();
    assert!(
        sha1.signals
            .iter()
            .any(|s| s.code == codes::CERT_WEAK_SIGNATURE_ALGORITHM)
    );
    // PKCS#12: with the password the key facts appear; without it, PKCS12_UNREADABLE or a Password error.
    let pw = Secret::new("rakvor-lab");
    let p12 = parse_any(&read("leaf.p12"), Some(&pw)).unwrap();
    assert_eq!(p12.private_key.unwrap().spki_sha256, c.key.spki_sha256);
    match parse_any(&read("leaf.p12"), None) {
        Ok(p) => assert!(p.signals.iter().any(|s| s.code == codes::PKCS12_UNREADABLE)),
        Err(e) => assert_eq!(e.kind, ErrorKind::Password),
    }
    let crl = parse_any(&read("intermediate.crl"), None).unwrap();
    assert_eq!(crl.crls[0].revoked[0].serial_hex, "2004");
    assert_eq!(crl.crls[0].revoked[0].revoked_at, "2026-02-01T00:00:00Z");
    assert_eq!(crl.crls[0].revoked[0].reason, "keyCompromise");
}

#[test]
fn validate_chain_agrees_with_openssl_verify() {
    let tsv = std::fs::read_to_string(fx("openssl-verify.tsv")).unwrap();
    let anchors = vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", der("root.crt"))],
        ..Default::default()
    }];
    let untrusted = vec![der("intermediate.crt")];
    let crls = vec![LabeledDer::new(
        "file:intermediate.crl",
        read("intermediate.crl"),
    )];
    let opts = ValidationOptions {
        at: AtTime::Fixed(AT.into()),
        ..Default::default()
    };
    for line in tsv.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (file, code) = (cols[0], cols[1].parse::<i32>().unwrap());
        let target = der(file);
        let req = ChainRequest {
            target_der: &target,
            untrusted_der: &untrusted,
            anchors: &anchors,
            crls: &crls,
            ..Default::default()
        };
        let v = or_skip!(validate_chain(&req, &opts), "validate_chain").unwrap();
        assert_eq!(v.openssl_code, code, "{file}: {}", v.openssl_reason);
        assert_eq!(v.at, AT);
        assert!(!v.nodes.is_empty() && v.nodes[0].depth == 0, "{file}");
        let has = |c: &str| v.signals.iter().any(|s| s.code == c);
        match code {
            0 => assert!(
                has(codes::CERT_CHAIN_VALID) && v.status == ChainStatus::Valid,
                "{file}"
            ),
            10 => assert!(has(codes::CERT_EXPIRED_AT_DATE), "{file}"),
            9 => assert!(has(codes::CERT_NOT_YET_VALID_AT_DATE), "{file}"),
            23 => assert!(has(codes::CERT_REVOKED), "{file}"),
            20 => assert!(
                has(codes::CERT_CHAIN_UNTRUSTED) && v.status == ChainStatus::Untrusted,
                "{file}"
            ),
            _ => {}
        }
        if code == 0 {
            // 3 levels: leaf, intermediate, root (anchor).
            assert_eq!(v.nodes.len(), 3, "{file}");
            assert!(v.nodes[2].anchor.is_some(), "{file}");
        }
    }
    // No anchor at all: built, checked, untrusted.
    let target = der("leaf.crt");
    let req = ChainRequest {
        target_der: &target,
        untrusted_der: &untrusted,
        ..Default::default()
    };
    let v = validate_chain(&req, &opts).unwrap();
    assert_eq!(v.status, ChainStatus::Untrusted);
}

#[test]
fn revocation_from_crl_and_ocsp() {
    let crls = vec![LabeledDer::new(
        "file:intermediate.crl",
        read("intermediate.crl"),
    )];
    let r = or_skip!(
        check_revocation(
            &der("leaf-revoked.crt"),
            &der("intermediate.crt"),
            &crls,
            &[],
            AT
        ),
        "check_revocation"
    )
    .unwrap();
    match r {
        RevocationStatus::Revoked {
            reason, revoked_at, ..
        } => {
            assert_eq!(reason, "keyCompromise");
            assert_eq!(revoked_at, "2026-02-01T00:00:00Z");
        }
        other => panic!("{other:?}"),
    }
    let good =
        check_revocation(&der("leaf.crt"), &der("intermediate.crt"), &crls, &[], AT).unwrap();
    assert!(matches!(good, RevocationStatus::Good { .. }), "{good:?}");
    let none = check_revocation(&der("leaf.crt"), &der("intermediate.crt"), &[], &[], AT).unwrap();
    assert!(matches!(none, RevocationStatus::Unknown { .. }));
    let ocsp = vec![LabeledDer::new(
        "file:leaf-revoked.ocsp",
        read("leaf-revoked.ocsp"),
    )];
    let r = check_revocation(
        &der("leaf-revoked.crt"),
        &der("intermediate.crt"),
        &[],
        &ocsp,
        AT,
    )
    .unwrap();
    assert!(matches!(r, RevocationStatus::Revoked { .. }), "{r:?}");
}

#[test]
fn timestamp_token_verifies_like_openssl_ts() {
    let anchors = vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", der("root.crt"))],
        ..Default::default()
    }];
    let untrusted = vec![der("intermediate.crt")];
    let req = ChainRequest {
        untrusted_der: &untrusted,
        anchors: &anchors,
        ..Default::default()
    };
    let opts = ValidationOptions::default();
    let v = or_skip!(
        verify_timestamp_token(&read("data.tsr"), Some(&read("data.txt")), &req, &opts),
        "verify_timestamp_token"
    )
    .unwrap();
    assert!(v.signature_valid && v.imprint_matches == Some(true));
    assert_eq!(v.info.policy_oid, RAKVOR_POLICY_LAB_TSA);
    assert!(
        v.signals
            .iter()
            .any(|s| s.code == codes::TIMESTAMP_TOKEN_VALID)
    );
    let v = verify_timestamp_token(&read("data.tsr"), Some(b"other data"), &req, &opts).unwrap();
    assert_eq!(v.imprint_matches, Some(false));
    assert!(
        v.signals
            .iter()
            .any(|s| s.code == codes::TIMESTAMP_TOKEN_INVALID)
    );
}

#[test]
fn key_matching_never_returns_key_material() {
    let m = or_skip!(
        match_key(&read("leaf.key"), None, &der("leaf.crt")),
        "match_key"
    )
    .unwrap();
    assert!(m.matches);
    let m = match_key(&read("leaf-mismatch.key"), None, &der("leaf-mismatch.crt")).unwrap();
    assert!(!m.matches);
    let json = serde_json::to_string(&m).unwrap();
    let key_pem = String::from_utf8(read("leaf-mismatch.key")).unwrap();
    let body_line = key_pem.lines().nth(1).unwrap();
    assert!(!json.contains(body_line), "key material in KeyMatch");
}

#[test]
fn certificate_text_is_the_openssl_dump() {
    let t = or_skip!(certificate_text(&der("leaf.crt")), "certificate_text").unwrap();
    assert!(t.contains("Serial Number") && t.contains("leaf.lab.rakvor.test"));
}

#[test]
fn anchors_resolve_from_file_and_bundled_root() {
    let specs = vec![
        AnchorSpec::File {
            path: fx("root.crt"),
        },
        AnchorSpec::Rakvor,
    ];
    let a = or_skip!(resolve_anchors(&specs, None), "resolve_anchors").unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].certificates.len(), 1);
    assert_eq!(a[1].certificates[0].der, RAKVOR_ROOT_DER);
    assert!(
        resolve_anchors(
            &[AnchorSpec::File {
                path: fx("missing.crt")
            }],
            None
        )
        .is_err()
    );
}

#[test]
fn trust_list_csv_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let root_b64 = openssl::base64::encode_block(&der("root.crt"));
    let csv = format!(
        "ecd_name,service_name,service_type,status,status_from,status_until,certificate_pem_or_b64,source_url,checked_utc\n\
         Rakvor Lab ECD,Lab CA,CA/QC,accredited,2025-01-01T00:00:00Z,,{root_b64},https://onac.example/ecd/1,2026-11-01T00:00:00Z\n"
    );
    let snap = or_skip!(
        trust_list::import_co_csv(
            csv.as_bytes(),
            "file:co.csv",
            "2026-11-03T10:15:00Z",
            dir.path()
        ),
        "trust_list::import_co_csv"
    )
    .unwrap();
    assert_eq!(snap.schema, TRUST_LIST_SCHEMA);
    assert!(!snap.signature_verified);
    assert_eq!(snap.entries.len(), 1);
    let loaded = trust_list::load(dir.path(), TrustListKind::Co, "latest").unwrap();
    assert_eq!(loaded, snap);
    assert_eq!(trust_list::list(dir.path()).unwrap().len(), 1);
    let root = parse_any(&read("root.crt"), None).unwrap();
    assert!(trust_list::lookup(&snap, &root.certificates[0], AT).is_some());
}
