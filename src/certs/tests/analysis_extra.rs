//! Agent A's own tests of the analysis (beyond the architect's acceptance tests): every error of a path is
//! collected, purposes, signature and name-constraint failures, revocation after the date, signing-time,
//! trust lists (EU XML, Colombian CSV) end to end, and no secret in any output.

use rv_certcheck_certs::*;
use std::path::{Path, PathBuf};

const AT: &str = "2026-06-01T00:00:00Z";

fn root_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fx(name: &str) -> PathBuf {
    root_dir().join("tests/fixtures/openssl").join(name)
}
fn tl(name: &str) -> PathBuf {
    root_dir().join("tests/fixtures/trustlists").join(name)
}
fn read(p: PathBuf) -> Vec<u8> {
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}
fn der(name: &str) -> Vec<u8> {
    openssl::x509::X509::from_pem(&read(fx(name)))
        .unwrap()
        .to_der()
        .unwrap()
}
fn root_anchor() -> Vec<ResolvedAnchor> {
    vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", der("root.crt"))],
        ..Default::default()
    }]
}
fn crl() -> Vec<LabeledDer> {
    vec![LabeledDer::new(
        "file:intermediate.crl",
        read(fx("intermediate.crl")),
    )]
}
fn opts(at: &str, purpose: Purpose) -> ValidationOptions {
    ValidationOptions {
        at: AtTime::Fixed(at.into()),
        purpose,
        ..Default::default()
    }
}
fn verdict(
    target: &[u8],
    anchors: &[ResolvedAnchor],
    crls: &[LabeledDer],
    ocsp: &[LabeledDer],
    o: &ValidationOptions,
) -> ChainVerdict {
    let untrusted = vec![der("intermediate.crt")];
    validate_chain(
        &ChainRequest {
            target_der: target,
            untrusted_der: &untrusted,
            anchors,
            crls,
            ocsp,
            ..Default::default()
        },
        o,
    )
    .unwrap()
}
fn has(v: &ChainVerdict, code: &str) -> bool {
    v.signals.iter().any(|s| s.code == code)
}

#[test]
fn every_error_of_the_path_is_collected_and_the_verdict_stays_failed() {
    // Wrong root and, in 2029, expired: OpenSSL's first answer is 20, then the walk continues and finds 10.
    let v = verdict(
        &der("leaf-wrong-root.crt"),
        &root_anchor(),
        &[],
        &[],
        &opts("2029-06-01T00:00:00Z", Purpose::Any),
    );
    assert_eq!(v.openssl_code, 20, "{v:?}");
    let codes: Vec<(u32, i32)> = v.errors.iter().map(|e| (e.depth, e.code)).collect();
    assert_eq!(codes, vec![(0, 20), (0, 10)], "{v:#?}");
    assert_eq!(v.status, ChainStatus::Untrusted);
    assert!(has(&v, codes::CERT_CHAIN_UNTRUSTED) && has(&v, codes::CERT_EXPIRED_AT_DATE));
    assert!(!has(&v, codes::CERT_CHAIN_VALID));
    assert_eq!(v.nodes[0].status, NodeStatus::Incomplete);
    assert!(
        v.nodes[0].anchor.is_none(),
        "a relaxed top is never an anchor"
    );

    // Revoked (CRL) and expired in 2027-06 ... the CRL itself expired 2027-01-01: every problem is listed.
    let v = verdict(
        &der("leaf-revoked.crt"),
        &root_anchor(),
        &crl(),
        &[],
        &opts("2028-06-01T00:00:00Z", Purpose::Any),
    );
    let found: Vec<i32> = v.errors.iter().map(|e| e.code).collect();
    assert!(found.contains(&10), "{found:?}");
    assert!(found.len() >= 2, "{found:?}");
    assert_eq!(v.status, ChainStatus::Invalid);
    assert!(
        has(&v, codes::CERT_REVOKED),
        "revoked on 2026-02-01, before the date"
    );
}

#[test]
fn a_ca_not_yet_valid_is_reported_at_its_depth() {
    // In 2024 the intermediate and the root (valid from 2025) are not yet valid either.
    let v = verdict(
        &der("leaf.crt"),
        &root_anchor(),
        &[],
        &[],
        &opts("2024-06-01T00:00:00Z", Purpose::Any),
    );
    let not_yet: Vec<u32> = v
        .errors
        .iter()
        .filter(|e| e.code == 9)
        .map(|e| e.depth)
        .collect();
    assert!(not_yet.contains(&0) && not_yet.len() >= 2, "{v:#?}");
    assert!(
        v.signals
            .iter()
            .any(|s| s.code == codes::CERT_NOT_YET_VALID_AT_DATE && s.params["depth"] != "0")
    );
}

#[test]
fn purposes_follow_openssl_and_document_signing_is_the_tools_own_check() {
    let leaf = der("leaf.crt");
    let a = root_anchor();
    let v = verdict(&leaf, &a, &crl(), &[], &opts(AT, Purpose::TlsServer));
    assert_eq!(v.status, ChainStatus::Valid, "{v:#?}");
    let v = verdict(&leaf, &a, &crl(), &[], &opts(AT, Purpose::CodeSigning));
    assert_eq!(v.openssl_code, 26);
    assert!(has(&v, codes::CERT_PURPOSE_MISMATCH) && v.status == ChainStatus::Invalid);
    let s = v
        .signals
        .iter()
        .find(|s| s.code == codes::CERT_PURPOSE_MISMATCH)
        .unwrap();
    assert_eq!(s.params["purpose"], "code-signing");
    assert!(s.params["eku"].contains("serverAuth"));
    let v = verdict(
        &der("tsa.crt"),
        &a,
        &crl(),
        &[],
        &opts(AT, Purpose::Timestamping),
    );
    assert_eq!(v.status, ChainStatus::Valid, "{v:#?}");
    let v = verdict(&leaf, &a, &crl(), &[], &opts(AT, Purpose::Timestamping));
    assert_eq!(v.openssl_code, 26);
    // document-signing: OpenSSL has no such purpose (code stays 0), the tool's own check fails.
    let v = verdict(&leaf, &a, &crl(), &[], &opts(AT, Purpose::DocumentSigning));
    assert_eq!(v.openssl_code, 0);
    assert_eq!(v.status, ChainStatus::Invalid);
    assert!(has(&v, codes::CERT_PURPOSE_MISMATCH));
    assert!(v.notes.iter().any(|n| n.contains("document-signing")));
}

#[test]
fn a_broken_signature_is_cert_signature_invalid() {
    let mut leaf = der("leaf.crt");
    let n = leaf.len();
    leaf[n - 10] ^= 0x01; // inside the signature value
    let v = verdict(&leaf, &root_anchor(), &[], &[], &opts(AT, Purpose::Any));
    assert_eq!(v.openssl_code, 7, "{v:#?}");
    assert!(has(&v, codes::CERT_SIGNATURE_INVALID));
    assert_eq!(v.status, ChainStatus::Invalid);
    let s = v
        .signals
        .iter()
        .find(|s| s.code == codes::CERT_SIGNATURE_INVALID)
        .unwrap();
    assert_eq!(s.params["depth"], "0");
}

/// A CA restricted to `.allowed.test` that issues `bad.other.test`, built with OpenSSL in memory.
#[allow(deprecated)]
fn name_constraint_case() -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
    use openssl::x509::{X509, X509Extension, X509NameBuilder};
    let name = |cn: &str| {
        let mut b = X509NameBuilder::new().unwrap();
        b.append_entry_by_text("CN", cn).unwrap();
        b.build()
    };
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name("NC Test CA")).unwrap();
    b.set_issuer_name(&name("NC Test CA")).unwrap();
    b.set_pubkey(&ca_key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(1_735_689_600).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(2_051_222_400).unwrap())
        .unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    let nc = X509Extension::new(
        None,
        None,
        "nameConstraints",
        "critical,permitted;DNS:.allowed.test",
    )
    .unwrap();
    b.append_extension(nc).unwrap();
    b.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = b.build();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name("bad.other.test")).unwrap();
    b.set_issuer_name(ca.subject_name()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(1_735_689_600).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(1_830_297_600).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("bad.other.test")
        .build(&b.x509v3_context(Some(&ca), None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&ca_key, MessageDigest::sha256()).unwrap();
    (ca.to_der().unwrap(), b.build().to_der().unwrap())
}

#[test]
fn a_name_outside_the_constraints_is_named() {
    let (ca, leaf) = name_constraint_case();
    let anchors = vec![ResolvedAnchor {
        spec: "file:nc-ca.crt".into(),
        certificates: vec![LabeledDer::new("file:nc-ca.crt", ca)],
        ..Default::default()
    }];
    let v = validate_chain(
        &ChainRequest {
            target_der: &leaf,
            anchors: &anchors,
            ..Default::default()
        },
        &opts(AT, Purpose::Any),
    )
    .unwrap();
    assert_eq!(v.openssl_code, 47, "{v:#?}");
    let s = v
        .signals
        .iter()
        .find(|s| s.code == codes::CERT_NAME_CONSTRAINT_VIOLATION)
        .expect("name constraint signal");
    assert_eq!(s.params["name"], "dns:bad.other.test");
    assert_eq!(s.params["constraint_by"], "CN=NC Test CA");
    let p = parse_any(&anchors[0].certificates[0].der, None).unwrap();
    let nc = p.certificates[0].name_constraints.clone().unwrap();
    assert_eq!(nc.permitted[0].value, ".allowed.test");
}

#[test]
fn revocation_after_the_date_is_good_at_that_date_and_says_so() {
    // OCSP (produced in November 2026) says revoked on 2026-02-01; judged at 2026-01-15 it was still good.
    let ocsp = vec![LabeledDer::new(
        "file:leaf-revoked.ocsp",
        read(fx("leaf-revoked.ocsp")),
    )];
    let v = verdict(
        &der("leaf-revoked.crt"),
        &root_anchor(),
        &[],
        &ocsp,
        &opts("2026-01-15T00:00:00Z", Purpose::Any),
    );
    assert_eq!(v.status, ChainStatus::Valid, "{v:#?}");
    assert!(matches!(
        v.nodes[0].revocation,
        Some(RevocationStatus::Good { .. })
    ));
    let note = v.nodes[0].revocation_note.clone().unwrap();
    assert!(
        note.contains("2026-02-01") && note.contains("after the date checked"),
        "{note}"
    );
    // The same response at 2026-06-01: revoked, with the reason and the date.
    let r = check_revocation(
        &der("leaf-revoked.crt"),
        &der("intermediate.crt"),
        &[],
        &ocsp,
        AT,
    )
    .unwrap();
    match r {
        RevocationStatus::Revoked {
            reason,
            revoked_at,
            source,
        } => {
            assert_eq!(
                (reason.as_str(), revoked_at.as_str()),
                ("keyCompromise", "2026-02-01T00:00:00Z")
            );
            assert_eq!(source.kind, RevocationSourceKind::Ocsp);
        }
        other => panic!("{other:?}"),
    }
    // A CRL past its nextUpdate (and issued before the date) is not used.
    let r = check_revocation(
        &der("leaf.crt"),
        &der("intermediate.crt"),
        &crl(),
        &[],
        "2027-06-01T00:00:00Z",
    )
    .unwrap();
    assert!(
        matches!(&r, RevocationStatus::Unknown { source } if source.contains("expired")),
        "{r:?}"
    );
    // Another CA's response does not cover the certificate; a forged one does not verify.
    let r = check_revocation(
        &der("leaf-wrong-root.crt"),
        &der("other-root.crt"),
        &crl(),
        &ocsp,
        AT,
    )
    .unwrap();
    assert!(matches!(r, RevocationStatus::Unknown { .. }), "{r:?}");
}

#[test]
fn signing_time_uses_the_time_supplied_and_says_so() {
    let untrusted = vec![der("intermediate.crt")];
    let a = root_anchor();
    let leaf = der("leaf-expired.crt");
    let o = ValidationOptions {
        at: AtTime::SigningTime,
        ..Default::default()
    };
    let v = validate_chain(
        &ChainRequest {
            target_der: &leaf,
            untrusted_der: &untrusted,
            anchors: &a,
            signing_time: Some("2025-06-01T12:00:00+02:00".into()),
            ..Default::default()
        },
        &o,
    )
    .unwrap();
    assert_eq!(
        (v.at.as_str(), v.at_source.as_str()),
        ("2025-06-01T10:00:00Z", "signing-time")
    );
    assert!(v.notes.iter().any(|n| n.contains("signing time supplied")));
    // Valid at signing time... except that the leaf expired 2025-01-01: still 10.
    assert_eq!(v.openssl_code, 10);
    let v = validate_chain(
        &ChainRequest {
            target_der: &leaf,
            untrusted_der: &untrusted,
            anchors: &a,
            ..Default::default()
        },
        &o,
    )
    .unwrap();
    assert_eq!(v.at_source, "signing-time-unavailable-now");
}

#[test]
fn rakvor_internal_is_flagged_for_the_bundled_root() {
    let a = resolve_anchors(&[AnchorSpec::Rakvor], None).unwrap();
    let v = validate_chain(
        &ChainRequest {
            target_der: RAKVOR_ROOT_DER,
            anchors: &a,
            ..Default::default()
        },
        &opts(AT, Purpose::Any),
    )
    .unwrap();
    assert!(has(&v, codes::CERT_ISSUED_BY_RAKVOR_INTERNAL), "{v:#?}");
}

#[test]
fn eu_trust_list_import_lookup_and_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let xml = read(tl("tl-sample.xml"));
    let snap = trust_list::import_eu(
        &xml,
        "file:tl-sample.xml",
        "2026-11-03T10:15:00Z",
        dir.path(),
    )
    .unwrap();
    assert!(snap.id.starts_with("eu-20261103T101500Z-"), "{}", snap.id);
    assert_eq!(
        snap.sha256,
        openssl::sha::sha256(&xml)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_eq!(snap.territory.as_deref(), Some("XX"));
    assert_eq!(snap.sequence_number.as_deref(), Some("7"));
    assert_eq!(snap.next_update.as_deref(), Some("2027-04-01T00:00:00Z"));
    assert!(!snap.signature_verified);
    assert_eq!(snap.services.len(), 3);
    assert_eq!(snap.entries.len(), 3);
    let s0 = &snap.services[0];
    assert_eq!(
        s0.tsp_name, "Rakvor Lab Synthetic TSP",
        "xml:lang=en preferred"
    );
    assert!(s0.service_type.ends_with("/Svctype/CA/QC"));
    assert_eq!(s0.history.len(), 2);
    assert!(s0.history[0].status.ends_with("/granted"));
    assert_eq!(s0.history[0].until.as_deref(), Some("2026-09-01T00:00:00Z"));
    assert!(s0.current_status.ends_with("/withdrawn"));
    assert_eq!(
        snap.services[2].tsp_name,
        "Invented Trust Services Ltd & Co"
    );

    let root = parse_any(&read(fx("root.crt")), None)
        .unwrap()
        .certificates
        .remove(0);
    let m = trust_list::lookup(&snap, &root, AT).unwrap();
    assert!(m.status_at.ends_with("/granted"), "{m:?}");
    let m = trust_list::lookup(&snap, &root, "2026-10-01T00:00:00Z").unwrap();
    assert!(m.status_at.ends_with("/withdrawn"));
    let leaf = parse_any(&read(fx("leaf.crt")), None)
        .unwrap()
        .certificates
        .remove(0);
    assert!(trust_list::lookup(&snap, &leaf, AT).is_none());

    // As an anchor: the chain of the leaf ends in a listed service.
    let a = resolve_anchors(
        &[AnchorSpec::TrustList {
            list: TrustListKind::Eu,
            snapshot: "latest".into(),
        }],
        Some(dir.path()),
    )
    .unwrap();
    assert_eq!(a[0].certificates.len(), 3);
    let v = verdict(&der("leaf.crt"), &a, &crl(), &[], &opts(AT, Purpose::Any));
    assert_eq!(v.status, ChainStatus::Valid, "{v:#?}");
    let s = v
        .signals
        .iter()
        .find(|s| s.code == codes::CERT_IN_TRUST_LIST)
        .expect("in trust list");
    assert!(s.params["status"].ends_with("/granted"));
    assert_eq!(s.params["snapshot"], snap.id);
    assert!(v.nodes[2].trust_list.is_some());
    // A chain that ends elsewhere: not in the list.
    let other = vec![
        a[0].clone(),
        ResolvedAnchor {
            spec: "file:other-root.crt".into(),
            certificates: vec![LabeledDer::new(
                "file:other-root.crt",
                der("other-root.crt"),
            )],
            ..Default::default()
        },
    ];
    let v = verdict(
        &der("leaf-wrong-root.crt"),
        &other,
        &[],
        &[],
        &opts(AT, Purpose::Any),
    );
    assert!(has(&v, codes::CERT_NOT_IN_TRUST_LIST), "{v:#?}");

    // Listing, and a snapshot altered after import is refused.
    let l = trust_list::list(dir.path()).unwrap();
    assert_eq!((l.len(), l[0].services, l[0].entries), (1, 3, 3));
    let p = &l[0].path;
    let mut t = std::fs::read_to_string(p).unwrap();
    t = t.replacen("Invented Qualified CA 1", "Invented Qualified CA 2", 1);
    std::fs::write(p, t).unwrap();
    let e = trust_list::load(dir.path(), TrustListKind::Eu, &snap.id).unwrap_err();
    assert!(e.message.contains("altered"), "{e}");
}

#[test]
fn eu_trust_list_rejects_hostile_or_foreign_xml() {
    let dir = tempfile::tempdir().unwrap();
    for bad in [
        &b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><TrustServiceStatusList>&e;</TrustServiceStatusList>"[..],
        b"<TrustServiceStatusList><SchemeInformation>",
        b"<html><body>not a TL</body></html>",
        b"<TrustServiceStatusList>&undefined;</TrustServiceStatusList>",
        b"\xff\xfe<",
    ] {
        assert!(trust_list::import_eu(bad, "file:x", "2026-11-03T10:15:00Z", dir.path()).is_err());
    }
    assert!(trust_list::list(dir.path()).unwrap().is_empty());
}

#[test]
fn colombian_csv_with_history_and_pem_cells() {
    let dir = tempfile::tempdir().unwrap();
    let csv = read(tl("co-sample.csv"));
    let snap = trust_list::import_co_csv(
        &csv,
        "file:co-sample.csv",
        "2026-11-03T10:15:00Z",
        dir.path(),
    )
    .unwrap();
    assert_eq!(snap.list, "co");
    assert_eq!(snap.services.len(), 2);
    assert_eq!(snap.entries.len(), 2);
    assert_eq!(snap.issue_date.as_deref(), Some("2026-11-01T00:00:00Z"));
    let lab = &snap.services[0];
    assert_eq!(lab.history.len(), 3);
    assert_eq!(lab.current_status, "accredited");
    assert_eq!(
        snap.services[1].service_name,
        "Ejemplo CA Firma Digital, Clase 2"
    );
    let root = parse_any(&read(fx("root.crt")), None)
        .unwrap()
        .certificates
        .remove(0);
    assert_eq!(
        trust_list::lookup(&snap, &root, "2026-07-15T00:00:00Z")
            .unwrap()
            .status_at,
        "suspended"
    );
    assert_eq!(
        trust_list::lookup(&snap, &root, AT).unwrap().status_at,
        "accredited"
    );
    let m = trust_list::lookup(&snap, &root, "2024-01-01T00:00:00Z").unwrap();
    assert!(m.status_at.starts_with("not listed at that date"), "{m:?}");
    // Errors name the line.
    let bad = b"ecd_name,service_name,service_type,status,status_from,status_until,certificate_pem_or_b64,source_url,checked_utc\nA,B,CA/QC,revoked,2025-01-01,,,https://x,2026-01-01\n";
    let e =
        trust_list::import_co_csv(bad, "file:x", "2026-11-03T10:15:00Z", dir.path()).unwrap_err();
    assert!(
        e.message.contains("line 2") && e.message.contains("status"),
        "{e}"
    );
    let e = trust_list::import_co_csv(b"a,b\n", "file:x", "2026-11-03T10:15:00Z", dir.path())
        .unwrap_err();
    assert!(e.message.contains("missing column"), "{e}");
}

#[test]
fn sniff_by_content_in_every_encoding() {
    let leaf = der("leaf.crt");
    let s = sniff(&leaf).unwrap();
    assert_eq!(
        (s.kind.0, s.encoding),
        (InputKind::Certificate, Encoding::Der)
    );
    let b64 = openssl::base64::encode_block(&leaf);
    let s = sniff(b64.as_bytes()).unwrap();
    assert_eq!(
        (s.kind.0, s.encoding),
        (InputKind::Certificate, Encoding::Base64)
    );
    assert_eq!(
        parse_any(b64.as_bytes(), None).unwrap().certificates[0].serial_hex,
        "2001"
    );
    let s = sniff(&read(fx("leaf.p12"))).unwrap();
    assert!(s.encrypted);
    let s = sniff(&read(fx("chain-bundle.pem"))).unwrap();
    assert_eq!(s.pem_labels, vec!["CERTIFICATE", "CERTIFICATE"]);
    let p = parse_any(&read(fx("chain.p7b")), None).unwrap();
    assert_eq!(p.certificates.len(), 2);
    let csr = parse_any(&read(fx("leaf.csr")), None).unwrap().csr.unwrap();
    assert!(csr.signature_valid);
    assert_eq!(csr.subject, "C=CO, O=Rakvor Lab, CN=csr.lab.rakvor.test");
    let o = parse_any(&read(fx("leaf-revoked.ocsp")), None)
        .unwrap()
        .ocsp
        .unwrap();
    assert_eq!(o.response_status, "successful");
    assert_eq!(o.responses[0].serial_hex, "2004");
    assert_eq!(o.responses[0].status, "revoked");
    assert_eq!(o.responses[0].reason.as_deref(), Some("keyCompromise"));
    let t = parse_any(&read(fx("data.tst")), None)
        .unwrap()
        .timestamp
        .unwrap();
    assert_eq!(t.policy_oid, RAKVOR_POLICY_LAB_TSA);
    assert_eq!(t.hash_algorithm, "sha256");
    assert_eq!(t.response_status, None);
    assert_eq!(
        t.certificates[0].subject,
        "C=CO, O=Rakvor Lab, CN=Rakvor Lab TSA"
    );
    let t = parse_any(&read(fx("data.tsr")), None)
        .unwrap()
        .timestamp
        .unwrap();
    assert_eq!(t.response_status.as_deref(), Some("granted"));
    assert_eq!(t.accuracy.as_deref(), Some("1s"));
    let c = &parse_any(&read(fx("leaf.crt")), None).unwrap().certificates[0];
    assert_eq!(c.key_usage, vec!["digitalSignature", "keyEncipherment"]);
    assert!(c.key_usage_critical);
    assert_eq!(
        c.aia_ca_issuers,
        vec!["http://pki.lab.rakvor.test/intermediate.crt"]
    );
    assert_eq!(c.basic_constraints.as_ref().map(|b| b.ca), Some(false));
    assert!(
        c.extensions
            .iter()
            .any(|e| e.name == "basicConstraints" && e.critical)
    );
    assert_eq!(c.version, 3);
    // A bare TST verifies like the TSR.
    let a = root_anchor();
    let untrusted = vec![der("intermediate.crt")];
    let v = verify_timestamp_token(
        &read(fx("data.tst")),
        Some(&read(fx("data.txt"))),
        &ChainRequest {
            untrusted_der: &untrusted,
            anchors: &a,
            ..Default::default()
        },
        &ValidationOptions::default(),
    )
    .unwrap();
    assert!(
        v.signals
            .iter()
            .any(|s| s.code == codes::TIMESTAMP_TOKEN_VALID),
        "{:?}",
        v.signals
    );
    // Without an anchor the TSA chain is untrusted, so the token is invalid.
    let v = verify_timestamp_token(
        &read(fx("data.tsr")),
        None,
        &ChainRequest::default(),
        &ValidationOptions::default(),
    )
    .unwrap();
    assert!(
        v.signals
            .iter()
            .any(|s| s.code == codes::TIMESTAMP_TOKEN_INVALID)
    );
}

#[test]
fn no_secret_in_any_output() {
    let pw = Secret::new("rakvor-lab");
    let key_pem = String::from_utf8(read(fx("leaf.key"))).unwrap();
    let key_lines: Vec<&str> = key_pem
        .lines()
        .filter(|l| !l.starts_with("-----") && l.len() > 20)
        .collect();
    let key_der = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes())
        .unwrap()
        .private_key_to_pkcs8()
        .unwrap();
    let key_hex: String = key_der[40..72].iter().map(|b| format!("{b:02x}")).collect();
    let mut outputs = vec![];
    let p = parse_any(&read(fx("leaf.p12")), Some(&pw)).unwrap();
    outputs.push(serde_json::to_string(&p).unwrap());
    outputs.push(format!("{p:?}"));
    let p = parse_any(&read(fx("leaf.key")), None).unwrap();
    outputs.push(serde_json::to_string(&p).unwrap());
    outputs.push(format!("{p:?}"));
    let m = match_key(&read(fx("leaf.p12")), Some(&pw), &der("leaf.crt")).unwrap();
    assert!(m.matches);
    outputs.push(serde_json::to_string(&m).unwrap());
    outputs.push(format!("{m:?}"));
    for bad in ["wrong", ""] {
        let w = Secret::new(bad);
        match parse_any(&read(fx("leaf.p12")), Some(&w)) {
            Ok(p) => {
                assert!(p.signals.iter().any(|s| s.code == codes::PKCS12_UNREADABLE));
                outputs.push(serde_json::to_string(&p).unwrap());
            }
            Err(e) => outputs.push(e.message),
        }
        if let Err(e) = match_key(&read(fx("leaf.p12")), Some(&w), &der("leaf.crt")) {
            assert_eq!(e.kind, ErrorKind::Password);
            outputs.push(e.message);
        }
    }
    outputs.push(format!("{pw:?}"));
    for o in &outputs {
        assert!(!o.contains("rakvor-lab"), "password in output: {o}");
        for l in &key_lines {
            assert!(!o.contains(l), "key material in output");
        }
        assert!(!o.contains(&key_hex), "key bytes (hex) in output");
    }
}

#[test]
fn a_pem_with_a_certificate_and_an_encrypted_key_keeps_the_certificate() {
    let key = openssl::pkey::PKey::private_key_from_pem(&read(fx("leaf.key"))).unwrap();
    let enc = key
        .private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), b"s3cret-pass")
        .unwrap();
    let mut both = read(fx("leaf.crt"));
    both.extend(&enc);
    let s = sniff(&both).unwrap();
    assert!(s.encrypted && s.kind.0 == InputKind::Certificate);
    let p = parse_any(&both, None).unwrap();
    assert_eq!(p.certificates.len(), 1);
    assert!(p.private_key.is_none());
    let p = parse_any(&both, Some(&Secret::new("s3cret-pass"))).unwrap();
    let k = p.private_key.unwrap();
    assert!(k.encrypted);
    assert_eq!(k.spki_sha256, p.certificates[0].key.spki_sha256);
    let e = parse_any(&enc, None).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Password);
    assert!(!e.message.contains("s3cret"));
    let e = parse_any(&enc, Some(&Secret::new("wrong"))).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Password);
}

fn withdrawn_anchor(dir: &Path) -> Vec<ResolvedAnchor> {
    trust_list::import_eu(
        &read(tl("tl-withdrawn.xml")),
        "file:tl-withdrawn.xml",
        "2026-11-03T10:15:00Z",
        dir,
    )
    .unwrap();
    resolve_anchors(
        &[AnchorSpec::TrustList {
            list: TrustListKind::Eu,
            snapshot: "latest".into(),
        }],
        Some(dir),
    )
    .unwrap()
}

#[test]
fn trust_list_service_withdrawn_before_the_date_is_not_an_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let a = withdrawn_anchor(dir.path());
    // The lab root's service was withdrawn on 2026-03-01: at 2026-06-01 the chain is untrusted, not valid.
    let v = verdict(&der("leaf.crt"), &a, &crl(), &[], &opts(AT, Purpose::Any));
    assert_eq!(v.status, ChainStatus::Untrusted, "{v:#?}");
    assert!(!has(&v, codes::CERT_CHAIN_VALID), "{v:#?}");
    let s = v
        .signals
        .iter()
        .find(|s| s.code == codes::CERT_CHAIN_UNTRUSTED && s.params.contains_key("service"))
        .unwrap_or_else(|| panic!("untrusted with the service named: {v:#?}"));
    assert_eq!(
        s.params["service"],
        "Lab Root CA (withdrawn before the date)"
    );
    assert!(s.params["service_status"].ends_with("/withdrawn"), "{s:?}");
    assert!(s.params["reason"].contains("withdrawn"), "{s:?}");
    assert!(v.nodes.iter().all(|n| n.anchor.is_none()), "{v:#?}");
    // Before the withdrawal the same snapshot anchors the chain.
    let v = verdict(
        &der("leaf.crt"),
        &a,
        &[],
        &[],
        &opts("2026-02-01T00:00:00Z", Purpose::Any),
    );
    assert_eq!(v.status, ChainStatus::Valid, "{v:#?}");
}

#[test]
fn trust_list_service_withdrawn_after_the_date_is_an_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let a = withdrawn_anchor(dir.path());
    // The unrelated root's service is withdrawn on 2026-09-01: granted at 2026-06-01, withdrawn at 2026-10-01.
    let v = verdict(
        &der("leaf-wrong-root.crt"),
        &a,
        &[],
        &[],
        &opts(AT, Purpose::Any),
    );
    assert_eq!(v.status, ChainStatus::Valid, "{v:#?}");
    assert!(has(&v, codes::CERT_CHAIN_VALID));
    let v = verdict(
        &der("leaf-wrong-root.crt"),
        &a,
        &[],
        &[],
        &opts("2026-10-01T00:00:00Z", Purpose::Any),
    );
    assert_eq!(v.status, ChainStatus::Untrusted, "{v:#?}");
    let s = v
        .signals
        .iter()
        .find(|s| s.code == codes::CERT_CHAIN_UNTRUSTED && s.params.contains_key("service"))
        .unwrap_or_else(|| panic!("{v:#?}"));
    assert_eq!(
        s.params["service"],
        "Unrelated Root CA (withdrawn after the date)"
    );
}

#[test]
fn trust_list_tsa_services_anchor_only_for_timestamping() {
    let dir = tempfile::tempdir().unwrap();
    let a = withdrawn_anchor(dir.path());
    // The TSA's own certificate is listed under a granted TSA/QTST service; its CA's service is withdrawn.
    let v = verdict(&der("tsa.crt"), &a, &[], &[], &opts(AT, Purpose::Any));
    assert_eq!(
        v.status,
        ChainStatus::Untrusted,
        "TSA type is not a CA anchor: {v:#?}"
    );
    let v = verdict(
        &der("tsa.crt"),
        &a,
        &[],
        &[],
        &opts(AT, Purpose::Timestamping),
    );
    assert_eq!(
        v.status,
        ChainStatus::Valid,
        "QTST anchors timestamping: {v:#?}"
    );
}

#[test]
fn colombian_csv_suspended_service_is_not_an_anchor_during_the_suspension() {
    let dir = tempfile::tempdir().unwrap();
    trust_list::import_co_csv(
        &read(tl("co-sample.csv")),
        "file:co-sample.csv",
        "2026-11-03T10:15:00Z",
        dir.path(),
    )
    .unwrap();
    let a = resolve_anchors(
        &[AnchorSpec::TrustList {
            list: TrustListKind::Co,
            snapshot: "latest".into(),
        }],
        Some(dir.path()),
    )
    .unwrap();
    let v = verdict(&der("leaf.crt"), &a, &[], &[], &opts(AT, Purpose::Any));
    assert_eq!(v.status, ChainStatus::Valid, "accredited at {AT}: {v:#?}");
    let v = verdict(
        &der("leaf.crt"),
        &a,
        &[],
        &[],
        &opts("2026-07-15T00:00:00Z", Purpose::Any),
    );
    assert_eq!(v.status, ChainStatus::Untrusted, "suspended: {v:#?}");
    assert!(
        v.signals
            .iter()
            .any(|s| s.code == codes::CERT_CHAIN_UNTRUSTED
                && s.params.get("service_status").map(String::as_str) == Some("suspended"))
    );
}
