//! Agent A: fuzz-style robustness. Every fixture (certificates, bundle, PKCS#7, PKCS#12, CRL, OCSP, TSR/TST,
//! keys, CSR, trust lists) is mutated 2,000 times with a seeded generator (bit flips, byte overwrites, length
//! bytes, truncation, insertion, deletion, duplication) and fed to every analysis entry point that accepts it.
//! Malformed input must give an error or an `Unknown`, never a panic; `sniff` must always answer `Ok`.
//! `RV_FUZZ_ITERATIONS` overrides the count (e.g. 20000 for a longer local run).

use rv_certcheck_certs::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

const AT: &str = "2026-06-01T00:00:00Z";

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn mutate(orig: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut m = orig.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        let n = m.len();
        match rng.below(8) {
            0 if n > 0 => {
                let i = rng.below(n);
                m[i] ^= 1 << rng.below(8);
            }
            1 if n > 0 => {
                let i = rng.below(n);
                m[i] = rng.next() as u8;
            }
            2 if n > 0 => {
                // DER headers live near the start and at nested offsets: hit a length octet.
                let i = rng.below(n.min(24));
                m[i] = [0x00, 0x7f, 0x80, 0x81, 0x82, 0x84, 0x85, 0xff][rng.below(8)];
            }
            3 => m.truncate(rng.below(n + 1)),
            4 => {
                let i = rng.below(n + 1);
                let k = 1 + rng.below(16);
                let ins: Vec<u8> = (0..k).map(|_| rng.next() as u8).collect();
                m.splice(i..i, ins);
            }
            5 if n > 0 => {
                let i = rng.below(n);
                let j = (i + 1 + rng.below(32)).min(n);
                m.drain(i..j);
            }
            6 if n > 1 => {
                let i = rng.below(n);
                let j = (i + 1 + rng.below(64)).min(n);
                let chunk = m[i..j].to_vec();
                let at = rng.below(m.len() + 1);
                m.splice(at..at, chunk);
            }
            _ if n > 0 => {
                // Swap two bytes (keeps the length, scrambles structure).
                let (i, j) = (rng.below(n), rng.below(n));
                m.swap(i, j);
            }
            _ => m.push(rng.next() as u8),
        }
    }
    m
}

fn files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut v = vec![];
    for d in ["openssl", "openssl/keys", "trustlists"] {
        for e in std::fs::read_dir(root.join(d)).unwrap().flatten() {
            let p = e.path();
            if p.is_file() && p.extension().and_then(|x| x.to_str()) != Some("sh") {
                v.push(p);
            }
        }
    }
    v.sort();
    v
}

fn der(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openssl")
        .join(name);
    openssl::x509::X509::from_pem(&std::fs::read(p).unwrap())
        .unwrap()
        .to_der()
        .unwrap()
}

#[test]
fn mutated_fixtures_never_panic() {
    let iterations: usize = std::env::var("RV_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let root = der("root.crt");
    let inter = der("intermediate.crt");
    let leaf = der("leaf.crt");
    let revoked = der("leaf-revoked.crt");
    let anchors = vec![ResolvedAnchor {
        spec: "file:root.crt".into(),
        certificates: vec![LabeledDer::new("file:root.crt", root)],
        ..Default::default()
    }];
    let untrusted = vec![inter.clone()];
    let pw = Secret::new("rakvor-lab");
    let opts = ValidationOptions {
        at: AtTime::Fixed(AT.into()),
        ..Default::default()
    };
    let store = tempfile::tempdir().unwrap();
    let mut total = 0usize;
    for f in files() {
        let orig = std::fs::read(&f).unwrap();
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let kind = sniff(&orig).unwrap().kind.0;
        let mut rng =
            Rng(0x9e37_79b9_7f4a_7c15 ^ (orig.len() as u64).wrapping_mul(31) ^ name.len() as u64);
        for i in 0..iterations {
            let m = mutate(&orig, &mut rng);
            let r = catch_unwind(AssertUnwindSafe(|| {
                let s = sniff(&m).expect("sniff never fails");
                let _ = parse_any(&m, None);
                let _ = parse_any(&m, Some(&pw));
                match kind {
                    InputKind::Certificate | InputKind::CertBundle | InputKind::Pkcs7 => {
                        let _ = certificate_text(&m);
                        let crls = vec![];
                        let _ = validate_chain(
                            &ChainRequest {
                                target_der: &m,
                                untrusted_der: &untrusted,
                                anchors: &anchors,
                                crls: &crls,
                                ..Default::default()
                            },
                            &opts,
                        );
                        let _ = check_revocation(&m, &inter, &[], &[], AT);
                        let _ = check_revocation(&leaf, &m, &[], &[], AT);
                    }
                    InputKind::Crl => {
                        let l = vec![LabeledDer::new("fuzz", m.clone())];
                        let _ = check_revocation(&revoked, &inter, &l, &[], AT);
                        let _ = validate_chain(
                            &ChainRequest {
                                target_der: &revoked,
                                untrusted_der: &untrusted,
                                anchors: &anchors,
                                crls: &l,
                                ..Default::default()
                            },
                            &opts,
                        );
                    }
                    InputKind::OcspResponse => {
                        let l = vec![LabeledDer::new("fuzz", m.clone())];
                        let _ = check_revocation(&revoked, &inter, &[], &l, AT);
                    }
                    InputKind::TimestampToken => {
                        let _ = verify_timestamp_token(
                            &m,
                            Some(b"data"),
                            &ChainRequest {
                                untrusted_der: &untrusted,
                                anchors: &anchors,
                                ..Default::default()
                            },
                            &opts,
                        );
                    }
                    InputKind::PrivateKey | InputKind::Pkcs12 => {
                        let _ = match_key(&m, Some(&pw), &leaf);
                        let _ = match_key(&leaf, None, &m);
                    }
                    _ => {}
                }
                if name.ends_with(".xml") {
                    let _ = trust_list::import_eu(
                        &m,
                        "file:fuzz.xml",
                        "2026-11-03T10:15:00Z",
                        store.path(),
                    );
                }
                if name.ends_with(".csv") {
                    let _ = trust_list::import_co_csv(
                        &m,
                        "file:fuzz.csv",
                        "2026-11-03T10:15:00Z",
                        store.path(),
                    );
                }
                s
            }));
            if r.is_err() {
                let out = std::env::temp_dir().join(format!("rv-certcheck-fuzz-{name}-{i}.bin"));
                let _ = std::fs::write(&out, &m);
                panic!(
                    "panic on mutation {i} of {name}; input saved to {}",
                    out.display()
                );
            }
            total += 1;
        }
    }
    let _ = trust_list::list(store.path());
    assert!(total >= 2000 * 20, "{total} mutated inputs");
}
