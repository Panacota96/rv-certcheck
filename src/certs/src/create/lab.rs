//! OWNER: B. Seeded, byte-identical lab sets with expected_findings.json.
//!
//! LAB ONLY — everything here is public by construction and must never protect anything real:
//! - keys: RSA from a ChaCha20 stream seeded with SHA-256("rakvor.lab-set/1|<seed>|key|<label>") (keys.rs
//!   `seeded_rsa`); RSA PKCS#1 v1.5 signatures are deterministic, so certificates, CRLs and OCSP responses are too;
//! - serials: 127 bits from the stream "serial|<label>";
//! - dates: offsets from `base_time` (never the wall clock); the set is judged at `base_time` itself;
//! - `valid-chain/leaf.p12`: password [`LAB_P12_PASSWORD`], salts and IV from the stream "p12|valid-chain";
//! - `key-mismatch/leaf.key`: an unencrypted PKCS#8 key (a deliberately public test key).
//!
//! Layout (certificates and CRLs PEM, OCSP responses DER):
//! ```text
//! <set>/ca/root.crt ca/intermediate.crt ca/constrained-intermediate.crt ca/root.crl ca/intermediate.crl
//! <set>/<case-id>/leaf.crt (+ other-root.crt, leaf.ocsp, leaf.key, leaf.p12 where the case needs them)
//! <set>/expected_findings.json   LabSetManifest: cases, expected/forbidden codes, openssl verify code, file SHA-256
//! ```
//! `openssl_verify_code` is what `openssl verify -attime <base> -CAfile <anchors> -untrusted <other .crt files>
//! [-crl_check -CRLfile <crls>] [-purpose <p>] <files[0]>` answers. It never consults OCSP, so the revoked-by-OCSP
//! case is 0 there and CERT_REVOKED comes from the OCSP response given to `analyze --ocsp`.

use super::build::{self, CertTemplate, OcspCertStatus, RevokedSpec, ku};
use super::derw;
use super::keys::{self, crypto};
use super::rng::Rand;
use super::signer::{SigAlg, Signer};
use crate::model::*;
use chrono::{DateTime, Duration, Utc};
use openssl::pkey::{PKey, Private};
use std::collections::BTreeMap;
use std::path::Path;

/// Password of the lab PKCS#12 (`valid-chain/leaf.p12`). Lab only.
pub const LAB_P12_PASSWORD: &str = "rakvor-lab";
const LAB_NOTICE: &str = "Rakvor lab/test certificate (rv-certcheck lab make): public test material, never evidence of anything.";

struct Lab {
    seed: u64,
    base: DateTime<Utc>,
    set: String,
    files: BTreeMap<String, Vec<u8>>,
}

struct Issuer {
    name: Vec<u8>,
    ski: Vec<u8>,
    signer: Signer,
    cert: Vec<u8>,
}

impl Lab {
    fn key(&self, label: &str, bits: u32) -> CertResult<PKey<Private>> {
        keys::seeded_rsa(&mut Rand::lab(self.seed, &format!("key|{label}")), bits)
    }
    fn serial(&self, label: &str) -> CertResult<Vec<u8>> {
        Rand::lab(self.seed, &format!("serial|{label}")).serial()
    }
    fn at(&self, days: i64) -> DateTime<Utc> {
        self.base + Duration::days(days)
    }
    fn rdns(&self, org: &str, cn: &str) -> Vec<(String, String)> {
        vec![
            ("C".into(), "CO".into()),
            ("O".into(), org.into()),
            (
                "OU".into(),
                format!("Lab set {} seed {}", self.set, self.seed),
            ),
            ("CN".into(), cn.into()),
        ]
    }
    fn put(&mut self, rel: &str, bytes: Vec<u8>) {
        self.files.insert(rel.to_string(), bytes);
    }
    fn put_cert(&mut self, rel: &str, der: &[u8]) {
        self.put(rel, keys::pem_encode("CERTIFICATE", der).into_bytes());
    }

    /// A lab certificate. `issuer` None = self-signed with `key`.
    #[allow(clippy::too_many_arguments)]
    fn cert(
        &self,
        label: &str,
        issuer: Option<&Issuer>,
        rdns: &[(String, String)],
        key: &PKey<Private>,
        nb: DateTime<Utc>,
        na: DateTime<Utc>,
        mut extensions: Vec<Vec<u8>>,
        alg: SigAlg,
    ) -> CertResult<Vec<u8>> {
        let subject = derw::name(rdns)?;
        let spki = key.public_key_to_der().map_err(crypto("lab key"))?;
        let ski = keys::key_id(&spki)?;
        let self_signer;
        let (issuer_name, aki, signer) = match issuer {
            Some(i) => (i.name.clone(), i.ski.clone(), &i.signer),
            None => {
                self_signer = Signer::Soft(key.clone());
                (subject.clone(), ski.clone(), &self_signer)
            }
        };
        extensions.push(build::ext_ski(&ski));
        extensions.push(build::ext_aki(&aki));
        extensions.push(build::ext_policy(RAKVOR_POLICY_LAB, LAB_NOTICE)?);
        let t = CertTemplate {
            serial: self.serial(label)?,
            issuer: issuer_name,
            subject,
            not_before: nb,
            not_after: na,
            spki,
            extensions,
        };
        build::certificate(&t, alg, signer)
    }

    fn ca(
        &self,
        label: &str,
        issuer: Option<&Issuer>,
        rdns: &[(String, String)],
        path_len: Option<u32>,
        extra: Vec<Vec<u8>>,
        (nb, na): (i64, i64),
    ) -> CertResult<Issuer> {
        let key = self.key(label, 2048)?;
        let mut ext = vec![
            build::ext_basic_constraints(true, path_len),
            build::ext_key_usage(&[ku::KEY_CERT_SIGN, ku::CRL_SIGN]),
        ];
        ext.extend(extra);
        let der = self.cert(
            label,
            issuer,
            rdns,
            &key,
            self.at(nb),
            self.at(na),
            ext,
            SigAlg::RsaSha256,
        )?;
        let spki = key.public_key_to_der().map_err(crypto("lab key"))?;
        Ok(Issuer {
            name: derw::name(rdns)?,
            ski: keys::key_id(&spki)?,
            signer: Signer::Soft(key),
            cert: der,
        })
    }

    /// A TLS-server style leaf under `issuer` (`eku` overrides serverAuth for the bad-EKU case).
    #[allow(clippy::too_many_arguments)]
    fn leaf(
        &self,
        case: &str,
        issuer: &Issuer,
        cn: &str,
        key: &PKey<Private>,
        (nb, na): (i64, i64),
        eku: &str,
        alg: SigAlg,
    ) -> CertResult<Vec<u8>> {
        let ext = vec![
            build::ext_basic_constraints(false, None),
            build::ext_key_usage(&[ku::DIGITAL_SIGNATURE, ku::KEY_ENCIPHERMENT]),
            build::ext_eku(&[eku], false),
            build::ext_san(&[GeneralName {
                kind: "dns".into(),
                value: cn.into(),
            }])?,
        ];
        self.cert(
            &format!("leaf|{case}"),
            Some(issuer),
            &self.rdns("Rakvor Lab", cn),
            key,
            self.at(nb),
            self.at(na),
            ext,
            alg,
        )
    }
}

const LEAF_VALIDITY: (i64, i64) = (-30, 365);

struct CaseOut {
    kind: LabCaseKind,
    description: String,
    files: Vec<String>,
    validation: LabValidation,
    expected: Vec<&'static str>,
    forbidden: Vec<&'static str>,
    openssl_verify_code: i32,
}

pub fn make(spec: &LabSetSpec) -> CertResult<LabSetManifest> {
    let kinds: Vec<LabCaseKind> = match spec.name.as_str() {
        "full" => LabCaseKind::ALL.to_vec(),
        "minimal" => vec![
            LabCaseKind::ValidChain,
            LabCaseKind::Expired,
            LabCaseKind::RevokedByCrl,
            LabCaseKind::KeyMismatch,
        ],
        other => {
            return Err(CertError::new(
                ErrorKind::InvalidInput,
                format!("unknown lab set '{other}': use full or minimal"),
            ));
        }
    };
    let base_text = if spec.base_time.trim().is_empty() {
        "2026-01-01T00:00:00Z"
    } else {
        spec.base_time.trim()
    };
    let base = match AtTime::parse(base_text)? {
        AtTime::Fixed(t) => chrono::DateTime::parse_from_rfc3339(&t)
            .map_err(|e| CertError::new(ErrorKind::InvalidInput, e.to_string()))?
            .with_timezone(&Utc),
        _ => {
            return Err(CertError::new(
                ErrorKind::InvalidInput,
                "the lab base time must be a fixed date (never the wall clock)",
            ));
        }
    };
    if spec.out_dir.exists()
        && std::fs::read_dir(&spec.out_dir)
            .map_err(keys::io_err(&spec.out_dir))?
            .next()
            .is_some()
    {
        return Err(CertError::new(
            ErrorKind::Policy,
            format!(
                "{} is not empty: a lab set is written into an empty or new folder",
                spec.out_dir.display()
            ),
        ));
    }
    let mut lab = Lab {
        seed: spec.seed,
        base,
        set: spec.name.clone(),
        files: BTreeMap::new(),
    };
    let at = rfc3339(base);

    // The lab hierarchy.
    let root_rdns = lab.rdns("Rakvor Lab", "Rakvor Lab Root CA");
    let root = lab.ca("root", None, &root_rdns, None, vec![], (-730, 7300))?;
    let int = lab.ca(
        "intermediate",
        Some(&root),
        &lab.rdns("Rakvor Lab", "Rakvor Lab Intermediate CA"),
        Some(0),
        vec![],
        (-365, 3650),
    )?;
    lab.put_cert("ca/root.crt", &root.cert.clone());
    lab.put_cert("ca/intermediate.crt", &int.cert.clone());

    let anchors = vec!["ca/root.crt".to_string()];
    let validation = |purpose: Purpose, crls: Vec<String>, ocsp: Vec<String>| LabValidation {
        anchors: anchors.clone(),
        at: at.clone(),
        purpose,
        crls,
        ocsp,
    };
    let int_crl = "ca/intermediate.crl".to_string();
    let mut crl_revoked: Vec<RevokedSpec> = vec![];
    let mut cases: Vec<CaseOut> = vec![];

    for kind in &kinds {
        let id = case_id(*kind);
        let leaf_rel = format!("{id}/leaf.crt");
        let cn = format!("{id}.lab.rakvor.test");
        let std_files = vec![leaf_rel.clone(), "ca/intermediate.crt".to_string()];
        let out = match kind {
            LabCaseKind::ValidChain => {
                let k = lab.key("leaf|valid-chain", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                let p12 = keys::pkcs12(
                    &k,
                    &[der.clone(), int.cert.clone(), root.cert.clone()],
                    &cn,
                    &Secret::new(LAB_P12_PASSWORD),
                    &mut Rand::lab(lab.seed, "p12|valid-chain"),
                )?;
                lab.put(&format!("{id}/leaf.p12"), p12);
                let mut files = std_files.clone();
                files.push(format!("{id}/leaf.p12"));
                CaseOut {
                    kind: *kind,
                    description: format!(
                        "Valid TLS-server chain root > intermediate > leaf at {at}, with the intermediate's CRL (leaf not listed). leaf.p12 holds the leaf key and chain (password '{LAB_P12_PASSWORD}', lab only)."
                    ),
                    files,
                    validation: validation(Purpose::TlsServer, vec![int_crl.clone()], vec![]),
                    expected: vec![codes::CERT_CHAIN_VALID],
                    forbidden: vec![
                        codes::CERT_CHAIN_UNTRUSTED,
                        codes::CERT_SIGNATURE_INVALID,
                        codes::CERT_EXPIRED_AT_DATE,
                        codes::CERT_REVOKED,
                        codes::REVOCATION_UNKNOWN,
                        codes::CERT_PURPOSE_MISMATCH,
                        codes::CERT_WEAK_KEY,
                        codes::CERT_WEAK_SIGNATURE_ALGORITHM,
                    ],
                    openssl_verify_code: 0,
                }
            }
            LabCaseKind::Expired => {
                let k = lab.key("leaf|expired", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    (-400, -30),
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description: format!("Leaf that expired 30 days before {at}."),
                    files: std_files,
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_EXPIRED_AT_DATE],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 10,
                }
            }
            LabCaseKind::NotYetValid => {
                let k = lab.key("leaf|not-yet-valid", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    (30, 400),
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description: format!("Leaf valid only from 30 days after {at}."),
                    files: std_files,
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_NOT_YET_VALID_AT_DATE],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 9,
                }
            }
            LabCaseKind::RevokedByCrl => {
                let k = lab.key("leaf|revoked-by-crl", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                crl_revoked.push(RevokedSpec {
                    serial: lab.serial(&format!("leaf|{id}"))?,
                    at: lab.at(-7),
                    reason: "keyCompromise".into(),
                });
                CaseOut {
                    kind: *kind,
                    description: format!(
                        "Leaf revoked (keyCompromise) 7 days before {at}; listed in ca/intermediate.crl."
                    ),
                    files: std_files,
                    validation: validation(Purpose::Any, vec![int_crl.clone()], vec![]),
                    expected: vec![codes::CERT_REVOKED],
                    forbidden: vec![codes::CERT_CHAIN_VALID, codes::REVOCATION_UNKNOWN],
                    openssl_verify_code: 23,
                }
            }
            LabCaseKind::RevokedByOcsp => {
                let k = lab.key("leaf|revoked-by-ocsp", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                let int_spki = int.signer.spki()?;
                let ocsp = build::ocsp_response(
                    &int.name,
                    &int.cert,
                    &int.name,
                    &keys::spki_key_bits(&int_spki)?,
                    &lab.serial(&format!("leaf|{id}"))?,
                    &OcspCertStatus::Revoked {
                        at: lab.at(-7),
                        reason: "keyCompromise".into(),
                    },
                    lab.at(-1),
                    Some(lab.at(7)),
                    SigAlg::RsaSha256,
                    &int.signer,
                )?;
                let ocsp_rel = format!("{id}/leaf.ocsp");
                lab.put(&ocsp_rel, ocsp);
                let mut files = std_files.clone();
                files.push(ocsp_rel.clone());
                CaseOut {
                    kind: *kind,
                    description: format!(
                        "Leaf revoked (keyCompromise) 7 days before {at}, known only from leaf.ocsp (signed by the intermediate, produced 1 day before). Not in any CRL: openssl verify, which never reads OCSP, accepts it."
                    ),
                    files,
                    validation: validation(Purpose::Any, vec![], vec![ocsp_rel]),
                    expected: vec![codes::CERT_REVOKED],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 0,
                }
            }
            LabCaseKind::WrongRoot => {
                let other = lab.ca(
                    "other-root",
                    None,
                    &[
                        ("C".into(), "CO".into()),
                        ("O".into(), "Unrelated Lab".into()),
                        ("CN".into(), "Unrelated Root CA".into()),
                    ],
                    None,
                    vec![],
                    (-730, 7300),
                )?;
                let k = lab.key("leaf|wrong-root", 2048)?;
                let der = lab.leaf(
                    id,
                    &other,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                let other_rel = format!("{id}/other-root.crt");
                lab.put_cert(&other_rel, &other.cert.clone());
                CaseOut {
                    kind: *kind,
                    description: "Complete chain to an unrelated root (other-root.crt), which is not the lab anchor.".into(),
                    files: vec![leaf_rel.clone(), other_rel],
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_CHAIN_UNTRUSTED],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 19,
                }
            }
            LabCaseKind::Rsa1024 => {
                let k = lab.key("leaf|rsa-1024", 1024)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description: "Leaf with a 1024-bit RSA key (chain otherwise valid; openssl verify at its default security level accepts it).".into(),
                    files: std_files,
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_WEAK_KEY],
                    forbidden: vec![],
                    openssl_verify_code: 0,
                }
            }
            LabCaseKind::Sha1Signed | LabCaseKind::Md5Signed => {
                let (alg, label) = if *kind == LabCaseKind::Sha1Signed {
                    (SigAlg::RsaSha1, "sha1WithRSAEncryption")
                } else {
                    (SigAlg::RsaMd5, "md5WithRSAEncryption")
                };
                let k = lab.key(&format!("leaf|{id}"), 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    alg,
                )?;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description: format!(
                        "Leaf signed {label} by the intermediate (chain otherwise valid; openssl verify at its default security level accepts it)."
                    ),
                    files: std_files,
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_WEAK_SIGNATURE_ALGORITHM],
                    forbidden: vec![],
                    openssl_verify_code: 0,
                }
            }
            LabCaseKind::BadEku => {
                let k = lab.key("leaf|bad-eku", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_CODE_SIGNING,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description:
                        "Leaf whose only EKU is codeSigning, judged for purpose tls-server.".into(),
                    files: std_files,
                    validation: validation(Purpose::TlsServer, vec![], vec![]),
                    expected: vec![codes::CERT_PURPOSE_MISMATCH],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 26,
                }
            }
            LabCaseKind::NameConstraintViolation => {
                let permitted = GeneralName {
                    kind: "dns".into(),
                    value: "lab.rakvor.test".into(),
                };
                let nc = lab.ca(
                    "constrained-intermediate",
                    Some(&root),
                    &lab.rdns("Rakvor Lab", "Rakvor Lab Constrained CA"),
                    Some(0),
                    vec![build::ext_name_constraints(&[permitted])?],
                    (-365, 3650),
                )?;
                lab.put_cert("ca/constrained-intermediate.crt", &nc.cert.clone());
                let k = lab.key("leaf|name-constraint-violation", 2048)?;
                let evil = "evil.example.net";
                let der = lab.leaf(
                    id,
                    &nc,
                    evil,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description: format!(
                        "Leaf for {evil} under an intermediate whose nameConstraints permit only DNS names in lab.rakvor.test."
                    ),
                    files: vec![leaf_rel.clone(), "ca/constrained-intermediate.crt".into()],
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_NAME_CONSTRAINT_VIOLATION],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 47,
                }
            }
            LabCaseKind::BrokenSignature => {
                let k = lab.key("leaf|broken-signature", 2048)?;
                let mut der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                // Flip one bit of the signature (the last octet of the certificate): DER stays well-formed.
                let last = der.len() - 1;
                der[last] ^= 0x01;
                lab.put_cert(&leaf_rel, &der);
                CaseOut {
                    kind: *kind,
                    description: "Leaf whose signature has one bit flipped (the TBS is intact)."
                        .into(),
                    files: std_files,
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::CERT_SIGNATURE_INVALID],
                    forbidden: vec![codes::CERT_CHAIN_VALID],
                    openssl_verify_code: 7,
                }
            }
            LabCaseKind::KeyMismatch => {
                let k = lab.key("leaf|key-mismatch", 2048)?;
                let der = lab.leaf(
                    id,
                    &int,
                    &cn,
                    &k,
                    LEAF_VALIDITY,
                    build::OID_EKU_SERVER_AUTH,
                    SigAlg::RsaSha256,
                )?;
                lab.put_cert(&leaf_rel, &der);
                let other = lab.key("other|key-mismatch", 2048)?;
                let key_rel = format!("{id}/leaf.key");
                lab.put(&key_rel, keys::plain_pkcs8_pem(&other)?.as_bytes().to_vec());
                let mut files = std_files.clone();
                files.push(key_rel);
                CaseOut {
                    kind: *kind,
                    description: "Valid leaf presented with leaf.key (same file stem), which is not its key: KEY_DOES_NOT_MATCH is reported on leaf.key. The key is an unencrypted, public lab key.".into(),
                    files,
                    validation: validation(Purpose::Any, vec![], vec![]),
                    expected: vec![codes::KEY_DOES_NOT_MATCH],
                    forbidden: vec![codes::KEY_MATCHES_CERTIFICATE],
                    openssl_verify_code: 0,
                }
            }
        };
        cases.push(out);
    }

    // CRLs: the intermediate's lists the revoked-by-crl leaf; the root's lists nothing.
    let int_crl_der = build::crl(
        &int.name,
        &int.ski,
        lab.at(-1),
        lab.at(30),
        1,
        &crl_revoked,
        SigAlg::RsaSha256,
        &int.signer,
    )?;
    let root_crl_der = build::crl(
        &root.name,
        &root.ski,
        lab.at(-1),
        lab.at(30),
        1,
        &[],
        SigAlg::RsaSha256,
        &root.signer,
    )?;
    lab.put(
        "ca/intermediate.crl",
        keys::pem_encode("X509 CRL", &int_crl_der).into_bytes(),
    );
    lab.put(
        "ca/root.crl",
        keys::pem_encode("X509 CRL", &root_crl_der).into_bytes(),
    );

    let files: BTreeMap<String, String> = lab
        .files
        .iter()
        .map(|(k, v)| (k.clone(), hex(&openssl::sha::sha256(v))))
        .collect();
    let manifest = LabSetManifest {
        schema: LAB_SET_SCHEMA.into(),
        set: spec.name.clone(),
        seed: spec.seed,
        base_time: at.clone(),
        tool_version: super::tool_version().into(),
        cases: cases
            .into_iter()
            .map(|c| LabCase {
                id: case_id(c.kind).into(),
                kind: c.kind,
                description: c.description,
                files: c.files,
                validation: c.validation,
                expected_codes: c.expected.iter().map(|s| s.to_string()).collect(),
                forbidden_codes: c.forbidden.iter().map(|s| s.to_string()).collect(),
                openssl_verify_code: c.openssl_verify_code,
            })
            .collect(),
        files,
    };
    write_set(&spec.out_dir, &lab.files, &manifest)?;
    Ok(manifest)
}

fn write_set(
    out: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    manifest: &LabSetManifest,
) -> CertResult<()> {
    std::fs::create_dir_all(out).map_err(keys::io_err(out))?;
    for (rel, bytes) in files {
        // The lab key and PKCS#12 are public test material, but they are still written owner-only.
        let secret = rel.ends_with(".key") || rel.ends_with(".p12");
        keys::write_new(&out.join(rel), bytes, secret)?;
    }
    let mut j = serde_json::to_string_pretty(manifest).expect("serializable");
    j.push('\n');
    keys::write_new(&out.join("expected_findings.json"), j.as_bytes(), false)
}

pub fn case_id(k: LabCaseKind) -> &'static str {
    match k {
        LabCaseKind::ValidChain => "valid-chain",
        LabCaseKind::Expired => "expired",
        LabCaseKind::NotYetValid => "not-yet-valid",
        LabCaseKind::RevokedByCrl => "revoked-by-crl",
        LabCaseKind::RevokedByOcsp => "revoked-by-ocsp",
        LabCaseKind::WrongRoot => "wrong-root",
        LabCaseKind::Rsa1024 => "rsa-1024",
        LabCaseKind::Sha1Signed => "sha1-signed",
        LabCaseKind::Md5Signed => "md5-signed",
        LabCaseKind::BadEku => "bad-eku",
        LabCaseKind::NameConstraintViolation => "name-constraint-violation",
        LabCaseKind::BrokenSignature => "broken-signature",
        LabCaseKind::KeyMismatch => "key-mismatch",
    }
}
