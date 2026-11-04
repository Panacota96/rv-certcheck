//! OWNER: B. CA folders (`rakvor.ca/1`): root, import, issue, revoke, CRL, OCSP.
//!
//! ```text
//! <CA>/ca.json            CaFolder; every version written is recorded in issued.jsonl (`ca_json_written`,
//!                         SHA-256), so an edit outside the tool (crl_url, allowed_profiles, ...) is detected
//!                         by every operation and by `pki verify`. `pki set` is the recorded way to change it.
//! <CA>/issued.jsonl       hash-chained IssuedRecord per operation (issued.rs)
//! <CA>/certs/ca.crt       the CA certificate (PEM); certs/<serial>.crt for every certificate issued
//! <CA>/crl/<n>.crl        every CRL (DER, recorded: number, SHA-256, file), crl/latest.crl a copy of the newest
//!                         (checked against the newest recorded CRL)
//! <CA>/ocsp/<serial>-<time>.der   every OCSP response signed (lab use)
//! <CA>/keys/              encrypted CA key (0600; directory 0700); token keys are only referenced in ca.json
//! ```
//! Every mutating operation: lock the folder, verify issued.jsonl and every file it records (SHA-256), unlock the
//! CA key, check that it is the key of `certs/ca.crt`, act, append the record. Serials are 128-bit random
//! positive integers (127 random bits). Certificates carry AKI/SKI, the CDP of `ca.json` (`crl_url`) when set and
//! the Rakvor internal policy with its user notice.

use super::build::{self, CertTemplate, OcspCertStatus, RevokedSpec, ku};
use super::derw;
use super::issued::{self, Lock};
use super::keys::{self, crypto, io_err};
use super::rng::Rand;
use super::signer::Signer;
use super::tokens;
use crate::model::*;
use chrono::{DateTime, Duration, Utc};
use openssl::x509::{X509, X509NameRef};
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------------------------------------------------
// Small helpers shared with csr / lab / tokens
// ------------------------------------------------------------------------------------------------------------

/// `C=CO, O=Rakvor, CN=...` in certificate order with OpenSSL short names (the model's DN format).
pub fn name_string(n: &X509NameRef) -> String {
    name_rdns(n)
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn name_rdns(n: &X509NameRef) -> Vec<(String, String)> {
    n.entries()
        .map(|e| {
            let o = e.object();
            let k = o
                .nid()
                .short_name()
                .map(str::to_string)
                .unwrap_or_else(|_| o.to_string());
            let v = e
                .data()
                .to_string()
                .unwrap_or_else(|_| hex(e.data().as_slice()));
            (k, v)
        })
        .collect()
}

pub fn now() -> DateTime<Utc> {
    let t = Utc::now();
    DateTime::from_timestamp(t.timestamp(), 0).unwrap_or(t)
}

/// RFC 3339 / `YYYY-MM-DD` / `now` (None = now).
pub fn parse_time(s: Option<&str>) -> CertResult<DateTime<Utc>> {
    match s.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(now()),
        Some(t) => match AtTime::parse(t)? {
            AtTime::Fixed(f) => chrono::DateTime::parse_from_rfc3339(&f)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| CertError::new(ErrorKind::InvalidInput, format!("{t}: {e}"))),
            AtTime::Now => Ok(now()),
            AtTime::SigningTime => Err(CertError::new(
                ErrorKind::InvalidInput,
                "signing-time is not a valid time here",
            )),
        },
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&openssl::sha::sha256(b))
}

pub fn x509_der(der: &[u8]) -> CertResult<X509> {
    X509::from_der(der).map_err(|e| CertError::new(ErrorKind::Parse, format!("certificate: {e}")))
}

/// Serial hex in the model's format (lowercase, no leading 00).
pub fn serial_hex(serial: &[u8]) -> String {
    let s: Vec<u8> = serial.iter().copied().skip_while(|b| *b == 0).collect();
    if s.is_empty() { "00".into() } else { hex(&s) }
}

fn norm_serial(s: &str) -> String {
    let t = s
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase()
        .replace(':', "");
    let t = t.trim_start_matches('0');
    let t = if t.len() % 2 == 1 {
        format!("0{t}")
    } else {
        t.to_string()
    };
    if t.is_empty() { "00".into() } else { t }
}

fn serial_bytes(hex_s: &str) -> CertResult<Vec<u8>> {
    let t = norm_serial(hex_s);
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            format!("serial '{hex_s}' is not hex"),
        ));
    }
    Ok((0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
        .collect())
}

fn check_id(ca_id: &str) -> CertResult<()> {
    if ca_id.is_empty()
        || !ca_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            format!("ca id '{ca_id}': use letters, digits, '-', '_' and '.' only"),
        ));
    }
    Ok(())
}

fn ensure_empty_dir(dir: &Path) -> CertResult<()> {
    if dir.exists() {
        let mut it = std::fs::read_dir(dir).map_err(io_err(dir))?;
        if it.next().is_some() {
            return Err(CertError::new(
                ErrorKind::Policy,
                format!(
                    "{} is not empty: a CA folder is only created in an empty or new folder",
                    dir.display()
                ),
            ));
        }
    }
    std::fs::create_dir_all(dir.join("certs")).map_err(io_err(dir))?;
    std::fs::create_dir_all(dir.join("crl")).map_err(io_err(dir))?;
    keys::key_dir(&dir.join("keys"))
}

fn absolute(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    match (abs.parent(), abs.file_name()) {
        (Some(par), Some(f)) => par.canonicalize().map(|c| c.join(f)).unwrap_or(abs.clone()),
        _ => abs,
    }
}

/// `KeyLocation::EncryptedFile::path`: relative to the CA folder when inside it (with `/`), else absolute.
fn location_path(path: &Path, ca_dir: &Path) -> String {
    let abs = absolute(path);
    let ca = ca_dir.canonicalize().unwrap_or_else(|_| absolute(ca_dir));
    match abs.strip_prefix(&ca) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => abs.display().to_string(),
    }
}

fn resolve_location_path(ca_dir: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        ca_dir.join(path)
    }
}

/// A new key at `target`. File keys: generated by OpenSSL, written encrypted (0600, never overwritten); the
/// in-memory key is returned for a PKCS#12. Token keys: generated on the token.
fn new_key(
    target: &KeyTarget,
    spec: KeySpec,
    ca_dir: &Path,
    confirm_root: bool,
) -> CertResult<(KeyLocation, Signer)> {
    match target {
        KeyTarget::EncryptedFile { path, password } => {
            if path.exists() {
                return Err(CertError::new(
                    ErrorKind::Policy,
                    format!(
                        "{} already exists: key files are never overwritten",
                        path.display()
                    ),
                ));
            }
            let k = keys::generate(spec)?;
            let pem = keys::encrypted_pkcs8_pem(&k, password, &mut Rand::Os)?;
            keys::write_new(path, pem.as_bytes(), true)?;
            Ok((
                KeyLocation::EncryptedFile {
                    path: location_path(path, ca_dir),
                    format: "pkcs8-encrypted".into(),
                },
                Signer::Soft(k),
            ))
        }
        KeyTarget::Pkcs11 {
            module,
            token_serial,
            pin,
            key_label,
        } => {
            let s = tokens::open(module, token_serial, pin)?;
            let loc = s.generate(spec, key_label, confirm_root)?;
            let KeyLocation::Pkcs11 { key_id_hex, .. } = &loc else {
                unreachable!()
            };
            let id = key_id_hex.clone();
            Ok((loc, Signer::token(s, &id)?))
        }
    }
}

/// Opens an existing key (file or token) with its password / PIN.
fn open_key(loc: &KeyLocation, ca_dir: &Path, unlock: &KeyUnlock) -> CertResult<(Signer, String)> {
    match loc {
        KeyLocation::EncryptedFile { path, .. } => {
            let p = resolve_location_path(ca_dir, path);
            let data = zeroize::Zeroizing::new(std::fs::read(&p).map_err(io_err(&p))?);
            let (k, fmt) = keys::open_key_file(&data, &unlock.secret)?;
            Ok((Signer::Soft(k), fmt))
        }
        KeyLocation::Pkcs11 {
            module,
            token_serial,
            key_id_hex,
            ..
        } => {
            let s = tokens::open(Path::new(module), token_serial, &unlock.secret)?;
            Ok((Signer::token(s, key_id_hex)?, "pkcs11".into()))
        }
    }
}

fn same_key(signer: &Signer, cert: &X509) -> CertResult<bool> {
    let a = signer.spki()?;
    let b = cert
        .public_key()
        .and_then(|k| k.public_key_to_der())
        .map_err(crypto("certificate key"))?;
    Ok(keys::canonical_spki(&a)? == keys::canonical_spki(&b)?)
}

// ------------------------------------------------------------------------------------------------------------
// Profiles
// ------------------------------------------------------------------------------------------------------------

/// Profile extensions (without SKI/AKI/policy/CDP, added by the caller). `rsa` adds keyEncipherment to TLS.
pub fn profile_extensions(
    profile: IssueProfile,
    rsa: bool,
    sans: &[GeneralName],
) -> CertResult<Vec<Vec<u8>>> {
    let mut e = vec![];
    match profile {
        IssueProfile::Intermediate => {
            e.push(build::ext_basic_constraints(true, Some(0)));
            e.push(build::ext_key_usage(&[ku::KEY_CERT_SIGN, ku::CRL_SIGN]));
        }
        IssueProfile::CodeSigning => {
            e.push(build::ext_basic_constraints(false, None));
            e.push(build::ext_key_usage(&[ku::DIGITAL_SIGNATURE]));
            e.push(build::ext_eku(&[build::OID_EKU_CODE_SIGNING], false));
        }
        IssueProfile::Examiner => {
            e.push(build::ext_basic_constraints(false, None));
            e.push(build::ext_key_usage(&[
                ku::DIGITAL_SIGNATURE,
                ku::NON_REPUDIATION,
            ]));
            e.push(build::ext_eku(
                &[
                    build::OID_EKU_EMAIL,
                    build::OID_EKU_DOCUMENT_SIGNING,
                    build::OID_EKU_MS_DOCUMENT_SIGNING,
                ],
                false,
            ));
        }
        IssueProfile::Tsa => {
            e.push(build::ext_basic_constraints(false, None));
            e.push(build::ext_key_usage(&[ku::DIGITAL_SIGNATURE]));
            e.push(build::ext_eku(&[build::OID_EKU_TIMESTAMPING], true));
        }
        IssueProfile::TlsServer => {
            if !sans.iter().any(|g| g.kind == "dns" || g.kind == "ip") {
                return Err(CertError::new(
                    ErrorKind::InvalidInput,
                    "the tls-server profile needs at least one dns: or ip: SAN",
                ));
            }
            e.push(build::ext_basic_constraints(false, None));
            let mut usage = vec![ku::DIGITAL_SIGNATURE];
            if rsa {
                usage.push(ku::KEY_ENCIPHERMENT);
            }
            e.push(build::ext_key_usage(&usage));
            e.push(build::ext_eku(&[build::OID_EKU_SERVER_AUTH], false));
        }
        IssueProfile::ClientInternal => return Err(client_internal_refused()),
    }
    if !sans.is_empty() {
        e.push(build::ext_san(sans)?);
    }
    Ok(e)
}

fn client_internal_refused() -> CertError {
    CertError::new(
        ErrorKind::Policy,
        "the client-internal profile is disabled in v0.1: client certificates need Rakvor's Certificate Policy / CPS, reviewed by the lawyer, first (rv-certcheck#2). Rakvor certificates are internal-use only: not a firma digital under Ley 527 de 1999 art. 28, not qualified under eIDAS.",
    )
}

/// Default key of `pki init-root`.
pub const ROOT_DEFAULT_KEY_SPEC: KeySpec = KeySpec::Rsa4096;

fn default_profiles(path_len_zero: bool) -> Vec<IssueProfile> {
    IssueProfile::ALL
        .into_iter()
        .filter(|p| p.enabled())
        .filter(|p| !(path_len_zero && *p == IssueProfile::Intermediate))
        .collect()
}

/// The key type `pki issue` uses when none is given: P-384 intermediate; P-256 tsa / tls-server; RSA-3072
/// code-signing / examiner (Windows signtool and rv-hashinv's RSA-only PDF signing must load them).
/// `init-root` defaults to RSA-4096 ([`ROOT_DEFAULT_KEY_SPEC`]).
pub fn default_key_spec(profile: IssueProfile) -> KeySpec {
    match profile {
        // RSA for what Windows signtool / rv-hashinv (RSA-only PDF signing) must load.
        IssueProfile::CodeSigning | IssueProfile::Examiner => KeySpec::Rsa3072,
        IssueProfile::Intermediate => KeySpec::P384,
        _ => KeySpec::P256,
    }
}

// ------------------------------------------------------------------------------------------------------------
// The CA as loaded
// ------------------------------------------------------------------------------------------------------------

struct Ca {
    dir: PathBuf,
    folder: CaFolder,
    cert: X509,
    cert_der: Vec<u8>,
    records: Vec<IssuedRecord>,
}

impl Ca {
    fn key_id(&self) -> CertResult<Vec<u8>> {
        match self.cert.subject_key_id() {
            Some(s) => Ok(s.as_slice().to_vec()),
            None => keys::key_id(
                &self
                    .cert
                    .public_key()
                    .and_then(|k| k.public_key_to_der())
                    .map_err(crypto("CA key"))?,
            ),
        }
    }
    fn subject_der(&self) -> CertResult<Vec<u8>> {
        self.cert.subject_name().to_der().map_err(crypto("CA name"))
    }
    fn unlock(&self, unlock: &KeyUnlock) -> CertResult<Signer> {
        let (s, _) = open_key(&self.folder.key, &self.dir, unlock)?;
        if !same_key(&s, &self.cert)? {
            return Err(CertError::new(
                ErrorKind::Policy,
                "the CA key does not match certs/ca.crt: refusing to sign",
            ));
        }
        Ok(s)
    }
    fn append(&mut self, rec: IssuedRecord) -> CertResult<IssuedRecord> {
        let r = issued::append(&self.dir, &self.records, rec)?;
        self.records.push(r.clone());
        Ok(r)
    }
    fn record(&self, action: &str, actor: &str) -> IssuedRecord {
        IssuedRecord {
            ts_utc: rfc3339(now()),
            action: action.into(),
            ca_id: self.folder.ca_id.clone(),
            actor: actor.into(),
            tool_version: super::tool_version().into(),
            ..Default::default()
        }
    }
    fn save_folder(&self) -> CertResult<String> {
        let mut j = serde_json::to_string_pretty(&self.folder).expect("serializable");
        j.push('\n');
        keys::replace(&self.dir.join("ca.json"), j.as_bytes())?;
        Ok(sha256_hex(j.as_bytes()))
    }
    /// Writes ca.json and records its SHA-256 (`ca_json_written`), so that only the tool changes it.
    fn save_and_record(&mut self, actor: &str) -> CertResult<IssuedRecord> {
        let sha = self.save_folder()?;
        let mut r = self.record(CA_JSON_WRITTEN, actor);
        r.file = Some("ca.json".into());
        r.file_sha256 = Some(sha);
        self.append(r)
    }
}

/// Loads and verifies a CA folder: ca.json, the issued.jsonl chain, certs/ca.crt against ca.json and the first
/// record, and the SHA-256 of every file a record names.
fn load(ca_dir: &Path) -> CertResult<Ca> {
    let p = ca_dir.join("ca.json");
    let text = std::fs::read(&p).map_err(|e| {
        CertError::new(
            ErrorKind::Io,
            format!(
                "{} is not a CA folder ({}: {e})",
                ca_dir.display(),
                p.display()
            ),
        )
    })?;
    let folder: CaFolder = serde_json::from_slice(&text)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("{}: {e}", p.display())))?;
    if folder.schema != CA_SCHEMA {
        return Err(CertError::new(
            ErrorKind::Unsupported,
            format!(
                "{}: schema '{}' (expected {CA_SCHEMA})",
                p.display(),
                folder.schema
            ),
        ));
    }
    let records = issued::verify_or_err(ca_dir)?;
    let mut problems = vec![];
    let cert_path = ca_dir.join(&folder.certificate_file);
    let pem = std::fs::read(&cert_path).map_err(io_err(&cert_path))?;
    let cert_der = keys::der_from_pem_or_der(&pem, &["CERTIFICATE"])?;
    if sha256_hex(&cert_der) != folder.certificate_sha256 {
        problems.push(format!(
            "{} is not the certificate recorded in ca.json",
            folder.certificate_file
        ));
    }
    match records.first() {
        Some(r)
            if (r.action == "ca_created" || r.action == "ca_imported")
                && r.ca_id == folder.ca_id
                && r.cert_sha256.as_deref() == Some(folder.certificate_sha256.as_str()) => {}
        _ => problems.push(
            "the first issued.jsonl record does not create or import this CA certificate".into(),
        ),
    }
    problems.extend(recorded_file_problems(ca_dir, &records));
    if !problems.is_empty() {
        return Err(CertError::new(
            ErrorKind::Policy,
            format!(
                "CA folder {} does not verify, nothing will be issued: {}",
                ca_dir.display(),
                problems.join("; ")
            ),
        ));
    }
    let cert = x509_der(&cert_der)?;
    Ok(Ca {
        dir: ca_dir.to_path_buf(),
        folder,
        cert,
        cert_der,
        records,
    })
}

/// The record action of every ca.json written by the tool.
pub const CA_JSON_WRITTEN: &str = "ca_json_written";

/// Every file a record names must still have the SHA-256 of its *latest* record (ca.json is rewritten, so only
/// its last version counts; certificates, CRLs and OCSP responses are written once). ca.json must be recorded,
/// and crl/latest.crl must be the newest recorded CRL.
fn recorded_file_problems(ca_dir: &Path, records: &[IssuedRecord]) -> Vec<String> {
    let mut problems = vec![];
    let mut latest: std::collections::BTreeMap<&str, &IssuedRecord> = Default::default();
    for r in records {
        if let (Some(f), Some(_)) = (&r.file, &r.file_sha256) {
            latest.insert(f.as_str(), r);
        }
    }
    for (f, r) in &latest {
        let h = r.file_sha256.as_deref().unwrap_or_default();
        match std::fs::read(ca_dir.join(f)) {
            Ok(b) if sha256_hex(&b) == h => {}
            Ok(_) => problems.push(format!(
                "{f} (record {}) was modified after it was recorded",
                r.seq
            )),
            Err(_) => problems.push(format!("{f} (record {}) is missing", r.seq)),
        }
    }
    if !latest.contains_key("ca.json") {
        problems.push(
            "ca.json is not recorded in issued.jsonl (no ca_json_written record): its content cannot be trusted"
                .into(),
        );
    }
    let newest_crl = records
        .iter()
        .filter(|r| r.action == "crl_issued")
        .max_by_key(|r| (r.crl_number.unwrap_or(0), r.seq));
    let latest_path = ca_dir.join("crl").join("latest.crl");
    match (newest_crl, std::fs::read(&latest_path)) {
        (Some(r), Ok(b)) => {
            if Some(sha256_hex(&b).as_str()) != r.file_sha256.as_deref() {
                problems.push(format!(
                    "crl/latest.crl is not the newest recorded CRL ({}, record {})",
                    r.file.as_deref().unwrap_or("?"),
                    r.seq
                ));
            }
        }
        (Some(r), Err(_)) => problems.push(format!(
            "crl/latest.crl is missing (newest recorded CRL: {}, record {})",
            r.file.as_deref().unwrap_or("?"),
            r.seq
        )),
        (None, Ok(_)) => {
            problems.push("crl/latest.crl exists but no CRL is recorded in issued.jsonl".into())
        }
        (None, Err(_)) => {}
    }
    problems
}

/// Verifies a CA folder (ca.json, issued.jsonl chain, recorded files) and returns the number of records.
#[cfg(test)]
pub fn verify_folder(ca_dir: &Path) -> CertResult<usize> {
    Ok(load(ca_dir)?.records.len())
}

fn write_cert(dir: &Path, rel: &str, der: &[u8]) -> CertResult<(PathBuf, String)> {
    let pem = keys::pem_encode("CERTIFICATE", der);
    let p = dir.join(rel);
    keys::write_new(&p, pem.as_bytes(), false)?;
    Ok((p, sha256_hex(pem.as_bytes())))
}

// ------------------------------------------------------------------------------------------------------------
// Operations
// ------------------------------------------------------------------------------------------------------------

pub fn init_root(req: &InitRootRequest) -> CertResult<CaFolder> {
    if matches!(req.key_target, KeyTarget::Pkcs11 { .. }) && !req.confirm_root {
        return Err(CertError::new(
            ErrorKind::Policy,
            "creating a root CA key on a token needs --confirm-root (the key ceremony checklist is in docs/company-pki.md)",
        ));
    }
    check_id(&req.ca_id)?;
    if req.validity_days == 0 {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            "validity must be at least 1 day",
        ));
    }
    let subject = derw::name(&req.subject.rdns)?;
    ensure_empty_dir(&req.ca_dir)?;
    let _lock = Lock::take(&req.ca_dir)?;
    let (key_loc, signer) = new_key(&req.key_target, req.key_spec, &req.ca_dir, req.confirm_root)?;
    let spki = signer.spki()?;
    let ski = keys::key_id(&spki)?;
    let nb = now();
    let na = nb + Duration::days(req.validity_days as i64);
    let mut extensions = vec![
        build::ext_basic_constraints(true, None),
        build::ext_key_usage(&[ku::KEY_CERT_SIGN, ku::CRL_SIGN]),
        build::ext_ski(&ski),
        build::ext_aki(&ski),
        build::ext_policy(RAKVOR_POLICY_INTERNAL, RAKVOR_INTERNAL_NOTICE)?,
    ];
    if !req.subject.sans.is_empty() {
        extensions.push(build::ext_san(&req.subject.sans)?);
    }
    let t = CertTemplate {
        serial: Rand::Os.serial()?,
        issuer: subject.clone(),
        subject,
        not_before: nb,
        not_after: na,
        spki,
        extensions,
    };
    let der = build::certificate(&t, signer.default_alg()?, &signer)?;
    let cert = x509_der(&der)?;
    let pk = cert.public_key().map_err(crypto("root key"))?;
    if !cert.verify(&pk).map_err(crypto("self-signature"))? {
        return Err(CertError::new(
            ErrorKind::Crypto,
            "the new root does not verify",
        ));
    }
    let (_, file_sha) = write_cert(&req.ca_dir, "certs/ca.crt", &der)?;
    let folder = CaFolder {
        schema: CA_SCHEMA.into(),
        ca_id: req.ca_id.clone(),
        kind: CaKind::Root,
        subject: name_string(cert.subject_name()),
        certificate_file: "certs/ca.crt".into(),
        certificate_sha256: sha256_hex(&der),
        serial_hex: serial_hex(&t.serial),
        not_before: rfc3339(nb),
        not_after: rfc3339(na),
        key_spec: Some(req.key_spec),
        key: key_loc.clone(),
        parent: None,
        parent_certificate_sha256: None,
        parent_subject: None,
        parent_key_id_hex: None,
        allowed_profiles: default_profiles(false),
        next_crl_number: 1,
        serial_policy: "random-128".into(),
        policy_oid: RAKVOR_POLICY_INTERNAL.into(),
        created_utc: rfc3339(nb),
        created_by: req.actor.clone(),
        tool_version: super::tool_version().into(),
        crl_url: None,
    };
    let mut ca = Ca {
        dir: req.ca_dir.clone(),
        folder: folder.clone(),
        cert,
        cert_der: der.clone(),
        records: vec![],
    };
    ca.save_folder()?;
    let mut r = ca.record("ca_created", &req.actor);
    r.serial_hex = Some(folder.serial_hex.clone());
    r.subject = Some(folder.subject.clone());
    r.not_before = Some(folder.not_before.clone());
    r.not_after = Some(folder.not_after.clone());
    r.cert_sha256 = Some(folder.certificate_sha256.clone());
    r.file = Some("certs/ca.crt".into());
    r.file_sha256 = Some(file_sha);
    r.key = Some(key_loc);
    ca.append(r)?;
    ca.save_and_record(&req.actor)?;
    Ok(folder)
}

pub fn import_ca(req: &ImportCaRequest) -> CertResult<CaFolder> {
    import_ca_with_issuer(req, None)
}

/// [`import_ca`] with the issuer's certificate (`pki import --issuer-cert`): it must have issued the imported
/// certificate (name and signature), and its SHA-256 is recorded as `parent_certificate_sha256`.
pub fn import_ca_with_issuer(
    req: &ImportCaRequest,
    issuer_certificate: Option<&[u8]>,
) -> CertResult<CaFolder> {
    check_id(&req.ca_id)?;
    let der = keys::der_from_pem_or_der(&req.certificate, &["CERTIFICATE"])?;
    let cert = x509_der(&der)?;
    let issuer_sha = match issuer_certificate {
        None => None,
        Some(b) => {
            let idr = keys::der_from_pem_or_der(b, &["CERTIFICATE"])?;
            let ic = x509_der(&idr)?;
            let names_match = ic.subject_name().to_der().ok() == cert.issuer_name().to_der().ok();
            let signed = ic
                .public_key()
                .and_then(|k| cert.verify(&k))
                .unwrap_or(false);
            if !names_match || !signed {
                return Err(CertError::new(
                    ErrorKind::Policy,
                    "--issuer-cert did not issue this certificate (issuer name or signature does not match)",
                ));
            }
            Some(sha256_hex(&idr))
        }
    };
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("certificate: {e}")))?;
    let is_ca = parsed
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|b| b.value.ca);
    let can_sign = match parsed.key_usage().ok().flatten() {
        Some(k) => k.value.key_cert_sign(),
        None => true,
    };
    if !is_ca || !can_sign {
        return Err(CertError::new(
            ErrorKind::Policy,
            "this certificate is not a CA certificate (basicConstraints CA:TRUE with keyCertSign): it cannot be managed as a CA",
        ));
    }
    let key_loc = match &req.key {
        KeyLocation::EncryptedFile { path, format } => KeyLocation::EncryptedFile {
            path: absolute(Path::new(path)).display().to_string(),
            format: format.clone(),
        },
        other => other.clone(),
    };
    // Key first (refuse before anything is written).
    let (signer, fmt) = open_key(&key_loc, &req.ca_dir, &req.unlock)?;
    if !same_key(&signer, &cert)? {
        return Err(CertError::new(
            ErrorKind::Policy,
            "the key does not match the certificate: refusing to import",
        ));
    }
    let key_loc = match key_loc {
        KeyLocation::EncryptedFile { path, .. } => KeyLocation::EncryptedFile {
            path: location_path(Path::new(&path), &req.ca_dir),
            format: fmt,
        },
        KeyLocation::Pkcs11 {
            module,
            token_serial,
            token_label,
            key_id_hex,
            key_label,
        } => {
            let label = match &signer {
                Signer::Token { session, .. } => session.token_label.clone(),
                _ => None,
            };
            KeyLocation::Pkcs11 {
                module,
                token_serial,
                token_label: token_label.or(label),
                key_id_hex,
                key_label,
            }
        }
    };
    ensure_empty_dir(&req.ca_dir)?;
    let _lock = Lock::take(&req.ca_dir)?;
    let self_signed = cert.subject_name().to_der().ok() == cert.issuer_name().to_der().ok()
        && cert
            .public_key()
            .and_then(|k| cert.verify(&k))
            .unwrap_or(false);
    let (_, file_sha) = write_cert(&req.ca_dir, "certs/ca.crt", &der)?;
    let pk = cert.public_key().map_err(crypto("CA key"))?;
    let asn1 = |t: &openssl::asn1::Asn1TimeRef| -> String {
        let epoch = openssl::asn1::Asn1Time::from_unix(0).expect("epoch");
        let d = epoch.diff(t).expect("time diff");
        let secs = d.days as i64 * 86400 + d.secs as i64;
        rfc3339(DateTime::from_timestamp(secs, 0).unwrap_or_default())
    };
    let folder = CaFolder {
        schema: CA_SCHEMA.into(),
        ca_id: req.ca_id.clone(),
        kind: if self_signed {
            CaKind::Imported
        } else {
            CaKind::Intermediate
        },
        subject: name_string(cert.subject_name()),
        certificate_file: "certs/ca.crt".into(),
        certificate_sha256: sha256_hex(&der),
        serial_hex: serial_hex(
            &cert
                .serial_number()
                .to_bn()
                .map_err(crypto("serial"))?
                .to_vec(),
        ),
        not_before: asn1(cert.not_before()),
        not_after: asn1(cert.not_after()),
        key_spec: keys::spec_of(&pk),
        key: key_loc.clone(),
        parent: None,
        parent_certificate_sha256: issuer_sha,
        parent_subject: (!self_signed).then(|| name_string(cert.issuer_name())),
        parent_key_id_hex: if self_signed {
            None
        } else {
            cert.authority_key_id().map(|k| hex(k.as_slice()))
        },
        allowed_profiles: default_profiles(cert.pathlen() == Some(0)),
        next_crl_number: 1,
        serial_policy: "random-128".into(),
        policy_oid: RAKVOR_POLICY_INTERNAL.into(),
        created_utc: rfc3339(now()),
        created_by: req.actor.clone(),
        tool_version: super::tool_version().into(),
        crl_url: None,
    };
    let mut ca = Ca {
        dir: req.ca_dir.clone(),
        folder: folder.clone(),
        cert,
        cert_der: der,
        records: vec![],
    };
    ca.save_folder()?;
    let mut r = ca.record("ca_imported", &req.actor);
    r.serial_hex = Some(folder.serial_hex.clone());
    r.subject = Some(folder.subject.clone());
    r.not_before = Some(folder.not_before.clone());
    r.not_after = Some(folder.not_after.clone());
    r.cert_sha256 = Some(folder.certificate_sha256.clone());
    r.file = Some("certs/ca.crt".into());
    r.file_sha256 = Some(file_sha);
    r.key = Some(key_loc);
    ca.append(r)?;
    ca.save_and_record(&req.actor)?;
    Ok(folder)
}

/// `pki set --crl-url URL`: the recorded way to change ca.json. Verifies the folder, sets (or, with None or an
/// empty string, clears) the CRL distribution point written into every certificate issued from now on, and
/// records the new ca.json. Returns the folder and the `ca_json_written` record.
pub fn set_crl_url(
    ca_dir: &Path,
    url: Option<&str>,
    actor: &str,
) -> CertResult<(CaFolder, IssuedRecord)> {
    let url = url.map(str::trim).filter(|u| !u.is_empty());
    if let Some(u) = url {
        let lower = u.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://"))
            || u.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(CertError::new(
                ErrorKind::InvalidInput,
                format!("--crl-url '{u}': give an http:// or https:// URL without spaces"),
            ));
        }
    }
    let _lock = Lock::take(ca_dir)?;
    let mut ca = load(ca_dir)?;
    ca.folder.crl_url = url.map(String::from);
    let r = ca.save_and_record(actor)?;
    Ok((ca.folder, r))
}

pub fn open(ca_dir: &Path) -> CertResult<CaFolder> {
    Ok(load(ca_dir)?.folder)
}

/// Subject, SANs and public key of a CSR whose self-signature verifies.
pub(crate) fn csr_parts(der: &[u8]) -> CertResult<(Vec<u8>, Vec<GeneralName>, Vec<u8>)> {
    let der = keys::der_from_pem_or_der(der, &["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"])?;
    let req = openssl::x509::X509Req::from_der(&der)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("CSR: {e}")))?;
    let pk = req.public_key().map_err(crypto("CSR key"))?;
    if !req.verify(&pk).unwrap_or(false) {
        return Err(CertError::new(
            ErrorKind::Policy,
            "the CSR's self-signature does not verify: refusing to certify its key",
        ));
    }
    let subject = req.subject_name().to_der().map_err(crypto("CSR subject"))?;
    let spki = pk.public_key_to_der().map_err(crypto("CSR key"))?;
    Ok((subject, super::csr::sans_of(&der)?, spki))
}

pub fn issue(req: &IssueRequest) -> CertResult<IssueResult> {
    issue_with(req, &IssueOptions::default())
}

pub fn issue_with(req: &IssueRequest, opts: &IssueOptions) -> CertResult<IssueResult> {
    if !req.profile.enabled() {
        return Err(client_internal_refused());
    }
    if req.profile == IssueProfile::Examiner {
        let spec = req.key_spec.unwrap_or(default_key_spec(req.profile));
        if !spec.is_rsa() && !opts.allow_non_rsa_examiner {
            return Err(CertError::new(
                ErrorKind::Policy,
                format!(
                    "the examiner profile needs an RSA key ({} given): rv-hashinv signs PDF reports with RSA keys only, so an {} examiner certificate could not sign reports. Use rsa-3072 (the default) or rsa-4096, or pass --allow-non-rsa-examiner for a certificate that will not sign rv-hashinv reports",
                    spec.name(),
                    spec.name()
                ),
            ));
        }
    }
    let _lock = Lock::take(&req.ca_dir)?;
    let mut ca = load(&req.ca_dir)?;
    if !ca.folder.allowed_profiles.contains(&req.profile) {
        return Err(CertError::new(
            ErrorKind::Policy,
            format!(
                "CA {} may not issue the {} profile{}",
                ca.folder.ca_id,
                req.profile.name(),
                if req.profile == IssueProfile::Intermediate && ca.cert.pathlen() == Some(0) {
                    " (its certificate has pathLenConstraint 0: it can only certify end entities)"
                } else {
                    ""
                }
            ),
        ));
    }
    if req.validity_days == 0 {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            "validity must be at least 1 day",
        ));
    }
    if req.profile == IssueProfile::Examiner {
        match (&req.csr_der, &req.key_target, &req.p12_password) {
            (None, Some(KeyTarget::EncryptedFile { .. }), Some(p)) if !p.is_empty() => {}
            (None, Some(KeyTarget::EncryptedFile { .. }), _) => {
                return Err(CertError::new(
                    ErrorKind::Password,
                    "the examiner profile writes a .p12: give its password",
                ));
            }
            _ => {
                return Err(CertError::new(
                    ErrorKind::InvalidInput,
                    "the examiner profile needs a new file key (the .p12 carries it): no CSR, no token key",
                ));
            }
        }
    }
    let signer = ca.unlock(&req.ca_unlock)?;
    // Subject, SANs, key.
    let (subject, sans, spki, subject_key, key_loc) = match &req.csr_der {
        Some(csr) => {
            let (csr_subject, csr_sans, spki) = csr_parts(csr)?;
            let subject = if req.subject.rdns.is_empty() {
                csr_subject
            } else {
                derw::name(&req.subject.rdns)?
            };
            let sans = if req.subject.sans.is_empty() {
                csr_sans
            } else {
                req.subject.sans.clone()
            };
            (subject, sans, spki, None, None)
        }
        None => {
            let subject = derw::name(&req.subject.rdns)?;
            let target = req.key_target.as_ref().ok_or_else(|| {
                CertError::new(
                    ErrorKind::InvalidInput,
                    "give either a CSR or where to create the new key",
                )
            })?;
            let spec = req.key_spec.unwrap_or(default_key_spec(req.profile));
            // Fail on the profile before a key is created.
            profile_extensions(
                req.profile,
                matches!(spec, KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096),
                &req.subject.sans,
            )?;
            let (loc, key) = new_key(target, spec, &req.ca_dir, false)?;
            (
                subject,
                req.subject.sans.clone(),
                key.spki()?,
                Some(key),
                Some(loc),
            )
        }
    };
    let is_rsa = openssl::pkey::PKey::public_key_from_der(&spki)
        .map(|k| k.id() == openssl::pkey::Id::RSA)
        .unwrap_or(false);
    let mut extensions = profile_extensions(req.profile, is_rsa, &sans)?;
    extensions.push(build::ext_ski(&keys::key_id(&spki)?));
    extensions.push(build::ext_aki(&ca.key_id()?));
    extensions.push(build::ext_policy(
        &ca.folder.policy_oid,
        RAKVOR_INTERNAL_NOTICE,
    )?);
    if let Some(url) = ca.folder.crl_url.as_deref().filter(|u| !u.is_empty()) {
        extensions.push(build::ext_cdp(url));
    }
    let nb = now();
    let ca_not_after = chrono::DateTime::parse_from_rfc3339(&ca.folder.not_after)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or(nb);
    let na = (nb + Duration::days(req.validity_days as i64)).min(ca_not_after);
    if na <= nb {
        return Err(CertError::new(
            ErrorKind::Policy,
            "the CA certificate has expired: it cannot issue",
        ));
    }
    let serial = Rand::Os.serial()?;
    let t = CertTemplate {
        serial: serial.clone(),
        issuer: ca.subject_der()?,
        subject,
        not_before: nb,
        not_after: na,
        spki,
        extensions,
    };
    let der = build::certificate(&t, signer.default_alg()?, &signer)?;
    let cert = x509_der(&der)?;
    let ca_pk = ca.cert.public_key().map_err(crypto("CA key"))?;
    if !cert.verify(&ca_pk).map_err(crypto("signature"))? {
        return Err(CertError::new(
            ErrorKind::Crypto,
            "the new certificate does not verify",
        ));
    }
    let sh = serial_hex(&serial);
    let rel = format!("certs/{sh}.crt");
    let (cert_path, file_sha) = write_cert(&req.ca_dir, &rel, &der)?;
    let mut p12_path = None;
    if req.profile == IssueProfile::Examiner {
        if let (Some(Signer::Soft(k)), Some(KeyTarget::EncryptedFile { path, .. }), Some(pw)) =
            (&subject_key, &req.key_target, &req.p12_password)
        {
            let p = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(format!("{sh}.p12"));
            let cn = name_rdns(cert.subject_name())
                .into_iter()
                .find(|(k, _)| k == "CN")
                .map(|(_, v)| v)
                .unwrap_or_else(|| sh.clone());
            let bytes = keys::pkcs12(
                k,
                &[der.clone(), ca.cert_der.clone()],
                &cn,
                pw,
                &mut Rand::Os,
            )?;
            keys::write_new(&p, &bytes, true)?;
            p12_path = Some(p);
        }
    }
    let mut r = ca.record("issued", &req.actor);
    r.serial_hex = Some(sh);
    r.profile = Some(req.profile);
    r.subject = Some(name_string(cert.subject_name()));
    r.not_before = Some(rfc3339(nb));
    r.not_after = Some(rfc3339(na));
    r.cert_sha256 = Some(sha256_hex(&der));
    r.file = Some(rel);
    r.file_sha256 = Some(file_sha);
    r.key = key_loc.clone();
    let record = ca.append(r)?;
    Ok(IssueResult {
        record,
        cert_path,
        key: key_loc,
        p12_path,
    })
}

/// Current revocation state of each serial: (reason, revoked_at) of its last `revoked` record.
fn revoked_map(records: &[IssuedRecord]) -> std::collections::BTreeMap<String, (String, String)> {
    let mut m = std::collections::BTreeMap::new();
    for r in records.iter().filter(|r| r.action == "revoked") {
        if let Some(s) = &r.serial_hex {
            m.insert(
                s.clone(),
                (
                    r.reason.clone().unwrap_or_else(|| "unspecified".into()),
                    r.revoked_at.clone().unwrap_or_else(|| r.ts_utc.clone()),
                ),
            );
        }
    }
    m
}

pub fn revoke(req: &RevokeRequest) -> CertResult<IssuedRecord> {
    let serial = norm_serial(&req.serial_hex);
    if !REVOCATION_REASONS.contains(&req.reason.as_str()) {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            format!(
                "unknown revocation reason '{}': use one of {}",
                req.reason,
                REVOCATION_REASONS.join(", ")
            ),
        ));
    }
    let at = parse_time(req.revoked_at.as_deref())?;
    let _lock = Lock::take(&req.ca_dir)?;
    let mut ca = load(&req.ca_dir)?;
    let issued = ca
        .records
        .iter()
        .find(|r| r.action == "issued" && r.serial_hex.as_deref() == Some(serial.as_str()))
        .cloned()
        .ok_or_else(|| {
            CertError::new(
                ErrorKind::InvalidInput,
                format!("serial {serial} was not issued by CA {}", ca.folder.ca_id),
            )
        })?;
    if revoked_map(&ca.records).contains_key(&serial) {
        return Err(CertError::new(
            ErrorKind::Policy,
            format!("serial {serial} is already revoked"),
        ));
    }
    let mut r = ca.record("revoked", &req.actor);
    r.serial_hex = Some(serial);
    r.profile = issued.profile;
    r.subject = issued.subject;
    r.cert_sha256 = issued.cert_sha256;
    r.reason = Some(req.reason.clone());
    r.revoked_at = Some(rfc3339(at));
    ca.append(r)
}

pub fn make_crl(req: &CrlRequest) -> CertResult<CrlResult> {
    if req.next_update_days == 0 {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            "next update must be at least 1 day ahead",
        ));
    }
    let this = parse_time(req.this_update.as_deref())?;
    let next = this + Duration::days(req.next_update_days as i64);
    let _lock = Lock::take(&req.ca_dir)?;
    let mut ca = load(&req.ca_dir)?;
    let signer = ca.unlock(&req.ca_unlock)?;
    let number = ca
        .records
        .iter()
        .filter_map(|r| r.crl_number)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1)
        .max(ca.folder.next_crl_number.max(1));
    let mut revoked = vec![];
    for (serial, (reason, at)) in revoked_map(&ca.records) {
        revoked.push(RevokedSpec {
            serial: serial_bytes(&serial)?,
            at: parse_time(Some(&at))?,
            reason,
        });
    }
    let der = build::crl(
        &ca.subject_der()?,
        &ca.key_id()?,
        this,
        next,
        number,
        &revoked,
        signer.default_alg()?,
        &signer,
    )?;
    let crl = openssl::x509::X509Crl::from_der(&der).map_err(crypto("CRL"))?;
    let ca_pk = ca.cert.public_key().map_err(crypto("CA key"))?;
    if !crl.verify(&ca_pk).map_err(crypto("CRL signature"))? {
        return Err(CertError::new(
            ErrorKind::Crypto,
            "the new CRL does not verify",
        ));
    }
    let rel = format!("crl/{number}.crl");
    let path = req.ca_dir.join(&rel);
    keys::write_new(&path, &der, false)?;
    keys::replace(&req.ca_dir.join("crl").join("latest.crl"), &der)?;
    let sha = sha256_hex(&der);
    let mut r = ca.record("crl_issued", &req.actor);
    r.file = Some(rel);
    r.file_sha256 = Some(sha.clone());
    r.crl_number = Some(number);
    r.not_before = Some(rfc3339(this));
    r.not_after = Some(rfc3339(next));
    let record = ca.append(r)?;
    ca.folder.next_crl_number = number + 1;
    ca.save_and_record(&req.actor)?;
    Ok(CrlResult {
        record,
        path,
        crl_number: number,
        sha256: sha,
    })
}

pub fn sign_ocsp(req: &OcspSignRequest) -> CertResult<OcspSignResult> {
    let serial = norm_serial(&req.serial_hex);
    let produced = parse_time(req.produced_at.as_deref())?;
    let next = req
        .next_update_days
        .map(|d| produced + Duration::days(d as i64));
    let _lock = Lock::take(&req.ca_dir)?;
    let mut ca = load(&req.ca_dir)?;
    let signer = ca.unlock(&req.ca_unlock)?;
    let was_issued = ca
        .records
        .iter()
        .any(|r| r.action == "issued" && r.serial_hex.as_deref() == Some(serial.as_str()));
    let revoked = revoked_map(&ca.records).get(&serial).cloned();
    let status = match (&revoked, was_issued) {
        (Some((reason, at)), _) if parse_time(Some(at))? <= produced => OcspCertStatus::Revoked {
            at: parse_time(Some(at))?,
            reason: reason.clone(),
        },
        (_, true) => OcspCertStatus::Good,
        (_, false) => OcspCertStatus::Unknown,
    };
    let ca_spki = ca
        .cert
        .public_key()
        .and_then(|k| k.public_key_to_der())
        .map_err(crypto("CA key"))?;
    let der = build::ocsp_response(
        &ca.subject_der()?,
        &ca.cert_der,
        &ca.subject_der()?,
        &keys::spki_key_bits(&ca_spki)?,
        &serial_bytes(&serial)?,
        &status,
        produced,
        next,
        signer.default_alg()?,
        &signer,
    )?;
    let sha = sha256_hex(&der);
    let rel = format!("ocsp/{serial}-{}.der", produced.format("%Y%m%dT%H%M%SZ"));
    let internal = req.ca_dir.join(&rel);
    keys::write_new(&internal, &der, false)?;
    if absolute(&req.out) != absolute(&internal) {
        keys::write_new(&req.out, &der, false)?;
    }
    let source = RevocationSource {
        kind: RevocationSourceKind::Ocsp,
        origin: format!("file:{}", req.out.display()),
        sha256: sha.clone(),
        this_update: Some(rfc3339(produced)),
        next_update: next.map(rfc3339),
    };
    let result_status = match &status {
        OcspCertStatus::Good => RevocationStatus::Good { source },
        OcspCertStatus::Revoked { at, reason } => RevocationStatus::Revoked {
            reason: reason.clone(),
            revoked_at: rfc3339(*at),
            source,
        },
        OcspCertStatus::Unknown => RevocationStatus::Unknown {
            source: format!("serial {serial} was not issued by CA {}", ca.folder.ca_id),
        },
    };
    let mut r = ca.record("ocsp_signed", &req.actor);
    r.serial_hex = Some(serial);
    r.file = Some(rel);
    r.file_sha256 = Some(sha.clone());
    r.not_before = Some(rfc3339(produced));
    r.not_after = next.map(rfc3339);
    if let Some((reason, at)) = revoked.filter(|_| matches!(status, OcspCertStatus::Revoked { .. }))
    {
        r.reason = Some(reason);
        r.revoked_at = Some(at);
    }
    let record = ca.append(r)?;
    Ok(OcspSignResult {
        record,
        path: req.out.clone(),
        status: result_status,
        sha256: sha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_normalise() {
        assert_eq!(norm_serial("00AB"), "ab");
        assert_eq!(norm_serial("0x0abc"), "0abc");
        assert_eq!(norm_serial("ab:cd"), "abcd");
        assert_eq!(serial_hex(&[0, 0x0f, 1]), "0f01");
        assert_eq!(serial_bytes("0f01").unwrap(), vec![0x0f, 1]);
    }

    #[test]
    fn verify_folder_detects_a_forged_record() {
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join("ca");
        init_root(&InitRootRequest {
            ca_dir: ca.clone(),
            ca_id: "t".into(),
            subject: SubjectSpec {
                rdns: vec![("CN".into(), "T".into())],
                sans: vec![],
            },
            key_spec: KeySpec::P256,
            key_target: KeyTarget::EncryptedFile {
                path: ca.join("keys/t.key.p8"),
                password: Secret::new("pw"),
            },
            validity_days: 2,
            confirm_root: false,
            actor: "t".into(),
        })
        .unwrap();
        // ca_created + ca_json_written.
        assert_eq!(verify_folder(&ca).unwrap(), 2);
        // A record appended by hand with a correct-looking but recomputed-without-chain hash is refused.
        let path = ca.join(issued::FILE);
        let mut text = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        v["seq"] = 3.into();
        v["action"] = "issued".into();
        text.push_str(&serde_json::to_string(&v).unwrap());
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        let e = verify_folder(&ca).unwrap_err();
        assert!(e.message.contains("line 3"), "{}", e.message);
        // A stale lock is reported, not broken.
        std::fs::write(ca.join("issued.lock"), "pid 1").unwrap();
        assert!(Lock::take(&ca).unwrap_err().message.contains("issued.lock"));
    }
}
