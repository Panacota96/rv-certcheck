//! The Create tab: a CA folder (its state from `pki show` and the `pki verify` result), the creation wizards and
//! the operations they run. Every operation calls the same certificate-layer function as the CLI command
//! (`pki::init_root`, `pki::import_ca`, `pki::issue`, `pki::revoke`, `pki::make_crl`, `csr::new`, `lab::make`,
//! `tokens::list`, `trust_list::import_*`) and writes the same audited run as the CLI
//! ([`rv_certcheck_core::creation::CreationRun`], frontend `gui`).
//!
//! ```text
//! form (text, choices, MaskedField secrets) ─► check (no secret taken yet) ─► take secrets ─► PreparedOp
//!   ─► execute (worker thread): CreationRun::start(preamble = ui_* actions) ─► certs::… ─► records ─► finish
//!   ─► OpResult (outcome, files, CA folder to refresh) ─► the secrets are dropped with the request (zeroized)
//! ```
//! Audit entries and parameters carry where keys are (file path, token serial, key id), never a password, PIN
//! or key.

use super::{MaskedField, UiLog};
use rv_certcheck_core::certs::{
    self, CaFolder, CertError, CrlRequest, CsrRequest, GeneralName, ImportCaRequest,
    InitRootRequest, IssueProfile, IssueRequest, KeyLocation, KeySpec, KeyTarget, KeyUnlock,
    LabSetSpec, RevokeRequest, Secret, SubjectSpec, TokenInfo, TrustListKind,
};
use rv_certcheck_core::creation::{
    CreationOutcome, CreationRun, LAB_NOTICE, internal_notice, issued_records, resolve,
};
use rv_certcheck_core::i18n::Catalog;
use rv_certcheck_core::{HashAlgo, TOOL_NAME, hash::hash_bytes};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Recorded in the parameters instead of the secret itself.
pub const SECRET_NOT_RECORDED: &str = "entered in the GUI (masked, not recorded)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wizard {
    NewRoot,
    Import,
    Issue,
    Revoke,
    Crl,
    Csr,
    Lab,
}

impl Wizard {
    pub const ALL: [Wizard; 7] = [
        Wizard::NewRoot,
        Wizard::Import,
        Wizard::Issue,
        Wizard::Revoke,
        Wizard::Crl,
        Wizard::Csr,
        Wizard::Lab,
    ];
    pub fn name(&self) -> &'static str {
        match self {
            Wizard::NewRoot => "new_root",
            Wizard::Import => "import",
            Wizard::Issue => "issue",
            Wizard::Revoke => "revoke",
            Wizard::Crl => "crl",
            Wizard::Csr => "csr",
            Wizard::Lab => "lab",
        }
    }
    /// i18n `ui` key of the wizard's title.
    pub fn key(&self) -> String {
        format!("wz_{}", self.name())
    }
    /// The wizard works on the opened CA folder.
    pub fn needs_ca(&self) -> bool {
        matches!(self, Wizard::Issue | Wizard::Revoke | Wizard::Crl)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyMode {
    /// Encrypted PKCS#8 file.
    #[default]
    File,
    /// PKCS#11 token.
    Token,
}

impl KeyMode {
    pub fn name(&self) -> &'static str {
        match self {
            KeyMode::File => "file",
            KeyMode::Token => "token",
        }
    }
}

/// Where a key is created (or found, for import) and the secret that protects it.
#[derive(Debug, Default)]
pub struct KeyForm {
    pub mode: KeyMode,
    /// Empty = the command's default file.
    pub key_file: String,
    pub password: MaskedField,
    /// Confirmation of a new key-file password.
    pub password_again: MaskedField,
    pub module: String,
    pub token_serial: String,
    pub key_label: String,
    /// CKA_ID (hex) of an existing token key (import).
    pub key_id: String,
    pub pin: MaskedField,
}

fn clean(s: &str) -> String {
    s.trim().trim_matches('"').trim().to_string()
}

impl KeyForm {
    /// For the parameters and the audit log: where the key goes, never the secret.
    pub fn describe(&self) -> Value {
        let opt = |s: &str| {
            let s = clean(s);
            if s.is_empty() { Value::Null } else { json!(s) }
        };
        let token = self.mode == KeyMode::Token;
        json!({
            "mode": self.mode.name(),
            "key_file": if token { Value::Null } else { opt(&self.key_file) },
            "pkcs11_module": if token { opt(&self.module) } else { Value::Null },
            "token_serial": if token { opt(&self.token_serial) } else { Value::Null },
            "key_label": if token { opt(&self.key_label) } else { Value::Null },
            "key_id": if token { opt(&self.key_id) } else { Value::Null },
            "secret": SECRET_NOT_RECORDED,
        })
    }

    /// Checks a new key's form without taking any secret.
    fn check_new(&self, c: &Catalog) -> Result<(), String> {
        match self.mode {
            KeyMode::File => {
                if self.password.is_empty() {
                    return Err(c.ui("err_key_password"));
                }
                if !self.password.same_as(&self.password_again) {
                    return Err(c.ui("err_passwords_differ"));
                }
            }
            KeyMode::Token => {
                if clean(&self.module).is_empty() || clean(&self.token_serial).is_empty() {
                    return Err(c.ui("err_token_needed"));
                }
                if self.pin.is_empty() {
                    return Err(c.ui("err_pin"));
                }
            }
        }
        Ok(())
    }

    /// Takes the secret into a new-key target (call after [`KeyForm::check_new`]). Every secret field is empty after.
    fn take_target(&mut self, default_file: PathBuf, default_label: &str) -> KeyTarget {
        let t = match self.mode {
            KeyMode::File => KeyTarget::EncryptedFile {
                path: Some(clean(&self.key_file))
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or(default_file),
                password: self.password.take(),
            },
            KeyMode::Token => KeyTarget::Pkcs11 {
                module: PathBuf::from(clean(&self.module)),
                token_serial: clean(&self.token_serial),
                pin: self.pin.take(),
                key_label: Some(clean(&self.key_label))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| default_label.to_string()),
            },
        };
        self.wipe();
        t
    }

    /// Where an existing key is (import), without its secret.
    fn location(&self, c: &Catalog) -> Result<KeyLocation, String> {
        match self.mode {
            KeyMode::File => {
                let f = clean(&self.key_file);
                if f.is_empty() {
                    return Err(c.ui("err_key_file"));
                }
                Ok(KeyLocation::EncryptedFile {
                    path: f,
                    format: "pkcs8-encrypted".into(),
                })
            }
            KeyMode::Token => {
                if clean(&self.module).is_empty()
                    || clean(&self.token_serial).is_empty()
                    || clean(&self.key_id).is_empty()
                {
                    return Err(c.ui("err_token_key_needed"));
                }
                Ok(KeyLocation::Pkcs11 {
                    module: clean(&self.module),
                    token_serial: clean(&self.token_serial),
                    token_label: None,
                    key_id_hex: clean(&self.key_id),
                    key_label: Some(clean(&self.key_label)).filter(|s| !s.is_empty()),
                })
            }
        }
    }

    /// The unlock secret of an existing key (password or PIN); every secret field is empty after.
    fn take_unlock(&mut self) -> Secret {
        let s = match self.mode {
            KeyMode::File => self.password.take(),
            KeyMode::Token => self.pin.take(),
        };
        self.wipe();
        s
    }

    pub fn wipe(&mut self) {
        self.password.wipe();
        self.password_again.wipe();
        self.pin.wipe();
    }

    pub fn secrets_empty(&self) -> bool {
        self.password.is_empty() && self.password_again.is_empty() && self.pin.is_empty()
    }
}

/// `C=CO,O=Rakvor,CN=Ana Ruiz` and SANs `dns:a, email:b` (commas, spaces or new lines) → SubjectSpec, with the
/// CLI's rules (`--subject`, `--san`).
pub fn parse_subject(dn: &str, sans: &str) -> Result<SubjectSpec, String> {
    let mut rdns = vec![];
    for part in dn.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("subject: '{part}' is not ATTRIBUTE=value"))?;
        rdns.push((k.trim().to_string(), v.trim().to_string()));
    }
    let mut out = vec![];
    for s in sans
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let (k, v) = s
            .split_once(':')
            .ok_or_else(|| format!("SAN '{s}': use dns:, ip:, email: or uri:"))?;
        let kind = k.trim().to_ascii_lowercase();
        if !matches!(kind.as_str(), "dns" | "ip" | "email" | "uri") {
            return Err(format!("SAN '{s}': use dns:, ip:, email: or uri:"));
        }
        out.push(GeneralName {
            kind,
            value: v.trim().to_string(),
        });
    }
    Ok(SubjectSpec { rdns, sans: out })
}

fn days(s: &str, c: &Catalog) -> Result<u32, String> {
    s.trim()
        .parse::<u32>()
        .ok()
        .filter(|d| *d > 0)
        .ok_or_else(|| c.ui("err_days"))
}

#[derive(Debug)]
pub struct RootForm {
    pub ca_dir: String,
    pub ca_id: String,
    pub subject: String,
    pub key_type: KeySpec,
    pub validity_days: String,
    pub key: KeyForm,
    /// Required for a key on a token (`--confirm-root`).
    pub confirm_root: bool,
}

impl Default for RootForm {
    fn default() -> Self {
        RootForm {
            ca_dir: String::new(),
            ca_id: String::new(),
            subject: String::new(),
            key_type: KeySpec::Rsa4096,
            validity_days: "7300".into(),
            key: KeyForm::default(),
            confirm_root: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ImportForm {
    pub ca_dir: String,
    pub ca_id: String,
    pub cert_file: String,
    pub key: KeyForm,
}

#[derive(Debug)]
pub struct IssueForm {
    pub profile: IssueProfile,
    pub subject: String,
    pub sans: String,
    /// Sign a CSR instead of generating a key.
    pub use_csr: bool,
    pub csr_file: String,
    pub key_type: KeySpec,
    pub validity_days: String,
    pub key: KeyForm,
    /// The CA key's password or PIN.
    pub ca_secret: MaskedField,
    /// Examiner: password of the .p12.
    pub p12_password: MaskedField,
    pub p12_again: MaskedField,
}

impl Default for IssueForm {
    fn default() -> Self {
        IssueForm {
            profile: IssueProfile::Examiner,
            subject: String::new(),
            sans: String::new(),
            use_csr: false,
            csr_file: String::new(),
            key_type: KeySpec::Rsa3072,
            validity_days: "825".into(),
            key: KeyForm::default(),
            ca_secret: MaskedField::default(),
            p12_password: MaskedField::default(),
            p12_again: MaskedField::default(),
        }
    }
}

#[derive(Debug)]
pub struct RevokeForm {
    pub serial: String,
    pub reason: String,
    /// Empty = now.
    pub at: String,
}

impl Default for RevokeForm {
    fn default() -> Self {
        RevokeForm {
            serial: String::new(),
            reason: "unspecified".into(),
            at: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct CrlForm {
    pub ca_secret: MaskedField,
    pub next_update_days: String,
}

impl Default for CrlForm {
    fn default() -> Self {
        CrlForm {
            ca_secret: MaskedField::default(),
            next_update_days: "30".into(),
        }
    }
}

#[derive(Debug)]
pub struct CsrForm {
    pub subject: String,
    pub sans: String,
    pub key_type: KeySpec,
    pub key: KeyForm,
    pub csr_out: String,
}

impl Default for CsrForm {
    fn default() -> Self {
        CsrForm {
            subject: String::new(),
            sans: String::new(),
            key_type: KeySpec::Rsa3072,
            key: KeyForm::default(),
            csr_out: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct LabForm {
    pub set: String,
    pub seed: String,
    pub base_time: String,
    pub out_dir: String,
}

impl Default for LabForm {
    fn default() -> Self {
        LabForm {
            set: "full".into(),
            seed: "1".into(),
            base_time: "2026-01-01T00:00:00Z".into(),
            out_dir: String::new(),
        }
    }
}

/// One issued certificate of the CA folder and its revocation status.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IssuedRow {
    pub serial: String,
    pub profile: String,
    pub subject: String,
    pub not_after: String,
    /// `keyCompromise at 2026-…` when revoked.
    pub revoked: Option<String>,
    pub cert_file: Option<PathBuf>,
}

/// The opened CA folder (`pki show`): `pki::open` verified issued.jsonl, so `verified` holds its record count.
#[derive(Clone, Debug, PartialEq)]
pub struct CaView {
    pub dir: PathBuf,
    pub folder: CaFolder,
    pub records: usize,
    pub issued: Vec<IssuedRow>,
}

/// Reads a CA folder exactly as `pki show` does (pki::open verifies the issued.jsonl chain and the files).
pub fn ca_view(dir: &Path) -> Result<CaView, String> {
    let folder = certs::pki::open(dir).map_err(|e| e.message)?;
    let records = issued_records(dir);
    let revoked: std::collections::BTreeMap<String, String> = records
        .iter()
        .filter(|x| x.action == "revoked")
        .filter_map(|x| {
            Some((
                x.serial_hex.clone()?,
                format!(
                    "{} at {}",
                    x.reason.clone().unwrap_or_default(),
                    x.revoked_at.clone().unwrap_or_default()
                ),
            ))
        })
        .collect();
    let issued = records
        .iter()
        .filter(|x| x.action == "issued")
        .map(|x| {
            let serial = x.serial_hex.clone().unwrap_or_default();
            IssuedRow {
                profile: x.profile.map(|p| p.name().to_string()).unwrap_or_default(),
                subject: x.subject.clone().unwrap_or_default(),
                not_after: x.not_after.clone().unwrap_or_default(),
                revoked: revoked.get(&serial).cloned(),
                cert_file: x.file.as_deref().map(|f| resolve(dir, f)),
                serial,
            }
        })
        .collect();
    Ok(CaView {
        dir: dir.to_path_buf(),
        folder,
        records: records.len(),
        issued,
    })
}

/// Profiles of the Issue dropdown: (profile, enabled, i18n key of the reason when disabled).
pub fn profile_choices() -> Vec<(IssueProfile, bool, Option<&'static str>)> {
    IssueProfile::ALL
        .into_iter()
        .map(|p| {
            (
                p,
                p.enabled(),
                (!p.enabled()).then_some("profile_client_internal_reason"),
            )
        })
        .collect()
}

#[derive(Debug, Default)]
pub struct CreateState {
    /// The CA folder being typed or picked.
    pub ca_entry: String,
    pub ca: Option<CaView>,
    /// `pki show` / `pki verify` failure for the folder in `ca_entry`.
    pub ca_error: Option<String>,
    /// Last `pki verify` result: Ok(records) or the reason.
    pub verify: Option<Result<usize, String>>,
    /// Folder of the runs (audit logs and reports): `<out>/logs/<RUN-ID>`, `<out>/reports/<RUN-ID>`.
    pub out_dir: String,
    pub wizard: Option<Wizard>,
    pub root: RootForm,
    pub import: ImportForm,
    pub issue: IssueForm,
    pub revoke: RevokeForm,
    pub crl: CrlForm,
    pub csr: CsrForm,
    pub lab: LabForm,
    /// PKCS#11 module for `tokens list` (shared by every token key form).
    pub token_module: String,
    pub tokens: Vec<TokenInfo>,
    /// The last operation's outcome.
    pub last: Option<CreationOutcome>,
    /// Folder that holds the last operation's files (Open folder).
    pub last_folder: Option<PathBuf>,
    pub busy: bool,
}

/// One operation ready to run, secrets inside the request (dropped, and so zeroized, after `execute`).
#[derive(Debug)]
pub enum OpKind {
    Show(PathBuf),
    Verify(PathBuf),
    TokensList(PathBuf),
    InitRoot(InitRootRequest),
    Import(ImportCaRequest, PathBuf),
    Issue(IssueRequest),
    Revoke(RevokeRequest),
    Crl(CrlRequest),
    Csr(CsrRequest),
    Lab(LabSetSpec),
    TrustImport {
        list: TrustListKind,
        file: PathBuf,
        store: PathBuf,
    },
}

#[derive(Debug)]
pub struct PreparedOp {
    pub kind: OpKind,
    pub command: &'static str,
    pub params: Value,
    pub out: PathBuf,
    pub actor: String,
    /// The ui_* actions recorded since the last run.
    pub preamble: Vec<(String, Value)>,
}

#[derive(Clone, Debug, Default)]
pub struct OpResult {
    pub outcome: CreationOutcome,
    /// CA folder to show after the operation.
    pub ca: Option<PathBuf>,
    pub ca_view: Option<Result<CaView, String>>,
    pub verify: Option<Result<usize, String>>,
    pub tokens: Option<Vec<TokenInfo>>,
    /// Folder of the files produced (Open folder).
    pub folder: Option<PathBuf>,
    /// After an intermediate was issued: its certificate and key file, to pre-fill Import.
    pub next_import: Option<(PathBuf, Option<PathBuf>)>,
}

fn not_started(command: &str, e: std::io::Error) -> CreationOutcome {
    CreationOutcome {
        command: command.into(),
        ok: false,
        exit_code: 1,
        error: Some(format!("cannot write the run: {e}")),
        ..Default::default()
    }
}

fn key_text(k: &KeyLocation) -> String {
    match k {
        KeyLocation::EncryptedFile { path, format } => format!("{path} ({format})"),
        KeyLocation::Pkcs11 {
            token_serial,
            key_id_hex,
            key_label,
            ..
        } => format!(
            "token {token_serial}, key id {key_id_hex}{}",
            key_label
                .as_deref()
                .map(|l| format!(" ({l})"))
                .unwrap_or_default()
        ),
    }
}

fn ca_summary(head: &str, f: &CaFolder, ca: &Path) -> Vec<String> {
    vec![
        head.to_string(),
        format!("  subject:     {}", f.subject),
        format!("  serial:      {}", f.serial_hex),
        format!("  valid:       {} .. {}", f.not_before, f.not_after),
        format!("  key:         {}", key_text(&f.key)),
        format!("  certificate: {}", ca.join(&f.certificate_file).display()),
        format!("  sha256:      {}", f.certificate_sha256),
    ]
}

/// Runs one operation as an audited run (same records as the CLI command). Blocking: the GUI calls it on a
/// worker thread; tests call it directly.
pub fn execute(op: PreparedOp) -> OpResult {
    let PreparedOp {
        kind,
        command,
        params,
        out,
        actor,
        preamble,
    } = op;
    let cmdline = vec![
        format!("{TOOL_NAME}-gui"),
        format!("{command} (gui)"),
        format!("out={}", out.display()),
    ];
    let mut r = match CreationRun::start(&out, &actor, "gui", command, params, &preamble, &cmdline)
    {
        Ok(r) => r,
        Err(e) => {
            return OpResult {
                outcome: not_started(command, e),
                ..Default::default()
            };
        }
    };
    let mut res = OpResult::default();
    let fail = |r: CreationRun, e: &CertError| r.fail(e);
    res.outcome = match kind {
        OpKind::Show(ca) => match certs::pki::open(&ca) {
            Err(e) => {
                res.ca_view = Some(Err(e.message.clone()));
                fail(r, &e)
            }
            Ok(f) => {
                let records = issued_records(&ca);
                r.record(
                    "ca_folder_read",
                    Some(&f.ca_id),
                    json!({"records": records.len(), "head": records.last().map(|x| x.entry_hash.clone())}),
                );
                let view = ca_view(&ca);
                let mut s = ca_summary(
                    &format!(
                        "CA {} ({:?}), issued.jsonl verified ({} records).",
                        f.ca_id,
                        f.kind,
                        records.len()
                    ),
                    &f,
                    &ca,
                );
                if let Ok(v) = &view {
                    s.push(format!("Issued certificates: {}", v.issued.len()));
                }
                let result = json!({"ca": f, "records": records.len()});
                res.ca_view = Some(view);
                res.ca = Some(ca.clone());
                res.folder = Some(ca);
                r.finish(result, s, &internal_notice(), 0)
            }
        },
        OpKind::Verify(ca) => match certs::pki::open(&ca) {
            Err(e) => {
                r.record(
                    "ca_folder_verification_failed",
                    None,
                    json!({"error": e.message}),
                );
                res.verify = Some(Err(e.message.clone()));
                if e.kind == certs::ErrorKind::Policy {
                    r.finish(
                        json!({"verified": false, "error": e.message}),
                        vec![format!("FAILED: {}", e.message)],
                        &internal_notice(),
                        3,
                    )
                } else {
                    fail(r, &e)
                }
            }
            Ok(f) => {
                let n = issued_records(&ca).len();
                r.record("ca_folder_verified", Some(&f.ca_id), json!({"records": n}));
                res.verify = Some(Ok(n));
                r.finish(
                    json!({"verified": true, "records": n, "ca_id": f.ca_id}),
                    vec![format!(
                        "OK: CA {} — issued.jsonl chain intact ({n} records), certs/ca.crt and every recorded file match.",
                        f.ca_id
                    )],
                    &internal_notice(),
                    0,
                )
            }
        },
        OpKind::TokensList(module) => match certs::tokens::list(&module) {
            Err(e) => fail(r, &e),
            Ok(list) => {
                r.record("tokens_listed", None, json!({"slots": list.len(),
                    "tokens": list.iter().filter(|t| t.token_present).map(|t| json!({"serial": t.serial, "label": t.label, "keys": t.keys.len()})).collect::<Vec<_>>()}));
                let mut s = vec![format!("{} slot(s) in {}", list.len(), module.display())];
                for t in &list {
                    s.push(format!(
                        "  slot {}: {}{}",
                        t.slot_id,
                        t.slot_description,
                        if t.token_present {
                            format!(
                                "  token '{}' serial {}",
                                t.label.clone().unwrap_or_default(),
                                t.serial.clone().unwrap_or_default()
                            )
                        } else {
                            "  (no token)".into()
                        }
                    ));
                }
                let v = serde_json::to_value(&list).unwrap_or_default();
                res.tokens = Some(list);
                r.finish(v, s, "", 0)
            }
        },
        OpKind::InitRoot(mut req) => {
            req.actor = r.actor();
            let ca = req.ca_dir.clone();
            match certs::pki::init_root(&req) {
                Err(e) => fail(r, &e),
                Ok(f) => {
                    r.record("ca_created", Some(&f.ca_id), json!({"subject": f.subject, "serial": f.serial_hex,
                        "not_after": f.not_after, "cert_sha256": f.certificate_sha256, "key": f.key}));
                    for rec in issued_records(&ca) {
                        r.issued(&ca, &rec);
                    }
                    r.file("ca certificate", &ca.join(&f.certificate_file));
                    r.file("ca.json", &ca.join("ca.json"));
                    if let KeyLocation::EncryptedFile { path, .. } = &f.key {
                        r.file("encrypted CA key", &resolve(&ca, path));
                    }
                    let s = ca_summary("Root CA created.", &f, &ca);
                    res.ca = Some(ca.clone());
                    res.folder = Some(ca);
                    r.finish(
                        serde_json::to_value(&f).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        0,
                    )
                }
            }
        }
        OpKind::Import(mut req, cert) => {
            req.actor = r.actor();
            let ca = req.ca_dir.clone();
            let _ = cert;
            match certs::pki::import_ca(&req) {
                Err(e) => fail(r, &e),
                Ok(f) => {
                    r.record(
                        "ca_imported",
                        Some(&f.ca_id),
                        json!({"subject": f.subject, "serial": f.serial_hex, "kind": f.kind,
                               "cert_sha256": f.certificate_sha256, "key": f.key, "allowed_profiles": f.allowed_profiles}),
                    );
                    for rec in issued_records(&ca) {
                        r.issued(&ca, &rec);
                    }
                    r.file("ca certificate", &ca.join(&f.certificate_file));
                    r.file("ca.json", &ca.join("ca.json"));
                    let mut s = ca_summary("CA imported.", &f, &ca);
                    s.push(format!(
                        "  profiles:    {}",
                        f.allowed_profiles
                            .iter()
                            .map(|p| p.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    res.ca = Some(ca.clone());
                    res.folder = Some(ca);
                    r.finish(
                        serde_json::to_value(&f).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        0,
                    )
                }
            }
        }
        OpKind::Issue(mut req) => {
            req.actor = r.actor();
            let ca = req.ca_dir.clone();
            let profile = req.profile;
            match certs::pki::issue(&req) {
                Err(e) => fail(r, &e),
                Ok(out) => {
                    let rec = &out.record;
                    r.record("certificate_issued", rec.serial_hex.as_deref(), json!({"profile": rec.profile,
                        "subject": rec.subject, "not_before": rec.not_before, "not_after": rec.not_after,
                        "cert_sha256": rec.cert_sha256, "key": out.key}));
                    r.issued(&ca, rec);
                    r.file("certificate", &out.cert_path);
                    let mut key_file = None;
                    if let Some(KeyLocation::EncryptedFile { path, .. }) = &out.key {
                        let p = resolve(&ca, path);
                        r.file("encrypted subject key", &p);
                        key_file = Some(p);
                    }
                    if let Some(p) = &out.p12_path {
                        r.file("examiner PKCS#12", p);
                    }
                    let mut s = vec![
                        format!("Certificate issued ({}).", profile.name()),
                        format!("  subject:     {}", rec.subject.clone().unwrap_or_default()),
                        format!(
                            "  serial:      {}",
                            rec.serial_hex.clone().unwrap_or_default()
                        ),
                        format!(
                            "  valid:       {} .. {}",
                            rec.not_before.clone().unwrap_or_default(),
                            rec.not_after.clone().unwrap_or_default()
                        ),
                        format!("  certificate: {}", out.cert_path.display()),
                    ];
                    if let Some(k) = &out.key {
                        s.push(format!("  key:         {}", key_text(k)));
                    }
                    if let Some(p) = &out.p12_path {
                        s.push(format!(
                            "  pkcs12:      {} (rv-hashinv --sign-cert)",
                            p.display()
                        ));
                    }
                    if profile == IssueProfile::Intermediate {
                        res.next_import = Some((out.cert_path.clone(), key_file));
                    }
                    res.folder = out.cert_path.parent().map(Path::to_path_buf);
                    res.ca = Some(ca);
                    r.finish(
                        serde_json::to_value(&out).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        0,
                    )
                }
            }
        }
        OpKind::Revoke(mut req) => {
            req.actor = r.actor();
            let ca = req.ca_dir.clone();
            match certs::pki::revoke(&req) {
                Err(e) => fail(r, &e),
                Ok(rec) => {
                    r.record("certificate_revoked", rec.serial_hex.as_deref(), json!({"reason": rec.reason,
                        "revoked_at": rec.revoked_at, "subject": rec.subject, "cert_sha256": rec.cert_sha256}));
                    r.issued(&ca, &rec);
                    let s = vec![
                        "Certificate revoked (publish it with a new CRL).".to_string(),
                        format!(
                            "  serial:      {}",
                            rec.serial_hex.clone().unwrap_or_default()
                        ),
                        format!("  subject:     {}", rec.subject.clone().unwrap_or_default()),
                        format!("  reason:      {}", rec.reason.clone().unwrap_or_default()),
                    ];
                    res.ca = Some(ca.clone());
                    res.folder = Some(ca);
                    r.finish(
                        serde_json::to_value(&rec).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        0,
                    )
                }
            }
        }
        OpKind::Crl(mut req) => {
            req.actor = r.actor();
            let ca = req.ca_dir.clone();
            match certs::pki::make_crl(&req) {
                Err(e) => fail(r, &e),
                Ok(out) => {
                    r.record("crl_signed", Some(&out.path.display().to_string()), json!({"crl_number": out.crl_number,
                        "sha256": out.sha256, "this_update": out.record.not_before, "next_update": out.record.not_after}));
                    r.issued(&ca, &out.record);
                    r.file("CRL", &out.path);
                    r.file("CRL (latest)", &ca.join("crl").join("latest.crl"));
                    let revoked = issued_records(&ca)
                        .iter()
                        .filter(|x| x.action == "revoked")
                        .count();
                    let s = vec![
                        format!("CRL {} signed ({revoked} revoked).", out.crl_number),
                        format!("  file:        {}", out.path.display()),
                        format!("  sha256:      {}", out.sha256),
                    ];
                    res.ca = Some(ca);
                    res.folder = out.path.parent().map(Path::to_path_buf);
                    r.finish(
                        serde_json::to_value(&out).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        0,
                    )
                }
            }
        }
        OpKind::Csr(req) => match certs::csr::new(&req) {
            Err(e) => fail(r, &e),
            Ok(out) => {
                r.record("csr_created", Some(&out.csr_path.display().to_string()), json!({"subject": out.csr.subject,
                    "sha256": out.csr.sha256, "key": out.key, "key_spki_sha256": out.csr.key.spki_sha256}));
                r.file("CSR", &out.csr_path);
                if let KeyLocation::EncryptedFile { path, .. } = &out.key {
                    r.file("encrypted key", Path::new(path));
                }
                let s = vec![
                    "CSR created (send the .csr to the CA; keep the key).".to_string(),
                    format!("  subject:     {}", out.csr.subject),
                    format!("  file:        {}", out.csr_path.display()),
                    format!("  key:         {}", key_text(&out.key)),
                ];
                res.folder = out.csr_path.parent().map(Path::to_path_buf);
                r.finish(serde_json::to_value(&out).unwrap_or_default(), s,
                    "A CSR only asks; the CA that signs it decides what the certificate is (a public, qualified or Rakvor CA).", 0)
            }
        },
        OpKind::Lab(spec) => {
            let dir = spec.out_dir.clone();
            match certs::lab::make(&spec) {
                Err(e) => fail(r, &e),
                Ok(m) => {
                    r.record("lab_set_written", Some(&dir.display().to_string()), json!({"set": m.set,
                        "seed": m.seed, "base_time": m.base_time, "cases": m.cases.len(), "files": m.files}));
                    r.file(
                        "expected_findings.json",
                        &dir.join("expected_findings.json"),
                    );
                    let mut s = vec![format!(
                        "Lab set '{}' (seed {}, base time {}) written: {} cases, {} files.",
                        m.set,
                        m.seed,
                        m.base_time,
                        m.cases.len(),
                        m.files.len()
                    )];
                    for c in &m.cases {
                        s.push(format!(
                            "  {:<26} openssl verify {:>2}  expects {}",
                            c.id,
                            c.openssl_verify_code,
                            c.expected_codes.join(", ")
                        ));
                    }
                    res.folder = Some(dir);
                    r.finish(
                        serde_json::to_value(&m).unwrap_or_default(),
                        s,
                        LAB_NOTICE,
                        0,
                    )
                }
            }
        }
        OpKind::TrustImport { list, file, store } => {
            let data = match std::fs::read(&file) {
                Ok(d) => d,
                Err(e) => {
                    return OpResult {
                        outcome: r.fail(&CertError::new(
                            certs::ErrorKind::Io,
                            format!("cannot read {}: {e}", file.display()),
                        )),
                        ..Default::default()
                    };
                }
            };
            r.record(
                "trust_list_source_read",
                Some(&file.display().to_string()),
                json!({"sha256": hash_bytes(&data, HashAlgo::Sha256), "bytes": data.len()}),
            );
            let source = format!("file:{}", file.display());
            let now = rv_certcheck_core::time::utc_now();
            let got = match list {
                TrustListKind::Eu => certs::trust_list::import_eu(&data, &source, &now, &store),
                TrustListKind::Co => certs::trust_list::import_co_csv(&data, &source, &now, &store),
            };
            match got {
                Err(e) => fail(r, &e),
                Ok(snap) => {
                    r.record("trust_list_imported", Some(&snap.id), json!({"list": snap.list, "sha256": snap.sha256,
                        "services": snap.services.len(), "entries": snap.entries.len(), "signature_verified": snap.signature_verified}));
                    let path = store.join(&snap.list).join(format!("{}.json", snap.id));
                    r.file("trust-list snapshot", &path);
                    let s = vec![
                        format!(
                            "Snapshot {} ({} services, {} certificates).",
                            snap.id,
                            snap.services.len(),
                            snap.entries.len()
                        ),
                        format!("  source:      {}", snap.source),
                        format!("  sha256:      {}", snap.sha256),
                    ];
                    res.folder = path.parent().map(Path::to_path_buf);
                    r.finish(
                        json!({"id": snap.id, "list": snap.list, "sha256": snap.sha256}),
                        s,
                        "The trust list's own XAdES signature is not verified in v0.1.",
                        0,
                    )
                }
            }
        }
    };
    res
}

impl CreateState {
    fn op(
        &self,
        log: &mut UiLog,
        actor: &str,
        kind: OpKind,
        command: &'static str,
        params: Value,
    ) -> PreparedOp {
        log.note(
            "ui_operation_started",
            json!({"command": command, "parameters": params}),
        );
        PreparedOp {
            kind,
            command,
            params,
            out: PathBuf::from(clean(&self.out_dir)),
            actor: actor.to_string(),
            preamble: log.drain(),
        }
    }

    fn ca_dir(&self, c: &Catalog) -> Result<PathBuf, String> {
        let d = clean(&self.ca_entry);
        if d.is_empty() {
            return Err(c.ui("err_ca_folder"));
        }
        Ok(PathBuf::from(d))
    }

    fn check_out(&self, c: &Catalog) -> Result<(), String> {
        if clean(&self.out_dir).is_empty() {
            return Err(c.ui("err_out_dir"));
        }
        Ok(())
    }

    /// `pki show` on the folder in `ca_entry`.
    pub fn open_ca(
        &mut self,
        log: &mut UiLog,
        actor: &str,
        c: &Catalog,
    ) -> Result<PreparedOp, String> {
        let ca = self.ca_dir(c)?;
        self.check_out(c)?;
        self.wipe_all();
        log.note(
            "ui_ca_folder_opened",
            json!({"path": ca.display().to_string()}),
        );
        let params = json!({"ca": ca.display().to_string()});
        Ok(self.op(log, actor, OpKind::Show(ca), "pki show", params))
    }

    /// `pki verify` on the opened (or typed) CA folder.
    pub fn verify_ca(
        &mut self,
        log: &mut UiLog,
        actor: &str,
        c: &Catalog,
    ) -> Result<PreparedOp, String> {
        let ca = self.ca_dir(c)?;
        self.check_out(c)?;
        let params = json!({"ca": ca.display().to_string()});
        Ok(self.op(log, actor, OpKind::Verify(ca), "pki verify", params))
    }

    /// `tokens list` with the module in `token_module` (no login, no PIN).
    pub fn list_tokens(
        &mut self,
        log: &mut UiLog,
        actor: &str,
        c: &Catalog,
    ) -> Result<PreparedOp, String> {
        let m = clean(&self.token_module);
        if m.is_empty() {
            return Err(c.ui("err_module"));
        }
        self.check_out(c)?;
        let params =
            json!({"pkcs11_module": m, "token_serial": Value::Null, "pin_from_env": Value::Null});
        Ok(self.op(
            log,
            actor,
            OpKind::TokensList(PathBuf::from(&m)),
            "tokens list",
            params,
        ))
    }

    pub fn set_wizard(&mut self, log: &mut UiLog, w: Option<Wizard>) {
        if self.wizard != w {
            // Secrets typed for another wizard never outlive it.
            self.wipe_all();
            self.wizard = w;
            log.note("ui_wizard_opened", json!({"wizard": w.map(|w| w.name())}));
        }
    }

    /// Selects an Issue profile; a disabled profile (client-internal) is refused with its reason.
    pub fn set_profile(
        &mut self,
        log: &mut UiLog,
        p: IssueProfile,
        c: &Catalog,
    ) -> Result<(), String> {
        if !p.enabled() {
            return Err(c.ui("profile_client_internal_reason"));
        }
        if self.issue.profile != p {
            self.issue.profile = p;
            if p == IssueProfile::Examiner {
                // The examiner .p12 carries a new file key.
                self.issue.key.mode = KeyMode::File;
                self.issue.use_csr = false;
            }
            log.note("ui_profile_changed", json!({"profile": p.name()}));
        }
        Ok(())
    }

    pub fn set_key_mode(&mut self, log: &mut UiLog, w: Wizard, m: KeyMode) {
        let form = match w {
            Wizard::NewRoot => &mut self.root.key,
            Wizard::Import => &mut self.import.key,
            Wizard::Issue => &mut self.issue.key,
            Wizard::Csr => &mut self.csr.key,
            _ => return,
        };
        if form.mode != m {
            form.wipe();
            form.mode = m;
            if form.module.trim().is_empty() {
                form.module = self.token_module.clone();
            }
            log.note(
                "ui_key_mode_changed",
                json!({"wizard": w.name(), "mode": m.name()}),
            );
        }
    }

    pub fn set_confirm_root(&mut self, log: &mut UiLog, on: bool) {
        if self.root.confirm_root != on {
            self.root.confirm_root = on;
            log.note("ui_confirm_root_changed", json!({"confirm_root": on}));
        }
    }

    /// Picks a token from `tokens list` for the key form of `w`.
    pub fn use_token(&mut self, log: &mut UiLog, w: Wizard, serial: &str) {
        let module = self.token_module.clone();
        let form = match w {
            Wizard::NewRoot => &mut self.root.key,
            Wizard::Import => &mut self.import.key,
            Wizard::Issue => &mut self.issue.key,
            Wizard::Csr => &mut self.csr.key,
            _ => return,
        };
        form.mode = KeyMode::Token;
        form.module = module.clone();
        form.token_serial = serial.to_string();
        log.note(
            "ui_token_selected",
            json!({"wizard": w.name(), "pkcs11_module": module, "token_serial": serial}),
        );
    }

    /// Validates the open wizard and turns it into an operation. Nothing is taken from a masked field unless the
    /// whole form is valid; once taken, every masked field of the Create tab is empty.
    pub fn prepare(
        &mut self,
        log: &mut UiLog,
        actor: &str,
        c: &Catalog,
    ) -> Result<PreparedOp, String> {
        let w = self.wizard.ok_or_else(|| c.ui("err_no_wizard"))?;
        self.check_out(c)?;
        // Checked in each arm after the form itself, so the form's own errors come first.
        let no_ca = w.needs_ca() && self.ca.is_none();
        let need_ca = || {
            if no_ca {
                Err(c.ui("err_open_ca_first"))
            } else {
                Ok(())
            }
        };
        let ca_dir = self.ca.as_ref().map(|v| v.dir.clone()).unwrap_or_default();
        let op = match w {
            Wizard::NewRoot => {
                let f = &mut self.root;
                let dir = clean(&f.ca_dir);
                let id = clean(&f.ca_id);
                if dir.is_empty() || id.is_empty() {
                    return Err(c.ui("err_ca_dir_id"));
                }
                let subject = parse_subject(&f.subject, "")?;
                if subject.rdns.is_empty() {
                    return Err(c.ui("err_subject"));
                }
                let validity_days = days(&f.validity_days, c)?;
                if f.key.mode == KeyMode::Token && !f.confirm_root {
                    return Err(c.ui("err_confirm_root"));
                }
                f.key.check_new(c)?;
                let dir = PathBuf::from(dir);
                let params = json!({"ca": dir.display().to_string(), "ca_id": id, "subject": subject,
                    "key_type": f.key_type, "key": f.key.describe(), "validity_days": validity_days,
                    "confirm_root": f.confirm_root});
                let key_target = f
                    .key
                    .take_target(dir.join("keys").join(format!("{id}.key.p8")), &id);
                let req = InitRootRequest {
                    ca_dir: dir,
                    ca_id: id,
                    subject,
                    key_spec: f.key_type,
                    key_target,
                    validity_days,
                    confirm_root: f.confirm_root,
                    actor: actor.into(),
                };
                (OpKind::InitRoot(req), "pki init-root", params)
            }
            Wizard::Import => {
                let f = &mut self.import;
                let dir = clean(&f.ca_dir);
                let id = clean(&f.ca_id);
                if dir.is_empty() || id.is_empty() {
                    return Err(c.ui("err_ca_dir_id"));
                }
                let cert = PathBuf::from(clean(&f.cert_file));
                let certificate = std::fs::read(&cert)
                    .map_err(|e| format!("{}: {} ({e})", c.ui("err_cert_file"), cert.display()))?;
                let location = f.key.location(c)?;
                let params = json!({"ca": dir, "ca_id": id, "cert": cert.display().to_string(),
                    "cert_sha256": hash_bytes(&certificate, HashAlgo::Sha256), "key": f.key.describe()});
                let unlock = KeyUnlock {
                    secret: f.key.take_unlock(),
                };
                let req = ImportCaRequest {
                    ca_dir: PathBuf::from(dir),
                    ca_id: id,
                    certificate,
                    key: location,
                    unlock,
                    actor: actor.into(),
                };
                (OpKind::Import(req, cert), "pki import", params)
            }
            Wizard::Issue => {
                let f = &mut self.issue;
                if !f.profile.enabled() {
                    return Err(c.ui("profile_client_internal_reason"));
                }
                let subject = parse_subject(&f.subject, &f.sans)?;
                let use_csr = f.use_csr && f.profile != IssueProfile::Examiner;
                if !use_csr && subject.rdns.is_empty() {
                    return Err(c.ui("err_subject"));
                }
                if f.profile == IssueProfile::TlsServer
                    && !subject
                        .sans
                        .iter()
                        .any(|g| g.kind == "dns" || g.kind == "ip")
                    && !use_csr
                {
                    return Err(c.ui("err_tls_san"));
                }
                let validity_days = days(&f.validity_days, c)?;
                let csr_der =
                    if use_csr {
                        let p = PathBuf::from(clean(&f.csr_file));
                        Some(std::fs::read(&p).map_err(|e| {
                            format!("{}: {} ({e})", c.ui("err_csr_file"), p.display())
                        })?)
                    } else {
                        None
                    };
                if f.ca_secret.is_empty() {
                    return Err(c.ui("err_ca_secret"));
                }
                if f.profile == IssueProfile::Examiner {
                    if f.key.mode != KeyMode::File {
                        return Err(c.ui("err_examiner_file_key"));
                    }
                    if f.p12_password.is_empty() {
                        return Err(c.ui("err_p12_password"));
                    }
                    if !f.p12_password.same_as(&f.p12_again) {
                        return Err(c.ui("err_passwords_differ"));
                    }
                }
                if !use_csr {
                    f.key.check_new(c)?;
                }
                need_ca()?;
                let params = json!({"ca": ca_dir.display().to_string(), "profile": f.profile, "subject": subject,
                    "csr": use_csr.then(|| clean(&f.csr_file)),
                    "csr_sha256": csr_der.as_ref().map(|b| hash_bytes(b, HashAlgo::Sha256)),
                    "key_type": (!use_csr).then_some(f.key_type), "key": f.key.describe(),
                    "ca_secret": SECRET_NOT_RECORDED,
                    "p12_password": (f.profile == IssueProfile::Examiner).then_some(SECRET_NOT_RECORDED),
                    "validity_days": validity_days});
                let stamp = rv_certcheck_core::time::utc_compact();
                let key_target = if use_csr {
                    f.key.wipe();
                    None
                } else {
                    Some(
                        f.key.take_target(
                            ca_dir
                                .join("subjects")
                                .join(format!("{}-{stamp}.key.p8", f.profile.name())),
                            f.profile.name(),
                        ),
                    )
                };
                let p12_password =
                    (f.profile == IssueProfile::Examiner).then(|| f.p12_password.take());
                let req = IssueRequest {
                    ca_dir: ca_dir.clone(),
                    ca_unlock: KeyUnlock {
                        secret: f.ca_secret.take(),
                    },
                    profile: f.profile,
                    subject,
                    csr_der,
                    key_spec: Some(f.key_type),
                    key_target,
                    p12_password,
                    validity_days,
                    actor: actor.into(),
                };
                (OpKind::Issue(req), "pki issue", params)
            }
            Wizard::Revoke => {
                let f = &self.revoke;
                let serial = clean(&f.serial).to_ascii_lowercase();
                if serial.is_empty() {
                    return Err(c.ui("err_serial"));
                }
                if !certs::REVOCATION_REASONS.contains(&f.reason.as_str()) {
                    return Err(c.ui("err_reason"));
                }
                let at = Some(clean(&f.at)).filter(|s| !s.is_empty());
                need_ca()?;
                let params = json!({"ca": ca_dir.display().to_string(), "serial": serial, "reason": f.reason, "at": at});
                let req = RevokeRequest {
                    ca_dir: ca_dir.clone(),
                    serial_hex: serial,
                    reason: f.reason.clone(),
                    revoked_at: at,
                    actor: actor.into(),
                };
                (OpKind::Revoke(req), "pki revoke", params)
            }
            Wizard::Crl => {
                let f = &mut self.crl;
                let next_update_days = days(&f.next_update_days, c)?;
                if f.ca_secret.is_empty() {
                    return Err(c.ui("err_ca_secret"));
                }
                need_ca()?;
                let params = json!({"ca": ca_dir.display().to_string(), "ca_secret": SECRET_NOT_RECORDED,
                    "next_update_days": next_update_days, "this_update": Value::Null});
                let req = CrlRequest {
                    ca_dir: ca_dir.clone(),
                    ca_unlock: KeyUnlock {
                        secret: f.ca_secret.take(),
                    },
                    this_update: None,
                    next_update_days,
                    actor: actor.into(),
                };
                (OpKind::Crl(req), "pki crl", params)
            }
            Wizard::Csr => {
                let f = &mut self.csr;
                let subject = parse_subject(&f.subject, &f.sans)?;
                if subject.rdns.is_empty() {
                    return Err(c.ui("err_subject"));
                }
                let out = clean(&f.csr_out);
                if out.is_empty() {
                    return Err(c.ui("err_csr_out"));
                }
                f.key.check_new(c)?;
                let out = PathBuf::from(out);
                let params = json!({"subject": subject, "key_type": f.key_type, "key": f.key.describe(),
                    "out": out.display().to_string()});
                let key_target = f.key.take_target(out.with_extension("key.p8"), "csr-key");
                let req = CsrRequest {
                    subject,
                    key_spec: f.key_type,
                    key_target,
                    out,
                };
                (OpKind::Csr(req), "csr new", params)
            }
            Wizard::Lab => {
                let f = &self.lab;
                if !matches!(f.set.as_str(), "full" | "minimal") {
                    return Err(c.ui("err_lab_set"));
                }
                let seed: u64 = f.seed.trim().parse().map_err(|_| c.ui("err_seed"))?;
                let out = clean(&f.out_dir);
                if out.is_empty() {
                    return Err(c.ui("err_lab_out"));
                }
                let params = json!({"set": f.set, "seed": seed, "base_time": f.base_time.trim(), "out": out});
                let spec = LabSetSpec {
                    name: f.set.clone(),
                    seed,
                    base_time: f.base_time.trim().to_string(),
                    out_dir: PathBuf::from(out),
                };
                (OpKind::Lab(spec), "lab make", params)
            }
        };
        self.wipe_all();
        let (kind, command, params) = op;
        log.note(
            "ui_wizard_submitted",
            json!({"wizard": w.name(), "command": command}),
        );
        Ok(self.op(log, actor, kind, command, params))
    }

    /// Applies an operation's result: outcome, CA folder view, verify result, tokens, Import pre-fill.
    pub fn finish(&mut self, r: OpResult) {
        self.busy = false;
        if let Some(v) = r.ca_view {
            match v {
                Ok(v) => {
                    self.ca_entry = v.dir.display().to_string();
                    self.ca = Some(v);
                    self.ca_error = None;
                }
                Err(e) => {
                    self.ca = None;
                    self.ca_error = Some(e);
                }
            }
        } else if let Some(dir) = &r.ca {
            match ca_view(dir) {
                Ok(v) => {
                    self.ca_entry = dir.display().to_string();
                    self.ca = Some(v);
                    self.ca_error = None;
                }
                Err(e) => self.ca_error = Some(e),
            }
        }
        if let Some(v) = r.verify {
            self.verify = Some(v);
        }
        if let Some(t) = r.tokens {
            self.tokens = t;
        }
        if let Some((cert, key)) = r.next_import {
            self.import.cert_file = cert.display().to_string();
            if let Some(k) = key {
                self.import.key.key_file = k.display().to_string();
            }
        }
        if r.outcome.ok {
            // Key and CSR files are never overwritten: a used name is cleared for the next certificate.
            match r.outcome.command.as_str() {
                "pki issue" => self.issue.key.key_file.clear(),
                "csr new" => {
                    self.csr.key.key_file.clear();
                    self.csr.csr_out.clear();
                }
                _ => {}
            }
        }
        self.last_folder = r.folder;
        self.last = Some(r.outcome);
    }

    /// Wipes every masked field of the tab.
    pub fn wipe_all(&mut self) {
        self.root.key.wipe();
        self.import.key.wipe();
        self.issue.key.wipe();
        self.issue.ca_secret.wipe();
        self.issue.p12_password.wipe();
        self.issue.p12_again.wipe();
        self.crl.ca_secret.wipe();
        self.csr.key.wipe();
    }

    pub fn secrets_empty(&self) -> bool {
        self.root.key.secrets_empty()
            && self.import.key.secrets_empty()
            && self.issue.key.secrets_empty()
            && self.issue.ca_secret.is_empty()
            && self.issue.p12_password.is_empty()
            && self.issue.p12_again.is_empty()
            && self.crl.ca_secret.is_empty()
            && self.csr.key.secrets_empty()
    }
}
