//! Creation and trust-list commands: pki, csr, lab, keys, tokens, trust-list.
//!
//! Every creation command (pki, csr, lab, keys, tokens) is an audited run, like `analyze`:
//! `<OUT>/logs/<RUN-ID>/audit.jsonl|audit.log|environment.json` and `<OUT>/reports/<RUN-ID>/report.json|.txt`.
//! The audit log records what was done (serials, subjects, SHA-256 of every file written, key *locations*, the
//! issued.jsonl entry each operation appended); never a password, PIN or key. Passwords and PINs are read from the
//! environment variable named by `--pass-env` / `--pin-env` / `--ca-pass-env`, or prompted without echo when the
//! variable is unset and stdin is a terminal. They are never accepted as command-line values.

use clap::{Args, Subcommand};
use rv_certcheck_core::audit::AuditLog;
use rv_certcheck_core::certs::{
    self, CertError, CrlRequest, CsrRequest, ErrorKind, GeneralName, ImportCaRequest,
    InitRootRequest, IssueProfile, IssueRequest, IssuedRecord, KeyLocation, KeySpec, KeyTarget,
    KeyUnlock, LabSetSpec, OcspSignRequest, RevokeRequest, Secret, SubjectSpec, TrustListKind,
};
use rv_certcheck_core::{HashAlgo, TOOL_NAME, TOOL_VERSION, hash::hash_bytes};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_REFUSED: u8 = 3;

pub const CREATION_EXIT_CODES: &str = "\
EXIT CODES:
  0  Done.
  1  Runtime error (file not readable, wrong password or PIN, token or crypto failure). Audited.
  2  Usage error (bad option value, empty subject, unknown profile or reason).
  3  Refused by a safety rule, or verification failed: root key on a token without --confirm-root,
     client-internal profile (needs the CP/CPS, rv-certcheck#2), a file that would be overwritten, a
     key that does not match its certificate, a CA folder whose issued.jsonl or files do not verify,
     a key that does not match (keys match). Nothing is issued. Audited.";

pub const CREATION_FILES: &str = "\
FILES WRITTEN (every command):
  <OUT>/logs/<RUN-ID>/audit.jsonl        Hash-chained log of the run (rv-certcheck verify-log checks it).
  <OUT>/logs/<RUN-ID>/audit.log          The same, human-readable.
  <OUT>/logs/<RUN-ID>/environment.json   Tool version, OS, host, user, command line.
  <OUT>/reports/<RUN-ID>/report.json|.txt  What was created or checked, with the SHA-256 of every file.";

pub const PKI_AFTER_HELP: &str = "\
DESCRIPTION:
  Rakvor's internal PKI. A CA folder (schema rakvor.ca/1) holds ca.json, the hash-chained issued.jsonl,
  certs/ (ca.crt and <serial>.crt), crl/ (<n>.crl, latest.crl), ocsp/ and keys/ (encrypted CA key,
  owner-only; a token key is only referenced). Every certificate carries a random 128-bit serial,
  AKI/SKI, the CRL URL of ca.json (crl_url) when set, and the Rakvor internal policy
  2.25.130074246409705057913773883974790544206.1.1 with its user notice.

  INTERNAL USE ONLY: these certificates are not a firma digital under Ley 527 de 1999 art. 28
  (Colombia) and not qualified certificates under eIDAS (EU 910/2014). Client certificates
  (profile client-internal) wait for Rakvor's CP/CPS reviewed by the lawyer (rv-certcheck#2).

EXAMPLES:
  Offline root on a YubiKey (key ceremony: docs/company-pki.md), then an intermediate in a file:
    rv-certcheck pki init-root --ca E:\\pki\\root --ca-id rakvor-root-2026 --subject \"C=CO,O=Rakvor,CN=Rakvor Root CA 2026\" \\
      --key-type p-384 --pkcs11-module \"C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll\" \\
      --token-serial 0012345678 --pin-env YUBIKEY_PIN --confirm-root
    rv-certcheck pki issue --ca E:\\pki\\root --ca-pass-env YUBIKEY_PIN --profile intermediate \\
      --subject \"C=CO,O=Rakvor,CN=Rakvor Issuing CA 2026\" --key-type p-384 --key-file E:\\pki\\issuing.key.p8
  Examiner certificate for signing reports (rv-hashinv --sign-cert):
    rv-certcheck pki issue --ca E:\\pki\\issuing --profile examiner --subject \"C=CO,O=Rakvor,CN=Ana Ruiz\" \\
      --san email:ana.ruiz@rakvor.co --key-type rsa-3072
  Revoke, then publish a CRL:
    rv-certcheck pki revoke --ca E:\\pki\\issuing --serial 5f3a09c1... --reason keyCompromise
    rv-certcheck pki crl --ca E:\\pki\\issuing
  Check a CA folder:
    rv-certcheck pki verify --ca E:\\pki\\issuing

SECURITY NOTES:
  - Encrypted keys: PKCS#8 PBES2, PBKDF2-HMAC-SHA256 600 000 iterations, AES-256-CBC; files 0600 on Unix,
    inside the user profile on Windows; never overwritten.
  - A root key on a token needs --confirm-root. Keep the root offline; issue from an intermediate.
  - issued.jsonl is verified before every operation: an edited, deleted or re-ordered record, or a
    modified certificate or CRL file, stops the CA (exit 3).";

/// Run output (shared by every creation command).
#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    /// Folder for the run's audit log and report: <OUT>/logs/<RUN-ID>/ and <OUT>/reports/<RUN-ID>/.
    /// Default: rakvor-out
    /// Example: --out D:\pki-runs
    #[arg(
        long,
        value_name = "DIR",
        default_value = "rakvor-out",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    out: PathBuf,
    /// Print the result as JSON on stdout instead of a summary.
    /// Default: off (human-readable summary)
    /// Example: --json
    #[arg(long, verbatim_doc_comment)]
    json: bool,
    /// Name written in the audit log and in issued.jsonl.
    /// Default: the operating-system user name
    /// Example: --actor "Ana Ruiz"
    #[arg(long, value_name = "NAME", verbatim_doc_comment)]
    actor: Option<String>,
}

/// Where a key is created or found: an encrypted file or a PKCS#11 token.
#[derive(Args, Clone, Debug)]
pub struct KeyArgs {
    /// Encrypted key file (PKCS#8, created owner-only, never overwritten).
    /// Default: see the command (init-root: <CA>/keys/<CA-ID>.key.p8; issue: <CA>/subjects/<PROFILE>-<TIME>.key.p8;
    /// csr new: <OUT-FILE>.key.p8)
    /// Example: --key-file E:\pki\ana-ruiz.key.p8
    #[arg(long, value_name = "FILE", verbatim_doc_comment)]
    key_file: Option<PathBuf>,
    /// Environment variable holding the key-file password (never logged; prompted without echo when unset).
    /// Default: RV_KEY_PASSWORD
    /// Example: --pass-env ROOT_KEY_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_KEY_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    pass_env: String,
    /// PKCS#11 module of the token (vendor library). With it the key lives on the token.
    /// Default: none (encrypted key file)
    /// Example: --pkcs11-module "C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"
    #[arg(long, value_name = "LIB", verbatim_doc_comment)]
    pkcs11_module: Option<PathBuf>,
    /// Serial number of the token to use (see `tokens list`).
    /// Default: none (required with --pkcs11-module)
    /// Example: --token-serial 0012345678
    #[arg(long, value_name = "SERIAL", verbatim_doc_comment)]
    token_serial: Option<String>,
    /// Label of a new key on the token.
    /// Default: the CA id, the profile or "csr-key"
    /// Example: --key-label rakvor-root-2026
    #[arg(long, value_name = "LABEL", verbatim_doc_comment)]
    key_label: Option<String>,
    /// CKA_ID (hex) of an existing key on the token (pki import).
    /// Default: none
    /// Example: --key-id 3f9a0c...
    #[arg(long, value_name = "HEX", verbatim_doc_comment)]
    key_id: Option<String>,
    /// Environment variable holding the token PIN (never logged; prompted without echo when unset).
    /// Default: RV_TOKEN_PIN
    /// Example: --pin-env YUBIKEY_PIN
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_TOKEN_PIN",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    pin_env: String,
}

/// A password or PIN from the environment variable `env`, else a no-echo prompt (twice for a new one) when stdin
/// is a terminal, else empty (the certificate layer then refuses with a clear message). Never from argv.
fn secret(env: &str, what: &str, new: bool) -> Result<Secret, String> {
    if let Ok(v) = std::env::var(env) {
        return Ok(Secret::new(v));
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Ok(Secret::default());
    }
    let first =
        rpassword::prompt_password(format!("{what} (environment variable {env} is not set): "))
            .map_err(|e| format!("cannot read the {what}: {e}"))?;
    let first = Secret::new(first);
    if new {
        let again = Secret::new(
            rpassword::prompt_password(format!("{what} again: "))
                .map_err(|e| format!("cannot read the {what}: {e}"))?,
        );
        if again.expose() != first.expose() {
            return Err(format!("the two {what} entries differ"));
        }
    }
    Ok(first)
}

impl KeyArgs {
    fn secret(&self, new: bool) -> Result<Secret, String> {
        if self.pkcs11_module.is_some() {
            secret(&self.pin_env, "Token PIN", false)
        } else {
            secret(&self.pass_env, "Key password", new)
        }
    }

    fn target(&self, default_file: PathBuf, default_label: &str) -> Result<KeyTarget, String> {
        match &self.pkcs11_module {
            Some(m) => Ok(KeyTarget::Pkcs11 {
                module: m.clone(),
                token_serial: self
                    .token_serial
                    .clone()
                    .ok_or("--token-serial is required with --pkcs11-module")?,
                pin: self.secret(false)?,
                key_label: self
                    .key_label
                    .clone()
                    .unwrap_or_else(|| default_label.into()),
            }),
            None => Ok(KeyTarget::EncryptedFile {
                path: self.key_file.clone().unwrap_or(default_file),
                password: self.secret(true)?,
            }),
        }
    }

    fn location(&self) -> Result<KeyLocation, String> {
        match &self.pkcs11_module {
            Some(m) => Ok(KeyLocation::Pkcs11 {
                module: m.display().to_string(),
                token_serial: self
                    .token_serial
                    .clone()
                    .ok_or("--token-serial is required with --pkcs11-module")?,
                token_label: None,
                key_id_hex: self
                    .key_id
                    .clone()
                    .ok_or("--key-id is required for an existing token key")?,
                key_label: self.key_label.clone(),
            }),
            None => Ok(KeyLocation::EncryptedFile {
                path: self
                    .key_file
                    .clone()
                    .ok_or("--key-file is required")?
                    .display()
                    .to_string(),
                format: "pkcs8-encrypted".into(),
            }),
        }
    }

    /// For the audit log: where the key goes, never the secret.
    fn describe(&self) -> Value {
        json!({
            "key_file": self.key_file.as_ref().map(|p| p.display().to_string()),
            "pkcs11_module": self.pkcs11_module.as_ref().map(|p| p.display().to_string()),
            "token_serial": self.token_serial,
            "key_label": self.key_label,
            "key_id": self.key_id,
            "secret_from_env": if self.pkcs11_module.is_some() { &self.pin_env } else { &self.pass_env },
        })
    }
}

/// Subject and SANs of a new certificate or CSR.
#[derive(Args, Clone, Debug)]
pub struct SubjectArgs {
    /// Subject as comma-separated attributes in order (C, ST, L, O, OU, CN, emailAddress, serialNumber, ...).
    /// Default: none (required, except when issuing from a CSR, whose subject is then used)
    /// Example: --subject "C=CO,O=Rakvor,CN=Ana Ruiz"
    #[arg(long, value_name = "DN", verbatim_doc_comment)]
    subject: Option<String>,
    /// Subject alternative name, repeatable: dns:NAME, ip:ADDRESS, email:ADDRESS, uri:URI.
    /// Default: none (tls-server needs at least one dns: or ip:)
    /// Example: --san dns:hub.rakvor.local --san email:ana.ruiz@rakvor.co
    #[arg(long = "san", value_name = "TYPE:VALUE", verbatim_doc_comment)]
    sans: Vec<String>,
}

impl SubjectArgs {
    fn spec(&self) -> Result<SubjectSpec, String> {
        let mut rdns = vec![];
        if let Some(s) = &self.subject {
            for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (k, v) = part
                    .split_once('=')
                    .ok_or_else(|| format!("--subject: '{part}' is not ATTRIBUTE=value"))?;
                rdns.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let mut sans = vec![];
        for s in &self.sans {
            let (k, v) = s
                .split_once(':')
                .ok_or_else(|| format!("--san '{s}': use dns:, ip:, email: or uri:"))?;
            let kind = k.trim().to_ascii_lowercase();
            if !matches!(kind.as_str(), "dns" | "ip" | "email" | "uri") {
                return Err(format!("--san '{s}': use dns:, ip:, email: or uri:"));
            }
            sans.push(GeneralName {
                kind,
                value: v.trim().to_string(),
            });
        }
        Ok(SubjectSpec { rdns, sans })
    }
}

fn parse_key_spec(s: &str) -> Result<KeySpec, String> {
    KeySpec::parse(s).map_err(|e| e.message)
}

fn parse_profile(s: &str) -> Result<IssueProfile, String> {
    IssueProfile::parse(s).map_err(|e| e.message)
}

// ------------------------------------------------------------------------------------------------------------
// The audited run of a creation command
// ------------------------------------------------------------------------------------------------------------

struct CreationRun {
    log: AuditLog,
    run_id: String,
    log_dir: PathBuf,
    report_dir: PathBuf,
    command: String,
    json: bool,
    files: Vec<Value>,
}

fn run_id() -> String {
    let seed = format!(
        "{:?}-{}-{}",
        std::time::SystemTime::now(),
        std::process::id(),
        rv_certcheck_core::env::hostname()
    );
    format!(
        "{}-{}",
        rv_certcheck_core::time::utc_compact(),
        &hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..6]
    )
}

fn sha256_file(p: &Path) -> Option<String> {
    std::fs::read(p)
        .ok()
        .map(|b| hash_bytes(&b, HashAlgo::Sha256))
}

impl CreationRun {
    fn start(r: &RunArgs, command: &str, params: Value) -> Result<CreationRun, u8> {
        let id = run_id();
        let log_dir = r.out.join("logs").join(&id);
        let report_dir = r.out.join("reports").join(&id);
        let actor = r
            .actor
            .clone()
            .unwrap_or_else(rv_certcheck_core::env::os_user);
        let fail = |e: std::io::Error| {
            eprintln!("error: cannot write the run under {}: {e}", r.out.display());
            EXIT_ERROR
        };
        let mut log = AuditLog::create(&log_dir, &id, &actor).map_err(fail)?;
        log.record(
            "run_started",
            None,
            json!({"tool": TOOL_NAME, "version": TOOL_VERSION, "frontend": "cli", "command": command,
                   "parameters": params, "openssl": certs::openssl_version()}),
        )
        .map_err(fail)?;
        let env = rv_certcheck_core::env::describe(
            TOOL_NAME,
            TOOL_VERSION,
            "cli",
            &std::env::args().collect::<Vec<_>>(),
        );
        let env_bytes = serde_json::to_vec_pretty(&env).unwrap_or_default();
        std::fs::write(log_dir.join("environment.json"), &env_bytes).map_err(fail)?;
        log.record(
            "environment_recorded",
            Some("environment.json"),
            json!({"sha256": hash_bytes(&env_bytes, HashAlgo::Sha256)}),
        )
        .map_err(fail)?;
        Ok(CreationRun {
            log,
            run_id: id,
            log_dir,
            report_dir,
            command: command.into(),
            json: r.json,
            files: vec![],
        })
    }

    fn actor(&self) -> String {
        // The actor of the run is the one recorded in audit.jsonl.
        let t = std::fs::read_to_string(self.log_dir.join("audit.jsonl")).unwrap_or_default();
        t.lines()
            .next()
            .and_then(|l| serde_json::from_str::<Value>(l).ok())
            .and_then(|v| v["actor"].as_str().map(String::from))
            .unwrap_or_else(rv_certcheck_core::env::os_user)
    }

    fn record(&mut self, action: &str, item: Option<&str>, details: Value) {
        if let Err(e) = self.log.record(action, item, details) {
            eprintln!("warning: audit log: {e}");
        }
    }

    /// Records a file the operation wrote (path and SHA-256).
    fn file(&mut self, role: &str, p: &Path) {
        if let Some(h) = sha256_file(p) {
            let v = json!({"role": role, "path": p.display().to_string(), "sha256": h});
            self.record("file_written", Some(&p.display().to_string()), v.clone());
            self.files.push(v);
        }
    }

    /// Records the issued.jsonl record an operation appended (links the two hash chains).
    fn issued(&mut self, ca: &Path, rec: &IssuedRecord) {
        self.record(
            "ca_log_appended",
            Some(&ca.join("issued.jsonl").display().to_string()),
            json!({"ca_id": rec.ca_id, "seq": rec.seq, "action": rec.action, "entry_hash": rec.entry_hash,
                   "serial": rec.serial_hex, "cert_sha256": rec.cert_sha256}),
        );
    }

    fn fail(mut self, e: &CertError) -> u8 {
        let code = match e.kind {
            ErrorKind::InvalidInput => EXIT_USAGE,
            ErrorKind::Policy => EXIT_REFUSED,
            _ => EXIT_ERROR,
        };
        self.record(
            "operation_failed",
            None,
            json!({"kind": e.kind, "error": e.message}),
        );
        self.record(
            "run_finished",
            None,
            json!({"status": "error", "exit_code": code}),
        );
        eprintln!("error: {}", e.message);
        eprintln!("  logs: {}", self.log_dir.display());
        code
    }

    /// Writes report.json / report.txt, closes the log and prints the summary (or the JSON result).
    fn finish(mut self, result: Value, summary: Vec<String>, notice: &str, code: u8) -> u8 {
        let report = json!({
            "schema": "rakvor.certcheck-creation-report/1",
            "tool": TOOL_NAME, "version": TOOL_VERSION, "run_id": self.run_id, "command": self.command,
            "result": result, "files": self.files, "notice": notice,
        });
        let mut text = format!(
            "RV CertCheck {TOOL_VERSION}: {cmd}\nRun {id}\n\n{body}\n\nFiles:\n{files}\n\n{notice}\n",
            cmd = self.command,
            id = self.run_id,
            body = summary.join("\n"),
            files = if self.files.is_empty() {
                "  (none)".into()
            } else {
                self.files
                    .iter()
                    .map(|f| {
                        format!(
                            "  {}  {}  ({})",
                            f["sha256"].as_str().unwrap_or(""),
                            f["path"].as_str().unwrap_or(""),
                            f["role"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            },
        );
        text.push_str(&format!(
            "\nAudit log: {}\n",
            self.log_dir.join("audit.jsonl").display()
        ));
        let _ = std::fs::create_dir_all(&self.report_dir);
        for (name, bytes) in [
            (
                "report.json",
                serde_json::to_vec_pretty(&report).unwrap_or_default(),
            ),
            ("report.txt", text.clone().into_bytes()),
        ] {
            let p = self.report_dir.join(name);
            if std::fs::write(&p, &bytes).is_ok() {
                self.record(
                    "report_written",
                    Some(name),
                    json!({"sha256": hash_bytes(&bytes, HashAlgo::Sha256)}),
                );
            }
        }
        self.record(
            "run_finished",
            None,
            json!({"status": if code == EXIT_OK { "ok" } else { "findings" }, "exit_code": code}),
        );
        let mut out = std::io::stdout().lock();
        if self.json {
            let _ = writeln!(
                out,
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        } else {
            for l in &summary {
                let _ = writeln!(out, "{l}");
            }
            let _ = writeln!(
                out,
                "  report: {}",
                self.report_dir.join("report.txt").display()
            );
            let _ = writeln!(out, "  logs:   {}", self.log_dir.display());
        }
        code
    }
}

fn usage(msg: &str) -> u8 {
    eprintln!("error: {msg}");
    EXIT_USAGE
}

fn read(p: &PathBuf) -> Result<Vec<u8>, u8> {
    std::fs::read(p).map_err(|e| {
        eprintln!("error: cannot read {}: {}", p.display(), e);
        EXIT_ERROR
    })
}

fn done<T: serde::Serialize>(r: certs::CertResult<T>) -> u8 {
    match r {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
    }
}

fn internal_notice() -> String {
    format!(
        "{} Client certificates (profile client-internal) wait for Rakvor's CP/CPS (rv-certcheck#2).",
        certs::RAKVOR_INTERNAL_NOTICE
    )
}

const LAB_NOTICE: &str = "Lab material: every key, salt and serial of a lab set derives from its seed and is public. Never use a lab certificate or key for anything real.";

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

fn ca_summary(head: &str, f: &certs::CaFolder, ca: &Path) -> Vec<String> {
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

// ------------------------------------------------------------------------------------------------------------
// pki
// ------------------------------------------------------------------------------------------------------------

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
pub enum PkiCommand {
    /// Create an offline root CA (key on a token with --confirm-root, else in an encrypted file).
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  <CA>/ca.json, <CA>/issued.jsonl, <CA>/certs/ca.crt, <CA>/keys/<CA-ID>.key.p8 (file key)"))]
    InitRoot {
        /// CA folder to create (must be empty or missing).
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\root-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Short id of the CA, used in file names and audit entries (letters, digits, - _ .).
        /// Default: none (required)
        /// Example: --ca-id rakvor-root-2026
        #[arg(long, value_name = "ID", verbatim_doc_comment)]
        ca_id: String,
        #[command(flatten)]
        subject: SubjectArgs,
        /// Key type: rsa-2048, rsa-3072, rsa-4096, p-256, p-384, ed25519.
        /// Default: rsa-4096
        /// Example: --key-type p-384
        #[arg(long, value_name = "TYPE", default_value = "rsa-4096", value_parser = parse_key_spec, verbatim_doc_comment, hide_default_value = true)]
        key_type: KeySpec,
        #[command(flatten)]
        key: KeyArgs,
        /// Validity in days.
        /// Default: 7300 (20 years)
        /// Example: --validity-days 3650
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 7300,
            verbatim_doc_comment,
            hide_default_value = true
        )]
        validity_days: u32,
        /// Required to create a root key on a token (a lost or exposed root key puts every Rakvor
        /// signature in doubt: follow the key ceremony in docs/company-pki.md).
        /// Default: off (a token root is refused)
        /// Example: --confirm-root
        #[arg(long, verbatim_doc_comment)]
        confirm_root: bool,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Bring an existing CA certificate and its key under management (e.g. the code-signing root).
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  <CA>/ca.json, <CA>/issued.jsonl, <CA>/certs/ca.crt (the key stays where it is)"))]
    Import {
        /// CA folder to create (must be empty or missing).
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\code-signing-root
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Short id of the CA.
        /// Default: none (required)
        /// Example: --ca-id rakvor-code-signing-root
        #[arg(long, value_name = "ID", verbatim_doc_comment)]
        ca_id: String,
        /// The CA certificate (PEM or DER).
        /// Default: none (required)
        /// Example: --cert packaging/signing/rakvor-code-signing-root.cer
        #[arg(long, value_name = "FILE", verbatim_doc_comment)]
        cert: PathBuf,
        /// The CA key: --key-file (encrypted PKCS#8 or PKCS#12/.pfx, kept where it is) or --pkcs11-module,
        /// --token-serial and --key-id.
        #[command(flatten)]
        key: KeyArgs,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Issue a certificate with a profile: intermediate, code-signing, examiner, tsa, tls-server
    /// (client-internal is disabled until the CP/CPS exists).
    #[command(after_long_help = format!("PROFILES:
  intermediate  CA:TRUE pathlen 0, keyCertSign + cRLSign (manage it with `pki import` as its own CA folder).
  code-signing  digitalSignature, EKU codeSigning (Rakvor release signing).
  examiner      digitalSignature + nonRepudiation, EKU emailProtection + documentSigning (RFC 9336 and
                Microsoft); also writes <serial>.p12 next to the key for rv-hashinv --sign-cert (RSA keys).
  tsa           digitalSignature, EKU timeStamping (critical).
  tls-server    digitalSignature (+keyEncipherment for RSA), EKU serverAuth, at least one dns:/ip: SAN.

{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  <CA>/certs/<SERIAL>.crt, the new key (encrypted), <SERIAL>.p12 (examiner), a record in <CA>/issued.jsonl"))]
    Issue {
        /// CA folder that signs.
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\issuing-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Profile: intermediate, code-signing, examiner, tsa, tls-server.
        /// Default: none (required)
        /// Example: --profile examiner
        #[arg(long, value_name = "PROFILE", value_parser = parse_profile, verbatim_doc_comment)]
        profile: IssueProfile,
        #[command(flatten)]
        subject: SubjectArgs,
        /// Certify the key of this CSR (PEM or DER; its self-signature must verify) instead of making a key.
        /// Default: none (a new key is generated)
        /// Example: --csr requests/hub.csr
        #[arg(long, value_name = "FILE", verbatim_doc_comment)]
        csr: Option<PathBuf>,
        /// Key type of the new key (ignored with --csr).
        /// Default: rsa-3072
        /// Example: --key-type p-256
        #[arg(long, value_name = "TYPE", default_value = "rsa-3072", value_parser = parse_key_spec, verbatim_doc_comment, hide_default_value = true)]
        key_type: KeySpec,
        /// Where the NEW subject key goes (file or token). The CA key is unlocked with --ca-pass-env.
        #[command(flatten)]
        key: KeyArgs,
        /// Environment variable with the CA key password (file key) or the CA token PIN.
        /// Default: RV_CA_PASSWORD
        /// Example: --ca-pass-env ROOT_KEY_PASS
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_CA_PASSWORD",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        ca_pass_env: String,
        /// Examiner profile: environment variable with the password of the .p12 written.
        /// Default: RV_P12_PASSWORD
        /// Example: --p12-pass-env ANA_P12_PASS
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_P12_PASSWORD",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        p12_pass_env: String,
        /// Validity in days (capped at the CA certificate's notAfter).
        /// Default: 825
        /// Example: --validity-days 365
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 825,
            verbatim_doc_comment,
            hide_default_value = true
        )]
        validity_days: u32,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Revoke an issued certificate (takes effect in the next CRL / OCSP response).
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  a `revoked` record in <CA>/issued.jsonl"))]
    Revoke {
        /// CA folder that issued the certificate.
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\issuing-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Serial number in hex (as `pki show` prints it; case and colons ignored).
        /// Default: none (required)
        /// Example: --serial 5f3a09c1d2e4...
        #[arg(long, value_name = "HEX", verbatim_doc_comment)]
        serial: String,
        /// RFC 5280 reason: unspecified, keyCompromise, cACompromise, affiliationChanged, superseded,
        /// cessationOfOperation, certificateHold, privilegeWithdrawn, aACompromise.
        /// Default: unspecified
        /// Example: --reason keyCompromise
        #[arg(
            long,
            value_name = "REASON",
            default_value = "unspecified",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        reason: String,
        /// Revocation time (RFC 3339 or YYYY-MM-DD).
        /// Default: now
        /// Example: --at 2026-11-02T09:00:00Z
        #[arg(long, value_name = "TIME", verbatim_doc_comment)]
        at: Option<String>,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Sign a CRL with every revoked serial.
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  <CA>/crl/<NUMBER>.crl and <CA>/crl/latest.crl (DER), a record in <CA>/issued.jsonl"))]
    Crl {
        /// CA folder.
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\issuing-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Environment variable with the CA key password or the CA token PIN.
        /// Default: RV_CA_PASSWORD
        /// Example: --ca-pass-env ISSUING_KEY_PASS
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_CA_PASSWORD",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        ca_pass_env: String,
        /// Days until nextUpdate.
        /// Default: 30
        /// Example: --next-update-days 7
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 30,
            verbatim_doc_comment,
            hide_default_value = true
        )]
        next_update_days: u32,
        /// thisUpdate (RFC 3339).
        /// Default: now
        /// Example: --this-update 2026-11-01T00:00:00Z
        #[arg(long, value_name = "TIME", verbatim_doc_comment)]
        this_update: Option<String>,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Sign an OCSP response for a serial at a given time (lab use; there is no OCSP server).
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  --out (DER) and a copy in <CA>/ocsp/, a record in <CA>/issued.jsonl"))]
    OcspSign {
        /// CA folder.
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\issuing-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Serial number in hex.
        /// Default: none (required)
        /// Example: --serial 5f3a09c1d2e4...
        #[arg(long, value_name = "HEX", verbatim_doc_comment)]
        serial: String,
        /// Output file (DER), never overwritten.
        /// Default: none (required)
        /// Example: --out leaf.ocsp
        #[arg(long = "ocsp-out", value_name = "FILE", verbatim_doc_comment)]
        ocsp_out: PathBuf,
        /// producedAt / thisUpdate (RFC 3339).
        /// Default: now
        /// Example: --produced-at 2026-11-01T00:00:00Z
        #[arg(long, value_name = "TIME", verbatim_doc_comment)]
        produced_at: Option<String>,
        /// Days until nextUpdate.
        /// Default: none (no nextUpdate)
        /// Example: --next-update-days 7
        #[arg(long, value_name = "DAYS", verbatim_doc_comment)]
        next_update_days: Option<u32>,
        /// Environment variable with the CA key password or the CA token PIN.
        /// Default: RV_CA_PASSWORD
        /// Example: --ca-pass-env ISSUING_KEY_PASS
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_CA_PASSWORD",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        ca_pass_env: String,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Show a CA folder: ca.json and every certificate issued, with its revocation state.
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}"))]
    Show {
        /// CA folder.
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\issuing-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Verify a CA folder: the issued.jsonl hash chain, certs/ca.crt and the SHA-256 of every recorded file.
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}"))]
    Verify {
        /// CA folder.
        /// Default: none (required)
        /// Example: --ca E:\rakvor-pki\issuing-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        #[command(flatten)]
        run: RunArgs,
    },
}

fn issued_records(ca: &Path) -> Vec<IssuedRecord> {
    std::fs::read_to_string(ca.join("issued.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

pub fn pki(c: PkiCommand) -> u8 {
    match c {
        PkiCommand::InitRoot {
            ca,
            ca_id,
            subject,
            key_type,
            key,
            validity_days,
            confirm_root,
            run,
        } => {
            let subject = match subject.spec() {
                Ok(s) => s,
                Err(e) => return usage(&e),
            };
            if subject.rdns.is_empty() {
                return usage(
                    "--subject is required, e.g. --subject \"C=CO,O=Rakvor,CN=Rakvor Root CA 2026\"",
                );
            }
            let params = json!({"ca": ca.display().to_string(), "ca_id": ca_id, "subject": subject,
                                "key_type": key_type, "key": key.describe(), "validity_days": validity_days,
                                "confirm_root": confirm_root});
            let target = if key.pkcs11_module.is_some() && !confirm_root {
                // Do not ask for a PIN that will not be used: init_root refuses first.
                KeyTarget::Pkcs11 {
                    module: key.pkcs11_module.clone().unwrap_or_default(),
                    token_serial: key.token_serial.clone().unwrap_or_default(),
                    pin: Secret::default(),
                    key_label: ca_id.clone(),
                }
            } else {
                match key.target(ca.join("keys").join(format!("{ca_id}.key.p8")), &ca_id) {
                    Ok(t) => t,
                    Err(e) => return usage(&e),
                }
            };
            let mut r = match CreationRun::start(&run, "pki init-root", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::init_root(&InitRootRequest {
                ca_dir: ca.clone(),
                ca_id,
                subject,
                key_spec: key_type,
                key_target: target,
                validity_days,
                confirm_root,
                actor: r.actor(),
            }) {
                Err(e) => r.fail(&e),
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
                    r.finish(
                        serde_json::to_value(&f).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
        PkiCommand::Import {
            ca,
            ca_id,
            cert,
            key,
            run,
        } => {
            let certificate = match read(&cert) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let location = match key.location() {
                Ok(l) => l,
                Err(e) => return usage(&e),
            };
            let unlock = match key.secret(false) {
                Ok(s) => KeyUnlock { secret: s },
                Err(e) => return usage(&e),
            };
            let params = json!({"ca": ca.display().to_string(), "ca_id": ca_id, "cert": cert.display().to_string(),
                                "cert_sha256": hash_bytes(&certificate, HashAlgo::Sha256), "key": key.describe()});
            let mut r = match CreationRun::start(&run, "pki import", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::import_ca(&ImportCaRequest {
                ca_dir: ca.clone(),
                ca_id,
                certificate,
                key: location,
                unlock,
                actor: r.actor(),
            }) {
                Err(e) => r.fail(&e),
                Ok(f) => {
                    r.record(
                        "ca_imported",
                        Some(&f.ca_id),
                        json!({"subject": f.subject, "serial": f.serial_hex,
                        "kind": f.kind, "cert_sha256": f.certificate_sha256, "key": f.key,
                        "allowed_profiles": f.allowed_profiles}),
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
                    r.finish(
                        serde_json::to_value(&f).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
        PkiCommand::Issue {
            ca,
            profile,
            subject,
            csr,
            key_type,
            key,
            ca_pass_env,
            p12_pass_env,
            validity_days,
            run,
        } => {
            let subject = match subject.spec() {
                Ok(s) => s,
                Err(e) => return usage(&e),
            };
            if csr.is_none() && subject.rdns.is_empty() {
                return usage("--subject is required (or --csr)");
            }
            let csr_der = match &csr {
                Some(p) => match read(p) {
                    Ok(b) => Some(b),
                    Err(c) => return c,
                },
                None => None,
            };
            // Refuse a disabled profile before asking for any password.
            let ca_unlock = if profile.enabled() {
                match secret(&ca_pass_env, "CA key password or PIN", false) {
                    Ok(s) => KeyUnlock { secret: s },
                    Err(e) => return usage(&e),
                }
            } else {
                KeyUnlock::default()
            };
            let key_target = if csr_der.is_some() || !profile.enabled() {
                None
            } else {
                let stamp = rv_certcheck_core::time::utc_compact();
                match key.target(
                    ca.join("subjects")
                        .join(format!("{}-{stamp}.key.p8", profile.name())),
                    profile.name(),
                ) {
                    Ok(t) => Some(t),
                    Err(e) => return usage(&e),
                }
            };
            let p12_password = if profile == IssueProfile::Examiner {
                match secret(&p12_pass_env, "Password of the .p12", true) {
                    Ok(s) => Some(s),
                    Err(e) => return usage(&e),
                }
            } else {
                None
            };
            let params = json!({"ca": ca.display().to_string(), "profile": profile, "subject": subject,
                "csr": csr.as_ref().map(|p| p.display().to_string()),
                "csr_sha256": csr_der.as_ref().map(|b| hash_bytes(b, HashAlgo::Sha256)),
                "key_type": (csr.is_none()).then_some(key_type), "key": key.describe(),
                "ca_secret_from_env": ca_pass_env, "p12_password_from_env": (profile == IssueProfile::Examiner).then_some(&p12_pass_env),
                "validity_days": validity_days});
            let mut r = match CreationRun::start(&run, "pki issue", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::issue(&IssueRequest {
                ca_dir: ca.clone(),
                ca_unlock,
                profile,
                subject,
                csr_der,
                key_spec: Some(key_type),
                key_target,
                p12_password,
                validity_days,
                actor: r.actor(),
            }) {
                Err(e) => r.fail(&e),
                Ok(res) => {
                    let rec = &res.record;
                    r.record("certificate_issued", rec.serial_hex.as_deref(), json!({"profile": rec.profile,
                        "subject": rec.subject, "not_before": rec.not_before, "not_after": rec.not_after,
                        "cert_sha256": rec.cert_sha256, "key": res.key}));
                    r.issued(&ca, rec);
                    r.file("certificate", &res.cert_path);
                    if let Some(KeyLocation::EncryptedFile { path, .. }) = &res.key {
                        r.file("encrypted subject key", &resolve(&ca, path));
                    }
                    if let Some(p) = &res.p12_path {
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
                        format!("  certificate: {}", res.cert_path.display()),
                        format!(
                            "  sha256:      {}",
                            rec.cert_sha256.clone().unwrap_or_default()
                        ),
                    ];
                    if let Some(k) = &res.key {
                        s.push(format!("  key:         {}", key_text(k)));
                    }
                    if let Some(p) = &res.p12_path {
                        s.push(format!(
                            "  pkcs12:      {} (rv-hashinv --sign-cert)",
                            p.display()
                        ));
                    }
                    r.finish(
                        serde_json::to_value(&res).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
        PkiCommand::Revoke {
            ca,
            serial,
            reason,
            at,
            run,
        } => {
            if !certs::REVOCATION_REASONS.contains(&reason.as_str()) {
                return usage(&format!(
                    "--reason '{reason}': use one of {}",
                    certs::REVOCATION_REASONS.join(", ")
                ));
            }
            let params = json!({"ca": ca.display().to_string(), "serial": serial, "reason": reason, "at": at});
            let mut r = match CreationRun::start(&run, "pki revoke", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::revoke(&RevokeRequest {
                ca_dir: ca.clone(),
                serial_hex: serial.to_ascii_lowercase(),
                reason,
                revoked_at: at,
                actor: r.actor(),
            }) {
                Err(e) => r.fail(&e),
                Ok(rec) => {
                    r.record("certificate_revoked", rec.serial_hex.as_deref(), json!({"reason": rec.reason,
                        "revoked_at": rec.revoked_at, "subject": rec.subject, "cert_sha256": rec.cert_sha256}));
                    r.issued(&ca, &rec);
                    let s = vec![
                        "Certificate revoked (publish it with `pki crl`).".to_string(),
                        format!(
                            "  serial:      {}",
                            rec.serial_hex.clone().unwrap_or_default()
                        ),
                        format!("  subject:     {}", rec.subject.clone().unwrap_or_default()),
                        format!("  reason:      {}", rec.reason.clone().unwrap_or_default()),
                        format!(
                            "  revoked at:  {}",
                            rec.revoked_at.clone().unwrap_or_default()
                        ),
                    ];
                    r.finish(
                        serde_json::to_value(&rec).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
        PkiCommand::Crl {
            ca,
            ca_pass_env,
            next_update_days,
            this_update,
            run,
        } => {
            let unlock = match secret(&ca_pass_env, "CA key password or PIN", false) {
                Ok(s) => KeyUnlock { secret: s },
                Err(e) => return usage(&e),
            };
            let params = json!({"ca": ca.display().to_string(), "ca_secret_from_env": ca_pass_env,
                                "next_update_days": next_update_days, "this_update": this_update});
            let mut r = match CreationRun::start(&run, "pki crl", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::make_crl(&CrlRequest {
                ca_dir: ca.clone(),
                ca_unlock: unlock,
                this_update,
                next_update_days,
                actor: r.actor(),
            }) {
                Err(e) => r.fail(&e),
                Ok(res) => {
                    r.record("crl_signed", Some(&res.path.display().to_string()), json!({"crl_number": res.crl_number,
                        "sha256": res.sha256, "this_update": res.record.not_before, "next_update": res.record.not_after}));
                    r.issued(&ca, &res.record);
                    r.file("CRL", &res.path);
                    r.file("CRL (latest)", &ca.join("crl").join("latest.crl"));
                    let revoked = issued_records(&ca)
                        .iter()
                        .filter(|x| x.action == "revoked")
                        .count();
                    let s = vec![
                        format!("CRL {} signed ({revoked} revoked).", res.crl_number),
                        format!(
                            "  this/next:   {} .. {}",
                            res.record.not_before.clone().unwrap_or_default(),
                            res.record.not_after.clone().unwrap_or_default()
                        ),
                        format!("  file:        {}", res.path.display()),
                        format!("  sha256:      {}", res.sha256),
                    ];
                    r.finish(
                        serde_json::to_value(&res).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
        PkiCommand::OcspSign {
            ca,
            serial,
            ocsp_out,
            produced_at,
            next_update_days,
            ca_pass_env,
            run,
        } => {
            let unlock = match secret(&ca_pass_env, "CA key password or PIN", false) {
                Ok(s) => KeyUnlock { secret: s },
                Err(e) => return usage(&e),
            };
            let params = json!({"ca": ca.display().to_string(), "serial": serial, "out": ocsp_out.display().to_string(),
                "produced_at": produced_at, "next_update_days": next_update_days, "ca_secret_from_env": ca_pass_env});
            let mut r = match CreationRun::start(&run, "pki ocsp-sign", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::sign_ocsp(&OcspSignRequest {
                ca_dir: ca.clone(),
                ca_unlock: unlock,
                serial_hex: serial.to_ascii_lowercase(),
                produced_at,
                next_update_days,
                out: ocsp_out,
                actor: r.actor(),
            }) {
                Err(e) => r.fail(&e),
                Ok(res) => {
                    let status = serde_json::to_value(&res.status).unwrap_or_default();
                    r.record(
                        "ocsp_signed",
                        res.record.serial_hex.as_deref(),
                        json!({"status": status["status"],
                        "sha256": res.sha256}),
                    );
                    r.issued(&ca, &res.record);
                    r.file("OCSP response", &res.path);
                    let s = vec![
                        format!(
                            "OCSP response signed: {}.",
                            status["status"].as_str().unwrap_or("?")
                        ),
                        format!(
                            "  serial:      {}",
                            res.record.serial_hex.clone().unwrap_or_default()
                        ),
                        format!("  file:        {}", res.path.display()),
                        format!("  sha256:      {}", res.sha256),
                    ];
                    r.finish(
                        serde_json::to_value(&res).unwrap_or_default(),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
        PkiCommand::Show { ca, run } => {
            let mut r =
                match CreationRun::start(&run, "pki show", json!({"ca": ca.display().to_string()}))
                {
                    Ok(r) => r,
                    Err(c) => return c,
                };
            match certs::pki::open(&ca) {
                Err(e) => r.fail(&e),
                Ok(f) => {
                    let records = issued_records(&ca);
                    r.record(
                        "ca_folder_read",
                        Some(&f.ca_id),
                        json!({"records": records.len(),
                        "head": records.last().map(|x| x.entry_hash.clone())}),
                    );
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
                    s.push(format!(
                        "  profiles:    {}",
                        f.allowed_profiles
                            .iter()
                            .map(|p| p.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    s.push(format!("  next CRL:    {}", f.next_crl_number));
                    let revoked: std::collections::BTreeMap<String, String> = records
                        .iter()
                        .filter(|x| x.action == "revoked")
                        .filter_map(|x| {
                            Some((x.serial_hex.clone()?, x.reason.clone().unwrap_or_default()))
                        })
                        .collect();
                    let issued: Vec<Value> = records
                        .iter()
                        .filter(|x| x.action == "issued")
                        .map(|x| {
                            let serial = x.serial_hex.clone().unwrap_or_default();
                            json!({"serial": serial, "profile": x.profile, "subject": x.subject,
                                   "not_after": x.not_after, "revoked": revoked.get(&serial)})
                        })
                        .collect();
                    s.push(format!("Issued certificates: {}", issued.len()));
                    for i in &issued {
                        s.push(format!(
                            "  {}  {:<13} {}  until {}{}",
                            i["serial"].as_str().unwrap_or(""),
                            i["profile"].as_str().unwrap_or(""),
                            i["subject"].as_str().unwrap_or(""),
                            i["not_after"].as_str().unwrap_or(""),
                            i["revoked"]
                                .as_str()
                                .map(|r| format!("  REVOKED ({r})"))
                                .unwrap_or_default()
                        ));
                    }
                    let result = json!({"ca": f, "issued": issued, "records": records.len()});
                    r.finish(result, s, &internal_notice(), EXIT_OK)
                }
            }
        }
        PkiCommand::Verify { ca, run } => {
            let mut r = match CreationRun::start(
                &run,
                "pki verify",
                json!({"ca": ca.display().to_string()}),
            ) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::pki::open(&ca) {
                Err(e) => {
                    let code = if e.kind == ErrorKind::Policy {
                        EXIT_REFUSED
                    } else {
                        EXIT_ERROR
                    };
                    r.record(
                        "ca_folder_verification_failed",
                        None,
                        json!({"error": e.message}),
                    );
                    if code == EXIT_REFUSED {
                        let s = vec![format!("FAILED: {}", e.message)];
                        eprintln!("error: {}", e.message);
                        r.finish(
                            json!({"verified": false, "error": e.message}),
                            s,
                            &internal_notice(),
                            code,
                        )
                    } else {
                        r.fail(&e)
                    }
                }
                Ok(f) => {
                    let n = issued_records(&ca).len();
                    r.record("ca_folder_verified", Some(&f.ca_id), json!({"records": n}));
                    let s = vec![format!(
                        "OK: CA {} — issued.jsonl chain intact ({n} records), certs/ca.crt and every recorded file match.",
                        f.ca_id
                    )];
                    r.finish(
                        json!({"verified": true, "records": n, "ca_id": f.ca_id}),
                        s,
                        &internal_notice(),
                        EXIT_OK,
                    )
                }
            }
        }
    }
}

fn resolve(ca: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        ca.join(path)
    }
}

// ------------------------------------------------------------------------------------------------------------
// csr, lab, keys, tokens
// ------------------------------------------------------------------------------------------------------------

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
pub enum CsrCommand {
    /// Create a key (token or encrypted file) and a CSR for a public or qualified CA.
    #[command(after_long_help = format!("EXAMPLES:
  rv-certcheck csr new --subject \"C=CO,O=Rakvor SAS,CN=www.rakvor.co\" --san dns:www.rakvor.co --key-type p-256 --csr-out www.csr
  Key on a YubiKey (qualified CAs often require it):
    rv-certcheck csr new --subject \"C=CO,CN=Ana Ruiz,serialNumber=CC79123456\" --csr-out ana.csr \\
      --pkcs11-module libykcs11.so --token-serial 0012345678 --pin-env YUBIKEY_PIN

{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  --out (PEM CSR) and the encrypted key (default <OUT-FILE>.key.p8)"))]
    New {
        #[command(flatten)]
        subject: SubjectArgs,
        /// Key type: rsa-2048, rsa-3072, rsa-4096, p-256, p-384, ed25519.
        /// Default: rsa-3072
        /// Example: --key-type p-256
        #[arg(long, value_name = "TYPE", default_value = "rsa-3072", value_parser = parse_key_spec, verbatim_doc_comment, hide_default_value = true)]
        key_type: KeySpec,
        #[command(flatten)]
        key: KeyArgs,
        /// CSR file to write (PEM), never overwritten.
        /// Default: none (required)
        /// Example: --csr-out ana-ruiz.csr
        #[arg(long = "csr-out", value_name = "FILE", verbatim_doc_comment)]
        csr_out: PathBuf,
        #[command(flatten)]
        run: RunArgs,
    },
    /// Display a CSR and check its self-signature.
    #[command(after_long_help = format!("{CREATION_EXIT_CODES}\n\n{CREATION_FILES}"))]
    Show {
        /// The CSR (PEM or DER).
        /// Default: none (required)
        /// Example: requests/ana-ruiz.csr
        #[arg(value_name = "FILE", verbatim_doc_comment)]
        file: PathBuf,
        #[command(flatten)]
        run: RunArgs,
    },
}

fn csr_lines(c: &certs::CsrInfo) -> Vec<String> {
    let mut s = vec![
        format!("  subject:     {}", c.subject),
        format!(
            "  key:         {} {}{}",
            c.key.algorithm,
            c.key.bits.map(|b| b.to_string()).unwrap_or_default(),
            c.key
                .curve
                .as_deref()
                .map(|x| format!(" {x}"))
                .unwrap_or_default()
        ),
        format!(
            "  signature:   {} ({})",
            c.signature_algorithm,
            if c.signature_valid {
                "verifies"
            } else {
                "DOES NOT VERIFY"
            }
        ),
        format!("  sha256:      {}", c.sha256),
    ];
    for g in &c.sans {
        s.push(format!("  san:         {}:{}", g.kind, g.value));
    }
    s
}

pub fn csr(c: CsrCommand) -> u8 {
    match c {
        CsrCommand::New {
            subject,
            key_type,
            key,
            csr_out,
            run,
        } => {
            let default_key = csr_out.with_extension("key.p8");
            let subject = match subject.spec() {
                Ok(s) if !s.rdns.is_empty() => s,
                Ok(_) => return usage("--subject is required"),
                Err(e) => return usage(&e),
            };
            let target = match key.target(default_key, "csr-key") {
                Ok(t) => t,
                Err(e) => return usage(&e),
            };
            let params = json!({"subject": subject, "key_type": key_type, "key": key.describe(),
                                "out": csr_out.display().to_string()});
            let mut r = match CreationRun::start(&run, "csr new", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::csr::new(&CsrRequest {
                subject,
                key_spec: key_type,
                key_target: target,
                out: csr_out,
            }) {
                Err(e) => r.fail(&e),
                Ok(res) => {
                    r.record("csr_created", Some(&res.csr_path.display().to_string()), json!({"subject": res.csr.subject,
                        "sha256": res.csr.sha256, "key": res.key, "key_spki_sha256": res.csr.key.spki_sha256}));
                    r.file("CSR", &res.csr_path);
                    if let KeyLocation::EncryptedFile { path, .. } = &res.key {
                        r.file("encrypted key", Path::new(path));
                    }
                    let mut s =
                        vec!["CSR created (send the .csr to the CA; keep the key).".to_string()];
                    s.extend(csr_lines(&res.csr));
                    s.push(format!("  file:        {}", res.csr_path.display()));
                    s.push(format!("  key:         {}", key_text(&res.key)));
                    r.finish(serde_json::to_value(&res).unwrap_or_default(), s,
                        "A CSR only asks; the CA that signs it decides what the certificate is (a public, qualified or Rakvor CA).", EXIT_OK)
                }
            }
        }
        CsrCommand::Show { file, run } => {
            let data = match read(&file) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let params = json!({"file": file.display().to_string(), "sha256": hash_bytes(&data, HashAlgo::Sha256)});
            let mut r = match CreationRun::start(&run, "csr show", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::csr::show(&data) {
                Err(e) => r.fail(&e),
                Ok(info) => {
                    r.record(
                        "csr_read",
                        Some(&file.display().to_string()),
                        json!({"subject": info.subject,
                        "signature_valid": info.signature_valid, "sha256": info.sha256}),
                    );
                    let mut s = vec![format!("CSR {}", file.display())];
                    s.extend(csr_lines(&info));
                    let code = if info.signature_valid {
                        EXIT_OK
                    } else {
                        EXIT_REFUSED
                    };
                    r.finish(serde_json::to_value(&info).unwrap_or_default(), s, "", code)
                }
            }
        }
    }
}

#[derive(Subcommand)]
pub enum LabCommand {
    /// Write a reproducible lab set and its expected_findings.json.
    #[command(after_long_help = format!("CASES (full): valid-chain, expired, not-yet-valid, revoked-by-crl, revoked-by-ocsp, wrong-root,
  rsa-1024, sha1-signed, md5-signed, bad-eku, name-constraint-violation, broken-signature, key-mismatch.
  minimal: valid-chain, expired, revoked-by-crl, key-mismatch. Each case lists its expected and
  forbidden finding codes and the code `openssl verify` gives at the base time.

EXAMPLES:
  rv-certcheck lab make --set full --seed 1 --lab-out lab-full-1
  rv-certcheck lab make --set minimal --seed 7 --base-time 2027-06-01 --lab-out lab-min-7

{CREATION_EXIT_CODES}\n\n{CREATION_FILES}\n  --lab-out/ca/*, --lab-out/<case>/*, --lab-out/expected_findings.json\n\n{LAB_NOTICE}"))]
    Make {
        /// Set name: full or minimal.
        /// Default: full
        /// Example: --set minimal
        #[arg(
            long = "set",
            value_name = "NAME",
            default_value = "full",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        set: String,
        /// Seed (same seed, set and base time = byte-identical set).
        /// Default: 1
        /// Example: --seed 42
        #[arg(
            long,
            value_name = "N",
            default_value_t = 1,
            verbatim_doc_comment,
            hide_default_value = true
        )]
        seed: u64,
        /// Reference time every validity period derives from (never the wall clock).
        /// Default: 2026-01-01T00:00:00Z
        /// Example: --base-time 2027-06-01
        #[arg(
            long,
            value_name = "TIME",
            default_value = "2026-01-01T00:00:00Z",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        base_time: String,
        /// Folder for the set (empty or missing).
        /// Default: none (required)
        /// Example: --lab-out lab-full-1
        #[arg(long = "lab-out", value_name = "DIR", verbatim_doc_comment)]
        lab_out: PathBuf,
        #[command(flatten)]
        run: RunArgs,
    },
}

pub fn lab(c: LabCommand) -> u8 {
    match c {
        LabCommand::Make {
            set,
            seed,
            base_time,
            lab_out,
            run,
        } => {
            if !matches!(set.as_str(), "full" | "minimal") {
                return usage(&format!("--set '{set}': use full or minimal"));
            }
            let params = json!({"set": set, "seed": seed, "base_time": base_time, "out": lab_out.display().to_string()});
            let mut r = match CreationRun::start(&run, "lab make", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            match certs::lab::make(&LabSetSpec {
                name: set,
                seed,
                base_time,
                out_dir: lab_out.clone(),
            }) {
                Err(e) => r.fail(&e),
                Ok(m) => {
                    r.record("lab_set_written", Some(&lab_out.display().to_string()), json!({"set": m.set,
                        "seed": m.seed, "base_time": m.base_time, "cases": m.cases.len(), "files": m.files}));
                    r.file(
                        "expected_findings.json",
                        &lab_out.join("expected_findings.json"),
                    );
                    let mut s = vec![
                        format!(
                            "Lab set '{}' (seed {}, base time {}) written: {} cases, {} files.",
                            m.set,
                            m.seed,
                            m.base_time,
                            m.cases.len(),
                            m.files.len()
                        ),
                        format!("  folder:      {}", lab_out.display()),
                    ];
                    for c in &m.cases {
                        s.push(format!(
                            "  {:<26} openssl verify {:>2}  expects {}",
                            c.id,
                            c.openssl_verify_code,
                            c.expected_codes.join(", ")
                        ));
                    }
                    r.finish(
                        serde_json::to_value(&m).unwrap_or_default(),
                        s,
                        LAB_NOTICE,
                        EXIT_OK,
                    )
                }
            }
        }
    }
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Check whether a private key belongs to a certificate (the key never leaves memory).
    #[command(after_long_help = format!("EXIT CODES:
  0  The key belongs to the certificate.
  1  Runtime error (unreadable file, wrong password, not implemented in this build).
  3  The key does NOT belong to the certificate.

{CREATION_FILES}"))]
    Match {
        /// Private key (PEM/DER, PKCS#8/PKCS#1/SEC1) or PKCS#12.
        /// Default: none (required)
        /// Example: keys/ana-ruiz.key.p8
        #[arg(value_name = "KEY", verbatim_doc_comment)]
        key: PathBuf,
        /// Certificate (PEM or DER).
        /// Default: none (required)
        /// Example: certs/5f3a09c1.crt
        #[arg(value_name = "CERT", verbatim_doc_comment)]
        cert: PathBuf,
        /// Environment variable with the key or PKCS#12 password (prompted without echo when unset).
        /// Default: RV_KEY_PASSWORD
        /// Example: --pass-env ANA_KEY_PASS
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_KEY_PASSWORD",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        pass_env: String,
        #[command(flatten)]
        run: RunArgs,
    },
}

/// DER of the first CERTIFICATE block, or the bytes themselves when DER.
fn cert_der(data: &[u8]) -> Vec<u8> {
    if data.first() == Some(&0x30) {
        return data.to_vec();
    }
    pem::parse_many(data)
        .ok()
        .and_then(|v| v.into_iter().find(|p| p.tag() == "CERTIFICATE"))
        .map(|p| p.into_contents())
        .unwrap_or_else(|| data.to_vec())
}

pub fn keys(c: KeysCommand) -> u8 {
    match c {
        KeysCommand::Match {
            key,
            cert,
            pass_env,
            run,
        } => {
            let (k, c) = match (read(&key), read(&cert)) {
                (Ok(k), Ok(c)) => (zeroize::Zeroizing::new(k), c),
                (Err(e), _) | (_, Err(e)) => return e,
            };
            let text = String::from_utf8_lossy(&k);
            let needs_password = text.contains("ENCRYPTED")
                || k.first() == Some(&0x30) && !text.contains("PRIVATE KEY");
            let pw = if needs_password {
                match secret(&pass_env, "Key password", false) {
                    Ok(s) => Some(s),
                    Err(e) => return usage(&e),
                }
            } else {
                std::env::var(&pass_env).ok().map(Secret::new)
            };
            let params = json!({"key": key.display().to_string(), "cert": cert.display().to_string(),
                                "cert_sha256": hash_bytes(&c, HashAlgo::Sha256), "password_from_env": pass_env});
            let mut r = match CreationRun::start(&run, "keys match", params) {
                Ok(r) => r,
                Err(code) => return code,
            };
            match certs::match_key(&k, pw.as_ref(), &cert_der(&c)) {
                Err(e) => r.fail(&e),
                Ok(m) => {
                    r.record(
                        "key_matched",
                        Some(&key.display().to_string()),
                        json!({"matches": m.matches,
                        "key_spki_sha256": m.key.spki_sha256, "cert_sha256": m.cert_sha256}),
                    );
                    let s = vec![
                        if m.matches {
                            format!("MATCH: the key belongs to {}.", m.cert_subject)
                        } else {
                            format!("NO MATCH: the key does not belong to {}.", m.cert_subject)
                        },
                        format!(
                            "  key:         {} (SPKI SHA-256 {})",
                            m.key.algorithm, m.key.spki_sha256
                        ),
                        format!("  certificate: {}", m.cert_sha256),
                    ];
                    let code = if m.matches { EXIT_OK } else { EXIT_REFUSED };
                    r.finish(serde_json::to_value(&m).unwrap_or_default(), s, "", code)
                }
            }
        }
    }
}

#[derive(Subcommand)]
pub enum TokensCommand {
    /// List PKCS#11 slots and tokens; with --token-serial, log in and list that token's keys.
    #[command(after_long_help = format!("EXAMPLES:
  rv-certcheck tokens list --pkcs11-module \"C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll\"
  rv-certcheck tokens list --pkcs11-module /usr/lib/softhsm/libsofthsm2.so --token-serial 7e29d86a112d890d --pin-env SOFTHSM_PIN

{CREATION_EXIT_CODES}\n\n{CREATION_FILES}"))]
    List {
        /// PKCS#11 module (vendor library).
        /// Default: none (required)
        /// Example: --pkcs11-module /usr/lib/softhsm/libsofthsm2.so
        #[arg(long, value_name = "LIB", verbatim_doc_comment)]
        pkcs11_module: PathBuf,
        /// Log in to this token and list its keys (public facts only).
        /// Default: none (no login)
        /// Example: --token-serial 0012345678
        #[arg(long, value_name = "SERIAL", verbatim_doc_comment)]
        token_serial: Option<String>,
        /// Environment variable holding the token PIN (never logged; prompted without echo when unset).
        /// Default: RV_TOKEN_PIN
        /// Example: --pin-env YUBIKEY_PIN
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_TOKEN_PIN",
            verbatim_doc_comment,
            hide_default_value = true
        )]
        pin_env: String,
        #[command(flatten)]
        run: RunArgs,
    },
}

pub fn tokens(c: TokensCommand) -> u8 {
    match c {
        TokensCommand::List {
            pkcs11_module,
            token_serial,
            pin_env,
            run,
        } => {
            let pin = match &token_serial {
                Some(_) => match secret(&pin_env, "Token PIN", false) {
                    Ok(p) => Some(p),
                    Err(e) => return usage(&e),
                },
                None => None,
            };
            let params = json!({"pkcs11_module": pkcs11_module.display().to_string(), "token_serial": token_serial,
                                "pin_from_env": token_serial.as_ref().map(|_| &pin_env)});
            let mut r = match CreationRun::start(&run, "tokens list", params) {
                Ok(r) => r,
                Err(c) => return c,
            };
            let mut list = match certs::tokens::list(&pkcs11_module) {
                Ok(l) => l,
                Err(e) => return r.fail(&e),
            };
            if let (Some(serial), Some(pin)) = (&token_serial, &pin) {
                match certs::tokens::open(&pkcs11_module, serial, pin).and_then(|s| s.keys()) {
                    Ok(keys) => {
                        for t in list
                            .iter_mut()
                            .filter(|t| t.serial.as_deref() == Some(serial.as_str()))
                        {
                            t.keys = keys.clone();
                        }
                    }
                    Err(e) => return r.fail(&e),
                }
            }
            r.record("tokens_listed", None, json!({"slots": list.len(),
                "tokens": list.iter().filter(|t| t.token_present).map(|t| json!({"serial": t.serial, "label": t.label, "keys": t.keys.len()})).collect::<Vec<_>>()}));
            let mut s = vec![format!(
                "{} slot(s) in {}",
                list.len(),
                pkcs11_module.display()
            )];
            for t in &list {
                s.push(format!(
                    "  slot {}: {}{}",
                    t.slot_id,
                    t.slot_description,
                    if t.token_present {
                        format!(
                            "  token '{}' serial {} ({} {})",
                            t.label.clone().unwrap_or_default(),
                            t.serial.clone().unwrap_or_default(),
                            t.manufacturer.clone().unwrap_or_default(),
                            t.model.clone().unwrap_or_default()
                        )
                    } else {
                        "  (no token)".into()
                    }
                ));
                for k in &t.keys {
                    s.push(format!(
                        "    key {}  {} {}{}  {}",
                        k.key_id_hex,
                        k.key.algorithm,
                        k.key.bits.map(|b| b.to_string()).unwrap_or_default(),
                        k.key
                            .curve
                            .as_deref()
                            .map(|c| format!(" {c}"))
                            .unwrap_or_default(),
                        k.label.clone().unwrap_or_default()
                    ));
                }
            }
            r.finish(
                serde_json::to_value(&list).unwrap_or_default(),
                s,
                "",
                EXIT_OK,
            )
        }
    }
}

// ------------------------------------------------------------------------------------------------------------
// trust-list (unchanged; agent A's area)
// ------------------------------------------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum TrustListCommand {
    /// Import a trust list as a dated, hashed snapshot: eu (LOTL/TL XML) or co (curated CSV).
    Import {
        /// eu or co.
        #[arg(long, value_name = "LIST", value_parser = ["eu", "co"])]
        list: String,
        /// The XML or CSV file.
        file: PathBuf,
        /// Snapshot folder. Default: the tool's data folder (RV_CERTCHECK_DATA overrides)
        #[arg(long, value_name = "DIR")]
        store: Option<PathBuf>,
    },
    /// List stored snapshots, newest first.
    List {
        #[arg(long, value_name = "DIR")]
        store: Option<PathBuf>,
    },
    /// Show one snapshot (services, status history).
    Show {
        /// eu or co.
        #[arg(long, value_name = "LIST", value_parser = ["eu", "co"])]
        list: String,
        /// Snapshot id or latest.
        id: String,
        #[arg(long, value_name = "DIR")]
        store: Option<PathBuf>,
    },
}

fn list_kind(s: &str) -> TrustListKind {
    if s == "co" {
        TrustListKind::Co
    } else {
        TrustListKind::Eu
    }
}

pub fn trust_list(c: TrustListCommand) -> u8 {
    let store = |s: Option<PathBuf>| s.unwrap_or_else(certs::trust_list::default_store_dir);
    match c {
        TrustListCommand::Import {
            list,
            file,
            store: s,
        } => {
            let data = match read(&file) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let source = format!("file:{}", file.display());
            let now = rv_certcheck_core::time::utc_now();
            let dir = store(s);
            done(match list_kind(&list) {
                TrustListKind::Eu => certs::trust_list::import_eu(&data, &source, &now, &dir),
                TrustListKind::Co => certs::trust_list::import_co_csv(&data, &source, &now, &dir),
            })
        }
        TrustListCommand::List { store: s } => done(certs::trust_list::list(&store(s))),
        TrustListCommand::Show { list, id, store: s } => {
            done(certs::trust_list::load(&store(s), list_kind(&list), &id))
        }
    }
}
