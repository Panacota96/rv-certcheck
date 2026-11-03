//! Creation and trust-list commands: pki, csr, lab, keys, tokens, trust-list.
//!
//! v0.1 freeze: every command parses its options, builds the request struct of the frozen certificate-layer API
//! (`rv_certcheck_core::certs`) and prints the result as JSON, or `error: not implemented: <operation>` with
//! exit code 1 while the layer is a stub. The CLI agent turns these into full commands (audited run folder with
//! audit.jsonl and a report, human-readable output, prompts) without changing the request mapping.

use clap::{Args, Subcommand};
use rv_certcheck_core::certs::{
    self, CrlRequest, CsrRequest, GeneralName, ImportCaRequest, InitRootRequest, IssueProfile,
    IssueRequest, KeyLocation, KeySpec, KeyTarget, KeyUnlock, LabSetSpec, OcspSignRequest,
    RevokeRequest, Secret, SubjectSpec, TrustListKind,
};
use std::path::PathBuf;

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Where a key is created or found: an encrypted file or a PKCS#11 token.
#[derive(Args, Clone, Debug)]
pub struct KeyArgs {
    /// Encrypted key file (PKCS#8, created owner-only, never overwritten).
    /// Default: keys/<name>.key.p8 inside the CA folder
    /// Example: --key-file keys/examiner.key.p8
    #[arg(long, value_name = "FILE", verbatim_doc_comment)]
    key_file: Option<PathBuf>,
    /// Environment variable holding the key-file password (never logged; prompted when unset).
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
    /// Label of the key on the token (new keys) or CKA_ID in hex (existing keys: --key-id).
    /// Default: the CA id or certificate name
    /// Example: --key-label rakvor-root-2026
    #[arg(long, value_name = "LABEL", verbatim_doc_comment)]
    key_label: Option<String>,
    /// CKA_ID (hex) of an existing key on the token.
    /// Default: none
    /// Example: --key-id 01
    #[arg(long, value_name = "HEX", verbatim_doc_comment)]
    key_id: Option<String>,
    /// Environment variable holding the token PIN (never logged; prompted when unset).
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

impl KeyArgs {
    fn secret(&self) -> Secret {
        let var = if self.pkcs11_module.is_some() {
            &self.pin_env
        } else {
            &self.pass_env
        };
        // TODO(CLI agent): no-echo prompt (rpassword) when the variable is unset and stdin is a terminal.
        Secret::new(std::env::var(var).unwrap_or_default())
    }

    fn target(&self, default_file: PathBuf, default_label: &str) -> Result<KeyTarget, String> {
        match &self.pkcs11_module {
            Some(m) => Ok(KeyTarget::Pkcs11 {
                module: m.clone(),
                token_serial: self
                    .token_serial
                    .clone()
                    .ok_or("--token-serial is required with --pkcs11-module")?,
                pin: self.secret(),
                key_label: self
                    .key_label
                    .clone()
                    .unwrap_or_else(|| default_label.into()),
            }),
            None => Ok(KeyTarget::EncryptedFile {
                path: self.key_file.clone().unwrap_or(default_file),
                password: self.secret(),
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
}

/// Subject and SANs of a new certificate or CSR.
#[derive(Args, Clone, Debug)]
pub struct SubjectArgs {
    /// Subject as comma-separated attributes in order (C, ST, L, O, OU, CN, emailAddress, serialNumber).
    /// Default: none (required, except when issuing from a CSR)
    /// Example: --subject "C=CO,O=Rakvor,CN=Ana Ruiz"
    #[arg(long, value_name = "DN", verbatim_doc_comment)]
    subject: Option<String>,
    /// Subject alternative name, repeatable: dns:NAME, ip:ADDRESS, email:ADDRESS, uri:URI.
    /// Default: none
    /// Example: --san dns:lab.rakvor.local --san email:ana.ruiz@rakvor.co
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

fn actor(a: &Option<String>) -> String {
    a.clone().unwrap_or_else(rv_certcheck_core::env::os_user)
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
pub enum PkiCommand {
    /// Create an offline root CA (key on a token with --confirm-root, else in an encrypted file).
    InitRoot {
        /// CA folder to create (must be empty or missing).
        /// Example: --ca E:\rakvor-pki\root-2026
        #[arg(long, value_name = "DIR", verbatim_doc_comment)]
        ca: PathBuf,
        /// Short id of the CA, used in file names and audit entries.
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
        /// signature in doubt: follow the key ceremony in docs/installation.md).
        #[arg(long)]
        confirm_root: bool,
        /// Name written in the issued-certificate log. Default: the operating-system user name.
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
    },
    /// Bring an existing CA certificate and its key under management (e.g. the code-signing root).
    Import {
        /// CA folder to create.
        #[arg(long, value_name = "DIR")]
        ca: PathBuf,
        /// Short id of the CA. Example: --ca-id rakvor-code-signing-root
        #[arg(long, value_name = "ID")]
        ca_id: String,
        /// The CA certificate (PEM or DER). Example: --cert packaging/signing/rakvor-code-signing-root.cer
        #[arg(long, value_name = "FILE")]
        cert: PathBuf,
        #[command(flatten)]
        key: KeyArgs,
        /// Name written in the issued-certificate log. Default: the operating-system user name.
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
    },
    /// Issue a certificate with a profile: intermediate, code-signing, examiner, tsa, tls-server
    /// (client-internal is disabled until the CP/CPS exists).
    Issue {
        /// CA folder that signs.
        #[arg(long, value_name = "DIR")]
        ca: PathBuf,
        /// Profile. Example: --profile examiner
        #[arg(long, value_name = "PROFILE", value_parser = parse_profile)]
        profile: IssueProfile,
        #[command(flatten)]
        subject: SubjectArgs,
        /// Issue for this CSR (its key and subject) instead of generating a key.
        #[arg(long, value_name = "FILE")]
        csr: Option<PathBuf>,
        /// Key type of the new key (ignored with --csr). Default: rsa-3072
        #[arg(long, value_name = "TYPE", default_value = "rsa-3072", value_parser = parse_key_spec, hide_default_value = true)]
        key_type: KeySpec,
        /// Where the NEW subject key goes (file or token). The CA key is unlocked with --ca-pass-env.
        #[command(flatten)]
        key: KeyArgs,
        /// Environment variable with the CA key password or PIN. Default: RV_CA_PASSWORD
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_CA_PASSWORD",
            hide_default_value = true
        )]
        ca_pass_env: String,
        /// Examiner profile: environment variable with the password of the .p12 written. Default: RV_P12_PASSWORD
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_P12_PASSWORD",
            hide_default_value = true
        )]
        p12_pass_env: String,
        /// Validity in days. Default: 825
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 825,
            hide_default_value = true
        )]
        validity_days: u32,
        /// Name written in the issued-certificate log. Default: the operating-system user name.
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
    },
    /// Revoke an issued certificate (takes effect in the next CRL / OCSP response).
    Revoke {
        #[arg(long, value_name = "DIR")]
        ca: PathBuf,
        /// Serial number in hex. Example: --serial 5f3a...
        #[arg(long, value_name = "HEX")]
        serial: String,
        /// RFC 5280 reason (keyCompromise, superseded, cessationOfOperation, ...). Default: unspecified
        #[arg(
            long,
            value_name = "REASON",
            default_value = "unspecified",
            hide_default_value = true
        )]
        reason: String,
        /// Revocation time (RFC 3339). Default: now
        #[arg(long, value_name = "TIME")]
        at: Option<String>,
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
    },
    /// Sign a CRL with every revoked serial.
    Crl {
        #[arg(long, value_name = "DIR")]
        ca: PathBuf,
        /// Environment variable with the CA key password or PIN. Default: RV_CA_PASSWORD
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_CA_PASSWORD",
            hide_default_value = true
        )]
        ca_pass_env: String,
        /// Days until nextUpdate. Default: 30
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 30,
            hide_default_value = true
        )]
        next_update_days: u32,
        /// thisUpdate (RFC 3339). Default: now
        #[arg(long, value_name = "TIME")]
        this_update: Option<String>,
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
    },
    /// Sign an OCSP response for a serial at a given time (lab use; there is no OCSP server).
    OcspSign {
        #[arg(long, value_name = "DIR")]
        ca: PathBuf,
        #[arg(long, value_name = "HEX")]
        serial: String,
        /// Output file (DER). Example: --out leaf.ocsp
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// producedAt / thisUpdate (RFC 3339). Default: now
        #[arg(long, value_name = "TIME")]
        produced_at: Option<String>,
        /// Days until nextUpdate. Default: none
        #[arg(long, value_name = "DAYS")]
        next_update_days: Option<u32>,
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_CA_PASSWORD",
            hide_default_value = true
        )]
        ca_pass_env: String,
        #[arg(long, value_name = "NAME")]
        actor: Option<String>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
pub enum CsrCommand {
    /// Create a key (token or encrypted file) and a CSR for a public or qualified CA.
    New {
        #[command(flatten)]
        subject: SubjectArgs,
        /// Key type. Default: rsa-3072
        #[arg(long, value_name = "TYPE", default_value = "rsa-3072", value_parser = parse_key_spec, hide_default_value = true)]
        key_type: KeySpec,
        #[command(flatten)]
        key: KeyArgs,
        /// CSR file to write (PEM). Example: --out ana-ruiz.csr
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Display a CSR and check its self-signature.
    Show {
        /// The CSR (PEM or DER).
        file: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum LabCommand {
    /// Write a reproducible lab set and its expected_findings.json.
    Make {
        /// Set name: full or minimal. Default: full
        #[arg(
            long = "set",
            value_name = "NAME",
            default_value = "full",
            hide_default_value = true
        )]
        set: String,
        /// Seed (same seed = byte-identical set). Default: 1
        #[arg(long, value_name = "N", default_value_t = 1, hide_default_value = true)]
        seed: u64,
        /// Reference time for every validity period. Default: 2026-01-01T00:00:00Z
        #[arg(
            long,
            value_name = "TIME",
            default_value = "2026-01-01T00:00:00Z",
            hide_default_value = true
        )]
        base_time: String,
        /// Output folder (empty or missing). Example: --out lab-full-1
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Check whether a private key belongs to a certificate (the key never leaves memory).
    Match {
        /// Private key (PEM/DER, PKCS#8/PKCS#1/SEC1) or PKCS#12.
        key: PathBuf,
        /// Certificate (PEM or DER).
        cert: PathBuf,
        /// Environment variable with the key or PKCS#12 password. Default: RV_KEY_PASSWORD
        #[arg(
            long,
            value_name = "VAR",
            default_value = "RV_KEY_PASSWORD",
            hide_default_value = true
        )]
        pass_env: String,
    },
}

#[derive(Subcommand)]
pub enum TokensCommand {
    /// List PKCS#11 slots, tokens and (after login) keys.
    List {
        /// PKCS#11 module (vendor library). Example: --pkcs11-module /usr/lib/softhsm/libsofthsm2.so
        #[arg(long, value_name = "LIB")]
        pkcs11_module: PathBuf,
    },
}

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

fn env_secret(var: &str) -> Secret {
    Secret::new(std::env::var(var).unwrap_or_default())
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
            actor: a,
        } => {
            let (subject, target) = match (
                subject.spec(),
                key.target(ca.join("keys").join(format!("{ca_id}.key.p8")), &ca_id),
            ) {
                (Ok(s), Ok(t)) => (s, t),
                (Err(e), _) | (_, Err(e)) => return usage(&e),
            };
            done(certs::pki::init_root(&InitRootRequest {
                ca_dir: ca,
                ca_id,
                subject,
                key_spec: key_type,
                key_target: target,
                validity_days,
                confirm_root,
                actor: actor(&a),
            }))
        }
        PkiCommand::Import {
            ca,
            ca_id,
            cert,
            key,
            actor: a,
        } => {
            let certificate = match read(&cert) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let location = match key.location() {
                Ok(l) => l,
                Err(e) => return usage(&e),
            };
            done(certs::pki::import_ca(&ImportCaRequest {
                ca_dir: ca,
                ca_id,
                certificate,
                key: location,
                unlock: KeyUnlock {
                    secret: key.secret(),
                },
                actor: actor(&a),
            }))
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
            actor: a,
        } => {
            let subject = match subject.spec() {
                Ok(s) => s,
                Err(e) => return usage(&e),
            };
            let csr_der = match &csr {
                Some(p) => match read(p) {
                    Ok(b) => Some(b),
                    Err(c) => return c,
                },
                None => None,
            };
            let key_target = if csr_der.is_some() {
                None
            } else {
                match key.target(
                    ca.join("keys").join(format!("{}.key.p8", profile.name())),
                    profile.name(),
                ) {
                    Ok(t) => Some(t),
                    Err(e) => return usage(&e),
                }
            };
            done(certs::pki::issue(&IssueRequest {
                ca_dir: ca,
                ca_unlock: KeyUnlock {
                    secret: env_secret(&ca_pass_env),
                },
                profile,
                subject,
                csr_der,
                key_spec: Some(key_type),
                key_target,
                p12_password: (profile == IssueProfile::Examiner)
                    .then(|| env_secret(&p12_pass_env)),
                validity_days,
                actor: actor(&a),
            }))
        }
        PkiCommand::Revoke {
            ca,
            serial,
            reason,
            at,
            actor: a,
        } => {
            if !certs::REVOCATION_REASONS.contains(&reason.as_str()) {
                return usage(&format!(
                    "--reason '{reason}': use one of {}",
                    certs::REVOCATION_REASONS.join(", ")
                ));
            }
            done(certs::pki::revoke(&RevokeRequest {
                ca_dir: ca,
                serial_hex: serial.to_ascii_lowercase(),
                reason,
                revoked_at: at,
                actor: actor(&a),
            }))
        }
        PkiCommand::Crl {
            ca,
            ca_pass_env,
            next_update_days,
            this_update,
            actor: a,
        } => done(certs::pki::make_crl(&CrlRequest {
            ca_dir: ca,
            ca_unlock: KeyUnlock {
                secret: env_secret(&ca_pass_env),
            },
            this_update,
            next_update_days,
            actor: actor(&a),
        })),
        PkiCommand::OcspSign {
            ca,
            serial,
            out,
            produced_at,
            next_update_days,
            ca_pass_env,
            actor: a,
        } => done(certs::pki::sign_ocsp(&OcspSignRequest {
            ca_dir: ca,
            ca_unlock: KeyUnlock {
                secret: env_secret(&ca_pass_env),
            },
            serial_hex: serial.to_ascii_lowercase(),
            produced_at,
            next_update_days,
            out,
            actor: actor(&a),
        })),
    }
}

pub fn csr(c: CsrCommand) -> u8 {
    match c {
        CsrCommand::New {
            subject,
            key_type,
            key,
            out,
        } => {
            let default_key = out.with_extension("key.p8");
            let (subject, target) = match (subject.spec(), key.target(default_key, "csr-key")) {
                (Ok(s), Ok(t)) => (s, t),
                (Err(e), _) | (_, Err(e)) => return usage(&e),
            };
            done(certs::csr::new(&CsrRequest {
                subject,
                key_spec: key_type,
                key_target: target,
                out,
            }))
        }
        CsrCommand::Show { file } => match read(&file) {
            Ok(b) => done(certs::csr::show(&b)),
            Err(c) => c,
        },
    }
}

pub fn lab(c: LabCommand) -> u8 {
    match c {
        LabCommand::Make {
            set,
            seed,
            base_time,
            out,
        } => {
            if !matches!(set.as_str(), "full" | "minimal") {
                return usage(&format!("--set '{set}': use full or minimal"));
            }
            done(certs::lab::make(&LabSetSpec {
                name: set,
                seed,
                base_time,
                out_dir: out,
            }))
        }
    }
}

pub fn keys(c: KeysCommand) -> u8 {
    match c {
        KeysCommand::Match {
            key,
            cert,
            pass_env,
        } => {
            let (k, c) = match (read(&key), read(&cert)) {
                (Ok(k), Ok(c)) => (k, c),
                (Err(e), _) | (_, Err(e)) => return e,
            };
            let pw = std::env::var(&pass_env).ok().map(Secret::new);
            // TODO(CLI agent): accept PEM certificates (convert with the certificate layer) and print a sentence.
            done(certs::match_key(&k, pw.as_ref(), &c))
        }
    }
}

pub fn tokens(c: TokensCommand) -> u8 {
    match c {
        TokensCommand::List { pkcs11_module } => done(certs::tokens::list(&pkcs11_module)),
    }
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
