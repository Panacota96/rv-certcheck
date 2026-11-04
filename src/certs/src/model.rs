//! The certificate model shared by the analysis side (agent A) and the creation side (agent B).
//!
//! FROZEN: fields may be added (with `#[serde(default)]` or `Option`), never renamed or removed; enum variants may
//! be added, never renamed. Serialized names are part of chain.json, ca.json, issued.jsonl, trust-list snapshots
//! and expected_findings.json, which other tools and the Python oracles read. No dependency on rv-certcheck-core:
//! [`Signal`]s are mapped to findings by core (`certscan.rs`).
//!
//! ```text
//!  bytes ──► sniff() ──► Sniffed { kind, encoding }
//!        ──► parse_any() ──► ParsedInput { certificates: Vec<CertInfo>, crls, ocsp, timestamp, key, csr, signals }
//!  ChainRequest + ValidationOptions ──► validate_chain() ──► ChainVerdict { nodes: Vec<ChainNode>, signals }
//!  CaFolder (ca.json, issued.jsonl, certs/, crl/, keys/) ◄── pki::{init_root, import_ca, issue, revoke, ...}
//!  LabSetSpec ──► lab::make() ──► files + expected_findings.json (LabCase { expected_codes })
//! ```
//!
//! Conventions (every field below follows them):
//! - Times are RFC 3339 UTC with second precision and a `Z` suffix: `2026-06-01T00:00:00Z`.
//! - Hex is lowercase, without separators (`openssl x509 -serial` output lowercased, leading `00` dropped).
//! - Fingerprints are over the DER encoding of the whole object.
//! - Distinguished names are rendered in certificate order, `, `-separated, OpenSSL short names
//!   (`C=CO, O=Rakvor, CN=Rakvor Lab Root`); `*_rdns` keeps the (attribute, value) pairs.
//! - Secrets (passwords, PINs, key bytes) are only ever held in [`Secret`] / zeroized buffers and never appear in
//!   any serialized struct of this module.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------------------------
// Errors and secrets
// ------------------------------------------------------------------------------------------------------------

/// What went wrong, so core can map it to a finding or an exit code without parsing text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The operation is a stub (v0.1 freeze). Core turns it into `ANALYSIS_NOT_IMPLEMENTED` / CLI exit 1.
    NotImplemented,
    /// The bytes are not the structure they claim to be (bad DER/PEM, truncated, wrong tag).
    Parse,
    /// A password or PIN is missing or wrong (PKCS#12, encrypted key, token login).
    Password,
    /// Recognised but not supported in this version (e.g. an unknown key algorithm, legacy RC2 PKCS#12).
    Unsupported,
    /// File system problem (CA folder, trust-list store, key file).
    Io,
    /// OpenSSL or another crypto backend failed for a reason other than bad input.
    Crypto,
    /// PKCS#11 module, slot, token or key problem.
    Token,
    /// Refused by a safety rule (root without --confirm-root, disabled profile, overwrite, online not allowed).
    Policy,
    /// Bad argument (unknown purpose, malformed date, empty subject).
    InvalidInput,
}

/// The single error type of the certificate layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CertError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> CertError {
        CertError {
            kind,
            message: message.into(),
        }
    }
    /// The error every v0.1 stub returns: `not implemented: <operation>`.
    pub fn not_implemented(operation: &str) -> CertError {
        CertError::new(
            ErrorKind::NotImplemented,
            format!("not implemented: {operation}"),
        )
    }
    pub fn is_not_implemented(&self) -> bool {
        self.kind == ErrorKind::NotImplemented
    }
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CertError {}

pub type CertResult<T> = Result<T, CertError>;

/// A password or PIN. Wiped on drop; `Debug` prints `Secret(***)`; deliberately not `Serialize`.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(Zeroizing::new(s.into()))
    }
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

// ------------------------------------------------------------------------------------------------------------
// Signals (→ findings in core)
// ------------------------------------------------------------------------------------------------------------

/// A raw observation; core maps it to a finding with the same code. Codes are listed in [`codes`] and worded in
/// `i18n/*.json` (a code missing there fails `catalogue_is_complete` in core).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// Finding code, e.g. `CERT_EXPIRED_AT_DATE`.
    pub code: String,
    /// `info` | `low` | `medium` | `high` (use [`codes::severity`] for the catalogue default).
    pub severity: String,
    /// Named parameters for the i18n text (strings only). Keys used by the catalogue are documented in [`codes`].
    pub params: BTreeMap<String, String>,
}

impl Signal {
    pub fn new(code: &str, severity: &str) -> Signal {
        Signal {
            code: code.into(),
            severity: severity.into(),
            params: BTreeMap::new(),
        }
    }
    /// A signal with the catalogue's default severity for `code` (`info` for an unknown code).
    pub fn of(code: &str) -> Signal {
        Signal::new(code, codes::severity(code).unwrap_or("info"))
    }
    pub fn with(mut self, k: &str, v: impl Into<String>) -> Signal {
        self.params.insert(k.into(), v.into());
        self
    }
}

/// Every finding and limitation code of the certificate layer, with its default severity. The i18n catalogue must
/// word each one (title / shows / does_not_prove for findings; one sentence for limitations).
pub mod codes {
    // Chain and certificate (agent A). Params in brackets are what the i18n text uses.
    /// info [subject, anchor, at]
    pub const CERT_CHAIN_VALID: &str = "CERT_CHAIN_VALID";
    /// high [subject, reason, code, depth]
    pub const CERT_CHAIN_UNTRUSTED: &str = "CERT_CHAIN_UNTRUSTED";
    /// high [subject, depth, reason]
    pub const CERT_SIGNATURE_INVALID: &str = "CERT_SIGNATURE_INVALID";
    /// high [subject, not_after, at]
    pub const CERT_EXPIRED_AT_DATE: &str = "CERT_EXPIRED_AT_DATE";
    /// high [subject, not_before, at]
    pub const CERT_NOT_YET_VALID_AT_DATE: &str = "CERT_NOT_YET_VALID_AT_DATE";
    /// high [subject, serial, reason, revoked_at, source]
    pub const CERT_REVOKED: &str = "CERT_REVOKED";
    /// medium [subject, source]
    pub const REVOCATION_UNKNOWN: &str = "REVOCATION_UNKNOWN";
    /// medium [subject, purpose, key_usage, eku]
    pub const CERT_PURPOSE_MISMATCH: &str = "CERT_PURPOSE_MISMATCH";
    /// high [subject, name, constraint_by]
    pub const CERT_NAME_CONSTRAINT_VIOLATION: &str = "CERT_NAME_CONSTRAINT_VIOLATION";
    /// medium [subject, algorithm, size]
    pub const CERT_WEAK_KEY: &str = "CERT_WEAK_KEY";
    /// medium [subject, algorithm]
    pub const CERT_WEAK_SIGNATURE_ALGORITHM: &str = "CERT_WEAK_SIGNATURE_ALGORITHM";
    /// info [subject]
    pub const CERT_SELF_SIGNED: &str = "CERT_SELF_SIGNED";
    /// info [subject, list, snapshot, service, status, at]
    pub const CERT_IN_TRUST_LIST: &str = "CERT_IN_TRUST_LIST";
    /// low [subject, list, snapshot]
    pub const CERT_NOT_IN_TRUST_LIST: &str = "CERT_NOT_IN_TRUST_LIST";
    /// info [subject, policy]
    pub const CERT_ISSUED_BY_RAKVOR_INTERNAL: &str = "CERT_ISSUED_BY_RAKVOR_INTERNAL";
    /// info [key, certificates]
    pub const KEY_MATCHES_CERTIFICATE: &str = "KEY_MATCHES_CERTIFICATE";
    /// high [key, certificate]
    pub const KEY_DOES_NOT_MATCH: &str = "KEY_DOES_NOT_MATCH";
    /// info [key]
    pub const KEY_NOT_PAIRED: &str = "KEY_NOT_PAIRED";
    /// info [gen_time, tsa, policy, hash_algorithm]
    pub const TIMESTAMP_TOKEN_VALID: &str = "TIMESTAMP_TOKEN_VALID";
    /// high [reason]
    pub const TIMESTAMP_TOKEN_INVALID: &str = "TIMESTAMP_TOKEN_INVALID";
    /// medium [reason]
    pub const PKCS12_UNREADABLE: &str = "PKCS12_UNREADABLE";
    // Core glue (certscan.rs).
    /// info [kind]
    pub const CRYPTO_INPUT_NOT_RECOGNISED: &str = "CRYPTO_INPUT_NOT_RECOGNISED";
    /// medium [kind, error]
    pub const CRYPTO_INPUT_UNPARSABLE: &str = "CRYPTO_INPUT_UNPARSABLE";
    /// info [operation]
    pub const ANALYSIS_NOT_IMPLEMENTED: &str = "ANALYSIS_NOT_IMPLEMENTED";
    /// high [algorithm, expected, actual]
    pub const EVIDENCE_CHANGED_DURING_READ: &str = "EVIDENCE_CHANGED_DURING_READ";
    /// medium [operation, error]
    pub const ANALYSIS_STEP_FAILED: &str = "ANALYSIS_STEP_FAILED";

    /// (code, default severity) for every finding of the certificate layer and the core glue.
    pub const FINDINGS: &[(&str, &str)] = &[
        (CERT_CHAIN_VALID, "info"),
        (CERT_CHAIN_UNTRUSTED, "high"),
        (CERT_SIGNATURE_INVALID, "high"),
        (CERT_EXPIRED_AT_DATE, "high"),
        (CERT_NOT_YET_VALID_AT_DATE, "high"),
        (CERT_REVOKED, "high"),
        (REVOCATION_UNKNOWN, "medium"),
        (CERT_PURPOSE_MISMATCH, "medium"),
        (CERT_NAME_CONSTRAINT_VIOLATION, "high"),
        (CERT_WEAK_KEY, "medium"),
        (CERT_WEAK_SIGNATURE_ALGORITHM, "medium"),
        (CERT_SELF_SIGNED, "info"),
        (CERT_IN_TRUST_LIST, "info"),
        (CERT_NOT_IN_TRUST_LIST, "low"),
        (CERT_ISSUED_BY_RAKVOR_INTERNAL, "info"),
        (KEY_MATCHES_CERTIFICATE, "info"),
        (KEY_DOES_NOT_MATCH, "high"),
        (KEY_NOT_PAIRED, "info"),
        (TIMESTAMP_TOKEN_VALID, "info"),
        (TIMESTAMP_TOKEN_INVALID, "high"),
        (PKCS12_UNREADABLE, "medium"),
        (CRYPTO_INPUT_NOT_RECOGNISED, "info"),
        (CRYPTO_INPUT_UNPARSABLE, "medium"),
        (ANALYSIS_NOT_IMPLEMENTED, "info"),
        (EVIDENCE_CHANGED_DURING_READ, "high"),
        (ANALYSIS_STEP_FAILED, "medium"),
    ];

    /// Run-level limitations printed in every report (what the tool cannot tell you).
    pub const LIMITATIONS: &[&str] = &[
        "VALIDATION_IS_AS_OF_THE_DATE_GIVEN",
        "OFFLINE_REVOCATION_DEPENDS_ON_SUPPLIED_FILES",
        "TRUST_LIST_SNAPSHOT_DATED",
        "TRUST_LIST_SIGNATURE_NOT_VERIFIED_V01",
        "RAKVOR_CERTIFICATES_ARE_INTERNAL_USE",
        "NO_VALIDATED_ERROR_RATES_YET",
        "CLEAN_RESULT_IS_NOT_AUTHENTICITY",
        "TIMESTAMPS_FROM_FILESYSTEM",
        "TIMESTAMP_PROVES_EXISTENCE_ONLY",
    ];

    pub fn severity(code: &str) -> Option<&'static str> {
        FINDINGS.iter().find(|(c, _)| *c == code).map(|(_, s)| *s)
    }
}

// ------------------------------------------------------------------------------------------------------------
// Input kinds
// ------------------------------------------------------------------------------------------------------------

/// What an item is, decided from its content (never from its extension).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// One X.509 certificate (DER, or one PEM `CERTIFICATE` block).
    Certificate,
    /// Several PEM certificates in one file (no other PEM block types).
    CertBundle,
    /// PKCS#7 / CMS SignedData holding certificates and/or CRLs (.p7b, .p7c), not a timestamp token.
    Pkcs7,
    /// PKCS#12 / PFX.
    Pkcs12,
    /// X.509 CRL (DER or PEM `X509 CRL`).
    Crl,
    /// OCSP response (DER `OCSPResponse`).
    OcspResponse,
    /// RFC 3161 TimeStampResp (.tsr) or bare TimeStampToken (.tst): CMS SignedData with id-ct-TSTInfo.
    TimestampToken,
    /// Private key: PKCS#8 (plain or encrypted), PKCS#1 RSA, SEC1 EC; DER or PEM.
    PrivateKey,
    /// PKCS#10 certificate signing request.
    Csr,
    /// Anything else: core keeps the inventory analysis (type by signature) for it.
    Unknown,
}

impl InputKind {
    pub fn name(&self) -> &'static str {
        match self {
            InputKind::Certificate => "certificate",
            InputKind::CertBundle => "cert_bundle",
            InputKind::Pkcs7 => "pkcs7",
            InputKind::Pkcs12 => "pkcs12",
            InputKind::Crl => "crl",
            InputKind::OcspResponse => "ocsp_response",
            InputKind::TimestampToken => "timestamp_token",
            InputKind::PrivateKey => "private_key",
            InputKind::Csr => "csr",
            InputKind::Unknown => "unknown",
        }
    }
    /// Human-readable type for the report's "detected type" line.
    pub fn label(&self) -> &'static str {
        match self {
            InputKind::Certificate => "X.509 certificate",
            InputKind::CertBundle => "X.509 certificate bundle (PEM)",
            InputKind::Pkcs7 => "PKCS#7 / CMS certificate container",
            InputKind::Pkcs12 => "PKCS#12 / PFX key store",
            InputKind::Crl => "X.509 certificate revocation list",
            InputKind::OcspResponse => "OCSP response",
            InputKind::TimestampToken => "RFC 3161 timestamp token",
            InputKind::PrivateKey => "Private key",
            InputKind::Csr => "PKCS#10 certificate signing request",
            InputKind::Unknown => "Not a recognised cryptographic object",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    #[default]
    Der,
    Pem,
    /// Base64 without PEM armour (some exports).
    Base64,
}

/// Result of [`crate::sniff`]: cheap, from the bytes only, never fails on hostile input (Unknown instead).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sniffed {
    pub kind: InputKindOrUnknown,
    pub encoding: Encoding,
    /// PEM block labels in file order (`CERTIFICATE`, `X509 CRL`, `ENCRYPTED PRIVATE KEY`, ...). Empty for DER.
    #[serde(default)]
    pub pem_labels: Vec<String>,
    /// True for an encrypted private key or a password-protected PKCS#12 (the password is needed to read keys).
    #[serde(default)]
    pub encrypted: bool,
}

/// `InputKind` with `Unknown` as the default, so `Sniffed::default()` is "unknown DER".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputKindOrUnknown(pub InputKind);

impl Default for InputKindOrUnknown {
    fn default() -> Self {
        InputKindOrUnknown(InputKind::Unknown)
    }
}

// ------------------------------------------------------------------------------------------------------------
// Parsed objects
// ------------------------------------------------------------------------------------------------------------

/// One SAN / name-constraint / general-name entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralName {
    /// `dns` | `ip` | `email` | `uri` | `dir` | `other`
    pub kind: String,
    /// IPs as text (`192.0.2.1`, `2001:db8::1`; IP ranges in name constraints as `192.0.2.0/24`).
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u32>,
    pub critical: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameConstraints {
    pub permitted: Vec<GeneralName>,
    pub excluded: Vec<GeneralName>,
    pub critical: bool,
}

/// One extension as present (for the technical report; the interesting ones are also decoded into fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub oid: String,
    /// OpenSSL short name where known (`basicConstraints`), else the OID.
    pub name: String,
    pub critical: bool,
}

/// Public facts about a key. Never contains private material.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// `rsa` | `ec` | `ed25519` | `ed448` | `dsa` | the algorithm OID
    pub algorithm: String,
    /// Modulus size for RSA/DSA, field size for EC, 256/456 for Ed25519/Ed448.
    pub bits: Option<u32>,
    /// `P-256` | `P-384` | `P-521` | `secp256k1` | `brainpoolP256r1` | ... (EC only).
    pub curve: Option<String>,
    /// SHA-256 of the DER SubjectPublicKeyInfo: equal for a key and its certificate.
    pub spki_sha256: String,
    /// Private-key items only: was the key stored encrypted.
    #[serde(default)]
    pub encrypted: bool,
}

/// Every field of one X.509 certificate that the reports and the findings use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    pub version: u32,
    pub subject: String,
    pub subject_rdns: Vec<(String, String)>,
    pub issuer: String,
    pub issuer_rdns: Vec<(String, String)>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub sans: Vec<GeneralName>,
    pub key: KeyInfo,
    /// OpenSSL long name (`sha256WithRSAEncryption`, `ecdsa-with-SHA256`, `ED25519`, `md5WithRSAEncryption`).
    pub signature_algorithm: String,
    pub signature_algorithm_oid: String,
    /// OpenSSL names: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement,
    /// keyCertSign, cRLSign, encipherOnly, decipherOnly. Empty when the extension is absent.
    pub key_usage: Vec<String>,
    pub key_usage_critical: bool,
    /// Short names where known (serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning,
    /// documentSigning, anyExtendedKeyUsage) else the OID.
    pub eku: Vec<String>,
    pub eku_critical: bool,
    pub basic_constraints: Option<BasicConstraints>,
    pub name_constraints: Option<NameConstraints>,
    /// certificatePolicies OIDs in order.
    pub policy_oids: Vec<String>,
    /// AIA id-ad-ocsp URLs.
    pub aia_ocsp: Vec<String>,
    /// AIA id-ad-caIssuers URLs.
    pub aia_ca_issuers: Vec<String>,
    /// CRL distribution point URLs (fullName URIs).
    pub crl_dps: Vec<String>,
    pub ski_hex: Option<String>,
    pub aki_hex: Option<String>,
    pub sha256: String,
    pub sha1: String,
    /// Subject == issuer AND the signature verifies with the certificate's own public key.
    pub self_signed: bool,
    pub extensions: Vec<ExtensionInfo>,
    /// The certificate itself (DER). Not serialized: chain.json carries fingerprints, certificate.txt the dump.
    #[serde(skip)]
    pub der: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedEntry {
    pub serial_hex: String,
    pub revoked_at: String,
    /// RFC 5280 reason name (`keyCompromise`, `cessationOfOperation`, ...) or `unspecified` when absent.
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlInfo {
    pub issuer: String,
    pub this_update: String,
    pub next_update: Option<String>,
    /// cRLNumber as decimal text.
    pub crl_number: Option<String>,
    pub aki_hex: Option<String>,
    pub signature_algorithm: String,
    pub revoked: Vec<RevokedEntry>,
    pub sha256: String,
    #[serde(skip)]
    pub der: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcspSingle {
    pub serial_hex: String,
    pub issuer_key_hash_hex: String,
    /// `good` | `revoked` | `unknown`
    pub status: String,
    pub revoked_at: Option<String>,
    pub reason: Option<String>,
    pub this_update: String,
    pub next_update: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcspInfo {
    /// OCSPResponseStatus: `successful`, `malformedRequest`, `internalError`, `tryLater`, `sigRequired`,
    /// `unauthorized`.
    pub response_status: String,
    pub produced_at: Option<String>,
    /// Responder by name (subject) or by key hash (`key:<hex>`).
    pub responder: Option<String>,
    pub responses: Vec<OcspSingle>,
    /// Certificates embedded in the response (responder chain).
    pub certificates: Vec<CertInfo>,
    pub sha256: String,
    #[serde(skip)]
    pub der: Vec<u8>,
}

/// TSTInfo of an RFC 3161 token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampInfo {
    pub gen_time: String,
    pub policy_oid: String,
    pub serial_hex: String,
    /// `sha256`, `sha384`, `sha512`, `sha1`, ... (OpenSSL short names).
    pub hash_algorithm: String,
    pub message_imprint_hex: String,
    pub tsa_name: Option<String>,
    pub nonce_hex: Option<String>,
    /// Accuracy as text (`1s`, `500ms`), when present.
    pub accuracy: Option<String>,
    pub ordering: bool,
    /// PKIStatus of a TimeStampResp (`granted`, `grantedWithMods`, `rejection`, ...); None for a bare token.
    pub response_status: Option<String>,
    /// Signer certificate first, then the other embedded certificates.
    pub certificates: Vec<CertInfo>,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrInfo {
    pub subject: String,
    pub subject_rdns: Vec<(String, String)>,
    pub sans: Vec<GeneralName>,
    pub key: KeyInfo,
    pub signature_algorithm: String,
    /// The CSR's self-signature verifies with the enclosed public key.
    pub signature_valid: bool,
    /// Requested extensions (extensionRequest attribute).
    pub requested_extensions: Vec<ExtensionInfo>,
    pub sha256: String,
}

/// Everything [`crate::parse_any`] found in one item. A PKCS#12 fills `certificates` (+ `private_key` facts when
/// the password opens it); a timestamp token fills `timestamp` and lists its certificates there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedInput {
    pub kind: InputKindOrUnknown,
    pub encoding: Encoding,
    /// In file order. For Certificate/CertBundle/Pkcs7/Pkcs12.
    pub certificates: Vec<CertInfo>,
    pub crls: Vec<CrlInfo>,
    pub ocsp: Option<OcspInfo>,
    pub timestamp: Option<TimestampInfo>,
    /// Public facts of the private key (PrivateKey items, opened PKCS#12). Never the key itself.
    pub private_key: Option<KeyInfo>,
    pub csr: Option<CsrInfo>,
    /// Parse-time observations (PKCS12_UNREADABLE, CERT_WEAK_KEY, CERT_WEAK_SIGNATURE_ALGORITHM,
    /// CERT_SELF_SIGNED, CERT_ISSUED_BY_RAKVOR_INTERNAL...). Chain-dependent signals come from validate_chain.
    pub signals: Vec<Signal>,
}

// ------------------------------------------------------------------------------------------------------------
// Validation
// ------------------------------------------------------------------------------------------------------------

/// Purpose checked against key usage / EKU (`--purpose`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    #[default]
    Any,
    TlsServer,
    TlsClient,
    CodeSigning,
    DocumentSigning,
    Email,
    Timestamping,
}

impl Purpose {
    pub const ALL: [Purpose; 7] = [
        Purpose::Any,
        Purpose::TlsServer,
        Purpose::TlsClient,
        Purpose::CodeSigning,
        Purpose::DocumentSigning,
        Purpose::Email,
        Purpose::Timestamping,
    ];
    pub fn name(&self) -> &'static str {
        match self {
            Purpose::Any => "any",
            Purpose::TlsServer => "tls-server",
            Purpose::TlsClient => "tls-client",
            Purpose::CodeSigning => "code-signing",
            Purpose::DocumentSigning => "document-signing",
            Purpose::Email => "email",
            Purpose::Timestamping => "timestamping",
        }
    }
    pub fn parse(s: &str) -> CertResult<Purpose> {
        Purpose::ALL
            .into_iter()
            .find(|p| p.name() == s.trim().to_ascii_lowercase())
            .ok_or_else(|| {
                CertError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "unknown purpose '{s}': use any, tls-server, tls-client, code-signing, document-signing, email or timestamping"
                    ),
                )
            })
    }
    /// The `openssl verify -purpose` name an oracle uses (None for any / document-signing, which have none).
    pub fn openssl_name(&self) -> Option<&'static str> {
        match self {
            Purpose::TlsServer => Some("sslserver"),
            Purpose::TlsClient => Some("sslclient"),
            Purpose::CodeSigning => Some("codesign"),
            Purpose::Email => Some("smimesign"),
            Purpose::Timestamping => Some("timestampsign"),
            Purpose::Any | Purpose::DocumentSigning => None,
        }
    }
}

/// `--at`: the moment the chain is judged at.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "mode", content = "time")]
pub enum AtTime {
    /// The analysis time (recorded in the verdict).
    #[default]
    Now,
    /// A given instant (RFC 3339 UTC, normalised by [`AtTime::parse`]).
    Fixed(String),
    /// The signing time of the object (timestamp genTime / CMS signingTime); falls back to Now with a note in
    /// the verdict when the item has none.
    SigningTime,
}

impl AtTime {
    /// `now` | `signing-time` | `YYYY-MM-DD` (midnight UTC) | RFC 3339 (`2026-06-01T12:00:00Z`, offsets converted).
    pub fn parse(s: &str) -> CertResult<AtTime> {
        let t = s.trim();
        match t.to_ascii_lowercase().as_str() {
            "now" => return Ok(AtTime::Now),
            "signing-time" => return Ok(AtTime::SigningTime),
            _ => {}
        }
        let bad = || {
            CertError::new(
                ErrorKind::InvalidInput,
                format!(
                    "invalid --at '{s}': use now, signing-time, YYYY-MM-DD or an RFC 3339 time such as 2026-06-01T12:00:00Z"
                ),
            )
        };
        if let Ok(d) = chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d") {
            let dt = d.and_hms_opt(0, 0, 0).ok_or_else(bad)?;
            return Ok(AtTime::Fixed(rfc3339(dt.and_utc())));
        }
        let dt = chrono::DateTime::parse_from_rfc3339(t).map_err(|_| bad())?;
        Ok(AtTime::Fixed(rfc3339(dt.with_timezone(&chrono::Utc))))
    }
    pub fn describe(&self) -> String {
        match self {
            AtTime::Now => "now".into(),
            AtTime::Fixed(t) => t.clone(),
            AtTime::SigningTime => "signing-time".into(),
        }
    }
}

/// RFC 3339 UTC, second precision, `Z` suffix (the model's time format).
pub fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustListKind {
    /// EU LOTL / national TLs (ETSI TS 119 612 XML).
    Eu,
    /// Colombia: curated CSV of ONAC-accredited ECDs (no machine-readable list is published).
    Co,
}

impl TrustListKind {
    pub fn name(&self) -> &'static str {
        match self {
            TrustListKind::Eu => "eu",
            TrustListKind::Co => "co",
        }
    }
}

/// One `--anchor` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum AnchorSpec {
    /// PEM/DER certificate(s) or a PKCS#7 bundle file; every certificate in it is trusted.
    File { path: PathBuf },
    /// The bundled Rakvor root ([`crate::RAKVOR_ROOT_DER`]).
    Rakvor,
    /// The operating system's store (Windows ROOT store; OpenSSL default paths elsewhere).
    System,
    /// A stored trust-list snapshot (`tl:eu@<id>`, `tl:co@<id>`; `latest` picks the newest).
    TrustList {
        list: TrustListKind,
        snapshot: String,
    },
}

impl AnchorSpec {
    /// `rakvor` | `system` | `tl:eu@SNAPSHOT` | `tl:co@SNAPSHOT` | anything else is a file path.
    pub fn parse(s: &str) -> CertResult<AnchorSpec> {
        let t = s.trim();
        if t.is_empty() {
            return Err(CertError::new(ErrorKind::InvalidInput, "empty --anchor"));
        }
        match t {
            "rakvor" => return Ok(AnchorSpec::Rakvor),
            "system" => return Ok(AnchorSpec::System),
            _ => {}
        }
        if let Some(rest) = t.strip_prefix("tl:") {
            let (list, snap) = rest.split_once('@').unwrap_or((rest, "latest"));
            let list = match list {
                "eu" => TrustListKind::Eu,
                "co" => TrustListKind::Co,
                _ => {
                    return Err(CertError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "unknown trust list '{list}' in --anchor {t}: use tl:eu@SNAPSHOT or tl:co@SNAPSHOT"
                        ),
                    ));
                }
            };
            let snapshot = if snap.is_empty() { "latest" } else { snap };
            return Ok(AnchorSpec::TrustList {
                list,
                snapshot: snapshot.into(),
            });
        }
        Ok(AnchorSpec::File {
            path: PathBuf::from(t),
        })
    }
    pub fn describe(&self) -> String {
        match self {
            AnchorSpec::File { path } => format!("file:{}", path.display()),
            AnchorSpec::Rakvor => "rakvor".into(),
            AnchorSpec::System => "system".into(),
            AnchorSpec::TrustList { list, snapshot } => format!("tl:{}@{}", list.name(), snapshot),
        }
    }
}

/// How an analysis judges chains. Built by the CLI/GUI from `--anchor --at --purpose --crl --ocsp --online`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidationOptions {
    /// No anchor = nothing is trusted: chains are still built and checked, and reported as untrusted.
    pub anchors: Vec<AnchorSpec>,
    pub at: AtTime,
    pub purpose: Purpose,
    /// `--crl` files (DER or PEM). Read, hashed and audited by core, then passed as [`ChainRequest::crls`].
    pub crl_files: Vec<PathBuf>,
    /// `--ocsp` files (DER OCSP responses). Read by core, passed as [`ChainRequest::ocsp`].
    pub ocsp_files: Vec<PathBuf>,
    /// Fetch CRLs/OCSP from AIA/CDP URLs (audited). v0.1: refused by core and CLI until agent A implements it.
    pub online: bool,
    /// Folder of stored trust-list snapshots (the tool's data folder); None = the default data folder.
    pub trust_list_dir: Option<PathBuf>,
}

/// DER bytes with where they came from: `file:<path>` (--crl/--ocsp/--anchor), `item:<index>` (an evidence item of
/// the run), `url:<url>` (online, audited), `bundled:rakvor`, `system`, `tl:<list>@<id>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledDer {
    pub origin: String,
    #[serde(skip)]
    pub der: Vec<u8>,
    /// SHA-256 of `der`.
    pub sha256: String,
}

impl LabeledDer {
    pub fn new(origin: impl Into<String>, der: Vec<u8>) -> LabeledDer {
        use sha2::Digest;
        let sha256 = hex(&sha2::Sha256::digest(&der));
        LabeledDer {
            origin: origin.into(),
            der,
            sha256,
        }
    }
}

/// Lowercase hex (the model's hex format).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One `--anchor` resolved to certificates by [`crate::resolve_anchors`] (once per run; core audits it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedAnchor {
    /// [`AnchorSpec::describe`] of the option it came from.
    pub spec: String,
    /// SHA-256 of the file or snapshot it was read from (None for `system`).
    pub source_sha256: Option<String>,
    /// The trusted certificates (origin = the spec).
    pub certificates: Vec<LabeledDer>,
    /// Trust-list anchors: the snapshot (services, status history) for CERT_IN_TRUST_LIST. Not serialized.
    #[serde(skip)]
    pub snapshot: Option<TrustListSnapshot>,
}

/// One chain-validation call. Build with `ChainRequest { target_der: .., ..Default::default() }` so new fields
/// never break callers. The certificate layer reads no file here: core resolves `--anchor` once
/// ([`crate::resolve_anchors`]) and reads `--crl`/`--ocsp` files itself (hashing and auditing them) and passes
/// everything below.
#[derive(Clone, Debug, Default)]
pub struct ChainRequest<'a> {
    /// The certificate to judge (depth 0).
    pub target_der: &'a [u8],
    /// Untrusted certificates that may complete the path (the item's own certificates and every certificate in
    /// the run). Never trusted by being here.
    pub untrusted_der: &'a [Vec<u8>],
    /// Exactly the trust anchors (nothing else is trusted; empty = every chain is untrusted).
    pub anchors: &'a [ResolvedAnchor],
    /// CRLs: `--crl` files and every CRL among the evidence items.
    pub crls: &'a [LabeledDer],
    /// OCSP responses: `--ocsp` files and every OCSP response among the evidence items.
    pub ocsp: &'a [LabeledDer],
    /// For `AtTime::SigningTime`: the object's signing time (RFC 3339), if the caller knows it.
    pub signing_time: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// OpenSSL accepted this depth (X509_V_OK).
    #[default]
    Ok,
    /// OpenSSL reported an error at this depth (code/reason say which).
    Error,
    /// The path could not be built up to here (missing issuer): the node is the last one found.
    Incomplete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSourceKind {
    #[default]
    Crl,
    Ocsp,
}

/// Where a revocation answer came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSource {
    pub kind: RevocationSourceKind,
    /// [`LabeledDer::origin`] of the CRL or OCSP response used.
    pub origin: String,
    pub sha256: String,
    pub this_update: Option<String>,
    pub next_update: Option<String>,
}

/// Revocation state of one certificate at the validation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RevocationStatus {
    Good {
        source: RevocationSource,
    },
    Revoked {
        /// RFC 5280 reason name or `unspecified`.
        reason: String,
        revoked_at: String,
        source: RevocationSource,
    },
    Unknown {
        /// Why unknown: `no CRL or OCSP response supplied`, `CRL expired at validation time`,
        /// `OCSP responder said unknown`, `offline: CDP http://... not fetched`, ...
        source: String,
    },
}

impl Default for RevocationStatus {
    fn default() -> Self {
        RevocationStatus::Unknown {
            source: "not checked".into(),
        }
    }
}

/// Membership of a certificate in a trust-list snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustListMatch {
    pub list: String,
    pub snapshot_id: String,
    pub snapshot_sha256: String,
    pub tsp_name: String,
    pub service_name: String,
    pub service_type: String,
    /// Service status at the validation time (ETSI status URI or the CSV status).
    pub status_at: String,
    pub at: String,
}

/// One certificate of a built chain, depth 0 = the target.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainNode {
    pub depth: u32,
    pub cert: CertInfo,
    pub status: NodeStatus,
    /// OpenSSL `X509_V_*` code at this depth (0 = OK).
    pub openssl_code: i32,
    /// OpenSSL's text for the code (`X509_verify_cert_error_string`), e.g. `certificate has expired`.
    pub openssl_reason: String,
    /// The node is a trust anchor (from which `--anchor`).
    pub anchor: Option<String>,
    pub revocation: Option<RevocationStatus>,
    pub trust_list: Option<TrustListMatch>,
    /// Added by agent A (defaulted): why a `Good` revocation status needs reading with care, e.g. "revoked on
    /// 2026-07-01, after the date checked" or "CRL issued after the date checked".
    #[serde(default)]
    pub revocation_note: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStatus {
    /// A path to an anchor was built and every check passed.
    Valid,
    /// A path was built but did not reach any anchor (or no anchor was given).
    Untrusted,
    /// A path reached an anchor but a check failed (signature, time, purpose, revocation, constraints).
    #[default]
    Invalid,
}

/// The verdict on one target certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerdict {
    pub status: ChainStatus,
    /// The instant actually used (RFC 3339) and how it was chosen (`now` | `given` | `signing-time` |
    /// `signing-time-unavailable-now`).
    pub at: String,
    pub at_source: String,
    pub purpose: Purpose,
    /// `--anchor` values that contributed certificates (AnchorSpec::describe()).
    pub anchors: Vec<String>,
    /// Depth 0 first. Present even for an untrusted chain (as far as it could be built).
    pub nodes: Vec<ChainNode>,
    /// OpenSSL's overall result: the first error it reported (0 = OK) and its text.
    pub openssl_code: i32,
    pub openssl_reason: String,
    /// Every error OpenSSL reported during the walk, in order (depth, code, reason), via a verify callback that
    /// continues after errors so that all problems of the chain are listed.
    pub errors: Vec<ChainError>,
    /// The signals derived from this chain (CERT_CHAIN_VALID / _UNTRUSTED / _EXPIRED_AT_DATE / CERT_REVOKED /
    /// REVOCATION_UNKNOWN / CERT_PURPOSE_MISMATCH / CERT_IN_TRUST_LIST ...), with `subject` and `depth` params.
    pub signals: Vec<Signal>,
    /// `OpenSSL 3.x.y ...` as linked (environment.json also records it).
    pub openssl_version: String,
    /// Added by agent A (defaulted): every URL fetched with `--online` for this chain (CRL distribution points,
    /// OCSP responders), with the response SHA-256 and the time, for core's audit log. Empty offline.
    #[serde(default)]
    pub online_fetches: Vec<OnlineFetch>,
    /// Added by agent A (defaulted): how the verdict was reached where it is not obvious from the codes (which
    /// OpenSSL CRL flags were used, where the error walk stopped, how `--at signing-time` was resolved, the
    /// tool's own policy checks).
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One URL fetched by `--online` (no cache; 15 s timeout). Added by agent A.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineFetch {
    /// `crl` | `ocsp`
    pub kind: String,
    pub url: String,
    /// Subject of the certificate whose status was asked for.
    pub for_subject: String,
    /// When the request was sent (RFC 3339).
    pub fetched_utc: String,
    pub http_status: Option<u16>,
    pub bytes: u64,
    /// SHA-256 of the response body (None when nothing was received).
    pub sha256: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainError {
    pub depth: u32,
    pub code: i32,
    pub reason: String,
}

/// Result of [`crate::verify_timestamp_token`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampVerdict {
    pub info: TimestampInfo,
    /// The CMS signature over TSTInfo verifies with the signer certificate (ESS signing-certificate checked).
    pub signature_valid: bool,
    /// Some(..) when the caller supplied the data: its digest equals the message imprint.
    pub imprint_matches: Option<bool>,
    /// The TSA certificate's chain at genTime with purpose timestamping.
    pub signer_chain: Option<ChainVerdict>,
    /// TIMESTAMP_TOKEN_VALID or TIMESTAMP_TOKEN_INVALID (+ chain signals).
    pub signals: Vec<Signal>,
}

/// Result of [`crate::match_key`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMatch {
    pub matches: bool,
    pub key: KeyInfo,
    pub cert_sha256: String,
    pub cert_subject: String,
}

// ------------------------------------------------------------------------------------------------------------
// Trust lists
// ------------------------------------------------------------------------------------------------------------

pub const TRUST_LIST_SCHEMA: &str = "rakvor.trust-list/1";

/// One status period of a trust service (ETSI ServiceHistory, or the CSV's status columns).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatusPeriod {
    /// ETSI status URI (`http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted`, `.../withdrawn`) or, for
    /// the Colombian CSV, `accredited` | `suspended` | `withdrawn`.
    pub status: String,
    pub from: String,
    /// Start of the next period (None = still current).
    pub until: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustService {
    /// Position in `TrustListSnapshot::services` (entries refer to it).
    pub index: u32,
    pub country: String,
    pub tsp_name: String,
    pub service_name: String,
    /// ETSI ServiceTypeIdentifier URI (`.../Svctype/CA/QC`, `.../Svctype/TSA/QTST`) or the CSV's type.
    pub service_type: String,
    pub current_status: String,
    pub history: Vec<ServiceStatusPeriod>,
    /// EU: the national TL the service came from; CO: the CSV row's source URL.
    pub source_url: String,
}

/// One certificate (digital identity) of a trust service.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustListEntry {
    pub service_index: u32,
    pub cert_sha256: String,
    pub subject: String,
    pub ski_hex: Option<String>,
    pub not_after: String,
    /// Base64 DER, so a snapshot can be used as `--anchor tl:..@ID` without the original XML/CSV.
    pub cert_b64: String,
}

/// A dated, hashed copy of a trust list as imported (stored as `<data>/trust-lists/<list>/<id>.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustListSnapshot {
    /// [`TRUST_LIST_SCHEMA`]
    pub schema: String,
    /// `<list>-<YYYYMMDDTHHMMSSZ>-<first 8 hex of sha256>`, e.g. `eu-20261103T101500Z-1a2b3c4d`.
    pub id: String,
    pub list: String,
    /// `file:<path>` or `url:<url>` of what was imported.
    pub source: String,
    pub fetched_utc: String,
    /// SHA-256 of the imported bytes (the XML or CSV exactly as read).
    pub sha256: String,
    /// TL metadata where present (EU: ListIssueDateTime, NextUpdate, TSLSequenceNumber, SchemeTerritory).
    pub issue_date: Option<String>,
    pub next_update: Option<String>,
    pub sequence_number: Option<String>,
    pub territory: Option<String>,
    /// v0.1 always false: the TL's XAdES signature is checked in v0.2 (limitation
    /// TRUST_LIST_SIGNATURE_NOT_VERIFIED_V01).
    pub signature_verified: bool,
    pub services: Vec<TrustService>,
    pub entries: Vec<TrustListEntry>,
}

/// One line of `trust-list list`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustListSummary {
    pub id: String,
    pub list: String,
    pub source: String,
    pub fetched_utc: String,
    pub sha256: String,
    pub services: u32,
    pub entries: u32,
    pub path: PathBuf,
}

// ------------------------------------------------------------------------------------------------------------
// PKI (creation)
// ------------------------------------------------------------------------------------------------------------

/// `ca.json` schema id.
pub const CA_SCHEMA: &str = "rakvor.ca/1";
/// `expected_findings.json` schema id.
pub const LAB_SET_SCHEMA: &str = "rakvor.lab-set/1";

/// Rakvor's private OID arc: a UUID OID under 2.25 (ITU-T X.667), usable without registration. Replace by an
/// IANA Private Enterprise Number arc if Rakvor obtains one (a new policy OID, never a re-use of these).
pub const RAKVOR_OID_ARC: &str = "2.25.130074246409705057913773883974790544206";
/// certificatePolicies OID in every certificate Rakvor issues (internal use: not a *firma digital* under
/// Ley 527 de 1999 art. 28, not qualified under eIDAS). Detected by CERT_ISSUED_BY_RAKVOR_INTERNAL.
pub const RAKVOR_POLICY_INTERNAL: &str = "2.25.130074246409705057913773883974790544206.1.1";
/// certificatePolicies OID of lab/test certificates (`lab make`): never evidence of anything.
pub const RAKVOR_POLICY_LAB: &str = "2.25.130074246409705057913773883974790544206.9.1";
/// TSA policy OID of the lab / test timestamping authority (fixtures and `lab make`).
pub const RAKVOR_POLICY_LAB_TSA: &str = "2.25.130074246409705057913773883974790544206.9.2";
/// The user-notice text written into the policy qualifier of every Rakvor-issued certificate.
pub const RAKVOR_INTERNAL_NOTICE: &str = "Rakvor internal use only. Not a firma digital under Ley 527 de 1999 art. 28 (Colombia); not a qualified certificate under eIDAS (EU 910/2014).";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeySpec {
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    #[serde(rename = "rsa-3072")]
    Rsa3072,
    #[serde(rename = "rsa-4096")]
    Rsa4096,
    #[serde(rename = "p-256")]
    P256,
    #[serde(rename = "p-384")]
    P384,
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl KeySpec {
    pub const ALL: [KeySpec; 6] = [
        KeySpec::Rsa2048,
        KeySpec::Rsa3072,
        KeySpec::Rsa4096,
        KeySpec::P256,
        KeySpec::P384,
        KeySpec::Ed25519,
    ];
    pub fn name(&self) -> &'static str {
        match self {
            KeySpec::Rsa2048 => "rsa-2048",
            KeySpec::Rsa3072 => "rsa-3072",
            KeySpec::Rsa4096 => "rsa-4096",
            KeySpec::P256 => "p-256",
            KeySpec::P384 => "p-384",
            KeySpec::Ed25519 => "ed25519",
        }
    }
    pub fn parse(s: &str) -> CertResult<KeySpec> {
        let t = s.trim().to_ascii_lowercase();
        KeySpec::ALL
            .into_iter()
            .find(|k| k.name() == t || k.name().replace('-', "") == t.replace('-', ""))
            .ok_or_else(|| {
                CertError::new(
                    ErrorKind::InvalidInput,
                    format!("unknown key type '{s}': use rsa-2048, rsa-3072, rsa-4096, p-256, p-384 or ed25519"),
                )
            })
    }
}

/// Where a private key lives. Serialized into ca.json / issued.jsonl; holds no secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum KeyLocation {
    /// An encrypted file. `path` is relative to the CA folder when inside it (`keys/ca.key.p8`), else absolute.
    /// `format`: `pkcs8-encrypted` (PEM, AES-256-CBC + PBKDF2/scrypt) or `pkcs12`.
    EncryptedFile { path: String, format: String },
    /// A key on a PKCS#11 token. The PIN is never stored.
    Pkcs11 {
        /// Module path as given (`C:\Program Files\Yubico\...\ykcs11.dll`, `/usr/lib/softhsm/libsofthsm2.so`).
        module: String,
        token_serial: String,
        token_label: Option<String>,
        /// CKA_ID, hex.
        key_id_hex: String,
        key_label: Option<String>,
    },
}

/// Where to create a new private key and the secret that protects it.
#[derive(Clone, Debug)]
pub enum KeyTarget {
    /// Encrypted PKCS#8 file at `path` (created, never overwritten; owner-only permissions).
    EncryptedFile { path: PathBuf, password: Secret },
    /// Generated on the token (CKA_SENSITIVE, non-extractable).
    Pkcs11 {
        module: PathBuf,
        token_serial: String,
        pin: Secret,
        key_label: String,
    },
}

/// How to unlock an existing key ([`KeyLocation`] says where it is).
#[derive(Clone, Debug, Default)]
pub struct KeyUnlock {
    /// File password or token PIN.
    pub secret: Secret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaKind {
    /// Created by `pki init-root`.
    Root,
    /// Created by `pki issue --profile intermediate` and then managed as its own CA folder.
    Intermediate,
    /// Brought under management by `pki import` (e.g. the existing code-signing root).
    Imported,
}

/// `ca.json` (schema [`CA_SCHEMA`]). Folder layout:
/// ```text
/// <CA>/ca.json            this struct
/// <CA>/issued.jsonl       IssuedRecord per line, hash-chained like audit.jsonl
/// <CA>/certs/ca.crt       the CA certificate (PEM) + certs/<serial>.crt for every issued certificate
/// <CA>/crl/<number>.crl   every CRL issued (DER) + crl/latest.crl
/// <CA>/keys/              encrypted private keys (owner-only); token keys are only referenced
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaFolder {
    pub schema: String,
    /// Short id chosen at creation (`rakvor-root-2026`), used in file names and audit entries.
    pub ca_id: String,
    pub kind: CaKind,
    pub subject: String,
    /// `certs/ca.crt`
    pub certificate_file: String,
    pub certificate_sha256: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub key_spec: Option<KeySpec>,
    pub key: KeyLocation,
    /// Parent CA's ca_id and certificate SHA-256 (None for a root).
    pub parent: Option<String>,
    pub parent_certificate_sha256: Option<String>,
    /// Profiles this CA may issue.
    pub allowed_profiles: Vec<IssueProfile>,
    /// Next cRLNumber to use.
    pub next_crl_number: u64,
    /// `random-128` (production) or `seeded` (lab).
    pub serial_policy: String,
    /// [`RAKVOR_POLICY_INTERNAL`] (or [`RAKVOR_POLICY_LAB`]).
    pub policy_oid: String,
    pub created_utc: String,
    pub created_by: String,
    pub tool_version: String,
    /// CRL distribution point URL written into every certificate this CA issues (cRLDistributionPoints), when set.
    /// Configured by editing ca.json (added by agent B; absent = no CDP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_url: Option<String>,
}

/// Certificate profiles of `pki issue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueProfile {
    /// CA:TRUE, pathlen 0, keyCertSign+cRLSign.
    Intermediate,
    /// digitalSignature, EKU codeSigning (release signing of Rakvor tools).
    CodeSigning,
    /// Examiner's report-signing .p12: digitalSignature+nonRepudiation, EKU documentSigning (1.3.6.1.5.5.7.3.36)
    /// + emailProtection.
    Examiner,
    /// Test TSA: digitalSignature, EKU timeStamping (critical).
    Tsa,
    /// TLS server: digitalSignature(+keyEncipherment for RSA), EKU serverAuth, SAN required.
    TlsServer,
    /// Client certificates with the "internal use" statement. DISABLED until the CP/CPS exists (v0.2).
    ClientInternal,
}

impl IssueProfile {
    pub const ALL: [IssueProfile; 6] = [
        IssueProfile::Intermediate,
        IssueProfile::CodeSigning,
        IssueProfile::Examiner,
        IssueProfile::Tsa,
        IssueProfile::TlsServer,
        IssueProfile::ClientInternal,
    ];
    pub fn name(&self) -> &'static str {
        match self {
            IssueProfile::Intermediate => "intermediate",
            IssueProfile::CodeSigning => "code-signing",
            IssueProfile::Examiner => "examiner",
            IssueProfile::Tsa => "tsa",
            IssueProfile::TlsServer => "tls-server",
            IssueProfile::ClientInternal => "client-internal",
        }
    }
    /// False for `client-internal` in v0.1 (needs the CP/CPS reviewed by the lawyer, rv-hub #4).
    pub fn enabled(&self) -> bool {
        !matches!(self, IssueProfile::ClientInternal)
    }
    pub fn parse(s: &str) -> CertResult<IssueProfile> {
        let t = s.trim().to_ascii_lowercase();
        IssueProfile::ALL
            .into_iter()
            .find(|p| p.name() == t)
            .ok_or_else(|| {
                CertError::new(
                    ErrorKind::InvalidInput,
                    format!("unknown profile '{s}': use intermediate, code-signing, examiner, tsa, tls-server or client-internal"),
                )
            })
    }
}

/// Subject of a new certificate or CSR.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectSpec {
    /// (attribute short name, value) in order: `[("C","CO"),("O","Rakvor"),("CN","Ana Ruiz")]`.
    pub rdns: Vec<(String, String)>,
    pub sans: Vec<GeneralName>,
}

/// RFC 5280 CRLReason names accepted by `pki revoke --reason`.
pub const REVOCATION_REASONS: [&str; 9] = [
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "privilegeWithdrawn",
    "aACompromise",
];

/// One line of `issued.jsonl`. Hash-chained exactly like audit.jsonl: `entry_hash` = SHA-256 (hex) of the
/// canonical JSON of the record without `entry_hash` (keys sorted, no whitespace, UTF-8), `prev_entry_hash` = the
/// previous line's `entry_hash` (64 zeros for the first).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedRecord {
    pub seq: u64,
    pub ts_utc: String,
    /// `ca_created` | `ca_imported` | `issued` | `revoked` | `crl_issued` | `ocsp_signed`
    pub action: String,
    pub ca_id: String,
    pub serial_hex: Option<String>,
    pub profile: Option<IssueProfile>,
    pub subject: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub cert_sha256: Option<String>,
    /// Relative to the CA folder (`certs/<serial>.crt`, `crl/<n>.crl`, `ocsp/<serial>-<time>.der`).
    pub file: Option<String>,
    pub file_sha256: Option<String>,
    /// revoked: reason name and time.
    pub reason: Option<String>,
    pub revoked_at: Option<String>,
    /// crl_issued: cRLNumber.
    pub crl_number: Option<u64>,
    /// Where the subject key lives (examiner .p12, token key), never the key.
    pub key: Option<KeyLocation>,
    pub actor: String,
    pub tool_version: String,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}

#[derive(Clone, Debug)]
pub struct InitRootRequest {
    pub ca_dir: PathBuf,
    pub ca_id: String,
    pub subject: SubjectSpec,
    pub key_spec: KeySpec,
    pub key_target: KeyTarget,
    pub validity_days: u32,
    /// Must be true when `key_target` is a token (`--confirm-root`); refused (ErrorKind::Policy) otherwise.
    pub confirm_root: bool,
    pub actor: String,
}

#[derive(Clone, Debug)]
pub struct ImportCaRequest {
    pub ca_dir: PathBuf,
    pub ca_id: String,
    /// The CA certificate (PEM or DER), e.g. packaging/signing/rakvor-code-signing-root.cer.
    pub certificate: Vec<u8>,
    /// Where its private key is (offline key file or token key); checked to match the certificate.
    pub key: KeyLocation,
    pub unlock: KeyUnlock,
    pub actor: String,
}

#[derive(Clone, Debug)]
pub struct IssueRequest {
    pub ca_dir: PathBuf,
    pub ca_unlock: KeyUnlock,
    pub profile: IssueProfile,
    pub subject: SubjectSpec,
    /// Either a CSR (its key and subject are used; `subject` overrides when non-empty)...
    pub csr_der: Option<Vec<u8>>,
    /// ...or a new key generated here.
    pub key_spec: Option<KeySpec>,
    pub key_target: Option<KeyTarget>,
    /// Examiner profile: also write `<serial>.p12` protected by this password.
    pub p12_password: Option<Secret>,
    pub validity_days: u32,
    pub actor: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueResult {
    pub record: IssuedRecord,
    pub cert_path: PathBuf,
    pub key: Option<KeyLocation>,
    pub p12_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct RevokeRequest {
    pub ca_dir: PathBuf,
    pub serial_hex: String,
    /// One of [`REVOCATION_REASONS`].
    pub reason: String,
    /// Default: now.
    pub revoked_at: Option<String>,
    pub actor: String,
}

#[derive(Clone, Debug)]
pub struct CrlRequest {
    pub ca_dir: PathBuf,
    pub ca_unlock: KeyUnlock,
    /// Default: now.
    pub this_update: Option<String>,
    pub next_update_days: u32,
    pub actor: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlResult {
    pub record: IssuedRecord,
    pub path: PathBuf,
    pub crl_number: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct OcspSignRequest {
    pub ca_dir: PathBuf,
    pub ca_unlock: KeyUnlock,
    pub serial_hex: String,
    /// producedAt / thisUpdate (lab: fixed times). Default: now.
    pub produced_at: Option<String>,
    pub next_update_days: Option<u32>,
    pub out: PathBuf,
    pub actor: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcspSignResult {
    pub record: IssuedRecord,
    pub path: PathBuf,
    pub status: RevocationStatus,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct CsrRequest {
    pub subject: SubjectSpec,
    pub key_spec: KeySpec,
    pub key_target: KeyTarget,
    /// Where the CSR (PEM) is written; never overwritten.
    pub out: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrResult {
    pub csr_path: PathBuf,
    pub key: KeyLocation,
    pub csr: CsrInfo,
}

// ------------------------------------------------------------------------------------------------------------
// Lab sets
// ------------------------------------------------------------------------------------------------------------

/// The cases a full lab set contains (plan v0.1). A set may hold several cases of one kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LabCaseKind {
    ValidChain,
    Expired,
    NotYetValid,
    RevokedByCrl,
    RevokedByOcsp,
    WrongRoot,
    Rsa1024,
    Sha1Signed,
    Md5Signed,
    BadEku,
    NameConstraintViolation,
    BrokenSignature,
    KeyMismatch,
}

impl LabCaseKind {
    pub const ALL: [LabCaseKind; 13] = [
        LabCaseKind::ValidChain,
        LabCaseKind::Expired,
        LabCaseKind::NotYetValid,
        LabCaseKind::RevokedByCrl,
        LabCaseKind::RevokedByOcsp,
        LabCaseKind::WrongRoot,
        LabCaseKind::Rsa1024,
        LabCaseKind::Sha1Signed,
        LabCaseKind::Md5Signed,
        LabCaseKind::BadEku,
        LabCaseKind::NameConstraintViolation,
        LabCaseKind::BrokenSignature,
        LabCaseKind::KeyMismatch,
    ];
}

/// `lab make --set NAME --seed N`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabSetSpec {
    /// `full` (every [`LabCaseKind`]) or `minimal` (valid-chain, expired, revoked-by-crl, key-mismatch).
    pub name: String,
    pub seed: u64,
    /// Reference instant every validity period is derived from, so output is byte-identical for a seed
    /// (default `2026-01-01T00:00:00Z`; never the wall clock).
    pub base_time: String,
    pub out_dir: PathBuf,
}

/// Validation settings a lab case expects `analyze` to be run with (mirrors the CLI options).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LabValidation {
    /// Relative to the set folder.
    pub anchors: Vec<String>,
    pub at: String,
    pub purpose: Purpose,
    pub crls: Vec<String>,
    pub ocsp: Vec<String>,
}

/// One case of a lab set, as written to `expected_findings.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabCase {
    /// `valid-chain`, `expired`, ... (unique in the set; a folder of that name holds the files).
    pub id: String,
    pub kind: LabCaseKind,
    pub description: String,
    /// Files of the case relative to the set folder; the first one is the item to analyse.
    pub files: Vec<String>,
    pub validation: LabValidation,
    /// Finding codes `analyze` must report for the first file (others may also appear unless listed below).
    pub expected_codes: Vec<String>,
    /// Codes that must NOT appear (e.g. CERT_CHAIN_VALID for a broken signature).
    #[serde(default)]
    pub forbidden_codes: Vec<String>,
    /// What `openssl verify` (with the same -attime/-purpose/-CRLfile) must answer: 0 for OK, else the X509_V code.
    pub openssl_verify_code: i32,
}

/// `expected_findings.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabSetManifest {
    /// [`LAB_SET_SCHEMA`]
    pub schema: String,
    pub set: String,
    pub seed: u64,
    pub base_time: String,
    pub tool_version: String,
    pub cases: Vec<LabCase>,
    /// SHA-256 of every file written, relative path → hex (sorted).
    pub files: BTreeMap<String, String>,
}

// ------------------------------------------------------------------------------------------------------------
// PKCS#11
// ------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKeyInfo {
    pub key_id_hex: String,
    pub label: Option<String>,
    pub key: KeyInfo,
    /// A certificate object with the same CKA_ID, if any.
    pub certificate_subject: Option<String>,
}

/// One slot of `tokens list`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    pub slot_id: u64,
    pub slot_description: String,
    pub token_present: bool,
    pub label: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub login_required: bool,
    /// Public keys visible without login (filled when listed after login).
    pub keys: Vec<TokenKeyInfo>,
}

// ------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers_accept_the_documented_values() {
        assert_eq!(
            AtTime::parse("2026-06-01").unwrap(),
            AtTime::Fixed("2026-06-01T00:00:00Z".into())
        );
        assert_eq!(
            AtTime::parse("2026-06-01T14:00:00+02:00").unwrap(),
            AtTime::Fixed("2026-06-01T12:00:00Z".into())
        );
        assert_eq!(AtTime::parse("now").unwrap(), AtTime::Now);
        assert_eq!(AtTime::parse("signing-time").unwrap(), AtTime::SigningTime);
        assert!(AtTime::parse("yesterday").is_err());
        for p in Purpose::ALL {
            assert_eq!(Purpose::parse(p.name()).unwrap(), p);
        }
        assert!(Purpose::parse("ssl").is_err());
        assert_eq!(AnchorSpec::parse("rakvor").unwrap(), AnchorSpec::Rakvor);
        assert_eq!(
            AnchorSpec::parse("tl:eu@eu-20261103T101500Z-1a2b3c4d").unwrap(),
            AnchorSpec::TrustList {
                list: TrustListKind::Eu,
                snapshot: "eu-20261103T101500Z-1a2b3c4d".into()
            }
        );
        assert_eq!(
            AnchorSpec::parse("tl:co").unwrap(),
            AnchorSpec::TrustList {
                list: TrustListKind::Co,
                snapshot: "latest".into()
            }
        );
        assert!(AnchorSpec::parse("tl:us@x").is_err());
        assert!(matches!(
            AnchorSpec::parse("roots/ca.pem").unwrap(),
            AnchorSpec::File { .. }
        ));
        for k in KeySpec::ALL {
            assert_eq!(KeySpec::parse(k.name()).unwrap(), k);
        }
        assert_eq!(KeySpec::parse("P256").unwrap(), KeySpec::P256);
        for p in IssueProfile::ALL {
            assert_eq!(IssueProfile::parse(p.name()).unwrap(), p);
        }
        assert!(!IssueProfile::ClientInternal.enabled());
    }

    #[test]
    fn secrets_never_print_and_errors_say_not_implemented() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{:?}", s), "Secret(***)");
        let e = CertError::not_implemented("sniff");
        assert!(e.is_not_implemented());
        assert_eq!(e.to_string(), "not implemented: sniff");
        assert_eq!(codes::severity(codes::CERT_REVOKED), Some("high"));
        assert!(RAKVOR_POLICY_INTERNAL.starts_with(RAKVOR_OID_ARC));
        assert!(RAKVOR_POLICY_LAB.starts_with(RAKVOR_OID_ARC));
    }

    #[test]
    fn serialized_names_are_stable() {
        let v = serde_json::to_value(RevocationStatus::Revoked {
            reason: "keyCompromise".into(),
            revoked_at: "2026-02-01T00:00:00Z".into(),
            source: RevocationSource::default(),
        })
        .unwrap();
        assert_eq!(v["status"], "revoked");
        assert_eq!(
            serde_json::to_value(KeyLocation::Pkcs11 {
                module: "m".into(),
                token_serial: "1".into(),
                token_label: None,
                key_id_hex: "01".into(),
                key_label: None
            })
            .unwrap()["type"],
            "pkcs11"
        );
        assert_eq!(
            serde_json::to_value(IssueProfile::CodeSigning).unwrap(),
            "code-signing"
        );
        for k in KeySpec::ALL {
            assert_eq!(serde_json::to_value(k).unwrap(), k.name());
        }
        assert_eq!(
            serde_json::to_value(InputKind::TimestampToken).unwrap(),
            "timestamp_token"
        );
        assert_eq!(
            serde_json::to_value(Sniffed::default()).unwrap()["kind"],
            "unknown"
        );
        assert_eq!(
            serde_json::to_value(LabCaseKind::NameConstraintViolation).unwrap(),
            "name-constraint-violation"
        );
        let c = CertInfo {
            der: vec![1, 2, 3],
            ..Default::default()
        };
        assert!(serde_json::to_value(&c).unwrap().get("der").is_none());
    }
}
