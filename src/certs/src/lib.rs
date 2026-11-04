//! RV CertCheck certificate layer: analysis of certificates and other cryptographic evidence (agent A) and
//! creation of Rakvor's internal PKI, CSRs, lab sets and PKCS#11 keys (agent B). The core
//! (`rv_certcheck_core::certscan`) calls it per item, maps every [`Signal`] to a finding and writes `chain.json`
//! and `certificate.txt` into the item's report folder. No unsafe code; OpenSSL 3 (vendored) through the
//! `openssl` crate does path validation, CMS, OCSP, CRL and PKCS#12.
//!
//! ```text
//! analysis   (agent A)  bytes ─► sniff ─► parse_any ─► ParsedInput (CertInfo, CRL, OCSP, TST, key facts, CSR)
//!                       ChainRequest + ValidationOptions ─► validate_chain ─► ChainVerdict (per-depth OpenSSL codes)
//!                       check_revocation, verify_timestamp_token, match_key, certificate_text, resolve_anchors
//!                       trust_list::{import_eu, import_co_csv, load, list, lookup}
//! creation   (agent B)  pki::{init_root, import_ca, open, issue, revoke, make_crl, sign_ocsp}
//!                       csr::{new, show}   lab::make   tokens::{list, generate_key, open}
//! ```
//!
//! FROZEN API: the signatures in this file do not change (arguments are request structs from `model.rs`, which may
//! gain defaulted fields). Each function below is a thin facade over the owning agent's module; every stub returns
//! `CertError { kind: NotImplemented, message: "not implemented: <operation>" }` until implemented.
//!
//! FILE OWNERSHIP (two agents work in parallel and never edit the same file):
//! ```text
//! ARCHITECT (frozen; change only by agreement):  src/certs/Cargo.toml, src/certs/src/lib.rs, src/certs/src/model.rs,
//!                                                 i18n/*.json, src/core/** (certscan.rs glue), Cargo.toml (workspace)
//! AGENT A (analysis + trust lists):              src/certs/src/analysis/**, src/certs/src/trustlist/**,
//!                                                 src/certs/tests/analysis_*.rs (own extra tests)
//! AGENT B (PKI, CSR, lab sets, PKCS#11):         src/certs/src/create/** (pki, csr, lab, tokens, keys...),
//!                                                 src/certs/tests/create_*.rs (own extra tests)
//! ACCEPTANCE (architect; make pass, never weaken): src/certs/tests/acceptance_analysis.rs (A),
//!                                                 src/certs/tests/acceptance_creation.rs (B),
//!                                                 src/cli/tests/analyze_sample.rs + examples/sample/expected_findings.json (A)
//! INDEPENDENT ORACLE (nobody's code calls it):    tests/fixtures/make_with_openssl.sh (OpenSSL CLI only) and its
//!                                                 output tests/fixtures/openssl/** (openssl-verify.tsv)
//! ```
//! A needs B (or B needs A): call the other side only through the public functions of this file. A new finding
//! code goes through the architect (model.rs `codes` + i18n), never directly into i18n/*.json.

#![forbid(unsafe_code)]

pub mod model;

mod analysis;
mod create;
mod trustlist;

pub use model::*;
use std::path::{Path, PathBuf};

/// The Rakvor internal root shipped with the tool (`packaging/signing/rakvor-code-signing-root.cer`, DER):
/// `--anchor rakvor`.
pub const RAKVOR_ROOT_DER: &[u8] =
    include_bytes!("../../../packaging/signing/rakvor-code-signing-root.cer");

/// OpenSSL as linked (`OpenSSL 3.6.3 9 Jun 2026`), for environment.json and every ChainVerdict.
pub fn openssl_version() -> &'static str {
    openssl::version::version()
}

// ------------------------------------------------------------------------------------------------------------
// Analysis (agent A)
// ------------------------------------------------------------------------------------------------------------

/// What the bytes are (by content, never by extension). Must not fail on hostile input: anything unrecognised is
/// `InputKind::Unknown` with `Ok`. Tested against every file of tests/fixtures/openssl and a lab set.
pub fn sniff(data: &[u8]) -> CertResult<Sniffed> {
    // OWNER: A
    analysis::sniff::sniff(data)
}

/// Parses any supported input. `password` opens a PKCS#12 or an encrypted key (never logged, never stored);
/// without it a PKCS#12 still yields its unencrypted certificates, or `PKCS12_UNREADABLE` in `signals`.
/// Parse-time signals (weak key, weak signature algorithm, self-signed, Rakvor internal policy) are filled here.
pub fn parse_any(data: &[u8], password: Option<&Secret>) -> CertResult<ParsedInput> {
    // OWNER: A
    analysis::parse::parse_any(data, password)
}

/// OpenSSL-style text dump of one certificate (`openssl x509 -text -noout` equivalent: `X509::to_text`), written
/// by core to the item's `certificate.txt`.
pub fn certificate_text(der: &[u8]) -> CertResult<String> {
    // OWNER: A
    analysis::text::certificate_text(der)
}

/// Turns `--anchor` values into trusted certificates, once per run. `trust_list_dir` = where snapshots are stored
/// (None = [`trust_list::default_store_dir`]). `File` anchors accept PEM, DER and PKCS#7.
pub fn resolve_anchors(
    specs: &[AnchorSpec],
    trust_list_dir: Option<&Path>,
) -> CertResult<Vec<ResolvedAnchor>> {
    // OWNER: A
    analysis::anchors::resolve_anchors(specs, trust_list_dir)
}

/// Builds and verifies the path of `req.target_der` with OpenSSL's verifier (X509_STORE_CTX with a callback
/// that records every error and continues), at `opts.at`, for `opts.purpose`, with revocation from `req.crls` /
/// `req.ocsp`, and returns one [`ChainNode`] per depth with OpenSSL's code and text. Signals carry `subject`.
/// Oracle: `openssl verify -attime -purpose -CRLfile -untrusted` on the same inputs gives the same first code.
pub fn validate_chain(req: &ChainRequest, opts: &ValidationOptions) -> CertResult<ChainVerdict> {
    // OWNER: A
    analysis::chain::validate_chain(req, opts)
}

/// Revocation state of `cert_der` (issued by `issuer_der`) at `at` (RFC 3339) from the given CRLs and OCSP
/// responses (signatures checked against the issuer or a delegated responder). No source covering the
/// certificate → `Unknown { source }`. Oracle: `openssl crl`, `openssl ocsp -respin`.
pub fn check_revocation(
    cert_der: &[u8],
    issuer_der: &[u8],
    crls: &[LabeledDer],
    ocsp: &[LabeledDer],
    at: &str,
) -> CertResult<RevocationStatus> {
    // OWNER: A
    analysis::revocation::check_revocation(cert_der, issuer_der, crls, ocsp, at)
}

/// Verifies an RFC 3161 TimeStampResp or TimeStampToken: CMS signature, ESS signing-certificate, the TSA
/// certificate's chain at genTime for purpose timestamping (anchors and untrusted from `req`, `req.target_der`
/// ignored), and — when `data` is given — that its digest equals the message imprint.
/// Oracle: `openssl ts -verify`.
pub fn verify_timestamp_token(
    token: &[u8],
    data: Option<&[u8]>,
    req: &ChainRequest,
    opts: &ValidationOptions,
) -> CertResult<TimestampVerdict> {
    // OWNER: A
    analysis::timestamp::verify_timestamp_token(token, data, req, opts)
}

/// Whether the private key in `key` (PEM/DER, PKCS#8/PKCS#1/SEC1, or a PKCS#12) is the key of `cert_der`. The key
/// is used in memory only and never copied, logged or returned. Oracle: compare `openssl pkey -pubout` with
/// `openssl x509 -pubkey`.
pub fn match_key(key: &[u8], password: Option<&Secret>, cert_der: &[u8]) -> CertResult<KeyMatch> {
    // OWNER: A
    analysis::keymatch::match_key(key, password, cert_der)
}

/// Trust-list snapshots: EU LOTL/TL XML and the curated Colombian CSV, stored dated and hashed.
pub mod trust_list {
    use super::*;

    /// `%LOCALAPPDATA%\Rakvor\rv-certcheck\trust-lists` on Windows, `$XDG_DATA_HOME/rakvor/rv-certcheck/trust-lists`
    /// (or `~/.local/share/...`) elsewhere. `RV_CERTCHECK_DATA` overrides the base folder (tests, portable use).
    pub fn default_store_dir() -> PathBuf {
        // OWNER: architect (implemented)
        crate::data_dir().join("trust-lists")
    }

    /// Imports an EU LOTL or national TL (ETSI TS 119 612 XML) into `store_dir` as a [`TrustListSnapshot`]
    /// (`<store>/eu/<id>.json`). `source` = `file:<path>` or `url:<url>`; `fetched_utc` is passed in so tests are
    /// deterministic. The XML's XAdES signature is NOT verified in v0.1 (`signature_verified = false`).
    pub fn import_eu(
        xml: &[u8],
        source: &str,
        fetched_utc: &str,
        store_dir: &Path,
    ) -> CertResult<TrustListSnapshot> {
        // OWNER: A
        crate::trustlist::eu::import_eu(xml, source, fetched_utc, store_dir)
    }

    /// Imports the curated Colombian CSV (format in docs/trust-lists.md: ecd_name, service_name, service_type,
    /// status, status_from, status_until, certificate_pem_or_b64, source_url, checked_utc) into `store_dir`.
    pub fn import_co_csv(
        csv: &[u8],
        source: &str,
        fetched_utc: &str,
        store_dir: &Path,
    ) -> CertResult<TrustListSnapshot> {
        // OWNER: A
        crate::trustlist::co::import_co_csv(csv, source, fetched_utc, store_dir)
    }

    /// Loads a stored snapshot (`latest` = newest of that list); verifies its recorded SHA-256 of the JSON file.
    pub fn load(store_dir: &Path, list: TrustListKind, id: &str) -> CertResult<TrustListSnapshot> {
        // OWNER: A
        crate::trustlist::store::load(store_dir, list, id)
    }

    /// Every stored snapshot, newest first.
    pub fn list(store_dir: &Path) -> CertResult<Vec<TrustListSummary>> {
        // OWNER: A
        crate::trustlist::store::list(store_dir)
    }

    /// The service of `snapshot` whose identity is `cert` (by SHA-256, else by subject + SKI) and its status at
    /// `at` (RFC 3339).
    pub fn lookup(
        snapshot: &TrustListSnapshot,
        cert: &CertInfo,
        at: &str,
    ) -> Option<TrustListMatch> {
        // OWNER: A
        crate::trustlist::store::lookup(snapshot, cert, at)
    }
}

// ------------------------------------------------------------------------------------------------------------
// Creation (agent B)
// ------------------------------------------------------------------------------------------------------------

/// Rakvor's internal CA folders (`rakvor.ca/1`). Every operation appends a hash-chained [`IssuedRecord`] to
/// `issued.jsonl`; key files are written owner-only and never overwritten; secrets are never logged. Every
/// certificate carries [`RAKVOR_POLICY_INTERNAL`] with [`RAKVOR_INTERNAL_NOTICE`] as user notice.
pub mod pki {
    use super::*;

    /// Creates an offline root CA in an empty `req.ca_dir`. Token key only with `req.confirm_root`.
    pub fn init_root(req: &InitRootRequest) -> CertResult<CaFolder> {
        // OWNER: B
        crate::create::pki::init_root(req)
    }

    /// Brings an existing CA certificate + its key (file or token) under management (e.g. the code-signing root).
    /// Refused when the key does not match the certificate.
    pub fn import_ca(req: &ImportCaRequest) -> CertResult<CaFolder> {
        // OWNER: B
        crate::create::pki::import_ca(req)
    }

    /// Reads `ca.json` and verifies the `issued.jsonl` chain (a broken chain is an error: nothing is issued).
    pub fn open(ca_dir: &Path) -> CertResult<CaFolder> {
        // OWNER: B
        crate::create::pki::open(ca_dir)
    }

    /// Issues one certificate with a profile (refuses `client-internal` in v0.1 with ErrorKind::Policy).
    pub fn issue(req: &IssueRequest) -> CertResult<IssueResult> {
        // OWNER: B
        crate::create::pki::issue(req)
    }

    /// Marks an issued serial revoked (recorded; takes effect in the next CRL / OCSP response).
    pub fn revoke(req: &RevokeRequest) -> CertResult<IssuedRecord> {
        // OWNER: B
        crate::create::pki::revoke(req)
    }

    /// Signs a CRL with every revoked serial (`crl/<number>.crl` + `crl/latest.crl`).
    pub fn make_crl(req: &CrlRequest) -> CertResult<CrlResult> {
        // OWNER: B
        crate::create::pki::make_crl(req)
    }

    /// Signs one OCSP response for a serial at a given time (lab use; there is no OCSP server).
    pub fn sign_ocsp(req: &OcspSignRequest) -> CertResult<OcspSignResult> {
        // OWNER: B
        crate::create::pki::sign_ocsp(req)
    }
}

/// PKCS#10 requests for a public or qualified CA.
pub mod csr {
    use super::*;

    /// New key (token or encrypted file) + CSR with the subject and SANs.
    pub fn new(req: &CsrRequest) -> CertResult<CsrResult> {
        // OWNER: B
        crate::create::csr::new(req)
    }

    /// Displays a CSR (PEM or DER) and checks its self-signature.
    pub fn show(data: &[u8]) -> CertResult<CsrInfo> {
        // OWNER: B
        crate::create::csr::show(data)
    }
}

/// Reproducible lab and test sets.
pub mod lab {
    use super::*;

    /// Writes the set under `spec.out_dir` (must be empty or missing) and its `expected_findings.json`.
    /// Byte-identical for the same name, seed and base time: seeded ChaCha20 keys, deterministic signatures
    /// (RSA PKCS#1 v1.5, Ed25519), serials from the seed, times from `base_time`, sorted file lists.
    pub fn make(spec: &LabSetSpec) -> CertResult<LabSetManifest> {
        // OWNER: B
        crate::create::lab::make(spec)
    }
}

/// PKCS#11 tokens (YubiKey via ykcs11, SoftHSM2 in CI). PINs only in [`Secret`].
pub mod tokens {
    use super::*;
    pub use crate::create::tokens::TokenSession;

    /// Slots and tokens of `module` (no login).
    pub fn list(module: &Path) -> CertResult<Vec<TokenInfo>> {
        // OWNER: B
        crate::create::tokens::list(module)
    }

    /// Generates a non-extractable key pair on the token. `confirm_root` is recorded with the key (CKA_LABEL
    /// suffix / audit); the refusal of a root key without `--confirm-root` is enforced by `pki::init_root`.
    pub fn generate_key(
        module: &Path,
        token_serial: &str,
        pin: &Secret,
        spec: KeySpec,
        label: &str,
        confirm_root: bool,
    ) -> CertResult<KeyLocation> {
        // OWNER: B
        crate::create::tokens::generate_key(module, token_serial, pin, spec, label, confirm_root)
    }

    /// Logs in to the token with that serial and returns a session for signing (used by pki for token keys).
    pub fn open(module: &Path, token_serial: &str, pin: &Secret) -> CertResult<TokenSession> {
        // OWNER: B
        crate::create::tokens::open(module, token_serial, pin)
    }
}

// ------------------------------------------------------------------------------------------------------------

/// Base data folder of the tool (trust-list snapshots). `RV_CERTCHECK_DATA` overrides it.
pub(crate) fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("RV_CERTCHECK_DATA").filter(|d| !d.is_empty()) {
        return PathBuf::from(d);
    }
    if cfg!(windows) {
        if let Some(d) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(d).join("Rakvor").join("rv-certcheck");
        }
    } else {
        if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
            return PathBuf::from(d).join("rakvor").join("rv-certcheck");
        }
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h)
                .join(".local")
                .join("share")
                .join("rakvor")
                .join("rv-certcheck");
        }
    }
    PathBuf::from("rakvor-data").join("rv-certcheck")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssl_is_the_vendored_3x() {
        assert!(
            openssl_version().starts_with("OpenSSL 3."),
            "{}",
            openssl_version()
        );
    }

    #[test]
    fn bundled_rakvor_root_is_der() {
        assert_eq!(RAKVOR_ROOT_DER.first(), Some(&0x30));
        assert!(openssl::x509::X509::from_der(RAKVOR_ROOT_DER).is_ok());
    }

    /// Both sides are implemented: no facade answers NotImplemented any more (empty or missing inputs give a
    /// real error or a result).
    #[test]
    fn nothing_is_a_stub() {
        fn ni<T: std::fmt::Debug>(r: CertResult<T>) -> bool {
            !matches!(r, Err(e) if e.is_not_implemented())
        }
        let d = Path::new("does-not-exist");
        // Both agents' lines removed: nothing is a stub any more, so no call may answer NotImplemented.
        let opts = ValidationOptions::default();
        let req = ChainRequest::default();
        assert!(ni(sniff(b"")));
        assert!(ni(parse_any(b"", None)));
        assert!(ni(certificate_text(b"")));
        assert!(ni(resolve_anchors(&[], None)));
        assert!(ni(validate_chain(&req, &opts)));
        assert!(ni(check_revocation(
            b"",
            b"",
            &[],
            &[],
            "2026-01-01T00:00:00Z"
        )));
        assert!(ni(verify_timestamp_token(b"", None, &req, &opts)));
        assert!(ni(match_key(b"", None, b"")));
        assert!(ni(trust_list::list(d)));
        assert!(ni(pki::open(d)));
        assert!(ni(csr::show(b"")));
        assert!(ni(tokens::list(d)));
    }
}
