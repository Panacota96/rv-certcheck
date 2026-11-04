//! rv-certcheck command-line interface. All work happens in `rv_certcheck_core` and the certificate layer
//! (`rv_certcheck_certs`); this file only parses arguments, renders events (progress bar or JSON Lines) and maps
//! results to exit codes. The creation commands (pki, csr, lab, keys, tokens, trust-list) live in `commands.rs`.

mod commands;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rv_certcheck_core::certs::{AnchorSpec, AtTime, Purpose, Secret, ValidationOptions};
use rv_certcheck_core::trust::{self, DEFAULT_TSA};
use rv_certcheck_core::{
    CASE_ROLE, CertOptions, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, audit, case, hash,
    i18n, run, verify,
};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FINDINGS: u8 = 3;
const EXIT_CANCELLED: u8 = 130;

const ABOUT: &str = "Analyze certificates and other cryptographic evidence (chains, revocation, timestamps, keys) and create Rakvor's internal certificates, with court-ready reports and a tamper-evident audit log.";

const LONG_ABOUT: &str = "\
DESCRIPTION:
  rv-certcheck analyzes a single file, a whole folder (bulk) or a list of files. For every file it:
    1. opens the file read-only and hashes it in one pass with one or two algorithms;
    2. recognises its content (not its extension): certificate, PEM bundle, PKCS#7, PKCS#12, CRL,
       OCSP response, RFC 3161 timestamp token, private key or CSR;
    3. reads every certificate field, builds and checks each chain with OpenSSL at the date and for the
       purpose chosen (--at, --purpose) against the anchors chosen (--anchor), checks revocation with the
       CRLs and OCSP responses supplied, verifies timestamp tokens and matches keys to certificates;
    4. writes chain.json and certificate.txt, a technical report and a customer-friendly summary.
  Each run also writes a statistics report and an audit trail under <OUT>/logs/<RUN-ID>/.
  Every action is appended to a hash-chained log that `rv-certcheck verify-log` can check later.
  Offline by default: nothing is fetched from the network.

  CASE FOLDER (--case-dir): Rakvor tools share one folder per case. rv-certcheck is an analysis tool: it
  verifies every item against the registry written at intake (evidence ids E0001, E0002, ...), so the
  report shows it examined bit-identical copies. `rv-certcheck verify-case <CASE>` checks it all.

  CREATION: pki, csr, lab, keys and tokens create Rakvor's internal certificates (internal use only:
  not a firma digital under Ley 527 de 1999 art. 28, not qualified under eIDAS), CSRs, reproducible
  lab sets and PKCS#11 keys; trust-list imports EU and Colombian trust lists as dated snapshots.";

const ANALYZE_AFTER_HELP: &str = "\
EXAMPLES:
  Analyze one certificate against a root you trust, today, for any purpose:
    rv-certcheck analyze --input evidence/signer.cer --anchor roots/ca-root.pem
  A folder of certificates, CRLs and tokens, judged at the signing date, for document signing:
    rv-certcheck analyze -i D:\\evidence -r --anchor roots/ca-root.pem --at 2025-03-14 --purpose document-signing
  With revocation information supplied offline, Spanish reports, case CASE-2026-014:
    rv-certcheck analyze -i D:\\evidence --anchor roots/ca-root.pem --crl ca.crl --ocsp leaf.ocsp --lang es --case CASE-2026-014
  Against the EU trust list snapshot imported earlier (rv-certcheck trust-list import):
    rv-certcheck analyze -i D:\\evidence --anchor tl:eu@latest
  Verify the audit log afterwards:
    rv-certcheck verify-log rakvor-out/logs/<RUN-ID>/audit.jsonl
  Analyze the evidence registered in a case folder (intake by rv-hashinv), then verify the whole case:
    rv-certcheck analyze --case-dir E:\\CASE-014 --anchor roots/ca-root.pem
    rv-certcheck verify-case E:\\CASE-014
  Re-examine two registered items of the case:
    rv-certcheck analyze --case-dir E:\\CASE-014 --evidence E0001,E0002

EXIT CODES:
  0    Completed; no high-severity finding.
  1    Runtime error (input not found, output not writable, case log locked, ...).
       See the audit log.
  2    Usage error (unknown option, more than two hash algorithms, unsupported language, bad
       --anchor/--at/--purpose value).
       With --case-dir: folder of another case or schema, --case missing when creating the
       case, unknown evidence id.
  3    Completed with at least one high-severity finding (e.g. untrusted or invalid chain, revoked
       or expired certificate, key that does not match, invalid timestamp token, evidence that
       differs from the case registry), or the case folder fails verification (nothing is
       written to it).
  130  Cancelled with Ctrl+C. Partial reports and the cancellation are written to the audit log.

FILES WRITTEN:
  <OUT>/logs/<RUN-ID>/audit.jsonl         Hash-chained log of every action (one JSON object per line).
  <OUT>/logs/<RUN-ID>/audit.log           The same actions, human-readable.
  <OUT>/logs/<RUN-ID>/hashes.csv          Hash register: index, path, size, digests, status.
  <OUT>/logs/<RUN-ID>/environment.json    Tool and dependency versions, OS, host, user, command line.
  <OUT>/reports/<RUN-ID>/statistics.json  Run statistics (+ statistics.<LANG>.html and .pdf).
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/chain.json        Chain per end-entity certificate, per-depth
                                                                OpenSSL code and reason, revocation, trust list.
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/certificate.txt   OpenSSL-style dump of every certificate.
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/technical.json|.<LANG>.html|.<LANG>.pdf   Technical review.
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/summary.json|.<LANG>.html|.<LANG>.pdf     Customer summary.
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/custody.json|.<es|fr>.html|.pdf|.en.html|.pdf  Custody form.
  <OUT>/logs/<RUN-ID>/timestamp-<SEQ>.tsr|.json  RFC 3161 token for the audit chain head.
  With --case-dir <CASE>, logs/ and reports/ go to <CASE>/runs/rv-certcheck/<RUN-ID>/, plus:
  <CASE>/case.json                        Case id, jurisdiction, creation (written once).
  <CASE>/case-log.jsonl                   Hash-chained case log of every tool: case_created,
                                          run_started, evidence_registered, run_finished.
  <CASE>/evidence/registry.json|.csv      Evidence registry (written at intake): E0001..., path, hashes.

FORENSIC NOTES:
  - Evidence is opened read-only and never modified; modification times are compared before and after.
  - Work on a verified copy (write-blocked image or export), not on original media.
  - Each audit entry stores the SHA-256 of the previous one; editing, deleting or re-ordering any
    line is detected by `verify-log`. Removing the last lines is detected only against a record
    kept outside the log: the RFC 3161 timestamp or, with --case-dir, the case log. Keep the log
    folder with the reports.
  - A file without findings is not proven authentic; read the Limitations section of each report.
  - A chain is judged at one instant (--at): an expired certificate can be normal for an old
    signature, whose validity matters at signing time. Offline, revocation is only as complete as
    the CRLs and OCSP responses supplied. Private keys and passwords never reach a log or report.
  - MD5 and SHA-1 are accepted for compatibility with older case files; pair them with SHA-256 or BLAKE3.
  - The chain head is timestamped by an RFC 3161 authority (proves when the log existed). Offline? The run
    finishes with `timestamp_pending`; run `rv-certcheck timestamp <LOG>` later.
  - With --sign-cert every PDF is signed with the examiner's certificate; the password is never logged.
  - Case folder: every tool re-verifies case-log.jsonl and the registry digest before
    writing, and refuses a broken case (exit 3). Appends happen under case-log.lock; a lock
    older than 10 minutes is reported as stale and never deleted automatically.
  - Each run's audit.jsonl records case_linked (the case-log entry it started from); the case
    log records the run's final audit head, so the two chains vouch for each other.";

#[derive(Parser)]
#[command(name = TOOL_NAME, version = TOOL_VERSION, about = ABOUT, long_about = LONG_ABOUT, max_term_width = 100,
          after_long_help = "Run `rv-certcheck <COMMAND> --help` for the options, examples and exit codes of each command.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze certificates, chains, CRLs, OCSP responses, timestamp tokens, keys and CSRs.
    #[command(long_about = LONG_ABOUT, after_long_help = ANALYZE_AFTER_HELP)]
    Analyze(Box<AnalyzeArgs>),
    /// Rakvor internal PKI: init-root, import, issue, revoke, crl, ocsp-sign, show, verify.
    #[command(subcommand, after_long_help = commands::PKI_AFTER_HELP)]
    Pki(commands::PkiCommand),
    /// Certificate signing requests: new, show.
    #[command(subcommand)]
    Csr(commands::CsrCommand),
    /// Reproducible lab and test certificate sets.
    #[command(subcommand)]
    Lab(commands::LabCommand),
    /// Private keys: match a key with a certificate.
    #[command(subcommand)]
    Keys(commands::KeysCommand),
    /// PKCS#11 hardware tokens: list slots, tokens and keys.
    #[command(subcommand)]
    Tokens(commands::TokensCommand),
    /// EU and Colombian trust lists: import, list, show dated snapshots.
    #[command(subcommand, name = "trust-list")]
    TrustList(commands::TrustListCommand),
    /// Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.
    #[command(after_long_help = "\
CHECKS:
  - every entry links to the previous one (hash chain): an edited, deleted or re-ordered entry
    breaks it;
  - every timestamp token (timestamp-<SEQ>.tsr) covers the hash of the entry it names, and every
    timestamp_obtained entry still has its token file;
  - truncation: a chain alone cannot show that entries were removed from its end. The log must
    still contain the entry covered by its RFC 3161 timestamp (covers_seq) and, for a run inside
    a case folder (<CASE>/runs/<TOOL>/<RUN-ID>/logs), end with the audit head that the case log
    recorded at run_finished (only timestamp_obtained may follow). Entries after the last
    anchored one are listed as not provable; with neither record the output says
    \"truncation not detectable without a timestamp or case record\".

EXAMPLES:
  rv-certcheck verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl
  rv-certcheck verify-log rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-certcheck verify-log E:\\CASE-014\\runs\\rv-certcheck\\20261019T101500Z-a1b2c3\\logs

EXIT CODES:
  0  The chain is intact and agrees with its timestamps and case record (if any).
  1  The log cannot be read.
  3  The chain is broken (an entry was edited, deleted or re-ordered), a timestamp does not
     match, or the log is shorter than its timestamp or case record says (truncated).")]
    VerifyLog {
        /// Path to audit.jsonl, or to the run's log folder that contains it.
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
    },
    /// Check every hash algorithm against known-answer test vectors.
    #[command(after_long_help = "\
EXAMPLES:
  rv-certcheck self-test

EXIT CODES:
  0  All algorithms give the published answer for the input \"abc\".
  1  At least one algorithm failed: do not use this build for evidence.")]
    SelfTest,
    /// Add an RFC 3161 timestamp to a finished run (e.g. after working offline).
    #[command(after_long_help = "\
EXAMPLES:
  rv-certcheck timestamp rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-certcheck timestamp rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-url https://freetsa.org/tsr

EXIT CODES:
  0  Timestamp obtained and logged.
  1  The TSA could not be reached (nothing changed; try again).
  3  The log is missing or broken: no timestamp is added.")]
    Timestamp {
        /// The run's log folder (or its audit.jsonl).
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// RFC 3161 time-stamping authority.
        /// Default: http://timestamp.digicert.com
        /// Example: --tsa-url https://freetsa.org/tsr
        #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
        tsa_url: String,
        /// Name written in the new audit entry.
        /// Default: the operating-system user name
        /// Example: --actor "Ana Ruiz"
        #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
        actor: Option<String>,
    },
    /// Verify a whole case folder: case log, evidence registry and every run's audit log.
    #[command(after_long_help = "\
CHECKS:
  - case-log.jsonl is an intact hash chain starting with case_created; case.json is unchanged;
  - evidence/registry.json has the SHA-256 recorded at the last registry change;
  - every run announced in the case log has an intact audit.jsonl (and valid timestamp
    tokens), its case_linked entry points to its run_started entry, and the audit head
    recorded at run_finished is its final entry (only timestamp_obtained may follow);
  - with --rehash: every registered item still reachable at its registered path is read again
    and its digests are compared with the registry (the latest registration of a path).

EXAMPLES:
  rv-certcheck verify-case E:\\CASE-014
  rv-certcheck verify-case E:\\CASE-014 --rehash

EXIT CODES:
  0  The case folder is intact (warnings, e.g. a run still in progress or an item not
     reachable for --rehash, are printed).
  1  The folder is not a case folder (no case.json).
  3  At least one check failed: the case was edited, truncated or re-ordered, or (--rehash)
     an evidence file differs from the registry.")]
    VerifyCase {
        /// The case folder (the one that holds case.json).
        ///
        /// Example: E:\CASE-014
        case: PathBuf,
        /// Also re-hash every registered item still reachable and compare it with the registry.
        /// Default: off (only the registry's digest is checked)
        /// Example: --rehash
        #[arg(long, verbatim_doc_comment)]
        rehash: bool,
    },
    /// Print the full help of every command as Markdown (used to generate docs/usage-cli.md).
    #[command(hide = true)]
    DocsCli,
    /// Describe this tool as JSON (schema rakvor.describe/1) for RV Hub and scripts.
    #[command(hide = true, after_long_help = DESCRIBE_AFTER_HELP)]
    Describe {
        /// Print JSON: one pretty-printed object with sorted keys.
        /// Default: on (JSON is the only format)
        /// Example: --json
        #[arg(long, verbatim_doc_comment)]
        json: bool,
    },
}

const DESCRIBE_AFTER_HELP: &str = "\
DESCRIPTION:
  Prints what this tool is, what it accepts and how to launch it, validated by
  schemas/describe.schema.json. RV Hub reads it to list the tool, start its GUI on a case
  folder (rv-certcheck-gui.exe --case-dir <CASE> [FILES...]) and suggest the tool for a file.
  Fields: schema, tool, title, version, role (analysis), main_verb (analyze), accepts
  (extensions crt, cer, der, pem, p7b, p7c, p12, pfx, crl, tsr, tst, key, csr; signatures:
  a DER SEQUENCE 30 82, a PEM -----BEGIN), case_formats, log_formats, cli_exe, gui_exe,
  exit_codes. Nothing is read or written; no audit log is created.

EXAMPLES:
  rv-certcheck describe --json

EXIT CODES:
  0  The description was printed.";

#[derive(Clone, Copy, ValueEnum)]
enum ProgressMode {
    /// Progress bar with elapsed time, throughput and ETA on stderr.
    Bar,
    /// One JSON event per line on stdout (for scripts and other tools).
    Jsonl,
    /// No progress output; only the final summary.
    None,
}

#[derive(Args)]
struct AnalyzeArgs {
    /// File or folder to review. Repeat for several.
    ///
    /// Folders are reviewed one level deep unless --recursive is given. Symbolic links are not followed.
    /// Default: none (required unless --input-list, --case-dir or --evidence is given).
    /// Example: --input D:\evidence --input E:\phone-export\chat.txt
    #[arg(
        short,
        long = "input",
        value_name = "PATH",
        required_unless_present_any = ["input_list", "case_dir", "evidence"],
        verbatim_doc_comment
    )]
    inputs: Vec<PathBuf>,

    /// Text file with one path per line (bulk review). Lines starting with # are ignored.
    ///
    /// Relative paths are resolved from the list file's folder.
    /// Default: none. Example: --input-list case-014-files.txt
    #[arg(short = 'L', long, value_name = "FILE", verbatim_doc_comment)]
    input_list: Option<PathBuf>,

    /// Also review files in subfolders.
    ///
    /// Default: off (only the first level of each folder). Example: -i D:\evidence --recursive
    #[arg(short, long, verbatim_doc_comment)]
    recursive: bool,

    /// Hash algorithm(s): one or two of md5, sha1, sha256, sha512, sha3-256, blake3.
    ///
    /// Both are computed in the same read of each file. More than two is refused (exit code 2).
    /// Default: sha256. Example: --hash sha256,md5   or   --hash sha256 --hash blake3
    #[arg(
        short = 'H',
        long = "hash",
        value_name = "ALGO",
        value_delimiter = ',',
        default_value = "sha256",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    hashes: Vec<String>,

    /// Folder where logs/ and reports/ are created. Created if missing. Ignored with --case-dir.
    ///
    /// Default: ./rakvor-out. Example: --out E:\case-014\rv-certcheck
    #[arg(
        short,
        long,
        value_name = "DIR",
        default_value = "rakvor-out",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    out: PathBuf,

    /// Report language: en, es, fr, or all (one HTML and PDF per language). JSON is language-neutral.
    ///
    /// Default: en. Example: --lang es   or   --lang all
    #[arg(
        short,
        long,
        value_name = "LANG",
        default_value = "en",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    lang: String,

    /// Name of the examiner, written in every audit entry and report.
    ///
    /// Default: the operating-system user name. Example: --actor "Ana Ruiz"
    #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
    actor: Option<String>,

    /// Case or engagement identifier printed on the reports. With --case-dir it names the case
    /// when the folder is created, and must match case.json afterwards (it can be left out).
    /// Default: none. Example: --case CASE-2026-014
    #[arg(short, long = "case", value_name = "ID", verbatim_doc_comment)]
    case_id: Option<String>,

    /// How progress is shown: bar, jsonl or none.
    ///
    /// Default: bar (hidden automatically when stderr is not a terminal).
    /// Example: --progress jsonl
    #[arg(
        short,
        long,
        value_enum,
        value_name = "MODE",
        default_value = "bar",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    progress: ProgressMode,

    /// Chain-of-custody form per item: co (Colombia, Fiscalía style, Spanish) or fr (France, scellés, French).
    /// An English copy is always added. With --case-dir the case's jurisdiction applies.
    /// Default: co
    /// Example: --jurisdiction fr
    #[arg(short, long, value_name = "CC", default_value = "co", value_parser = ["co", "fr"], verbatim_doc_comment, hide_default_value = true, hide_possible_values = true)]
    jurisdiction: String,

    /// RFC 3161 time-stamping authority for the audit chain head.
    /// Default: http://timestamp.digicert.com
    /// Example: --tsa-url https://freetsa.org/tsr
    #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
    tsa_url: String,

    /// Do not request a trusted timestamp (offline labs). Also set by RV_NO_TIMESTAMP=1.
    /// Default: off (a timestamp is requested)
    /// Example: --no-timestamp
    #[arg(long, env = "RV_NO_TIMESTAMP", value_parser = clap::builder::FalseyValueParser::new(), verbatim_doc_comment, hide_env = true)]
    no_timestamp: bool,

    /// Examiner's certificate (.p12/.pfx, RSA) used to sign every PDF report. The password is read from
    /// the environment variable named by --sign-pass-env, or asked for interactively.
    /// Default: none (PDFs are not signed)
    /// Example: --sign-cert C:\certs\ana-ruiz.p12
    #[arg(long, value_name = "P12", verbatim_doc_comment)]
    sign_cert: Option<PathBuf>,

    /// Environment variable holding the certificate password.
    /// Default: RV_SIGN_PASSWORD
    /// Example: --sign-pass-env CERT_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_SIGN_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    sign_pass_env: String,

    /// Shared case folder that links the Rakvor tools of one case (created with --case if missing).
    /// Outputs go to <DIR>/runs/rv-certcheck/<RUN-ID>/; every hashed file is registered in
    /// <DIR>/evidence/registry.json; the run is recorded in <DIR>/case-log.jsonl.
    /// With no --input, every registered item is examined again.
    /// Default: none (standalone run in --out)
    /// Example: --case-dir E:\CASE-014 --case CASE-014
    #[arg(long, value_name = "DIR", verbatim_doc_comment)]
    case_dir: Option<PathBuf>,

    /// Registered evidence ids to examine (needs --case-dir), comma-separated or repeated.
    /// Default: none (the --input files, or every registered item)
    /// Example: --evidence E0001,E0007
    #[arg(
        short = 'E',
        long = "evidence",
        value_name = "IDS",
        requires = "case_dir",
        verbatim_doc_comment
    )]
    evidence: Vec<String>,

    /// Trust anchor: certificates to trust. Repeat for several. A FILE (PEM, DER or PKCS#7), `rakvor`
    /// (the bundled Rakvor internal root), `system` (the operating system's store), or a trust-list
    /// snapshot `tl:eu@SNAPSHOT` / `tl:co@SNAPSHOT` (`latest` = newest; see `trust-list list`).
    /// Default: none (nothing is trusted: chains are built and checked, and reported untrusted)
    /// Example: --anchor roots/ca-root.pem --anchor tl:eu@latest
    #[arg(long = "anchor", value_name = "ANCHOR", value_parser = parse_anchor, verbatim_doc_comment)]
    anchors: Vec<AnchorSpec>,

    /// Instant the chains are judged at: now, a date (YYYY-MM-DD, midnight UTC), an RFC 3339 time, or
    /// signing-time. In v0.1 only a timestamp token (.tsr/.tst) has a signing time: its genTime, used for
    /// its own TSA chain (which is always judged at genTime). Every other item has no signing time yet and
    /// is judged now; the run's reports carry a note saying so. A token is checked against the evidence
    /// file with the same stem in the run (data.tsr with data or data.*); without one it is not linked
    /// to any file (imprint_checked=no).
    /// Default: now
    /// Example: --at 2025-03-14   or   --at 2025-03-14T09:30:00-05:00   or   --at signing-time
    #[arg(long, value_name = "WHEN", default_value = "now", value_parser = parse_at, verbatim_doc_comment, hide_default_value = true)]
    at: AtTime,

    /// Purpose checked against key usage and extended key usage: any, tls-server, tls-client,
    /// code-signing, document-signing, email, timestamping.
    /// Default: any
    /// Example: --purpose document-signing
    #[arg(long, value_name = "PURPOSE", default_value = "any", value_parser = parse_purpose, verbatim_doc_comment, hide_default_value = true)]
    purpose: Purpose,

    /// CRL file (DER or PEM) used for revocation, in addition to the CRLs among the evidence. Repeatable.
    /// Each file is hashed and recorded in the audit log.
    /// Default: none
    /// Example: --crl ca-2025-03.crl
    #[arg(long = "crl", value_name = "FILE", verbatim_doc_comment)]
    crls: Vec<PathBuf>,

    /// OCSP response file (DER) used for revocation, in addition to those among the evidence. Repeatable.
    /// Default: none
    /// Example: --ocsp signer-2025-03-14.ocsp
    #[arg(long = "ocsp", value_name = "FILE", verbatim_doc_comment)]
    ocsps: Vec<PathBuf>,

    /// Fetch CRLs and OCSP responses from the CRL distribution points and AIA OCSP URLs of every
    /// certificate of each built path (HTTP/HTTPS, 15 s timeout, no cache). Every URL, response SHA-256
    /// and time is audited (revocation_fetched) and listed in chain.json.
    /// Default: off (offline)
    /// Example: --online
    #[arg(long, verbatim_doc_comment)]
    online: bool,

    /// Environment variable holding the password of PKCS#12 items and encrypted keys (never logged).
    /// Default: RV_P12_PASSWORD (when unset, PKCS#12 items are read without a password)
    /// Example: --p12-pass-env CASE_P12_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_P12_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    p12_pass_env: String,
}

fn parse_anchor(s: &str) -> Result<AnchorSpec, String> {
    AnchorSpec::parse(s).map_err(|e| e.message)
}

fn parse_at(s: &str) -> Result<AtTime, String> {
    AtTime::parse(s).map_err(|e| e.message)
}

fn parse_purpose(s: &str) -> Result<Purpose, String> {
    Purpose::parse(s).map_err(|e| e.message)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    ExitCode::from(match cli.command {
        Command::Analyze(a) => analyze(*a),
        Command::Pki(c) => commands::pki(c),
        Command::Csr(c) => commands::csr(c),
        Command::Lab(c) => commands::lab(c),
        Command::Keys(c) => commands::keys(c),
        Command::Tokens(c) => commands::tokens(c),
        Command::TrustList(c) => commands::trust_list(c),
        Command::VerifyLog { log } => verify_log(log),
        Command::VerifyCase { case, rehash } => verify_case(case, rehash),
        Command::SelfTest => self_test(),
        Command::Timestamp {
            log,
            tsa_url,
            actor,
        } => timestamp(log, tsa_url, actor),
        Command::DocsCli => {
            print!("{}", docs_cli());
            EXIT_OK
        }
        Command::Describe { json: _ } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&describe()).expect("describe is valid JSON")
            );
            EXIT_OK
        }
    })
}

fn usage_error(msg: &str) -> u8 {
    eprintln!(
        "error: {}\n\nFor more information, try 'rv-certcheck analyze --help'.",
        msg
    );
    EXIT_USAGE
}

fn analyze(a: AnalyzeArgs) -> u8 {
    for f in a.crls.iter().chain(&a.ocsps) {
        if !f.is_file() {
            return usage_error(&format!("no such file: {}", f.display()));
        }
    }
    for anchor in &a.anchors {
        if let AnchorSpec::File { path } = anchor
            && !path.is_file()
        {
            return usage_error(&format!(
                "--anchor {}: no such file (use a certificate file, rakvor, system or tl:eu@SNAPSHOT)",
                path.display()
            ));
        }
    }
    let mut algos = Vec::new();
    for h in &a.hashes {
        match HashAlgo::parse(h) {
            Some(x) => algos.push(x),
            None => {
                return usage_error(&format!(
                    "unknown hash algorithm '{}': use md5, sha1, sha256, sha512, sha3-256 or blake3",
                    h
                ));
            }
        }
    }
    if let Err(e) = hash::validate_selection(&algos) {
        return usage_error(&e);
    }
    let langs = match i18n::parse_langs(&a.lang) {
        Ok(l) => l,
        Err(e) => return usage_error(&e),
    };
    let evidence_ids = match case::parse_evidence_ids(&a.evidence) {
        Ok(ids) => ids,
        Err(e) => return usage_error(&e.message),
    };
    if let Some(dir) = &a.case_dir {
        // Case problems found before the run map to their own exit codes (2 usage, 3 broken case).
        if let Err(e) = case::preflight(dir, a.case_id.as_deref(), &evidence_ids) {
            return match e.exit_code() {
                EXIT_USAGE => usage_error(&e.message),
                code => {
                    eprintln!("error: {}", e.message);
                    code
                }
            };
        }
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    let _ = ctrlc::set_handler(move || c.store(true, Ordering::SeqCst));

    let cfg = RunConfig {
        inputs: a.inputs,
        input_list: a.input_list,
        recursive: a.recursive,
        algorithms: algos,
        out_dir: a.out,
        langs,
        actor: a.actor.unwrap_or_else(rv_certcheck_core::env::os_user),
        case_id: a.case_id,
        frontend: "cli".into(),
        preamble: vec![],
        command_line: std::env::args().collect(),
        tool_name: TOOL_NAME.into(),
        tool_version: TOOL_VERSION.into(),
        jurisdiction: a.jurisdiction.clone(),
        tsa_url: if a.no_timestamp {
            None
        } else {
            Some(a.tsa_url.clone())
        },
        sign_password: a
            .sign_cert
            .as_ref()
            .and_then(|_| password(&a.sign_pass_env)),
        sign_cert: a.sign_cert.clone(),
        case_dir: a.case_dir.clone(),
        evidence_ids,
        case_role: CASE_ROLE,
        cert: CertOptions {
            validation: ValidationOptions {
                anchors: a.anchors.clone(),
                at: a.at.clone(),
                purpose: a.purpose,
                crl_files: a.crls.clone(),
                ocsp_files: a.ocsps.clone(),
                online: a.online,
                trust_list_dir: None,
            },
            p12_password: std::env::var(&a.p12_pass_env).ok().map(Secret::new),
        },
    };

    let bar = match a.progress {
        ProgressMode::Bar => {
            let b = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr_with_hz(8));
            b.set_style(
                ProgressStyle::with_template("{spinner} [{elapsed_precise}] {wide_bar} {binary_bytes}/{binary_total_bytes} {binary_bytes_per_sec} ETA {eta} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            Some(b)
        }
        _ => None,
    };
    let jsonl = matches!(a.progress, ProgressMode::Jsonl);
    // A closed stdout (e.g. `| head`) must never abort a forensic run half-way: stop printing, keep working.
    let mut stdout_open = true;
    let mut sink = |e: &Event| {
        if jsonl && stdout_open {
            let mut out = std::io::stdout().lock();
            stdout_open = writeln!(out, "{}", serde_json::to_string(e).unwrap_or_default())
                .and_then(|_| out.flush())
                .is_ok();
        }
        if let Some(b) = &bar {
            match e {
                Event::RunStarted {
                    total_bytes,
                    total_items,
                    ..
                } => {
                    b.set_length(*total_bytes);
                    b.set_message(format!("0/{} files", total_items));
                }
                Event::Progress {
                    done,
                    total,
                    bytes_done,
                    ..
                } => {
                    b.set_position(*bytes_done);
                    b.set_message(format!("{}/{} files", done, total));
                }
                Event::Error { path, message } => b.println(format!(
                    "warning: {}: {}",
                    path.as_deref().unwrap_or("-"),
                    message
                )),
                Event::Cancelled { .. } => b.println("cancelled: writing partial reports..."),
                Event::Timestamp { status, reason, .. } if status != "ok" => b.println(format!(
                    "warning: timestamp pending ({}); run `rv-certcheck timestamp` later",
                    reason.as_deref().unwrap_or("-")
                )),
                _ => {}
            }
        }
    };
    let result = run(&cfg, &mut sink, &cancel);
    if let Some(b) = &bar {
        b.finish_and_clear();
    }
    match result {
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
        Ok(s) => {
            if !jsonl {
                let out = format!(
                    "{status}  run {id}\n  items: {items}  bytes: {bytes}  errors: {errors}  elapsed: {elapsed}\n  findings: high {h}, medium {m}, low {l}, info {i}\n  timestamp: {ts}\n  report: {report}\n  logs:   {logs}",
                    status = if s.cancelled {
                        "CANCELLED"
                    } else if s.high > 0 {
                        "DONE (high-severity findings)"
                    } else {
                        "DONE"
                    },
                    id = s.run_id,
                    items = s.items,
                    bytes = s.bytes,
                    errors = s.errors,
                    elapsed = rv_certcheck_core::time::human_duration(s.elapsed_ms),
                    h = s.high,
                    m = s.medium,
                    l = s.low,
                    i = s.info,
                    ts = format!(
                        "{} {}",
                        s.timestamp["status"].as_str().unwrap_or("off"),
                        s.timestamp["gen_time"].as_str().unwrap_or("")
                    )
                    .trim(),
                    report = s
                        .report_dir
                        .join(format!("statistics.{}.html", cfg.langs[0]))
                        .display(),
                    logs = s.log_dir.display()
                );
                let _ = writeln!(std::io::stdout(), "{}", out);
                if let Some(c) = &s.case {
                    let t = &c.tally;
                    let _ = writeln!(
                        std::io::stdout(),
                        "  case:   {} ({}) registered {} (new {}), verified {}, mismatched {}, not in registry {}",
                        c.case_id,
                        c.role,
                        t.registered,
                        t.added,
                        t.verified,
                        t.mismatched,
                        t.unregistered
                    );
                }
            }
            if s.cancelled {
                EXIT_CANCELLED
            } else if s.high > 0 {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            }
        }
    }
}

fn password(env: &str) -> Option<String> {
    if let Ok(p) = std::env::var(env) {
        return Some(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // No echo: the password never appears on screen or in a terminal recording.
        return rpassword::prompt_password("Certificate password: ").ok();
    }
    None
}

fn timestamp(log: PathBuf, tsa_url: String, actor: Option<String>) -> u8 {
    let dir = if log.is_file() {
        log.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    } else {
        log
    };
    if !dir.join("audit.jsonl").is_file() {
        eprintln!(
            "error: no audit log at {}: nothing to timestamp",
            dir.join("audit.jsonl").display()
        );
        return EXIT_FINDINGS;
    }
    let mut audit_log =
        match audit::AuditLog::resume(&dir, &actor.unwrap_or_else(rv_certcheck_core::env::os_user))
        {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: {}", e);
                return EXIT_FINDINGS;
            }
        };
    match trust::timestamp_head(&dir, audit_log.entries(), audit_log.head(), &tsa_url) {
        Ok(ts) => {
            if let Err(e) = audit_log.record("timestamp_obtained", Some(&ts.file), ts.to_json()) {
                eprintln!("error: {}", e);
                return EXIT_ERROR;
            }
            println!(
                "OK  timestamp {} by {} covers entry #{}",
                ts.gen_time, ts.tsa, ts.covers_seq
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
    }
}

fn verify_log(log: PathBuf) -> u8 {
    let path = if log.is_dir() {
        log.join("audit.jsonl")
    } else {
        log
    };
    let v = match verify::verify_log(&path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    if v.problems.is_empty() {
        println!(
            "OK  {} entries, chain intact: {}",
            v.entries,
            path.display()
        );
        for t in &v.timestamps {
            println!("    {}", t);
        }
        println!("    {}", v.truncation);
    } else {
        println!("BROKEN  {}", path.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
    }
    for w in &v.warnings {
        println!("  warning: {}", w);
    }
    if v.problems.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    }
}

fn verify_case(dir: PathBuf, rehash: bool) -> u8 {
    if !dir.join(case::CASE_FILE).is_file() {
        eprintln!(
            "error: {} is not a case folder (no {})",
            dir.display(),
            case::CASE_FILE
        );
        return EXIT_ERROR;
    }
    let mut v = case::verify_case(&dir);
    let rehashed = rehash.then(|| case::rehash_registry(&dir, &mut v));
    if v.problems.is_empty() {
        println!(
            "OK  case {}: {} case-log entries, {} registered items, {} runs verified: {}",
            v.case_id,
            v.entries,
            v.registry_items,
            v.runs,
            dir.display()
        );
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_OK
    } else {
        println!("BROKEN  case {}: {}", v.case_id, dir.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_FINDINGS
    }
}

fn self_test() -> u8 {
    let failed = hash::self_test();
    for (algo, _) in hash::KNOWN_ANSWERS {
        println!(
            "{:<9} {}",
            algo.name(),
            if failed.contains(&algo) {
                "FAIL"
            } else {
                "PASS"
            }
        );
    }
    if failed.is_empty() {
        EXIT_OK
    } else {
        EXIT_ERROR
    }
}

/// The tool's self-description (`describe --json`, schema rakvor.describe/1; see schemas/describe.schema.json).
/// serde_json sorts the keys (no preserve_order feature), so the output is stable.
fn describe() -> serde_json::Value {
    serde_json::json!({
        "schema": "rakvor.describe/1",
        "tool": TOOL_NAME,
        "title": "RV CertCheck",
        "version": TOOL_VERSION,
        "role": CASE_ROLE.name(),
        "main_verb": "analyze",
        // Inputs are recognised by content; these are the usual names and first bytes.
        "accepts": {
            "extensions": ["crt", "cer", "der", "pem", "p7b", "p7c", "p12", "pfx", "crl", "tsr", "tst", "key", "csr"],
            "signatures": [
                {"format": "der-sequence", "match": [{"offset": 0, "hex": "3082"}]},
                {"format": "pem", "match": [{"offset": 0, "hex": "2d2d2d2d2d424547494e"}]}
            ]
        },
        "case_formats": [case::SCHEMA_CASE],
        "log_formats": ["rakvor.audit/1"],
        "cli_exe": format!("{}.exe", TOOL_NAME),
        "gui_exe": format!("{}-gui.exe", TOOL_NAME),
        "exit_codes": {
            "0": "Completed; no high-severity finding.",
            "1": "Runtime error (input not found, output not writable, case log locked, ...).",
            "2": "Usage error (unknown option, bad --anchor/--at/--purpose value, case folder of another case or schema).",
            "3": "Completed with at least one high-severity finding (untrusted or invalid chain, revoked or expired certificate, ...), a refused creation operation, or a case or CA folder that fails verification.",
            "130": "Cancelled with Ctrl+C; partial reports and the cancellation are in the audit log."
        }
    })
}

/// Markdown of every command's long help, so docs/usage-cli.md can never drift from the binary.
fn docs_cli() -> String {
    let mut root = Cli::command().term_width(100);
    root.build();
    let mut out = String::from(
        "# Command-line reference\n\n<!-- Generated by `rv-certcheck docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
    );
    out.push_str("```mermaid\nflowchart LR\n  A[rv-certcheck] --> B[analyze]\n  A --> C[verify-log]\n  A --> D[self-test]\n  A --> T[timestamp]\n  A --> V[verify-case]\n  A --> P[pki / csr / lab / keys / tokens]\n  A --> L[trust-list]\n  T --> E\n  B --> E[(logs/RUN-ID)]\n  B --> F[(reports/RUN-ID)]\n  B -. --case-dir .-> K[(CASE folder)]\n  P --> CA[(CA folder rakvor.ca/1)]\n  L --> S[(trust-list snapshots)]\n  B -. --anchor tl: .-> S\n  V --> K\n  C --> E\n```\n\n");
    out.push_str(&format!(
        "## rv-certcheck\n\n```text\n{}\n```\n\n",
        root.render_long_help().to_string().trim_end()
    ));
    let names: Vec<String> = root
        .get_subcommands()
        // `describe` is hidden from the command list but documented (RV Hub reads it).
        .filter(|c| (!c.is_hide_set() || c.get_name() == "describe") && c.get_name() != "help")
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        let sub = root.find_subcommand_mut(&name).expect("subcommand");
        let mut sub = sub.clone().bin_name(format!("rv-certcheck {}", name));
        out.push_str(&format!(
            "## rv-certcheck {}\n\n```text\n{}\n```\n\n",
            name,
            sub.render_long_help().to_string().trim_end()
        ));
        // Command groups (pki, csr, lab, keys, tokens, trust-list): one section per subcommand.
        sub.build();
        let children: Vec<String> = sub
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
            .map(|c| c.get_name().to_string())
            .collect();
        for child in children {
            let c = sub.find_subcommand_mut(&child).expect("subcommand");
            let mut c = c
                .clone()
                .bin_name(format!("rv-certcheck {} {}", name, child));
            out.push_str(&format!(
                "### rv-certcheck {} {}\n\n```text\n{}\n```\n\n",
                name,
                child,
                c.render_long_help().to_string().trim_end()
            ));
        }
    }
    out
}
