# Architecture

One engine, two front-ends, and a certificate layer underneath. The certificate layer (`src/certs`) knows X.509,
CMS, CRL, OCSP, RFC 3161, trust lists, CA folders and PKCS#11; it has no dependency on the engine and forbids
`unsafe` code. The engine (`src/core`) reads the evidence, hashes it, writes the audit chain, the case folder and
the reports, and turns the certificate layer's signals into findings; it never prints. The CLI and the GUI turn
user input into a `RunConfig` (analysis) or a request struct (creation) and render the results, so both
interfaces produce identical logs and reports.

```mermaid
flowchart TB
    subgraph Front-ends
        CLI["rv-certcheck (src/cli)<br/>clap · indicatif<br/>main.rs: analyze, verify-*<br/>commands.rs: pki, csr, lab, keys, tokens, trust-list"]
        GUI["rv-certcheck-gui (src/gui)<br/>egui"]
    end
    subgraph Core["rv_certcheck_core (src/core)"]
        RUN["run.rs<br/>pipeline"]
        CS["certscan.rs<br/>certificate glue"]
        H["hash.rs"]
        AN["analyzer.rs<br/>generic file checks"]
        AU["audit.rs"]
        CA["case.rs<br/>case folder"]
        TR["trust.rs<br/>RFC 3161 of the log,<br/>PDF signing"]
        REP["report/<br/>JSON · HTML · PDF"]
    end
    subgraph Certs["rv_certcheck_certs (src/certs) — #![forbid(unsafe_code)]"]
        API["lib.rs: frozen API<br/>model.rs: frozen model + finding codes"]
        ANA["analysis/<br/>sniff · parse · chain · revocation<br/>timestamp · anchors · keymatch · online"]
        TLS["trustlist/<br/>eu · co · store"]
        CRE["create/<br/>pki · build · derw · keys · signer<br/>issued · csr · lab · tokens · rng"]
    end
    subgraph Native["Linked libraries"]
        OSSL[("OpenSSL 3<br/>vendored, static<br/>(openssl crate)")]
        P11[("PKCS#11 module<br/>loaded at run time<br/>(cryptoki)")]
    end
    CLI -- RunConfig --> RUN
    GUI -- RunConfig --> RUN
    CLI -- "request structs" --> API
    RUN --> H & AN & AU & CA & REP & TR
    RUN --> CS --> API
    API --> ANA & TLS & CRE
    ANA --> OSSL
    CRE --> OSSL
    CRE --> P11
```

## Crates

| Crate | Path | Responsibility |
| --- | --- | --- |
| `rv-certcheck-certs` | [src/certs](../src/certs/src/lib.rs) | The certificate layer. **Analysis**: content sniffing, field extraction, path building and verification, CRL/OCSP evaluation, `--online` fetching, RFC 3161, key matching, anchor resolution. **Trust lists**: EU XML and Colombian CSV import, snapshot store, lookup. **Creation**: CA folders and profiles, DER writer, key generation and protection, PKCS#11, CSRs, lab sets. Its API (`lib.rs`) and model (`model.rs`) are frozen: fields may be added, never renamed. |
| `rv-certcheck-core` | [src/core](../src/core/src/lib.rs) | Intake of inputs, one-pass dual hashing, generic file checks, the audit chain, the case folder (`CASE_ROLE` = analysis), the certificate glue (`certscan.rs`), reports in three languages, RFC 3161 timestamping of the audit log, PDF signing with the examiner's certificate. |
| `rv-certcheck-cli` | [src/cli](../src/cli/src/main.rs) | `analyze`, `verify-log`, `verify-case`, `timestamp`, `self-test`, `docs-cli` (hidden) in `main.rs`; the creation commands and `trust-list` in `commands.rs`, each writing its own audited run. |
| `rv-certcheck-gui` | [src/gui](../src/gui/src/lib.rs) | Desktop app; see [usage-gui.md](usage-gui.md). |

## Where OpenSSL sits

OpenSSL 3 is compiled from source by `openssl-src` (feature `vendored`) and linked statically; no system OpenSSL
is used, on any platform. The version linked is printed in `environment.json`, every `chain.json` and every verdict.

| Used for | Through | Not used for |
| --- | --- | --- |
| Path building and verification (`X509_verify_cert`, `X509_STORE`, `X509_VERIFY_PARAM`) | `openssl::x509::store`, `X509StoreContext` | — |
| Certificate, CRL, CSR, PKCS#12 decoding; names, times, fingerprints, `X509_print` | `openssl::x509`, `openssl::pkcs12` | Extensions decoding (x509-parser) |
| CRL signature checks, OCSP (`OCSP_basic_verify`, CertID), PKCS#7 signature over TSTInfo | `openssl::ocsp`, `openssl::pkcs7` | Parsing TSTInfo, ESS attributes (cms + a DER walk) |
| Key generation (non-lab), signing with file keys, PBKDF2, AES-256-CBC, HMAC, `RAND_bytes` | `openssl::pkey`, `pkcs5`, `symm`, `rand` | Writing DER (the tool's own `derw.rs`); the randomness of lab keys (candidates come from a seeded ChaCha20 stream; OpenSSL `BIGNUM` only tests primality and builds the key) |

What is **not** OpenSSL: the DER writer for everything the creation side signs (`derw.rs`), the trust-list
parsers (quick-xml, own CSV reader), PKCS#11 (cryptoki), the HTTP client for `--online` and RFC 3161 (ureq), legacy
PKCS#12 reading (p12-keystore), and the audit chain and reports (core).

## Data flow of an analysis run

```mermaid
sequenceDiagram
    autonumber
    participant UI as CLI / GUI
    participant R as run.rs
    participant C as certscan.rs
    participant L as certs (OpenSSL)
    participant A as audit.jsonl
    participant FS as Evidence (read-only)
    participant O as reports/
    UI->>R: run(config, sink, cancel)
    R->>A: run_started, environment_recorded, inputs_resolved
    R->>C: prepare(): read --crl/--ocsp, resolve --anchor
    C->>L: resolve_anchors()
    R->>A: validation_options (anchors + SHA-256, at, purpose, files, online, openssl)
    loop each item
        R->>FS: read 1: hash in 1 MiB chunks
        R->>A: item_started, item_hashed
        R->>C: analyze_item()
        C->>FS: read 2 (≤ 16 MiB), re-hash
        C->>L: sniff(), parse_any()
        R->>A: item_analyzed
    end
    R->>C: cross_item_stage(): pool of certificates, CRLs, OCSP
    loop each crypto item
        C->>L: validate_chain() per end entity, verify_timestamp_token(), key match
        L-->>C: ChainVerdict (nodes, errors, signals, notes, online_fetches)
        C->>O: chain.json, certificate.txt
        R->>A: item_certificates_checked, revocation_fetched (--online), output_written
    end
    R->>O: technical, summary, custody, statistics
    R->>A: item_reports_written, statistics_report_written, run_finished
```

## Data flow of a creation command

```mermaid
flowchart LR
    U["pki issue …"] --> RUNS["CreationRun::start<br/>audit.jsonl: run_started, environment_recorded"]
    RUNS --> LOCK["Lock the CA folder"]
    LOCK --> VER["Verify issued.jsonl chain<br/>+ SHA-256 of every recorded file"]
    VER -->|broken| REF["Refuse (exit 3)<br/>operation_failed"]
    VER --> KEY["Unlock CA key (file password / token PIN)<br/>check it matches certs/ca.crt"]
    KEY --> BUILD["derw/build: TBS + extensions<br/>sign (OpenSSL or PKCS#11)"]
    BUILD --> CHECK["OpenSSL parses and verifies<br/>the new certificate / CRL"]
    CHECK --> W["Write certs/&lt;serial&gt;.crt (never overwrite)"]
    W --> APP["Append issued.jsonl record"]
    APP --> AUD["audit: file_written, ca_log_appended,<br/>report_written, run_finished"]
```

## Run states (as the GUI sees them)

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Running: Start (inputs ≥ 1, algorithms 1–2)
    Running --> Finished: RunFinished
    Running --> Cancelled: Cancel → partial reports
    Running --> Failed: error (e.g. output not writable)
    Finished --> Running: Start again (new run ID)
    Cancelled --> Running
    Failed --> Running
```

## Concurrency and cancellation

- Items are processed sequentially on purpose: the order of audit entries equals the order of work. The
  certificate stage runs after the hashing loop because a chain may need certificates, CRLs or OCSP responses
  found in later items.
- Cancellation is an `AtomicBool` checked between hashing chunks; the engine still writes partial reports and
  `run_cancelled`.
- A CA folder is locked during every mutating operation; two `pki` commands on the same folder cannot interleave.
- PKCS#11: one module context per module path for the life of the process (`C_Initialize` once).

## Why Rust

See [ADR 0001](adr/0001-language.md): v0.1 is pure Rust with OpenSSL 3 through FFI for path validation, CMS,
OCSP, CRL and PKCS#12; v0.2 adds an optional, separately signed Python worker for PAdES and XAdES only.
