# Forensic audit trail

Everything RV CertCheck does is written to `<OUT>/logs/<RUN-ID>/`: analysis runs and creation runs alike. The
folder is designed so that a second examiner, months later, can check **what was done, to which files, with
which anchors, dates and revocation data, by whom, with which tool and OpenSSL version**, and that the record was
not altered. Creating certificates adds a second, permanent record in the CA folder: `issued.jsonl`
([below](#creation-runs-and-the-ca-folders-issuedjsonl)).

| File | Content |
| --- | --- |
| `audit.jsonl` | One JSON object per action, hash-chained (authoritative) |
| `audit.log` | The same actions as readable text (convenience copy) |
| `hashes.csv` | Hash register: `index,path,size,<algo1>[,<algo2>],status,error` |
| `environment.json` | Tool version, compiler, target, every dependency version, OS, host, OS user, working folder, command line |

## The hash chain

```mermaid
flowchart LR
    G["GENESIS<br/>000…000"] --> E1
    E1["#1 run_started<br/>prev = GENESIS<br/>entry_hash = H1"] --> E2
    E2["#2 environment_recorded<br/>prev = H1<br/>entry_hash = H2"] --> E3
    E3["#3 inputs_resolved<br/>prev = H2<br/>entry_hash = H3"] --> EN["… #N run_finished"]
```

Each entry has: `seq`, `ts_utc`, `run_id`, `actor`, `action`, optional `item`, `details`,
`prev_entry_hash`, `entry_hash`.

```text
entry_hash = SHA-256( canonical JSON of the entry without "entry_hash" )
canonical  = keys sorted at every level, no spaces, UTF-8, integers only
             (Python: json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
```

Editing a value changes that entry's hash; deleting or re-ordering breaks `seq` and `prev_entry_hash`.
Verify with either implementation:

```bash
rv-certcheck verify-log rakvor-out/logs/<RUN-ID>          # exit 0 intact, 3 broken or truncated
python tests/verify_chain.py rakvor-out/logs/<RUN-ID>   # independent re-implementation (chain + hashes.csv)
```

> The chain shows the log is **internally consistent**. On its own it does not prove *when* it was written —
> that is what the trusted timestamp below adds — nor that it is *complete*: removing the last entries leaves a
> shorter chain that is still valid. Storing the final `entry_hash` (printed in the statistics report) in your
> case management system remains good practice.

### Truncation: what anchors the end of the log

A chain cannot vouch for its own length, so `verify-log` compares the end of the log with the records kept
**outside** it:

```mermaid
flowchart LR
    L["audit.jsonl<br/>entries #1 … #N"] --> V{"verify-log"}
    T["timestamp-K.json + .tsr<br/>covers_seq K, head = hash of #K"] --> V
    C["case-log.jsonl run_finished<br/>audit_entries M, audit_head"] --> V
    V -->|"#K or #M missing, or another hash"| B["BROKEN: truncated (exit 3)"]
    V -->|"the records agree"| O["OK + which entries are anchored"]
    V -->|"no timestamp, not in a case"| N["OK + 'truncation not detectable<br/>without a timestamp or case record'"]
```

| Record | Where | What `verify-log` checks |
| --- | --- | --- |
| RFC 3161 timestamp | `timestamp-<K>.json` / `.tsr` next to the log | entry `#K` still exists and its `entry_hash` is the head the token signs; every `timestamp_obtained` entry still has its token file |
| Case log | `<CASE>/case-log.jsonl`, for a run in `<CASE>/runs/<tool>/<RUN-ID>/logs` | `run_finished` of this run records `audit_entries` and `audit_head`: entry `#M` exists with that hash, and only `timestamp_obtained` follows it |

The output names the last anchored entry. A standalone run timestamps the head **before** writing
`timestamp_obtained`, `statistics_report_written` and `run_finished`, so those 3 entries are reported as
"cannot be proven complete"; a run in a case folder is anchored to its last entry by the case log. Without either
record `verify-log` prints `truncation not detectable without a timestamp or case record` (exit 0: nothing
contradicts the log, but nothing vouches for its length). Deleting the timestamp files **and** the entries that
refer to them is detectable only through the case log or a head kept elsewhere.

## Trusted timestamp (RFC 3161)

Every run asks a Time-Stamp Authority (TSA) to sign the chain head **just before the statistics report** is
written, so the report can show the result. Default TSA: `http://timestamp.digicert.com` (`--tsa-url` to change).

```mermaid
sequenceDiagram
    participant T as rv-certcheck
    participant L as audit.jsonl
    participant A as TSA (RFC 3161)
    T->>L: … item_reports_written (entry #N)
    T->>A: entry_hash of #N (the head, a SHA-256) + nonce
    alt reachable
        A-->>T: signed token (genTime)
        T->>L: timestamp_obtained (covers_seq N, gen_time, tsa, token_sha256)
    else offline
        T->>L: timestamp_pending (reason) — warning on the statistics report
        Note over T: later: rv-certcheck timestamp logs/RUN-ID
    end
    T->>L: statistics_report_written · run_finished
```

- The token is stored next to the log: `timestamp-<N>.tsr` (DER) and `timestamp-<N>.json` (readable summary).
- Offline or air-gapped: the run still completes. When the network is back, `rv-certcheck timestamp <log folder>`
  re-verifies the chain and appends `timestamp_obtained` — earlier entries are never rewritten.
- The TSA receives the chain head itself: the `entry_hash` of entry `#N` (already a SHA-256 digest) is the
  message imprint of the request (hash algorithm SHA-256); it is not hashed a second time.
- `verify-log` checks each token: imprint = stored head, and entry `#N` still exists with that hash (a missing
  entry `#N` is reported as truncation), and the TSA's CMS signature (ESS signing-certificate, message digest,
  RSA signature, `timeStamping` key usage); `verify-case` does the same for every run.
- The TSA certificate chain is validated only with `verify-log --tsa-ca <CA bundle>` (at genTime); without it
  the output says "chain not checked". Revocation is never checked.
- Independent check: `openssl ts -verify -digest <head> -in timestamp-<N>.tsr -CAfile <TSA chain>`.
- `--no-timestamp` (or `RV_NO_TIMESTAMP=1`) disables it; tests use a local TSA (`tests/fake_tsa.py`).
- **Limitation:** a timestamp shows the log existed at that time; it does not prove that its content is true.
- This timestamp concerns the **audit log**. Timestamp tokens found among the evidence are verified separately by
  `analyze` ([theory.md B8](theory.md#b8-rfc-3161-tokens-and-ess-signing-certificate)).

## Signed PDF reports

`--sign-cert examiner.p12` (GUI: *4. Trust → Certificate*) signs every PDF — statistics, technical, summary and
custody — with **your own** certificate. The password comes from the environment variable named by
`--sign-pass-env` (default `RV_SIGN_PASSWORD`) or an interactive prompt; it is never written to any log.
The log records `signing_certificate_loaded` with the certificate subject and SHA-256 fingerprint; a wrong password
stops the run (`run_failed`, exit 1) before any evidence is read. HTML and JSON reports are not signed: their
digests are in the audit chain, which is timestamped.

## Chain-of-custody form per item

`--jurisdiction co` (default) writes, for each item, a Colombian *registro de cadena de custodia* in Spanish
(fields of the Fiscalía manual, Ley 906 de 2004); `--jurisdiction fr` a French *fiche de scellé / suivi* in French
(Code de procédure pénale art. 156 ff.). An English version is always added. The form is pre-filled from the run
(case, item, size, both digests, UTC times, tool, examiner, audit entries) and leaves signature lines for the
physical transfers. This is a working aid, not legal advice: check it against the current official form.

## Actions recorded

| Action | When | Key details |
| --- | --- | --- |
| `run_started` | first | tool, version, frontend, algorithms, langs, inputs, case |
| `ui_*` | GUI only, before the run | input added/removed, hash selection, language, recursive, start clicked |
| `environment_recorded` | | digests of `environment.json` |
| `inputs_resolved` | | number of items and bytes |
| `item_started` | each item | index, size, modified time |
| `item_hashed` | each item | digests, bytes read, `mtime_unchanged` |
| `item_error` | unreadable item | error message |
| `validation_options` | `analyze`, before the items | every `--anchor` (described), the SHA-256 of each anchor file and of each resolved anchor certificate (or the resolution error), `--at` as given, `--purpose`, every `--crl` / `--ocsp` file with its SHA-256, `--online`, `p12_password` "supplied (not recorded)" or "none", the OpenSSL version |
| `item_analyzed` | each item | detected type, extension, findings, status |
| `item_certificates_checked` | each cryptographic item, after the loop | kind, number of certificates, per verdict: status, OpenSSL code and reason, depths; failed steps; finding codes; online fetches |
| `revocation_fetched` | `--online` only, per URL | kind (crl/ocsp), URL, certificate subject, request time, HTTP status, bytes, response SHA-256 or error |
| `output_written` | each `chain.json` / `certificate.txt` | item, kind, relative file, digest |
| `item_cancelled` / `run_cancelled` | on cancel | processed count |
| `duplicate_group` | after the loop | hash, item indexes |
| `hash_register_written` | | digests of `hashes.csv` |
| `item_reports_written` | each item | digests of every report file |
| `statistics_report_written` | | digests of statistics files |
| `run_finished` / `run_failed` | last | totals, severities, elapsed |

## Creation runs and the CA folder's `issued.jsonl`

Every creation command (`pki init-root/import/issue/revoke/crl/ocsp-sign/show/verify`, `csr new/show`,
`lab make`, `keys match`, `tokens list`) writes its own run under `--out` (default `rakvor-out`), with the same
`audit.jsonl` chain rule:

| Action | Key details |
| --- | --- |
| `run_started` | tool, version, frontend `cli`, command, parameters (paths, profile, subject, key type, key **location**, validity; never a password or PIN), OpenSSL version |
| `environment_recorded` | SHA-256 of `environment.json` |
| `ca_created`, `ca_imported`, `certificate_issued`, `certificate_revoked`, `crl_signed`, `ocsp_signed`, `csr_created`, `lab_set_written`, `key_matched`, `tokens_listed`, `ca_folder_verified` / `ca_folder_verification_failed` | what was done (serial, profile, subject, SHA-256s, CRL number, status) |
| `file_written` | role, path and SHA-256 of every file written (certificate, CRL, OCSP response, CSR, `.p12`, key file, lab files) |
| `ca_log_appended` | the CA, the `issued.jsonl` record's `seq`, action, `entry_hash`, serial and certificate SHA-256: **links the run's chain to the CA's chain** |
| `operation_failed` | error kind and message (a refusal by a safety rule is exit 3) |
| `report_written`, `run_finished` | SHA-256 of `report.json` / `report.txt`; status and exit code |

Creation runs request no RFC 3161 timestamp; add one with `rv-certcheck timestamp <LOG>` when the record must be
dated by a third party (e.g. after a key ceremony).

**`issued.jsonl`** (in the CA folder, schema `rakvor.ca/1`) holds one record per CA operation: `ca_created`,
`ca_imported`, `ca_json_written`, `issued`, `revoked`, `crl_issued`, `ocsp_signed`, with serial, profile, subject, validity,
certificate SHA-256, file and file SHA-256, revocation reason and time, CRL number, the key's location (never the
key), actor and tool version. It is chained exactly like `audit.jsonl`:

```mermaid
flowchart LR
    G["000…000"] --> R1["#1 ca_created<br/>certs/ca.crt + SHA-256"]
    R1 --> R1b["#2 ca_json_written<br/>ca.json + SHA-256"]
    R1b --> R2["#3 issued<br/>serial, profile, cert SHA-256"]
    R2 --> R3["#4 revoked<br/>serial, reason, time"]
    R3 --> R4["#5 crl_issued<br/>crl/1.crl + SHA-256"]
    R4 --> R5["#6 ca_json_written<br/>next_crl_number"]
    R2 -. "ca_log_appended (entry_hash of #3)" .-> A["run audit.jsonl<br/>of pki issue"]
    R4 -. "ca_log_appended (entry_hash of #5, #6)" .-> B["run audit.jsonl<br/>of pki crl"]
```

- **Before every operation** the tool re-verifies the whole chain, that the first record creates or imports this
  CA's certificate, that `certs/ca.crt` is the certificate recorded in `ca.json`, the SHA-256 of every file a
  record names (for `ca.json`, its latest `ca_json_written` record), and that `crl/latest.crl` is the newest
  recorded CRL. Any difference stops the CA: nothing is issued until a person investigates.
- `rv-certcheck pki verify --ca <FOLDER>` runs the same check on demand (exit 3 when broken); run it at the start
  of every session and before handing a CA folder to a reviewer. `pki show` lists every certificate with its
  revocation state.
- `ca.json` is changed only by the tool (`pki set --crl-url` for the CDP); a hand edit of any field stops the CA.
- What the chain does **not** cover: removing the last records of `issued.jsonl` (with the files they name rolled
  back to match) leaves a valid shorter chain. The `ca_log_appended` entries of the creation runs, and
  their timestamps, are the outside record of its length.
- Key files are created owner-only and never overwritten; token keys are referenced by token serial and key id.

## Evidence handling

```mermaid
flowchart LR
    O[("Original media")] -->|write blocker + imaging tool| C[("Verified working copy")]
    C -->|read-only open| T["RV CertCheck"]
    T --> L["logs/"]
    T --> R["reports/"]
    L & R --> K["Case file<br/>(keep together)"]
```

- Files are opened with read-only access; modification times are compared before and after hashing
  (`mtime_unchanged` in `item_hashed`).
- Symbolic links are never followed (no escape outside the selected folders).
- The tool does not replace imaging tools or write blockers: run it on a verified copy.

## Mapping to ISO/IEC 27037:2012

| 27037 principle / activity | How RV CertCheck supports it |
| --- | --- |
| Auditability (5.3.2) | Every action logged with actor, UTC time and chain hash; `verify-log` checks the chain and its end against the timestamp and the case log |
| Repeatability (5.3.3) | `environment.json` records exact tool and dependency versions; same input → same hashes |
| Reproducibility (5.3.4) | Independent verifier (`tests/verify_chain.py`), standard algorithms, and a second implementation of the tool (the other profile) that numbers, hashes and verifies identically |
| Justifiability (5.3.5) | Every finding states what it shows and what it does **not** prove; limitations in every report |
| Preservation (7.1.4) | Read-only access; hashes of every file and of every report produced |
| Documentation / chain of custody | Hash register, reports, and log folder form the record of the examination |
| Justifiability of certificate verdicts | Anchors, instant, purpose and revocation files recorded with their SHA-256 (`validation_options`); per-depth OpenSSL codes and the notes on how each verdict was reached (`chain.json`); the OpenSSL version |
| Auditability of created certificates | `issued.jsonl` chain + `ca_log_appended` cross-links + `pki verify` |

Colombian practice (Ley 906 de 2004, Manual de cadena de custodia) and French practice (Code de procédure
pénale, art. 156 ff. for expertise) both expect the examiner to document the method and preserve integrity;
the log folder plus the reports are that documentation for this step of the examination.
