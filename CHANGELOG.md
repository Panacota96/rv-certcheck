# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [Unreleased]

### Added
- Project scaffolded with rakvor-tool-forge (rust profile) on 2026-11-03.
- **Analysis** (`analyze`): recognition by content of certificates, PEM bundles, PKCS#7, PKCS#12 (password from
  `--p12-pass-env`, never logged), CRLs, OCSP responses, RFC 3161 tokens, private keys and CSRs; full field
  extraction and `certificate.txt` (OpenSSL dump).
- RFC 5280 path validation by vendored OpenSSL 3 with the OpenSSL code at every depth, every error collected by
  re-running the verifier, and `chain.json` per item; `--anchor FILE|rakvor|system|tl:eu@ID|tl:co@ID`,
  `--at now|DATE|RFC3339|signing-time`, `--purpose` (including the tool's own `document-signing` rule).
- Revocation from CRLs and OCSP responses supplied (`--crl`, `--ocsp`) or found among the evidence, with stated
  freshness rules; `--online` fetching of CDP and AIA OCSP URLs (HTTP/HTTPS, 15 s, 20 MiB, no cache), every
  fetch audited (`revocation_fetched`).
- RFC 3161 token verification: status, CMS signature, ESS signing-certificate(-v2), TSA chain at genTime.
- Weak-key (RSA < 2048, DSA, EC < 256) and weak-signature (MD2/MD4/MD5/SHA-1) findings; name-constraint
  findings naming the entry; private-key matching; `CERT_ISSUED_BY_RAKVOR_INTERNAL`.
- 26 finding codes and 9 limitations worded in en/es/fr with *shows* and *does not prove*.
- **Trust lists** (`trust-list import|list|show`): EU LOTL/TL (ETSI TS 119 612) and the curated Colombian CSV
  (`schemas/trustlist-co.schema.json`) as dated, hashed snapshots; service status at the validation date.
- **Creation**: `pki init-root|import|issue|revoke|crl|ocsp-sign|show|verify` with CA folders (`rakvor.ca/1`),
  hash-chained `issued.jsonl`, profiles intermediate, code-signing, examiner (`.p12`), tsa, tls-server
  (`client-internal` refused until the CP/CPS exists), keys in PBES2-encrypted PKCS#8 or on PKCS#11 tokens
  (`--confirm-root` for a token root); `csr new|show`; `lab make` (seeded, byte-identical sets with
  `expected_findings.json`); `keys match`; `tokens list`. Every certificate carries the Rakvor internal-use policy.
- Independent oracles: OpenSSL CLI fixtures, Python `cryptography`, the seeded lab set, the sample's
  `expected_findings.json`; fuzz tests of the parsers.
- Documentation: README, theory (plain-language and expert parts), admissibility (Ley 527 arts. 28–30 and 35–37,
  eIDAS trust lists, ISO/IEC 27037/27041/27042, FRE 702, CPR Part 35; draft pending legal review), reports
  (finding catalogue), architecture, installation (Rakvor-root signature check, PKCS#11, vendored OpenSSL build),
  usage, case folder, forensic audit (creation runs, `issued.jsonl`), company PKI guide.

### Known limitations (v0.1)
- No validated error rates; verdicts are compared with OpenSSL and Python `cryptography` on synthetic sets only.
- EU trust-list signatures are not verified; the Colombian ONAC list is curated by hand.
- `--anchor system` is Unix-only (the Windows ROOT store is not read).
- `--at signing-time` falls back to now: core does not yet supply a signing time.
- A timestamp token's imprint is not compared with any evidence file during `analyze`.
- Signed documents (PAdES, XAdES), S/MIME, Authenticode, OpenPGP, JWS and live TLS are planned for v0.2.
- Certificates issued by Rakvor are for internal use only: not a *firma digital* (Ley 527 art. 28), not qualified
  (eIDAS).
- No `describe` subcommand yet (RV Hub discovery).
