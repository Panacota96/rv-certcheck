# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [0.2.0](https://github.com/Panacota96/rv-certcheck/compare/v0.1.0...v0.2.0) (2026-11-04)


### Features

* **certs:** freeze the certificate model, the certificate-layer API and the finding catalogue ([e82bf76](https://github.com/Panacota96/rv-certcheck/commit/e82bf763e62318ed4c66e2a5e76816dfd9ee36ae))
* **cli:** audited pki, csr, lab, keys and tokens commands ([5f55596](https://github.com/Panacota96/rv-certcheck/commit/5f555965e8bff727962f3655251e8b09626f6d85))
* **cli:** hidden describe --json (rakvor.describe/1) and GUI --case-dir for RV Hub ([acd0b35](https://github.com/Panacota96/rv-certcheck/commit/acd0b35307cc8ba0808a1d2065aed09c07baccc5))
* **core,cli:** --online revocation fetching enabled and audited; no ANALYSIS_NOT_IMPLEMENTED path ([bd660a8](https://github.com/Panacota96/rv-certcheck/commit/bd660a8bb80e2120344ae45cc53d658011712adc))
* **core:** creation module, the audited run of a creation operation for non-CLI front-ends (additive) ([aca83f8](https://github.com/Panacota96/rv-certcheck/commit/aca83f8e4775a72bf2e0368a728ea67e28f90d81))
* **create:** Rakvor PKI, CSRs, seeded lab sets and PKCS[#11](https://github.com/Panacota96/rv-certcheck/issues/11) tokens ([270c3ba](https://github.com/Panacota96/rv-certcheck/commit/270c3bad2a5b3212b0c729fcfbede5d84367430d))
* **gui:** Analyze, Create and Trust lists tabs over the certificate layer ([0ebb586](https://github.com/Panacota96/rv-certcheck/commit/0ebb58628e76fe80a98413b301f39a9f38630ea2))
* **gui:** Rakvor window and .exe icon, headless screenshots, GUI usage guide ([3a6b0cc](https://github.com/Panacota96/rv-certcheck/commit/3a6b0cc0d37dbd38f60da4efc64f1d12ff18341f))


### Bug Fixes

* **analysis:** trust-list status at the date, CERT_CHAIN_INVALID, honest wording, timestamp imprint pairing ([2f17f6b](https://github.com/Panacota96/rv-certcheck/commit/2f17f6bfdd8355179dead781daa30b11e3f1699d))
* **create:** DER length reader never panics on non-DER bytes (raw token EC points); drop unused rcgen; guide: rv-hashinv scan verb ([441003b](https://github.com/Panacota96/rv-certcheck/commit/441003bb938f7a1b9664558c84d06256fe3b95c2))
* **gui:** masked fields keep no undo history (egui's undoer copies the text) ([ed1ffcf](https://github.com/Panacota96/rv-certcheck/commit/ed1ffcfad589fddd369f60515c3fb18add56d72a))
* **pki:** record ca.json and check crl/latest.crl, pki set --crl-url, parent of imported CAs, RSA examiner keys ([34c2a87](https://github.com/Panacota96/rv-certcheck/commit/34c2a872476199142ec8658935985495c1f604d4))
* **tokens:** portable CK_ULONG conversion for RSA modulus bits (Windows build) ([a804c77](https://github.com/Panacota96/rv-certcheck/commit/a804c77278b544d0d8c6483f855321f5b292c0aa))

## [Unreleased]

### Fixed
- `verify-log` and `verify-case` now verify the TSA's CMS signature on every RFC 3161 token (signer certificate
  in the token, ESS signing-certificate binding, message digest over TSTInfo, RSA PKCS#1 v1.5 signature,
  `timeStamping` key usage); before, a token with an altered signature was reported intact. `verify-log --tsa-ca
  <PEM>` also validates the TSA certificate chain at genTime; without it the output says "chain not checked".
  Unreadable bundle: exit 1; signature or chain failure: exit 3. Revocation is not checked; RSA signers only.

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
- 27 finding codes and 9 limitations (plus the run note `AT_SIGNING_TIME_TOKENS_ONLY_V01`) worded in en/es/fr
  with *shows* and *does not prove*.
- `CERT_CHAIN_INVALID` (high): every OpenSSL verify error not mapped to a specific finding (13, 14, 24, 25, 32,
  34, 37, 79, …), with OpenSSL's code and reason; these were reported as `CERT_CHAIN_UNTRUSTED` before.
- Timestamp imprint pairing: a token is checked against the evidence file of the same stem in the run
  (`data.tsr` ↔ `data`, `data.*`); a mismatch is `TIMESTAMP_TOKEN_INVALID` ("imprint does not match <file>"); a
  token without such a file is valid with `imprint_checked=no` and is worded as not linked to any file.
- `describe --json` (hidden, `rakvor.describe/1`, `schemas/describe.schema.json`) and `rv-certcheck-gui --case-dir`
  for RV Hub.
- `pki set --crl-url URL`, `pki import --issuer-cert FILE` (parent certificate SHA-256; issuer subject and key id
  recorded for every imported intermediate), `pki issue --allow-non-rsa-examiner`.
- CI runs the PKCS#11 tests against a SoftHSM2 token on Linux.
- **Trust lists** (`trust-list import|list|show`, each an audited run): EU LOTL/TL (ETSI TS 119 612) and the
  curated Colombian CSV (`schemas/trustlist-co.schema.json`) as dated, hashed snapshots. A `tl:` anchor trusts
  only certificates of CA services (and, for timestamping, TSA services) whose status at `--at` is granted,
  recognised at national level or accredited, status history included; a chain ending in a withdrawn or
  suspended service is `CERT_CHAIN_UNTRUSTED` naming the service and its status.
- **Creation**: `pki init-root|import|issue|revoke|crl|ocsp-sign|show|verify` with CA folders (`rakvor.ca/1`),
  hash-chained `issued.jsonl`, profiles intermediate, code-signing, examiner (`.p12`), tsa, tls-server
  (`client-internal` refused until the CP/CPS exists), keys in PBES2-encrypted PKCS#8 or on PKCS#11 tokens
  (`--confirm-root` for a token root); `csr new|show`; `lab make` (seeded, byte-identical sets with
  `expected_findings.json`); `keys match`; `tokens list`. Every certificate carries the Rakvor internal-use policy.
- **CA folder integrity**: every `ca.json` the tool writes is recorded in `issued.jsonl` (`ca_json_written`, SHA-256)
  and `crl/latest.crl` must be the newest recorded CRL, so a hand edit (e.g. `crl_url`, `allowed_profiles`) fails
  `pki verify` and every operation (exit 3).
- `--key-type` is optional for `pki init-root` and `pki issue`: library defaults per profile (rsa-4096 root, p-384
  intermediate, p-256 tsa / tls-server, rsa-3072 code-signing / examiner), shown in the help and followed by the
  GUI. An EC or Ed25519 examiner key is refused unless `--allow-non-rsa-examiner` (rv-hashinv signs with RSA only).
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
- `--at signing-time` gives a signing time only to timestamp tokens (their genTime); other items are judged now and
  the run says so (`AT_SIGNING_TIME_TOKENS_ONLY_V01`).
- A timestamp token with no evidence file of the same stem in the run is not linked to any file.
- CA folders created before the `ca.json` record existed are refused by `pki verify`; re-create or re-import them.
- Signed documents (PAdES, XAdES), S/MIME, Authenticode, OpenPGP, JWS and live TLS are planned for v0.2.
- Certificates issued by Rakvor are for internal use only: not a *firma digital* (Ley 527 art. 28), not qualified
  (eIDAS).
