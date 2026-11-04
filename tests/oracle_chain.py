#!/usr/bin/env python3
"""Second, independent oracle for rv-certcheck chain verdicts: Python `cryptography`'s X.509 path validator
(Rust, webpki-style; not OpenSSL), so a shared OpenSSL bug cannot make both oracles agree with the tool.

Usage: python3 tests/oracle_chain.py VERDICTS.json [FIXTURES_DIR]

VERDICTS.json is written by src/certs/tests/analysis_oracle_python.rs: a list of
  {"file": "leaf.crt", "at": "2026-06-01T00:00:00Z", "status": "valid|invalid|untrusted",
   "codes": ["CERT_CHAIN_VALID", ...], "errors": [[depth, openssl_code], ...]}
computed with the lab root as the only anchor, the intermediate as untrusted, purpose any and NO revocation
data (cryptography's verifier does not check revocation).

Agreement rule (what cryptography's policy decides differently is stated, not hidden):
  - cryptography accepts  <=>  the verdict is valid AND carries no CERT_WEAK_SIGNATURE_ALGORITHM
    (its policy forbids SHA-1 / MD5 signatures, which OpenSSL accepts and the tool reports as a finding);
  - when cryptography says "not valid at validation time", the verdict must report CERT_EXPIRED_AT_DATE or
    CERT_NOT_YET_VALID_AT_DATE.
Exit 0 when every case agrees, 3 on a disagreement, 4 when `cryptography` (>= 43, x509.verification) is not
installed (pip install cryptography; optional locally, installed in CI).
"""
import datetime
import json
import os
import sys

try:
    from cryptography import x509
    from cryptography.x509 import verification as v
except ImportError:  # pragma: no cover - depends on the environment
    print("cryptography with x509.verification is not installed", file=sys.stderr)
    sys.exit(4)


def load(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def check(fixtures, case, root, inter):
    at = datetime.datetime.strptime(case["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    builder = (
        v.PolicyBuilder()
        .store(v.Store([root]))
        .time(at)
        .extension_policies(ca_policy=v.ExtensionPolicy.webpki_defaults_ca(), ee_policy=v.ExtensionPolicy.permit_all())
    )
    target = load(os.path.join(fixtures, case["file"]))
    try:
        builder.build_client_verifier().verify(target, [inter])
        return True, "ok"
    except v.VerificationError as e:
        return False, str(e)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    here = os.path.dirname(os.path.abspath(__file__))
    fixtures = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "fixtures", "openssl")
    with open(sys.argv[1], encoding="utf-8") as fh:
        cases = json.load(fh)
    root = load(os.path.join(fixtures, "root.crt"))
    inter = load(os.path.join(fixtures, "intermediate.crt"))
    problems = []
    for c in cases:
        ok, why = check(fixtures, c, root, inter)
        codes = set(c["codes"])
        want = c["status"] == "valid" and "CERT_WEAK_SIGNATURE_ALGORITHM" not in codes
        line = f'{c["file"]} at {c["at"]}: cryptography {"accepts" if ok else "rejects (" + why[:90] + ")"}; ' \
               f'rv-certcheck {c["status"]} {sorted(codes)}'
        print(line)
        if ok != want:
            problems.append("DISAGREE " + line)
        elif not ok and "not valid at validation time" in why and not (
            codes & {"CERT_EXPIRED_AT_DATE", "CERT_NOT_YET_VALID_AT_DATE"}
        ):
            problems.append("DISAGREE (reason) " + line)
    for p in problems:
        print(p, file=sys.stderr)
    print(f"{len(cases)} cases, {len(problems)} disagreements")
    return 3 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
