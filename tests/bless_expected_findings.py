#!/usr/bin/env python3
"""Checks, or with RV_BLESS=1 regenerates, examples/sample/expected_findings.json from the real analysis.

Usage: [RV_BLESS=1] python3 tests/bless_expected_findings.py PATH/TO/rv-certcheck

Runs `rv-certcheck analyze -i examples/sample/evidence` with the file's own "args" (RV_NO_TIMESTAMP=1) and
collects the finding codes of every item from its technical.json.
  - check mode (default): every item's "expected" list must equal the codes reported, and no "forbidden" code
    may appear; exit 3 otherwise, with the differences.
  - RV_BLESS=1: "expected" becomes exactly the codes reported (in report order); "forbidden", "args" and the
    comment are kept as written by hand. A forbidden code that appears is never blessed: exit 3.
Review the diff of a blessed file by hand: each code must be what its fixture was built to show
(tests/fixtures/make_with_openssl.sh). Standard library only.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(repo, "examples", "sample", "expected_findings.json")
    with open(path, encoding="utf-8") as fh:
        expected = json.load(fh)
    with tempfile.TemporaryDirectory() as out:
        env = dict(os.environ, RV_NO_TIMESTAMP="1")
        cmd = [binary, "analyze", "-i", "examples/sample/evidence", "--progress", "none", "-o", out] + expected["args"]
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True, text=True)
        if r.returncode not in (0, 3):
            print(r.stdout, r.stderr, file=sys.stderr)
            return r.returncode or 1
        got = {}
        for t in glob.glob(os.path.join(out, "reports", "*", "items", "*", "technical.json")):
            with open(t, encoding="utf-8") as fh:
                tech = json.load(fh)
            got[tech["item"]["file_name"]] = [f["code"] for f in tech["findings"]]
    problems = []
    bless = os.environ.get("RV_BLESS") == "1"
    items = expected["items"]
    for name in sorted(set(items) | set(got)):
        want = items.get(name, {"expected": [], "forbidden": []})
        codes = got.get(name, [])
        for c in want.get("forbidden", []):
            if c in codes:
                problems.append(f"{name}: reports forbidden {c} (got {codes})")
        if not bless and sorted(want["expected"]) != sorted(set(codes)):
            problems.append(f"{name}: expected {sorted(want['expected'])}, got {sorted(set(codes))}")
        if bless:
            seen = []
            for c in codes:
                if c not in seen:
                    seen.append(c)
            want["expected"] = seen
            want.setdefault("forbidden", [])
            items[name] = want
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 3
    if bless:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(expected, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"blessed {path} ({len(items)} items); review the diff by hand")
    else:
        print(f"{path}: {len(items)} items agree with the analysis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
