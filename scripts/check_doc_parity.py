#!/usr/bin/env python3
"""Translated user docs keep the shape of their English reference (Python standard library only).

Every `<name>.es.md` and `<name>.fr.md` (repository root and docs/) is compared with `<name>.md`: the number of
headings, numbered steps, fenced code blocks, table rows and "to be verified" markers must be equal, and the first
line must say that the English page is the reference. The pages in REQUIRED must exist in both languages.

Run from the repository root (CI does): python -I scripts/check_doc_parity.py [ROOT]
Exit code 0 when every pair matches, 1 otherwise (one line per problem).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REQUIRED = ["README.md", "docs/usage.md", "docs/usage-gui.md", "docs/installation.md", "docs/quick-guide.md"]
LANGS = {"es": "versión de referencia", "fr": "version de référence"}
MARKER = "to be verified"
HEADING = re.compile(r"^#{1,6} ")
STEP = re.compile(r"^\s*\d+\.\s")


def shape(text: str) -> dict:
    """Counts the structure of a Markdown page; headings, steps and table rows inside code blocks are ignored."""
    counts = {"headings": 0, "numbered steps": 0, "code blocks": 0, "table rows": 0,
              f'"{MARKER}" markers': text.count(MARKER)}
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if not fenced:
                counts["code blocks"] += 1
            fenced = not fenced
            continue
        if fenced:
            continue
        if HEADING.match(line):
            counts["headings"] += 1
        elif STEP.match(line):
            counts["numbered steps"] += 1
        elif line.lstrip().startswith("|"):
            counts["table rows"] += 1
    return counts


def translations(root: Path) -> list[Path]:
    found = []
    for base in (root, root / "docs"):
        for lang in LANGS:
            found.extend(sorted(base.glob(f"*.{lang}.md")))
    return found


def check(root: Path) -> list[str]:
    problems = []
    for ref in REQUIRED:
        for lang in LANGS:
            t = root / ref.replace(".md", f".{lang}.md")
            if not t.is_file():
                problems.append(f"{t.relative_to(root).as_posix()}: missing (translation of {ref})")
    for t in translations(root):
        lang = t.suffixes[-2].lstrip(".")
        ref = t.with_name(t.name[: -len(f".{lang}.md")] + ".md")
        name = t.relative_to(root).as_posix()
        if not ref.is_file():
            problems.append(f"{name}: no English page {ref.name} to compare with")
            continue
        text = t.read_text(encoding="utf-8")
        first = next((line for line in text.splitlines() if line.strip()), "")
        if not (first.startswith(">") and LANGS[lang] in first and ref.name in first):
            problems.append(f"{name}: the first line must say that {ref.name} is the reference version "
                            f"('{LANGS[lang]}')")
        want, got = shape(ref.read_text(encoding="utf-8")), shape(text)
        for k in want:
            if want[k] != got[k]:
                problems.append(f"{name}: {got[k]} {k}, {ref.name} has {want[k]}")
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    problems = check(root)
    pairs = len(translations(root))
    for p in problems:
        print(f"FAIL  {p}")
    if problems:
        return 1
    print(f"OK  {pairs} translated pages have the shape of their English reference")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
