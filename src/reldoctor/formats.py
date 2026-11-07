"""Machine-readable report formats: SARIF 2.1.0 and JUnit XML."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, Tuple
from xml.sax.saxutils import escape, quoteattr

_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def _clean(s: str) -> str:
    return _XML_BAD.sub("�", s)


def to_sarif(findings, checks: Dict[str, Tuple[str, str]], version: str) -> str:
    level = {"error": "error", "warn": "warning", "info": "note"}
    codes = sorted({f.code for f in findings})
    rules = [{"id": c, "name": c,
              "shortDescription": {"text": checks[c][1]},
              "defaultConfiguration": {"level": level[checks[c][0]]}} for c in codes]
    index = {c: i for i, c in enumerate(codes)}
    results = []
    for f in findings:
        results.append({
            "ruleId": f.code, "ruleIndex": index[f.code], "level": level[f.severity],
            "message": {"text": _clean(f.message)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(f.file or "dist")}}}],
            # a stable identity lets GitHub code scanning match the same finding across runs
            "partialFingerprints": {"reldoctor/v1": hashlib.sha256(
                f"{f.code}\0{f.file}\0{f.message}".encode("utf-8", "replace")).hexdigest()[:32]},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "reldoctor", "version": version,
                                      "informationUri": "https://github.com/calasdan-sketch/reldoctor",
                                      "rules": rules}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)


def _uri(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._~/-]", lambda m: "%%%02X" % ord(m.group()), name.replace("\\", "/"))


def to_junit(findings, strict: bool) -> str:
    """One <testcase> per finding; failures for errors (and warnings when strict)."""
    cases, failures = [], 0
    for f in findings:
        fail = f.severity == "error" or (strict and f.severity == "warn")
        failures += fail
        name = quoteattr(_clean(f"{f.code} {f.file}".strip()))
        body = ""
        if fail:
            body = (f"<failure message={quoteattr(_clean(f.message)[:300])} type={quoteattr(f.severity)}>"
                    f"{escape(_clean(f.message))}</failure>")
        elif f.severity == "warn":
            body = f"<system-out>{escape(_clean(f.message))}</system-out>"
        cases.append(f'<testcase classname="reldoctor" name={name}>{body}</testcase>')
    if not cases:
        cases.append('<testcase classname="reldoctor" name="release-audit"/>')
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="reldoctor" tests="{len(cases)}" failures="{failures}" errors="0">\n'
            + "\n".join(cases) + "\n</testsuite>")


def to_markdown(findings, failed: bool, errors: int, warns: int) -> str:
    """A table for $GITHUB_STEP_SUMMARY or a pull-request comment."""
    from .safety import escape_terminal

    def cell(text: str) -> str:
        text = escape_terminal(text).replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
        for ch in "[]()!*_~":
            text = text.replace(ch, "\\" + ch)
        return text

    head = f"### reldoctor: {'FAIL' if failed else 'PASS'} ({errors} error(s), {warns} warning(s))"
    if not findings:
        return head
    rows = ["| | check | file | what |", "|---|---|---|---|"]
    mark = {"error": "x", "warn": "!", "info": "i"}
    for f in findings:
        rows.append(f"| {mark.get(f.severity, '?')} | `{f.code}` | {cell(f.file)} | {cell(f.message)} |")
    return head + "\n\n" + "\n".join(rows)
