"""Baselines: adopt reldoctor on a project that already has warnings.

``reldoctor dist/ --write-baseline reldoctor-baseline.json`` records today's *warnings*;
``reldoctor dist/ --baseline reldoctor-baseline.json`` then hides exactly those and fails
only on anything new.

Rules that keep this from becoming a way to hide real problems:

* Only warnings can be baselined. Errors are things PyPI or an installer rejects, or leaked
  secrets; they are never written to a baseline and never matched against one.
* ``diff_*`` findings compare two specific releases, so accepting them has no meaning; they
  are never baselined.
* An entry matches on the check code, the artifact kind and the full message with the release
  version blanked out. A different file, a different number or a different path is a new finding.
* A baseline that is missing, unreadable, too large or malformed is an error (exit 2), never
  "no baseline". Failing open here would silently switch the gate off.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Iterable, List, Set, Tuple

FORMAT = 1
MAX_BYTES = 5_000_000
MAX_ENTRIES = 20_000

_WHEEL = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)(?P<rest>(?:-[^-]+){3,4}\.whl)$")
_SDIST = re.compile(r"^(?P<name>.+)-(?P<ver>[^-]+)(?P<rest>\.tar\.gz|\.zip)$")

Entry = Tuple[str, str, str]   # (code, artifact label with version blanked, message with version blanked)


class BaselineError(ValueError):
    pass


def _blank(label: str, message: str) -> Tuple[str, str]:
    for rx in (_WHEEL, _SDIST):
        m = rx.match(label)
        if m:
            ver = m.group("ver")
            norm_label = f"{m.group('name')}-{{version}}{m.group('rest')}"
            norm_msg = re.sub(r"(?<![\w.])%s(?![\w])" % re.escape(ver), "{version}", message)
            return norm_label, norm_msg
    return label, message


def entry_for(f) -> Entry:
    label, message = _blank(f.file or "", f.message)
    return (f.code, label, message)


def eligible(f) -> bool:
    """Can this finding be baselined at all?"""
    return f.severity == "warn" and not f.code.startswith("diff_")


def write(path: str, findings: Iterable) -> int:
    """Write the baseline atomically; returns the number of entries."""
    entries = sorted({entry_for(f) for f in findings if eligible(f)})
    doc = {
        "reldoctor-baseline": FORMAT,
        "note": "Warnings accepted on purpose. Review this file like code; delete an entry once the problem is fixed.",
        "entries": [{"code": c, "file": fl, "message": m} for c, fl, m in entries],
    }
    text = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".reldoctor-baseline-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(entries)


def load(path: str) -> Set[Entry]:
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            raise BaselineError(f"{size:,} bytes is too large for a baseline file (limit {MAX_BYTES:,})")
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError as e:
        raise BaselineError(f"cannot read it: {e.strerror or e}") from None
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BaselineError("it is not valid UTF-8 JSON; create it with --write-baseline") from None
    if not isinstance(doc, dict) or doc.get("reldoctor-baseline") != FORMAT:
        raise BaselineError(f"not a reldoctor baseline (format {FORMAT}); create it with --write-baseline")
    entries = doc.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise BaselineError("'entries' must be a list of at most %d items" % MAX_ENTRIES)
    out: Set[Entry] = set()
    for i, e in enumerate(entries):
        if (not isinstance(e, dict) or set(e) != {"code", "file", "message"}
                or not all(isinstance(e[k], str) for k in e)):
            raise BaselineError(f"entry {i + 1} must have exactly the text fields code, file, message")
        out.add((e["code"], e["file"], e["message"]))
    return out


def apply(findings: List, accepted: Set[Entry]) -> Tuple[List, int, List[Entry]]:
    """(findings still to report, number hidden, baseline entries that matched nothing)."""
    kept, hidden, used = [], 0, set()
    for f in findings:
        e = entry_for(f)
        if eligible(f) and e in accepted:
            hidden += 1
            used.add(e)
        else:
            kept.append(f)
    return kept, hidden, sorted(accepted - used)

