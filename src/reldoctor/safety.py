"""Helpers for handling untrusted artifact content safely.

Everything reldoctor prints can come from an attacker-controlled archive
(member names, METADATA values), so terminal output is escaped, and leaked
secrets are reported by kind and location only, never echoed.
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import List, Optional, Tuple

# C0/C1 controls, DEL, bidi overrides/isolates/marks, zero-width and BOM.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f"
    "\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)


def escape_terminal(text: str) -> str:
    """Make untrusted text inert on a terminal: no escapes, no bidi tricks.

    Newlines and tabs are escaped too, so one finding is always one line.
    """
    text = text.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
    return _UNSAFE_CHARS.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def unsafe_path_reason(name: str) -> Optional[str]:
    """Return why an archive member path is unsafe to extract, or None."""
    if "\x00" in name:
        return "contains a NUL byte"
    if "\\" in name:
        return "contains a backslash (Windows separator)"
    if name.startswith("/"):
        return "is an absolute path"
    if re.match(r"^[A-Za-z]:", name):
        return "starts with a drive letter"
    parts = name.split("/")
    if ".." in parts:
        return "contains a '..' component"
    return None


def link_escapes(member: str, target: str) -> bool:
    """True when a tar link at `member` pointing at `target` leaves the archive."""
    if target.startswith("/") or "\\" in target or re.match(r"^[A-Za-z]:", target):
        return True
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member), target))
    return resolved == ".." or resolved.startswith("../") or resolved.startswith("/")


# --- leaked secrets -------------------------------------------------------
# Only well-established, low-false-positive token shapes. Matches are never
# printed; the finding names the kind and the file.
_PEM_BEGIN = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
_PEM_BODY = re.compile(rb"^[A-Za-z0-9+/=:,\s-]{64,}$")
_PEM_WINDOW = 16384      # bytes after a header searched for the END line
_PEM_MAX_HEADERS = 64    # headers examined per file (bounds work on hostile input)

SECRET_PATTERNS: List[Tuple[str, "re.Pattern[bytes]"]] = [
    ("AWS access key id", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("PyPI API token", re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("Slack token", re.compile(rb"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
]


def _has_private_key(blob: bytes) -> bool:
    """A whole PEM block, not just the header: code that *parses* keys
    mentions the header string without containing a key."""
    for i, m in enumerate(_PEM_BEGIN.finditer(blob)):
        if i >= _PEM_MAX_HEADERS:
            break
        window = blob[m.end():m.end() + _PEM_WINDOW]
        end = window.find(b"-----END ")
        if end != -1 and _PEM_BODY.match(window[:end]):
            return True
    return False


SENSITIVE_BASENAMES = {
    ".pypirc": "PyPI upload credentials",
    ".netrc": "netrc credentials",
    "_netrc": "netrc credentials",
    ".git-credentials": "git credentials",
    "id_rsa": "SSH private key",
    "id_dsa": "SSH private key",
    "id_ecdsa": "SSH private key",
    "id_ed25519": "SSH private key",
}
_ENV_TEMPLATES = {"example", "sample", "template", "dist", "defaults", "tmpl", "in"}

JUNK_DIRS = {".tox", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             ".ipynb_checkpoints", ".idea", ".vscode"}
JUNK_FILES = {".DS_Store", "Thumbs.db"}
VCS_DIRS = {".git", ".hg", ".svn"}


def sensitive_file_kind(name: str) -> Optional[str]:
    """Classify a member path as a credential file, or None."""
    parts = [p for p in name.split("/") if p]
    if not parts:
        return None
    base = parts[-1]
    if base in SENSITIVE_BASENAMES:
        return SENSITIVE_BASENAMES[base]
    if base == ".env" or (base.startswith(".env.") and base[5:].lower() not in _ENV_TEMPLATES):
        return "dotenv file"
    if len(parts) >= 2 and parts[-2] == ".aws" and base in {"credentials", "config"}:
        return "AWS credentials"
    return None


def scan_secrets(blob: bytes) -> List[str]:
    """Kinds of secrets found in blob (deduplicated, in pattern order)."""
    kinds = ["private key"] if _has_private_key(blob) else []
    return kinds + [kind for kind, rx in SECRET_PATTERNS if rx.search(blob)]


def path_allowed(member: str, patterns) -> bool:
    """True when `member` (or its path below the sdist root) matches an
    --allow-path glob. Matching is case-sensitive and uses '/' separators."""
    if not patterns:
        return False
    candidates = [member]
    if "/" in member:
        candidates.append(member.split("/", 1)[1])
    return any(fnmatch.fnmatchcase(c, pat) for c in candidates for pat in patterns)
