"""Helpers for handling untrusted artifact content safely.

Everything reldoctor prints can come from an attacker-controlled archive
(member names, METADATA values), so terminal output is escaped, and leaked
secrets are reported by kind and location only, never echoed: every finding
message is passed through `redact()` before it leaves the library.
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Dict, Iterable, List, Optional, Tuple

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


# --- paths ------------------------------------------------------------------

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


def is_normalized_path(name: str) -> bool:
    """PyPI's rule (warehouse `_non_canonical_member_path`): an installer must
    not map the member to a different path, so `a/./b`, `a//b`, `./a` fail."""
    return not name.startswith("/") and posixpath.normpath(name) == name.rstrip("/")


_MAX_LINK_HOPS = 40


def resolve_link_escapes(links: Dict[str, str], member: str, target: str) -> bool:
    """True when symlink `member` -> `target` resolves outside the archive,
    following other symlinks in the same archive (chains like
    `a -> ..` then `b -> a/..`). Any absolute, drive-letter or backslash
    target, or a chain deeper than 40 hops, counts as escaping."""
    def bad_target(t: str) -> bool:
        return t.startswith("/") or "\\" in t or bool(re.match(r"^[A-Za-z]:", t))

    if bad_target(target):
        return True
    hops = 0
    # a stack of pending components, processed left to right
    resolved: List[str] = [p for p in posixpath.dirname(member).split("/") if p]
    pending: List[str] = [p for p in target.split("/") if p not in ("", ".")]
    while pending:
        part = pending.pop(0)
        if part == "..":
            if not resolved:
                return True
            resolved.pop()
            continue
        resolved.append(part)
        here = "/".join(resolved)
        if here in links:
            hops += 1
            nxt = links[here]
            if hops > _MAX_LINK_HOPS or bad_target(nxt):
                return True
            resolved.pop()
            pending = [p for p in nxt.split("/") if p not in ("", ".")] + pending
    return False


def link_escapes(member: str, target: str) -> bool:
    """True when a single tar link at `member` pointing at `target` leaves the
    archive (no chain-following; see `resolve_link_escapes`)."""
    return resolve_link_escapes({}, member, target)


# --- leaked secrets -------------------------------------------------------
# Only well-established, low-false-positive token shapes. Matches are never
# printed; the finding names the kind and the file.
_PEM_BEGIN = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
_PEM_BODY = re.compile(rb"^[A-Za-z0-9+/=:,\s-]{64,}$")
_PEM_WINDOW = 16384      # bytes after a header searched for the END line
_PEM_MAX_HEADERS = 64    # headers examined per chunk (bounds work on hostile input)

_TOKEN_SOURCES: List[Tuple[str, str]] = [
    ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ("PyPI API token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    # real Slack tokens carry numeric team/user ids: xoxb-<digits>-<digits>-<secret>
    ("Slack token", r"\bxox[abposr]-[0-9]{6,}-[0-9A-Za-z-]{8,}"),
]
SECRET_PATTERNS = [(kind, re.compile(src.encode())) for kind, src in _TOKEN_SOURCES]
_TEXT_PATTERNS = [(kind, re.compile(src)) for kind, src in _TOKEN_SOURCES]
_TEXT_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----")

# Values that are published documentation examples or obvious placeholders.
# AWS's own docs use AKIAIOSFODNN7EXAMPLE; anything that spells out EXAMPLE,
# or is mostly one repeated character, is not a live credential.
_PLACEHOLDER_WORDS = re.compile(rb"EXAMPLE|example|XXXX|xxxx|your|YOUR|placeholder|PLACEHOLDER|dummy|DUMMY")


def _is_placeholder(token: bytes) -> bool:
    body = token.split(b"_", 1)[-1] if token.startswith((b"gh", b"github_pat")) else token
    if _PLACEHOLDER_WORDS.search(token):
        return True
    return len(set(body)) < 6


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


def scan_secrets(blob: bytes) -> List[str]:
    """Kinds of secrets found in blob (deduplicated, in pattern order)."""
    kinds = ["private key"] if _has_private_key(blob) else []
    for kind, rx in SECRET_PATTERNS:
        if any(not _is_placeholder(m.group()) for m in rx.finditer(blob)):
            kinds.append(kind)
    return kinds


SCAN_OVERLAP = 32 * 1024  # > PEM window + header, > any token length


class StreamScanner:
    """Scan a file in chunks with overlap, so large files are covered too."""

    def __init__(self):
        self.kinds: List[str] = []
        self._tail = b""

    def feed(self, chunk: bytes) -> None:
        blob = self._tail + chunk
        for k in scan_secrets(blob):
            if k not in self.kinds:
                self.kinds.append(k)
        self._tail = blob[-SCAN_OVERLAP:]


_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")


def redact(text: str) -> str:
    """Strip credentials from text that will be printed: URL userinfo
    (`https://user:pass@host` -> `https://***@host`) and anything matching a
    secret pattern (placeholders included: redaction errs on hiding)."""
    text = _URL_USERINFO.sub(r"\1***@", text)
    for kind, rx in _TEXT_PATTERNS:
        text = rx.sub(f"<redacted {kind}>", text)
    return _TEXT_PEM.sub("<redacted private key>", text)


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


# --- --allow-path ---------------------------------------------------------

def path_allowed(member: str, patterns) -> bool:
    """True when `member` (or its path below the sdist root) matches an
    --allow-path glob. Matching is case-sensitive and uses '/' separators."""
    if not patterns:
        return False
    candidates = [member]
    if "/" in member:
        candidates.append(member.split("/", 1)[1])
    return any(fnmatch.fnmatchcase(c, pat) for c in candidates for pat in patterns)


# Paths an --allow-path pattern must never exempt: ordinary source files and
# credential files at typical locations, with and without an sdist root. A
# glob that matches any of them is broad enough to hide a real leak.
ALLOW_CANARIES = [
    "a", "README", "Makefile", "setup.py", "notes.txt", "id_rsa", ".env",
    "pkg/__init__.py", "pkg/mod.py", "pkg/sub/settings.py", "pkg/.env",
    "src/pkg/config.py", "config/.pypirc", "data/keys.pem", "pkg/data/creds.json",
    "x.dist-info/RECORD", "x.dist-info/METADATA", "pkg/a.b.c",
]


def broad_allow_pattern(pattern: str) -> Optional[str]:
    """Return a canary path the pattern would exempt, or None if it is narrow."""
    if not pattern.strip():
        return "(empty pattern)"
    for c in ALLOW_CANARIES:
        for full in (c, f"demo-1.0/{c}"):
            if path_allowed(full, (pattern,)):
                return full
    return None


def check_allow_patterns(patterns: Iterable[str]) -> List[Tuple[str, str]]:
    """(pattern, example it would exempt) for every over-broad pattern."""
    out = []
    for p in patterns:
        hit = broad_allow_pattern(p)
        if hit:
            out.append((p, hit))
    return out
