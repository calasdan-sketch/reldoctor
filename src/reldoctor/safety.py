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
    ("Slack webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Stripe live key", r"\b[sr]k_live_[0-9A-Za-z]{24,}"),
    ("OpenAI API key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"),
    ("Anthropic API key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,}"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b"),
    ("npm auth token in .npmrc", r"_authToken\s*=\s*[A-Za-z0-9_\-./+=]{16,}"),
    ("database URL with password",
     r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^\s:/@'\"<>]+:[^\s/@'\"<>]{4,}@[^\s'\"<>/]+"),
]
# Literal substrings every match must contain: a plain `in` test (memchr speed)
# gates each regex, so clean megabyte-sized binaries are not run through
# fifteen regular expressions.
_NEEDLES = {
    "AWS access key id": (b"AKIA", b"ASIA"),
    "GitHub token": (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
    "PyPI API token": (b"pypi-AgEI",),
    "Slack token": (b"xox",),
    "Slack webhook": (b"hooks.slack.com",),
    "Google API key": (b"AIza",),
    "Stripe live key": (b"k_live_",),
    "OpenAI API key": (b"sk-proj-", b"sk-svcacct-", b"sk-admin-"),
    "Anthropic API key": (b"sk-ant-",),
    "npm token": (b"npm_",),
    "SendGrid API key": (b"SG.",),
    "GitLab token": (b"glpat-",),
    "Hugging Face token": (b"hf_",),
    "npm auth token in .npmrc": (b"_authToken",),
    "database URL with password": (b"://",),
}
SECRET_PATTERNS = [(kind, re.compile(src.encode()), _NEEDLES[kind]) for kind, src in _TOKEN_SOURCES]
_TEXT_PATTERNS = [(kind, re.compile(src)) for kind, src in _TOKEN_SOURCES]
_TEXT_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----")

# Values that are published documentation examples or obvious placeholders.
# AWS's own docs use AKIAIOSFODNN7EXAMPLE; anything that spells out EXAMPLE,
# or is mostly one repeated character, is not a live credential.
_PLACEHOLDER_WORDS = re.compile(rb"EXAMPLE|example|XXXX|xxxx|your|YOUR|placeholder|PLACEHOLDER|dummy|DUMMY")


_DB_PLACEHOLDER = re.compile(
    rb"(?i)://[^:]+:(?:password|passwd|pass|pwd|secret|changeme|your[-_a-z]*|xxx+|\*+|\$\{?\w+\}?|%s|<[^>]*>|\{[^}]*\}"
    rb"|example|test|admin|root|postgres|guest|user)@|"
    rb"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host|hostname|example\.\w+|db|database|redis|postgres)(?=[:/?\s'\"]|$)")


def _is_placeholder(token: bytes) -> bool:
    if b"://" in token and _DB_PLACEHOLDER.search(token):
        return True
    if token.startswith(b"_authToken") or token.startswith(b"_authtoken"):
        return bool(re.search(rb"\$\{|\$[A-Z_]+|<|xxxx|XXXX|your", token))
    body = token.split(b"_", 1)[-1] if token.startswith((b"gh", b"github_pat")) else token
    if _PLACEHOLDER_WORDS.search(token):
        return True
    return len(set(body)) < 6


_PEM_ESCAPED = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\\r)?\\n[A-Za-z0-9+/=\\rn]{60,}")


def _has_private_key(blob: bytes) -> bool:
    """A whole PEM block, not just the header: code that *parses* keys
    mentions the header string without containing a key."""
    if _PEM_ESCAPED.search(blob):  # a key serialized inside JSON/YAML with literal \\n
        return True
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
    kinds = ["private key"] if (b"PRIVATE KEY" in blob and _has_private_key(blob)) else []
    for kind, rx, needles in SECRET_PATTERNS:
        if not any(n in blob for n in needles):
            continue
        if any(not _is_placeholder(m.group()) for m in rx.finditer(blob)):
            kinds.append(kind)
    return kinds


SCAN_OVERLAP = 32 * 1024  # > PEM window + header, > any token length


# Usernames that appear in docs, CI images and templates rather than on a developer's laptop.
GENERIC_USERS = {
    "user", "username", "your-username", "yourname", "you", "me", "name", "foo", "bar", "test",
    "tester", "someone", "somebody", "john", "jane", "jdoe", "johndoe", "janedoe", "alice", "bob",
    "example", "runner", "runneradmin", "vsts", "builder", "build", "buildbot", "jenkins", "ubuntu",
    "travis", "circleci", "ec2-user", "admin", "root", "docker", "vagrant", "appveyor", "azureuser",
    "buildkite-agent", "gitlab-runner", "pi", "dev", "developer", "default", "all users", "public",
    "pkg", "nobody", "www-data", "app", "code", "work", "home", "myuser", "my-user", "xxx", "x",
    "shared", "tmp", "local", "bin", "lib", "opt", "usr", "var", "etc", "conda", "mambauser",
    "sandbox", "codespace", "gitpod", "vscode", "node", "wheel", "cibuildwheel", "build-user",
}
_LOCAL_PATH = re.compile(
    rb"(?<![A-Za-z0-9_.-])(?:/home/([A-Za-z0-9_-][A-Za-z0-9._-]{1,31})/|/Users/([A-Za-z0-9._ -]{2,32})/|"
    rb"[A-Za-z]:\\{1,2}Users\\{1,2}([A-Za-z0-9._ -]{2,32})\\{1,2})")
_OBFUSCATED_EXEC = re.compile(
    rb"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?"
    rb"(?:base64\.(?:b64|urlsafe_b64|b32|a85)decode|zlib\.decompress|bz2\.decompress|lzma\.decompress|"
    rb"codecs\.decode|marshal\.loads|bytes\.fromhex|binascii\.unhexlify|__import__\s*\(\s*['\"](?:base64|zlib|marshal)['\"])")
ELF_MAGIC = b"\x7fELF"


def _mask_user(name: str) -> str:
    return name[:1] + "***"


class StreamScanner:
    """Scan a file in chunks with overlap, so large files are covered too.

    Besides secrets it notes (all bounded, nothing executed): personal
    paths such as /home/<user>/, obfuscated exec() payloads in Python files,
    and for ELF files the newest glibc symbol version they reference.
    """

    MAX_PATHS = 50

    def __init__(self, name: str = ""):
        self.name = name
        self.kinds: List[str] = []
        self.local_users: List[str] = []   # masked, deduplicated
        self.obfuscated = False
        self.head = b""
        self.glibc_max: Optional[Tuple[int, int]] = None
        self.musl = False
        self.glibc_needed = False
        self._elf = False
        self._tail = b""
        self._first = True
        self._is_py = name.endswith((".py", ".pyw"))

    def feed(self, chunk: bytes) -> None:
        if self._first:
            self._first = False
            self.head = chunk[:65536]
            self._elf = chunk.startswith(ELF_MAGIC)
        blob = self._tail + chunk
        for k in scan_secrets(blob):
            if k not in self.kinds:
                self.kinds.append(k)
        if len(self.local_users) < self.MAX_PATHS and (b"/home/" in blob or b"/Users/" in blob or b"Users\\" in blob):
            for m in _LOCAL_PATH.finditer(blob):
                user = next(g for g in m.groups() if g).decode("utf-8", "replace")
                if user.lower() in GENERIC_USERS or user.startswith(("<", "{", "$", "%")):
                    continue
                masked = _mask_user(user)
                if masked not in self.local_users:
                    self.local_users.append(masked)
        if self._is_py and not self.obfuscated and (b"exec" in blob or b"eval" in blob) \
                and _OBFUSCATED_EXEC.search(blob):
            self.obfuscated = True
        if self._elf:
            from .binary import GLIBC_NEEDED, GLIBC_REF, MUSL_HINT
            if b"GLIBC_" in blob:
                for m in GLIBC_REF.finditer(blob):
                    v = (int(m.group(1)), int(m.group(2)))
                    if self.glibc_max is None or v > self.glibc_max:
                        self.glibc_max = v
            if not self.musl and (b"musl" in blob):
                self.musl = bool(MUSL_HINT.search(blob))
            if not self.glibc_needed and b"libc.so.6" in blob:
                self.glibc_needed = bool(GLIBC_NEEDED.search(blob))
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
    ".pgpass": "PostgreSQL password file",
    ".htpasswd": "htpasswd credentials",
    ".dockercfg": "Docker registry credentials",
    "terraform.tfstate": "Terraform state (holds secrets)",
    "terraform.tfstate.backup": "Terraform state (holds secrets)",
    "credentials.tfrc.json": "Terraform Cloud token",
    "id_rsa": "SSH private key",
    "id_dsa": "SSH private key",
    "id_ecdsa": "SSH private key",
    "id_ed25519": "SSH private key",
}
SENSITIVE_SUFFIXES = {
    ".p12": "PKCS#12 key bundle", ".pfx": "PKCS#12 key bundle", ".jks": "Java keystore",
    ".keystore": "Java keystore", ".kdbx": "KeePass database", ".tfvars": "Terraform variables file",
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
    low = base.lower()
    for suf, why in SENSITIVE_SUFFIXES.items():
        if low.endswith(suf):
            return why
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
