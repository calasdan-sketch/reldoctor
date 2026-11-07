"""Release-readiness checks over built artifacts (wheel + sdist).

Everything here inspects what will actually be uploaded — the artifact, not
the source tree — so findings reflect what installers and PyPI will see.
Archives are treated as untrusted: nothing is extracted, reads are bounded,
and member names are never used as filesystem paths.
"""
from __future__ import annotations

import base64
import csv
import email.message
import email.parser
import hashlib
import io
import os
import posixpath
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from . import diff as _diff
from . import metacheck, nested, supply, wheelcheck
from .binary import sniff
from .reqs import parse_requirement
from .safety import (
    JUNK_DIRS,
    JUNK_FILES,
    VCS_DIRS,
    StreamScanner,
    is_normalized_path,
    path_allowed,
    redact,
    resolve_link_escapes,
    sensitive_file_kind,
    maybe_sensitive_file_kind,
    unsafe_path_reason,
)

PEP440 = re.compile(
    r"^([1-9][0-9]*!)?(0|[1-9][0-9]*)"
    r"(\.(0|[1-9][0-9]*))*"
    r"((a|b|rc)(0|[1-9][0-9]*))?"
    r"(\.post(0|[1-9][0-9]*))?"
    r"(\.dev(0|[1-9][0-9]*))?"
    r"(\+[a-z0-9]+(\.[a-z0-9]+)*)?$"
)
# name = module[.sub]:attr[.sub] [extra1, extra2]
ENTRY_POINT = re.compile(
    r"^[^=\s][^=]*?\s*=\s*[A-Za-z_][\w.]*\s*(:\s*[A-Za-z_][\w.]*)?"
    r"\s*(\[\s*[\w.-]+(\s*,\s*[\w.-]+)*\s*\])?$"
)
CONTENT_TYPES = {"text/plain", "text/x-rst", "text/markdown"}
MARKDOWN_VARIANTS = {"GFM", "CommonMark"}  # packaging.metadata, case-sensitive
# warehouse forklift/metadata.py SUPPORTED_METADATA_VERSIONS
SUPPORTED_METADATA_VERSIONS = {"1.0", "1.1", "1.2", "2.1", "2.2", "2.3", "2.4", "2.5"}
DIST_FIELDS = ("Requires-Dist", "Provides-Dist", "Obsoletes-Dist")
MAX_MEMBER_PATH = 200           # Windows MAX_PATH is 260, and site-packages takes ~60-80 of it
MAX_SUMMARY_LENGTH = 512        # warehouse _LENGTH_LIMITS
MAX_VERSION_LENGTH = 128        # warehouse MAX_VERSION_LENGTH
MAX_PROJECT_URL_LABEL = 32      # warehouse project-url label limit
# warehouse legacy.py: zips over 64 MiB uncompressed and > 50x ratio are rejected,
# and only stored/deflated members are accepted
COMPRESSION_RATIO_MIN_SIZE = 64 * 1024 * 1024
COMPRESSION_RATIO_THRESHOLD = 50
ALLOWED_ZIP_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
BINARY_EXT = re.compile(r"\.(pyd|dll|dylib|so(\.\d+)*)$", re.IGNORECASE)

# Bounds for untrusted archives.
MAX_METADATA_BYTES = 16 * 1024 * 1024        # METADATA / PKG-INFO / RECORD
MAX_ARCHIVE_READ = 1024 * 1024 * 1024        # total bytes hashed/scanned per archive
DEFAULT_MAX_MEMBERS = 100_000
MAX_MEMBERS = DEFAULT_MAX_MEMBERS            # members per archive (CLI: --max-members)
CHUNK = 1024 * 1024

# code -> (severity, what it means). Severity lives here so a code is always
# reported at the same level, and `reldoctor --list-checks` documents itself.
CHECKS: Dict[str, Tuple[str, str]] = {
    # discovery
    "no_artifacts": ("error", "no wheel or sdist found"),
    "missing_wheel": ("warn", "no wheel built; pip will build from the sdist"),
    "missing_sdist": ("warn", "no sdist built"),
    "sdist_zip_format": ("warn", "sdist is a .zip; PEP 625 sdists are .tar.gz"),
    # archive safety (both formats)
    "wheel_corrupt": ("error", "wheel is not a readable zip"),
    "sdist_corrupt": ("error", "sdist is not a readable tarball"),
    "unsafe_path": ("error", "member path is absolute, uses '..', a drive letter or backslashes"),
    "path_not_normalized": ("error", "member path is not normalized (a/./b, a//b, ./a); PyPI rejects it"),
    "too_many_members": ("error", "archive has more members than --max-members; not inspected further"),
    "sparse_member": ("error", "sdist has a GNU sparse member; PyPI rejects it"),
    "unsupported_compression": ("error", "wheel member is not stored/deflated (bzip2, lzma...); PyPI rejects it"),
    "compression_ratio": ("error", "wheel expands > 50x and past 64 MiB; PyPI rejects it as a zip bomb"),
    "zip_symlink": ("warn", "wheel member carries symlink mode bits"),
    "duplicate_entry": ("error", "the same path appears twice in the archive"),
    "case_collision": ("warn", "paths differ only by case (collide on Windows/macOS)"),
    "unsafe_link": ("error", "sdist symlink/hardlink points outside the archive (chains followed)"),
    "special_file": ("error", "sdist contains a device, FIFO or other special file"),
    "archive_too_large": ("warn", "archive exceeds the read budget; hash/secret checks are partial"),
    "member_unreadable": ("error", "an archive member could not be read"),
    # leaks and junk
    "sensitive_file": ("error", "a credential file (.env, .pypirc, SSH key...) is shipped"),
    "secret_in_file": ("error", "a file contains a token or private key"),
    "nested_archive_partial": ("warn", "a zip/tar bundled inside the release was too deep, large or full to "
                                       "inspect completely"),
    "long_path": ("warn", "a member path over 200 characters can pass Windows' 260-character limit once installed"),
    "maybe_sensitive_file": ("warn", "a file named like credentials or secrets (credentials.json, secrets.yml, "
                                     "local_settings.py, *.env...) is shipped"),
    "vcs_metadata_shipped": ("warn", ".git/.hg/.svn directory shipped"),
    "junk_file": ("warn", "tool caches, editor dirs or OS junk shipped"),
    "bytecode_shipped": ("warn", "wheel ships .pyc/__pycache__"),
    # wheel structure
    "bad_wheel_filename": ("error", "wheel filename is not name-version[-build]-py-abi-plat.whl"),
    "wheel_name_not_normalized": ("error", "wheel filename project part is not the normalized name; PyPI rejects it"),
    "wheel_no_dist_info": ("error", "not exactly one .dist-info/METADATA"),
    "no_wheel_file": ("error", ".dist-info/WHEEL missing"),
    "wheel_no_version": ("error", "WHEEL lacks Wheel-Version"),
    "wheel_tag_mismatch": ("warn", "WHEEL Tag lines disagree with the filename tags"),
    "binary_in_pure_wheel": ("error", "compiled extension inside a none-any wheel"),
    "no_record": ("error", ".dist-info/RECORD missing"),
    "record_incomplete": ("warn", "files in the wheel are not listed in RECORD"),
    "record_missing_file": ("error", "RECORD lists a file that is not in the wheel"),
    "record_hash_mismatch": ("error", "RECORD hash does not match the file"),
    "record_size_mismatch": ("error", "RECORD size does not match the file"),
    "record_weak_hash": ("error", "RECORD uses md5/sha1 or an unknown algorithm"),
    "record_no_hash": ("warn", "RECORD row has no hash"),
    "record_unparseable": ("error", "RECORD is not valid CSV (NUL bytes, oversized fields...)"),
    "bad_entry_point": ("error", "entry_points.txt line does not parse"),
    # metadata (wheel METADATA and sdist PKG-INFO)
    "name_mismatch": ("error", "metadata Name disagrees with the filename"),
    "version_mismatch": ("error", "metadata Version disagrees with the filename"),
    "version_not_pep440": ("error", "Version is not canonical PEP 440"),
    "local_version": ("error", "Version has a +local segment; PyPI rejects it"),
    "dev_version": ("warn", "Version is a .dev release"),
    "no_summary": ("warn", "no Summary"),
    "summary_too_long": ("error", "Summary longer than 512 characters; PyPI rejects it"),
    "version_too_long": ("error", "Version longer than 128 characters; PyPI rejects it"),
    "no_requires_python": ("warn", "no Requires-Python"),
    "no_license_metadata": ("warn", "no License, License-Expression or License classifier"),
    "license_conflict": ("error", "both License and License-Expression set; PyPI rejects this (PEP 639)"),
    "license_classifier_with_expression": ("warn", "License :: classifiers alongside License-Expression (PEP 639)"),
    "license_file_missing": ("error", "a License-File is not in the archive (PEP 639)"),
    "no_long_description": ("warn", "no long description"),
    "no_content_type": ("warn", "long description has no Description-Content-Type"),
    "bad_content_type": ("error", "Description-Content-Type is not text/plain|x-rst|markdown, "
                                  "UTF-8, GFM/CommonMark; PyPI rejects it"),
    "direct_url_dependency": ("error", "Requires/Provides/Obsoletes-Dist uses a direct URL; PyPI rejects it"),
    "bad_requirement": ("error", "a *-Dist value is not a valid PEP 508 requirement; PyPI rejects it"),
    "project_url_rejected": ("error", "Project-URL has no label, a label over 32 chars, or no URL; PyPI rejects it"),
    "bad_project_url": ("warn", "Project-URL/Home-page is not an http(s) URL"),
    "old_metadata_version": ("warn", "Metadata-Version older than 2.1"),
    "bad_metadata_version": ("error", "Metadata-Version is unparseable or not one PyPI accepts"),
    # sdist structure
    "sdist_no_root": ("error", "sdist does not have exactly one top-level directory"),
    "sdist_root_mismatch": ("warn", "sdist top-level dir is not {name}-{version}"),
    "sdist_name_not_normalized": ("warn", "sdist filename project part is not normalized (PEP 625)"),
    "sdist_no_build_config": ("error", "sdist has neither pyproject.toml nor setup.py"),
    "sdist_no_pkg_info": ("error", "sdist lacks PKG-INFO"),
    "sdist_no_version": ("error", "PKG-INFO has no Version"),
    "sdist_no_license_file": ("warn", "no LICENSE/COPYING file in the sdist"),
    "sdist_version": ("info", "the version found in PKG-INFO"),
    # cross-artifact
    "version_drift": ("error", "artifacts disagree on version"),
    "name_drift": ("error", "artifacts are for different projects"),
    "metadata_drift": ("warn", "wheel and sdist metadata disagree (dependencies, Requires-Python...)"),
    "wheel_metadata_drift": ("warn", "wheels of one release disagree on dependencies, Requires-Python, license or "
                                     "summary (stale wheel from another commit?)"),
    "wheel_source_drift": ("warn", "the same Python file has different content in two wheels of one release "
                                   "(stale wheel from another commit?)"),
}

for _mod in (metacheck, supply, wheelcheck, _diff):
    for _code in _mod.CHECKS_EXTRA:
        assert _code not in CHECKS, _code
    CHECKS.update(_mod.CHECKS_EXTRA)

# a stdlib finding on any of these already explains why packaging would reject the file
_METADATA_CODES = {"version_not_pep440", "local_version", "license_conflict", "license_file_missing",
                   "bad_content_type", "direct_url_dependency", "bad_requirement", "project_url_rejected",
                   "bad_metadata_version", "invalid_classifier", "deprecated_classifier",
                   "invalid_license_expression", "bad_requires_python", "invalid_author_email",
                   "invalid_dynamic_field", "bad_url_field", "field_newer_than_metadata_version",
                   "license_expression_old_metadata",
                   "summary_too_long", "version_too_long"}

# Codes that can never be silenced: ignoring them would let a broken or empty
# release pass, so the gate has to stay closed.
UNIGNORABLE = {"no_artifacts", "wheel_corrupt", "sdist_corrupt", "wheel_no_dist_info",
               "sdist_no_pkg_info", "member_unreadable", "record_unparseable", "too_many_members"}


@dataclass(frozen=True)
class Finding:
    severity: str  # error | warn | info
    code: str
    message: str
    file: str = ""

    def as_dict(self):
        return {"severity": self.severity, "code": self.code,
                "message": self.message, "file": self.file}


def _f(code: str, message: str, file: str = "") -> Finding:
    # Every message is redacted here, centrally: findings quote archive
    # content (URLs, requirement strings, paths) that may carry credentials.
    return Finding(CHECKS[code][0], code, redact(message), redact(file))


def _fp(pairs, label: str) -> List[Finding]:
    return [_f(code, msg, label) for code, msg in pairs]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def filename_normalize(name: str) -> str:
    """Project name as it must appear in wheel/sdist filenames."""
    return re.sub(r"[-_.]+", "_", name).lower()


def parse_metadata(text: str) -> email.message.Message:
    """Parse RFC822-style metadata into a Message (keeps repeated headers such
    as Classifier listable via get_all — a plain dict would lose them)."""
    return email.parser.Parser().parsestr(text)


# --- metadata checks shared by wheel METADATA and sdist PKG-INFO ----------

def _long_description(meta: email.message.Message) -> str:
    body = meta.get_payload()
    if isinstance(body, str) and body.strip():
        return body
    return meta.get("Description", "") or ""


def _md_version(meta: email.message.Message) -> Tuple[int, int]:
    try:
        major, minor = (meta.get("Metadata-Version") or "0.0").strip().split(".")[:2]
        return int(major), int(minor)
    except ValueError:
        return (0, 0)


def _url_ok(url: str) -> bool:
    return bool(re.match(r"^https?://[^\s/$.?#][^\s]*$", url.strip(), re.IGNORECASE))


def check_metadata(meta: email.message.Message, label: str,
                   members: Set[str], license_root: str) -> List[Finding]:
    """Checks PyPI applies to metadata regardless of artifact type.

    `members` is the archive's member names; `license_root` is where
    License-File paths resolve ("x.dist-info/licenses/" or "x-1.0/").
    """
    out: List[Finding] = []
    version = meta.get("Version", "") or ""
    if not PEP440.match(version):
        out.append(_f("version_not_pep440", f"Version {version!r} is not PEP 440", label))
    if "+" in version:
        out.append(_f("local_version", f"Version {version!r} has a local segment; PyPI rejects it", label))
    if ".dev" in version:
        out.append(_f("dev_version", f"Version {version!r} is a dev release", label))
    if not meta.get("Summary"):
        out.append(_f("no_summary", "metadata has no Summary", label))
    if not meta.get("Requires-Python"):
        out.append(_f("no_requires_python", "metadata has no Requires-Python", label))

    has_license = bool(meta.get("License"))
    has_expr = bool(meta.get("License-Expression"))
    license_classifiers = [c for c in meta.get_all("Classifier", []) if c.startswith("License ::")]
    if has_license and has_expr:
        out.append(_f("license_conflict",
                      "both License and License-Expression are set; PyPI rejects this (PEP 639)", label))
    if has_expr and license_classifiers:
        out.append(_f("license_classifier_with_expression",
                      f"{len(license_classifiers)} License :: classifier(s) alongside License-Expression", label))
    any_license_classifier = any("License" in c for c in meta.get_all("Classifier", []))
    if not (has_license or has_expr or any_license_classifier):
        out.append(_f("no_license_metadata", "no License, License-Expression or License :: classifier", label))
    # License-File placement is only specified from Metadata 2.4 (PEP 639);
    # older setuptools put the files elsewhere, so don't second-guess them.
    for lf in meta.get_all("License-File", []) if _md_version(meta) >= (2, 4) else []:
        lf = lf.strip()
        if lf and (unsafe_path_reason(lf) or license_root + lf not in members):
            out.append(_f("license_file_missing",
                          f"License-File {lf!r} is not at {license_root}{lf}", label))

    desc = _long_description(meta)
    dct = (meta.get("Description-Content-Type") or "").strip()
    if not desc.strip():
        out.append(_f("no_long_description", "metadata has no long description", label))
    elif not dct:
        out.append(_f("no_content_type",
                      "long description present but no Description-Content-Type; "
                      "PyPI may render it as plain text", label))
    if dct:
        problem = content_type_problem(dct)
        if problem:
            out.append(_f("bad_content_type", f"Description-Content-Type {dct!r}: {problem}", label))
    summary = meta.get("Summary") or ""
    if len(summary) > MAX_SUMMARY_LENGTH:
        out.append(_f("summary_too_long", f"Summary is {len(summary)} characters (max {MAX_SUMMARY_LENGTH})", label))
    if len(version) > MAX_VERSION_LENGTH:
        out.append(_f("version_too_long", f"Version is {len(version)} characters (max {MAX_VERSION_LENGTH})", label))

    out.extend(check_dist_fields(meta, label))
    for pu in meta.get_all("Project-URL", []):
        lab, sep, url = pu.partition(",")
        lab, url = lab.strip(), url.strip()
        if not sep or not lab or not url or len(lab) > MAX_PROJECT_URL_LABEL:
            out.append(_f("project_url_rejected",
                          f"Project-URL {pu.strip()!r} needs 'Label, URL' with a label of at most "
                          f"{MAX_PROJECT_URL_LABEL} characters", label))
        elif not _url_ok(url):
            out.append(_f("bad_project_url", f"Project-URL {pu.strip()!r} is not an http(s) URL", label))
    home = meta.get("Home-page")
    if home and home.strip().upper() != "UNKNOWN" and not _url_ok(home):
        out.append(_f("bad_project_url", f"Home-page {home.strip()!r} is not an http(s) URL", label))
    out.extend(check_metadata_version(meta, label))
    out.extend(_fp(metacheck.all_metadata_checks(meta, _md_version(meta)), label))
    if desc.strip():
        out.extend(_fp(metacheck.check_readme(meta, desc), label))
    return out


def content_type_problem(value: str) -> Optional[str]:
    """Mirror packaging.metadata's Description-Content-Type validation."""
    msg = email.message.Message()
    msg["content-type"] = value
    ctype = msg.get_content_type().lower()
    if ctype not in CONTENT_TYPES or ctype not in value.lower():
        return f"must be one of {sorted(CONTENT_TYPES)}"
    charset = msg.get_param("charset", "UTF-8")
    if not isinstance(charset, str) or charset.lower() != "utf-8":
        return "only charset=UTF-8 is allowed"
    variant = msg.get_param("variant", "GFM")
    if ctype == "text/markdown" and variant not in MARKDOWN_VARIANTS:
        return f"Markdown variant must be one of {sorted(MARKDOWN_VARIANTS)}"
    return None


def check_dist_fields(meta: email.message.Message, label: str) -> List[Finding]:
    """Requires-/Provides-/Obsoletes-Dist must parse and must not be direct URLs."""
    out: List[Finding] = []
    for field in DIST_FIELDS:
        for req in meta.get_all(field, []):
            err, direct = parse_requirement(req)
            if err:
                out.append(_f("bad_requirement", f"{field} {req.strip()!r} is invalid: {err}", label))
            elif direct:
                out.append(_f("direct_url_dependency",
                              f"{field} {req.strip()!r} is a direct URL; PyPI rejects "
                              "\"Can't have direct dependency\"", label))
    return out


def check_metadata_version(meta: email.message.Message, label: str) -> List[Finding]:
    md_ver = (meta.get("Metadata-Version", "") or "").strip()
    if md_ver not in SUPPORTED_METADATA_VERSIONS:
        return [_f("bad_metadata_version",
                   f"Metadata-Version {md_ver!r} is not one PyPI accepts "
                   f"({', '.join(sorted(SUPPORTED_METADATA_VERSIONS))})", label)]
    if _md_version(meta) < (2, 1):
        return [_f("old_metadata_version", f"Metadata-Version {md_ver} is old; use >= 2.1", label)]
    return []


# --- member-level checks shared by both archive types ---------------------

def check_member_names(names: List[str], label: str, allow: Tuple[str, ...] = ()) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[str] = set()
    folded: Dict[str, str] = {}
    dup_reported: Set[str] = set()
    junk: Set[str] = set()
    vcs = False
    unnormalized: List[str] = []
    maybe_files: List[Tuple[str, str]] = []
    long_paths: List[str] = []
    for n in names:
        reason = unsafe_path_reason(n)
        if reason:
            out.append(_f("unsafe_path", f"member {n!r} {reason}", label))
        elif not is_normalized_path(n):
            unnormalized.append(n)
        key = n.rstrip("/")
        if key in seen and key not in dup_reported:
            dup_reported.add(key)
            out.append(_f("duplicate_entry", f"{key!r} appears more than once", label))
        elif key not in seen:
            low = key.lower()
            if low in folded and folded[low] != key:
                out.append(_f("case_collision", f"{folded[low]!r} and {key!r} differ only by case", label))
            folded.setdefault(low, key)
        seen.add(key)
        if len(key) > MAX_MEMBER_PATH:
            long_paths.append(key)
        kind = sensitive_file_kind(key)
        if kind and not path_allowed(key, allow):
            out.append(_f("sensitive_file", f"{key!r} looks like a {kind}; it would be public on PyPI", label))
        elif not kind and not path_allowed(key, allow) and not key.endswith("/"):
            maybe = maybe_sensitive_file_kind(key)
            if maybe:
                maybe_files.append((key, maybe))
        parts = key.split("/")
        if any(p in VCS_DIRS for p in parts[:-1]) or parts[-1] in VCS_DIRS:
            vcs = True
        hit = next((p for p in parts if p in JUNK_DIRS), None) or (
            parts[-1] if parts[-1] in JUNK_FILES else None)
        if hit:
            junk.add(hit)
    if long_paths:
        out.append(_f("long_path",
                      f"{len(long_paths)} member path(s) are over {MAX_MEMBER_PATH} characters (longest "
                      f"{max(map(len, long_paths))}); installed under site-packages they can pass Windows' "
                      "260-character path limit and fail to install there", label))
    if maybe_files:
        shown = ", ".join(f"{k!r} ({why})" for k, why in maybe_files[:3])
        out.append(_f("maybe_sensitive_file",
                      f"{len(maybe_files)} file(s) are usually credentials or secrets: {shown}. If they are "
                      "harmless data, exempt them with --allow-path", label))
    if unnormalized:
        out.append(_f("path_not_normalized",
                      f"{len(unnormalized)} member path(s) are not normalized (e.g. {unnormalized[0]!r}); "
                      "PyPI rejects \"Archive member path is not normalized\"", label))
    if vcs:
        out.append(_f("vcs_metadata_shipped", "version-control metadata (.git/.hg/.svn) is shipped", label))
    if junk:
        out.append(_f("junk_file", f"shipped junk: {', '.join(sorted(junk))}", label))
    return out


_ZIP_READ_ERRORS = (zipfile.BadZipFile, RuntimeError, OSError, zlib.error, NotImplementedError, EOFError,
                    ValueError, UnicodeError)


class _Budget:
    def __init__(self, limit: Optional[int] = None):
        self.left = MAX_ARCHIVE_READ if limit is None else limit
        self.exhausted = False

    def take(self, n: int) -> bool:
        if n > self.left:
            self.exhausted = True
            return False
        self.left -= n
        return True


def _read_capped(fp, cap: int) -> Optional[bytes]:
    data = fp.read(cap + 1)
    return None if len(data) > cap else data


def _record_hash(fp, algo: str) -> Tuple[str, int]:
    h = hashlib.new(algo)
    size = 0
    while True:
        chunk = fp.read(CHUNK)
        if not chunk:
            break
        size += len(chunk)
        h.update(chunk)
    return base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii"), size


def _scan_stream(fp, name: str = "") -> StreamScanner:
    scanner = StreamScanner(name)
    while True:
        chunk = fp.read(CHUNK)
        if not chunk:
            break
        scanner.feed(chunk)
    return scanner


_SOURCE_MAP = re.compile(r"\.(js|mjs|css)\.map$", re.IGNORECASE)
_LARGE_FILE = 20 * 1024 * 1024
MAX_PYPI_FILE = 100 * 1024 * 1024
_SQLITE_MAGIC = b"SQLite format 3\x00"


class _Agg:
    """Per-artifact roll-up of findings that are reported once, not per file."""

    def __init__(self):
        self.local: Dict[str, List[str]] = {}

    def paths(self, name: str, users: List[str]) -> None:
        for u in users:
            self.local.setdefault(u, []).append(name)

    # Documentation and source files quote example paths (`/home/guido/...`), so a
    # name seen only there is trusted only when it recurs; any other file type
    # (compiled code, JSON, configs, source maps) is a strong signal on its own.
    _DOC_EXT = (".py", ".pyi", ".md", ".rst", ".txt", ".html", ".ipynb", ".cfg", ".toml", ".yml", ".yaml")

    def findings(self, label: str) -> List[Finding]:
        real: Dict[str, List[str]] = {}
        for user, names in self.local.items():
            strong = any(not (n.lower().endswith(self._DOC_EXT) or n.endswith(("/METADATA", "/PKG-INFO", "PKG-INFO")))
                         for n in names)
            if strong or len(set(names)) >= 3:
                real[user] = names
        if not real:
            return []
        files = sorted({n for v in real.values() for n in v})
        users = ", ".join(sorted(real)[:5])
        return [_f("local_path_leak",
                   f"{len(files)} file(s) contain a personal home-directory path for user(s) {users} "
                   f"(e.g. {files[0]!r}); it exposes a username and machine layout. Build in a clean "
                   "container or strip paths", label)]


def _file_findings(name: str, size: int, sc: StreamScanner, label: str, allowed: bool,
                   agg: _Agg) -> List[Finding]:
    """Findings from one scanned file. `allowed` (from --allow-path) exempts the
    secret and personal-path checks only."""
    out: List[Finding] = []
    if sc.kinds and not allowed:
        out.append(_f("secret_in_file", f"{name!r} contains what looks like a {', '.join(sc.kinds)} "
                                        "(value not shown); it would be public on PyPI. If this is a deliberate "
                                        "test fixture, exempt it with --allow-path", label))
    if sc.obfuscated:
        out.append(_f("obfuscated_exec", f"{name!r} runs exec()/eval() on decoded data (base64/zlib/marshal...)", label))
    if sc.local_users and not allowed:
        agg.paths(name, sc.local_users)
    if sc.head.startswith(_SQLITE_MAGIC):
        out.append(_f("database_file_shipped", f"{name!r} is a SQLite database", label))
    if _SOURCE_MAP.search(name):
        out.append(_f("source_map_shipped", f"{name!r} is a source map: it embeds original source and build paths", label))
    if size >= _LARGE_FILE and not wheelcheck.binary_is_library(name):
        out.append(_f("large_file", f"{name!r} is {size:,} bytes; confirm it belongs in a package", label))
    return out


def _nested_findings(data: bytes, name: str, label: str, allow: Tuple[str, ...], agg: _Agg,
                     limits: "nested.Limits") -> List[Finding]:
    """Credentials inside an archive that is itself a file of the release."""
    out: List[Finding] = []
    for display, size, sc, sens in nested.inspect(data, name, limits):
        if path_allowed(display, allow):
            continue
        if sens:
            out.append(_f("sensitive_file", f"{display!r} looks like a {sens}; it would be public on PyPI", label))
        out.extend(_file_findings(display, size, sc, label, False, agg))
    return out


def _nested_partial(limits: "nested.Limits", label: str) -> List[Finding]:
    if not limits.skipped:
        return []
    return [_f("nested_archive_partial",
               f"{limits.skipped} bundled archive(s) or member(s) were not fully inspected (deeper than "
               f"{nested.MAX_DEPTH} levels, over {nested.MAX_NESTED_BYTES // (1024 * 1024)} MiB, or too many "
               "members); secret coverage inside them is partial", label)]


def _secret_findings(name: str, kinds: List[str], label: str) -> List[Finding]:
    sc = StreamScanner(name)
    sc.kinds = list(kinds)
    return _file_findings(name, 0, sc, label, False, _Agg())


# --- wheel -----------------------------------------------------------------

def _wheel_filename(fname: str) -> Optional[Tuple[str, str, Set[str]]]:
    if not fname.endswith(".whl"):
        return None
    parts = fname[:-4].split("-")
    if len(parts) not in (5, 6):
        return None
    py, abi, plat = parts[-3:]
    if len(parts) == 6 and not re.match(r"^\d", parts[2]):
        return None
    tags = {f"{a}-{b}-{c}" for a in py.split(".") for b in abi.split(".") for c in plat.split(".")}
    return parts[0], parts[1], tags


def check_wheel(path: str, allow: Tuple[str, ...] = ()) -> List[Finding]:
    """Audit one wheel. `allow` holds --allow-path globs exempt from the
    credential/secret checks (for deliberate test fixtures)."""
    out: List[Finding] = []
    fname = os.path.basename(path)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError, RuntimeError, zlib.error):
        return [_f("wheel_corrupt", f"{fname} is not a valid zip", fname)]
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            return [_f("too_many_members", f"{len(infos)} members (limit {MAX_MEMBERS}; see --max-members)", fname)]
        names = [i.filename for i in infos]
        out.extend(check_member_names(names, fname, allow))
        bad_comp = [i.filename for i in infos if i.compress_type not in ALLOWED_ZIP_COMPRESSION]
        if bad_comp:
            out.append(_f("unsupported_compression",
                          f"{len(bad_comp)} member(s) use a compression PyPI rejects (e.g. {bad_comp[0]!r}); "
                          "only stored/deflated are accepted", fname))
        try:
            packed = os.stat(path).st_size
        except OSError:
            packed = 0
        unpacked = sum(i.file_size for i in infos)
        if packed and unpacked > COMPRESSION_RATIO_MIN_SIZE and unpacked / packed > COMPRESSION_RATIO_THRESHOLD:
            out.append(_f("compression_ratio",
                          f"expands to {unpacked} bytes from {packed} (> {COMPRESSION_RATIO_THRESHOLD}x); "
                          "PyPI rejects this as a zip bomb", fname))
        links = [i.filename for i in infos if (i.external_attr >> 16) & 0o170000 == 0o120000]
        if links:
            out.append(_f("zip_symlink", f"{len(links)} member(s) have symlink mode bits (e.g. {links[0]!r}); "
                                         "installers write them as regular files", fname))
        files = [i for i in infos if not i.is_dir()]
        member_set = {i.filename for i in files}

        parsed = _wheel_filename(fname)
        if not parsed:
            out.append(_f("bad_wheel_filename", f"{fname!r} is not name-version[-build]-py-abi-plat.whl", fname))
            file_proj = fname.split("-")[0]
            file_ver = fname.split("-")[1] if "-" in fname else ""
            file_tags: Set[str] = set()
        else:
            file_proj, file_ver, file_tags = parsed
            if file_proj != filename_normalize(file_proj):
                out.append(_f("wheel_name_not_normalized",
                              f"filename project {file_proj!r} should be {filename_normalize(file_proj)!r}", fname))

        metas = [n for n in member_set
                 if n.endswith(".dist-info/METADATA") and n.count("/") == 1]
        if len(metas) != 1:
            out.append(_f("wheel_no_dist_info", f"{fname}: expected exactly one top-level .dist-info/METADATA", fname))
            return out
        meta_path = metas[0]
        dist_dir = meta_path.rsplit("/", 1)[0]

        def read_small(member: str) -> Optional[str]:
            try:
                with zf.open(member) as fp:
                    data = _read_capped(fp, MAX_METADATA_BYTES)
            except _ZIP_READ_ERRORS as e:
                out.append(_f("member_unreadable", f"{member!r}: {type(e).__name__}", fname))
                return None
            if data is None:
                out.append(_f("member_unreadable", f"{member!r} exceeds {MAX_METADATA_BYTES} bytes", fname))
                return None
            return data.decode("utf-8", "replace")

        text = read_small(meta_path)
        if text is None:
            return out
        meta = parse_metadata(text)
        name, version = meta.get("Name", "") or "", meta.get("Version", "") or ""
        if normalize(name) != normalize(file_proj):
            out.append(_f("name_mismatch", f"METADATA Name {name!r} != filename project {file_proj!r}", fname))
        if version != file_ver:
            out.append(_f("version_mismatch", f"METADATA Version {version!r} != filename version {file_ver!r}", fname))
        out.extend(check_metadata(meta, fname, member_set, f"{dist_dir}/licenses/"))
        out.extend(_fp(wheelcheck.check_dist_info_name(fname, dist_dir), fname))
        pk = wheelcheck.packaging_problems(text)
        if pk and not any(f.severity == "error" and f.code in _METADATA_CODES for f in out):
            out.extend(_f("packaging_rejects_metadata", m, fname) for m in pk)
        desc_text = _long_description(meta)
        if desc_text.strip():
            rp = wheelcheck.render_problem(meta, desc_text)
            if rp:
                out.append(_f("description_render_failed", f"PyPI would show 'description failed to render': {rp}", fname))

        # WHEEL file and tags
        root_purelib: Optional[bool] = None
        if f"{dist_dir}/WHEEL" not in member_set:
            out.append(_f("no_wheel_file", f"{dist_dir}/WHEEL missing", fname))
        else:
            wtext = read_small(f"{dist_dir}/WHEEL")
            if wtext is not None:
                wheel_meta = parse_metadata(wtext)
                if not wheel_meta.get("Wheel-Version"):
                    out.append(_f("wheel_no_version", "WHEEL file lacks Wheel-Version", fname))
                wtags = set()
                for raw_tag in wheel_meta.get_all("Tag", []):
                    bits = raw_tag.strip().split("-")
                    if len(bits) == 3:   # compressed form: cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64
                        wtags |= {f"{a}-{b}-{c}" for a in bits[0].split(".") for b in bits[1].split(".")
                                  for c in bits[2].split(".")}
                    elif raw_tag.strip():
                        wtags.add(raw_tag.strip())
                purelib_raw = (wheel_meta.get("Root-Is-Purelib") or "").strip().lower()
                if purelib_raw in ("true", "false"):
                    root_purelib = purelib_raw == "true"
                if file_tags and wtags and wtags != file_tags:
                    out.append(_f("wheel_tag_mismatch",
                                  f"WHEEL tags {sorted(wtags)} != filename tags {sorted(file_tags)}", fname))
        if file_tags and all(t.endswith("-none-any") for t in file_tags):
            binaries = sorted(n for n in member_set if BINARY_EXT.search(n))
            if binaries:
                out.append(_f("binary_in_pure_wheel",
                              f"{len(binaries)} compiled file(s) in a none-any wheel (e.g. {binaries[0]!r}); "
                              "it will install on platforms it cannot run on", fname))
        pyc = [n for n in member_set if n.endswith((".pyc", ".pyo")) or "/__pycache__/" in f"/{n}"]
        if pyc:
            out.append(_f("bytecode_shipped", f"{len(pyc)} bytecode file(s) shipped (e.g. {pyc[0]!r})", fname))

        # RECORD: every listed file exists with matching sha256 and size
        budget = _Budget()
        record_path = f"{dist_dir}/RECORD"
        hashed: Set[str] = set()
        if record_path not in member_set:
            out.append(_f("no_record", f"{record_path} missing", fname))
        else:
            rtext = read_small(record_path)
            if rtext is not None:
                listed: Set[str] = set()
                unhashed: List[str] = []
                problems = {"record_missing_file": [], "record_hash_mismatch": [],
                            "record_size_mismatch": [], "record_weak_hash": []}
                try:
                    if "\x00" in rtext:
                        raise csv.Error("line contains NUL")
                    rows = list(csv.reader(io.StringIO(rtext)))
                except csv.Error as e:
                    out.append(_f("record_unparseable", f"{record_path} is not valid CSV ({e}); "
                                                        "its hashes cannot be checked", fname))
                    rows = None
                for row in rows or []:
                    if not row or not row[0].strip():
                        continue
                    rpath = row[0]
                    listed.add(rpath)
                    rhash = row[1].strip() if len(row) > 1 else ""
                    rsize = row[2].strip() if len(row) > 2 else ""
                    if rpath == record_path or rpath.startswith(f"{dist_dir}/RECORD."):
                        continue  # RECORD itself and its signatures carry no hash
                    if rpath not in member_set:
                        problems["record_missing_file"].append(rpath)
                        continue
                    if not rhash:
                        unhashed.append(rpath)
                        continue
                    algo, _, digest = rhash.partition("=")
                    algo = algo.lower()
                    if algo not in {"sha256", "sha384", "sha512"}:
                        problems["record_weak_hash"].append(rpath)
                        continue
                    if not budget.take(zf.getinfo(rpath).file_size):
                        continue
                    try:
                        with zf.open(rpath) as fp:
                            actual, size = _record_hash(fp, algo)
                    except _ZIP_READ_ERRORS as e:
                        out.append(_f("member_unreadable", f"{rpath!r}: {type(e).__name__}", fname))
                        continue
                    hashed.add(rpath)
                    if actual != digest:
                        problems["record_hash_mismatch"].append(rpath)
                    if rsize and rsize != str(size):
                        problems["record_size_mismatch"].append(rpath)
                why = {
                    "record_missing_file": "listed in RECORD but not in the wheel",
                    "record_hash_mismatch": "content differs from its RECORD sha256 (changed after build?)",
                    "record_size_mismatch": "size differs from RECORD",
                    "record_weak_hash": "hashed with md5/sha1 or an unknown algorithm",
                }
                for code, paths in problems.items():
                    if paths:
                        out.append(_f(code, f"{len(paths)} file(s) {why[code]} (e.g. {paths[0]!r})", fname))
                if unhashed:
                    out.append(_f("record_no_hash", f"{len(unhashed)} RECORD row(s) without a hash "
                                                    f"(e.g. {unhashed[0]!r})", fname))
                missing = sorted(n for n in member_set if n not in listed) if rows is not None else []
                if missing:
                    out.append(_f("record_incomplete",
                                  f"{len(missing)} file(s) absent from RECORD (e.g. {missing[0]!r})", fname))

        # every file is streamed once, in overlapping chunks, within the budget:
        # secrets, personal paths, obfuscated code, native-library headers
        agg = _Agg()
        nlimits = nested.Limits()
        natives: List[wheelcheck.NativeFile] = []
        for info in files:
            if not budget.take(info.file_size):
                continue
            try:
                with zf.open(info) as fp:
                    sc = _scan_stream(fp, info.filename)
            except _ZIP_READ_ERRORS as e:
                out.append(_f("member_unreadable", f"{info.filename!r}: {type(e).__name__}", fname))
                continue
            out.extend(_file_findings(info.filename, info.file_size, sc, fname,
                                      path_allowed(info.filename, allow), agg))
            if sc.head and not path_allowed(info.filename, allow) and nested.archive_kind(sc.head, info.filename):
                if info.file_size > nested.MAX_NESTED_BYTES:
                    nlimits.skipped += 1
                else:
                    try:
                        with zf.open(info) as fp:
                            blob = fp.read(info.file_size)
                    except _ZIP_READ_ERRORS:
                        blob = b""
                    out.extend(_nested_findings(blob, info.filename, fname, allow, agg, nlimits))
            bi = sniff(sc.head) if sc.head else None
            if bi is not None and wheelcheck.binary_is_library(info.filename):
                natives.append(wheelcheck.NativeFile(info.filename, bi, sc.glibc_max, sc.musl, sc.glibc_needed, sc.glibcxx_max))
            if info.filename.endswith(".pth") and info.file_size <= 65536:
                out.extend(_fp(supply.analyze_pth(info.filename, sc.head.decode("utf-8", "replace")), fname))
        out.extend(agg.findings(fname))
        out.extend(_nested_partial(nlimits, fname))
        if budget.exhausted:
            out.append(_f("archive_too_large",
                          f"more than {MAX_ARCHIVE_READ} bytes of content; hash/secret checks are partial", fname))

        # tags versus contents, top-level names
        plats = {t.split("-")[2] for t in file_tags}
        out.extend(_fp(wheelcheck.check_platform_tags(plats), fname))
        ext_names = [n for n in member_set if wheelcheck.binary_is_library(n) and re.search(r"\.(so|pyd)$", n)]
        out.extend(_fp(wheelcheck.check_wheel_tags_vs_contents(
            plats, {t.split("-")[0] for t in file_tags}, {t.split("-")[1] for t in file_tags},
            natives, ext_names, root_purelib, meta.get("Requires-Python") or ""), fname))
        tops = supply.top_level_names(n for n in member_set)
        shadow = supply.shadowed_stdlib(tops)
        if shadow:
            out.append(_f("shadows_stdlib",
                          f"top-level {', '.join(repr(x) for x in shadow)} has the name of a standard-library "
                          "module and would shadow it for every program in the environment", fname))
        clutter = supply.top_level_clutter(tops)
        if clutter:
            out.append(_f("top_level_tests",
                          f"installs top-level package(s) {', '.join(repr(x) for x in clutter)} into site-packages; "
                          "they collide with other projects' (move under your package or exclude them)", fname))

        # entry points
        ep_path = f"{dist_dir}/entry_points.txt"
        if ep_path in member_set:
            ep_text = read_small(ep_path) or ""
            for line in ep_text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    continue
                if not ENTRY_POINT.match(line):
                    out.append(_f("bad_entry_point", f"unparseable entry point: {line!r}", fname))
            out.extend(_fp(supply.entry_point_shadows(ep_text), fname))
    return out


def wheel_metadata(path: str) -> Optional[email.message.Message]:
    """METADATA of a wheel, or None if it cannot be read safely."""
    try:
        with zipfile.ZipFile(path) as zf:
            if len(zf.infolist()) > MAX_MEMBERS:
                return None
            metas = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA") and n.count("/") == 1]
            if len(metas) != 1:
                return None
            with zf.open(metas[0]) as fp:
                data = _read_capped(fp, MAX_METADATA_BYTES)
    except Exception:  # noqa: BLE001 - corrupt input is already reported by check_wheel
        return None
    return parse_metadata(data.decode("utf-8", "replace")) if data is not None else None


# --- sdist -----------------------------------------------------------------

_SDIST_NAME = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+)\.tar\.gz$")


def _open_tar(path: str):
    return tarfile.open(path, "r:*")


def check_sdist(path: str, allow: Tuple[str, ...] = ()) -> List[Finding]:
    out: List[Finding] = []
    fname = os.path.basename(path)
    try:
        tf = _open_tar(path)
        with tf:
            members = []
            for mem in tf:
                members.append(mem)
                if len(members) > MAX_MEMBERS:
                    return [_f("too_many_members", f"more than {MAX_MEMBERS} members "
                                                   "(see --max-members)", fname)]
            return out + _check_sdist_members(tf, members, fname, allow)
    except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError) as e:
        return [_f("sdist_corrupt", f"{fname} is not a valid tarball ({type(e).__name__})", fname)]


def _check_sdist_members(tf: tarfile.TarFile, members: List[tarfile.TarInfo], fname: str,
                         allow: Tuple[str, ...] = ()) -> List[Finding]:
    out: List[Finding] = []
    # Raw names are what PyPI validates (path_not_normalized is reported on them);
    # structure checks below use the normalized form, so one "./" prefix does not
    # cascade into a dozen misleading findings.
    out.extend(check_member_names([m.name for m in members], fname, allow))
    by_name: Dict[str, tarfile.TarInfo] = {}
    for mem in members:
        norm = posixpath.normpath(mem.name) if mem.name else ""
        if norm not in ("", "."):
            by_name.setdefault(norm, mem)
    links = {n: mem.linkname for n, mem in by_name.items() if mem.issym()}
    for n, mem in by_name.items():
        if mem.issparse():
            out.append(_f("sparse_member", f"{n!r} is a GNU sparse member; PyPI rejects these", fname))
        if mem.issym():
            if resolve_link_escapes(links, n, mem.linkname):
                out.append(_f("unsafe_link", f"{n!r} links to {mem.linkname!r}, which resolves outside "
                                             "the archive", fname))
        elif mem.islnk():
            target = mem.linkname
            if unsafe_path_reason(target) or resolve_link_escapes(links, "", target) \
                    or posixpath.normpath(target) not in by_name:
                out.append(_f("unsafe_link", f"hardlink {n!r} points at {target!r}, which is not a "
                                             "member of the archive", fname))
        elif not (mem.isfile() or mem.isdir()):
            out.append(_f("special_file", f"{n!r} is not a regular file or directory", fname))

    names = list(by_name)
    top = {n.split("/", 1)[0] for n in names}
    if len(top) != 1:
        out.append(_f("sdist_no_root", "sdist should contain exactly one top-level directory", fname))
    root = sorted(top)[0] if top else ""
    name_set = set(names)
    file_set = {n for n, mem in by_name.items() if mem.isfile()}

    m = _SDIST_NAME.match(fname)
    file_proj, file_ver = (m.group("name"), m.group("version")) if m else ("", "")
    if m and file_proj != filename_normalize(file_proj):
        out.append(_f("sdist_name_not_normalized",
                      f"filename project {file_proj!r} should be {filename_normalize(file_proj)!r} (PEP 625)", fname))
    if m and root and root != f"{file_proj}-{file_ver}":
        out.append(_f("sdist_root_mismatch", f"top-level dir {root!r} != {file_proj}-{file_ver}", fname))

    if not ({f"{root}/pyproject.toml", f"{root}/setup.py"} & name_set):
        out.append(_f("sdist_no_build_config", "sdist contains neither pyproject.toml nor setup.py", fname))

    budget = _Budget()
    agg = _Agg()
    nlimits = nested.Limits()
    pkg_info = f"{root}/PKG-INFO"
    if pkg_info not in file_set:
        out.append(_f("sdist_no_pkg_info", "sdist lacks PKG-INFO", fname))
    else:
        fp = tf.extractfile(by_name[pkg_info])
        data = _read_capped(fp, MAX_METADATA_BYTES) if fp else None
        if data is None:
            out.append(_f("member_unreadable", f"{pkg_info!r} is unreadable or too large", fname))
        else:
            meta = parse_metadata(data.decode("utf-8", "replace"))
            version = meta.get("Version")
            if not version:
                out.append(_f("sdist_no_version", "PKG-INFO has no Version", fname))
            out.append(_f("sdist_version", f"PKG-INFO version {version}", fname))
            if m and meta.get("Name") and normalize(meta.get("Name")) != normalize(file_proj):
                out.append(_f("name_mismatch", f"PKG-INFO Name {meta.get('Name')!r} != filename project "
                                               f"{file_proj!r}", fname))
            if m and version and version != file_ver:
                out.append(_f("version_mismatch", f"PKG-INFO Version {version!r} != filename version "
                                                  f"{file_ver!r}", fname))
            # License-File checks only: other metadata rules are reported on the wheel,
            # and PKG-INFO below Metadata-Version 2.2 is not authoritative.
            for lf in meta.get_all("License-File", []) if _md_version(meta) >= (2, 4) else []:
                lf = lf.strip()
                if lf and (unsafe_path_reason(lf) or f"{root}/{lf}" not in file_set):
                    out.append(_f("license_file_missing", f"License-File {lf!r} is not at {root}/{lf}", fname))
            # PyPI applies these to the sdist's own PKG-INFO too (warehouse
            # validate_artifact_dependencies)
            out.extend(check_dist_fields(meta, fname))
            out.extend(check_metadata_version(meta, fname))
            if meta.get("License") and meta.get("License-Expression"):
                out.append(_f("license_conflict",
                              "both License and License-Expression are set; PyPI rejects this (PEP 639)", fname))

    if not any(re.search(r"(LICEN[CS]E|COPYING)", n.rsplit("/", 1)[-1].upper()) for n in file_set):
        out.append(_f("sdist_no_license_file", "no LICENSE/COPYING file in the sdist", fname))

    for n, mem in by_name.items():
        if path_allowed(n, allow):
            continue
        source = mem
        if mem.islnk():
            # a hardlink ships its target's bytes under a new name: scan them
            # here even when the target itself sits under --allow-path
            source = by_name.get(posixpath.normpath(mem.linkname))
            if source is None or not source.isfile():
                continue
        elif not mem.isfile():
            continue
        if not budget.take(source.size):
            continue
        fp = tf.extractfile(source)
        if fp is None:
            continue
        sc = _scan_stream(fp, n)
        out.extend(_file_findings(n, source.size, sc, fname, False, agg))
        if sc.head and nested.archive_kind(sc.head, n):
            if source.size > nested.MAX_NESTED_BYTES:
                nlimits.skipped += 1
            else:
                fp2 = tf.extractfile(source)
                if fp2 is not None:
                    out.extend(_nested_findings(fp2.read(source.size), n, fname, allow, agg, nlimits))
    out.extend(agg.findings(fname))
    out.extend(_nested_partial(nlimits, fname))
    if budget.exhausted:
        out.append(_f("archive_too_large",
                      f"more than {MAX_ARCHIVE_READ} bytes of content; secret scan is partial", fname))
    setup = by_name.get(f"{root}/setup.py")
    if setup is not None and setup.isfile() and not path_allowed(f"{root}/setup.py", allow):
        fp = tf.extractfile(setup)
        data = fp.read(supply.MAX_SETUP_BYTES + 1) if fp else b""
        out.extend(_fp(supply.analyze_setup_py(data), fname))
    return out


def sdist_metadata(path: str) -> Optional[email.message.Message]:
    try:
        with _open_tar(path) as tf:
            for count, mem in enumerate(tf):
                if count >= MAX_MEMBERS:
                    return None
                name = posixpath.normpath(mem.name)
                if mem.isfile() and name.count("/") == 1 and name.endswith("/PKG-INFO"):
                    fp = tf.extractfile(mem)
                    data = _read_capped(fp, MAX_METADATA_BYTES) if fp else None
                    return parse_metadata(data.decode("utf-8", "replace")) if data is not None else None
    except Exception:  # noqa: BLE001 - corrupt input is already reported by check_sdist
        return None
    return None


# --- cross-artifact --------------------------------------------------------

def _reqs(meta: email.message.Message) -> Set[str]:
    return {re.sub(r"\s+", "", r).lower() for r in meta.get_all("Requires-Dist", [])}


def check_drift(wheel_metas: List[Tuple[str, email.message.Message]],
                sdist_metas: List[Tuple[str, email.message.Message]]) -> List[Finding]:
    out: List[Finding] = []
    for sname, smeta in sdist_metas:
        try:
            md = tuple(int(x) for x in (smeta.get("Metadata-Version") or "0").split(".")[:2])
        except ValueError:
            continue
        if md < (2, 2):
            continue  # PKG-INFO fields are only trustworthy from Metadata 2.2 (PEP 643)
        dynamic = {d.strip().lower() for d in smeta.get_all("Dynamic", [])}
        for wname, wmeta in wheel_metas:
            diffs = []
            if "requires-python" not in dynamic and (smeta.get("Requires-Python") or "") != (wmeta.get("Requires-Python") or ""):
                diffs.append("Requires-Python")
            if "requires-dist" not in dynamic and _reqs(smeta) != _reqs(wmeta):
                diffs.append("Requires-Dist")
            if "summary" not in dynamic and (smeta.get("Summary") or "") != (wmeta.get("Summary") or ""):
                diffs.append("Summary")
            if diffs:
                out.append(_f("metadata_drift", f"{wname} and {sname} disagree on {', '.join(diffs)}", wname))
    return out


def _wheel_fingerprint(path: str) -> Optional[Tuple[email.message.Message, Dict[str, str]]]:
    """METADATA and {python-source path: RECORD hash} of one wheel, read cheaply and bounded."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                return None
            tops = [i.filename for i in infos if i.filename.endswith(".dist-info/METADATA") and i.filename.count("/") == 1]
            if len(tops) != 1:
                return None
            dist = tops[0].rsplit("/", 1)[0]
            with zf.open(tops[0]) as fp:
                mdata = _read_capped(fp, MAX_METADATA_BYTES)
            rec = ""
            if f"{dist}/RECORD" in {i.filename for i in infos}:
                with zf.open(f"{dist}/RECORD") as fp:
                    rdata = _read_capped(fp, MAX_METADATA_BYTES)
                rec = rdata.decode("utf-8", "replace") if rdata is not None else ""
    except Exception:  # noqa: BLE001 - unreadable wheels are reported by check_wheel
        return None
    if mdata is None:
        return None
    hashes: Dict[str, str] = {}
    try:
        for row in csv.reader(io.StringIO(rec)):
            if len(row) > 1 and row[0].endswith(".py") and ".dist-info/" not in row[0] \
                    and row[1].lower().startswith("sha256="):
                hashes[row[0]] = row[1]
    except csv.Error:
        pass
    return parse_metadata(mdata.decode("utf-8", "replace")), hashes


def check_wheel_consistency(wheels: List[str]) -> List[Finding]:
    """Wheels of one release must come from one build: a stale wheel left in dist/
    from an earlier commit shows up as metadata or Python source that differs."""
    prints = [(os.path.basename(w), fp) for w in wheels for fp in [_wheel_fingerprint(w)] if fp]
    if len(prints) < 2:
        return []
    out: List[Finding] = []
    ref_name, (ref_meta, ref_src) = prints[0]
    for name, (meta, src) in prints[1:]:
        diffs = []
        for field in ("Summary", "Requires-Python", "License-Expression", "License"):
            if (meta.get(field) or "").strip() != (ref_meta.get(field) or "").strip():
                diffs.append(field)
        for field in ("Requires-Dist", "Provides-Extra"):
            if {x.strip() for x in meta.get_all(field, [])} != {x.strip() for x in ref_meta.get_all(field, [])}:
                diffs.append(field)
        if diffs:
            out.append(_f("wheel_metadata_drift",
                          f"{name} and {ref_name} are the same release but disagree on {', '.join(diffs)}; "
                          "one of them was probably built from a different commit (stale file in dist/?)", name))
        changed = sorted(p for p in set(src) & set(ref_src) if src[p] != ref_src[p])
        if changed:
            out.append(_f("wheel_source_drift",
                          f"{len(changed)} Python file(s) differ between {name} and {ref_name} (e.g. {changed[0]!r}); "
                          "wheels of one release should ship the same source. Rebuild from a clean dist/ "
                          "(generated per-platform files are fine: --ignore wheel_source_drift)", name))
    return out


def _iter_artifacts(paths: Iterable[str]) -> Tuple[List[str], List[str], List[str], List[str]]:
    wheels, sdists, zips, dirs = [], [], [], []
    for p in paths:
        if os.path.isdir(p):
            dirs.append(p)
            for f in sorted(os.listdir(p)):
                full = os.path.join(p, f)
                if not os.path.isfile(full):
                    continue
                if f.endswith(".whl"):
                    wheels.append(full)
                elif f.endswith(".tar.gz"):
                    sdists.append(full)
                elif f.endswith(".zip"):
                    zips.append(full)
        elif os.path.isfile(p):
            if p.endswith(".whl"):
                wheels.append(p)
            elif p.endswith(".tar.gz"):
                sdists.append(p)
            elif p.endswith(".zip"):
                zips.append(p)
            else:
                raise ValueError(f"not a wheel, sdist or directory: {p}")
        else:
            raise FileNotFoundError(p)
    return wheels, sdists, zips, dirs


def _check_one(job: Tuple[str, str, Tuple[str, ...], int]) -> List[Finding]:
    kind, path, allow, max_members = job
    global MAX_MEMBERS
    MAX_MEMBERS = max_members      # a spawned worker starts from the default; the CLI value travels with the job
    return check_wheel(path, allow) if kind == "wheel" else check_sdist(path, allow)


PARALLEL_MIN_BYTES = 64 * 1024 * 1024    # below this a process pool costs more than it saves


def _auto_jobs(paths: List[str]) -> int:
    try:
        total = sum(os.path.getsize(p) for p in paths)
    except OSError:
        return 1
    if len(paths) < 3 or total < PARALLEL_MIN_BYTES:
        return 1
    return max(1, min(4, os.cpu_count() or 1, len(paths)))


def auto_jobs_for(paths: Iterable[str]) -> int:
    """Worker count the CLI uses when --jobs is not given."""
    try:
        wheels, sdists, _z, _o = _iter_artifacts(list(paths))
    except (OSError, ValueError):
        return 1
    return _auto_jobs(wheels + sdists)


LAST_RUN_PARALLEL = False    # whether the last _run_checks really used worker processes (for tests)


def _run_checks(jobs_list: List[Tuple[str, str, Tuple[str, ...], int]], jobs: int) -> List[List[Finding]]:
    """Findings per artifact, in input order. A process pool is used when `jobs` > 1
    and silently replaced by a sequential run if the platform cannot start one."""
    global LAST_RUN_PARALLEL
    LAST_RUN_PARALLEL = False
    if jobs > 1 and len(jobs_list) > 1:
        try:
            import multiprocessing
            from concurrent.futures import ProcessPoolExecutor
            # "spawn" behaves the same on every OS (no fork of a threaded parent) and keeps tests honest
            with ProcessPoolExecutor(max_workers=min(jobs, len(jobs_list)),
                                     mp_context=multiprocessing.get_context("spawn")) as pool:
                results = list(pool.map(_check_one, jobs_list))
            LAST_RUN_PARALLEL = True
            return results
        except Exception:  # noqa: BLE001 - BrokenProcessPool, OSError, pickling: fall back, never lose a check
            pass
    return [_check_one(j) for j in jobs_list]


def diagnose(paths: Iterable[str], allow: Iterable[str] = (), against: Iterable[str] = (),
             jobs: int = 1) -> List[Finding]:
    """Diagnose artifacts given as files and/or directories of artifacts.

    `allow` is a list of member-path globs (e.g. "tests/certs/*") exempt
    from the credential-file and secret checks only. `against` is the previous
    release (directories and/or files) for the offline release-diff checks.
    `jobs` is the number of worker processes (default 1: in-process; the CLI picks
    automatically for big releases, see `_auto_jobs`).
    """
    paths = list(paths)
    allow = tuple(allow)
    wheels, sdists, zips, _ = _iter_artifacts(paths)
    out: List[Finding] = []
    if not wheels and not sdists:
        where = ", ".join(paths) or "(nothing)"
        out.append(_f("no_artifacts", f"no .whl or .tar.gz files in {where}"))
        for z in zips:
            out.append(_f("sdist_zip_format", "zip sdists are not standard; build a .tar.gz", os.path.basename(z)))
        return out
    if not wheels:
        out.append(_f("missing_wheel", "no wheel built; pip will fall back to the sdist"))
    if not sdists:
        out.append(_f("missing_sdist", "no sdist built; PyPI encourages shipping one"))
    for z in zips:
        out.append(_f("sdist_zip_format", "zip sdists are not standard (PEP 625); build a .tar.gz",
                      os.path.basename(z)))

    versions: Set[str] = set()
    projects: Set[str] = set()
    wheel_metas, sdist_metas = [], []
    todo = [("wheel", w, allow, MAX_MEMBERS) for w in wheels] + [("sdist", x, allow, MAX_MEMBERS) for x in sdists]
    results = _run_checks(todo, jobs)
    by_path = {(k, p): r for (k, p, _a, _m), r in zip(todo, results)}
    for w in wheels:
        out.extend(by_path[("wheel", w)])
        parts = os.path.basename(w).split("-")
        if len(parts) > 1:
            projects.add(normalize(parts[0]))
            versions.add(parts[1])
        meta = wheel_metadata(w)
        if meta is not None:
            wheel_metas.append((os.path.basename(w), meta))
    for s in sdists:
        out.extend(by_path[("sdist", s)])
        m = _SDIST_NAME.match(os.path.basename(s))
        if m:
            projects.add(normalize(m.group("name")))
            versions.add(m.group("version"))
        meta = sdist_metadata(s)
        if meta is not None:
            sdist_metas.append((os.path.basename(s), meta))
    if len(projects) > 1:
        out.append(_f("name_drift", f"artifacts are for different projects: {sorted(projects)}"))
    if len(versions) > 1:
        out.append(_f("version_drift", f"artifacts disagree on version: {sorted(versions)}"))
    out.extend(check_drift(wheel_metas, sdist_metas))
    out.extend(check_wheel_consistency(wheels))

    if not wheels:  # sdist-only upload: PyPI validates its PKG-INFO fields, so do the table checks here
        for sname, smeta in sdist_metas:
            if _md_version(smeta) >= (2, 2):
                out.extend(_fp(metacheck.all_metadata_checks(smeta, _md_version(smeta)), sname))
    for w in wheels + sdists:
        try:
            if os.path.getsize(w) > MAX_PYPI_FILE:
                out.append(_f("file_too_large", f"{os.path.getsize(w):,} bytes; PyPI's default per-file limit is "
                                                f"{MAX_PYPI_FILE:,} (a project can ask for more)", os.path.basename(w)))
        except OSError:
            pass
    seen_names: Set[str] = set()
    for _label, m in wheel_metas + sdist_metas:
        nm = m.get("Name")
        if nm and nm not in seen_names:
            seen_names.add(nm)
            target = supply.typosquat_target(nm)
            if target:
                out.append(_f("typosquat_name", f"project name {nm!r} is one edit from the very popular {target!r}; "
                                                "PyPI may block it as a typosquat and users may confuse them"))
    against = list(against)
    if against:
        out.extend(_release_diff(wheels + sdists, against))
    return out


def _release_diff(current: List[str], against: List[str]) -> List[Finding]:
    try:
        old_w, old_s, _, _ = _iter_artifacts(against)
    except (FileNotFoundError, ValueError, NotADirectoryError):
        return [_f("diff_unreadable", f"--against path not found or not a release directory: {against}")]
    # the new set must not include the old files themselves
    cur_real = {os.path.realpath(p) for p in current}
    olds = [p for p in old_w + old_s if os.path.realpath(p) not in cur_real]
    if not olds:
        return [_f("diff_unreadable", "no wheel or sdist found in --against; nothing to compare with")]
    new_inv = [i for i in (_diff.read_inventory(p) for p in current) if i]
    old_inv = [i for i in (_diff.read_inventory(p) for p in olds) if i]
    if not old_inv:
        return [_f("diff_unreadable", "the artifacts in --against could not be read")]
    return [_f(code, msg) for code, msg in _diff.compare(new_inv, old_inv)]


def diagnose_dist_dir(dist_dir: str) -> List[Finding]:
    """Diagnose every artifact in a dist directory, plus cross-artifact checks."""
    if not os.path.isdir(dist_dir):
        if not os.path.exists(dist_dir):
            raise FileNotFoundError(dist_dir)
        raise NotADirectoryError(dist_dir)
    return diagnose([dist_dir])
