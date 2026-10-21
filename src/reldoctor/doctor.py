"""Release-readiness checks over built artifacts (wheel + sdist).

Everything here inspects what will actually be uploaded — the artifact, not
the source tree — so findings reflect what installers and PyPI will see.
"""
from __future__ import annotations

import email.message
import email.parser
import io
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional

PEP440 = re.compile(
    r"^([1-9][0-9]*!)?(0|[1-9][0-9]*)"
    r"(\.(0|[1-9][0-9]*))*"
    r"((a|b|rc)(0|[1-9][0-9]*))?"
    r"(\.post(0|[1-9][0-9]*))?"
    r"(\.dev(0|[1-9][0-9]*))?$"
)
ENTRY_POINT = re.compile(r"^[A-Za-z_][\w.-]*\s*=\s*[A-Za-z_][\w.]*\s*(:\s*[A-Za-z_][\w.]*)?$")


@dataclass(frozen=True)
class Finding:
    severity: str  # error | warn | info
    code: str
    message: str

    def as_dict(self):
        return {"severity": self.severity, "code": self.code, "message": self.message}


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_metadata(text: str) -> email.message.Message:
    """Parse RFC822-style metadata into a Message (keeps repeated headers such
    as Classifier listable via get_all — a plain dict would lose them)."""
    return email.parser.Parser().parsestr(text)


def check_wheel(path: str) -> List[Finding]:
    out: List[Finding] = []
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return [Finding("error", "wheel_corrupt", f"{os.path.basename(path)} is not a valid zip")]
    with zf:
        names = zf.namelist()
        dist_infos = [n for n in names if n.endswith(".dist-info/METADATA")]
        if len(dist_infos) != 1:
            return [Finding("error", "wheel_no_dist_info", f"{os.path.basename(path)}: expected exactly one .dist-info/METADATA")]
        meta_path = dist_infos[0]
        dist_dir = meta_path.rsplit("/", 1)[0]
        meta = parse_metadata(zf.read(meta_path).decode("utf-8", "replace"))

        fname = os.path.basename(path)
        parts = fname.split("-")
        file_proj, file_ver = parts[0], parts[1] if len(parts) > 1 else ""

        name, version = meta.get("Name", ""), meta.get("Version", "")
        if normalize(name) != normalize(file_proj.replace("_", "-")):
            out.append(Finding("error", "name_mismatch",
                              f"METADATA Name {name!r} != filename project {file_proj!r}"))
        if version != file_ver:
            out.append(Finding("error", "version_mismatch",
                              f"METADATA Version {version!r} != filename version {file_ver!r}"))
        if not PEP440.match(version or ""):
            out.append(Finding("error", "version_not_pep440", f"Version {version!r} is not PEP 440"))
        if "+" in (version or ""):
            out.append(Finding("error", "local_version", f"Version {version!r} has a local segment; PyPI rejects it"))
        if ".dev" in (version or ""):
            out.append(Finding("warn", "dev_version", f"Version {version!r} is a dev release"))
        if not meta.get("Summary"):
            out.append(Finding("warn", "no_summary", "METADATA has no Summary"))
        if not meta.get("Requires-Python"):
            out.append(Finding("warn", "no_requires_python", "METADATA has no Requires-Python"))
        if not meta.get("License") and not any(k.startswith("License") for k in meta):
            if not any("License" in c for c in meta.get_all("Classifier", [])):
                out.append(Finding("warn", "no_license_metadata", "no License field or License :: classifier"))
        if not any(k.startswith("Description") or k == "Description-Content-Type" for k in meta):
            body = zf.read(meta_path).decode("utf-8", "replace")
            if body.count("\n\n") == 0:
                out.append(Finding("warn", "no_long_description", "METADATA has no long description body"))
        if not meta.get("Description-Content-Type") and "\n\n" in zf.read(meta_path).decode("utf-8", "replace"):
            out.append(Finding("warn", "no_content_type",
                              "long description present but no Description-Content-Type; PyPI may render it as plain text"))

        md_ver = meta.get("Metadata-Version", "")
        try:
            if tuple(int(x) for x in md_ver.split(".")[:2]) < (2, 1):
                out.append(Finding("warn", "old_metadata_version", f"Metadata-Version {md_ver} is old; use >= 2.1"))
        except ValueError:
            out.append(Finding("error", "bad_metadata_version", f"unparseable Metadata-Version {md_ver!r}"))

        if f"{dist_dir}/WHEEL" not in names:
            out.append(Finding("error", "no_wheel_file", f"{dist_dir}/WHEEL missing"))
        else:
            wheel_meta = parse_metadata(zf.read(f"{dist_dir}/WHEEL").decode("utf-8", "replace"))
            if not wheel_meta.get("Wheel-Version"):
                out.append(Finding("error", "wheel_no_version", "WHEEL file lacks Wheel-Version"))
        if f"{dist_dir}/RECORD" not in names:
            out.append(Finding("error", "no_record", f"{dist_dir}/RECORD missing"))
        else:
            record_lines = [l for l in zf.read(f"{dist_dir}/RECORD").decode("utf-8", "replace").splitlines() if l.strip()]
            listed = {l.split(",", 1)[0] for l in record_lines}
            missing = [n for n in names if n not in listed and not n.endswith("/")]
            if missing:
                out.append(Finding("warn", "record_incomplete",
                                  f"{len(missing)} file(s) absent from RECORD (e.g. {missing[0]})"))

        ep_path = f"{dist_dir}/entry_points.txt"
        if ep_path in names:
            ep_text = zf.read(ep_path).decode("utf-8", "replace")
            section = None
            for line in ep_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1]
                    continue
                if "=" not in line or not ENTRY_POINT.match(line):
                    out.append(Finding("error", "bad_entry_point", f"unparseable entry point: {line!r}"))
    return out


def check_sdist(path: str) -> List[Finding]:
    out: List[Finding] = []
    try:
        tf = tarfile.open(path, "r:*")
    except tarfile.TarError:
        return [Finding("error", "sdist_corrupt", f"{os.path.basename(path)} is not a valid tarball")]
    with tf:
        members = tf.getnames()
        top = {m.split("/", 1)[0] for m in members}
        if len(top) != 1:
            out.append(Finding("error", "sdist_no_root", "sdist should contain exactly one top-level directory"))
        root = sorted(top)[0] if top else ""
        has_build_file = any(m == f"{root}/pyproject.toml" or m == f"{root}/setup.py" for m in members)
        if not has_build_file:
            out.append(Finding("error", "sdist_no_build_config", "sdist contains neither pyproject.toml nor setup.py"))
        pkg_info = next((m for m in members if m == f"{root}/PKG-INFO"), None)
        if not pkg_info:
            out.append(Finding("error", "sdist_no_pkg_info", "sdist lacks PKG-INFO"))
        else:
            meta = parse_metadata(tf.extractfile(pkg_info).read().decode("utf-8", "replace"))
            if not meta.get("Version"):
                out.append(Finding("error", "sdist_no_version", "PKG-INFO has no Version"))
            out.append(Finding("info", "sdist_version", f"PKG-INFO version {meta.get('Version')}"))
        if not any("LICENSE" in m.upper() or "COPYING" in m.upper() for m in members):
            out.append(Finding("warn", "sdist_no_license_file", "no LICENSE/COPYING file in the sdist"))
    return out


def diagnose_dist_dir(dist_dir: str) -> List[Finding]:
    """Diagnose every artifact in a dist directory, plus cross-artifact checks."""
    wheels = sorted(f for f in os.listdir(dist_dir) if f.endswith(".whl"))
    sdists = sorted(f for f in os.listdir(dist_dir) if f.endswith(".tar.gz"))
    out: List[Finding] = []
    if not wheels and not sdists:
        return [Finding("error", "no_artifacts", f"no .whl or .tar.gz files in {dist_dir}")]
    if not wheels:
        out.append(Finding("warn", "missing_wheel", "no wheel built; pip will fall back to the sdist"))
    if not sdists:
        out.append(Finding("warn", "missing_sdist", "no sdist built; PyPI encourages shipping one"))

    versions = set()
    for w in wheels:
        out.extend(check_wheel(os.path.join(dist_dir, w)))
        parts = w.split("-")
        if len(parts) > 1:
            versions.add(parts[1])
    for s in sdists:
        out.extend(check_sdist(os.path.join(dist_dir, s)))
        # <name>-<version>.tar.gz
        m = re.match(r"^.+-(\d[^-]*)\.tar\.gz$", s)
        if m:
            versions.add(m.group(1))
    if len(versions) > 1:
        out.append(Finding("error", "version_drift", f"artifacts disagree on version: {sorted(versions)}"))
    return out
