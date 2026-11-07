"""Compare a new release with the previous one, offline, from local files.

`pip download PROJECT==OLD --no-deps -d prev/` gets the old files; then
`reldoctor dist/ --against prev/` reports what changed in ways a maintainer
should confirm on purpose: size jumps, new dependencies, new commands, new
executable code, dropped platform wheels. Nothing is extracted to disk.
"""
from __future__ import annotations

import email.message
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import pyspec

Pair = Tuple[str, str]

CHECKS_EXTRA: Dict[str, Tuple[str, str]] = {
    "diff_version_exists": ("error", "this exact filename already exists in the previous release set; PyPI never accepts a re-upload"),
    "diff_version_not_newer": ("warn", "new version is not newer than the previous one"),
    "diff_size_jump": ("warn", "artifact size changed a lot since the previous release"),
    "diff_new_dependency": ("warn", "a dependency was added since the previous release"),
    "diff_removed_dependency": ("info", "a dependency was removed since the previous release"),
    "diff_requires_python_raised": ("warn", "Requires-Python now excludes Python versions the previous release supported"),
    "diff_new_entry_point": ("warn", "a new console script or plugin entry point appeared"),
    "diff_removed_entry_point": ("warn", "a console script or entry point was removed (breaking for users of it)"),
    "diff_new_executable_code": ("warn", "new compiled binaries, .pth files or install scripts appeared"),
    "diff_removed_package": ("warn", "a top-level package present in the previous release is gone"),
    "diff_wheel_dropped": ("warn", "a platform wheel published last time is missing from this release"),
    "diff_license_changed": ("warn", "the license changed since the previous release"),
    "diff_new_files": ("info", "files added since the previous release"),
    "diff_unreadable": ("warn", "the previous release could not be read; no comparison was made"),
}

SIZE_RATIO = 2.0
SIZE_MIN_DELTA = 2 * 1024 * 1024
MAX_FILES = 100_000


@dataclass
class Inventory:
    filename: str
    kind: str                            # wheel | sdist
    project: str = ""
    version: str = ""
    tag: str = ""                        # python-abi-platform for wheels
    size: int = 0
    files: Dict[str, int] = field(default_factory=dict)
    requires: Set[str] = field(default_factory=set)
    requires_python: str = ""
    license: str = ""
    entry_points: Set[str] = field(default_factory=set)
    scripts: Set[str] = field(default_factory=set)


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _req_name(req: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
    return norm(m.group(1)) if m else req.strip().lower()


def _meta(text: str) -> email.message.Message:
    import email.parser
    return email.parser.Parser().parsestr(text)


def _entry_points(text: str) -> Set[str]:
    out, section = set(), ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
        elif line and not line.startswith(("#", ";")) and "=" in line and section:
            out.add(f"{section}:{line.split('=', 1)[0].strip()}")
    return out


def read_inventory(path: str) -> Optional[Inventory]:
    fname = os.path.basename(path)
    try:
        size = os.path.getsize(path)
        if fname.endswith(".whl"):
            return _read_wheel(path, fname, size)
        if fname.endswith(".tar.gz"):
            return _read_sdist(path, fname, size)
    except Exception:  # noqa: BLE001 - a corrupt previous release is reported as diff_unreadable
        return None
    return None


def _bounded(zf: zipfile.ZipFile, name: str, cap: int = 16 * 1024 * 1024) -> bytes:
    """Read a member but never more than `cap` bytes (headers can lie about size)."""
    with zf.open(name) as fp:
        data = fp.read(cap + 1)
    return b"" if len(data) > cap else data


def _read_wheel(path: str, fname: str, size: int) -> Optional[Inventory]:
    parts = fname[:-4].split("-")
    if len(parts) not in (5, 6):
        return None
    inv = Inventory(fname, "wheel", norm(parts[0]), parts[1], "-".join(parts[-3:]), size)
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            return None
        raw = {i.filename: i.file_size for i in infos if not i.is_dir()}
        # version-specific dist-info/data directory names must not look like added files
        inv.files = {re.sub(r"^[^/]+\.(dist-info|data)/", lambda m: m.group(1).upper() + "/", n): size
                     for n, size in raw.items()}
        for n in raw:
            if n.endswith(".dist-info/METADATA") and n.count("/") == 1:
                data = _bounded(zf, n)
                m = _meta(data.decode("utf-8", "replace"))
                inv.requires = {_req_name(r) for r in m.get_all("Requires-Dist", [])}
                inv.requires_python = (m.get("Requires-Python") or "").strip()
                inv.license = (m.get("License-Expression") or m.get("License") or "").strip()
            elif n.endswith(".dist-info/entry_points.txt") and n.count("/") == 1 and raw[n] < 1024 * 1024:
                inv.entry_points = _entry_points(_bounded(zf, n, 1024 * 1024).decode("utf-8", "replace"))
    inv.scripts = {n for n in inv.files if n.startswith("DATA/scripts/")}
    return inv


def _read_sdist(path: str, fname: str, size: int) -> Optional[Inventory]:
    m = re.match(r"^(?P<name>.+)-(?P<version>[^-]+)\.tar\.gz$", fname)
    if not m:
        return None
    inv = Inventory(fname, "sdist", norm(m.group("name")), m.group("version"), "", size)
    with tarfile.open(path, "r:*") as tf:
        for count, mem in enumerate(tf):
            if count > MAX_FILES:
                return None
            if mem.isfile():
                rel = mem.name.split("/", 1)[-1] if "/" in mem.name else mem.name
                inv.files[rel] = mem.size
                if rel == "PKG-INFO" and mem.size < 16 * 1024 * 1024:
                    fp = tf.extractfile(mem)
                    if fp:
                        meta = _meta(fp.read().decode("utf-8", "replace"))
                        inv.requires = {_req_name(r) for r in meta.get_all("Requires-Dist", [])}
                        inv.requires_python = (meta.get("Requires-Python") or "").strip()
                        inv.license = (meta.get("License-Expression") or meta.get("License") or "").strip()
    return inv


def _pkgs(inv: Inventory) -> Set[str]:
    """Importable packages (directories with an __init__.py, up to three levels deep)."""
    out = set()
    for n in inv.files:
        parts = n.split("/")
        if inv.kind == "sdist" and parts and parts[0] in ("src", "lib"):
            parts = parts[1:]
        if parts and parts[-1] == "__init__.py" and 2 <= len(parts) <= 4 and parts[0] not in ("DIST-INFO", "DATA"):
            out.add(".".join(parts[:-1]))
    return out


def _version_key(v: str) -> Tuple:
    nums = re.match(r"^(\d+(?:\.\d+)*)", v)
    base = tuple(int(x) for x in nums.group(1).split(".")) if nums else ()
    pre = 0 if re.search(r"(a|b|rc|\.dev)\d*", v[nums.end():] if nums else "") else 1
    return base + (0,) * (6 - len(base)), pre


def _executables(inv: Inventory) -> Set[str]:
    return {n for n in inv.files
            if re.search(r"\.(so|pyd|dll|dylib|pth)(\.\d+)*$", n) or n.startswith("DATA/scripts/")}


def _raised(old: str, new: str) -> List[str]:
    """Python minors the old spec allowed and the new one forbids (3.6-3.15)."""
    lost = []
    for minor in range(6, 16):
        a = pyspec.allows_minor(old, 3, minor) if old else True
        b = pyspec.allows_minor(new, 3, minor) if new else True
        if a is True and b is False:
            lost.append(f"3.{minor}")
    return lost


def compare(new: List[Inventory], old: List[Inventory]) -> List[Pair]:
    out: List[Pair] = []
    old_by_name = {i.filename: i for i in old}
    for n in new:
        if n.filename in old_by_name:
            out.append(("diff_version_exists",
                        f"{n.filename} is already in the previous release set; PyPI refuses to accept a file "
                        "name twice (even with different contents). Bump the version"))
    projects = {i.project for i in new} & {i.project for i in old}
    if not projects:
        return out
    new = [i for i in new if i.project in projects]
    old = [i for i in old if i.project in projects]
    nv = max((i.version for i in new), key=_version_key, default="")
    ov = max((i.version for i in old), key=_version_key, default="")
    if nv and ov and nv != ov and _version_key(nv) <= _version_key(ov):
        out.append(("diff_version_not_newer", f"new version {nv} is not newer than previous {ov}"))
    # pair artifacts by kind+tag
    for n in new:
        o = next((x for x in old if x.kind == n.kind and (x.tag == n.tag)), None)
        if o is None and n.kind == "wheel":
            same_plat = [x for x in old if x.kind == "wheel" and x.tag.split("-")[-1] == n.tag.split("-")[-1]]
            o = same_plat[0] if len(same_plat) == 1 else None
        if o is None:
            continue
        lbl = n.filename
        if o.size and n.size:
            ratio = n.size / o.size
            delta = abs(n.size - o.size)
            if (ratio >= SIZE_RATIO or ratio <= 1 / SIZE_RATIO) and delta >= SIZE_MIN_DELTA // 8:
                out.append(("diff_size_jump", f"{lbl}: {o.size:,} -> {n.size:,} bytes ({ratio:.1f}x) "
                                              f"compared with {o.filename}"))
            elif ratio >= 1.5 and delta >= SIZE_MIN_DELTA * 2:
                out.append(("diff_size_jump", f"{lbl}: grew by {delta:,} bytes compared with {o.filename}"))
        added_deps = sorted(n.requires - o.requires)
        if added_deps:
            out.append(("diff_new_dependency", f"{lbl}: new dependencies {added_deps[:6]}"))
        removed = sorted(o.requires - n.requires)
        if removed:
            out.append(("diff_removed_dependency", f"{lbl}: dependencies removed {removed[:6]}"))
        lost = _raised(o.requires_python, n.requires_python)
        if lost:
            out.append(("diff_requires_python_raised",
                        f"{lbl}: Requires-Python {o.requires_python or '(none)'!r} -> {n.requires_python or '(none)'!r} "
                        f"drops Python {', '.join(lost[:4])}"))
        new_eps = sorted(n.entry_points - o.entry_points)
        if new_eps:
            out.append(("diff_new_entry_point", f"{lbl}: new entry points {new_eps[:6]}"))
        gone_eps = sorted(o.entry_points - n.entry_points)
        if gone_eps:
            out.append(("diff_removed_entry_point", f"{lbl}: entry points removed {gone_eps[:6]}"))
        exe_new = sorted(_executables(n) - _executables(o))
        if exe_new:
            out.append(("diff_new_executable_code", f"{lbl}: new native/.pth/script files {exe_new[:4]}"))
        gone_pkgs = sorted(_pkgs(o) - _pkgs(n))
        if gone_pkgs:
            out.append(("diff_removed_package", f"{lbl}: top-level package(s) gone {gone_pkgs[:5]}"))
        if o.license and n.license and o.license.strip().lower() != n.license.strip().lower():
            out.append(("diff_license_changed", f"{lbl}: license {o.license[:60]!r} -> {n.license[:60]!r}"))
        added = sorted(set(n.files) - set(o.files))
        if added:
            out.append(("diff_new_files", f"{lbl}: {len(added)} file(s) added (e.g. {added[0]!r})"))
    for o in old:
        if o.kind == "wheel" and not any(n.kind == "wheel" and n.tag == o.tag for n in new):
            out.append(("diff_wheel_dropped",
                        f"previous release had {o.filename} (tag {o.tag}); this release has no wheel with that tag"))
    return out
