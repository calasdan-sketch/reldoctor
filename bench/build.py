"""Builders for synthetic wheels, sdists and native-binary headers.

Everything is generated from scratch with the standard library, so the corpus is
deterministic and offline. Secrets are assembled at runtime from fragments
(never written contiguously in this file) so scanners do not flag the repo.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import struct
import tarfile
import zipfile
from typing import Dict, Iterable, List, Optional, Tuple

README = "# Acme Widgets\n\nWidgets for acme. See https://example.com/docs for details.\n"
LICENSE = "MIT License\n\nPermission is hereby granted, free of charge, to any person...\n"

DEFAULT_CLASSIFIERS = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries",
]


def frag(*parts: str) -> str:
    """Join fragments at runtime (keeps fake secrets out of the source text)."""
    return "".join(parts)


# --- native binary headers -------------------------------------------------

def elf(machine: int = 62, glibc: Optional[str] = "GLIBC_2.17", musl: bool = False,
        needed_glibc: bool = True, big_endian: bool = False, size: int = 4096,
        glibcxx: Optional[str] = None) -> bytes:
    e = ">" if big_endian else "<"
    hdr = b"\x7fELF" + bytes([2, 2 if big_endian else 1, 1, 0]) + b"\0" * 8
    hdr += struct.pack(e + "HHI", 3, machine, 1)
    body = hdr + b"\0" * (64 - len(hdr))
    strings = b"\0"
    if glibc:
        strings += glibc.encode() + b"\0"
    if glibcxx:
        strings += glibcxx.encode() + b"\0"
    if needed_glibc:
        strings += b"libc.so.6\0"
    if musl:
        strings += b"ld-musl-x86_64.so.1\0"
    return (body + strings).ljust(size, b"\0")


def macho_thin(cpu: int, minos: Tuple[int, int] = (10, 13), size: int = 4096) -> bytes:
    cmd = struct.pack("<IIIIII", 0x32, 24, 1, (minos[0] << 16) | (minos[1] << 8), 0, 0)
    magic = b"\xcf\xfa\xed\xfe"
    hdr = magic + struct.pack("<iiIIIII", cpu, 3, 6, 1, len(cmd), 0, 0)
    return (hdr + cmd).ljust(size, b"\0")


def macho_fat(cpus: Iterable[int], minos: Tuple[int, int] = (10, 13)) -> bytes:
    cpus = list(cpus)
    slices, offsets, off = [], [], 0x1000
    for c in cpus:
        s = macho_thin(c, minos)
        slices.append(s)
        offsets.append(off)
        off += 0x1000
    out = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(cpus))
    for c, o, s in zip(cpus, offsets, slices):
        out += struct.pack(">iiIII", c, 3, o, len(s), 12)
    out = out.ljust(0x1000, b"\0")
    for s in slices:
        out += s
    return out


def pe(machine: int = 0x8664, size: int = 2048) -> bytes:
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80)
    dos = dos.ljust(0x80, b"\0")
    return (dos + b"PE\0\0" + struct.pack("<H", machine)).ljust(size, b"\0")


X86_64_MACHO, ARM64_MACHO = 0x01000007, 0x0100000C


# --- wheel -----------------------------------------------------------------

def record_row(path: str, data: bytes) -> str:
    h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={h},{len(data)}"


def default_metadata(name: str, version: str, requires_python: str = ">=3.9") -> List[Tuple[str, str]]:
    return [
        ("Metadata-Version", "2.4"), ("Name", name), ("Version", version),
        ("Summary", "Widgets for acme"), ("Description-Content-Type", "text/markdown"),
        ("Author-email", "Acme Dev <dev@acme-widgets.dev>"),
        ("License-Expression", "MIT"), ("License-File", "LICENSE"),
        ("Project-URL", "Source, https://github.com/acme/widgets"),
        ("Project-URL", "Documentation, https://acme-widgets.dev/docs"),
        *[("Classifier", c) for c in DEFAULT_CLASSIFIERS],
        ("Requires-Python", requires_python),
        ("Requires-Dist", "requests>=2.0"), ("Requires-Dist", "pytest>=7; extra == 'test'"),
        ("Provides-Extra", "test"),
    ]


def render_metadata(fields: List[Tuple[str, str]], body: str) -> str:
    return "".join(f"{k}: {v}\n" for k, v in fields) + "\n" + body


class Mutator:
    """Edits to a metadata field list: replace values, drop names, append lines."""

    def __init__(self, replace: Optional[Dict[str, str]] = None, drop: Iterable[str] = (),
                 add: Iterable[Tuple[str, str]] = ()):
        self.replace, self.drop, self.add = replace or {}, set(drop), list(add)

    def apply(self, fields: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        out = [(k, self.replace.get(k, v)) for k, v in fields if k not in self.drop]
        return out + self.add


def build_wheel(out_dir: str, name: str = "acme_widgets", version: str = "1.0.0", *,
                tag: str = "py3-none-any", files: Optional[Dict[str, bytes]] = None,
                meta: Optional[Mutator] = None, requires_python: str = ">=3.9",
                body: str = README, purelib: Optional[bool] = None,
                entry_points: Optional[str] = None, record: str = "ok",
                filename: Optional[str] = None, dist_info: Optional[str] = None,
                compression: int = zipfile.ZIP_DEFLATED, wheel_tags: Optional[List[str]] = None,
                license_file: bool = True, extra_members: Optional[List[Tuple[str, bytes]]] = None,
                top_init: bool = True, wheel_version: str = "1.0") -> str:
    dist_info = dist_info or f"{name}-{version}.dist-info"
    fields = default_metadata(name, version, requires_python)
    if meta:
        fields = meta.apply(fields)
    members: Dict[str, bytes] = {}
    if top_init:
        members[f"{name}/__init__.py"] = b'"""Acme widgets."""\n__version__ = "%s"\n' % version.encode()
    members.update(files or {})
    if license_file:
        members[f"{dist_info}/licenses/LICENSE"] = LICENSE.encode()
    members[f"{dist_info}/METADATA"] = render_metadata(fields, body).encode()
    if purelib is None:
        purelib = tag.endswith("-any")
    tags = wheel_tags or [tag]
    members[f"{dist_info}/WHEEL"] = (
        f"Wheel-Version: {wheel_version}\nGenerator: bench (1.0)\n"
        f"Root-Is-Purelib: {'true' if purelib else 'false'}\n" + "".join(f"Tag: {t}\n" for t in tags)).encode()
    if entry_points:
        members[f"{dist_info}/entry_points.txt"] = entry_points.encode()
    rows = [record_row(p, d) for p, d in members.items()]
    if record == "bad_hash" and rows:
        first = next(p for p in members if p.endswith("__init__.py"))
        members[first] = members[first] + b"# tampered\n"
    if record == "bad_size":
        rows = [r.rsplit(",", 1)[0] + ",1" if r.startswith(f"{name}/__init__.py") else r for r in rows]
    if record == "drop_one":
        rows = [r for r in rows if not r.startswith(f"{name}/__init__.py")]
    if record == "ghost":
        rows.append(f"{name}/ghost.py,sha256=AAAA,10")
    path = os.path.join(out_dir, filename or f"{name}-{version}-{tag}.whl")
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression) as zf:
        for p, d in members.items():
            zf.writestr(p, d)
        for p, d in extra_members or []:
            zf.writestr(p, d)
        if record != "missing":
            zf.writestr(f"{dist_info}/RECORD", "\n".join(rows + [f"{dist_info}/RECORD,,"]) + "\n")
    return path


# --- sdist -----------------------------------------------------------------

PYPROJECT = '[build-system]\nrequires = ["setuptools>=77"]\nbuild-backend = "setuptools.build_meta"\n'


def build_sdist(out_dir: str, name: str = "acme_widgets", version: str = "1.0.0", *,
                files: Optional[Dict[str, bytes]] = None, meta: Optional[Mutator] = None,
                requires_python: str = ">=3.9", body: str = README,
                filename: Optional[str] = None, links: Optional[List[Tuple[str, str]]] = None,
                setup_py: Optional[str] = None) -> str:
    root = f"{name}-{version}"
    fields = default_metadata(name, version, requires_python)
    if meta:
        fields = meta.apply(fields)
    members: Dict[str, bytes] = {
        f"{root}/PKG-INFO": render_metadata(fields, body).encode(),
        f"{root}/pyproject.toml": PYPROJECT.encode(),
        f"{root}/LICENSE": LICENSE.encode(),
        f"{root}/src/{name}/__init__.py": b"__version__ = '%s'\n" % version.encode(),
    }
    if setup_py is not None:
        members[f"{root}/setup.py"] = setup_py.encode()
    for p, d in (files or {}).items():
        members[f"{root}/{p}"] = d
    path = os.path.join(out_dir, filename or f"{name}-{version}.tar.gz")
    os.makedirs(out_dir, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for p, d in members.items():
            ti = tarfile.TarInfo(p)
            ti.size = len(d)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(d))
        for p, target in links or []:
            ti = tarfile.TarInfo(f"{root}/{p}")
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            tf.addfile(ti)
    return path


def release(out_dir: str, name: str = "acme_widgets", version: str = "1.0.0", *,
            wheel: Optional[dict] = None, sdist: Optional[dict] = None, with_sdist: bool = True) -> None:
    build_wheel(out_dir, name, version, **(wheel or {}))
    if with_sdist:
        build_sdist(out_dir, name, version, **(sdist or {}))
