"""Wheel platform tags: PyPI's accept-list and what each tag promises.

`valid_platform_tag` mirrors warehouse/utils/wheel.py (`_parse_platform_tag`,
read from the main branch on 2026-11-07). PyPI changes this list over time
(new macOS majors, new platforms); a tag newer than this snapshot is reported
with the snapshot date so a false alarm is easy to recognise.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Set, Tuple

SNAPSHOT = "2026-11-07"

_STATIC = {
    "any", "win32", "win_arm64", "win_amd64", "win_ia64",
    "manylinux1_x86_64", "manylinux1_i686", "manylinux2010_x86_64", "manylinux2010_i686",
    "manylinux2014_x86_64", "manylinux2014_i686", "manylinux2014_aarch64",
    "manylinux2014_armv7l", "manylinux2014_ppc64", "manylinux2014_ppc64le",
    "manylinux2014_s390x", "linux_armv6l", "linux_armv7l",
}
_MAC_RE = re.compile(r"^macosx_(\d+)_(\d+)_(.*)$")
_MAC_ARCH = {"ppc", "ppc64", "i386", "x86_64", "arm64", "intel", "fat", "fat3", "fat64",
             "universal", "universal2"}
_MAC_MAJORS = {"11", "12", "13", "14", "15", "26"}
_IOS_RE = re.compile(r"^ios_(\d+)_(\d+)_(.*)_(iphoneos|iphonesimulator)$")
_ANDROID_RE = re.compile(r"^android_(\d+)_(.*)$")
_LINUX_RE = re.compile(r"^(many|musl)linux_(\d+)_(\d+)_(.*)$")
_JOINT = {"x86_64", "i686", "aarch64", "armv7l", "ppc64le", "s390x", "riscv64"}
_EMSCRIPTEN_RE = re.compile(r"^pyemscripten_(\d+)_(\d+)_wasm32$")


def valid_platform_tag(tag: str) -> bool:
    if tag in _STATIC:
        return True
    m = _MAC_RE.match(tag)
    if m and m.group(3) in _MAC_ARCH:
        if m.group(1) == "10":
            return True
        if m.group(1) in _MAC_MAJORS and m.group(2) == "0":
            return True
    m = _LINUX_RE.match(tag)
    if m:
        arches = _JOINT if m.group(1) == "musl" else _JOINT | {"ppc64"}
        if m.group(4) in arches:
            return True
    m = _IOS_RE.match(tag)
    if m and m.group(3) in {"arm64", "x86_64"}:
        return True
    m = _ANDROID_RE.match(tag)
    if m and m.group(2) in {"armeabi_v7a", "arm64_v8a", "x86", "x86_64"}:
        return True
    return bool(_EMSCRIPTEN_RE.match(tag))


# canonical architecture names used when comparing with binaries
_ARCH_ALIASES = {
    "x86_64": "x86_64", "amd64": "x86_64", "i686": "x86", "i386": "x86", "win32": "x86",
    "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm", "armv6l": "arm",
    "ppc64le": "ppc64le", "ppc64": "ppc64", "ppc": "ppc", "s390x": "s390x", "riscv64": "riscv64",
}
_MAC_MULTI = {
    "universal2": {"x86_64", "arm64"}, "intel": {"x86", "x86_64"}, "fat": {"x86", "ppc"},
    "fat3": {"x86", "x86_64", "ppc"}, "fat64": {"x86_64", "ppc64"}, "universal": {"x86", "ppc"},
}
_GLIBC = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}


class PlatformInfo:
    """What a platform tag promises about the binaries inside."""

    def __init__(self, tag: str):
        self.tag = tag
        self.os: str = "other"           # any | linux | macos | windows | other
        self.libc: Optional[str] = None  # glibc | musl
        self.libc_min: Optional[Tuple[int, int]] = None
        self.archs: Set[str] = set()
        self.macos_min: Optional[Tuple[int, int]] = None
        self._parse(tag)

    def _parse(self, tag: str) -> None:
        if tag == "any":
            self.os = "any"
            return
        if tag.startswith("win"):
            self.os = "windows"
            self.archs = {_ARCH_ALIASES.get({"win_amd64": "x86_64", "win_arm64": "arm64",
                                             "win32": "i686", "win_ia64": "ia64"}.get(tag, ""), "")} - {""}
            return
        m = _MAC_RE.match(tag)
        if m:
            self.os = "macos"
            self.macos_min = (int(m.group(1)), int(m.group(2)))
            arch = m.group(3)
            self.archs = set(_MAC_MULTI.get(arch, {_ARCH_ALIASES.get(arch, arch)}))
            return
        m = _LINUX_RE.match(tag)
        if m:
            self.os = "linux"
            self.libc = "musl" if m.group(1) == "musl" else "glibc"
            if self.libc == "glibc":
                self.libc_min = (int(m.group(2)), int(m.group(3)))
            self.archs = {_ARCH_ALIASES.get(m.group(4), m.group(4))}
            return
        m = re.match(r"^(manylinux1|manylinux2010|manylinux2014)_(.*)$", tag)
        if m:
            self.os, self.libc = "linux", "glibc"
            self.libc_min = _GLIBC[m.group(1)]
            self.archs = {_ARCH_ALIASES.get(m.group(2), m.group(2))}
            return
        m = re.match(r"^linux_(.*)$", tag)
        if m:
            self.os = "linux"
            self.archs = {_ARCH_ALIASES.get(m.group(1), m.group(1))}


def python_tag_versions(tags: Set[str]) -> Dict[str, Set[Tuple[int, int]]]:
    """{'cp': {(3,11)}, ...} for cpXY interpreter tags among full tags (py-abi-plat)."""
    out: Dict[str, Set[Tuple[int, int]]] = {}
    for t in tags:
        py = t.split("-")[0]
        m = re.match(r"^cp(\d)(\d+)$", py)
        if m:
            out.setdefault("cp", set()).add((int(m.group(1)), int(m.group(2))))
    return out
