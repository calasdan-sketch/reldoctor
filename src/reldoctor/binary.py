"""Read just enough of ELF, Mach-O and PE headers to compare them with wheel tags.

Pure stdlib, bounded: only a header buffer is examined, never executed.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional, Set, Tuple

HEAD_BYTES = 64 * 1024

_ELF_MACHINE = {3: "x86", 62: "x86_64", 183: "arm64", 40: "arm", 22: "s390x",
                243: "riscv64", 20: "ppc"}
_MACHO_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
              18: "ppc", 0x01000012: "ppc64"}
_PE_MACHINE = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C4: "arm"}


@dataclass
class BinInfo:
    fmt: str                       # elf | macho | pe
    archs: Set[str] = field(default_factory=set)
    macos_min: Optional[Tuple[int, int]] = None


def sniff(head: bytes) -> Optional[BinInfo]:
    """Classify a file by its first bytes, or None if it is not a native binary."""
    try:
        if head[:4] == b"\x7fELF" and len(head) >= 20:
            return _elf(head)
        if head[:2] == b"MZ":
            return _pe(head)
        return _macho(head)
    except (struct.error, IndexError):
        return None


def _elf(head: bytes) -> Optional[BinInfo]:
    endian = {1: "<", 2: ">"}.get(head[5])
    if endian is None:
        return None
    machine = struct.unpack_from(endian + "H", head, 18)[0]
    if machine == 21:
        arch = "ppc64le" if endian == "<" else "ppc64"
    else:
        arch = _ELF_MACHINE.get(machine, f"elf-machine-{machine}")
    return BinInfo("elf", {arch})


def _pe(head: bytes) -> Optional[BinInfo]:
    off = struct.unpack_from("<I", head, 0x3C)[0]
    if off + 6 > len(head) or head[off:off + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", head, off + 4)[0]
    return BinInfo("pe", {_PE_MACHINE.get(machine, f"pe-machine-{machine:#x}")})


def _macho(head: bytes) -> Optional[BinInfo]:
    magic = head[:4]
    if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return _macho_thin(head, 0)
    if magic == b"\xca\xfe\xba\xbe":  # fat; Java class files share this magic
        n = struct.unpack_from(">I", head, 4)[0]
        if not 1 <= n <= 20:
            return None
        archs, minos = set(), None
        for i in range(n):
            cpu, _sub, off, _size, _al = struct.unpack_from(">iiIII", head, 8 + 20 * i)
            archs.add(_MACHO_CPU.get(cpu & 0xFFFFFFFF, f"macho-cpu-{cpu & 0xFFFFFFFF:#x}"))
            if off + 32 < len(head) and head[off:off + 4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                thin = _macho_thin(head, off)
                if thin and thin.macos_min:
                    minos = max(minos, thin.macos_min) if minos else thin.macos_min
        return BinInfo("macho", archs, minos)
    return None


def _macho_thin(head: bytes, base: int) -> Optional[BinInfo]:
    cpu = struct.unpack_from("<i", head, base + 4)[0] & 0xFFFFFFFF
    arch = _MACHO_CPU.get(cpu, f"macho-cpu-{cpu:#x}")
    is64 = head[base:base + 4] == b"\xcf\xfa\xed\xfe"
    ncmds = struct.unpack_from("<I", head, base + 16)[0]
    pos = base + (32 if is64 else 28)
    minos = None
    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(head):
            break
        cmd, size = struct.unpack_from("<II", head, pos)
        if size < 8:
            break
        if cmd == 0x32 and pos + 16 <= len(head):          # LC_BUILD_VERSION
            platform, ver = struct.unpack_from("<II", head, pos + 8)
            if platform == 1:                              # macOS
                minos = ((ver >> 16) & 0xFFFF, (ver >> 8) & 0xFF)
        elif cmd == 0x24 and pos + 12 <= len(head):        # LC_VERSION_MIN_MACOSX
            ver = struct.unpack_from("<I", head, pos + 8)[0]
            minos = ((ver >> 16) & 0xFFFF, (ver >> 8) & 0xFF)
        pos += size
    return BinInfo("macho", {arch}, minos)


# Symbol-version strings in an ELF's dynamic string table.
GLIBC_REF = re.compile(rb"GLIBC_(\d+)\.(\d+)")
GLIBCXX_REF = re.compile(rb"GLIBCXX_3\.4\.(\d+)")
MUSL_HINT = re.compile(rb"ld-musl-|libc\.musl-")
GLIBC_NEEDED = re.compile(rb"libc\.so\.6")


def ext_abi_tag(name: str) -> Optional[Tuple[str, Optional[Tuple[int, int]]]]:
    """('abi3'|'cpython'|'pypy'|'none', (3, 11)) from an extension module filename."""
    base = name.rsplit("/", 1)[-1]
    m = re.search(r"\.cpython-(\d)(\d+)[a-z]*(?:-[\w-]+)?\.(?:so|pyd)$", base)
    if m:
        return "cpython", (int(m.group(1)), int(m.group(2)))
    m = re.search(r"\.cp(\d)(\d+)-win[\w]*\.pyd$", base)
    if m:
        return "cpython", (int(m.group(1)), int(m.group(2)))
    if re.search(r"\.abi3\.(?:so|pyd)$", base):
        return "abi3", None
    if re.search(r"\.pypy\d+-pp\d+[\w-]*\.(?:so|pyd)$", base):
        return "pypy", None
    if re.search(r"\.(?:so|pyd)$", base):
        return "none", None
    return None


# Newest GLIBCXX_3.4.N symbol version each manylinux policy allows, from auditwheel 6.8.2's
# `policy/manylinux-policy.json` (the x86_64/i686/aarch64/armv7l/riscv64 entries; ppc64le and s390x
# use a different version scheme there and are not checked). Keys are the policy's glibc version.
GLIBCXX_POLICY = {
    (2, 5): 8, (2, 12): 13, (2, 17): 19, (2, 24): 22, (2, 26): 22, (2, 27): 24, (2, 28): 24,
    (2, 31): 28, (2, 34): 29, (2, 35): 30, (2, 36): 30, (2, 37): 30, (2, 38): 30, (2, 39): 33,
    (2, 40): 33, (2, 41): 33,
}
GLIBCXX_ARCHS = {"x86_64", "x86", "arm64", "arm", "riscv64"}


def glibcxx_allowed(glibc_floor: Tuple[int, int]) -> Optional[int]:
    """N of the newest GLIBCXX_3.4.N the manylinux policy at `glibc_floor` allows, or None below the oldest."""
    keys = [k for k in GLIBCXX_POLICY if k <= glibc_floor]
    return GLIBCXX_POLICY[max(keys)] if keys else None
