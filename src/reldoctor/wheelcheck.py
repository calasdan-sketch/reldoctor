"""Wheel tag and native-binary consistency, plus the optional second-opinion
oracles (``packaging`` and ``readme_renderer``) when they are installed.

What this answers: does the wheel's filename tell the truth about what is
inside? A wheel tagged ``manylinux2014_x86_64`` that holds an arm64 library, or
a ``cp311`` wheel with a ``cpython-312`` extension, installs fine and then
fails at import time on the user's machine.
"""
from __future__ import annotations

import email.message
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from . import binary, pyspec
from .platform_tags import SNAPSHOT, PlatformInfo, valid_platform_tag

Pair = Tuple[str, str]

CHECKS_EXTRA: Dict[str, Tuple[str, str]] = {
    "unsupported_platform_tag": ("error", "wheel platform tag is not on PyPI's accept-list (e.g. linux_x86_64); PyPI rejects it"),
    "dist_info_name_mismatch": ("error", ".dist-info directory is not {name}-{version}.dist-info from the filename; PyPI cannot find METADATA"),
    "purelib_mismatch": ("warn", "WHEEL Root-Is-Purelib disagrees with the platform tag and contents"),
    "platform_wheel_without_binaries": ("warn", "wheel has a platform tag but contains no compiled code"),
    "binary_arch_mismatch": ("error", "a compiled library's CPU architecture does not match the wheel's platform tag"),
    "binary_os_mismatch": ("error", "a compiled library is for a different operating system than the wheel's platform tag"),
    "manylinux_glibc_too_new": ("error", "a library needs a newer glibc than the manylinux tag promises"),
    "manylinux_glibcxx_too_new": ("error", "a library needs a newer libstdc++ (GLIBCXX_3.4.N) than the manylinux tag allows"),
    "musllinux_links_glibc": ("error", "a musllinux wheel contains a library linked against glibc"),
    "manylinux_links_musl": ("error", "a manylinux wheel contains a library linked against musl"),
    "macos_target_too_new": ("error", "a library needs a newer macOS than the macosx tag promises"),
    "extension_abi_mismatch": ("error", "an extension module's CPython ABI suffix does not match the wheel's ABI tag"),
    "abi3_extension_not_stable": ("warn", "abi3 wheel holds an extension that is built for one specific CPython version"),
    "tag_requires_python_conflict": ("warn", "the wheel's cpXY tag is a Python version Requires-Python excludes"),
    "packaging_rejects_metadata": ("error", "the 'packaging' library (which PyPI uses) rejects this METADATA"),
    "wheel_version_unsupported": ("error", "WHEEL declares a Wheel-Version major other than 1; installers refuse the wheel"),
    "wheel_version_newer": ("warn", "WHEEL declares Wheel-Version 1.x newer than 1.0; installers print a warning"),
    "wheel_no_tag": ("warn", "WHEEL has no Tag line (PEP 427 requires at least one)"),
    "purelib_unclear": ("warn", "WHEEL has no usable Root-Is-Purelib (true/false); installers may disagree on where to put the files"),
    "script_hardcoded_interpreter": ("warn", "a script in .data/scripts has a #! line naming a fixed Python path, which installers do not rewrite"),
    "description_render_failed": ("error", "the long description does not render with readme_renderer (what PyPI uses)"),
}


@dataclass
class NativeFile:
    name: str
    info: binary.BinInfo
    glibc_max: Optional[Tuple[int, int]] = None
    musl: bool = False
    glibc_needed: bool = False
    glibcxx_max: Optional[int] = None


def check_dist_info_name(fname: str, dist_dir: str) -> List[Pair]:
    parts = fname[:-4].split("-") if fname.endswith(".whl") else []
    if len(parts) in (5, 6):
        want = f"{parts[0]}-{parts[1]}.dist-info"
        if dist_dir != want:
            return [("dist_info_name_mismatch",
                     f"found {dist_dir!r} but the filename implies {want!r}; PyPI looks for "
                     f"{want}/METADATA and refuses the upload")]
    return []


def check_platform_tags(plats: Set[str]) -> List[Pair]:
    out = []
    for p in sorted(plats):
        if not valid_platform_tag(p):
            hint = ""
            if p.startswith("linux_"):
                hint = " Build in a manylinux/musllinux container (cibuildwheel, or `auditwheel repair`)."
            elif p.startswith("macosx"):
                hint = " Use macosx_<major>_<minor>_<arch> (arch: x86_64, arm64, universal2...)."
            out.append(("unsupported_platform_tag",
                        f"platform tag {p!r} is not accepted by PyPI (accept-list read {SNAPSHOT}).{hint}"))
    return out


def check_wheel_tags_vs_contents(
    plats: Set[str], pytags: Set[str], abis: Set[str], natives: List[NativeFile],
    ext_names: List[str], root_is_purelib: Optional[bool], requires_python: str,
) -> List[Pair]:
    out: List[Pair] = []
    infos = [PlatformInfo(p) for p in sorted(plats) if valid_platform_tag(p)]
    platform_specific = [pi for pi in infos if pi.os != "any"]
    libs = [n for n in natives if binary_is_library(n.name)]

    if platform_specific and not natives and not ext_names:
        out.append(("platform_wheel_without_binaries",
                    "the wheel is tagged for a specific platform but holds no compiled code; "
                    "a py3-none-any wheel would install everywhere"))
    if platform_specific and root_is_purelib is True and (libs or ext_names):
        out.append(("purelib_mismatch", "WHEEL says Root-Is-Purelib: true but the wheel has a platform tag "
                                        "and compiled code; set it to false"))
    if not platform_specific and infos and root_is_purelib is False and not libs and not ext_names:
        out.append(("purelib_mismatch", "WHEEL says Root-Is-Purelib: false but the wheel is platform-independent "
                                        "and holds no compiled code"))

    oses = {pi.os for pi in platform_specific}
    os_of = {"elf": "linux", "macho": "macos", "pe": "windows"}
    for n in libs:
        want_os = os_of[n.info.fmt]
        if platform_specific and want_os not in oses:
            out.append(("binary_os_mismatch",
                        f"{n.name!r} is a {n.info.fmt.upper()} library ({want_os}) in a wheel tagged "
                        f"{'/'.join(sorted(oses))}"))
            continue
        same_os = [pi for pi in platform_specific if pi.os == want_os]
        for pi in same_os:
            if pi.archs and not (n.info.archs & pi.archs):
                out.append(("binary_arch_mismatch",
                            f"{n.name!r} is built for {'/'.join(sorted(n.info.archs))} but the wheel tag "
                            f"{pi.tag!r} promises {'/'.join(sorted(pi.archs))}; it will fail to import there"))
                break
            if pi.os == "macos" and len(pi.archs) > 1 and not pi.archs <= n.info.archs:
                out.append(("binary_arch_mismatch",
                            f"{n.name!r} holds only {'/'.join(sorted(n.info.archs))} but the wheel tag "
                            f"{pi.tag!r} promises {'/'.join(sorted(pi.archs))}; run delocate-fuse or build universal2"))
                break
        gl = [pi for pi in same_os if pi.libc == "glibc" and pi.libc_min]
        if gl and n.glibc_max:
            floor = min(pi.libc_min for pi in gl)
            if n.glibc_max > floor:
                out.append(("manylinux_glibc_too_new",
                            f"{n.name!r} references GLIBC_{n.glibc_max[0]}.{n.glibc_max[1]} but the tag promises "
                            f"glibc {floor[0]}.{floor[1]}; `auditwheel repair` would relabel it "
                            f"manylinux_{n.glibc_max[0]}_{n.glibc_max[1]}"))
        if gl and n.glibcxx_max is not None and (n.info.archs & binary.GLIBCXX_ARCHS):
            floor = min(pi.libc_min for pi in gl)
            allowed = binary.glibcxx_allowed(floor)
            if allowed is not None and n.glibcxx_max > allowed:
                out.append(("manylinux_glibcxx_too_new",
                            f"{n.name!r} references GLIBCXX_3.4.{n.glibcxx_max} but the manylinux policy for glibc "
                            f"{floor[0]}.{floor[1]} allows up to GLIBCXX_3.4.{allowed} (auditwheel's policy data); "
                            "systems with an older libstdc++ cannot import it. Build in the matching manylinux "
                            "image or run `auditwheel repair`"))
        if any(pi.libc == "musl" for pi in same_os) and n.glibc_needed:
            out.append(("musllinux_links_glibc",
                        f"{n.name!r} is linked against libc.so.6 (glibc) but the wheel is musllinux"))
        if any(pi.libc == "glibc" for pi in same_os) and n.musl:
            out.append(("manylinux_links_musl", f"{n.name!r} is linked against musl but the wheel is manylinux"))
        mac = [pi for pi in same_os if pi.macos_min]
        if mac and n.info.macos_min:
            floor_m = min(pi.macos_min for pi in mac)
            if n.info.macos_min > floor_m:
                out.append(("macos_target_too_new",
                            f"{n.name!r} needs macOS {n.info.macos_min[0]}.{n.info.macos_min[1]}+ but the tag "
                            f"promises {floor_m[0]}.{floor_m[1]}; set MACOSX_DEPLOYMENT_TARGET or fix the tag"))

    cp_minors = set()
    for t in pytags:
        m = re.fullmatch(r"cp(\d)(\d+)", t)
        if m:
            cp_minors.add((int(m.group(1)), int(m.group(2))))
    is_abi3 = "abi3" in abis
    for name in ext_names:
        kind = binary.ext_abi_tag(name)
        if not kind or kind[0] != "cpython":
            continue
        ver = kind[1]
        if is_abi3:
            out.append(("abi3_extension_not_stable",
                        f"{name!r} is built for CPython {ver[0]}.{ver[1]} only, but the wheel claims abi3 "
                        "(stable ABI); compile it with Py_LIMITED_API / py_limited_api=True"))
        elif ver not in cp_minors:
            tag_s = ", ".join(sorted(f"cp{a}{b}" for a, b in cp_minors)) or "no cpXY tag"
            out.append(("extension_abi_mismatch",
                        f"{name!r} is for CPython {ver[0]}.{ver[1]} but the wheel is tagged {tag_s}; "
                        "it will not import (or will crash) on the Python the tag selects"))
    if requires_python and not is_abi3:
        gone = [f"{a}.{b}" for a, b in sorted(cp_minors) if pyspec.allows_minor(requires_python, a, b) is False]
        if gone:
            out.append(("tag_requires_python_conflict",
                        f"wheel is tagged for CPython {', '.join(gone)} but Requires-Python {requires_python!r} excludes it"))
    return out


_LIB_RE = re.compile(r"\.(pyd|dll|dylib|so(\.\d+)*)$", re.IGNORECASE)


def binary_is_library(name: str) -> bool:
    return bool(_LIB_RE.search(name))


# --- optional oracles ---------------------------------------------------------

def packaging_problems(raw_text: str) -> Optional[List[str]]:
    """Problems found by packaging.metadata (what PyPI runs), or None if the
    library is missing or too old. Empty list = accepted."""
    try:
        import packaging
        from packaging.metadata import Metadata
    except ImportError:
        return None
    # packaging before 24.2 does not know Metadata 2.4 (PEP 639) and would reject every modern
    # wheel; an oracle that is out of date must stay silent rather than call valid files broken.
    ver = re.match(r"(\d+)\.(\d+)", str(getattr(packaging, "__version__", "")))
    if not ver or (int(ver.group(1)), int(ver.group(2))) < (24, 2):
        return None
    try:
        Metadata.from_email(raw_text, validate=True)
    except Exception as e:  # noqa: BLE001 - ExceptionGroup/InvalidMetadata vary by version
        subs = getattr(e, "exceptions", None) or [e]
        # License-File under Metadata < 2.4 is emitted by setuptools/wheel for years and
        # accepted by PyPI and twine; strict packaging validation would flag half of PyPI.
        subs = [x for x in subs if "license-file introduced in metadata version" not in str(x)]
        return [f"packaging {getattr(packaging, '__version__', '?')}: " + str(x).split("\n")[0][:300] for x in subs[:6]]
    return []


def render_problem(meta: email.message.Message, text: str) -> Optional[str]:
    """Why readme_renderer cannot render the description, or None (also None when not installed)."""
    import io
    import warnings
    ctype = (meta.get("Description-Content-Type") or "text/x-rst").split(";")[0].strip().lower()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # readme_renderer warns on import when its Markdown extra is missing
            if ctype == "text/markdown":
                import readme_renderer.markdown as r
            elif ctype == "text/x-rst":
                import readme_renderer.rst as r
            else:
                return None
    except ImportError:
        return None
    if ctype == "text/markdown" and not getattr(r, "variants", True):
        # readme_renderer >= 44 ships Markdown support as the optional `[md]` extra; without it
        # every Markdown description "fails", which says nothing about the project.
        return None
    stream = io.StringIO()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ok = r.render(text[:2_000_000], stream=stream)
    except Exception as e:  # noqa: BLE001
        return f"renderer crashed ({type(e).__name__})"
    if ok is None:
        first = " ".join(stream.getvalue().split())[:240]
        return first or "the renderer returned nothing"
    return None


_WHEEL_VERSION = re.compile(r"^\s*(\d{1,4})\.(\d{1,4})\s*$")


def check_wheel_file(wheel_meta) -> List[Pair]:
    """Checks on the parsed ``.dist-info/WHEEL`` headers (PEP 427). A missing Wheel-Version is
    reported separately (``wheel_no_version``)."""
    out: List[Pair] = []
    raw = (wheel_meta.get("Wheel-Version") or "").strip()
    if raw:
        m = _WHEEL_VERSION.match(raw)
        if not m:
            out.append(("wheel_version_unsupported", f"Wheel-Version {raw[:20]!r} is not of the form 1.0"))
        elif int(m.group(1)) != 1:
            out.append(("wheel_version_unsupported",
                        f"Wheel-Version {raw} has major version {m.group(1)}; installers support major 1 only and "
                        "refuse this wheel"))
        elif int(m.group(2)) > 0:
            out.append(("wheel_version_newer", f"Wheel-Version {raw}: installers that only know 1.0 print a warning"))
    if not [t for t in wheel_meta.get_all("Tag", []) if t.strip()]:
        out.append(("wheel_no_tag", "WHEEL has no Tag line"))
    purelib = (wheel_meta.get("Root-Is-Purelib") or "").strip().lower()
    if purelib not in ("true", "false"):
        shown = purelib[:20] if purelib else "missing"
        out.append(("purelib_unclear", f"Root-Is-Purelib is {shown!r}; write true (pure Python) or false (compiled code)"))
    return out


_FIXED_PYTHON_SHEBANG = re.compile(rb"^#![ \t]*(?:/[^\s]*?/)?(?:env[ \t]+(?:-S[ \t]+)?)?(python[0-9.]*w?)\b")


def check_script_shebang(member: str, head: bytes) -> List[Pair]:
    """``<name>-<ver>.data/scripts/*``: installers rewrite a ``#!python`` line to the target
    interpreter; any other Python shebang is copied as written."""
    first = head.split(b"\n", 1)[0].rstrip(b"\r")
    if not first.startswith(b"#!") or first.startswith((b"#!python", b"#! python")):
        return []
    m = _FIXED_PYTHON_SHEBANG.match(first)
    if not m:
        return []
    shown = first[:60].decode("ascii", "replace")
    return [("script_hardcoded_interpreter",
             f"script {member.rsplit('/', 1)[-1]!r} starts with {shown!r}; installers only rewrite '#!python', so this "
             "path is used as is on every machine (and breaks in virtual environments). Use '#!python' or a console-script entry point")]
