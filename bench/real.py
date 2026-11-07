"""Real PyPI wheels: false-positive check on untouched releases, and detection of
real binaries re-labelled with a wrong platform tag (so auditwheel can compete).

Needs network (pip download) and a venv with the competitor tools.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import zipfile
from typing import Dict, List, Optional, Tuple

from .run import ROOT, run

LX64 = ["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64"]
LA64 = ["manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64"]
# (platform(s), python version, abi, requirement)
DOWNLOADS = [
    (None, None, None, "requests==2.32.3"), (None, None, None, "six==1.16.0"),
    (None, None, None, "click==8.1.7"), (None, None, None, "attrs==24.2.0"),
    (LX64, "3.13", "cp313", "numpy==2.1.3"),
    (LX64, "3.13", "cp313", "pyyaml==6.0.2"),
    (LX64, "3.13", "cp313", "pydantic-core==2.27.1"),
    (LX64, "3.13", "cp313", "cryptography==43.0.3"),
    (LX64, "3.13", "cp313", "pillow==11.0.0"),
    (LX64, "3.13", "cp313", "lxml==5.3.0"),
    (LX64, "3.13", "cp313", "psutil==6.1.0"),
    (LA64, "3.13", "cp313", "pillow==11.0.0"),
    ("musllinux_1_2_x86_64", "3.13", "cp313", "cryptography==43.0.3"),
    ("musllinux_1_2_aarch64", "3.12", "cp312", "lxml==5.3.0"),
    ("macosx_11_0_arm64", "3.13", "cp313", "numpy==2.1.3"),
    ("macosx_10_13_x86_64", "3.13", "cp313", "numpy==2.1.3"),
    ("win_amd64", "3.13", "cp313", "numpy==2.1.3"),
    ("win32", "3.13", "cp313", "pyyaml==6.0.2"),
    ("win_amd64", "3.12", "cp312", "pydantic-core==2.27.1"),
]
KNOWN_BAD = {
    "attrs-24.2.0-py3-none-any.whl": "Metadata-Version 2.3 with License-Expression; twine 7 rejects it too",
    "PyYAML-6.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl":
        "filename 'PyYAML' is not normalized; PyPI's current upload code rejects that (these files predate the rule)",
    "PyYAML-6.0.2-cp313-cp313-win32.whl": "same non-normalized 'PyYAML' filename",
}


def fetch(pip: str, cache: str) -> List[str]:
    os.makedirs(cache, exist_ok=True)
    for plat, pyv, abi, req in DOWNLOADS:
        cmd = [pip, "download", "-q", "--no-deps", "--only-binary=:all:", "-d", cache, req]
        if plat:
            for p in ([plat] if isinstance(plat, str) else plat):
                cmd += ["--platform", p]
            cmd += ["--python-version", pyv, "--implementation", "cp", "--abi", abi]
        run(cmd, timeout=300)
    return sorted(os.path.join(cache, f) for f in os.listdir(cache) if f.endswith(".whl"))


def relabel(src: str, new_tag: str, out_dir: str) -> str:
    """Copy a real wheel under a different tag (filename + WHEEL), fixing RECORD."""
    base = os.path.basename(src)[:-4].split("-")
    new_base = "-".join(base[:-3] + [new_tag])
    dst = os.path.join(out_dir, new_base + ".whl")
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        wheel_path = next(n for n in zin.namelist() if n.endswith(".dist-info/WHEEL"))
        record_path = next(n for n in zin.namelist() if n.endswith(".dist-info/RECORD"))
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == wheel_path:
                text = data.decode()
                text = re.sub(r"(?m)^Tag: .*$", "", text).rstrip("\n") + f"\nTag: {new_tag}\n"
                data = text.encode()
                new_wheel = data
            if info.filename == record_path:
                continue
            zout.writestr(info.filename, data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(new_wheel).digest()).rstrip(b"=").decode()
        rows = []
        for line in zin.read(record_path).decode().splitlines():
            if line.startswith(wheel_path + ","):
                line = f"{wheel_path},sha256={digest},{len(new_wheel)}"
            rows.append(line)
        zout.writestr(record_path, "\n".join(rows) + "\n")
    return dst


# (id, source wheel substring, new tag, expected reldoctor codes)
MUTATIONS = [
    ("arch: x86_64 ELF labelled aarch64", "pydantic_core-2.27.1-cp313-cp313-manylinux_2_17_x86_64", "cp313-cp313-manylinux_2_17_aarch64", {"binary_arch_mismatch"}),
    ("arch: aarch64 ELF labelled x86_64", "pillow-11.0.0-cp313-cp313-manylinux_2_28_aarch64", "cp313-cp313-manylinux_2_28_x86_64", {"binary_arch_mismatch"}),
    ("arch: arm64 Mach-O labelled x86_64", "numpy-2.1.3-cp313-cp313-macosx_11_0_arm64", "cp313-cp313-macosx_11_0_x86_64", {"binary_arch_mismatch"}),
    ("arch: amd64 PE labelled win32", "numpy-2.1.3-cp313-cp313-win_amd64", "cp313-cp313-win32", {"binary_arch_mismatch"}),
    ("os: Linux ELF labelled macOS", "numpy-2.1.3-cp313-cp313-manylinux_2_17_x86_64", "cp313-cp313-macosx_11_0_arm64", {"binary_os_mismatch"}),
    ("os: macOS Mach-O labelled Linux", "numpy-2.1.3-cp313-cp313-macosx_11_0_arm64", "cp313-cp313-manylinux_2_17_aarch64", {"binary_os_mismatch"}),
    ("glibc: needs 2.28 labelled manylinux2014", "pillow-11.0.0-cp313-cp313-manylinux_2_28_x86_64", "cp313-cp313-manylinux2014_x86_64", {"manylinux_glibc_too_new"}),
    ("libc: glibc build labelled musllinux", "cryptography-43.0.3-cp39-abi3-manylinux_2_28_x86_64", "cp39-abi3-musllinux_1_2_x86_64", {"musllinux_links_glibc"}),
    ("libc: musl build labelled manylinux", "cryptography-43.0.3-cp39-abi3-musllinux_1_2_x86_64", "cp39-abi3-manylinux_2_28_x86_64", {"manylinux_links_musl"}),
    ("macOS: needs 11.0 labelled 10.9", "numpy-2.1.3-cp313-cp313-macosx_11_0_arm64", "cp313-cp313-macosx_10_9_arm64", {"macos_target_too_new"}),
    ("abi: cp313 extension labelled cp312", "lxml-5.3.0-cp313-cp313-manylinux_2_28_x86_64", "cp312-cp312-manylinux_2_28_x86_64", {"extension_abi_mismatch"}),
    ("PyPI: linux_x86_64 tag", "numpy-2.1.3-cp313-cp313-manylinux_2_17_x86_64", "cp313-cp313-linux_x86_64", {"unsupported_platform_tag"}),
]


def auditwheel_flags(venv: str, whl: str) -> Tuple[Optional[bool], str]:
    """`auditwheel show` flagged this wheel? It fails outright on some inconsistencies; otherwise it
    prints the tag the contents would justify, so compare that with the tag in the filename (what a
    careful user of the tool would do)."""
    exe = os.path.join(venv, "bin", "auditwheel")
    if not os.path.exists(exe):
        return None, ""
    code, out, _ = run([exe, "show", whl], timeout=300)
    text = out.lower()
    bad = code != 0 or "not consistent" in text or "cannot be" in text or "invalid" in text or "error" in text[:200]
    m = re.search(r'platform tag:\s*"([^"]+)"', out.replace("\n", " "))
    if m and not bad:
        sys.path.insert(0, os.path.join(ROOT, "src"))
        from reldoctor.platform_tags import PlatformInfo
        inferred = PlatformInfo(m.group(1))
        claimed = [PlatformInfo(t) for t in os.path.basename(whl)[:-4].split("-")[-1].split(".")]
        glibc = [c.libc_min for c in claimed if c.libc_min]
        if inferred.libc_min and glibc and inferred.libc_min > min(glibc):
            bad = True
    return bad, out


def run_real(args, tools, workdir: str) -> dict:
    venv = args.tools_venv
    if not venv:
        raise SystemExit("--real needs --tools-venv (pip, twine, auditwheel...)")
    cache = os.path.join(workdir, "_real_cache")
    wheels = fetch(os.path.join(venv, "bin", "pip"), cache)
    rows_md: List[str] = []
    data: Dict[str, object] = {"clean": {}, "mutated": []}

    # 1) untouched releases: any reldoctor error is a false positive (unless known-bad)
    fp, known = [], []
    clean_times: Dict[str, List[float]] = {t.name: [] for t in tools}
    for w in wheels:
        d = os.path.join(workdir, "_one", os.path.basename(w)[:-4])
        os.makedirs(d, exist_ok=True)
        dst = os.path.join(d, os.path.basename(w))
        if not os.path.exists(dst):
            os.link(w, dst)
        for t in tools:
            flagged, out, sec = t.flags(d, None)
            clean_times[t.name].append(sec)
            if t.name == "reldoctor" and flagged:
                (known if os.path.basename(w) in KNOWN_BAD else fp).append((os.path.basename(w), out))
    data["clean"] = {"wheels": len(wheels), "false_positives": [f for f, _ in fp],
                     "known_bad_flagged": [f for f, _ in known],
                     "median_seconds": {n: sorted(v)[len(v) // 2] for n, v in clean_times.items() if v}}
    rows_md.append(f"{len(wheels)} untouched wheels from PyPI. reldoctor flagged {len(fp) + len(known)} of them; "
                   f"unexplained false positives: {len(fp)}"
                   + (f" ({', '.join(f for f, _ in fp)})" if fp else "")
                   + f". Explained flags, each a genuine rule hit: "
                   f"{'; '.join(f'{f} ({KNOWN_BAD[f]})' for f, _ in known) or 'none'}.")
    rows_md.append("")
    rows_md.append("Median seconds per wheel: " + ", ".join(f"{n} {v:.2f}" for n, v in data["clean"]["median_seconds"].items()))

    # 2) real binaries with a wrong tag
    by_prefix = {os.path.basename(w): w for w in wheels}
    rows_md += ["", "DETECT = passes the genuine wheel and flags the mislabelled copy; noisy = the tool already flags the genuine wheel "
                "(no credit); miss = passes both.", "",
                "| real wheel, wrong label | " + " | ".join(t.name for t in tools) + " | auditwheel show | expected code fired |",
                "|---|" + "---|" * (len(tools) + 2)]
    mdir = os.path.join(workdir, "_mut")
    for label, prefix, tag, expect in MUTATIONS:
        src = next((p for n, p in by_prefix.items() if n.startswith(prefix)), None)
        if not src:
            rows_md.append(f"| {label} | source wheel not available |")
            continue
        out_dir = os.path.join(mdir, re.sub(r"\W+", "_", label))
        whl = relabel(src, tag, out_dir)
        orig_dir = os.path.join(mdir, "orig_" + re.sub(r"\W+", "_", os.path.basename(src)[:-4]))
        os.makedirs(orig_dir, exist_ok=True)
        if not os.path.exists(os.path.join(orig_dir, os.path.basename(src))):
            os.link(src, os.path.join(orig_dir, os.path.basename(src)))
        cells, fired = [], None
        for t in tools:
            flagged, out, _ = t.flags(out_dir, None)
            base_flagged, _, _ = t.flags(orig_dir, None)
            # credit a tool only if it passes the genuine wheel and flags the mislabelled one
            cells.append("noisy" if base_flagged else ("DETECT" if flagged else "miss"))
            if t.name == "reldoctor":
                env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
                _, jout, _ = run([sys.executable, "-m", "reldoctor.cli", out_dir, "--format", "json"], env=env)
                codes = {f["code"] for f in json.loads(jout)["findings"]}
                fired = bool(expect & codes)
        aw, _ = auditwheel_flags(venv, whl)
        aw0, _ = auditwheel_flags(venv, src)
        aw_cell = "-" if aw is None else ("noisy" if aw0 else ("DETECT" if aw else "miss"))
        rows_md.append(f"| {label} | " + " | ".join(cells) + f" | {aw_cell} | {'yes' if fired else 'NO'} |")
        aw = aw_cell
        data["mutated"].append({"case": label, "cells": cells, "auditwheel": aw, "expected_code_fired": fired})
    return {"md": "\n".join(rows_md), "data": data}
