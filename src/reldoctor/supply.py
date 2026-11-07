"""Supply-chain checks: what an artifact would do or pretend to be.

Everything here reads text only. `setup.py` is parsed with ast.parse and
never executed or imported; `.pth` files are read, not loaded.
"""
from __future__ import annotations

import ast
import os
import re
import sys
from functools import lru_cache
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

Pair = Tuple[str, str]

CHECKS_EXTRA: Dict[str, Tuple[str, str]] = {
    "setup_py_network": ("warn", "setup.py makes a network call when pip builds the sdist"),
    "setup_py_obfuscated": ("error", "setup.py decodes and executes a hidden payload"),
    "setup_py_subprocess": ("info", "setup.py runs other programs at build/install time"),
    "setup_py_unparseable": ("warn", "setup.py could not be parsed; install-time code was not reviewed"),
    "obfuscated_exec": ("error", "a Python file runs exec()/eval() on decoded data (base64, zlib, marshal...)"),
    "pth_executes_code": ("warn", ".pth file contains an import line, which Python runs at every start-up"),
    "pth_suspicious_code": ("error", ".pth file runs obfuscated, network or process-spawning code at start-up"),
    "entry_point_shadows_command": ("warn", "a console script has the name of a common system command"),
    "shadows_stdlib": ("error", "a top-level module/package has the name of a standard-library module"),
    "top_level_tests": ("warn", "wheel installs a top-level tests/docs/examples package into site-packages"),
    "typosquat_name": ("warn", "project name is one edit away from a very popular PyPI project"),
    "local_path_leak": ("warn", "files contain a personal home-directory path (/home/<user>/, C:\\Users\\<user>\\)"),
    "source_map_shipped": ("warn", ".map source maps ship original source and build paths"),
    "database_file_shipped": ("warn", "a database/dump file (.sqlite, .db, .sql dump) is shipped"),
    "large_file": ("warn", "a single file inside the artifact is very large"),
    "file_too_large": ("error", "artifact is over PyPI's default 100 MiB per-file limit"),
}

SYSTEM_COMMANDS = frozenset((
    "pip pip3 python python3 py easy_install sudo su ls cat cp mv rm sh bash zsh ssh scp git curl wget "
    "node npm npx docker kubectl make gcc cc ld tar unzip chmod chown ps kill grep sed awk find "
    "systemctl service apt apt-get yum dnf brew conda ping nc").split())

_NET_CALLS = {
    ("urllib.request", "urlopen"), ("urllib.request", "urlretrieve"), ("requests", "get"),
    ("requests", "post"), ("requests", "put"), ("http.client", "HTTPConnection"),
    ("http.client", "HTTPSConnection"), ("socket", "socket"), ("socket", "create_connection"),
    ("ftplib", "FTP"), ("smtplib", "SMTP"), ("httpx", "get"), ("httpx", "post"),
}
_PROC_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execvp"), ("os", "execl"),
               ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
               ("subprocess", "check_call"), ("subprocess", "check_output")}
_DECODERS = {"b64decode", "b32decode", "a85decode", "urlsafe_b64decode", "decompress", "loads",
             "fromhex", "unhexlify", "decode"}
MAX_SETUP_BYTES = 2 * 1024 * 1024


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _has_decoder(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _dotted(sub.func).rsplit(".", 1)[-1]
            if name in _DECODERS and name not in ("loads", "decode") or _dotted(sub.func) in (
                    "marshal.loads", "codecs.decode", "zlib.decompress", "bz2.decompress", "lzma.decompress"):
                return True
    return False


def analyze_setup_py(data: bytes) -> List[Pair]:
    """Install-time behaviour found in a setup.py (text only, never executed)."""
    if len(data) > MAX_SETUP_BYTES:
        return [("setup_py_unparseable", "setup.py is over 2 MiB; install-time code was not reviewed")]
    try:
        tree = ast.parse(data.decode("utf-8", "replace"))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return [("setup_py_unparseable", "setup.py does not parse as Python 3; install-time code was not reviewed")]
    imports: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    imports[a.asname] = a.name
                else:
                    imports[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                imports[a.asname or a.name] = f"{node.module}.{a.name}"
    net, proc, hidden = [], [], False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if not name:
            continue
        head, _, rest = name.partition(".")
        full = f"{imports.get(head, head)}.{rest}" if rest else imports.get(head, head)
        mod, _, attr = full.rpartition(".")
        if (mod, attr) in _NET_CALLS or full in ("urlopen", "urlretrieve"):
            net.append(full)
        elif (mod, attr) in _PROC_CALLS:
            proc.append(full)
        if name in ("exec", "eval") and node.args and _has_decoder(node.args[0]):
            hidden = True
        if name in ("exec", "eval", "compile") and node.args and isinstance(node.args[0], ast.Call):
            inner = _dotted(node.args[0].func)
            if inner.rsplit(".", 1)[-1] in ("b64decode", "decompress", "fromhex", "unhexlify"):
                hidden = True
    out: List[Pair] = []
    if hidden:
        out.append(("setup_py_obfuscated", "setup.py runs exec()/eval() on decoded data; "
                                           "pip would run it on the installing machine"))
    if net:
        out.append(("setup_py_network", f"setup.py calls {', '.join(sorted(set(net))[:3])}; "
                                        "builds from this sdist hit the network and break offline or reproducible builds"))
    if proc:
        out.append(("setup_py_subprocess", f"setup.py runs programs via {', '.join(sorted(set(proc))[:3])}"))
    return out


_PTH_BAD = re.compile(
    r"base64|b64decode|exec\s*\(|eval\s*\(|subprocess|os\.system|os\.popen|urlopen|urllib|requests|socket|"
    r"http\.client|marshal|zlib|__import__|compile\s*\(|getattr\s*\(", re.I)


def analyze_pth(name: str, text: str) -> List[Pair]:
    lines = [ln for ln in text.splitlines() if ln.lstrip().startswith(("import ", "import\t"))]
    if not lines:
        return []
    base = name.rsplit("/", 1)[-1]
    if any(_PTH_BAD.search(ln) for ln in lines):
        return [("pth_suspicious_code",
                 f"{base!r} has an import line that runs hidden, network or process code on every Python start")]
    return [("pth_executes_code",
             f"{base!r} has {len(lines)} import line(s); Python runs them at every start-up, "
             "for every program in the environment. Make sure that is intended")]


def entry_point_shadows(ep_text: str) -> List[Pair]:
    out, section = [], ""
    for line in ep_text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section in ("console_scripts", "gui_scripts") and "=" in line and not line.startswith(("#", ";")):
            cmd = line.split("=", 1)[0].strip()
            if cmd.lower() in SYSTEM_COMMANDS:
                out.append(("entry_point_shadows_command",
                            f"{section} entry {cmd!r} would install a command named like the system's {cmd!r}"))
    return out


def stdlib_names() -> FrozenSet[str]:
    names = getattr(sys, "stdlib_module_names", None)
    return frozenset(names) if names else frozenset()


# Common stdlib names real projects shadow by accident; used when the running
# Python (3.9) has no sys.stdlib_module_names.
_FALLBACK_STDLIB = frozenset((
    "abc argparse array ast asyncio base64 collections copy csv ctypes dataclasses datetime decimal "
    "enum errno functools glob hashlib heapq http importlib inspect io itertools json logging math "
    "multiprocessing os pathlib pickle queue random re select shutil signal socket sqlite3 ssl string "
    "struct subprocess sys tempfile threading time token traceback types typing unittest urllib uuid "
    "warnings weakref xml zipfile zlib test").split())

# Names that exist in the stdlib but that third-party packages are routinely and
# deliberately published under (backports); never flagged.
_STDLIB_OK = frozenset(("typing", "enum", "dataclasses", "asyncio", "pathlib", "contextvars"))


def top_level_names(members: Iterable[str]) -> Dict[str, str]:
    """{import name: kind} for top-level modules/packages, ignoring metadata dirs."""
    out: Dict[str, str] = {}
    for n in members:
        top = n.split("/", 1)[0]
        if top.endswith((".dist-info", ".data", ".egg-info")) or top in ("", ".", ".."):
            continue
        if "/" in n:
            out.setdefault(top, "package")
        elif top.endswith(".py"):
            out.setdefault(top[:-3], "module")
        else:
            m = re.match(r"^([A-Za-z_]\w*)\.(?:cpython-|abi3|pyd|so|cp\d)", top)
            if m:
                out.setdefault(m.group(1), "extension")
    return out


def shadowed_stdlib(tops: Dict[str, str]) -> List[str]:
    std = stdlib_names() or _FALLBACK_STDLIB
    return sorted(t for t in tops if t in std and t not in _STDLIB_OK and not t.startswith("_"))


SUSPICIOUS_TOPS = {"tests", "test", "docs", "doc", "examples", "example", "benchmarks", "scripts", "build", "dist"}


def top_level_clutter(tops: Dict[str, str]) -> List[str]:
    return sorted(t for t, kind in tops.items() if t in SUSPICIOUS_TOPS and kind == "package")


# --- typosquat -------------------------------------------------------------

_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "$": "s"})


@lru_cache(maxsize=1)
def popular_projects() -> FrozenSet[str]:
    path = os.path.join(os.path.dirname(__file__), "data", "popular_projects.txt")
    with open(path, encoding="utf-8") as fh:
        return frozenset(ln.strip() for ln in fh if ln.strip() and not ln.startswith("#"))


def _within_one_edit(a: str, b: str) -> bool:
    """True if a and b differ by one insertion, deletion, substitution or adjacent swap."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def typosquat_target(name: str) -> Optional[str]:
    """The popular project `name` imitates, or None. A name that IS popular, or
    that differs only by separators, is never flagged."""
    norm = re.sub(r"[-_.]+", "-", name).lower()
    pop = popular_projects()
    if norm in pop or len(norm) < 5:
        return None
    flat = norm.replace("-", "")
    for p in pop:
        if len(p) < 5:
            continue
        pflat = p.replace("-", "")
        if flat == pflat:
            return p                        # e.g. 'py-yaml' vs 'pyyaml' only by separators
        if _within_one_edit(flat, pflat):
            return p
    shifted = flat.translate(_HOMOGLYPH)
    if shifted != flat:
        for p in pop:
            if len(p) >= 5 and p.replace("-", "") == shifted:
                return p
    return None
