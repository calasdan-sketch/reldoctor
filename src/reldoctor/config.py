"""Project settings from `[tool.reldoctor]` in pyproject.toml.

```toml
[tool.reldoctor]
strict = true                       # warnings fail too
ignore = ["typosquat_name"]         # silence check codes (never the locked ones)
allow-path = ["tests/certs/*"]      # deliberate fixtures, exempt from the leak checks
against = ["prev/"]                 # previous release, relative to this file
max-members = 50000
```

The file is read from the working directory only (never searched upward, never
from the artifacts being audited), `--config FILE` names another, and `--no-config`
turns it off. Unknown keys and wrong types are errors: a typo must not silently
disable a check.
"""
from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, Optional, Tuple

KEYS = {"strict": bool, "ignore": list, "allow-path": list, "against": list, "max-members": int}
_HEADER = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]\s*(?:#.*)?$")


_OTHER_LAYOUT = re.compile(r"""(?m)^\s*\[?\[?\s*tool\s*\.\s*["']?reldoctor|^\s*["']?reldoctor["']?\s*[=.]""")


class ConfigError(ValueError):
    pass


def _toml_loads(text: str) -> Dict[str, Any]:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return _mini_table(text)
    try:
        data = tomllib.loads(text)
    except Exception as e:  # noqa: BLE001 - tomllib.TOMLDecodeError and friends
        raise ConfigError(f"not valid TOML: {e}") from None
    tool = data.get("tool", {})
    return tool.get("reldoctor", {}) if isinstance(tool, dict) else {}


def _mini_table(text: str) -> Dict[str, Any]:
    """Read only the `[tool.reldoctor]` table (Python < 3.11 without tomli).
    Supports the value shapes this tool uses: strings, booleans, integers and
    (multi-line) arrays of strings."""
    out: Dict[str, Any] = {}
    inside = False
    seen_header = False
    pending_key: Optional[str] = None
    pending: List[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if pending_key is not None:
            pending.append(_strip_comment(raw))
            if pending[-1].rstrip().endswith("]"):
                out[pending_key] = _value(" ".join(pending), pending_key)
                pending_key, pending = None, []
            continue
        m = _HEADER.match(raw)
        if m and not raw.lstrip().startswith("[["):
            inside = re.sub(r"\s*\.\s*", ".", m.group(1)) == "tool.reldoctor"
            seen_header = seen_header or inside
            continue
        if raw.lstrip().startswith("[["):
            inside = False
            continue
        if not inside:
            continue
        line = _strip_comment(raw).strip()
        if not line:
            continue
        key, eq, value = line.partition("=")
        key = key.strip().strip("\"'")
        if not eq or not key:
            raise ConfigError(f"line {lineno}: expected key = value")
        if value.strip().startswith("[") and not value.strip().endswith("]"):
            pending_key, pending = key, [_strip_comment(value)]
            continue
        out[key] = _value(value, key)
    if pending_key is not None:
        raise ConfigError(f"{pending_key}: unterminated array")
    if not seen_header and _OTHER_LAYOUT.search(text):
        raise ConfigError("[tool.reldoctor] is written in a layout this Python (before 3.11, without tomli) cannot "
                          "read; use a plain [tool.reldoctor] table or `pip install tomli`")
    return out


def _strip_comment(s: str) -> str:
    quote = ""
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return s[:i]
    return s


def _value(raw: str, key: str) -> Any:
    v = _strip_comment(raw).strip()
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        parsed = ast.literal_eval(v)       # TOML strings/ints/arrays of strings are Python literals
    except (ValueError, SyntaxError, RecursionError, MemoryError, TypeError):
        raise ConfigError(f"{key}: cannot read value {v[:40]!r}") from None
    return parsed


def find_config(explicit: Optional[str], cwd: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit
    path = os.path.join(cwd or os.getcwd(), "pyproject.toml")
    return path if os.path.isfile(path) else None


def load(path: str) -> Tuple[Dict[str, Any], str]:
    """Validated settings of `path` and the directory relative paths resolve against."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(2_000_000)
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror or e}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"{path} is not UTF-8") from None
    table = _toml_loads(text)
    if not isinstance(table, dict):
        raise ConfigError("[tool.reldoctor] must be a table")
    unknown = sorted(set(table) - set(KEYS))
    if unknown:
        raise ConfigError(f"unknown key(s) in [tool.reldoctor]: {', '.join(map(repr, unknown))}; "
                          f"allowed: {', '.join(sorted(KEYS))}")
    for key, want in KEYS.items():
        if key not in table:
            continue
        val = table[key]
        if want is int and (isinstance(val, bool) or not isinstance(val, int)):
            raise ConfigError(f"{key} must be an integer")
        if want is bool and not isinstance(val, bool):
            raise ConfigError(f"{key} must be true or false")
        if want is list and (not isinstance(val, list) or not all(isinstance(x, str) for x in val)):
            raise ConfigError(f"{key} must be a list of strings")
    return table, os.path.dirname(os.path.abspath(path))
