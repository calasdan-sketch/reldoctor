"""A small, stdlib-only reader for Requires-Python specifiers.

Only plain numeric versions are evaluated (``>=3.9``, ``<4``, ``!=3.8.*``,
``~=3.8``); anything else (pre-release suffixes, ``===``) makes
`allows_minor` return None, meaning "do not judge", never a guess.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

_CLAUSE = re.compile(r"^(~=|===|==|!=|<=|>=|<|>)\s*([0-9][0-9A-Za-z.!+*_-]*)$")
_PLAIN = re.compile(r"^(\d+(?:\.\d+)*)(\.\*)?$")
_PATCHES = (0, 1, 2, 5, 10, 50, 99)


def split_clauses(spec: str) -> Optional[List[Tuple[str, str]]]:
    """[(op, version)] or None when the text is not a well-formed specifier."""
    out = []
    parts = [x for x in spec.split(",") if x.strip()]
    if not parts:
        return None
    for part in parts:
        m = _CLAUSE.match(part.strip())
        if not m:
            return None
        out.append((m.group(1), m.group(2)))
    return out


def _tuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _clause_allows(op: str, ver: str, cand: Tuple[int, ...]) -> Optional[bool]:
    m = _PLAIN.match(ver)
    if not m or op == "===":
        return None
    base, star = _tuple(m.group(1)), bool(m.group(2))
    if star and op not in ("==", "!="):
        return None
    if op in ("==", "!="):
        if star:
            hit = cand[:len(base)] == base
        else:
            hit = _cmp(cand, base) == 0
        return hit if op == "==" else not hit
    c = _cmp(cand, base)
    if op == ">=":
        return c >= 0
    if op == ">":
        return c > 0
    if op == "<=":
        return c <= 0
    if op == "<":
        return c < 0
    if op == "~=":
        if len(base) < 2:
            return None
        return c >= 0 and cand[:len(base) - 1] == base[:-1]
    return None


def allows(spec: str, version: Tuple[int, ...]) -> Optional[bool]:
    clauses = split_clauses(spec)
    if clauses is None:
        return None
    for op, ver in clauses:
        r = _clause_allows(op, ver, version)
        if r is None:
            return None
        if not r:
            return False
    return True


def allows_minor(spec: str, major: int, minor: int) -> Optional[bool]:
    """Does any X.Y.patch release satisfy the specifier? None = cannot tell."""
    results = [allows(spec, (major, minor, p)) for p in _PATCHES]
    if any(r is None for r in results):
        return None
    return any(results)
