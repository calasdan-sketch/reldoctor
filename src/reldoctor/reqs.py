"""A small, stdlib-only PEP 508 requirement checker.

PyPI parses every Requires-Dist / Provides-Dist / Obsoletes-Dist value with
`packaging.requirements.Requirement` and rejects the upload if one fails to
parse or carries a direct URL. This module mirrors that grammar closely
enough to say "PyPI would reject this" without depending on `packaging`.
It is deliberately lenient where the grammar is ambiguous: a false "invalid"
would block a good release, a missed one only defers the error to upload.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_WS = re.compile(r"[ \t]*")
# packaging's VERSION_PATTERN (non-canonical spellings allowed, as in specifiers)
_VERSION = (
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:alpha|a|beta|b|preview|pre|c|rc)[-_.]?[0-9]*)?"
    r"(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?"
)
_LOCAL = r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?"  # only valid with ==, !=
_SPEC = re.compile(
    r"(?:"
    r"===[ \t]*[^\s;,)]+"
    r"|(?:==|!=)[ \t]*(?:v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*\.\*|" + _VERSION + _LOCAL + r")"
    r"|~=[ \t]*(?=v?(?:[0-9]+!)?[0-9]+\.[0-9])" + _VERSION +
    r"|(?:<=|>=|<|>)[ \t]*" + _VERSION +
    r")",
    re.IGNORECASE,
)
_MARKER_VAR = re.compile(
    r"(?:python_full_version|python_version|os[._]name|sys[._]platform|platform_release"
    r"|platform_system|platform[._](?:version|machine|python_implementation)"
    r"|python_implementation|implementation_(?:name|version)|extras?|dependency_groups)\b"
)
_MARKER_STR = re.compile(r"'[^']*'|\"[^\"]*\"")
_MARKER_OP = re.compile(r"(?:===|==|!=|<=|>=|~=|<|>|not[ \t]+in\b|in\b)")


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0

    def ws(self):
        self.i = _WS.match(self.s, self.i).end()

    def take(self, rx) -> Optional[str]:
        self.ws()
        m = rx.match(self.s, self.i)
        if not m:
            return None
        self.i = m.end()
        return m.group()

    def lit(self, text: str) -> bool:
        self.ws()
        if self.s.startswith(text, self.i):
            self.i += len(text)
            return True
        return False

    # marker grammar (PEP 508), depth-limited against hostile nesting
    def marker_or(self, depth=0) -> bool:
        if depth > 50 or not self.marker_and(depth):
            return False
        while self.word("or"):
            if not self.marker_and(depth):
                return False
        return True

    def marker_and(self, depth) -> bool:
        if not self.marker_expr(depth):
            return False
        while self.word("and"):
            if not self.marker_expr(depth):
                return False
        return True

    def word(self, w: str) -> bool:
        self.ws()
        m = re.compile(w + r"\b").match(self.s, self.i)
        if m:
            self.i = m.end()
            return True
        return False

    def marker_expr(self, depth) -> bool:
        if self.lit("("):
            return self.marker_or(depth + 1) and self.lit(")")
        return bool(self.marker_var() and self.take(_MARKER_OP) and self.marker_var())

    def marker_var(self) -> bool:
        return bool(self.take(_MARKER_VAR) or self.take(_MARKER_STR))


def parse_requirement(text: str) -> Tuple[Optional[str], bool]:
    """Return (error, is_direct_url). error is None when `text` parses."""
    p = _Parser(text.strip())
    if not p.take(_NAME):
        return "does not start with a valid project name", False
    if p.lit("["):
        p.ws()
        if not p.lit("]"):
            if not p.take(_NAME):
                return "bad extras list", False
            while p.lit(","):
                if not p.take(_NAME):
                    return "bad extras list", False
            if not p.lit("]"):
                return "unclosed extras list", False
    direct = False
    if p.lit("@"):
        direct = True
        p.ws()
        m = re.compile(r"[^\s;]+").match(p.s, p.i)
        if not m or not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", m.group()):
            return "direct reference is not a URL", True
        p.i = m.end()
        if p.i < len(p.s) and not p.s[p.i].isspace():
            return "a URL must be followed by whitespace before ';'", True
    else:
        paren = p.lit("(")
        if p.take(_SPEC):
            while p.lit(","):
                if not p.take(_SPEC):
                    return "bad version specifier", False
        elif paren:
            return "bad version specifier", False
        if paren and not p.lit(")"):
            return "unclosed '('", False
    if p.lit(";"):
        if not p.marker_or():
            return "bad environment marker", direct
    p.ws()
    if p.i != len(p.s):
        return f"unexpected text at position {p.i}", direct
    return None, direct
