"""reldoctor CLI: audit built release artifacts before upload."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from . import __version__
from . import doctor
from .doctor import CHECKS, UNIGNORABLE, Finding, diagnose
from .safety import check_allow_patterns, escape_terminal


def _gh_escape(value: str, prop: bool = False) -> str:
    """Escape for GitHub Actions workflow commands (data or property)."""
    value = escape_terminal(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def _render_text(findings: List[Finding], errors: int, warns: int, failed: bool) -> str:
    lines = []
    for f in findings:
        where = f"[{escape_terminal(f.file)}] " if f.file else ""
        lines.append(f"{f.severity.upper():5} {f.code:26} {where}{escape_terminal(f.message)}")
    verdict = "FAIL" if failed else "PASS"
    lines.append(f"\n{errors} error(s), {warns} warning(s) - {verdict}")
    return "\n".join(lines)


def _render_github(findings: List[Finding], errors: int, warns: int, failed: bool) -> str:
    level = {"error": "error", "warn": "warning", "info": "notice"}
    lines = []
    for f in findings:
        # Artifacts are not repository files, so they go in the message rather
        # than `file=` (which GitHub resolves against the checkout).
        props = f"title={_gh_escape('reldoctor ' + f.code, prop=True)}"
        where = f"[{f.file}] " if f.file else ""
        lines.append(f"::{level[f.severity]} {props}::{_gh_escape(where + f.message)}")
    lines.append(f"reldoctor: {errors} error(s), {warns} warning(s) - {'FAIL' if failed else 'PASS'}")
    return "\n".join(lines)


def _list_checks() -> str:
    width = max(len(c) for c in CHECKS)
    return "\n".join(f"{sev.upper():5} {code:{width}}  {desc}" for code, (sev, desc) in CHECKS.items())


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="reldoctor",
        description="Audit wheel + sdist the way PyPI and pip will see them.",
    )
    ap.add_argument("paths", nargs="*", metavar="PATH",
                    help="dist directory and/or .whl / .tar.gz files (e.g. dist/)")
    ap.add_argument("--strict", action="store_true", help="warnings also fail")
    ap.add_argument("--format", choices=["text", "json", "github"], default="text",
                    help="output format; 'github' emits Actions annotations")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--ignore", action="append", default=[], metavar="CODE[,CODE]",
                    help="silence a finding code (repeatable); see --list-checks")
    ap.add_argument("--allow-path", action="append", default=[], metavar="GLOB",
                    help="exempt archive paths matching GLOB from the secret/credential checks "
                         "(e.g. 'tests/certs/*'); repeatable")
    ap.add_argument("--max-members", type=int, default=doctor.DEFAULT_MAX_MEMBERS, metavar="N",
                    help=f"refuse archives with more than N members (default {doctor.DEFAULT_MAX_MEMBERS})")
    ap.add_argument("--list-checks", action="store_true", help="print every check code and exit")
    ap.add_argument("--version", action="version", version=f"reldoctor {__version__}")
    args = ap.parse_args(argv)

    if args.list_checks:
        print(_list_checks())
        return 0
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("reldoctor: error: give a dist directory or artifact files", file=sys.stderr)
        return 2

    ignored = {c.strip() for group in args.ignore for c in group.split(",") if c.strip()}
    unknown = sorted(ignored - set(CHECKS))
    if unknown:
        print(f"reldoctor: unknown check code(s) for --ignore: {', '.join(map(escape_terminal, unknown))}",
              file=sys.stderr)
        return 2
    locked = sorted(ignored & UNIGNORABLE)
    if locked:
        print(f"reldoctor: these checks cannot be ignored: {', '.join(locked)}", file=sys.stderr)
        return 2

    broad = check_allow_patterns(args.allow_path)
    if broad:
        for pat, example in broad:
            print(f"reldoctor: --allow-path {escape_terminal(pat)!r} is too broad: it would also "
                  f"exempt {example!r}. Name the fixture directory, e.g. 'tests/certs/*'",
                  file=sys.stderr)
        return 2
    if args.max_members < 1:
        print("reldoctor: --max-members must be at least 1", file=sys.stderr)
        return 2

    try:
        saved, doctor.MAX_MEMBERS = doctor.MAX_MEMBERS, args.max_members
        try:
            findings = diagnose(args.paths, allow=args.allow_path)
        finally:
            doctor.MAX_MEMBERS = saved
    except FileNotFoundError as e:
        print(f"reldoctor: no such file or directory: {escape_terminal(str(e))}", file=sys.stderr)
        return 2
    except (ValueError, NotADirectoryError, PermissionError) as e:
        print(f"reldoctor: {escape_terminal(str(e))}", file=sys.stderr)
        return 2

    findings = [f for f in findings if f.code not in ignored]
    errors = sum(f.severity == "error" for f in findings)
    warns = sum(f.severity == "warn" for f in findings)
    failed = bool(errors or (args.strict and warns))

    fmt = "json" if args.json else args.format
    if fmt == "json":
        text = json.dumps({"errors": errors, "warnings": warns, "passed": not failed,
                           "findings": [f.as_dict() for f in findings]}, indent=2)
    elif fmt == "github":
        text = _render_github(findings, errors, warns, failed)
    else:
        text = _render_text(findings, errors, warns, failed)
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `reldoctor dist/ | head`; the exit code still counts
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
