"""reldoctor CLI: audit built release artifacts before upload."""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List

from . import __version__
from . import baseline as _baseline
from . import config as _config
from . import doctor
from .doctor import CHECKS, UNIGNORABLE, Finding, diagnose
from .safety import check_allow_patterns, escape_terminal


def _gh_escape(value: str, prop: bool = False) -> str:
    """Escape for GitHub Actions workflow commands (data or property)."""
    value = escape_terminal(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def _render_text(findings: List[Finding], errors: int, warns: int, failed: bool,
                 checked: List[str] | None = None, baselined: int = 0) -> str:
    lines = []
    for f in findings:
        where = f"[{escape_terminal(f.file)}] " if f.file else ""
        lines.append(f"{f.severity.upper():5} {f.code:26} {where}{escape_terminal(f.message)}")
    verdict = "FAIL" if failed else "PASS"
    if checked:
        # without this a clean run says nothing about WHICH files were looked at
        shown = ", ".join(escape_terminal(c) for c in checked[:6]) + (f", +{len(checked) - 6} more" if len(checked) > 6 else "")
        lines.append(f"checked {len(checked)} file(s): {shown}")
    if baselined:
        lines.append(f"{baselined} accepted warning(s) hidden by the baseline")
    lines.append(f"\n{errors} error(s), {warns} warning(s) - {verdict}")
    return "\n".join(lines)


def _render_github(findings: List[Finding], errors: int, warns: int, failed: bool, baselined: int = 0) -> str:
    level = {"error": "error", "warn": "warning", "info": "notice"}
    lines = []
    for f in findings:
        # Artifacts are not repository files, so they go in the message rather
        # than `file=` (which GitHub resolves against the checkout).
        props = f"title={_gh_escape('reldoctor ' + f.code, prop=True)}"
        where = f"[{f.file}] " if f.file else ""
        lines.append(f"::{level[f.severity]} {props}::{_gh_escape(where + f.message)}")
    if baselined:
        lines.append(f"reldoctor: {baselined} accepted warning(s) hidden by the baseline")
    lines.append(f"reldoctor: {errors} error(s), {warns} warning(s) - {'FAIL' if failed else 'PASS'}")
    return "\n".join(lines)


def expand_globs(paths: List[str]) -> List[str]:
    """Expand ``dist/*.whl`` ourselves when the shell did not (Windows cmd.exe and PowerShell
    pass wildcards through untouched). A name that exists is never treated as a pattern, and a
    pattern that matches nothing is left alone so it is reported as "no such file"."""
    out: List[str] = []
    for p in paths:
        hits = []
        if not os.path.exists(p) and any(c in p for c in "*?["):
            hits = sorted(glob.glob(p))
        for q in (hits or [p]):
            if q not in out:
                out.append(q)
    return out


def _list_checks() -> str:
    width = max(len(c) for c in CHECKS)
    return "\n".join(f"{sev.upper():5} {code:{width}}  {desc}" for code, (sev, desc) in CHECKS.items())


def _explain(code: str) -> int:
    from .advice import advice_for
    if code not in CHECKS:
        print(f"reldoctor: unknown check code {escape_terminal(code)!r}; see --list-checks", file=sys.stderr)
        return 2
    sev, desc = CHECKS[code]
    print(f"{code}  ({sev})\n\n{desc}\n")
    print("Can be silenced with --ignore: " + ("no, the gate stays closed" if code in UNIGNORABLE else "yes"))
    fix = advice_for(code)
    if fix:
        print(f"\nWhat to do: {fix}")
    return 0


def main(argv: List[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("reldoctor: interrupted", file=sys.stderr)
        return 2
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - never a bare traceback with the "findings" exit code
        print(f"reldoctor: internal error ({type(e).__name__}): {escape_terminal(str(e))[:300]}. "
              "The release was NOT approved. Please report this with the artifact type that triggered it.",
              file=sys.stderr)
        return 3


def _main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="reldoctor",
        description="Audit wheel + sdist the way PyPI and pip will see them.",
        epilog="reldoctor is made by Calas Automations Inc. (MIT license).",
    )
    ap.add_argument("paths", nargs="*", metavar="PATH",
                    help="dist directory and/or .whl / .tar.gz files (e.g. dist/)")
    ap.add_argument("--strict", action="store_true", help="warnings also fail")
    ap.add_argument("--format", choices=["text", "json", "github", "sarif", "junit", "markdown"], default="text",
                    help="output format; 'github' emits Actions annotations, 'sarif' SARIF 2.1.0 for code "
                         "scanning, 'junit' JUnit XML, 'markdown' a table for $GITHUB_STEP_SUMMARY")
    ap.add_argument("--against", action="append", default=[], metavar="PATH",
                    help="previous release (directory or files, e.g. from `pip download PROJECT==OLD --no-deps`): "
                         "report size jumps, new dependencies, new commands, dropped wheels. Offline.")
    ap.add_argument("--json", action="store_true", help="same as --format json")
    ap.add_argument("--ignore", action="append", default=[], metavar="CODE[,CODE]",
                    help="silence a finding code (repeatable); see --list-checks")
    ap.add_argument("--allow-path", action="append", default=[], metavar="GLOB",
                    help="exempt archive paths matching GLOB from the secret/credential checks "
                         "(e.g. 'tests/certs/*'); repeatable")
    ap.add_argument("--baseline", metavar="FILE",
                    help="hide the warnings listed in FILE (made with --write-baseline) and fail only on new ones. "
                         "Errors are never hidden; a missing or broken FILE is an error")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="record today's warnings in FILE for --baseline, then continue as usual "
                         "(errors still fail the run)")
    ap.add_argument("--max-members", type=int, default=None, metavar="N",
                    help=f"refuse archives with more than N members (default {doctor.DEFAULT_MAX_MEMBERS})")
    ap.add_argument("--jobs", type=int, default=None, metavar="N",
                    help="worker processes for big releases (default: automatic for 3+ artifacts over 64 MiB; "
                         "1 turns it off)")
    ap.add_argument("--config", metavar="FILE", help="read [tool.reldoctor] from FILE instead of ./pyproject.toml")
    ap.add_argument("--no-config", action="store_true", help="ignore ./pyproject.toml")
    ap.add_argument("--explain", metavar="CODE", help="describe one check code and how to fix it, then exit")
    ap.add_argument("--list-checks", action="store_true", help="print every check code and exit")
    ap.add_argument("--version", action="version", version=f"reldoctor {__version__}")
    args = ap.parse_args(argv)

    if args.list_checks:
        print(_list_checks())
        return 0
    if args.explain:
        return _explain(args.explain.strip())
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("reldoctor: error: give a dist directory or artifact files", file=sys.stderr)
        return 2

    args.paths = expand_globs(args.paths)
    if args.jobs is not None and args.jobs < 1:
        print("reldoctor: --jobs must be at least 1", file=sys.stderr)
        return 2

    cfg: dict = {}
    cfg_dir = os.getcwd()
    if not args.no_config:
        cfg_path = _config.find_config(args.config)
        if cfg_path:
            try:
                cfg, cfg_dir = _config.load(cfg_path)
            except _config.ConfigError as e:
                print(f"reldoctor: {escape_terminal(cfg_path)}: {escape_terminal(str(e))} "
                      "(--no-config skips the file)", file=sys.stderr)
                return 2
            if cfg:
                print(f"reldoctor: using [tool.reldoctor] from {escape_terminal(cfg_path)}", file=sys.stderr)
    if cfg.get("strict"):
        args.strict = True
    args.ignore = list(cfg.get("ignore", [])) + args.ignore
    # Windows users type tests\\certs\\*; archive member names always use forward slashes
    args.allow_path = [a.replace("\\", "/") for a in list(cfg.get("allow-path", [])) + args.allow_path]
    args.against = [a if os.path.isabs(a) else os.path.join(cfg_dir, a) for a in cfg.get("against", [])] + args.against
    if args.baseline is None and cfg.get("baseline"):
        args.baseline = cfg["baseline"] if os.path.isabs(cfg["baseline"]) else os.path.join(cfg_dir, cfg["baseline"])
    if args.max_members is None:
        args.max_members = cfg.get("max-members", doctor.DEFAULT_MAX_MEMBERS)

    ignored = {c.strip() for group in args.ignore for c in group.split(",") if c.strip()}
    unknown = sorted(ignored - set(CHECKS))
    if unknown:
        print(f"reldoctor: unknown check code(s) to ignore: {', '.join(map(escape_terminal, unknown))}",
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
            findings = diagnose(args.paths, allow=args.allow_path, against=args.against,
                                jobs=doctor.auto_jobs_for(args.paths) if args.jobs is None else args.jobs)
        finally:
            doctor.MAX_MEMBERS = saved
    except FileNotFoundError as e:
        print(f"reldoctor: no such file or directory: {escape_terminal(str(e))}", file=sys.stderr)
        return 2
    except (ValueError, NotADirectoryError, PermissionError) as e:
        print(f"reldoctor: {escape_terminal(str(e))}", file=sys.stderr)
        return 2

    findings = [f for f in findings if f.code not in ignored]
    baselined, stale = 0, []
    if args.baseline or args.write_baseline:
        if args.write_baseline:
            try:
                n = _baseline.write(args.write_baseline, findings)
            except OSError as e:
                print(f"reldoctor: cannot write the baseline {escape_terminal(args.write_baseline)}: "
                      f"{e.strerror or e}", file=sys.stderr)
                return 2
            print(f"reldoctor: wrote {n} accepted warning(s) to {escape_terminal(args.write_baseline)}",
                  file=sys.stderr)
        if args.baseline:
            try:
                accepted = _baseline.load(args.baseline)
            except _baseline.BaselineError as e:
                print(f"reldoctor: baseline {escape_terminal(args.baseline)}: {escape_terminal(str(e))}",
                      file=sys.stderr)
                return 2
            findings, baselined, stale = _baseline.apply(findings, accepted)
            stale = [e for e in stale if e[0] not in ignored]   # silenced by --ignore, not fixed
            if stale:
                print(f"reldoctor: {len(stale)} baseline entr{'y' if len(stale) == 1 else 'ies'} no longer match "
                      "anything (fixed?); rerun with --write-baseline to drop them", file=sys.stderr)
    try:
        _w, _s, _z, _d = doctor._iter_artifacts(args.paths)
        checked = [os.path.basename(x) for x in _w + _s + _z]
    except (OSError, ValueError):
        checked = []
    errors = sum(f.severity == "error" for f in findings)
    warns = sum(f.severity == "warn" for f in findings)
    failed = bool(errors or (args.strict and warns))

    fmt = "json" if args.json else args.format
    if fmt in ("sarif", "junit", "markdown"):
        from . import formats   # xml.sax pulls in urllib.request: ~0.1 s of start-up the text/json paths never need
    if fmt == "json":
        text = json.dumps({"errors": errors, "warnings": warns, "passed": not failed,
                           "checked": checked, "baselined": baselined, "findings": [f.as_dict() for f in findings]}, indent=2)
    elif fmt == "github":
        text = _render_github(findings, errors, warns, failed, baselined)
    elif fmt == "sarif":
        text = formats.to_sarif(findings, CHECKS, __version__)
    elif fmt == "junit":
        text = formats.to_junit(findings, args.strict)
    elif fmt == "markdown":
        text = formats.to_markdown(findings, failed, errors, warns, baselined)
    else:
        text = _render_text(findings, errors, warns, failed, checked, baselined)
    try:
        _write(text, utf8=fmt != "text")
    except BrokenPipeError:  # e.g. `reldoctor dist/ | head`; the exit code still counts
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
    except OSError as e:     # disk full, closed descriptor: say so, and do not look like "findings found"
        print(f"reldoctor: cannot write the report: {e.strerror or e}", file=sys.stderr)
        return 2
    return 1 if failed else 0


def _write(text: str, utf8: bool = False) -> None:
    """Print without ever failing on a console that cannot show a character (cp1252
    on Windows, LANG=C in a container): unprintable characters come out as \\uXXXX.

    ``utf8``: the machine formats (json, github, sarif, junit, markdown) are read by programs
    that expect UTF-8 (GitHub's runner, SARIF and JUnit consumers). Redirecting them on Windows
    would otherwise write cp1252 bytes under a "UTF-8" label."""
    try:
        if utf8:
            sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]
        else:
            sys.stdout.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    except (AttributeError, ValueError, OSError):
        pass
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(getattr(sys.stdout, "encoding", None) or "ascii", "backslashreplace")
              .decode(getattr(sys.stdout, "encoding", None) or "ascii", "replace"))
    sys.stdout.flush()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
