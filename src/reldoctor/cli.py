"""reldoctor CLI: audit built release artifacts before upload."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .doctor import diagnose_dist_dir


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="reldoctor",
        description="Audit wheel + sdist the way PyPI and pip will see them.",
    )
    ap.add_argument("dist_dir", help="directory containing built .whl / .tar.gz files")
    ap.add_argument("--strict", action="store_true", help="warnings also fail")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--version", action="version", version=f"reldoctor {__version__}")
    args = ap.parse_args(argv)

    try:
        findings = diagnose_dist_dir(args.dist_dir)
    except FileNotFoundError:
        print(f"reldoctor: no such directory: {args.dist_dir}", file=sys.stderr)
        return 2

    errors = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warn"]

    if args.json:
        print(json.dumps(
            {"errors": len(errors), "warnings": len(warns),
             "findings": [f.as_dict() for f in findings]}, indent=2))
    else:
        for f in findings:
            print(f"{f.severity.upper():5} {f.code:24} {f.message}")
        verdict = "FAIL" if errors or (args.strict and warns) else "PASS"
        print(f"\n{len(errors)} error(s), {len(warns)} warning(s) — {verdict}")

    if errors:
        return 1
    return 1 if args.strict and warns else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
