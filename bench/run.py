"""Run reldoctor and other release checkers over the corpus and score them.

    python -m bench.run                       # reldoctor only
    python -m bench.run --tools-venv VENV     # + twine, check-wheel-contents, pydistcheck, auditwheel
    python -m bench.run --baseline-src DIR    # also score an older reldoctor checkout (DIR = its src/)
    python -m bench.run --real                # + real PyPI wheels (needs network and --tools-venv)

A tool "flags" a release when it exits non-zero. reldoctor's default gate is
errors only; "strict" also fails on warnings. Results go to bench/results.json
and bench/RESULTS.md.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from .corpus import BAD, CASES, GOOD

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run(cmd, env=None, cwd=None, timeout=180):
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
        return p.returncode, p.stdout + p.stderr, time.perf_counter() - t0
    except subprocess.TimeoutExpired:
        return 124, "timeout", time.perf_counter() - t0


class Tool:
    name = ""

    def available(self) -> bool:
        return True

    def flags(self, dist: str, prev: Optional[str]) -> Tuple[Optional[bool], str, float]:
        """(flagged?, output, seconds); flagged None = not applicable."""
        raise NotImplementedError


class Reldoctor(Tool):
    def __init__(self, name: str, src: str, strict=False, args=()):
        self.name, self.src, self.strict, self.args = name, src, strict, list(args)

    def flags(self, dist, prev):
        env = dict(os.environ, PYTHONPATH=self.src)
        cmd = [sys.executable, "-m", "reldoctor.cli", dist, "--format", "json"] + self.args
        if self.strict:
            cmd.append("--strict")
        if prev:
            cmd += ["--against", prev]
        code, out, sec = run(cmd, env=env)
        if code == 2 and prev and "--against" in out:
            return False, "no --against support", sec    # older version: cannot see release diffs
        return code == 1, out, sec


class External(Tool):
    def __init__(self, name, venv, exe, extra=(), wheels_only=False, needs_ext=False):
        self.name, self.venv, self.exe, self.extra, self.wheels_only = name, venv, exe, list(extra), wheels_only

    def available(self):
        return bool(self.venv) and os.path.exists(os.path.join(self.venv, "bin", self.exe))

    def flags(self, dist, prev):
        files = sorted(os.path.join(dist, f) for f in os.listdir(dist)
                       if f.endswith(".whl") or (not self.wheels_only and f.endswith(".tar.gz")))
        if not files:
            return None, "", 0.0
        code, out, sec = run([os.path.join(self.venv, "bin", self.exe)] + self.extra + files)
        return code != 0, out, sec


def build_tools(args) -> List[Tool]:
    tools: List[Tool] = [
        Reldoctor("reldoctor", os.path.join(ROOT, "src")),
        Reldoctor("reldoctor --strict", os.path.join(ROOT, "src"), strict=True),
    ]
    if args.baseline_src:
        tools.append(Reldoctor("reldoctor 0.2.0 (before)", args.baseline_src))
    v = args.tools_venv
    for t in (External("twine check", v, "twine", ["check"]),
              External("twine check --strict", v, "twine", ["check", "--strict"]),
              External("check-wheel-contents", v, "check-wheel-contents", wheels_only=True),
              External("pydistcheck", v, "pydistcheck")):
        if t.available():
            tools.append(t)
    return tools


def score(tools: List[Tool], workdir: str, log=print) -> dict:
    res: Dict[str, dict] = {t.name: {"good_fp": [], "good_n": 0, "bad": {}, "times": []} for t in tools}
    for c in CASES:
        d = os.path.join(workdir, c.id)
        os.makedirs(d, exist_ok=True)
        prev = c.build(d)
        dist = os.path.join(d, "dist")
        for t in tools:
            flagged, out, sec = t.flags(dist, prev)
            r = res[t.name]
            r["times"].append(sec)
            if c.kind == "good":
                r["good_n"] += 1
                if flagged:
                    r["good_fp"].append(c.id)
            else:
                r["bad"][c.id] = flagged
    return res


def summarize(res: dict) -> List[dict]:
    rows = []
    cats = sorted({c.category for c in BAD})
    for name, r in res.items():
        row = {"tool": name, "false_positives": len(r["good_fp"]), "good_n": r["good_n"],
               "fp_ids": r["good_fp"], "median_seconds": round(statistics.median(r["times"]), 3) if r["times"] else None}
        row["precision"] = None
        tp = sum(1 for v in r["bad"].values() if v)
        fn = sum(1 for v in r["bad"].values() if not v)
        fp = len(r["good_fp"])
        row["recall_all"] = round(tp / (tp + fn), 3) if tp + fn else None
        row["precision"] = round(tp / (tp + fp), 3) if tp + fp else None
        pypi = [c.id for c in BAD if c.pypi]
        row["recall_pypi_rejects"] = round(sum(1 for i in pypi if r["bad"].get(i)) / len(pypi), 3)
        row["pypi_caught"] = sum(1 for i in pypi if r["bad"].get(i))
        row["pypi_total"] = len(pypi)
        for cat in cats:
            ids = [c.id for c in BAD if c.category == cat]
            row[f"recall_{cat}"] = round(sum(1 for i in ids if r["bad"].get(i)) / len(ids), 3)
            row[f"caught_{cat}"] = f"{sum(1 for i in ids if r['bad'].get(i))}/{len(ids)}"
        row["missed"] = sorted(i for i, v in r["bad"].items() if not v)
        rows.append(row)
    return rows


def attribution(workdir: str) -> dict:
    """For reldoctor itself: did the *expected* code fire (not just any failure)?"""
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    hit, wrong = 0, []
    for c in BAD:
        d = os.path.join(workdir, c.id)
        prev = os.path.join(d, "prev") if os.path.isdir(os.path.join(d, "prev")) else None
        cmd = [sys.executable, "-m", "reldoctor.cli", os.path.join(d, "dist"), "--format", "json"]
        if prev:
            cmd += ["--against", prev]
        code, out, _ = run(cmd, env=env)
        try:
            codes = {f["code"] for f in json.loads(out)["findings"]}
        except ValueError:
            codes = set()
        if c.expect & codes:
            hit += 1
        else:
            wrong.append((c.id, sorted(c.expect), sorted(codes)[:6]))
    return {"expected_code_fired": hit, "total": len(BAD), "misses": wrong}


def render_md(rows: List[dict], attr: dict, real: Optional[dict]) -> str:
    cats = sorted({c.category for c in BAD})
    out = ["# Benchmark results", "",
           f"Corpus: {len(GOOD)} good releases and {len(BAD)} deliberately broken ones "
           f"({sum(1 for c in BAD if c.pypi)} that PyPI itself rejects, citing the rule). "
           "A tool flags a release when it exits non-zero. Re-run: `python -m bench.run --tools-venv VENV`.", "",
           "**Read this first.** The synthetic corpus was written by reldoctor's author from the rules reldoctor "
           "implements, so reldoctor's 100% on 'PyPI rejects' is a regression guard, not an estimate of how many "
           "real-world problems it finds. What the table does show is what the other tools do *not* look at. "
           "The independent evidence is the real-wheel section at the bottom (untouched PyPI wheels, and real "
           "binaries re-labelled with a wrong tag).", "",
           "| tool | false positives | recall: PyPI rejects | recall: all broken | precision | median s/release |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['tool']} | {r['false_positives']}/{r['good_n']} | {r['pypi_caught']}/{r['pypi_total']} "
                   f"({r['recall_pypi_rejects']:.0%}) | {r['recall_all']:.0%} | "
                   f"{'-' if r['precision'] is None else format(r['precision'], '.0%')} | {r['median_seconds']} |")
    out += ["", "## Recall by defect category", "", "| tool | " + " | ".join(cats) + " |",
            "|---|" + "---|" * len(cats)]
    for r in rows:
        out.append(f"| {r['tool']} | " + " | ".join(r[f"caught_{c}"] for c in cats) + " |")
    out += ["", f"reldoctor fired the *expected* check code on {attr['expected_code_fired']}/{attr['total']} "
                "broken releases (not just any failure).", ""]
    if attr["misses"]:
        out.append("Expected-code misses: " + "; ".join(f"{i} wanted {w}, got {g}" for i, w, g in attr["misses"]))
    if real:
        out += ["", "## Real PyPI wheels", "", real["md"]]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools-venv", help="virtualenv with twine, check-wheel-contents, pydistcheck, auditwheel installed")
    ap.add_argument("--baseline-src", help="src/ dir of an older reldoctor to score as 'before'")
    ap.add_argument("--real", action="store_true", help="also run the real-wheel set (network)")
    ap.add_argument("--keep", help="build the corpus under this directory and keep it")
    ap.add_argument("--out", default=HERE)
    args = ap.parse_args(argv)
    tools = build_tools(args)
    work = args.keep or tempfile.mkdtemp(prefix="reldoctor-bench-")
    if args.keep:
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
    try:
        res = score(tools, work)
        rows = summarize(res)
        attr = attribution(work)
        real = None
        with open(os.path.join(args.out, "RESULTS.md"), "w") as fh:   # keep the synthetic part if --real fails
            fh.write(render_md(rows, attr, None))
        if args.real:
            from .real import run_real
            real = run_real(args, tools, work)
        with open(os.path.join(args.out, "results.json"), "w") as fh:
            json.dump({"summary": rows, "attribution": attr, "real": real and real["data"]}, fh, indent=2)
        md = render_md(rows, attr, real)
        with open(os.path.join(args.out, "RESULTS.md"), "w") as fh:
            fh.write(md)
        print(md)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
