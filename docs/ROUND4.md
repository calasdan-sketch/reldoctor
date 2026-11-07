# Round 4: the stranger's first hour

Date of the work: 2026-11-07. Branch `expert-2`. Nothing was published, tagged, uploaded or pushed.

**How the panel was run, honestly.** The tooling available to this run could not start independent sub-agents, so one author
played each specialist in turn, running real commands for each. That is weaker than independent reviewers: the same person
who built a thing also attacked it. Pass B re-ran every specialist against the new code (and found one more defect: the
repository tripped its own leak scan once `bench/` went into the sdist).

## 1. Baseline (before any change)

| What | Result | Command |
|---|---|---|
| Tests, repository dev environment | **426 passed, 39 failed** (465) | `.venv/bin/python -m pytest -q` |
| Tests, after the first fix | 465 passed | same |
| Benchmark, synthetic (25 good + 100 broken) | 0/25 false positives, 24/24 PyPI-rejects, 73% / 100% (errors / strict) | `python -m bench.run --tools-venv ... --baseline-src <86dfa7c src>` |
| Real wheels, median s | 1.08 (previous code, same run) | same, `--real` |
| Registry | `reldoctor` 0.1.0 only | `pip index versions reldoctor` |
| Repo version | 0.3.0 (pyproject, `__version__`, top changelog heading all agree) | `grep` + test |

## 2. Specialists and findings

Every row names the command that proved it.

| Specialist | Finding | Proof | Status |
|---|---|---|---|
| First-hour user (README only, clean venv) | `pip install reldoctor` gets 0.1.0, which lacks `--against`, `--explain`, most checks; README never said so | `pip index versions reldoctor` -> only 0.1.0 | README now installs `reldoctor>=0.3` and says to check `--version`; publishing is Dan's step |
| First-hour user | Quick start works from the built wheel in fresh Python 3.11, 3.12 and 3.13 venvs; `--version`, `--help`, `python -m reldoctor` all work from a directory with spaces in its name | installed wheel with `pip install --no-index`, ran from `my proj/` | OK |
| First-hour user | A clean run (PASS) never says which files it looked at | ran `reldoctor dist/` | fixed: `checked N file(s): ...` line, JSON `"checked"` |
| Release engineer | **39 tests fail** in the dev environment; cause: `readme_renderer` 46 ships Markdown as an optional extra, so `render()` returns None and reldoctor called every Markdown README broken. Same bug hits any user of `reldoctor[render]`/`[all]` | `pytest -x` showed `description_render_failed ... the renderer returned nothing`; `python -c "import readme_renderer.markdown"` printed the "extra not available" warning | fixed in code and in the extras; test added |
| Release engineer | Missing metadata a stranger sees: author was a GitHub handle, no Homepage/Issues, one classifier, no `py.typed`, no OS or Python-version classifiers | unzip METADATA of the built wheel | fixed |
| Release engineer | sdist lacked CHANGELOG, `bench/`, `tools/`; tests (which import `bench`) cannot pass from the sdist | `tar tzf dist/*.tar.gz` | fixed with `MANIFEST.in`; 488 tests pass from the extracted sdist on 3.11, 3.12, 3.13 |
| Release engineer | `twine check` passes both artifacts; wheel holds LICENSE, `py.typed`, entry point; no personal paths (the only `/home/` strings are the scanner's own regex text) | `twine check`, `unzip -l`, a path grep | OK |
| Supply-chain reviewer | After `bench/` entered the sdist, reldoctor's own audit failed (`secret_in_file`: a fake database URL in `bench/corpus.py`) | `reldoctor dist/ --strict` on the new build | fixed (URL assembled at runtime); a test now scans the whole repository |
| Supply-chain reviewer | Dependencies: none required; extras `packaging>=24.2`, `readme_renderer[md]>=43.0`. In a clean venv only the standard library is imported | `pip list` in the clean venv shows only reldoctor | OK. Unverified: whether `[md]` exists on `readme_renderer` 43 (pip warns and still installs, it does not fail) |
| Docs/DX writer | The README sample output was not reproducible (no generator) and its messages had drifted from the real ones | read `bench/` for a generator: none | `bench/demo.py` added, sample replaced by the real output, test keeps it true |
| Docs/DX writer | README stated `1.3x slower than twine`; the run today gives 1.5x (and 2.2x vs check-wheel-contents) | bench run | README corrected |
| CI/CD integrator | Windows shells do not expand `dist/*.whl`; reldoctor said "no such file" | `reldoctor "dist dir/*.whl"` (quoted, so the shell does not expand) | fixed: reldoctor expands wildcards itself |
| CI/CD integrator | CI never installed the built wheel into a clean environment or ran it from elsewhere; no Windows job | read `.github/workflows/ci.yml` | added (not run) |
| CI/CD integrator | `--format junit/markdown/...` on a cp1252 console wrote cp1252 bytes under a "UTF-8" label | `PYTHONIOENCODING=cp1252` run, decode as UTF-8 failed | fixed; the old round-3 test that expected `\xe9` escapes in github/junit output was updated on purpose |
| CI/CD integrator | `--jobs 0` / `-3` silently accepted; settings file with a BOM rejected; `--allow-path 'a\b\*'` never matches | ran each | fixed; tests added |
| Hostile-input fuzzer | 550 random byte-flip, truncate, zero-fill and duplicate mutations of a real wheel and sdist, run through `diagnose`: 0 crashes, none slower than 5 s (two seeds) | `fuzz.py` in the scratch directory (not committed) | OK |
| Hostile-input fuzzer | CRLF line ends in METADATA, WHEEL and RECORD (what some Windows builds write): no false findings | script building such a wheel | OK; test added |
| Hostile-input fuzzer | Non-ASCII and bidi-control file names on `LANG=C`, `PYTHONUTF8=0`: no traceback, names escaped | ran the CLI | OK |
| Performance engineer | Start-up imported `xml.sax` and `urllib.request` (about 0.1 s) for every run; the secret scan did up to 36 substring searches per file | `python -X importtime`; `cProfile` on a 40,000-member wheel | fixed; scan 1.5x to 13x faster on 32 MiB buffers |
| Performance engineer | 40,000 tiny members take about 40 s (loaded machine); the zip is opened three times | `cProfile` | NOT fixed (see table) |
| Performance engineer | 150 MiB random member plus 40,000 files: peak memory about 490 MB, correct findings (`file_too_large`, `large_file`) | resource usage of the child process | OK |
| Concurrency | Six simultaneous runs on the same directory: identical output, same exit code | shell | OK |
| Windows packager | Static review only. No `shell=True`, `os.replace`, signals or in-place writes in `src/`; all file reads are binary or explicit UTF-8; archive names are handled as `/`; the `spawn` process pool is guarded by `if __name__ == "__main__"` | `grep -nE "shell=True|os.replace|signal|open\(" src` and reading `cli.py`, `doctor.py` | fixes: wildcards, UTF-8 machine formats, BOM, backslash globs. **Never run on Windows** |
| Read-only filesystem | The tool writes nothing to disk (no temp files, nothing extracted). The sandbox runs as root, so a permission test would prove nothing | grep for write modes | reasoned, not demonstrated |
| Competitor's maintainer | Re-read, same day, what rivals offer (`--help` of the installed 0.11.3 / 0.6.3 and `pip index versions`): pydistcheck has `--inspect`, per-project size limits and expected-file patterns; check-wheel-contents has `--package`/`--src-dir`/`--toplevel` layout expectations; versions in the README table are still the latest on PyPI | `pip index versions twine check-wheel-contents pydistcheck auditwheel` | README table unchanged; the gaps are listed below as NOT-DONE |

## 3. Scored ideas (value / differentiation / effort / risk, each 1 low to 5 high)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Do not call Markdown READMEs broken when `readme_renderer` has no `[md]`; depend on `readme_renderer[md]` | 5 | 1 | 1 | 1 | DONE |
| 2 | Expand `dist/*.whl` ourselves (Windows shells) | 4 | 1 | 1 | 1 | DONE |
| 3 | Machine formats always UTF-8 | 3 | 2 | 1 | 2 | DONE |
| 4 | Say which files were checked (text and JSON) | 4 | 1 | 1 | 1 | DONE |
| 5 | Full PyPI-page metadata: author, URLs, classifiers | 4 | 1 | 1 | 1 | DONE |
| 6 | `py.typed` marker | 2 | 1 | 1 | 1 | DONE |
| 7 | `MANIFEST.in` so the sdist carries changelog, tests, bench | 3 | 1 | 1 | 1 | DONE |
| 8 | Tests that keep version, author, URLs, classifiers and LICENSE consistent | 4 | 2 | 1 | 1 | DONE |
| 9 | Test that the repository passes its own leak scan | 4 | 3 | 1 | 1 | DONE |
| 10 | CI: clean-venv install of the built wheel, run from another folder | 4 | 2 | 1 | 1 | DONE (not run) |
| 11 | CI: Windows job, Python 3.10 | 4 | 1 | 1 | 2 | DONE (not run) |
| 12 | Reproducible README demo (`bench/demo.py`) plus a test | 3 | 2 | 2 | 1 | DONE |
| 13 | Single-pass secret prefilter | 2 | 1 | 1 | 2 | DONE |
| 14 | Lazy import of the report-format module | 2 | 1 | 1 | 1 | DONE |
| 15 | Validate `--jobs`; accept BOM settings files; backslash `--allow-path` | 3 | 1 | 1 | 1 | DONE |
| 16 | Open each zip once instead of three times | 2 | 1 | 3 | 3 | NOT-DONE (gain about 10-15% on huge member counts only) |
| 17 | `--baseline FILE`: adopt on a legacy project by accepting today's warnings and failing only on new ones | 5 | 4 | 4 | 3 | NOT-DONE (best next feature) |
| 18 | Ready-made GitHub Action (`action.yml`) | 4 | 3 | 2 | 2 | NOT-DONE (needs a tagged release to point at) |
| 19 | `--inspect` archive summary and per-project size limits (pydistcheck has both) | 3 | 1 | 3 | 1 | NOT-DONE |
| 20 | Layout expectations (`--package`, `--toplevel`, like check-wheel-contents) | 3 | 1 | 3 | 2 | NOT-DONE |
| 21 | abi3 stable-ABI symbol audit | 3 | 2 | 5 | 3 | NOT-DONE (abi3audit exists) |
| 22 | PEP 740 attestation / trusted-publishing readiness check | 4 | 4 | 4 | 3 | NOT-DONE (needs PyPI's live state or the workflow file) |
| 23 | Inspect zip-format sdists | 1 | 1 | 2 | 1 | NOT-DONE (rare) |
| 24 | Make `mypy` pass (26 findings, mostly "might be None") | 2 | 1 | 3 | 2 | NOT-DONE; mypy is not configured, so `py.typed` only promises the public API |
| 25 | Warn when the bundled classifier/SPDX snapshot is older than six months | 3 | 3 | 2 | 1 | NOT-DONE |
| 26 | Pre-commit hook | 1 | 1 | 2 | 1 | NOT-DONE (artifacts are not in the repository at commit time) |

## 4. Numbers

| | Before round 4 | After |
|---|---|---|
| Tests (dev environment) | 426 pass, 39 fail (465) | 489 pass, 0 fail |
| Check codes | 137 | 137 (this round added no new checks; it fixed behaviour) |
| Synthetic benchmark | 0/25 FP; 24/24 rejects; 73% / 100% | unchanged: 0/25; 24/24; 73% / 100% |
| Real wheels | 12/12 mislabels detected, 0 unexplained FP | unchanged |
| Median seconds, synthetic | 0.418 (previous code, same run) | 0.378 |
| Median seconds, real wheels | 1.08 (previous code, same run) | 0.95 |

The previous-code row shows 24/25 false positives on this machine for the `readme_renderer` reason above; it is in
`bench/RESULTS.md` as measured. Timings come from a shared, loaded machine: trust ratios only.

## 5. Static Windows review (not run on Windows)

| Area | Finding |
|---|---|
| Path separators | archive members are `/`-names and parsed as such; OS paths go through `os.path`. Backslash member names are reported as `unsafe_path`. `--allow-path` now normalizes `\` to `/` |
| `os.replace` on open files | not used; reldoctor never writes files |
| cp1252 console | text output uses `backslashreplace`; machine formats now forced to UTF-8 |
| CRLF | tested on METADATA, WHEEL, RECORD (passes) |
| `shell=True`, signals | none in `src/` (`bench/` uses `subprocess` with lists) |
| Wildcards | cmd.exe/PowerShell do not expand them: fixed |
| Multiprocessing | `spawn` context with an `if __name__ == "__main__"` guard; falls back to a serial run on any pool failure |
| Settings file | BOM accepted; read as UTF-8 |
| Long paths (260 characters) | the `long_path` check warns about members; reldoctor's own handling of very long input paths on Windows is untested |

## 6. What could not be tested

- Windows and macOS: nothing was run. The CI workflow now has a Windows job; its first run is the real test.
- Python 3.9 and 3.10: only a syntax-level check (`ast.parse(feature_version=(3, 9))`) and a grep for newer library calls. Real runs: 3.11, 3.12, 3.13.
- Installing the published package from PyPI: it does not exist at 0.3.0 yet. The built wheel was installed with `--no-index` instead.
- `pip install reldoctor[all]` with the new `[md]` extra was not resolved offline; the code path was tested with a stub of the broken `readme_renderer`, and with the real 46.0 installed without its extra.
- Read-only filesystems and `shell=True`-style injection are reasoned about, not demonstrated (the sandbox runs as root).
- Multi-process speed-up on a big release (`--jobs`): the machine had 2 shared CPUs.
- Whether `readme_renderer` 43 has an `[md]` extra.
- The "previous code" benchmark row is environment dependent (see section 4).

## Decisions for Dan

1. Approve the copyright line `Calas Automations Inc.` in LICENSE (this is a legal choice, so it needs your yes) and the author name in the package metadata.
2. Publish 0.3.0 (see `PUBLISH-CHECKLIST.md`) and let GitHub Actions run first, mainly for the new Windows job.
3. Next feature to build: `--baseline FILE` (idea 17) so a project with old warnings can adopt reldoctor without turning its CI red.
