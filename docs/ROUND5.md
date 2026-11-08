# Round 5: adopt it on an old project, and read the wheel the way an installer does

Date of the work: 2026-11-08. Branch `expert-2`. Nothing was published, tagged, uploaded or pushed.

**How the panel was run, honestly.** This run could not start independent sub-agents, so one author played each specialist
in turn, running real commands for each (every finding below names its command). That is weaker than independent
reviewers. Pass B re-ran every specialist against the new code.

## 1. Baseline (before any change)

| What | Result | Command |
|---|---|---|
| Tests | 489 passed | `.venv/bin/python -m pytest -q` |
| Benchmark (25 good + 100 broken) | 0/25 false positives, 24/24 PyPI-rejects, 73% / 100% (errors / strict) | `python -m bench.run` (committed round-4 numbers) |
| Registry | `reldoctor` 0.1.0 only | `pip index versions reldoctor` |
| Repo version | 0.3.0, unpublished; kept (nothing new was published, so no bump is forced) | `grep` + test |

## 2. Author line

Already `Calas Automations Inc.` in `pyproject.toml` (`authors`, no `maintainers`, no email invented) and `LICENSE`
(`Copyright (c) 2026 Calas Automations Inc.`) from round 4. This round added `__author__`, the SARIF `driver.organization`
and a `--help` footer, replaced a personal-looking user name in a test and in the benchmark corpus with a neutral one, and
added `tests/test_round5.py::test_author_is_pinned_everywhere`.

Proof from a freshly built (non-editable) wheel and sdist:

```
python -m build -o dist/                       # in a scratch copy of the tree
unzip -p dist/*.whl '*/METADATA' | sed -n 1,6p   -> Author: Calas Automations Inc.
tar -xzOf dist/*.tar.gz --wildcards '*/PKG-INFO' | grep ^Author   -> Author: Calas Automations Inc.
unzip -p dist/*.whl '*/licenses/LICENSE' | sed -n 3p   -> Copyright (c) 2026 Calas Automations Inc.
```

Left alone on purpose: the GitHub URLs (real URLs, not author labels) and the author name on old git commits (history).
Whether the GitHub repository is public could not be checked from here (the sandbox proxy answers 403 for github.com).
The package metadata links to it; see decision 2 below.

## 3. Upgrade path from 0.1.0 (the version on the registry)

`pip download reldoctor==0.1.0 --no-deps`, installed in a scratch venv, compared with this tree.

| Question | Result | Command |
|---|---|---|
| Does 0.1.0 leave settings or state files that 0.3.0 must read? | No. 0.1.0 has `cli.py` and `doctor.py` only, no config, cache or baseline | `unzip -l` on the wheel |
| Does every 0.1.0 check code still exist? | Yes, 0 missing | script comparing 0.1.0 `Finding(...)` codes with `CHECKS` |
| Does `reldoctor DIR` and `--json` still work? | Yes. 0.1.0's JSON keys (`errors`, `warnings`, `findings`) are all still present; new keys are additive (`passed`, `checked`, `baselined`; `file` on findings) | ran both on the same demo release |
| Exit codes | 0.1.0: 0 or 1. Now also 2 (usage) and 3 (internal error). Scripts that only test for non-zero are unaffected; a script that treats 1 as "findings" and anything else as "ok" now sees 2 for a bad invocation | `grep return` in both CLIs |
| `pip install --upgrade` over 0.1.0 | Works; `reldoctor --version` and `python -m reldoctor --version` print 0.3.0 | scratch venv |
| Behaviour change a 0.1.0 user will notice | many more checks can fail a release that used to pass (already in the checklist) | n/a |

No migration is needed.

## 4. Specialists and findings

| Specialist | Finding | Proof | Status |
|---|---|---|---|
| PyPA / warehouse maintainer | `WHEEL` with `Wheel-Version: 2.0` passed. Installers refuse a major version they do not know (PEP 427) | probe building a wheel with that header: no finding | fixed: `wheel_version_unsupported` (error); `1.x` newer than 1.0 is `wheel_version_newer` (warn) |
| PyPA maintainer | `WHEEL` with no `Tag` line, or `Root-Is-Purelib` missing or `maybe`, passed silently | same probe | fixed: `wheel_no_tag`, `purelib_unclear` (warnings). How each installer treats a missing `Root-Is-Purelib` was not verified against installer source, hence warnings |
| PyPA maintainer | Differential test against `packaging.utils.parse_wheel_filename`: a filename with an empty tag part (`name-1.0--py3-none.whl`) was accepted by reldoctor's parser | `tests/test_round5.py::test_differential_wheel_filename_parsing` failed first, then passed after the fix | fixed: now `bad_wheel_filename` |
| PyPA maintainer | A classifier added to PyPI after the bundled snapshot (2026.9.21.13) is reported as an **error** ("PyPI rejects") although PyPI accepts it | read of `metacheck.check_classifiers`; test with a patched snapshot age | fixed: an installed `trove-classifiers` is trusted over the snapshot, and the message says how old the snapshot is when it is over 180 days. Severity left as error (typos are the common case) |
| PyPA maintainer | `Provides-Extra: Test_Extra` (not normalized) and duplicate `Provides-Extra` pass, as they also do in `packaging` 26.3 | probe | not changed (idea 34) |
| Release engineer | Teams with old warnings cannot turn on `--strict` without fixing everything first; the other tools offer only `--ignore` | `pydistcheck --help`, `check-wheel-contents --help` list no baseline option (versions 0.11.3 and 0.6.3, current on the registry) | built: `--baseline` / `--write-baseline` |
| Release engineer | A baseline must not become a way to hide real problems or silently turn the gate off | adversarial tests below | designed in: warnings only, `diff_*` never, hand-edited error entries ignored, broken/missing/oversized file is exit 2 |
| Supply-chain auditor | `https://user:secret@host/...` and `git+https://bot:token@github.com/...` in a source file were not reported | scratch probe (not committed); committed equivalent: `test_credential_urls` | fixed: secret kind "URL with embedded password"; placeholders (`user:password@`, `${TOKEN}`, `{token}`, example hosts) ignored; value never printed |
| Supply-chain auditor | Ansible vault password files, `.s3cfg`, `.my.cnf` and agent/MCP settings (`.mcp.json`, `.cursor/mcp.json`, `.claude/settings.local.json`, `.cargo/credentials*`) shipped without a finding | probe over 32 file names | fixed (first three errors, the rest warnings) |
| Supply-chain auditor | Cost of the new pattern on hostile input | 22 MB of repeated `https://a:bbb...` scans in 4.7 s, against 3.3 s without the pattern; 5 MB of colons 1.0 s; no super-linear case found | accepted; the scanner was already about 0.1 s per MB |
| Supply-chain auditor | Secrets in `PASSWORD = '...'` assignments, JWTs, Twilio SIDs, Mailgun keys are not found | probe | not changed on purpose (false-positive rate); documented in limits |
| Wheel-format specialist | A script in `.data/scripts/` starting `#!/usr/bin/python3` or `#!/home/build/venv/bin/python` is copied as written; only `#!python` is rewritten by installers | probe | fixed: `script_hardcoded_interpreter` (warn); `#!python`, `#!/bin/sh`, `#!/usr/bin/env bash` are fine |
| Wheel-format specialist | Fuzz: 600 seeded byte-level mutations (flip, delete, insert) of a wheel and an sdist, plus 9 hostile baseline files | scratch script (not committed) and now `test_seeded_byte_mutation_fuzz_never_crashes` (80 mutations); no crash, no run over 5 s | clean |
| Wheel-format specialist | Golden-file tests for all six output formats did not exist | none in `tests/` | added (`tests/golden/`, regenerate with `RELDOCTOR_REGEN_GOLDEN=1`) |

### Pass B (attack the result)

| Finding | Proof | Status |
|---|---|---|
| A PASS in `markdown` or `github` format did not say it was hiding baselined warnings (only text and JSON did) | read of the diff; test `test_baseline_note_in_every_human_format_...` | fixed |
| Running with `--ignore CODE` made that code's baseline entries look "fixed" (stale warning) | same test | fixed |
| README claims, run from a freshly built non-editable wheel in a clean venv | quick start, `--help`, `--version`, `--write-baseline` / `--baseline` from a directory with a space in its name, `LANG=C`, upgrade over a 0.1.0 install | all as documented |
| The wheel runs on Python 3.11 and 3.12 (and 3.13); 3.9 and 3.10 syntax-only (`ast.parse(feature_version=(3, 9))`) | scratch runs | unchanged limit |
| Own tests: a literal fake credential URL in the new tests tripped the repository's own leak scan | `test_the_repository_does_not_trip_its_own_secret_scanner` failed | fixed (built at run time) |

## 5. Numbers

| What | Before | After |
|---|---|---|
| Tests | 489 | 567 (all pass, Python 3.13; CLI smoke on 3.11 and 3.12) |
| Check codes | 137 | 142 |
| Benchmark corpus | 25 good, 100 broken | 27 good, 105 broken (7 new cases) |
| False positives (default) | 0/25 | 0/27 |
| Recall, PyPI-rejects | 24/24 | 24/24 |
| Recall, all broken, default / `--strict` | 73% / 100% | 72% / 100% |
| Expected code fired | 100/100 | 105/105 |
| Median seconds per release (same run, start-of-round code vs this tree) | 0.558 | 0.605 (about 8% slower; this machine is shared and timings move by that much between runs; the absolute values are higher than round 4's 0.378 because the machine was busier) |
| Competitors, same run | twine check 7/24; check-wheel-contents 3/24; pydistcheck 0/24 | unchanged |

The 105/105 and 100% figures are a regression guard against a corpus written from reldoctor's own rules, not an estimate
of real-world recall (see `bench/RESULTS.md`).

## 6. Ideas, scored (1 to 5; effort and risk: higher is worse)

| # | Idea | Value | Differentiation | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | `--baseline` / `--write-baseline` (round 4 idea 17) | 5 | 4 | 3 | 2 | DONE |
| 2 | `Wheel-Version` major check | 3 | 3 | 1 | 1 | DONE |
| 3 | Missing `Tag` / unusable `Root-Is-Purelib` | 2 | 2 | 1 | 1 | DONE |
| 4 | `#!python` rule for `.data/scripts` | 3 | 4 | 2 | 1 | DONE |
| 5 | Credentialed URLs (`scheme://user:pw@host`) | 4 | 3 | 2 | 2 | DONE |
| 6 | More credential file names (vault, s3cfg, MCP/agent settings, cargo/gem) | 3 | 3 | 1 | 1 | DONE |
| 7 | Trust an installed `trove-classifiers`; say when the snapshot is old (round 4 idea 25, partly) | 4 | 2 | 2 | 1 | DONE |
| 8 | Reject empty or odd wheel tag parts in the filename | 2 | 1 | 1 | 1 | DONE |
| 9 | Author line in `__author__`, SARIF, `--help`; pinned by test | 3 | 1 | 1 | 1 | DONE |
| 10 | Golden files for every output format | 4 | 1 | 2 | 1 | DONE |
| 11 | Seeded property tests, differential tests vs `packaging`, mutation-style sanity tests | 4 | 2 | 2 | 1 | DONE |
| 12 | Baseline note in markdown and github formats; ignored codes are not "stale" | 2 | 1 | 1 | 1 | DONE |
| 13 | Ready-made GitHub Action `action.yml` (round 4 idea 18) | 4 | 3 | 2 | 2 | NOT-DONE: cannot be tested here and needs a tagged release to point at |
| 14 | `--inspect` summary and per-project size limits (idea 19) | 3 | 1 | 3 | 1 | NOT-DONE |
| 15 | Layout expectations `--package` / `--toplevel` (idea 20) | 3 | 1 | 3 | 2 | NOT-DONE |
| 16 | abi3 stable-ABI symbol audit (idea 21) | 3 | 2 | 5 | 3 | NOT-DONE (`abi3audit` exists) |
| 17 | PEP 740 attestation / trusted-publishing readiness (idea 22) | 4 | 4 | 4 | 3 | NOT-DONE (needs the workflow file or PyPI's live state) |
| 18 | Zip-format sdists (idea 23) | 1 | 1 | 2 | 1 | NOT-DONE |
| 19 | mypy clean (idea 24) | 2 | 1 | 3 | 2 | NOT-DONE (mypy not installed here) |
| 20 | Pre-commit hook (idea 26) | 1 | 1 | 2 | 1 | NOT-DONE |
| 21 | Open each zip once (idea 16) | 2 | 1 | 3 | 3 | NOT-DONE |
| 22 | `Provides-Extra` normalization and duplicates (PEP 685) | 2 | 2 | 1 | 1 | NOT-DONE: `packaging` 26.3 accepts them too, so no evidence PyPI rejects |
| 23 | Generic `password = '...'` / JWT scanning | 3 | 1 | 2 | 4 | NOT-DONE: false-positive rate |
| 24 | `reldoctor --prune-baseline` (drop stale entries without rewriting new ones) | 2 | 2 | 2 | 1 | NOT-DONE; `--write-baseline` already refreshes |
| 25 | Reproducible-build check (zip timestamps, member order) | 3 | 3 | 3 | 2 | NOT-DONE |
| 26 | Metadata 2.5 (`Import-Name`) awareness | 2 | 2 | 2 | 3 | NOT-DONE: unverified which version warehouse accepts today |

## 7. What could not be tested

- Windows and macOS were never run. The CI Windows job has still not been seen to pass.
- Python 3.9 and 3.10: syntax-only. 3.11 and 3.12: CLI smoke only (the test suite ran on 3.13).
- Whether the GitHub repository is public or private (proxy blocks github.com).
- How `installer`, `pip` and `uv` each treat a missing `Root-Is-Purelib`; hence a warning, not an error.
- The installed-from-PyPI path (0.3.0 is not on PyPI); the built wheel was installed from a local file.
- `mypy` and `hypothesis` are not installed here; the property tests use a seeded generator instead.
- Multi-process scanning on a large release (2 shared CPUs).

## Decisions for Dan

1. Approve releasing 0.3.0 as the next PyPI version (see `PUBLISH-CHECKLIST.md`). Nothing else is needed to bump the number.
2. Open https://github.com/calasdan-sketch/reldoctor in a signed-out browser window. If it shows "404", the repository is private:
   remove the `[project.urls]` block from `pyproject.toml` (and the tests that pin it) before uploading, because PyPI would
   show dead links.
3. Push the branch and let GitHub Actions run once (the Windows job has never run).
