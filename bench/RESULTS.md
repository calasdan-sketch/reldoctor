# Benchmark results

Corpus: 25 good releases and 100 deliberately broken ones (24 that PyPI itself rejects, citing the rule). A tool flags a release when it exits non-zero. Re-run: `python -m bench.run --tools-venv VENV`.

**Read this first.** The synthetic corpus was written by reldoctor's author from the rules reldoctor implements, so reldoctor's 100% on 'PyPI rejects' is a regression guard, not an estimate of how many real-world problems it finds. What the table does show is what the other tools do *not* look at. The independent evidence is the real-wheel section at the bottom (untouched PyPI wheels, and real binaries re-labelled with a wrong tag).

| tool | false positives | recall: PyPI rejects | recall: all broken | precision | median s/release |
|---|---|---|---|---|---|
| reldoctor | 0/25 | 24/24 (100%) | 73% | 100% | 0.378 |
| reldoctor --strict | 0/25 | 24/24 (100%) | 100% | 100% | 0.374 |
| reldoctor 0.3.0 at start of round 4 | 24/25 | 24/24 (100%) | 100% | 81% | 0.418 |
| twine check | 0/25 | 7/24 (29%) | 7% | 100% | 0.69 |
| twine check --strict | 0/25 | 7/24 (29%) | 7% | 100% | 0.736 |
| check-wheel-contents | 0/25 | 3/24 (12%) | 7% | 100% | 0.536 |
| pydistcheck | 0/25 | 0/24 (0%) | 2% | 100% | 0.228 |

## Recall by defect category

| tool | binary | diff | integrity | leak | pypi | supply |
|---|---|---|---|---|---|---|
| reldoctor | 12/17 | 1/8 | 6/10 | 26/27 | 23/23 | 5/15 |
| reldoctor --strict | 17/17 | 8/8 | 10/10 | 27/27 | 23/23 | 15/15 |
| reldoctor 0.3.0 at start of round 4 | 17/17 | 8/8 | 10/10 | 27/27 | 23/23 | 15/15 |
| twine check | 0/17 | 0/8 | 0/10 | 0/27 | 7/23 | 0/15 |
| twine check --strict | 0/17 | 0/8 | 0/10 | 0/27 | 7/23 | 0/15 |
| check-wheel-contents | 1/17 | 0/8 | 1/10 | 0/27 | 3/23 | 2/15 |
| pydistcheck | 0/17 | 0/8 | 1/10 | 0/27 | 0/23 | 1/15 |

reldoctor fired the *expected* check code on 100/100 broken releases (not just any failure).


## Real PyPI wheels

19 untouched wheels from PyPI. reldoctor flagged 3 of them; unexplained false positives: 0. Explained flags, each a genuine rule hit: PyYAML-6.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (filename 'PyYAML' is not normalized; PyPI's current upload code rejects that (these files predate the rule)); PyYAML-6.0.2-cp313-cp313-win32.whl (same non-normalized 'PyYAML' filename); attrs-24.2.0-py3-none-any.whl (Metadata-Version 2.3 with License-Expression; twine 7 rejects it too).

Median seconds per wheel: reldoctor 0.95, reldoctor --strict 0.93, reldoctor 0.3.0 at start of round 4 1.08, twine check 0.63, twine check --strict 0.58, check-wheel-contents 0.43, pydistcheck 1.75

DETECT = passes the genuine wheel and flags the mislabelled copy; noisy = the tool already flags the genuine wheel (no credit); miss = passes both.

| real wheel, wrong label | reldoctor | reldoctor --strict | reldoctor 0.3.0 at start of round 4 | twine check | twine check --strict | check-wheel-contents | pydistcheck | auditwheel show | expected code fired |
|---|---|---|---|---|---|---|---|---|---|
| arch: x86_64 ELF labelled aarch64 | DETECT | noisy | noisy | miss | miss | miss | miss | DETECT | yes |
| arch: aarch64 ELF labelled x86_64 | DETECT | noisy | noisy | miss | miss | noisy | noisy | DETECT | yes |
| arch: arm64 Mach-O labelled x86_64 | DETECT | noisy | noisy | miss | miss | noisy | noisy | noisy | yes |
| arch: amd64 PE labelled win32 | DETECT | noisy | noisy | miss | miss | noisy | miss | noisy | yes |
| os: Linux ELF labelled macOS | DETECT | noisy | noisy | miss | miss | noisy | noisy | miss | yes |
| os: macOS Mach-O labelled Linux | DETECT | noisy | noisy | miss | miss | noisy | noisy | noisy | yes |
| glibc: needs 2.28 labelled manylinux2014 | DETECT | noisy | noisy | miss | miss | noisy | noisy | DETECT | yes |
| libc: glibc build labelled musllinux | DETECT | noisy | DETECT | miss | miss | noisy | noisy | DETECT | yes |
| libc: musl build labelled manylinux | DETECT | noisy | DETECT | miss | miss | noisy | noisy | DETECT | yes |
| macOS: needs 11.0 labelled 10.9 | DETECT | noisy | noisy | miss | miss | noisy | noisy | noisy | yes |
| abi: cp313 extension labelled cp312 | DETECT | noisy | DETECT | miss | noisy | noisy | miss | miss | yes |
| PyPI: linux_x86_64 tag | DETECT | noisy | noisy | miss | miss | noisy | noisy | miss | yes |
