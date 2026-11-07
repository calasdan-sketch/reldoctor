# Benchmark results

Corpus: 20 good releases and 88 deliberately broken ones (24 that PyPI itself rejects, citing the rule). A tool flags a release when it exits non-zero. Re-run: `python -m bench.run --tools-venv VENV`.

**Read this first.** The synthetic corpus was written by reldoctor's author from the rules reldoctor implements, so reldoctor's 100% on 'PyPI rejects' is a regression guard, not an estimate of how many real-world problems it finds. What the table does show is what the other tools do *not* look at. The independent evidence is the real-wheel section at the bottom (untouched PyPI wheels, and real binaries re-labelled with a wrong tag).

| tool | false positives | recall: PyPI rejects | recall: all broken | precision | median s/release |
|---|---|---|---|---|---|
| reldoctor | 0/20 | 24/24 (100%) | 74% | 100% | 0.126 |
| reldoctor --strict | 0/20 | 24/24 (100%) | 100% | 100% | 0.125 |
| reldoctor 0.2.0 (before) | 0/20 | 13/24 (54%) | 33% | 100% | 0.072 |
| twine check | 0/20 | 7/24 (29%) | 8% | 100% | 0.24 |
| twine check --strict | 0/20 | 7/24 (29%) | 8% | 100% | 0.24 |
| check-wheel-contents | 0/20 | 3/24 (12%) | 8% | 100% | 0.177 |
| pydistcheck | 0/20 | 0/24 (0%) | 1% | 100% | 0.074 |

## Recall by defect category

| tool | binary | diff | integrity | leak | pypi | supply |
|---|---|---|---|---|---|---|
| reldoctor | 11/16 | 1/8 | 6/8 | 19/20 | 23/23 | 5/13 |
| reldoctor --strict | 16/16 | 8/8 | 8/8 | 20/20 | 23/23 | 13/13 |
| reldoctor 0.2.0 (before) | 1/16 | 0/8 | 6/8 | 8/20 | 13/23 | 1/13 |
| twine check | 0/16 | 0/8 | 0/8 | 0/20 | 7/23 | 0/13 |
| twine check --strict | 0/16 | 0/8 | 0/8 | 0/20 | 7/23 | 0/13 |
| check-wheel-contents | 1/16 | 0/8 | 1/8 | 0/20 | 3/23 | 2/13 |
| pydistcheck | 0/16 | 0/8 | 1/8 | 0/20 | 0/23 | 0/13 |

reldoctor fired the *expected* check code on 88/88 broken releases (not just any failure).


## Real PyPI wheels

19 untouched wheels from PyPI: reldoctor flagged 3 of them. Unexplained false positives: 0. Explained flags, each a genuine rule hit: PyYAML-6.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (filename 'PyYAML' is not normalized; PyPI's current upload code rejects that (these files predate the rule)), PyYAML-6.0.2-cp313-cp313-win32.whl (same non-normalized 'PyYAML' filename), attrs-24.2.0-py3-none-any.whl (Metadata-Version 2.3 with License-Expression; twine 7 rejects it too).

Median seconds per wheel: reldoctor 0.39, reldoctor --strict 0.36, reldoctor 0.2.0 (before) 0.26, twine check 0.28, twine check --strict 0.28, check-wheel-contents 0.19, pydistcheck 1.14

DETECT = passes the genuine wheel and flags the mislabelled copy; noisy = the tool already flags the genuine wheel, or cannot read it (auditwheel is Linux-only), so no credit; miss = passes both.

| real wheel, wrong label | reldoctor | reldoctor --strict | reldoctor 0.2.0 (before) | twine check | twine check --strict | check-wheel-contents | pydistcheck | auditwheel show | expected code fired |
|---|---|---|---|---|---|---|---|---|---|
| arch: x86_64 ELF labelled aarch64 | DETECT | noisy | miss | miss | miss | miss | miss | DETECT | yes |
| arch: aarch64 ELF labelled x86_64 | DETECT | noisy | miss | miss | miss | noisy | noisy | DETECT | yes |
| arch: arm64 Mach-O labelled x86_64 | DETECT | noisy | miss | miss | miss | noisy | noisy | noisy | yes |
| arch: amd64 PE labelled win32 | DETECT | noisy | miss | miss | miss | noisy | miss | noisy | yes |
| os: Linux ELF labelled macOS | DETECT | noisy | miss | miss | miss | noisy | noisy | miss | yes |
| os: macOS Mach-O labelled Linux | DETECT | noisy | miss | miss | miss | noisy | noisy | noisy | yes |
| glibc: needs 2.28 labelled manylinux2014 | DETECT | noisy | miss | miss | miss | noisy | noisy | DETECT | yes |
| libc: glibc build labelled musllinux | DETECT | noisy | miss | miss | miss | noisy | noisy | DETECT | yes |
| libc: musl build labelled manylinux | DETECT | noisy | miss | miss | miss | noisy | noisy | DETECT | yes |
| macOS: needs 11.0 labelled 10.9 | DETECT | noisy | miss | miss | miss | noisy | noisy | noisy | yes |
| abi: cp313 extension labelled cp312 | DETECT | noisy | miss | miss | noisy | noisy | miss | miss | yes |
| PyPI: linux_x86_64 tag | DETECT | noisy | miss | miss | miss | noisy | noisy | miss | yes |
