# Benchmark results

Corpus: 27 good releases and 105 deliberately broken ones (24 that PyPI itself rejects, citing the rule). A tool flags a release when it exits non-zero. Re-run: `python -m bench.run --tools-venv VENV`.

**Read this first.** The synthetic corpus was written by reldoctor's author from the rules reldoctor implements, so reldoctor's 100% on 'PyPI rejects' is a regression guard, not an estimate of how many real-world problems it finds. What the table does show is what the other tools do *not* look at. The independent evidence is the real-wheel section at the bottom (untouched PyPI wheels, and real binaries re-labelled with a wrong tag).

| tool | false positives | recall: PyPI rejects | recall: all broken | precision | median s/release |
|---|---|---|---|---|---|
| reldoctor | 0/27 | 24/24 (100%) | 72% | 100% | 0.605 |
| reldoctor --strict | 0/27 | 24/24 (100%) | 100% | 100% | 0.589 |
| reldoctor at start of round 5 | 0/27 | 24/24 (100%) | 70% | 100% | 0.558 |
| twine check | 0/27 | 7/24 (29%) | 7% | 100% | 1.113 |
| twine check --strict | 0/27 | 7/24 (29%) | 7% | 100% | 1.083 |
| check-wheel-contents | 0/27 | 3/24 (12%) | 8% | 100% | 0.803 |
| pydistcheck | 0/27 | 0/24 (0%) | 2% | 100% | 0.372 |

## Recall by defect category

| tool | binary | diff | integrity | leak | pypi | supply |
|---|---|---|---|---|---|---|
| reldoctor | 12/17 | 1/8 | 7/11 | 28/30 | 23/23 | 5/16 |
| reldoctor --strict | 17/17 | 8/8 | 11/11 | 30/30 | 23/23 | 16/16 |
| reldoctor at start of round 5 | 12/17 | 1/8 | 6/11 | 26/30 | 23/23 | 5/16 |
| twine check | 0/17 | 0/8 | 0/11 | 0/30 | 7/23 | 0/16 |
| twine check --strict | 0/17 | 0/8 | 0/11 | 0/30 | 7/23 | 0/16 |
| check-wheel-contents | 1/17 | 0/8 | 1/11 | 1/30 | 3/23 | 2/16 |
| pydistcheck | 0/17 | 0/8 | 1/11 | 0/30 | 0/23 | 1/16 |

reldoctor fired the *expected* check code on 105/105 broken releases (not just any failure).

