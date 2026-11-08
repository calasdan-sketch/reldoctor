# reldoctor

**Find out what PyPI will reject, what you are about to leak, and whether your wheel tells the truth, before you upload.**

`reldoctor` audits the exact wheel and sdist in `dist/` the way PyPI and installers read them.
It verifies every RECORD hash, applies PyPI's own upload rules (classifiers, SPDX licenses, platform
tags, metadata), scans for credentials and personal paths, reads the native libraries inside a wheel
to check they match its platform tag, flags install-time code, and (with `--against`) tells you what
changed since the last release. Pure standard library, no network, nothing extracted to disk.

## Quick start

```bash
pip install "reldoctor>=0.3"     # Python 3.9 or newer; older releases lack --against, --explain and most checks
python -m build                  # or: uv build / hatch build / flit build
reldoctor dist/                  # audit everything in dist/
reldoctor --version              # confirm you got 0.3 or newer

pip download myproject==1.2.3 --no-deps -d prev/   # the last release, for comparison
reldoctor dist/ --against prev/
```

A synthetic broken release (built by `python -m bench.demo OUT`, not a real project; the wheel name is
shortened to `[...]` here and the two INFO lines are omitted):

```
$ reldoctor dist/ --against prev/
ERROR invalid_classifier    [...] classifier 'Topic :: Software Development :: Widgets' is not a valid trove classifier (checked against trove-classifiers 2026.9.21.13); PyPI rejects the upload. Fix the spelling or remove it
WARN  readme_relative_links [...] long description links to 1 relative path(s) ('docs/logo.png'); PyPI does not resolve them, so they render broken. Use absolute https:// URLs
ERROR secret_in_file        [...] 'acme_widgets/settings.py' contains what looks like a Stripe live key (value not shown); it would be public on PyPI. If this is a deliberate test fixture, exempt it with --allow-path
WARN  local_path_leak       [...] 1 file(s) contain a personal home-directory path for user(s) j*** (e.g. 'acme_widgets/_speed.cpython-312-x86_64-linux-gnu.so'); it exposes a username and machine layout. Build in a clean container or strip paths
ERROR binary_arch_mismatch  [...] 'acme_widgets/_speed.cpython-312-x86_64-linux-gnu.so' is built for arm64 but the wheel tag 'manylinux2014_x86_64' promises x86_64; it will fail to import there
ERROR manylinux_glibc_too_new [...] 'acme_widgets/_speed.cpython-312-x86_64-linux-gnu.so' references GLIBC_2.34 but the tag promises glibc 2.17; `auditwheel repair` would relabel it manylinux_2_34
checked 2 file(s): acme_widgets-1.0.0-cp312-cp312-manylinux2014_x86_64.whl, acme_widgets-1.0.0.tar.gz

4 error(s), 2 warning(s) - FAIL
```

## What it checks

`reldoctor --list-checks` prints all 142 check codes with their severity. In groups:

| Area | Examples |
|---|---|
| **Will PyPI accept it?** | rules taken from PyPI's own upload code (warehouse `forklift/legacy.py`, `forklift/metadata.py`, `utils/wheel.py`) and `packaging.metadata`: direct URLs or unparseable PEP 508 strings in `Requires-`/`Provides-`/`Obsoletes-Dist`; unsupported `Metadata-Version`; invalid or deprecated trove classifiers; invalid SPDX `License-Expression`; `License` + `License-Expression` and missing `License-File`s (PEP 639); platform tags off PyPI's accept-list (`linux_x86_64`); non-normalized wheel names and `.dist-info` dirs; invalid author emails and `Dynamic` fields; `Description-Content-Type`; `+local` and over-long versions; Summary over 512 chars; Project-URL labels over 32 chars; non-normalized member paths; bzip2/lzma wheel members; zip-bomb ratios; GNU sparse tar members; files over 100 MiB |
| **Does the wheel tell the truth?** | native libraries are read (ELF, Mach-O thin and fat, PE) and compared with the platform tag: CPU architecture, operating system, newest `GLIBC_x.y` and `GLIBCXX_3.4.N` against the manylinux floor (policy data from auditwheel), glibc-vs-musl, macOS deployment target against `macosx_X_Y`, `cpython-3NN` extension suffix against the `cpNNN`/`abi3` tag, `Requires-Python` against the `cpXY` tag, `Root-Is-Purelib`, platform tag with no compiled code; the WHEEL file itself (`Wheel-Version` major other than 1, no `Tag`, no usable `Root-Is-Purelib`); `.data/scripts` with a fixed `#!/usr/bin/python3` instead of `#!python` |
| **Leaks** | `.env`, `.pypirc`, `.netrc`, SSH keys, `.aws/credentials`, `.docker/config.json`, kubeconfigs, cloud service-account keys, shell histories, `.npmrc`, `.p12`/`.jks`, `terraform.tfstate` (and, as warnings, `credentials.json`, `secrets.yml`, `local_settings.py`, `*.env`...); PEM private keys (also `\n`-escaped inside JSON), AWS, GitHub, GitLab, PyPI and TestPyPI, npm, Slack, Discord, Google, Stripe live, OpenAI, Anthropic, SendGrid, Hugging Face, Shopify, Docker Hub, DigitalOcean, Databricks and Vault tokens, Azure storage keys, database URLs and `https://user:password@host` URLs with passwords, inside files of any size (including content reached through sdist hardlinks), inside UTF-16 text (what PowerShell's `>` writes), and inside zip / tar / gzip / bzip2 / xz files bundled in the release (two levels deep, bounded). Documented examples and placeholders (`AKIAIOSFODNN7EXAMPLE`, `${NPM_TOKEN}`) are ignored. Personal home-directory paths (`/home/<user>/`, `C:\Users\<user>\`) in compiled code and configs, source maps, SQLite files. Secret values and URL credentials are redacted from every message |
| **Install-time code** | `setup.py` parsed with `ast` (never run) for network calls, hidden `exec(base64...)` payloads and subprocess use; `.pth` files that run code at every Python start; obfuscated `exec()`/`eval()` in any module; console scripts named `pip`, `sudo`, `ls`...; top-level modules that shadow the standard library; top-level `tests/` or `docs/`; project name one edit from a top-1,500 PyPI project |
| **Release diff** (`--against`) | same filename already released (PyPI never accepts a re-upload), size jump, new or removed dependencies, `Requires-Python` raised, new or removed console scripts, new native/`.pth`/script files, vanished packages, a platform wheel that was published last time and is missing now, license change |
| **Integrity** | every RECORD row's sha256 and size against the real file, files missing from / extra to RECORD, md5/sha1 hashes, malformed RECORD CSV, duplicate zip entries |
| **Archive safety** | absolute, `..`, drive-letter and backslash member paths; sdist symlinks escaping the tree, following chains of links; dangling hardlinks; device/FIFO members; names that collide on case-insensitive filesystems; symlink mode bits in wheels; a member cap (`--max-members`, default 100,000) |
| **Metadata quality** | Name/Version vs filename, Summary, Requires-Python vs `Programming Language :: Python :: X.Y` classifiers, license, long description and content type, relative links in the README, undeclared extras, Project-URL format |
| **Wheels of one release** | the same release must come from one build: metadata (`Requires-Dist`, `Requires-Python`, license, summary) or Python source that differs between the wheels in `dist/` points at a stale file from another commit |
| **Wheel vs sdist** | project and version drift; Requires-Dist / Requires-Python / Summary drift when PKG-INFO is Metadata 2.2+ (fields marked `Dynamic` are skipped) |

## Usage

```bash
reldoctor dist/                              # a directory of artifacts
reldoctor dist/*.whl dist/*.tar.gz           # or specific files (reldoctor expands the * itself on Windows)
reldoctor dist/ --strict                     # warnings fail too (release mode)
reldoctor dist/ --format json                # machine-readable (--json still works); json, github, sarif, junit and markdown are always UTF-8
reldoctor dist/ --format github              # GitHub Actions annotations
reldoctor dist/ --format sarif > reldoctor.sarif   # GitHub code scanning / any SARIF viewer
reldoctor dist/ --format junit > reldoctor.xml     # JUnit XML for CI dashboards
reldoctor dist/ --format markdown >> "$GITHUB_STEP_SUMMARY"   # a table on the workflow run page
reldoctor --explain secret_in_file           # what a check means and how to fix it
reldoctor dist/ --against prev/              # also compare with the previous release (offline)
reldoctor dist/ --write-baseline reldoctor-baseline.json   # accept today's warnings (once, when adopting)
reldoctor dist/ --strict --baseline reldoctor-baseline.json  # ...then fail only on new ones
python -m reldoctor dist/                    # same thing without the script on PATH
reldoctor dist/ --ignore no_summary,dev_version
reldoctor dist/ --allow-path 'tests/certs/*' # deliberate test keys: exempt from leak checks only
```

Exit codes: `0` pass, `1` findings (errors, or warnings with `--strict`), `2` usage error (including a report that
could not be written), `3` internal error (the release is not approved; please report it).

### Settings file

Put your choices in `pyproject.toml` so the command line stays short:

```toml
[tool.reldoctor]
strict = true                       # warnings fail too
ignore = ["typosquat_name"]         # silence check codes (never the locked ones)
allow-path = ["tests/certs/*"]      # deliberate fixtures, exempt from the leak checks only
against = ["prev/"]                 # previous release, relative to this file
baseline = "reldoctor-baseline.json"  # accepted warnings (see below), relative to this file
max-members = 50000
```

Command-line `--ignore` / `--allow-path` / `--against` are added to these. The file is read from the directory
you run in (never searched upward, never taken from the artifacts), `--config FILE` names another and `--no-config`
skips it. A typo'd key or wrong type is an error, the locked checks stay locked and over-broad `allow-path` globs
are still refused. If you audit artifacts from an untrusted pull request, run with `--no-config`: a
config file can silence checks. On Python before 3.11 without `tomli`, only a plain `[tool.reldoctor]` table is read
(anything else is an error, not silently skipped).

### Adopting reldoctor on an old project: `--baseline`

An existing project often has a few warnings it cannot fix today, and `--strict` would turn CI red on day one.
Run `reldoctor dist/ --write-baseline reldoctor-baseline.json` once and commit the file. From then on
`--baseline reldoctor-baseline.json` (or `baseline = "..."` in `[tool.reldoctor]`) hides exactly those warnings
and fails on anything new. The rules are strict on purpose:

- only **warnings** are recorded; errors (what PyPI or an installer rejects, leaked secrets) are never hidden, even if someone edits the file by hand;
- an entry is the check code, the artifact, and the full message with the release version blanked out, so it survives a version bump but a different file or path is a new finding;
- release-comparison findings (`diff_*`) are never recorded;
- a missing, oversized or malformed baseline is a usage error (exit 2), never "no baseline";
- entries that no longer match anything are reported on stderr, so the file shrinks as you fix things (rerun `--write-baseline`).

Releases of three or more artifacts totalling over 64 MiB are scanned in parallel (up to 4 worker processes);
`--jobs N` sets it and `--jobs 1` turns it off.

The gate fails closed: an empty `dist/` fails, an unknown `--ignore` code is a usage error,
an `--allow-path` glob broad enough to exempt ordinary source or credential files (`*`, `?*`,
`*.*`, `*.py`, `*.pem`...) is refused, and some checks (`no_artifacts`, corrupt archives,
unreadable members, malformed RECORD, too many members, missing METADATA/PKG-INFO) cannot be ignored.

### In CI

```yaml
- run: pip install build reldoctor
- run: python -m build
- run: pip download "$PROJECT==$PREVIOUS_VERSION" --no-deps -d prev/ || true   # optional: release diff
- run: reldoctor dist/ --strict --format github $( [ -d prev ] && echo "--against prev/" )
- run: reldoctor dist/ --format markdown >> "$GITHUB_STEP_SUMMARY"   # optional: a readable table
- run: twine upload dist/*
```

Optional second opinions: `pip install reldoctor[all]` makes reldoctor also run `packaging.metadata`
(the library PyPI validates METADATA with) and `readme_renderer` (what PyPI renders the description with)
when it finds a problem the built-in rules did not.

## How it compares

Measured by `bench/` on one machine (Python 3.13); every number can be re-run with the commands under
"Reproduce the benchmark". Full tables: [bench/RESULTS.md](https://github.com/calasdan-sketch/reldoctor/blob/main/bench/RESULTS.md).
A tool "flags" a release when it exits non-zero. The synthetic corpus was written by this project's author
from the rules reldoctor implements, so treat the first row as a regression guard and read the other tools'
numbers as "what that tool does not look at"; the last two rows use real PyPI wheels and are the independent evidence.

| | reldoctor 0.3.0 | [twine check][twine] 7.0.0 | [check-wheel-contents][cwc] 0.6.3 | [pydistcheck][pdc] 0.11.3 | [auditwheel show][aw] 6.8.2 |
|---|---|---|---|---|---|
| Synthetic releases PyPI itself rejects, flagged (24, rules cited per case) | **24** | 7 | 3 | 0 | n/a |
| All 100 deliberately broken synthetic releases (errors only / warnings count too) | 73% / 100% | 7% | 7% | 2% | n/a |
| False positives on 25 good synthetic releases | 0 | 0 | 0 | 0 | n/a |
| Real PyPI wheels re-labelled with a wrong platform tag, detected (12; credited only if the tool passes the genuine wheel) | **12** | 0 | 0 | 0 | 5 (Linux wheels only; cannot read the macOS and Windows ones) |
| Unexplained false positives on 19 untouched real wheels | 0 (3 flagged for genuine rule hits) | not measured | not measured | not measured | not measured |
| Median seconds per real wheel (incl. interpreter start; shared, heavily loaded machine, so compare ratios) | 0.95 (1.08 for the previous code, same run) | 0.63 | 0.43 | 1.75 | not measured |

What the other tools are for, from their own documentation: `twine check` renders the long description the way
PyPI does and validates metadata with `packaging`; check-wheel-contents lints wheel layout (W001-W202);
pydistcheck checks sizes, debug symbols and unexpected files in wheels and sdists; `auditwheel show/repair`
decides which manylinux tag a Linux wheel deserves and vendors shared libraries. [pyroma][pyroma],
[check-manifest][cm], [validate-pyproject][vp] and [abi3audit][a3] work on the source tree or on stable-ABI
symbol use and are complementary (installed for the teardown, not scored). reldoctor does not re-implement
rST rendering (install `reldoctor[render]`, or keep running `twine check`), layout linting, vendoring, or abi3 symbol audits.
From pydistcheck's documented options it has no equivalent of `--inspect` (an archive summary), per-project size limits
or the debug-symbols check (checked 2026-11-07 against `pydistcheck --help` 0.11.3).

[twine]: https://twine.readthedocs.io/en/stable/#twine-check
[cwc]: https://pypi.org/project/check-wheel-contents
[pdc]: https://pypi.org/project/pydistcheck/
[aw]: https://github.com/pypa/auditwheel
[pyroma]: https://github.com/regebro/pyroma
[cm]: https://github.com/mgedmin/check-manifest
[vp]: https://github.com/abravalheri/validate-pyproject
[a3]: https://github.com/pypa/abi3audit

PyPI's own rules were read from [warehouse](https://github.com/pypi/warehouse) (`warehouse/forklift/legacy.py`,
`forklift/metadata.py`, `utils/wheel.py`, main branch, 2026-11-07); where reldoctor is stricter or looser than
PyPI it says so in the check's description.

Why the leak check matters: GitGuardian's scan of PyPI found 3,938 unique secrets across
2,922 projects, including 43 `.pypirc` files with publishing credentials
([report](https://www.cyberdefensemagazine.com/gitguardian-researchers-find-thousands-of-leaked-secrets-in-pypi-python-package-index-packages/)).

## Honest limits

- **Windows has not been run.** The code was reviewed by reading it (no `shell=True`, no signals, no file
  replacement; archive member names are handled as `/` paths; output is escaped for a cp1252 console and the
  machine formats are written as UTF-8; wildcards are expanded by reldoctor itself), and the CI workflow has a
  `windows-latest` job, but nobody has watched it pass there yet. Tested for real: Python 3.11, 3.12 and 3.13 on Linux.
  Python 3.9 and 3.10 are checked by syntax only until the CI matrix has run.
- A baseline matches on the exact message, so a warning whose text contains a changing number (for example a count of files) reappears as new when the number changes. That fails closed on purpose.
- It inspects artifacts, not your source tree, and never contacts PyPI. Anything that depends on
  PyPI's live state is out of reach: whether the name is taken, project size quotas, per-project
  file-size overrides, its malware scan, trusted-publishing and attestation setup (PEP 740).
- Three tables are bundled snapshots and can go stale: trove classifiers (2026.9.21.13), SPDX ids
  (as shipped in `packaging` 26.3) and PyPI's platform-tag accept-list (read 2026-11-07). A brand-new
  classifier or platform tag may be reported until you update reldoctor; the message names the snapshot.
  `tools/refresh_data.py` regenerates them.
- The secret scan uses high-confidence patterns. It misses secrets in other formats and flags
  real-but-intentional test keys (for example TLS test certificates); exempt those with `--allow-path`.
  `local_path_leak` ignores generic and CI user names and, for documentation and source files, needs the
  same name in three files before it speaks, so a single hard-coded path in one `.py` file is missed.
- Bundled archives are opened for the secret scan only: zip, tar, gzip, bzip2 and xz, two levels deep, an archive
  up to 64 MiB, 256 MiB decompressed and 50,000 members per artifact. Encrypted members, 7z/rar/zstd and anything
  past those bounds are not inspected; a `nested_archive_partial` warning says so. Secrets that are base64-encoded,
  compressed inside `.pyc` or split across string concatenations are not found.
- UTF-16 text is recognised by its byte-order mark or a clear every-other-byte-zero pattern; UTF-32 and other encodings are not decoded.
- `maybe_sensitive_file` and `long_path` are name-based heuristics (warnings); `wheel_source_drift` can fire on
  files a build legitimately generates per platform (`--ignore wheel_source_drift`).
- Binary checks read headers and the dynamic-symbol version strings; they do not resolve every
  dependency the way `auditwheel` does (no external-library policy, `GLIBCXX` but no `CXXABI` check, no
  RPATH or vendored-library audit) and do not verify abi3 symbol use (see `abi3audit`). Mach-O minimum
  OS is read only where a slice's load commands sit in the first 64 KiB.
- `setup.py` analysis is static. It resolves import aliases but not `getattr` tricks or code in other
  modules, so a clean result is not proof of a clean install.
- `typosquat_name` compares with the 1,500 most-downloaded projects only and can flag an honest
  project one letter away from a big one; `--ignore typosquat_name` if so.
- PEP 508 requirement parsing is a stdlib re-implementation, differential-tested against
  `packaging` on 111 requirement strings (all agree) but not guaranteed identical. The SPDX parser is
  checked against `packaging.licenses` on a fixed sample (see `tests/test_expert2.py`).
- Reads are bounded (16 MiB per metadata file, 1 GiB of content per archive); past that a
  `archive_too_large` warning says hash/secret coverage is partial.
- Version checking accepts canonical PEP 440 only, so non-normalized spellings like `1.0-rc1` are flagged.
- Zip-format sdists are only flagged, not inspected.
- reldoctor is about 1.5x slower than `twine check` and 2.2x slower than `check-wheel-contents` on real wheels (same
  benchmark run, shared machine): it reads every byte of every file once and loads three data tables. Round 4 made it a little
  faster than before (0.95 s against 1.08 s for the previous code on the same wheels in the same run): a single pass decides
  whether any secret pattern can match, and the report formats are only imported when asked for. The parallel scan for big releases
  (`--jobs`) is tested for identical output but its speed-up was not measured: the 2-CPU machine used here was shared.
- A release of tens of thousands of tiny files is slow: 40,000 members took about 40 s on the loaded machine (about 1 ms per
  member, profiled; the archive is opened three times and every member goes through the hash and secret checks).
- Timings are medians from one shared, busy machine (load average 9-16 on 2 CPUs); only the ratios mean anything.
- The "previous code" row of the benchmark shows 24 false positives out of 25 good releases on the machine used here, and the cause is
  not a rule: that machine has `readme_renderer` installed *without* its `[md]` extra, which made the old code call every
  Markdown description unrenderable. Round 4 fixed that (see the changelog); the number is kept because it is what a user with that setup saw.

## Reproduce the benchmark

```bash
python -m venv /tmp/tools && /tmp/tools/bin/pip install twine check-wheel-contents pydistcheck auditwheel
python -m bench.run --tools-venv /tmp/tools          # synthetic corpus: 25 good + 100 broken releases
python -m bench.run --tools-venv /tmp/tools --real   # + real PyPI wheels (downloads ~60 MB)
```

The corpus is generated from scratch by `bench/build.py` and `bench/corpus.py` (each broken case names
the defect, whether PyPI rejects it and the rule's source). The same corpus runs as part of `pytest`.

## Python API

```python
from reldoctor import diagnose
for f in diagnose(["dist/"]):
    print(f.severity, f.code, f.file, f.message)
```

## License

MIT. See [LICENSE](https://github.com/calasdan-sketch/reldoctor/blob/main/LICENSE).
