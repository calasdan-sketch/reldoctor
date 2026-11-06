# reldoctor

**Find out what PyPI will reject, and what you are about to leak, before you upload.**

`reldoctor` audits the exact wheel and sdist in `dist/` the way PyPI and installers read them:
it verifies every RECORD hash, catches upload-blocking metadata (direct-URL dependencies,
PEP 639 license conflicts), flags credential files and tokens that would become public,
checks archives for path-traversal tricks, and compares the wheel against the sdist.
Pure standard library, no network, nothing extracted to disk.

## Quick start

```bash
pip install reldoctor
python -m build          # or: uv build / hatch build / flit build
reldoctor dist/          # audit everything in dist/
```

A synthetic broken release (built for this README, not a real project):

```
$ reldoctor dist/
ERROR sensitive_file             [acme_widgets-1.4.0-py3-none-any.whl] 'acme_widgets/.env' looks like a dotenv file; it would be public on PyPI
ERROR direct_url_dependency      [acme_widgets-1.4.0-py3-none-any.whl] Requires-Dist 'fastjson @ git+https://example.com/fastjson.git' is a direct URL; PyPI rejects "Can't have direct dependency"
ERROR record_hash_mismatch       [acme_widgets-1.4.0-py3-none-any.whl] 1 file(s) content differs from its RECORD sha256 (changed after build?) (e.g. 'demo/__init__.py')
ERROR record_size_mismatch       [acme_widgets-1.4.0-py3-none-any.whl] 1 file(s) size differs from RECORD (e.g. 'demo/__init__.py')
INFO  sdist_version              [acme_widgets-1.4.1.tar.gz] PKG-INFO version 1.4.1
ERROR version_drift              artifacts disagree on version: ['1.4.0', '1.4.1']

5 error(s), 0 warning(s) - FAIL
```

## What it checks

`reldoctor --list-checks` prints all 70+ check codes with their severity. In groups:

| Area | Examples |
|---|---|
| **Will PyPI accept it?** | rules taken from PyPI's own upload code (warehouse `forklift/legacy.py`, `forklift/metadata.py`) and `packaging.metadata`: direct URLs or unparseable PEP 508 strings in `Requires-`/`Provides-`/`Obsoletes-Dist`; unsupported `Metadata-Version`; `Description-Content-Type` type, charset and Markdown variant; `License` + `License-Expression` and missing `License-File`s (PEP 639); `+local` and over-long versions; Summary over 512 chars; Project-URL labels over 32 chars; non-normalized member paths (`a/./b`, `./a`); bzip2/lzma wheel members; zips over 50x ratio past 64 MiB; GNU sparse tar members |
| **Leaks** | `.env`, `.pypirc`, `.netrc`, SSH keys, `.aws/credentials`; PEM private-key blocks, AWS key ids, GitHub, PyPI and Slack tokens inside files of any size (including content reached through sdist hardlinks). Documented examples and placeholders (`AKIAIOSFODNN7EXAMPLE`, `xoxb-your-token-here`) are ignored. Secret values and URL credentials are redacted from every message |
| **Integrity** | every RECORD row's sha256 and size against the real file, files missing from / extra to RECORD, md5/sha1 hashes, malformed RECORD CSV, duplicate zip entries |
| **Archive safety** | absolute, `..`, drive-letter and backslash member paths; sdist symlinks escaping the tree, following chains of links (`a -> ..`, `b -> a/..`); dangling hardlinks; device/FIFO members; names that collide on case-insensitive filesystems; symlink mode bits in wheels; a member cap (`--max-members`, default 100,000) |
| **Wheel correctness** | filename format and normalization, WHEEL `Tag` vs filename, compiled `.so`/`.pyd` inside a `none-any` wheel, shipped bytecode, entry points (including `[extras]`) |
| **Metadata quality** | Name/Version vs filename, Summary, Requires-Python, license, long description and content type, Project-URL format |
| **Sdist** | single `{name}-{version}/` root, PEP 625 filename, `pyproject.toml`/`setup.py`, PKG-INFO, LICENSE/COPYING |
| **Wheel vs sdist** | project and version drift; Requires-Dist / Requires-Python / Summary drift when PKG-INFO is Metadata 2.2+ (fields marked `Dynamic` are skipped) |
| **Junk** | `.git/`, `.tox/`, `.venv/`, `.pytest_cache/`, `.DS_Store` and friends |

## Usage

```bash
reldoctor dist/                              # a directory of artifacts
reldoctor dist/*.whl dist/*.tar.gz           # or specific files
reldoctor dist/ --strict                     # warnings fail too (release mode)
reldoctor dist/ --format json                # machine-readable (--json still works)
reldoctor dist/ --format github              # GitHub Actions annotations
reldoctor dist/ --ignore no_summary,dev_version
reldoctor dist/ --allow-path 'tests/certs/*' # deliberate test keys: exempt from leak checks only
```

Exit codes: `0` pass, `1` findings (errors, or warnings with `--strict`), `2` usage error.

The gate fails closed: an empty `dist/` fails, an unknown `--ignore` code is a usage error,
an `--allow-path` glob broad enough to exempt ordinary source or credential files (`*`, `?*`,
`*.*`, `*.py`, `*.pem`...) is refused, and some checks (`no_artifacts`, corrupt archives,
unreadable members, malformed RECORD, too many members, missing METADATA/PKG-INFO) cannot be ignored.

### In CI

```yaml
- run: pip install build reldoctor
- run: python -m build
- run: reldoctor dist/ --strict --format github
- run: twine upload dist/*
```

## How it compares

Statements about other tools come from their own docs or source, linked. "Not listed" means the
check is not in that tool's documented checks; it may exist elsewhere.

| | reldoctor | [`twine check`][twine] | [check-wheel-contents][cwc] | [pydistcheck][pdc] | [pyroma][pyroma] |
|---|---|---|---|---|---|
| Input | built wheel + sdist | built dists | wheels only | wheels, sdists, conda | a project (see its docs) |
| Renders reStructuredText like PyPI | no (use twine) | **yes** | not listed | not listed | not listed |
| Wheel layout lint (top-level modules, duplicates by content) | partial (bytecode, duplicate names) | not listed | **yes, W001-W202** | partial (case collisions, unexpected files) | not listed |
| Compiled-file debug symbols, non-ASCII/space paths | no | not listed | not listed | **yes** | not listed |
| Verifies RECORD sha256/size | yes | not listed | not listed | not listed | not listed |
| Credential file + token scan | yes | not listed | not listed | `.git`/unexpected files | not listed |
| Direct-URL deps, PEP 639 license rules | yes | not listed | not listed | not listed | not listed |
| Path traversal / unsafe links in archives | yes | not listed | not listed | not listed | not listed |
| Wheel-vs-sdist drift | yes | not listed | not listed | not listed | not listed |
| GitHub annotations output | yes | not listed | not listed | not listed | not listed |

`twine check`'s scope is from its [check.py source][twine] at the linked commit (newer releases may check more); check-wheel-contents' codes from its
[PyPI page][cwc]; pydistcheck's from its [PyPI page][pdc]. These tools complement each other:
running `twine check` alongside reldoctor covers rST rendering, which reldoctor deliberately
does not re-implement.

[twine]: https://github.com/pypa/twine/blob/0f7a68bbf556478b8b5360aa02b1291775d92182/twine/commands/check.py
[cwc]: https://pypi.org/project/check-wheel-contents
[pdc]: https://pypi.org/project/pydistcheck/
[pyroma]: https://www.github.com/regebro/pyroma

Why the leak check matters: GitGuardian's scan of PyPI found 3,938 unique secrets across
2,922 projects, including 43 `.pypirc` files with publishing credentials
([report](https://www.cyberdefensemagazine.com/gitguardian-researchers-find-thousands-of-leaked-secrets-in-pypi-python-package-index-packages/)).

## Honest limits

- It inspects artifacts, not your source tree, and does not contact PyPI.
- The secret scan uses a few high-confidence patterns. It will miss secrets in other
  formats and it will flag real-but-intentional test keys (for example TLS test
  certificates); exempt those with `--allow-path`.
- PEP 508 requirement parsing is a stdlib re-implementation, differential-tested against
  `packaging` on 111 requirement strings (all agree) but not guaranteed identical.
- PyPI rules not checked: classifier validity, author email validity, name squatting,
  file-size quotas, and its YARA malware scan.
- Reads are bounded (16 MiB per metadata file, 1 GiB of content per archive); past that a
  `archive_too_large` warning says hash/secret coverage is partial.
- Version checking accepts canonical PEP 440 only, so non-normalized spellings like `1.0-rc1` are flagged.
- Zip-format sdists are only flagged, not inspected.

## Python API

```python
from reldoctor import diagnose
for f in diagnose(["dist/"]):
    print(f.severity, f.code, f.file, f.message)
```

## License

MIT. See [LICENSE](LICENSE).
