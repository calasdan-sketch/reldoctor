# reldoctor

**Upload day is too late to find out your release is broken.** Audit built artifacts — the exact wheel and sdist you're about to upload — the way PyPI and pip will read them:

- **Versions**: PEP 440 parseability, PyPI-illegal local segments (`+local`), dev releases, wheel/sdist agreement, METADATA vs filename agreement
- **Metadata**: Name/Version vs filename, Summary, Requires-Python, license field or classifier, long description + `Description-Content-Type` (so PyPI renders it instead of dumping raw text)
- **Structure**: exactly one `.dist-info`, `WHEEL` and `RECORD` present, RECORD actually covering the files, supported Metadata-Version
- **Entry points**: `console_scripts` lines that parse (`name = pkg.module:attr`)
- **Sdist**: top-level root dir, `pyproject.toml`/`setup.py`, `PKG-INFO`, LICENSE/COPYING file
- **Cross-artifact**: name and version drift between wheel and sdist

## Install

```bash
pip install reldoctor
```

## Usage

```bash
python -m build                 # build your dists
reldoctor dist/                 # audit them
reldoctor dist/ --strict        # warnings fail too (release mode)
reldoctor dist/ --json          # machine-readable
```

```
WARN  missing_sdist            no sdist built; PyPI encourages shipping one
WARN  no_content_type          long description present but no Description-Content-Type...
2 error(s), 2 warning(s) — PASS
```

Exit codes: `0` clean (warnings allowed unless `--strict`), `1` findings, `2` usage error.

## Release workflow

```yaml
- run: pip install build reldoctor
- run: python -m build
- run: reldoctor dist/ --strict
- run: twine upload dist/*
```

## Notes

- Inspects artifacts, not sources — `reldoctor` reads the zips and tarballs, so what it checks is what installers get.
- Pure stdlib: no `packaging`, no `twine` import. It complements (doesn't replace) `twine check`.
- Info-level findings (like the sdist version it found) never affect the exit code.

## License

MIT-style: use it, ship it, no warranty.
