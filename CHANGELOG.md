# Changelog

## 0.2.0 (unreleased)

### Added
- **RECORD integrity**: every row's sha256/sha384/sha512 and size is verified against the real
  file; rows pointing at missing files, md5/sha1 hashes and unhashed rows are reported. RECORD
  is parsed as CSV, so paths containing commas work.
- **Leak checks**: credential files (`.env`, `.pypirc`, `.netrc`, SSH keys, `.aws/credentials`)
  and token/private-key content (PEM blocks, AWS key ids, GitHub, PyPI and Slack tokens) in
  wheels and sdists. Secret values are never printed. `--allow-path GLOB` exempts deliberate
  fixtures from these checks only.
- **PyPI-rejection rules**: direct-URL `Requires-Dist`, `License` + `License-Expression`
  together, missing `License-File`s (Metadata 2.4+, PEP 639), unknown
  `Description-Content-Type`, malformed `Project-URL`/`Home-page`.
- **Archive safety**: absolute / `..` / drive-letter / backslash member paths, duplicate zip
  entries, case-insensitive collisions, sdist links escaping the tree, special files.
- **Wheel checks**: filename format and normalization, WHEEL `Tag` vs filename, compiled
  extensions in `none-any` wheels, shipped bytecode, VCS dirs and tool-cache junk.
- **Sdist checks**: PEP 625 filename normalization, `{name}-{version}` root, PKG-INFO
  Name/Version vs filename.
- **Cross-artifact**: project-name drift (previously documented but not implemented) and
  Requires-Dist / Requires-Python / Summary drift when PKG-INFO is Metadata 2.2+ (honours `Dynamic`).
- CLI: accepts files as well as directories; `--format text|json|github` (GitHub Actions
  annotations); `--ignore CODE`; `--list-checks`. JSON findings now include `file` and a
  top-level `passed`.
- `reldoctor.diagnose(paths)` and the `CHECKS` registry in the public API.

### Fixed
- Terminal output escapes control, bidi and zero-width characters from archive content.
- `+local` versions no longer also report `version_not_pep440`.
- Entry points with `[extras]` no longer fail.
- Long-description detection uses the metadata body / `Description` field instead of
  counting blank lines.
- Truncated or otherwise unreadable archives are reported instead of crashing; a file
  passed where a directory was expected is a usage error (exit 2) instead of a traceback.
- Only a top-level `.dist-info/METADATA` counts (vendored dist-info dirs no longer break the check).
- Build requirement raised to `setuptools>=77`, needed for the SPDX `license = "MIT"` string.

### Changed
- Fails closed: unknown `--ignore` codes and `--allow-path '*'` are usage errors, and corrupt
  or missing-metadata findings cannot be ignored.
- Text output prefixes each finding with the artifact name; the summary line uses an ASCII
  hyphen. Healthy releases built with hashed RECORDs (all mainstream backends) are unaffected,
  but hand-made wheels with empty RECORD hashes now warn (`record_no_hash`).

## 0.1.0
- Initial release.
