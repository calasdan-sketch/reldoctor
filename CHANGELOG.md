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

### Review fixes (panel review of synapse-1)
- **Security:** finding messages could print secrets, e.g. a token in a direct-URL
  `Requires-Dist` or `user:pass@` in a Project-URL. Every message now has URL userinfo and
  anything matching a secret pattern redacted, centrally, before output in any format.
- A malformed RECORD (NUL bytes, oversized CSV field) crashed with a traceback; it is now
  `record_unparseable`, which cannot be ignored.
- PyPI rules re-checked against warehouse `forklift/legacy.py` / `forklift/metadata.py` and
  `packaging.metadata`:
  - `bad_content_type` is now an error, with charset (UTF-8 only) and Markdown variant (GFM/CommonMark) checks.
  - `Metadata-Version` must be one of 1.0, 1.1, 1.2, 2.1-2.5.
  - `Provides-Dist` and `Obsoletes-Dist` are checked as well as `Requires-Dist`, all three
    for direct URLs and PEP 508 validity (`bad_requirement`), in the wheel and in PKG-INFO.
  - New: `path_not_normalized` (sdist `./` prefixes are no longer stripped silently),
    `sparse_member`, `unsupported_compression`, `compression_ratio`, `summary_too_long`,
    `version_too_long`, `project_url_rejected` (label over 32 chars, missing label or URL).
- Symlink checks follow chains of links inside the sdist (`a -> ..`, `b -> a/..`), with a hop
  limit; dangling hardlinks are flagged.
- Archives with more than `--max-members` (default 100,000) members are refused (`too_many_members`, cannot be ignored).
- `--allow-path` patterns are tested against a set of canary paths (source files, `.env`,
  `.pypirc`, keys); any glob that would exempt one (`?*`, `*.*`, `*.py`...) is refused.
- A hardlink's target content is scanned under the link's own name, so an allow-listed key
  cannot ship under another name.
- The secret scan streams every file in overlapping chunks instead of skipping files over
  2 MiB; AWS's documented example key and placeholder tokens no longer match; the Slack
  pattern requires the numeric ids real tokens carry. New `zip_symlink` warning.

## 0.1.0
- Initial release.
