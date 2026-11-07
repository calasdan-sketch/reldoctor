# Changelog

## 0.3.0 (unreleased)

Expert round 2: PyPI-maintainer, supply-chain, release-engineering and wheel-tag review, with a
committed benchmark (`bench/`, results in `bench/RESULTS.md`).

### Round 3 (additions on this unreleased line)
Specialists: a malicious-package author, a secret-scanner engineer, a release engineer with a wheel matrix,
a Windows packager, a docs/DX lead, a performance engineer. Two passes: build, then review of the new code.

- Added: `[tool.reldoctor]` settings in `pyproject.toml` (`strict`, `ignore`, `allow-path`, `against`,
  `max-members`; `--config`, `--no-config`); `--explain CODE`; `--format markdown`; `--jobs` (parallel scan,
  automatic for big releases); stable SARIF `partialFingerprints`.
- Added leak coverage: secrets inside zip/tar/gzip/bzip2/xz files bundled in a release (`nested.py`, bounded;
  `nested_archive_partial` when something was too deep, large or encrypted to open); UTF-16 text (PowerShell's `>`);
  TestPyPI, Shopify, Docker Hub, DigitalOcean, Databricks, Vault and Discord-webhook tokens and Azure storage keys;
  credential file names (kubeconfig, `.docker/config.json`, cloud service-account keys, shell histories...) and the
  warning-level `maybe_sensitive_file` (`credentials.json`, `secrets.yml`, `local_settings.py`, `*.env`...).
- Added `manylinux_glibcxx_too_new`: newest `GLIBCXX_3.4.N` in an ELF library against the limit of the wheel's manylinux
  policy (table from auditwheel 6.8.2's policy data; vendored `libstdc++` files are not judged).
- Added release checks: `wheel_metadata_drift` and `wheel_source_drift` (a stale wheel from another commit in
  `dist/`), `long_path` (member paths over 200 characters; Windows' 260-character limit).
- Fixed: the README link scan took minutes on a hostile long description (quadratic regular expressions;
  now bounded and tested); a non-ASCII file name crashed the report with a traceback on a `LANG=C` or
  cp1252 console (now written with `\uXXXX` escapes); an unwritable report or an internal error no longer exits
  with the "findings" code (`2` and `3`); TestPyPI tokens were not recognised; `python -m reldoctor` is safe to
  re-import by worker processes.
- Fixed: with `packaging` older than 24.2 installed (it does not know Metadata 2.4), `reldoctor[all]` called every
  modern wheel broken; the oracle now stays silent below 24.2 and the extra requires `packaging>=24.2`.
- Changed: `--max-members` defaults from the settings file when not given; checks 131 -> 137.

### Added (round 2)
- **Wheel tags versus contents** (`wheelcheck.py`, `binary.py`, `platform_tags.py`): reads ELF,
  Mach-O (thin and fat) and PE headers and compares them with the wheel's platform tag. New checks:
  `binary_arch_mismatch`, `binary_os_mismatch`, `manylinux_glibc_too_new` (newest `GLIBC_x.y` symbol
  version against the manylinux floor), `musllinux_links_glibc`, `manylinux_links_musl`,
  `macos_target_too_new` (LC_BUILD_VERSION against `macosx_X_Y`), `extension_abi_mismatch`
  (`cpython-312` suffix in a `cp311` wheel), `abi3_extension_not_stable`, `tag_requires_python_conflict`,
  `platform_wheel_without_binaries`, `purelib_mismatch`.
- **PyPI accept-list for platform tags** (`unsupported_platform_tag`), ported from warehouse's
  `utils/wheel.py`: `linux_x86_64` and friends are now an error.
- **Trove classifiers** (`invalid_classifier`, `deprecated_classifier`) from a bundled, dated snapshot of
  `trove-classifiers`; **SPDX License-Expression validation** (`invalid_license_expression`, parser checked
  against `packaging.licenses`); `license_classifier_mismatch`.
- More PyPI upload rules from `forklift/metadata.py`: `invalid_author_email`, `invalid_dynamic_field`,
  `bad_url_field`, `bad_requires_python`, `dist_info_name_mismatch`; plus `license_expression_old_metadata`
  (twine 7 / packaging reject License-Expression under Metadata-Version < 2.4), `field_newer_than_metadata_version`,
  `undeclared_extra`, `python_classifier_conflict`.
- **Release diff**: `--against PREVIOUS` compares the new files with the previous release's, offline
  (`pip download PROJECT==OLD --no-deps -d prev/`). Reports `diff_version_exists` (PyPI never accepts a
  filename twice), `diff_size_jump`, `diff_new_dependency`, `diff_requires_python_raised`,
  `diff_new_entry_point`, `diff_removed_entry_point`, `diff_new_executable_code`, `diff_removed_package`,
  `diff_wheel_dropped`, `diff_license_changed`, `diff_new_files`.
- **Supply-chain checks** (`supply.py`): `setup.py` is parsed with `ast` (never run) for network calls,
  hidden `exec(base64...)` payloads and subprocess use; `.pth` files with import lines; obfuscated
  `exec()`/`eval()` in any `.py`; console scripts named like system commands (`pip`, `sudo`...);
  top-level names that shadow the standard library; top-level `tests`/`docs`; `typosquat_name` against
  the 1,500 most-downloaded projects (bundled list, 2026-11-01).
- **More leak coverage**: Google, Stripe live, OpenAI, Anthropic, npm, SendGrid, GitLab, Hugging Face
  tokens, Slack webhooks, `.npmrc` auth tokens, database URLs with passwords, private keys serialized
  inside JSON (`\n`-escaped), `.p12/.pfx/.jks/.keystore/.kdbx/.tfvars`, `.pgpass`, `.htpasswd`,
  `terraform.tfstate`; `local_path_leak` (`/home/<user>/`, `C:\\Users\\<user>\\`, name masked in output,
  CI and documentation names ignored), `source_map_shipped`, `database_file_shipped`, `large_file`,
  `file_too_large` (PyPI's 100 MiB default).
- `readme_relative_links`: relative links and images in the long description render broken on PyPI.
- Optional second opinions when installed: `packaging` (what PyPI runs on METADATA, `packaging_rejects_metadata`)
  and `readme_renderer` (`description_render_failed`). `pip install reldoctor[all]`.
- `--format sarif` (SARIF 2.1.0, for GitHub code scanning) and `--format junit`.
- `python -m reldoctor`.
- `bench/`: generator for 20 good and 88 broken releases, runner that scores reldoctor, its previous
  version, `twine check`, `check-wheel-contents`, `pydistcheck` and `auditwheel show`, and a real-wheel
  mode (untouched PyPI wheels for false positives; real binaries re-labelled with wrong tags).

### Fixed
- `wheel_tag_mismatch` false positive on every wheel whose WHEEL file uses the compressed tag form
  (`cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64`), e.g. pydantic-core.
- `wheel_name_not_normalized` is now an error: PyPI rejects `Filename 'PyYAML-...' should contain the
  normalized project name` (warehouse `forklift/legacy.py`).
- Secret findings now say how to exempt a deliberate fixture (`--allow-path`).

### Changed
- Findings that were warnings stay warnings; new errors only where PyPI rejects the upload or the
  artifact will fail on the user's machine. 58 new check codes (131 in all); the full list is `reldoctor --list-checks`.
- Test suite runs from a clean checkout (`pytest` finds `src/` itself).

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
