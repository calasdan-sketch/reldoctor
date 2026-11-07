"""One-line "what to do" for the findings people hit most (`reldoctor --explain CODE`).

Only fixes that are stable advice are listed; a code without an entry still
prints its description. Keys are checked against the real check codes by the tests.
"""
from __future__ import annotations

from typing import Optional

ADVICE = {
    "no_artifacts": "Build first (python -m build) and pass the directory that holds the .whl and .tar.gz.",
    "secret_in_file": "Remove the secret from the source, REVOKE it at the provider (it is already compromised if it "
                      "was ever pushed or uploaded), then rebuild. A deliberate test fixture can be exempted with "
                      "--allow-path 'tests/certs/*' or allow-path in [tool.reldoctor].",
    "sensitive_file": "Delete the file from the package, or exclude it in your build backend (MANIFEST.in, "
                      "[tool.setuptools.exclude-package-data], hatch exclude); rotate anything it held.",
    "maybe_sensitive_file": "Open the file. If it holds credentials, remove it and rotate them; if it is harmless data, "
                            "exempt it with --allow-path.",
    "local_path_leak": "Build in a clean container or CI job, or strip build paths (-ffile-prefix-map for C code, "
                       "SOURCE_DATE_EPOCH for reproducible archives).",
    "record_hash_mismatch": "The wheel was changed after it was built. Rebuild it; never edit a wheel by hand without "
                            "re-running `wheel pack`.",
    "record_incomplete": "Files were added to the wheel after the build wrote RECORD. Rebuild.",
    "invalid_classifier": "Use only classifiers from https://pypi.org/classifiers/.",
    "deprecated_classifier": "Replace it with the classifier PyPI names in its deprecation list.",
    "invalid_license_expression": "Use an SPDX expression such as MIT or Apache-2.0 OR MIT (https://spdx.org/licenses/).",
    "license_conflict": "Set only License-Expression (PEP 639) or only License, not both: in pyproject.toml use "
                        "license = \"MIT\" and remove the license table.",
    "license_file_missing": "List only files that exist: check license-files in pyproject.toml.",
    "bad_content_type": "Use text/markdown, text/x-rst or text/plain (readme = \"README.md\" sets it for you).",
    "readme_relative_links": "Use absolute https:// URLs for images and links in the README; PyPI shows them broken otherwise.",
    "direct_url_dependency": "PyPI rejects `name @ https://...` dependencies. Depend on a released version instead.",
    "bad_requirement": "Fix the dependency string (PEP 508), e.g. requests>=2.31; python_version >= \"3.9\".",
    "local_version": "PyPI rejects +local versions. Release a plain version (1.2.3) and keep local builds off PyPI.",
    "version_not_pep440": "Use a canonical PEP 440 version such as 1.0.0, 1.0.0rc1 or 1.0.0.post1.",
    "dev_version": "A .dev version is a pre-release; make sure the version was bumped for the release.",
    "unsupported_platform_tag": "PyPI refuses plain linux_x86_64 wheels. Build in a manylinux container "
                                "(cibuildwheel) or run auditwheel repair.",
    "binary_arch_mismatch": "The compiled code is for another CPU than the wheel name claims. Rebuild on the right "
                            "machine/target; do not rename wheels.",
    "binary_os_mismatch": "The compiled code is for another operating system than the wheel name claims. Rebuild.",
    "manylinux_glibc_too_new": "Build inside the manylinux image that matches the tag (or run auditwheel repair, "
                               "which relabels the wheel with the right tag).",
    "manylinux_glibcxx_too_new": "Build C++ extensions in the manylinux image that matches the tag (its toolchain links "
                                 "newer libstdc++ pieces statically), or run auditwheel repair.",
    "macos_target_too_new": "Set MACOSX_DEPLOYMENT_TARGET to the version in the tag when building, or fix the tag.",
    "extension_abi_mismatch": "The extension was built for another Python version than the wheel tag says. Build "
                              "one wheel per Python version (cibuildwheel).",
    "purelib_mismatch": "Root-Is-Purelib must be false for wheels with compiled code and true for pure Python.",
    "platform_wheel_without_binaries": "Pure-Python projects should ship py3-none-any. Check that the extension "
                                      "actually got built into the wheel.",
    "binary_in_pure_wheel": "Rename/rebuild as a platform wheel, or remove the compiled file from the package.",
    "typosquat_name": "If the similarity is a coincidence, ignore with --ignore typosquat_name; "
                      "otherwise pick a more distinct name before the first upload.",
    "setup_py_network": "Install-time downloads are blocked by many installers and look like malware. Vendor the "
                        "data or fetch it at runtime with the user's consent.",
    "pth_suspicious_code": "A .pth file runs at every Python start. Remove it unless it is essential and "
                           "explain it in the README.",
    "obfuscated_exec": "Remove exec/eval of decoded data; scanners and users treat it as malware.",
    "diff_version_exists": "PyPI never accepts the same filename twice. Bump the version and rebuild.",
    "diff_wheel_dropped": "A platform wheel from the last release is missing; those users would fall back to "
                          "compiling the sdist. Rebuild the full wheel matrix.",
    "diff_new_dependency": "Check the new dependency is intended; each one is something your users now trust.",
    "diff_requires_python_raised": "Raising Requires-Python drops older users: confirm it, and note it in the changelog.",
    "bytecode_shipped": "Exclude __pycache__ and *.pyc from the package (they are rebuilt on install).",
    "vcs_metadata_shipped": "A .git/.hg directory ended up in the artifact: build from a clean export, not the "
                            "working directory.",
    "junk_file": "Exclude the listed editor/cache folders from the build.",
    "file_too_large": "PyPI's default limit is 100 MiB per file; trim data files or ask PyPI for a limit increase.",
    "large_file": "Confirm the file belongs in the package; large data is better downloaded on demand.",
    "nested_archive_partial": "Inspect the bundled archive yourself, or unpack small fixtures into plain files.",
    "sdist_no_license_file": "Add a LICENSE file and list it in license-files so it ships in the sdist.",
    "missing_wheel": "Run `python -m build` (builds both) or `python -m build --wheel`.",
    "missing_sdist": "Run `python -m build --sdist` so source installs and distro packagers can build.",
}


def advice_for(code: str) -> Optional[str]:
    return ADVICE.get(code)
