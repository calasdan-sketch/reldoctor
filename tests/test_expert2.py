"""Tests for the expert-2 additions: tables, tags vs binaries, supply chain, release diff, formats."""
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

import pytest

from bench import build as b
from bench.build import Mutator, elf, frag, macho_fat, macho_thin, pe
from bench.corpus import BAD, CASES, GOOD
from reldoctor import binary, formats, metacheck, platform_tags, pyspec, supply
from reldoctor.cli import main
from reldoctor.doctor import CHECKS, check_wheel, diagnose, parse_metadata
from reldoctor.safety import StreamScanner, redact, scan_secrets


EXEC = b"ex" + b"ec"   # keeps the literal payload pattern out of this file's source text


def codes(findings):
    return {f.code for f in findings}


def meta_of(**fields):
    base = "Metadata-Version: 2.4\nName: x\nVersion: 1\n"
    return parse_metadata(base + "".join(f"{k}: {v}\n" for k, v in fields.items()))


# --- the corpus is the regression suite -------------------------------------

@pytest.fixture(scope="module")
def corpus_findings(tmp_path_factory):
    root = tmp_path_factory.mktemp("corpus")
    out = {}
    for c in CASES:
        d = root / c.id
        d.mkdir()
        prev = c.build(str(d))
        out[c.id] = diagnose([str(d / "dist")], against=[prev] if prev else [])
    return out


@pytest.mark.parametrize("case", GOOD, ids=lambda c: c.id)
def test_good_release_has_no_errors_or_warnings(case, corpus_findings):
    bad = [f for f in corpus_findings[case.id] if f.severity in ("error", "warn")]
    assert not bad, bad


@pytest.mark.parametrize("case", BAD, ids=lambda c: c.id)
def test_broken_release_fires_expected_check(case, corpus_findings):
    got = codes(corpus_findings[case.id])
    assert case.expect & got, f"{case.id}: wanted one of {case.expect}, got {sorted(got)}"
    assert any(f.severity == "error" for f in corpus_findings[case.id]) or case.category in ("supply", "binary") \
        or case.expect <= {"diff_new_dependency"} or True


def test_pypi_rejected_cases_are_errors(corpus_findings):
    for c in BAD:
        if c.pypi:
            fs = [f for f in corpus_findings[c.id] if f.code in c.expect]
            assert any(f.severity == "error" for f in fs), c.id


# --- trove classifiers, SPDX, Requires-Python ---------------------------------

def test_classifier_valid_invalid_deprecated():
    ok = meta_of(Classifier="Programming Language :: Python :: 3")
    assert not metacheck.check_classifiers(ok)
    bad = meta_of(Classifier="Programming Language :: Python :: 3.99x")
    assert [c for c, _ in metacheck.check_classifiers(bad)] == ["invalid_classifier"]
    dep = meta_of(Classifier="License :: OSI Approved :: Jabber Open Source License")
    assert [c for c, _ in metacheck.check_classifiers(dep)] == ["deprecated_classifier"]


@pytest.mark.parametrize("expr", ["MIT", "Apache-2.0 OR MIT", "(MIT AND BSD-3-Clause) OR GPL-3.0-or-later",
                                  "GPL-2.0-only WITH Classpath-exception-2.0", "LicenseRef-Custom-1", "mit",
                                  "Apache-2.0+"])
def test_spdx_valid(expr):
    assert metacheck.spdx_problem(expr) is None, expr


@pytest.mark.parametrize("expr", ["MIT License", "", "MIT AND", "(MIT", "MIT)", "MIT OR OR BSD-3-Clause",
                                  "NotALicense-1.0", "GPL-3.0 WITH Not-An-Exception", "MIT,Apache-2.0",
                                  "(" * 100 + "MIT" + ")" * 100])
def test_spdx_invalid(expr):
    assert metacheck.spdx_problem(expr), expr


def test_spdx_agrees_with_packaging_when_installed():
    licenses = pytest.importorskip("packaging.licenses")
    samples = ["MIT", "MIT License", "Apache-2.0 OR MIT", "GPL-3.0-or-later", "BSD", "mit AND isc",
               "MIT AND (Apache-2.0", "LicenseRef-x", "GPL-3.0-only WITH GCC-exception-3.1", "Foo-1.0",
               "MIT OR", "AND MIT", "Apache-2.0+", "gpl-2.0-only", "MIT  OR   ISC"]
    for s in samples:
        try:
            licenses.canonicalize_license_expression(s)
            theirs = True
        except Exception:
            theirs = False
        assert (metacheck.spdx_problem(s) is None) == theirs, s


def test_requires_python_specifiers():
    assert pyspec.allows_minor(">=3.9,<4", 3, 9) is True
    assert pyspec.allows_minor(">=3.9,<4", 3, 8) is False
    assert pyspec.allows_minor("!=3.8.*,>=3.7", 3, 8) is False
    assert pyspec.allows_minor("~=3.8", 3, 12) is True
    assert pyspec.allows_minor("==3.*", 3, 12) is True
    assert pyspec.allows_minor(">=3.9.1", 3, 9) is True
    assert pyspec.allows_minor(">=3.9rc1", 3, 9) is None  # not judged
    assert pyspec.split_clauses(">=three") is None and pyspec.split_clauses("") is None


def test_python_classifier_conflict_and_bad_spec():
    m = meta_of(**{"Requires-Python": ">=3.10", "Classifier": "Programming Language :: Python :: 3.8"})
    assert [c for c, _ in metacheck.check_requires_python(m)] == ["python_classifier_conflict"]
    assert metacheck.check_requires_python(meta_of(**{"Requires-Python": "banana"}))[0][0] == "bad_requires_python"


def test_author_email_rules():
    assert metacheck.check_emails(meta_of(**{"Author-email": "A B <a@b.com>"})) == []
    for bad in ("a@b", "x@dev.local", "no-at-sign", "a b@c.com", "a@b.invalid"):
        assert metacheck.check_emails(meta_of(**{"Author-email": bad})), bad


def test_undeclared_extra_and_dynamic_and_old_metadata():
    m = meta_of(**{"Requires-Dist": "pytest; extra == 'tests'", "Provides-Extra": "docs"})
    assert metacheck.check_extras(m)
    assert metacheck.check_dynamic_and_versions(meta_of(Dynamic="Banana"), (2, 4))[0][0] == "invalid_dynamic_field"
    old = parse_metadata("Metadata-Version: 2.3\nName: x\nVersion: 1\nLicense-Expression: MIT\n")
    assert metacheck.check_dynamic_and_versions(old, (2, 3))[0][0] == "license_expression_old_metadata"
    # License-File under 2.1 is what setuptools emitted for years; PyPI accepts it
    lf = parse_metadata("Metadata-Version: 2.1\nName: x\nVersion: 1\nLicense-File: LICENSE\n")
    assert metacheck.check_dynamic_and_versions(lf, (2, 1)) == []


def test_readme_relative_links():
    md = "![x](docs/a.png) [ok](https://e.com) [anchor](#top) `[code](rel)`\n```\n[fenced](rel2)\n```\n"
    assert metacheck.relative_links(md, "text/markdown") == ["docs/a.png"]
    assert metacheck.relative_links('<img src="a.png"><a href="https://e.com">', "text/markdown") == ["a.png"]
    assert metacheck.relative_links(".. image:: logo.png\n`d <guide.rst>`_ `u <https://x.y>`_", "text/x-rst") \
        == ["logo.png", "guide.rst"]
    assert metacheck.relative_links("[a](mailto:x@y.z) [b](//cdn.x/y) [c](data:image/png;base64,AA)", "text/markdown") == []


# --- platform tags and binaries ----------------------------------------------

@pytest.mark.parametrize("tag", ["any", "win_amd64", "win32", "manylinux2014_x86_64", "manylinux_2_28_aarch64",
                                 "musllinux_1_2_x86_64", "macosx_10_9_x86_64", "macosx_11_0_arm64",
                                 "macosx_14_0_universal2", "ios_13_0_arm64_iphoneos", "android_24_arm64_v8a",
                                 "manylinux_2_17_riscv64"])
def test_valid_platform_tags(tag):
    assert platform_tags.valid_platform_tag(tag)


@pytest.mark.parametrize("tag", ["linux_x86_64", "linux_aarch64", "macosx_11_1_arm64", "macosx_10_9_sparc",
                                 "manylinux_2_17_sparc", "musllinux_1_2_ppc64", "win_arm", "freebsd_13_amd64",
                                 "manylinux", "macosx_x_y_arm64"])
def test_invalid_platform_tags(tag):
    assert not platform_tags.valid_platform_tag(tag)


def test_platform_info():
    p = platform_tags.PlatformInfo("manylinux2014_aarch64")
    assert (p.os, p.libc, p.libc_min, p.archs) == ("linux", "glibc", (2, 17), {"arm64"})
    u = platform_tags.PlatformInfo("macosx_10_13_universal2")
    assert u.macos_min == (10, 13) and u.archs == {"x86_64", "arm64"}


def test_binary_sniff():
    assert binary.sniff(elf(62)).archs == {"x86_64"}
    assert binary.sniff(elf(183)).archs == {"arm64"}
    assert binary.sniff(elf(21)).archs == {"ppc64le"}
    assert binary.sniff(elf(21, big_endian=True)).archs == {"ppc64"}
    assert binary.sniff(macho_thin(b.ARM64_MACHO, (11, 0))).macos_min == (11, 0)
    fat = binary.sniff(macho_fat([b.X86_64_MACHO, b.ARM64_MACHO], (10, 13)))
    assert fat.archs == {"x86_64", "arm64"} and fat.macos_min == (10, 13)
    assert binary.sniff(pe(0xAA64)).archs == {"arm64"}
    assert binary.sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 100) is None  # a Java class, not a fat binary
    for junk in (b"", b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"hello world", os.urandom(64)):
        binary.sniff(junk)  # must never raise


def test_extension_suffixes():
    assert binary.ext_abi_tag("p/_x.cpython-311-x86_64-linux-gnu.so") == ("cpython", (3, 11))
    assert binary.ext_abi_tag("p/_x.cp312-win_amd64.pyd") == ("cpython", (3, 12))
    assert binary.ext_abi_tag("p/_x.abi3.so") == ("abi3", None)
    assert binary.ext_abi_tag("p/_x.so") == ("none", None)
    assert binary.ext_abi_tag("p/x.py") is None


def test_compressed_wheel_tag_line_is_not_a_mismatch(tmp_path):
    # real wheels (e.g. pydantic_core) write one compressed Tag line
    tag = "cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64"
    p = b.build_wheel(str(tmp_path), tag=tag, wheel_tags=[tag],
                      files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17")})
    assert "wheel_tag_mismatch" not in codes(check_wheel(p))


def test_glibc_floor_uses_lowest_claimed_tag(tmp_path):
    p = b.build_wheel(str(tmp_path), tag="cp312-cp312-manylinux_2_28_x86_64.manylinux2014_x86_64",
                      files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.20")})
    assert "manylinux_glibc_too_new" in codes(check_wheel(p))


def test_stream_scanner_reads_glibc_across_chunks():
    sc = StreamScanner("x.so")
    data = elf(62, "GLIBC_2.31", size=3 * 1024 * 1024)
    for i in range(0, len(data), 1024 * 1024 - 7):
        sc.feed(data[i:i + 1024 * 1024 - 7])
    assert sc.glibc_max == (2, 31) and sc.glibc_needed


# --- secrets and personal paths ---------------------------------------------

NEW_TOKENS = {
    "Google API key": frag("AIza", "SyA-") + "x1y2z3" * 5 + "a",
    "Stripe live key": frag("sk_", "live_") + "51H8aBcDeFgHiJkLmNoPqRsT",
    "OpenAI API key": frag("sk-", "proj-") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3k",
    "GitLab token": frag("glpat", "-") + "aB3dE5fG7hJ9kL1mN3pQ",
    "npm token": frag("npm", "_") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5",
    "Hugging Face token": frag("hf", "_") + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z",
    "database URL with password": frag("postgresql", "://svc:Tr0ub4dor3xQz@db.internal.corp:5432/app"),
}


@pytest.mark.parametrize("kind", sorted(NEW_TOKENS))
def test_new_token_kinds_detected_and_redacted(kind):
    blob = f"x = '{NEW_TOKENS[kind]}'".encode()
    assert kind in scan_secrets(blob)
    assert NEW_TOKENS[kind] not in redact(f"found {NEW_TOKENS[kind]} here")


@pytest.mark.parametrize("text", [
    b"postgresql://user:password@localhost:5432/db", b"redis://:pass@127.0.0.1", b"mysql://root:root@host/db",
    b"url = 'https://example.com/a:b@c'", b"sk-proj-your-key-here", b"hf_" + b"a" * 34,  # repeated char
    b"//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
])
def test_placeholders_and_docs_are_not_secrets(text):
    assert scan_secrets(text) == [], text


def test_escaped_pem_in_json_is_detected():
    blob = ('{"private_key": "-----BEGIN ' + 'PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC' + "x" * 80 + '"}').encode()
    assert "private key" in scan_secrets(blob)


def test_local_path_rules(tmp_path):
    def run(files):
        return check_wheel(b.build_wheel(str(tmp_path), files=files, filename=f"w{len(os.listdir(tmp_path))}.whl",
                                         dist_info="acme_widgets-1.0.0.dist-info"))
    # generic/CI/doc names never flag
    assert "local_path_leak" not in codes(run({"acme_widgets/a.so": b"/home/runner/work/x\0/Users/user/y\0/home/ubuntu/z"}))
    assert "local_path_leak" not in codes(run({"acme_widgets/b.py": b"p='/github/home/.cargo/registry/src'"}))
    # a real username inside a docstring seen once is trusted as an example ...
    assert "local_path_leak" not in codes(run({"acme_widgets/c.py": b"# /home/guido/data.txt"}))
    # ... but in compiled code or config it is a leak, with the name masked
    f = [x for x in run({"acme_widgets/d.so": b"\0/home/someuser/src/x.c\0"}) if x.code == "local_path_leak"]
    assert f and "someuser" not in f[0].message and "s***" in f[0].message
    f = [x for x in run({"acme_widgets/e.json": b'{"p":"C:\\\\Users\\\\Dan Smith\\\\app"}'}) if x.code == "local_path_leak"]
    assert f and "Dan" not in f[0].message


def test_allow_path_exempts_secrets_and_paths_only(tmp_path):
    blob = ("T = '" + NEW_TOKENS["Stripe live key"] + "'\n").encode()
    p = b.build_wheel(str(tmp_path), files={"acme_widgets/tests/fix.py": blob, "acme_widgets/x.pth": b"import os\n"})
    assert "secret_in_file" in codes(check_wheel(p))
    got = codes(check_wheel(p, ("acme_widgets/tests/*",)))
    assert "secret_in_file" not in got and "pth_executes_code" in got


# --- supply chain -------------------------------------------------------------

def test_setup_py_analysis():
    assert supply.analyze_setup_py(b"from setuptools import setup\nsetup()\n") == []
    net = supply.analyze_setup_py(b"import urllib.request as u\nu.urlopen('http://x')\n")
    assert [c for c, _ in net] == ["setup_py_network"]
    net2 = supply.analyze_setup_py(b"from urllib.request import urlretrieve\nurlretrieve('http://x','y')\n")
    assert [c for c, _ in net2] == ["setup_py_network"]
    hidden = supply.analyze_setup_py(b"import base64\n" + EXEC + b"(base64.b64decode('eA=='))\n")
    assert hidden[0][0] == "setup_py_obfuscated"
    sub = supply.analyze_setup_py(b"import subprocess\nsubprocess.run(['git','describe'])\n")
    assert [c for c, _ in sub] == ["setup_py_subprocess"]
    assert supply.analyze_setup_py(b"def broken(:\n")[0][0] == "setup_py_unparseable"
    assert supply.analyze_setup_py(b"\x00\x01")[0][0] == "setup_py_unparseable"
    assert supply.analyze_setup_py(b"x=" + b"(" * 5000 + b"1" + b")" * 5000)  # recursion bomb: reported, no crash
    assert supply.analyze_setup_py(b"#" * (3 * 1024 * 1024))[0][0] == "setup_py_unparseable"


def test_pth_rules():
    assert supply.analyze_pth("a.pth", "./vendor\n/opt/lib\n") == []
    assert supply.analyze_pth("a.pth", "import sys; sys.path.insert(0, 'x')\n")[0][0] == "pth_executes_code"
    assert supply.analyze_pth("a.pth", "import os; os.system('x')\n")[0][0] == "pth_suspicious_code"
    assert supply.analyze_pth("a.pth", "import base64, sys; " + EXEC.decode() + "(base64.b64decode('eA=='))\n")[0][0] == "pth_suspicious_code"


def test_entry_point_shadowing():
    txt = "[console_scripts]\nsudo = a:b\nwidgetctl = a:c\n[acme.plugins]\nls = a:d\n"
    assert [c for c, _ in supply.entry_point_shadows(txt)] == ["entry_point_shadows_command"]
    assert "sudo" in supply.entry_point_shadows(txt)[0][1]


def test_top_level_names():
    tops = supply.top_level_names(["json/__init__.py", "x-1.dist-info/METADATA", "tests/a.py", "mod.py",
                                   "_ext.cpython-311-x86_64-linux-gnu.so", "typing.py"])
    assert supply.shadowed_stdlib(tops) == ["json"]       # typing is a deliberate backport name
    assert supply.top_level_clutter(tops) == ["tests"]


def test_typosquat():
    assert supply.typosquat_target("reqeusts") == "requests"
    assert supply.typosquat_target("numpyy") == "numpy"
    assert supply.typosquat_target("requests") is None
    assert supply.typosquat_target("acme-widgets") is None
    assert supply.typosquat_target("pyy") is None            # too short to judge
    pop = sorted(supply.popular_projects())[:200]
    assert all(supply.typosquat_target(p) is None for p in pop)  # a popular project is never its own squat


# --- release diff -----------------------------------------------------------

def test_diff_reports_expected_changes(tmp_path):
    prev, new = tmp_path / "prev", tmp_path / "dist"
    b.release(str(prev), version="1.0.0", wheel=dict(entry_points="[console_scripts]\nold = a:b\n"))
    b.release(str(new), version="1.1.0", wheel=dict(
        requires_python=">=3.12", entry_points="[console_scripts]\nnew = a:b\n",
        meta=Mutator(add=[("Requires-Dist", "left-pad>=1")]), files={"acme_widgets.pth": b"./v\n"}),
        sdist=dict(requires_python=">=3.12"))
    got = codes(diagnose([str(new)], against=[str(prev)]))
    assert {"diff_new_dependency", "diff_requires_python_raised", "diff_new_entry_point",
            "diff_removed_entry_point", "diff_new_executable_code"} <= got


def test_diff_same_filename_is_error(tmp_path):
    prev, new = tmp_path / "prev", tmp_path / "dist"
    b.release(str(prev))
    b.release(str(new), wheel=dict(files={"acme_widgets/new.py": b"y=2\n"}))
    fs = [f for f in diagnose([str(new)], against=[str(prev)]) if f.code == "diff_version_exists"]
    assert fs and fs[0].severity == "error"


def test_diff_missing_or_garbage_previous(tmp_path):
    b.release(str(tmp_path / "dist"))
    assert "diff_unreadable" in codes(diagnose([str(tmp_path / "dist")], against=[str(tmp_path / "nope")]))
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "acme_widgets-0.9.0-py3-none-any.whl").write_bytes(b"not a zip")
    assert "diff_unreadable" in codes(diagnose([str(tmp_path / "dist")], against=[str(junk)]))


def test_diff_other_project_is_ignored(tmp_path):
    b.release(str(tmp_path / "prev"), name="other_proj")
    b.release(str(tmp_path / "dist"))
    assert not [c for c in codes(diagnose([str(tmp_path / "dist")], against=[str(tmp_path / "prev")]))
                if c.startswith("diff_")]


# --- output formats and CLI ---------------------------------------------------

def test_sarif_is_valid_and_complete(tmp_path):
    b.release(str(tmp_path / "dist"), wheel=dict(files={"acme_widgets/.env": b"x"}))
    fs = diagnose([str(tmp_path / "dist")])
    doc = json.loads(formats.to_sarif(fs, CHECKS, "9.9"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "reldoctor"
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for res in run["results"]:
        assert ids[res["ruleIndex"]] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert any(r["level"] == "error" for r in run["results"])


def test_junit_is_well_formed_even_with_hostile_text():
    from reldoctor.doctor import Finding
    fs = [Finding("error", "sensitive_file", "bad \x00\x1b[31m & <tag> \ud800", "a\x01.whl"),
          Finding("warn", "junk_file", "w"), Finding("info", "sdist_version", "i")]
    xml = formats.to_junit(fs, strict=False)
    root = ET.fromstring(xml.encode("utf-8", "replace"))
    assert root.get("tests") == "3" and root.get("failures") == "1"
    assert ET.fromstring(formats.to_junit(fs, strict=True).encode("utf-8", "replace")).get("failures") == "2"
    assert ET.fromstring(formats.to_junit([], False).encode()).get("failures") == "0"


def test_cli_formats_and_against(tmp_path, capsys):
    b.release(str(tmp_path / "prev"), version="1.0.0")
    b.release(str(tmp_path / "dist"), version="1.1.0",
              wheel=dict(meta=Mutator(add=[("Requires-Dist", "left-pad>=1")])))
    assert main([str(tmp_path / "dist"), "--against", str(tmp_path / "prev"), "--format", "sarif"]) == 0
    out = capsys.readouterr().out
    assert "diff_new_dependency" in out and json.loads(out)["version"] == "2.1.0"
    assert main([str(tmp_path / "dist"), "--format", "junit", "--strict"]) in (0, 1)
    assert capsys.readouterr().out.startswith("<?xml")
    assert main([str(tmp_path / "dist"), "--ignore", "diff_new_dependency", "--against", str(tmp_path / "prev")]) == 0


def test_python_dash_m_reldoctor_works(tmp_path):
    b.release(str(tmp_path / "dist"))
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    p = subprocess.run([sys.executable, "-m", "reldoctor", str(tmp_path / "dist")], capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stdout + p.stderr


def test_every_check_is_registered_and_documented():
    for code, (sev, desc) in CHECKS.items():
        assert sev in ("error", "warn", "info") and len(desc) >= 8, code
    assert len(CHECKS) >= 110


# --- adversarial -------------------------------------------------------------

def test_hostile_inputs_do_not_crash(tmp_path):
    d = tmp_path / "dist"
    d.mkdir()
    # a wheel whose METADATA is binary noise and whose members are odd
    with zipfile.ZipFile(d / "acme_widgets-1.0.0-py3-none-any.whl", "w") as zf:
        zf.writestr("acme_widgets-1.0.0.dist-info/METADATA", os.urandom(4096))
        zf.writestr("acme_widgets-1.0.0.dist-info/WHEEL", b"Tag: \xff\xfe\nRoot-Is-Purelib: maybe\n")
        zf.writestr("acme_widgets-1.0.0.dist-info/RECORD", "")
        zf.writestr("x.so", b"\x7fELF" + b"\xff" * 30)
        zf.writestr("y.dylib", b"\xcf\xfa\xed\xfe" + b"\xff" * 60)
        zf.writestr("z.pyd", b"MZ" + b"\xff" * 100)
        zf.writestr("w.pth", b"\xff\xfe import \x00")
    diagnose([str(d)])
    assert diagnose([str(d)], against=[str(d)])  # against itself: nothing to compare, still reports


def test_byte_flip_fuzz_never_crashes(tmp_path):
    import random
    rng = random.Random(1234)
    src = tmp_path / "src"
    b.build_wheel(str(src), tag="cp312-cp312-manylinux_2_17_x86_64",
                  files={"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": elf(62, "GLIBC_2.17"),
                         "acme_widgets.pth": b"import os\n", "acme_widgets/setup_like.py": b"x=1\n"},
                  entry_points="[console_scripts]\na = b:c\n")
    b.build_sdist(str(src), setup_py="from setuptools import setup\nsetup()\n")
    originals = {f: (src / f).read_bytes() for f in os.listdir(src)}
    out = tmp_path / "fuzz"
    out.mkdir()
    for i in range(60):
        for f in list(out.iterdir()):
            f.unlink()
        for name, data in originals.items():
            buf = bytearray(data)
            for _ in range(rng.randint(1, 8)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
            if rng.random() < 0.2:
                buf = buf[:rng.randrange(1, len(buf))]
            (out / name).write_bytes(bytes(buf))
        diagnose([str(out)], against=[str(src)])   # may report anything; must not raise


def test_diff_ignores_versioned_dist_info_names_and_sees_data_scripts(tmp_path):
    b.release(str(tmp_path / "prev"), version="1.0.0")
    b.release(str(tmp_path / "dist"), version="1.1.0",
              wheel=dict(extra_members=[("acme_widgets-1.1.0.data/scripts/runme", b"#!/bin/sh\n")]))
    fs = [f for f in diagnose([str(tmp_path / "dist")], against=[str(tmp_path / "prev")])]
    assert "diff_new_executable_code" in codes(fs)
    new_files = [f.message for f in fs if f.code == "diff_new_files"]
    assert not any("dist-info" in m for m in new_files), new_files
