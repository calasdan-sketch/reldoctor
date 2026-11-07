"""Round 4: what a stranger who installs the package actually gets."""
import io
import json
import os
import re
import sys
import warnings

import pytest

from reldoctor import __version__, wheelcheck
from reldoctor import cli as cli_mod
from reldoctor.cli import expand_globs, main
from tests.test_doctor import make_sdist, make_wheel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


# --- release consistency: the same facts everywhere ---------------------------------

def test_version_is_the_same_everywhere():
    py = _read("pyproject.toml")
    assert re.search(r'^version = "%s"$' % re.escape(__version__), py, re.M)
    top = re.search(r"^## (\d+\.\d+\.\d+)", _read("CHANGELOG.md"), re.M).group(1)
    assert top == __version__


def test_author_and_license_agree():
    py = _read("pyproject.toml")
    assert 'authors = [{ name = "Calas Automations Inc." }]' in py
    assert "Calas Automations Inc." in _read("LICENSE")
    assert 'license = "MIT"' in py and _read("LICENSE").startswith("MIT License")


def test_urls_point_at_the_one_repository():
    py = _read("pyproject.toml")
    urls = set(re.findall(r"https://github\.com/[\w.-]+/[\w.-]+", py))
    assert urls == {"https://github.com/calasdan-sketch/reldoctor"}
    for key in ("Homepage", "Issues", "Source", "Changelog"):
        assert re.search(r"^%s = " % key, py, re.M)


def test_pyproject_classifiers_are_valid_and_typed_marker_ships():
    from reldoctor import metacheck
    py = _read("pyproject.toml")
    block = re.search(r"classifiers = \[(.*?)\]", py, re.S).group(1)
    found = re.findall(r'"([^"]+)"', block)
    valid, deprecated, _hdr = metacheck._trove()
    assert [c for c in found if c not in valid] == []
    assert [c for c in found if c in deprecated] == []
    assert "Typing :: Typed" in found
    assert os.path.isfile(os.path.join(ROOT, "src", "reldoctor", "py.typed"))
    assert "py.typed" in py


def test_python_classifiers_cover_requires_python_floor():
    py = _read("pyproject.toml")
    assert 'requires-python = ">=3.9"' in py
    assert "Programming Language :: Python :: 3.9" in py


def test_manifest_ships_changelog_and_the_files_tests_import():
    m = _read("MANIFEST.in")
    for want in ("CHANGELOG.md", "graft tests", "graft bench"):
        assert want in m


# --- readme_renderer without its Markdown extra must stay silent ---------------------

def test_missing_markdown_extra_is_not_a_finding(monkeypatch):
    import types
    fake = types.ModuleType("readme_renderer.markdown")
    fake.variants = {}                 # what readme_renderer >= 44 has without `readme_renderer[md]`

    def render(raw, **kw):
        warnings.warn("Markdown renderers are not available.")
        return None
    fake.render = render
    pkg = types.ModuleType("readme_renderer")
    monkeypatch.setitem(sys.modules, "readme_renderer", pkg)
    monkeypatch.setitem(sys.modules, "readme_renderer.markdown", fake)
    pkg.markdown = fake
    import email.message
    meta = email.message.Message()
    meta["Description-Content-Type"] = "text/markdown"
    with warnings.catch_warnings():
        warnings.simplefilter("error")   # no UserWarning may leak to the user's terminal either
        assert wheelcheck.render_problem(meta, "# hello\n") is None


# --- command line: Windows shells do not expand wildcards ----------------------------

def test_wildcards_are_expanded_when_the_shell_did_not(tmp_path, capsys):
    make_wheel(tmp_path)
    make_sdist(tmp_path)
    pattern = os.path.join(str(tmp_path), "*.whl")
    assert expand_globs([pattern]) == [os.path.join(str(tmp_path), "demo-1.0.0-py3-none-any.whl")]
    assert main([pattern, "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["checked"] == ["demo-1.0.0-py3-none-any.whl"]


def test_existing_name_with_brackets_is_not_a_pattern(tmp_path):
    odd = tmp_path / "a[1]"
    odd.mkdir()
    assert expand_globs([str(odd)]) == [str(odd)]


def test_pattern_with_no_match_is_reported_not_ignored(tmp_path, capsys):
    assert main([os.path.join(str(tmp_path), "*.whl")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_text_report_names_the_files_it_checked(tmp_path, capsys):
    make_wheel(tmp_path)
    make_sdist(tmp_path)
    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "checked 2 file(s): demo-1.0.0-py3-none-any.whl, demo-1.0.0.tar.gz" in out
    assert out.rstrip().endswith("PASS")


@pytest.mark.parametrize("n", ["0", "-2"])
def test_jobs_below_one_is_a_usage_error(tmp_path, capsys, n):
    make_wheel(tmp_path)
    assert main([str(tmp_path), "--jobs", n]) == 2
    assert "--jobs must be at least 1" in capsys.readouterr().err


def test_settings_file_with_byte_order_mark(tmp_path, capsys, monkeypatch):
    (tmp_path / "dist").mkdir()
    make_wheel(tmp_path / "dist")
    (tmp_path / "pyproject.toml").write_bytes(b"\xef\xbb\xbf[tool.reldoctor]\r\nstrict = true\r\n")
    monkeypatch.chdir(tmp_path)
    # a wheel with no sdist is a warning; strict from the BOM'd file makes it fail
    assert main(["dist"]) == 1
    assert "using [tool.reldoctor]" in capsys.readouterr().err


def test_backslash_allow_path_works_like_slash(tmp_path, capsys):
    key = "-----BEGIN RSA PRIVATE KEY-----\n" + ("A" * 64 + "\n") * 6 + "-----END RSA PRIVATE KEY-----\n"
    make_wheel(tmp_path, extra_files={"demo/certs/test.pem": key})
    make_sdist(tmp_path)
    assert main([str(tmp_path), "--format", "json"]) == 1
    capsys.readouterr()
    assert main([str(tmp_path), "--allow-path", "demo\\certs\\*", "--format", "json"]) == 0


def test_formats_module_is_not_imported_for_plain_text(tmp_path):
    import subprocess
    make_wheel(tmp_path)
    make_sdist(tmp_path)
    code = ("import sys; from reldoctor.cli import main; "
            f"main([{str(tmp_path)!r}]); print('F' if 'reldoctor.formats' in sys.modules else 'N')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src")))
    assert r.stdout.strip().endswith("N"), r.stdout + r.stderr


def test_crlf_text_members_are_read(tmp_path):
    """Wheels built on Windows can carry CRLF line ends in METADATA, WHEEL and RECORD."""
    import base64
    import hashlib
    import zipfile
    from reldoctor import diagnose
    w = make_wheel(tmp_path)
    make_sdist(tmp_path)
    with zipfile.ZipFile(w) as z:
        items = {n: z.read(n) for n in z.namelist()}
    out = {n: (b.replace(b"\n", b"\r\n") if n.endswith(("METADATA", "WHEEL")) else b) for n, b in items.items()}
    rec = next(n for n in out if n.endswith("RECORD"))
    rows = [f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode()},{len(b)}"
            for n, b in out.items() if n != rec] + [f"{rec},,"]
    out[rec] = ("\r\n".join(rows) + "\r\n").encode()
    with zipfile.ZipFile(w, "w") as z:
        for n, b in out.items():
            z.writestr(n, b)
    assert [f for f in diagnose([str(tmp_path)]) if f.severity != "info"] == []


def test_secret_prefilter_agrees_with_full_scan():
    from reldoctor import safety
    pre = "gh" + "p_"
    token = pre + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    assert safety.scan_secrets(("x = '%s'\n" % token).encode()) != []
    assert safety.scan_secrets(b"nothing to see here\n" * 100) == []


@pytest.mark.parametrize("fmt", ["junit", "markdown", "github", "json"])
def test_machine_formats_are_utf8_even_on_a_cp1252_console(tmp_path, fmt):
    """Windows redirects use the legacy code page; the XML says UTF-8, so the bytes must be."""
    import subprocess
    make_wheel(tmp_path, extra_files={"démo/.env": "A=1\n"})
    make_sdist(tmp_path)
    r = subprocess.run([sys.executable, "-m", "reldoctor", str(tmp_path), "--format", fmt, "--no-config"],
                       capture_output=True, env=dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"),
                                                     PYTHONIOENCODING="cp1252", PYTHONUTF8="0"))
    assert r.returncode == 1, r.stderr
    text = r.stdout.decode("utf-8")        # must not raise: valid UTF-8
    assert "�" not in text
    if fmt != "json":                      # json escapes non-ASCII itself
        assert "démo" in text


def test_readme_demo_release_reproduces(tmp_path, capsys):
    """The sample output in the README comes from `python -m bench.demo`; keep it true."""
    from bench import demo
    assert demo.main(str(tmp_path)) == 0
    capsys.readouterr()
    assert main([str(tmp_path / "dist"), "--against", str(tmp_path / "prev"), "--no-config", "--format", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert (out["errors"], out["warnings"]) == (4, 2)
    assert {f["code"] for f in out["findings"]} >= {"invalid_classifier", "secret_in_file", "binary_arch_mismatch",
                                                    "manylinux_glibc_too_new", "local_path_leak", "readme_relative_links"}
    assert len(out["checked"]) == 2


def test_the_repository_does_not_trip_its_own_secret_scanner():
    """Everything MANIFEST.in puts into the sdist must pass reldoctor's own leak scan (fake keys are built at runtime)."""
    from reldoctor import safety
    hits = {}
    for top in ("src", "bench", "tests", "tools"):
        for dirpath, dirs, files in os.walk(os.path.join(ROOT, top)):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "reldoctor.egg-info")]
            for fn in files:
                if fn.endswith(".pyc"):
                    continue
                path = os.path.join(dirpath, fn)
                with open(path, "rb") as fh:
                    kinds = safety.scan_secrets(fh.read())
                if kinds:
                    hits[os.path.relpath(path, ROOT)] = kinds
    for fn in ("README.md", "CHANGELOG.md", "PUBLISH-CHECKLIST.md"):
        with open(os.path.join(ROOT, fn), "rb") as fh:
            kinds = safety.scan_secrets(fh.read())
        if kinds:
            hits[fn] = kinds
    assert hits == {}
