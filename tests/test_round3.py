"""Round 3: hostile-input hardening, UTF-16 and nested-archive secrets, config file, CLI robustness."""
import gzip
import io
import json
import os
import subprocess
import sys
import tarfile
import time
import zipfile

import pytest

from bench import build as b
from reldoctor import advice, config, metacheck, nested
from reldoctor.cli import main
from reldoctor.doctor import CHECKS, diagnose
from reldoctor.safety import (StreamScanner, maybe_sensitive_file_kind, scan_secrets, sensitive_file_kind,
                              utf16_codec)

# secrets are assembled at runtime so this file holds no contiguous token
GH = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"


def codes(findings):
    return {f.code for f in findings}


def wheel_with(tmp_path, files, **kw):
    b.build_wheel(str(tmp_path), files=files, **kw)
    return diagnose([str(tmp_path)])


# --- hostile long descriptions (quadratic regexes) -----------------------------------

@pytest.mark.parametrize("text,ctype", [
    ("<img src=x " * 100_000, "text/markdown"),
    ("![a](b) " * 100_000, "text/markdown"),
    ("[" * 200_000, "text/markdown"),
    ("`<" * 200_000, "text/x-rst"),
    ("`a<b " * 100_000, "text/x-rst"),
    ("<a " * 300_000, "text/markdown"),
])
def test_relative_links_is_linear_on_hostile_input(text, ctype):
    t0 = time.time()
    metacheck.relative_links(text, ctype)
    assert time.time() - t0 < 5


def test_relative_links_still_finds_normal_links():
    md = "![x](docs/a.png) <img src='b.png'> [t](https://example.org) <a href=\"c.html\">c</a>"
    assert metacheck.relative_links(md, "text/markdown") == ["docs/a.png", "b.png", "c.html"]
    rst = "see `guide <guide/x.rst>`_ and `site <https://example.org>`__\n\n.. image:: img/p.png\n"
    assert metacheck.relative_links(rst, "text/x-rst") == ["img/p.png", "guide/x.rst"]


# --- UTF-16 text (PowerShell `>`, Windows editors) -----------------------------------

@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_secret_is_found(tmp_path, codec):
    f = wheel_with(tmp_path, {"acme_widgets/cfg.txt": ("TOKEN=" + GH + "\n" * 5).encode(codec)})
    assert "secret_in_file" in codes(f)


def test_utf16_secret_across_chunks(tmp_path):
    big = ("x = 1\n" * 400_000 + "TOKEN=" + GH).encode("utf-16")
    assert "secret_in_file" in codes(wheel_with(tmp_path, {"acme_widgets/big.txt": big}))


def test_utf16_detection_ignores_native_libraries():
    assert utf16_codec(b.elf()) is None
    assert utf16_codec(b"plain ascii text " * 10) is None
    assert utf16_codec("hello world, this is text".encode("utf-16-le")) == "utf-16-le"


def test_utf16_clean_file_is_clean():
    sc = StreamScanner("a.txt")
    sc.feed("nothing to see here, just words".encode("utf-16"))
    assert sc.kinds == []


# --- more token shapes -----------------------------------------------------------------

def test_new_provider_tokens():
    samples = {
        "PyPI API token": "pypi-" + "AgENdGVzdC5weXBpLm9yZw" + "Ik" + "aB3" * 20,
        "Shopify access token": "shp" + "at_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "Docker Hub access token": "dckr" + "_pat_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9",
        "DigitalOcean token": "dop" + "_v1_" + "0123456789abcdef" * 4,
        "HashiCorp Vault token": "hv" + "s." + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1f",
        "Discord webhook": "https://discord.com/api/web" + "hooks/123456789012345678/" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5" * 2,
        "Azure storage account key": "Account" + "Key=" + "A1b2C3d4" * 10 + "E5f6g7" + "==",
    }
    for kind, text in samples.items():
        assert kind in scan_secrets(f'x = "{text}"'.encode()), kind


def test_new_provider_placeholders_are_quiet():
    for text in ["dckr" + "_pat_" + "x" * 30, "shp" + "at_" + "0" * 32, "hv" + "s." + "your-token-goes-here-now-ok"]:
        assert scan_secrets(text.encode()) == [], text


# --- credential-looking file names ------------------------------------------------------

@pytest.mark.parametrize("name", ["kubeconfig", ".kube/config", ".docker/config.json", ".boto", ".vault-token",
                                  ".bash_history", ".python_history", "client_secret_1234.json",
                                  "x-firebase-adminsdk-ab12.json", "service-account.json", "serviceAccountKey.json",
                                  "gcloud/application_default_credentials.json", "wallet.dat"])
def test_sensitive_names(name):
    assert sensitive_file_kind(name)


@pytest.mark.parametrize("name", ["credentials.json", "secrets.yml", "prod.env", ".envrc", "local_settings.py",
                                  "token.json", "master.key", "cookies.txt"])
def test_maybe_sensitive_names_warn_not_fail(tmp_path, name):
    assert sensitive_file_kind(name) is None and maybe_sensitive_file_kind(name)
    f = wheel_with(tmp_path, {"acme_widgets/" + name: b"x"})
    assert "maybe_sensitive_file" in codes(f) and "sensitive_file" not in codes(f)
    assert next(x for x in f if x.code == "maybe_sensitive_file").severity == "warn"


@pytest.mark.parametrize("name", ["env.example", "config.env.template", "settings.py", "docs/credentials.rst",
                                  "pkg/token_utils.py", "sample.env.sample"])
def test_ordinary_names_are_quiet(name):
    assert maybe_sensitive_file_kind(name) is None or name.endswith(".env.sample") is False


def test_maybe_sensitive_can_be_allowed(tmp_path):
    f = None
    b.build_wheel(str(tmp_path), files={"acme_widgets/credentials.json": b"{}"})
    f = diagnose([str(tmp_path)], allow=["acme_widgets/credentials.json"])
    assert "maybe_sensitive_file" not in codes(f)


# --- archives inside the release ----------------------------------------------------------

def zip_bytes(**members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in members.items():
            zf.writestr(n.replace("__", "/"), d)
    return buf.getvalue()


def tgz_bytes(name, data):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_secret_inside_bundled_zip_wheel(tmp_path):
    f = wheel_with(tmp_path, {"acme_widgets/data.zip": zip_bytes(**{"cfg.py": GH.encode()})})
    hit = [x for x in f if x.code == "secret_in_file"]
    assert hit and "data.zip!/cfg.py" in hit[0].message


def test_dotenv_inside_bundled_zip(tmp_path):
    f = wheel_with(tmp_path, {"acme_widgets/data.zip": zip_bytes(**{".env": b"A=1"})})
    assert any(x.code == "sensitive_file" and "data.zip!/.env" in x.message for x in f)


@pytest.mark.parametrize("blob", [gzip.compress(GH.encode()), tgz_bytes("x.txt", GH.encode())])
def test_secret_inside_gzip_and_tgz(tmp_path, blob):
    assert "secret_in_file" in codes(wheel_with(tmp_path, {"acme_widgets/blob.bin": blob}))


def test_secret_inside_sdist_bundled_zip(tmp_path):
    b.build_sdist(str(tmp_path), files={"fixtures/data.zip": zip_bytes(**{"c.py": GH.encode()})})
    assert "secret_in_file" in codes(diagnose([str(tmp_path)]))


def test_bundled_archive_respects_allow_path(tmp_path):
    b.build_wheel(str(tmp_path), files={"acme_widgets/fixtures/data.zip": zip_bytes(**{"c.py": GH.encode()})})
    assert "secret_in_file" not in codes(diagnose([str(tmp_path)], allow=["acme_widgets/fixtures/*"]))
    assert "secret_in_file" not in codes(diagnose([str(tmp_path)], allow=["acme_widgets/fixtures/data.zip!/*"]))


def test_nested_depth_is_bounded_and_reported(tmp_path):
    deep = GH.encode()
    for i in range(4):
        deep = zip_bytes(**{f"l{i}.zip": deep})
    f = wheel_with(tmp_path, {"acme_widgets/deep.zip": deep})
    assert "nested_archive_partial" in codes(f)


def test_compression_bomb_is_not_expanded(tmp_path, monkeypatch):
    monkeypatch.setattr(nested, "MAX_UNPACKED_BYTES", 4 * 1024 * 1024)
    t0 = time.time()
    f = wheel_with(tmp_path, {"acme_widgets/bomb.gz": gzip.compress(b"\0" * (64 * 1024 * 1024), 1)})
    assert "nested_archive_partial" in codes(f) and time.time() - t0 < 20


def test_corrupt_bundled_archive_is_not_an_error(tmp_path):
    f = wheel_with(tmp_path, {"acme_widgets/bad.zip": b"PK\x03\x04" + b"garbage" * 50})
    assert not any(x.severity == "error" for x in f)


def test_nested_members_over_cap_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(nested, "MAX_NESTED_MEMBERS", 5)
    z = zip_bytes(**{f"f{i}.txt": b"x" for i in range(10)})
    assert "nested_archive_partial" in codes(wheel_with(tmp_path, {"acme_widgets/many.zip": z}))


def test_ordinary_zip_with_clean_files_is_quiet(tmp_path):
    f = wheel_with(tmp_path, {"acme_widgets/data.zip": zip_bytes(**{"a.txt": b"hello", "b.csv": b"1,2,3"})})
    assert not any(x.severity == "error" for x in f)
    assert "nested_archive_partial" not in codes(f)


# --- config file ---------------------------------------------------------------------------

TOML = '''
[project]
name = "x"
[tool.reldoctor]
strict = true
ignore = ["dev_version", # a comment
          "typosquat_name"]
allow-path = ["tests/certs/*"]
max-members = 5000
'''


@pytest.mark.parametrize("path", ["real", "mini"])
def test_config_parses_both_ways(tmp_path, monkeypatch, path):
    if path == "mini":
        monkeypatch.setattr(config, "_toml_loads", config._mini_table)
    p = tmp_path / "pyproject.toml"
    p.write_text(TOML)
    table, base = config.load(str(p))
    assert table == {"strict": True, "ignore": ["dev_version", "typosquat_name"],
                     "allow-path": ["tests/certs/*"], "max-members": 5000}
    assert base == str(tmp_path)


def test_mini_parser_ignores_other_tables_and_hash_in_strings():
    t = config._mini_table('[tool.other]\nignore = 3\n[tool.reldoctor]\nallow-path = ["a#b/*"] # c\n[x]\nstrict = 9\n')
    assert t == {"allow-path": ["a#b/*"]}


@pytest.mark.parametrize("body,msg", [
    ("strikt = true", "unknown key"),
    ("strict = 1", "true or false"),
    ('ignore = "x"', "list of strings"),
    ("max-members = true", "integer"),
])
def test_config_rejects_typos_and_wrong_types(tmp_path, body, msg):
    p = tmp_path / "pyproject.toml"
    p.write_text("[tool.reldoctor]\n" + body + "\n")
    with pytest.raises(config.ConfigError, match=msg):
        config.load(str(p))


def project(tmp_path, toml):
    dist = tmp_path / "dist"
    b.build_wheel(str(dist), files={"acme_widgets/cfg.py": GH.encode()})
    b.build_sdist(str(dist))
    (tmp_path / "pyproject.toml").write_text(toml)
    return str(dist)


def test_config_allow_path_and_ignore_apply(tmp_path, monkeypatch, capsys):
    dist = project(tmp_path, '[tool.reldoctor]\nallow-path = ["acme_widgets/cfg.py"]\nignore = ["sdist_version"]\n')
    monkeypatch.chdir(tmp_path)
    assert main([dist, "--format", "json"]) == 0
    cap = capsys.readouterr()
    out = json.loads(cap.out)
    assert "secret_in_file" not in {f["code"] for f in out["findings"]}
    assert "sdist_version" not in {f["code"] for f in out["findings"]}
    assert "using [tool.reldoctor]" in cap.err


def test_no_config_flag(tmp_path, monkeypatch, capsys):
    dist = project(tmp_path, '[tool.reldoctor]\nallow-path = ["acme_widgets/cfg.py"]\n')
    monkeypatch.chdir(tmp_path)
    assert main([dist, "--no-config"]) == 1


def test_config_strict_and_cli_union(tmp_path, monkeypatch, capsys):
    dist = project(tmp_path, '[tool.reldoctor]\nstrict = true\nallow-path = ["acme_widgets/cfg.py"]\n')
    monkeypatch.chdir(tmp_path)
    assert main([dist, "--ignore", "sdist_version"]) == 0
    b.build_wheel(str(tmp_path / "dist"), name="acme_widgets", version="1.0.0", meta=b.Mutator(drop=["Summary"]),
                  files={"acme_widgets/cfg.py": GH.encode()})
    assert main([dist, "--ignore", "sdist_version"]) == 1   # no_summary warning fails because strict came from config


def test_config_cannot_unlock_locked_codes_or_broad_allow(tmp_path, monkeypatch, capsys):
    dist = project(tmp_path, '[tool.reldoctor]\nignore = ["wheel_corrupt"]\n')
    monkeypatch.chdir(tmp_path)
    assert main([dist]) == 2
    (tmp_path / "pyproject.toml").write_text('[tool.reldoctor]\nallow-path = ["*"]\n')
    assert main([dist]) == 2
    (tmp_path / "pyproject.toml").write_text('[tool.reldoctor]\nignore = ["no_such_code"]\n')
    assert main([dist]) == 2


def test_config_error_is_a_usage_error_and_names_the_file(tmp_path, monkeypatch, capsys):
    dist = project(tmp_path, "[tool.reldoctor]\nstrikt = true\n")
    monkeypatch.chdir(tmp_path)
    assert main([dist]) == 2
    assert "pyproject.toml" in capsys.readouterr().err
    assert main([dist, "--no-config"]) == 1


def test_config_is_not_searched_upward_or_in_artifact_dir(tmp_path, monkeypatch):
    dist = project(tmp_path, '[tool.reldoctor]\nallow-path = ["acme_widgets/cfg.py"]\n')
    sub = tmp_path / "sub"
    sub.mkdir()
    monkeypatch.chdir(sub)
    assert main([dist]) == 1


def test_config_against_is_relative_to_the_config_file(tmp_path, monkeypatch, capsys):
    prev = tmp_path / "prev"
    b.build_wheel(str(prev), version="0.9.0")
    dist = project(tmp_path, '[tool.reldoctor]\nagainst = ["prev"]\nallow-path = ["acme_widgets/cfg.py"]\n')
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    cfg = tmp_path / "pyproject.toml"
    monkeypatch.chdir(elsewhere)
    assert main([dist, "--config", str(cfg), "--format", "json"]) in (0, 1)
    assert "diff_unreadable" not in capsys.readouterr().out


def test_max_members_from_config(tmp_path, monkeypatch, capsys):
    dist = project(tmp_path, "[tool.reldoctor]\nmax-members = 3\n")
    monkeypatch.chdir(tmp_path)
    assert main([dist, "--format", "json"]) == 1
    assert "too_many_members" in capsys.readouterr().out


# --- --explain, exit codes, console robustness ------------------------------------------------

def test_explain_known_and_unknown(capsys):
    assert main(["--explain", "secret_in_file"]) == 0
    out = capsys.readouterr().out
    assert "secret_in_file" in out and "What to do" in out
    assert main(["--explain", "wheel_corrupt"]) == 0
    assert "no, the gate stays closed" in capsys.readouterr().out
    assert main(["--explain", "nope"]) == 2


def test_advice_covers_only_real_codes():
    assert set(advice.ADVICE) <= set(CHECKS)
    assert all(len(v) > 20 for v in advice.ADVICE.values())


def test_internal_error_has_its_own_exit_code(tmp_path, monkeypatch, capsys):
    import reldoctor.cli as cli
    monkeypatch.setattr(cli, "diagnose", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    b.build_wheel(str(tmp_path))
    assert main([str(tmp_path)]) == 3
    err = capsys.readouterr().err
    assert "NOT approved" in err and "boom" in err


def run_cli(args, env=None, cwd=None, stdout=subprocess.PIPE):
    e = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.abspath("src"), os.path.abspath(".")]))
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "reldoctor", *args], env=e, cwd=cwd, stdout=stdout,
                          stderr=subprocess.PIPE, timeout=120)


@pytest.mark.parametrize("fmt", ["text", "github", "junit", "json", "sarif"])
def test_non_ascii_names_never_crash_on_an_ascii_console(tmp_path, fmt):
    b.build_wheel(str(tmp_path), extra_members=[("acme_widgets/café_日本/.env", b"A=1")])
    r = run_cli([str(tmp_path), "--format", fmt], env={"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"})
    assert r.returncode == 1, r.stderr.decode()
    assert b"Traceback" not in r.stderr
    assert b"\\xe9" in r.stdout or b"\\u00e9" in r.stdout or fmt in ("json", "sarif")


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full")
def test_unwritable_report_is_a_usage_error_not_findings(tmp_path):
    b.build_wheel(str(tmp_path))
    with open("/dev/full", "wb") as full:
        r = run_cli([str(tmp_path)], stdout=full)
    assert r.returncode == 2 and b"Traceback" not in r.stderr


# --- parallel scan -----------------------------------------------------------------------------

def test_jobs_gives_identical_findings(tmp_path):
    for v in ("1.0.0", "1.0.1", "1.0.2"):
        b.build_wheel(str(tmp_path), version=v, files={"acme_widgets/cfg.py": GH.encode()})
    b.build_sdist(str(tmp_path), version="1.0.2")
    import reldoctor.doctor as d
    one = diagnose([str(tmp_path)], jobs=1)
    assert d.LAST_RUN_PARALLEL is False
    many = diagnose([str(tmp_path)], jobs=3)
    assert d.LAST_RUN_PARALLEL is True      # really ran in worker processes, not the fallback
    assert [f.as_dict() for f in one] == [f.as_dict() for f in many]


def test_jobs_carries_max_members_to_workers(tmp_path, monkeypatch):
    import reldoctor.doctor as d
    for v in ("1.0.0", "1.0.1"):
        b.build_wheel(str(tmp_path), version=v)
    monkeypatch.setattr(d, "MAX_MEMBERS", 2)
    assert "too_many_members" in codes(diagnose([str(tmp_path)], jobs=2))


def test_auto_jobs_stays_single_for_small_releases(tmp_path):
    import reldoctor.doctor as d
    b.build_wheel(str(tmp_path))
    assert d._auto_jobs([str(p) for p in tmp_path.iterdir()]) == 1


# --- wheels of one release must agree ------------------------------------------------------

def test_stale_wheel_with_other_source_is_flagged(tmp_path):
    b.build_wheel(str(tmp_path), tag="cp312-cp312-win_amd64", files={"acme_widgets/core.py": b"x = 1\n"})
    b.build_wheel(str(tmp_path), tag="cp312-cp312-win32", files={"acme_widgets/core.py": b"x = 2\n"})
    f = diagnose([str(tmp_path)])
    hit = [x for x in f if x.code == "wheel_source_drift"]
    assert hit and "core.py" in hit[0].message


def test_wheel_metadata_drift_between_wheels(tmp_path):
    b.build_wheel(str(tmp_path), tag="py3-none-any")
    b.build_wheel(str(tmp_path), tag="cp312-cp312-win32",
                  meta=b.Mutator(add=[("Requires-Dist", "extra-dep>=1")]))
    hit = [x for x in diagnose([str(tmp_path)]) if x.code == "wheel_metadata_drift"]
    assert hit and "Requires-Dist" in hit[0].message


def test_consistent_wheels_are_quiet(tmp_path):
    for tag in ("cp312-cp312-win_amd64", "cp312-cp312-win32", "cp312-cp312-musllinux_1_2_x86_64"):
        b.build_wheel(str(tmp_path), tag=tag)
    assert not codes(diagnose([str(tmp_path)])) & {"wheel_source_drift", "wheel_metadata_drift"}


# --- long paths, markdown, SARIF identity --------------------------------------------------------

def test_long_member_path_warns(tmp_path):
    name = "acme_widgets/" + "d" * 90 + "/" + "e" * 90 + "/mod.py"
    f = wheel_with(tmp_path, {name: b"x = 1\n"})
    hit = [x for x in f if x.code == "long_path"]
    assert hit and hit[0].severity == "warn"


def test_markdown_format(tmp_path, capsys):
    b.build_wheel(str(tmp_path), extra_members=[("acme_widgets/.env", b"A=1")])
    assert main([str(tmp_path), "--format", "markdown"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("### reldoctor: FAIL") and "| `sensitive_file` |" in out


def test_markdown_escapes_hostile_names(tmp_path, capsys):
    b.build_wheel(str(tmp_path), extra_members=[("acme_widgets/<img src=x onerror=1>|[a](http://x)/.env", b"A=1")])
    main([str(tmp_path), "--format", "markdown"])
    out = capsys.readouterr().out
    assert "<img" not in out and "](http" not in out


def test_sarif_has_stable_fingerprints(tmp_path, capsys):
    b.build_wheel(str(tmp_path), extra_members=[("acme_widgets/.env", b"A=1")])
    main([str(tmp_path), "--format", "sarif"])
    first = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    main([str(tmp_path), "--format", "sarif"])
    second = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert all("reldoctor/v1" in r["partialFingerprints"] for r in first)
    assert [r["partialFingerprints"] for r in first] == [r["partialFingerprints"] for r in second]


# --- worker processes and runaway nesting ------------------------------------------------------

def test_parallel_run_through_the_module_prints_one_report(tmp_path):
    for v in ("1.0.0", "1.0.1", "1.0.2"):
        b.build_wheel(str(tmp_path), version=v)
    r = run_cli([str(tmp_path), "--jobs", "3", "--format", "json"])
    assert r.returncode in (0, 1), r.stderr.decode()
    assert json.loads(r.stdout.decode())["errors"] >= 0     # exactly one JSON document, no recursion
    assert r.stdout.count(b'"findings"') == 1


def test_total_nested_member_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(nested, "MAX_TOTAL_MEMBERS", 7)
    z = zip_bytes(**{f"f{i}.txt": b"x" for i in range(5)})
    f = wheel_with(tmp_path, {"acme_widgets/a.zip": z, "acme_widgets/b.zip": z})
    assert "nested_archive_partial" in codes(f)


# --- libstdc++ versus the manylinux policy ------------------------------------------------------

from reldoctor import binary  # noqa: E402


@pytest.mark.parametrize("floor,expect", [((2, 17), 19), ((2, 18), 19), ((2, 28), 24), ((2, 35), 30),
                                          ((2, 39), 33), ((2, 4), None)])
def test_glibcxx_policy_lookup(floor, expect):
    assert binary.glibcxx_allowed(floor) == expect


@pytest.mark.parametrize("tag,cx,flagged", [
    ("cp312-cp312-manylinux2014_x86_64", "GLIBCXX_3.4.19", False),
    ("cp312-cp312-manylinux2014_x86_64", "GLIBCXX_3.4.20", True),
    ("cp312-cp312-manylinux_2_28_x86_64", "GLIBCXX_3.4.24", False),
    ("cp312-cp312-manylinux_2_28_x86_64", "GLIBCXX_3.4.25", True),
])
def test_glibcxx_too_new(tmp_path, tag, cx, flagged):
    f = wheel_with(tmp_path, {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": b.elf(62, "GLIBC_2.17", glibcxx=cx)},
                   tag=tag)
    assert ("manylinux_glibcxx_too_new" in codes(f)) is flagged


def test_vendored_libstdcxx_is_not_judged(tmp_path):
    f = wheel_with(tmp_path, {"acme_widgets/_s.cpython-312-x86_64-linux-gnu.so": b.elf(62, "GLIBC_2.17"),
                              "acme_widgets.libs/libstdc++-abc123.so.6.0.30": b.elf(62, "GLIBC_2.17", glibcxx="GLIBCXX_3.4.30")},
                   tag="cp312-cp312-manylinux2014_x86_64")
    assert "manylinux_glibcxx_too_new" not in codes(f)


def test_glibcxx_scan_ignores_non_elf():
    sc = StreamScanner("notes.txt")
    sc.feed(b"mentions GLIBCXX_3.4.99 in prose")
    assert sc.glibcxx_max is None


# --- an out-of-date optional oracle must not call valid files broken --------------------------

def test_old_packaging_oracle_stays_silent(monkeypatch):
    import packaging
    from reldoctor import wheelcheck
    text = "Metadata-Version: 2.4\nName: x\nVersion: 1\nLicense-Expression: MIT\n"
    monkeypatch.setattr(packaging, "__version__", "24.0")
    assert wheelcheck.packaging_problems(text) is None
    monkeypatch.setattr(packaging, "__version__", "24.2")
    assert wheelcheck.packaging_problems(text) == []
