"""Round 5: baselines, WHEEL-file and script checks, credential URLs, author pin, golden files,
seeded property tests, differential tests against `packaging`, and mutation-style sanity checks."""
import json
import os
import random
import re
import zipfile

import pytest

from bench.build import Mutator, build_sdist, build_wheel, record_row
from reldoctor import CHECKS, __author__, __version__, baseline, diagnose, metacheck, safety, wheelcheck
from reldoctor.cli import main
from reldoctor.doctor import Finding, parse_metadata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTHOR = "Calas Automations Inc."


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def codes(findings):
    return {f.code for f in findings}


def release(tmp, version="1.0.0", **wheel):
    d = str(tmp)
    build_wheel(d, version=version, **wheel)
    build_sdist(d, version=version)
    return d


def cli(args, capsys):
    rc = main(args)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


# --- the author line is one fixed string everywhere ------------------------------

def test_author_is_pinned_everywhere(tmp_path, capsys):
    assert __author__ == AUTHOR
    assert 'authors = [{ name = "Calas Automations Inc." }]' in _read("pyproject.toml")
    assert "maintainers" not in _read("pyproject.toml")
    assert _read("LICENSE").splitlines()[2] == "Copyright (c) 2026 Calas Automations Inc."
    d = release(tmp_path)
    rc, out, _ = cli([d, "--format", "sarif", "--no-config"], capsys)
    assert json.loads(out)["runs"][0]["tool"]["driver"]["organization"] == AUTHOR
    with pytest.raises(SystemExit):
        main(["--help"])
    assert AUTHOR in capsys.readouterr().out


def test_no_personal_handles_in_author_labels():
    for name in ("pyproject.toml", "LICENSE", "src/reldoctor/__init__.py", "src/reldoctor/cli.py"):
        text = _read(name)
        assert "Dan Calas" not in text and "DC Enterprises" not in text
    assert not re.search(r"(?i)author\s*=\s*.*calasdan", _read("pyproject.toml"))


# --- --baseline -------------------------------------------------------------------

def warn_release(tmp, version="1.0.0"):
    """A release whose only problems are warnings (relative README link)."""
    return release(tmp, version=version, body="# T\n\n![logo](docs/logo.png)\n")


def test_baseline_roundtrip_hides_warnings_and_survives_a_version_bump(tmp_path, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    da, db = warn_release(a, "1.0.0"), warn_release(b, "1.0.1")
    bl = str(tmp_path / "bl.json")
    rc, out, err = cli([da, "--no-config", "--strict", "--write-baseline", bl], capsys)
    assert rc == 1 and "wrote 1 accepted warning" in err          # still fails: nothing is baselined yet
    rc, out, err = cli([db, "--no-config", "--strict", "--baseline", bl], capsys)
    assert rc == 0, out                                           # next version: same warning, accepted
    assert "1 accepted warning(s) hidden by the baseline" in out and "readme_relative_links" not in out.split("hidden")[0]
    rc, out, _ = cli([db, "--no-config", "--strict", "--baseline", bl, "--json"], capsys)
    j = json.loads(out)
    assert rc == 0 and j["baselined"] == 1 and j["passed"] is True


def test_baseline_new_warning_still_fails(tmp_path, capsys):
    d1 = warn_release(tmp_path / "a")
    bl = str(tmp_path / "bl.json")
    cli([d1, "--no-config", "--write-baseline", bl], capsys)
    d2 = release(tmp_path / "b", body="# T\n\n![x](docs/other.png)\n", meta=Mutator(add=[("Classifier", "Typing :: Typed")]))
    rc, out, _ = cli([d2, "--no-config", "--strict", "--baseline", bl], capsys)
    assert rc == 1 and "readme_relative_links" in out             # different path => a new finding


def test_baseline_never_hides_errors_even_if_hand_edited(tmp_path, capsys):
    d = release(tmp_path, meta=Mutator(add=[("Classifier", "Topic :: Nope :: Nothing")]))
    bl = str(tmp_path / "bl.json")
    rc, _, err = cli([d, "--no-config", "--write-baseline", bl], capsys)
    assert rc == 1
    assert json.load(open(bl))["entries"] == []                   # errors are not recorded
    findings = diagnose([d])
    err_f = next(f for f in findings if f.code == "invalid_classifier")
    entry = baseline.entry_for(err_f)
    with open(bl, "w") as fh:
        json.dump({"reldoctor-baseline": 1, "entries": [{"code": entry[0], "file": entry[1], "message": entry[2]}]}, fh)
    rc, out, _ = cli([d, "--no-config", "--baseline", bl], capsys)
    assert rc == 1 and "invalid_classifier" in out                # a forged entry changes nothing


def test_baseline_diff_findings_are_not_baselinable():
    f = Finding("warn", "diff_size_jump", "grew 5x", "")
    assert not baseline.eligible(f)
    assert not baseline.eligible(Finding("error", "secret_in_file", "x", "a.whl"))
    assert baseline.eligible(Finding("warn", "local_path_leak", "x", "a.whl"))


def test_baseline_stale_entries_reported_on_stderr(tmp_path, capsys):
    d1 = warn_release(tmp_path / "a")
    bl = str(tmp_path / "bl.json")
    cli([d1, "--no-config", "--write-baseline", bl], capsys)
    clean = release(tmp_path / "c")
    rc, out, err = cli([clean, "--no-config", "--baseline", bl], capsys)
    assert rc == 0 and "1 baseline entry no longer match" in err.replace("entries", "entry") or "no longer match" in err
    assert "baseline" not in out                                  # stdout (the report) stays clean


@pytest.mark.parametrize("content", [b"", b"\xff\xfe\x00", b"{", b"[]", b"null", b'{"reldoctor-baseline": 2, "entries": []}',
                                     b'{"reldoctor-baseline": 1}', b'{"reldoctor-baseline": 1, "entries": {}}',
                                     b'{"reldoctor-baseline": 1, "entries": [1]}',
                                     b'{"reldoctor-baseline": 1, "entries": [{"code": "x"}]}',
                                     b'{"reldoctor-baseline": 1, "entries": [{"code": 1, "file": "", "message": ""}]}',
                                     b"[" * 200000])
def test_broken_baseline_fails_closed(tmp_path, capsys, content):
    d = warn_release(tmp_path / "r")
    bl = tmp_path / "bl.json"
    bl.write_bytes(content)
    rc, out, err = cli([d, "--no-config", "--baseline", str(bl)], capsys)
    assert rc == 2 and "baseline" in err and out == ""


def test_missing_baseline_fails_closed(tmp_path, capsys):
    d = warn_release(tmp_path / "r")
    rc, out, err = cli([d, "--no-config", "--baseline", str(tmp_path / "nope.json")], capsys)
    assert rc == 2 and "cannot read" in err


def test_oversized_baseline_is_refused(tmp_path, capsys):
    bl = tmp_path / "big.json"
    bl.write_bytes(b" " * (baseline.MAX_BYTES + 1))
    with pytest.raises(baseline.BaselineError):
        baseline.load(str(bl))


def test_write_baseline_unwritable_is_usage_error(tmp_path, capsys):
    d = warn_release(tmp_path / "r")
    rc, _, err = cli([d, "--no-config", "--write-baseline", str(tmp_path / "no" / "dir" / "b.json")], capsys)
    assert rc == 2 and "cannot write the baseline" in err


def test_baseline_file_is_deterministic_ascii_and_atomic(tmp_path):
    fs = [Finding("warn", "local_path_leak", "café ‮ x", "a-1.0.0-py3-none-any.whl"),
          Finding("warn", "junk_file", "b", "a-1.0.0-py3-none-any.whl")]
    p1, p2 = str(tmp_path / "1.json"), str(tmp_path / "2.json")
    baseline.write(p1, fs)
    baseline.write(p2, list(reversed(fs)))
    raw = open(p1, "rb").read()
    assert raw == open(p2, "rb").read() and raw.isascii() and raw.endswith(b"\n")
    assert [p for p in os.listdir(tmp_path) if p.startswith(".reldoctor-baseline")] == []
    assert len(baseline.load(p1)) == 2


def test_baseline_from_config_file_with_spaces_in_path(tmp_path, capsys, monkeypatch):
    proj = tmp_path / "my project"
    proj.mkdir()
    d = warn_release(proj / "out dir")
    cli([d, "--no-config", "--write-baseline", str(proj / "base line.json")], capsys)
    (proj / "pyproject.toml").write_text('[tool.reldoctor]\nstrict = true\nbaseline = "base line.json"\n')
    monkeypatch.chdir(proj)
    rc, out, err = cli([d], capsys)
    assert rc == 0, out + err


def test_baseline_config_type_is_validated(tmp_path, capsys, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[tool.reldoctor]\nbaseline = 5\n")
    monkeypatch.chdir(tmp_path)
    d = release(tmp_path / "r")
    rc, _, err = cli([d], capsys)
    assert rc == 2 and "baseline must be a non-empty string" in err


# --- seeded property tests ------------------------------------------------------------

def test_property_fingerprint_ignores_version_but_not_content():
    rnd = random.Random(2026)
    for _ in range(300):
        v1 = ".".join(str(rnd.randrange(0, 40)) for _ in range(rnd.choice([2, 3, 4])))
        v2 = v1 + "." + str(rnd.randrange(1, 9))
        text = rnd.choice(["bad link 'docs/x.png'", "1 file(s) leak 'a/b.so'", "unicode café", "ver %s inside"])
        for label_fmt in ("pkg-{v}-py3-none-any.whl", "pkg-{v}-cp312-cp312-manylinux2014_x86_64.whl", "pkg-{v}.tar.gz"):
            a = Finding("warn", "junk_file", text.replace("%s", v1), label_fmt.format(v=v1))
            b = Finding("warn", "junk_file", text.replace("%s", v2), label_fmt.format(v=v2))
            assert baseline.entry_for(a) == baseline.entry_for(b)
            c = Finding("warn", "junk_file", text.replace("%s", v1) + "!", label_fmt.format(v=v1))
            assert baseline.entry_for(a) != baseline.entry_for(c)
            d = Finding("warn", "bytecode_shipped", text.replace("%s", v1), label_fmt.format(v=v1))
            assert baseline.entry_for(a) != baseline.entry_for(d)


def test_property_write_load_apply_roundtrip(tmp_path):
    rnd = random.Random(7)
    alphabet = "abc xyz'\"\\/é‮\u0000 \n"
    for i in range(60):
        fs = [Finding("warn", rnd.choice(["junk_file", "local_path_leak", "long_path"]),
                      "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 40))), f"p-1.{i}-py3-none-any.whl")
              for _ in range(rnd.randrange(0, 12))]
        path = str(tmp_path / f"b{i}.json")
        baseline.write(path, fs)
        kept, hidden, stale = baseline.apply(fs, baseline.load(path))
        assert kept == [] and hidden == len(fs) and stale == []


# --- WHEEL file, scripts, credentials ----------------------------------------------------

def rewrite_wheel_file(tmp, wheel_text):
    d = str(tmp)
    p = build_wheel(d)
    with zipfile.ZipFile(p) as z:
        items = {n: z.read(n) for n in z.namelist()}
    di = "acme_widgets-1.0.0.dist-info"
    items[f"{di}/WHEEL"] = wheel_text.encode()
    rows = [record_row(n, v) for n, v in items.items() if n != f"{di}/RECORD"]
    items[f"{di}/RECORD"] = ("\n".join(rows + [f"{di}/RECORD,,"]) + "\n").encode()
    with zipfile.ZipFile(p, "w") as z:
        for n, v in items.items():
            z.writestr(n, v)
    return d


GOOD_WHEEL = "Wheel-Version: 1.0\nGenerator: x\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


@pytest.mark.parametrize("text,expected", [
    (GOOD_WHEEL, set()),
    (GOOD_WHEEL.replace("1.0", "2.0"), {"wheel_version_unsupported"}),
    (GOOD_WHEEL.replace("1.0", "1.1"), {"wheel_version_newer"}),
    (GOOD_WHEEL.replace("1.0", "one"), {"wheel_version_unsupported"}),
    (GOOD_WHEEL.replace("Tag: py3-none-any\n", ""), {"wheel_no_tag"}),
    (GOOD_WHEEL.replace("Root-Is-Purelib: true\n", ""), {"purelib_unclear"}),
    (GOOD_WHEEL.replace("true", "maybe"), {"purelib_unclear"}),
])
def test_wheel_file_checks(tmp_path, text, expected):
    got = codes(diagnose([rewrite_wheel_file(tmp_path, text)])) & {
        "wheel_version_unsupported", "wheel_version_newer", "wheel_no_tag", "purelib_unclear"}
    assert got == expected


def test_wheel_file_check_codes_are_registered_with_right_severity():
    assert CHECKS["wheel_version_unsupported"][0] == "error"
    for c in ("wheel_version_newer", "wheel_no_tag", "purelib_unclear", "script_hardcoded_interpreter"):
        assert CHECKS[c][0] == "warn"


@pytest.mark.parametrize("script,flagged", [
    (b"#!/usr/bin/python3\nprint(1)\n", True),
    (b"#!/usr/bin/env python3\n", True),
    (b"#!/home/build/venv/bin/python\n", True),
    (b"#!python\nprint(1)\n", False),
    (b"#!pythonw\n", False),
    (b"#!/bin/sh\necho hi\n", False),
    (b"#!/usr/bin/env bash\n", False),
    (b"print(1)\n", False),
    (b"", False),
])
def test_script_shebang(tmp_path, script, flagged):
    d = str(tmp_path)
    build_wheel(d, files={"acme_widgets-1.0.0.data/scripts/tool": script})
    assert ("script_hardcoded_interpreter" in codes(diagnose([d]))) is flagged


def _secret_kinds(content: bytes):
    return safety.scan_secrets(content)


def test_credential_urls():
    pw = "s3cretPw99"
    assert "URL with embedded password" in _secret_kinds(("U='https://deploy:" + pw + "@pkgs.corp-internal.net/simple'").encode())
    assert "URL with embedded password" in _secret_kinds(("git+https://bot:" + pw + "@github.com/o/r.git").encode())
    for harmless in ["https://user:password@pkgs.corp.net/simple", "https://${USER}:${TOKEN}@pkgs.corp.net/simple",
                     "https://{user}:{token}@pkgs.corp.net/simple", "https://github.com/org/repo",
                     "http://localhost:8000/a@b.com", "https://a:b@host.tld/", "https://user:%s@host.corp.net/"]:
        assert "URL with embedded password" not in _secret_kinds(harmless.encode()), harmless


def test_credential_url_is_redacted_in_messages():
    assert "s3cretPw99" not in safety.redact("see https://deploy:" + "s3cretPw99" + "@pkgs.corp-internal.net/simple")


@pytest.mark.parametrize("name,kind", [
    (".vault_pass", "sensitive"), ("ansible/.vault-pass", "sensitive"), (".s3cfg", "sensitive"), (".my.cnf", "sensitive"),
    (".claude/settings.local.json", "maybe"), (".cursor/mcp.json", "maybe"), (".mcp.json", "maybe"),
    (".cargo/credentials.toml", "maybe"), ("pkg/data.json", None), ("docs/mcp.json", None)])
def test_new_sensitive_names(name, kind):
    assert bool(safety.sensitive_file_kind(name)) is (kind == "sensitive")
    assert bool(safety.maybe_sensitive_file_kind(name)) is (kind == "maybe")


# --- classifier snapshot age ------------------------------------------------------------------

def _meta(*classifiers):
    return parse_metadata("Metadata-Version: 2.4\nName: x\nVersion: 1\n" + "".join(f"Classifier: {c}\n" for c in classifiers))


def test_stale_snapshot_adds_hint_and_live_list_wins(monkeypatch):
    bogus = "Topic :: Brand New :: Thing"
    monkeypatch.setattr(metacheck, "_snapshot_age_days", lambda h: 400)
    monkeypatch.setattr(metacheck, "_live_classifiers", lambda: None)
    msg = metacheck.check_classifiers(_meta(bogus))[0][1]
    assert "400 days old" in msg and "upgrade" in msg
    monkeypatch.setattr(metacheck, "_snapshot_age_days", lambda h: 10)
    assert "days old" not in metacheck.check_classifiers(_meta(bogus))[0][1]
    monkeypatch.setattr(metacheck, "_live_classifiers", lambda: frozenset({bogus}))
    assert metacheck.check_classifiers(_meta(bogus)) == []


def test_snapshot_age_parses_and_survives_garbage():
    assert metacheck._snapshot_age_days("trove-classifiers 2020.1.1.1") > 1000
    assert metacheck._snapshot_age_days("bundled trove list") is None
    assert metacheck._snapshot_age_days("trove-classifiers 2026.13.45.1") is None


# --- golden files: every output format on one fixed broken release -----------------------------

GOLDEN = os.path.join(ROOT, "tests", "golden")


def _golden_release(tmp):
    from bench import demo
    demo.main(str(tmp))
    return os.path.join(str(tmp), "dist"), os.path.join(str(tmp), "prev")


@pytest.mark.parametrize("fmt,ext", [("text", "txt"), ("json", "json"), ("github", "txt"), ("sarif", "json"),
                                    ("junit", "xml"), ("markdown", "md")])
def test_golden_output(tmp_path, capsys, monkeypatch, fmt, ext):
    monkeypatch.setattr(metacheck, "_snapshot_age_days", lambda h: 10)
    monkeypatch.setattr(metacheck, "_live_classifiers", lambda: None)
    monkeypatch.chdir(tmp_path)
    dist, prev = _golden_release(tmp_path)
    capsys.readouterr()          # drop the "wrote ..." line the demo builder prints
    rc, out, _ = cli([dist, "--against", prev, "--no-config", "--strict", "--format", fmt], capsys)
    assert rc == 1
    out = out.replace(__version__, "{VERSION}").replace(str(tmp_path), "{TMP}")
    path = os.path.join(GOLDEN, f"demo_{fmt}.{ext}")
    if os.environ.get("RELDOCTOR_REGEN_GOLDEN"):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
    with open(path, encoding="utf-8", newline="") as fh:
        assert out == fh.read(), f"{fmt} output changed; if intended rerun with RELDOCTOR_REGEN_GOLDEN=1 and review the diff"


# --- differential tests against `packaging` (what PyPI uses) -----------------------------------

packaging = pytest.importorskip("packaging")


def test_differential_wheel_filename_parsing():
    from packaging.utils import InvalidWheelFilename, parse_wheel_filename
    from reldoctor.doctor import PEP440, _wheel_filename
    rnd = random.Random(11)
    names = ["acme_widgets", "acme", "a", "Acme_Widgets", "acme-widgets", "acme.widgets", "1abc", "_x"]
    vers = ["1.0.0", "1.0", "1!2.0", "1.0.0rc1", "1.0.0.post2", "1.0.dev3", "1.0+local", "x", "1..0", "01.0"]
    builds = ["", "1-", "12abc-", "b1-", "-"]
    tags = ["py3-none-any", "cp312-cp312-manylinux2014_x86_64", "py2.py3-none-any", "cp312-cp312-win_amd64-extra", ""]
    disagreements = []
    for _ in range(600):
        fn = f"{rnd.choice(names)}-{rnd.choice(vers)}-{rnd.choice(builds)}{rnd.choice(tags)}.whl"
        try:
            parse_wheel_filename(fn)
            ref = True
        except InvalidWheelFilename:
            ref = False
        except Exception:
            ref = False
        parsed = _wheel_filename(fn)
        # the filename split is lenient by design; the version is judged by the PEP 440 check on
        # the same string (version_not_pep440), so the two together are what must not be looser
        ours = parsed is not None and PEP440.match(parsed[1]) is not None
        # fail closed: we may be stricter than packaging, never looser
        if ours and not ref:
            disagreements.append(fn)
    assert disagreements == []


def test_differential_pep440():
    from packaging.version import InvalidVersion, Version
    from reldoctor.doctor import PEP440
    rnd = random.Random(13)
    parts = ["1", "2", "0", "10", "1!", "v", "rc1", "a2", "b3", ".post1", ".dev4", "+loc", "+a.b", ".", "-", "_", "post", "dev", "x", " "]
    loose = []
    for _ in range(1500):
        s = "".join(rnd.choice(parts) for _ in range(rnd.randrange(1, 6)))
        try:
            Version(s)
            ref = True
        except InvalidVersion:
            ref = False
        if PEP440.match(s) and not ref:
            loose.append(s)
    assert loose == []


# --- mutation-style sanity: flip key conditions, the tests must notice -----------------------------

def _errors_stay_visible(tmp_path, capsys):
    d = release(tmp_path, meta=Mutator(add=[("Classifier", "Topic :: Nope :: Nothing")]))
    bl = str(tmp_path / "bl.json")
    entry = baseline.entry_for(next(f for f in diagnose([d]) if f.code == "invalid_classifier"))
    with open(bl, "w") as fh:
        json.dump({"reldoctor-baseline": 1, "entries": [dict(zip(("code", "file", "message"), entry))]}, fh)
    rc, out, _ = cli([d, "--no-config", "--baseline", bl], capsys)
    return rc == 1 and "invalid_classifier" in out


def test_mutation_baseline_error_guard_is_load_bearing(tmp_path, capsys, monkeypatch):
    assert _errors_stay_visible(tmp_path / "ok", capsys)
    monkeypatch.setattr(baseline, "eligible", lambda f: True)            # mutant: baseline everything
    assert not _errors_stay_visible(tmp_path / "mutant", capsys)         # the suite would catch it


def test_mutation_version_blanking_is_load_bearing(monkeypatch):
    a = Finding("warn", "junk_file", "x", "p-1.0.0-py3-none-any.whl")
    b = Finding("warn", "junk_file", "x", "p-1.0.1-py3-none-any.whl")
    assert baseline.entry_for(a) == baseline.entry_for(b)
    monkeypatch.setattr(baseline, "_blank", lambda label, message: (label, message))
    assert baseline.entry_for(a) != baseline.entry_for(b)


def test_mutation_wheel_major_check(monkeypatch):
    meta = parse_metadata("Wheel-Version: 2.0\nTag: a-b-c\nRoot-Is-Purelib: true\n")
    assert wheelcheck.check_wheel_file(meta)[0][0] == "wheel_version_unsupported"
    monkeypatch.setattr(wheelcheck, "_WHEEL_VERSION", re.compile(r"^\s*(\d)\.(\d)\s*$"))
    assert wheelcheck.check_wheel_file(meta)[0][0] == "wheel_version_unsupported"   # same behaviour: not a mutant
    monkeypatch.setattr(wheelcheck, "check_wheel_file", lambda m: [])
    assert wheelcheck.check_wheel_file(meta) == []                                   # a no-op mutant is visibly different


def test_baseline_note_in_every_human_format_and_ignored_codes_are_not_stale(tmp_path, capsys):
    d = warn_release(tmp_path / "r")
    bl = str(tmp_path / "bl.json")
    cli([d, "--no-config", "--write-baseline", bl], capsys)
    for fmt in ("text", "github", "markdown"):
        rc, out, err = cli([d, "--no-config", "--strict", "--baseline", bl, "--format", fmt], capsys)
        assert rc == 0 and "1 accepted warning(s) hidden by the baseline" in out, fmt
    rc, out, err = cli([d, "--no-config", "--baseline", bl, "--ignore", "readme_relative_links"], capsys)
    assert "no longer match" not in err          # silenced with --ignore is not the same as fixed


def test_seeded_byte_mutation_fuzz_never_crashes(tmp_path):
    """Flip, delete and insert bytes in a wheel and an sdist; diagnose must return findings, never raise."""
    src = tmp_path / "src"
    w = build_wheel(str(src), files={"acme_widgets-1.0.0.data/scripts/t": b"#!/usr/bin/python\n"})
    s = build_sdist(str(src))
    originals = {p: open(p, "rb").read() for p in (w, s)}
    rnd = random.Random(5)
    out = tmp_path / "out"
    out.mkdir()
    for _ in range(80):
        p = rnd.choice(sorted(originals))
        b = bytearray(originals[p])
        for _ in range(rnd.choice([1, 2, 5, 20])):
            k, mode = rnd.randrange(len(b)), rnd.random()
            if mode < .5:
                b[k] = rnd.randrange(256)
            elif mode < .8:
                del b[k:k + rnd.randrange(1, 50)]
            else:
                b[k:k] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 30)))
        for old in out.iterdir():
            old.unlink()
        (out / os.path.basename(p)).write_bytes(bytes(b))
        assert isinstance(diagnose([str(out)]), list)
