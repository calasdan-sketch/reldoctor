"""Tests for the 0.2 checks: archive safety, leaks, RECORD integrity,
PyPI-rejection rules, cross-artifact drift and safe output."""
import io
import json
import os
import tarfile
import zipfile

import pytest

from reldoctor import doctor
from reldoctor.cli import main
from reldoctor.doctor import check_sdist, check_wheel, diagnose_dist_dir
from reldoctor.safety import escape_terminal, link_escapes, scan_secrets, unsafe_path_reason
from tests.test_doctor import codes, make_sdist, make_wheel, record_row

WHL = "demo-1.0.0-py3-none-any.whl"
DIST = "demo-1.0.0.dist-info"

# Fake secrets are assembled at runtime so no contiguous token sits in the repo.
_MIX = "".join(chr(c) for c in range(ord("a"), ord("z") + 1)) + "0123456789"
FAKE_GH = "gh" + "p_" + (_MIX[::-1] * 2)[:36]
FAKE_AWS = "AK" + "IA" + "QW7RT3YP9ZUX2NBV"
FAKE_KEY = ("-----BEGIN " + "PRIVATE KEY-----\n" + ("MIIB" + "x" * 60 + "\n") * 3
            + "-----END " + "PRIVATE KEY-----\n")


def rewrite_wheel(path, mutate):
    """Rebuild a wheel with members transformed by mutate(dict) -> dict (RECORD untouched)."""
    with zipfile.ZipFile(path) as z:
        members = {n: z.read(n) for n in z.namelist()}
    members = mutate(members)
    with zipfile.ZipFile(path, "w") as z:
        for n, b in members.items():
            z.writestr(n, b)


def raw_sdist(tmp, name, members):
    path = tmp / name
    with tarfile.open(path, "w:gz") as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return str(path)


def tinfo(name, data=b"", **kw):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for k, v in kw.items():
        setattr(info, k, v)
    return info, data


# --- output safety --------------------------------------------------------

def test_escape_terminal_neutralises_controls_and_bidi():
    s = escape_terminal("a\x1b[31mred\u202eevil\u200bz\nnext")
    assert "\x1b" not in s and "\u202e" not in s and "\u200b" not in s and "\n" not in s
    assert "\\u001b" in s and "\\u202e" in s and "\\n" in s


def test_cli_text_output_escapes_hostile_metadata(tmp_path, capsys):
    make_wheel(tmp_path, meta_name="demo\x1b]0;pwned\x07\u202e")
    make_sdist(tmp_path)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "\u202e" not in out
    assert "name_mismatch" in out


def test_github_format_annotations_are_escaped(tmp_path, capsys):
    make_wheel(tmp_path, meta_version="9.9.9")
    make_sdist(tmp_path)
    assert main([str(tmp_path), "--format", "github"]) == 1
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if "version_mismatch" in l)
    assert line.startswith("::error title=reldoctor version_mismatch::[demo-1.0.0-py3-none-any.whl] ")
    assert "\n" not in line


# --- archive safety -------------------------------------------------------

@pytest.mark.parametrize("bad", ["../evil.py", "/etc/passwd", "C:/x.py", "pkg\\x.py"])
def test_unsafe_member_paths(tmp_path, bad):
    make_wheel(tmp_path, extra_files={bad: "x"})
    assert "unsafe_path" in codes(check_wheel(str(tmp_path / WHL)))


def test_unsafe_path_reason_accepts_normal_paths():
    assert unsafe_path_reason("pkg/sub/mod.py") is None
    assert unsafe_path_reason("pkg/..hidden/mod.py") is None


def test_duplicate_and_case_collision(tmp_path):
    p = make_wheel(tmp_path, extra_files={"demo/Readme.txt": "a", "demo/README.txt": "b"})
    found = codes(check_wheel(p))
    assert "case_collision" in found

    with zipfile.ZipFile(p, "a") as z:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            z.writestr("demo/__init__.py", "evil = 1\n")
    found = codes(check_wheel(p))
    assert "duplicate_entry" in found


def test_link_escapes():
    assert link_escapes("pkg-1.0/a", "../../etc/passwd")
    assert link_escapes("pkg-1.0/a", "/etc/passwd")
    assert not link_escapes("pkg-1.0/docs/a", "../README")


def test_sdist_symlink_out_of_tree_and_special_files(tmp_path):
    root = "demo-1.0.0"
    p = raw_sdist(tmp_path, "demo-1.0.0.tar.gz", [
        tinfo(f"{root}/PKG-INFO", b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"),
        tinfo(f"{root}/pyproject.toml", b"[project]\n"),
        tinfo(f"{root}/LICENSE", b"MIT\n"),
        tinfo(f"{root}/escape", type=tarfile.SYMTYPE, linkname="../../../home/user/.ssh/id_rsa"),
        tinfo(f"{root}/fifo", type=tarfile.FIFOTYPE),
    ])
    found = codes(check_sdist(p))
    assert "unsafe_link" in found and "special_file" in found


def test_truncated_sdist_is_reported_not_crashed(tmp_path):
    p = make_sdist(tmp_path)
    data = open(p, "rb").read()
    open(p, "wb").write(data[: len(data) // 2])
    assert codes(check_sdist(p)) == ["sdist_corrupt"]


# --- leaks ----------------------------------------------------------------

def test_sensitive_files_flagged_and_templates_allowed(tmp_path):
    p = make_wheel(tmp_path, extra_files={"demo/.env": "X=1", "demo/.env.example": "X=",
                                          ".pypirc": "[pypi]"})
    msgs = [f.message for f in check_wheel(p) if f.code == "sensitive_file"]
    assert len(msgs) == 2
    assert not any(".env.example" in m for m in msgs)


@pytest.mark.parametrize("secret", [FAKE_GH, FAKE_AWS, FAKE_KEY])
def test_secrets_detected_but_never_echoed(tmp_path, secret, capsys):
    make_wheel(tmp_path, extra_files={"demo/settings.py": f"TOKEN = '{secret}'\n"})
    make_sdist(tmp_path, extra_files={"tests/fixture.txt": secret})
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert out.count("secret_in_file") == 2
    assert secret not in out and secret[:20] not in out


def test_pem_header_alone_is_not_a_key():
    assert scan_secrets(b'MARKER = b"-----BEGIN ' + b'OPENSSH PRIVATE KEY-----"\n') == []


def test_allow_path_exempts_fixtures_only(tmp_path, capsys):
    make_wheel(tmp_path)
    make_sdist(tmp_path, extra_files={"tests/certs/server.key": FAKE_KEY,
                                      "src/creds.py": FAKE_GH})
    main([str(tmp_path), "--allow-path", "tests/certs/*", "--json"])
    found = json.loads(capsys.readouterr().out)["findings"]
    hits = [f["message"] for f in found if f["code"] == "secret_in_file"]
    assert len(hits) == 1 and "creds.py" in hits[0]


def test_allow_everything_is_refused(tmp_path):
    make_wheel(tmp_path)
    assert main([str(tmp_path), "--allow-path", "*"]) == 2
    assert main([str(tmp_path), "--allow-path", "**/*"]) == 2


def test_junk_vcs_and_bytecode(tmp_path):
    p = make_wheel(tmp_path, extra_files={"demo/__pycache__/x.cpython-312.pyc": b"\0",
                                          "demo/.DS_Store": b"\0", ".git/config": "[core]"})
    found = codes(check_wheel(p))
    assert {"bytecode_shipped", "junk_file", "vcs_metadata_shipped"} <= set(found)


# --- RECORD integrity -----------------------------------------------------

def test_record_hash_and_size_mismatch(tmp_path):
    p = make_wheel(tmp_path)
    rewrite_wheel(p, lambda m: {**m, "demo/__init__.py": b"tampered = True\n"})
    found = codes(check_wheel(p))
    assert "record_hash_mismatch" in found and "record_size_mismatch" in found


def test_record_lists_missing_file_and_weak_hash(tmp_path):
    p = make_wheel(tmp_path)

    def mutate(m):
        rec = m[f"{DIST}/RECORD"].decode()
        rec += "demo/ghost.py,sha256=abc,3\n"
        rec = rec.replace("demo/__init__.py,sha256=", "demo/__init__.py,md5=")
        return {**m, f"{DIST}/RECORD": rec.encode()}
    rewrite_wheel(p, mutate)
    found = codes(check_wheel(p))
    assert "record_missing_file" in found and "record_weak_hash" in found


def test_record_rows_without_hash_warn(tmp_path):
    p = make_wheel(tmp_path)

    def mutate(m):
        rec = m[f"{DIST}/RECORD"].decode().splitlines()
        rec = [r.split(",")[0] + ",," if r.startswith("demo/") else r for r in rec]
        return {**m, f"{DIST}/RECORD": ("\n".join(rec) + "\n").encode()}
    rewrite_wheel(p, mutate)
    assert "record_no_hash" in codes(check_wheel(p))


def test_record_with_quoted_comma_path(tmp_path):
    p = make_wheel(tmp_path, extra_files={"demo/a,b.txt": "x"})
    assert check_wheel(p) == []


def test_budget_exhaustion_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "MAX_ARCHIVE_READ", 10)
    p = make_wheel(tmp_path, extra_files={"demo/big.txt": "y" * 100})
    assert "archive_too_large" in codes(check_wheel(p))


def test_oversized_metadata_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "MAX_METADATA_BYTES", 50)
    p = make_wheel(tmp_path)
    assert "member_unreadable" in codes(check_wheel(p))


# --- wheel structure ------------------------------------------------------

def test_binary_in_pure_wheel(tmp_path):
    p = make_wheel(tmp_path, extra_files={"demo/_speed.cpython-312-x86_64-linux-gnu.so": b"\x7fELF"})
    assert "binary_in_pure_wheel" in codes(check_wheel(p))


def test_wheel_tag_mismatch(tmp_path):
    p = make_wheel(tmp_path)

    def mutate(m):
        w = m[f"{DIST}/WHEEL"].replace(b"Tag: py3-none-any", b"Tag: cp312-cp312-linux_x86_64")
        return {**m, f"{DIST}/WHEEL": w}
    rewrite_wheel(p, mutate)
    assert "wheel_tag_mismatch" in codes(check_wheel(p))


def test_bad_and_unnormalized_wheel_filenames(tmp_path):
    p = make_wheel(tmp_path)
    bad = tmp_path / "demo-1.0.0.whl"
    os.rename(p, bad)
    assert "bad_wheel_filename" in codes(check_wheel(str(bad)))

    p = make_wheel(tmp_path, name="Demo.Pkg", meta_name="Demo.Pkg")
    assert "wheel_name_not_normalized" in codes(check_wheel(p))


# --- PyPI rejection rules -------------------------------------------------

def test_direct_url_dependency(tmp_path):
    p = make_wheel(tmp_path, extra_meta="Requires-Dist: dep @ git+https://example.com/dep.git\n"
                                        "Requires-Dist: ok>=1; python_version >= '3.9'\n")
    found = [f for f in check_wheel(p) if f.code == "direct_url_dependency"]
    assert len(found) == 1


def test_license_and_expression_conflict(tmp_path):
    p = make_wheel(tmp_path, extra_meta="License-Expression: MIT\n")
    assert "license_conflict" in codes(check_wheel(p))


def test_license_file_must_be_shipped(tmp_path):
    # Metadata < 2.4: old setuptools layout, not checked
    p = make_wheel(tmp_path, name="old", extra_meta="License-File: LICENSE\n")
    assert "license_file_missing" not in codes(check_wheel(p))

    p = make_wheel(tmp_path, license_field="", metadata_version="2.4",
                   extra_meta="License-Expression: MIT\nLicense-File: LICENSE\n")
    assert "license_file_missing" in codes(check_wheel(p))
    p = make_wheel(tmp_path, name="ok", license_field="", metadata_version="2.4",
                   extra_meta="License-Expression: MIT\nLicense-File: LICENSE\n",
                   extra_files={"ok-1.0.0.dist-info/licenses/LICENSE": "MIT"})
    assert check_wheel(p) == []
    p = make_wheel(tmp_path, name="trav", license_field="", metadata_version="2.4",
                   extra_meta="License-Expression: MIT\nLicense-File: ../../LICENSE\n")
    assert "license_file_missing" in codes(check_wheel(p))


def test_content_type_and_urls(tmp_path):
    p = make_wheel(tmp_path, extra_meta="Project-URL: Source, javascript:alert(1)\n"
                                        "Project-URL: no-comma-here\n"
                                        "Project-URL: Docs, https://example.com/docs\n")
    found = codes(check_wheel(p))
    assert found.count("bad_project_url") == 1 and found.count("project_url_rejected") == 1


def test_local_version_reported_once(tmp_path):
    p = make_wheel(tmp_path, version="1.0.0+local.1", meta_version="1.0.0+local.1")
    found = codes(check_wheel(p))
    assert "local_version" in found and "version_not_pep440" not in found


def test_entry_point_with_extras_is_valid(tmp_path):
    p = make_wheel(tmp_path, entry_points="[console_scripts]\ndemo = demo.cli:main [fast, cli]\n")
    assert check_wheel(p) == []


# --- sdist naming and drift ----------------------------------------------

def test_sdist_naming(tmp_path):
    p = make_sdist(tmp_path, name="Demo.Pkg")
    assert "sdist_name_not_normalized" in codes(check_sdist(p))


def test_sdist_pkg_info_name_mismatch(tmp_path):
    p = make_sdist(tmp_path)
    data = open(p, "rb").read()
    q = raw_sdist(tmp_path, "other-1.0.0.tar.gz", [
        tinfo("other-1.0.0/PKG-INFO", b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"),
        tinfo("other-1.0.0/pyproject.toml", b""), tinfo("other-1.0.0/LICENSE", b"MIT"),
    ])
    assert data and "name_mismatch" in codes(check_sdist(q))


def test_name_drift(tmp_path):
    make_wheel(tmp_path)
    make_sdist(tmp_path, name="other")
    assert "name_drift" in codes(diagnose_dist_dir(str(tmp_path)))


def test_metadata_drift_respects_dynamic(tmp_path):
    make_wheel(tmp_path, extra_meta="Requires-Dist: requests>=2\n")
    make_sdist(tmp_path, pkg_info_extra="Summary: A demo package\nRequires-Python: >=3.9\n")
    # Metadata 2.1 PKG-INFO: not authoritative, so no drift claimed
    assert "metadata_drift" not in codes(diagnose_dist_dir(str(tmp_path)))

    for f in tmp_path.iterdir():
        f.unlink()
    make_wheel(tmp_path, extra_meta="Requires-Dist: requests>=2\n")
    sd = make_sdist(tmp_path, pkg_info_extra="Summary: A demo package\nRequires-Python: >=3.9\n")
    _bump_pkg_info(sd, "2.2")
    assert "metadata_drift" in codes(diagnose_dist_dir(str(tmp_path)))

    for f in tmp_path.iterdir():
        f.unlink()
    make_wheel(tmp_path, extra_meta="Requires-Dist: requests>=2\n")
    sd = make_sdist(tmp_path, pkg_info_extra="Summary: A demo package\nRequires-Python: >=3.9\n"
                                             "Dynamic: Requires-Dist\n")
    _bump_pkg_info(sd, "2.2")
    assert "metadata_drift" not in codes(diagnose_dist_dir(str(tmp_path)))


def _bump_pkg_info(path, mv):
    with tarfile.open(path) as tf:
        members = [(m, tf.extractfile(m).read()) for m in tf.getmembers()]
    with tarfile.open(path, "w:gz") as tf:
        for m, data in members:
            if m.name.endswith("/PKG-INFO"):
                data = data.replace(b"Metadata-Version: 2.1", f"Metadata-Version: {mv}".encode())
                m.size = len(data)
            tf.addfile(m, io.BytesIO(data))


# --- CLI ------------------------------------------------------------------

def test_cli_accepts_files_and_ignores(tmp_path, capsys):
    w = make_wheel(tmp_path, summary="")
    s = make_sdist(tmp_path)
    assert main([w, s, "--strict"]) == 1
    assert main([w, s, "--strict", "--ignore", "no_summary"]) == 0
    capsys.readouterr()


def test_cli_fails_closed_on_bad_setup(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("x")
    assert main([str(tmp_path / "notes.txt")]) == 2           # not an artifact
    assert main([]) == 2                                       # nothing given
    make_wheel(tmp_path)
    assert main([str(tmp_path), "--ignore", "no_such_code"]) == 2
    assert main([str(tmp_path), "--ignore", "no_artifacts"]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main([str(empty)]) == 1                             # empty dist dir fails
    capsys.readouterr()


def test_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    assert "secret_in_file" in out and "record_hash_mismatch" in out


def test_diagnose_dist_dir_rejects_file(tmp_path):
    p = make_wheel(tmp_path)
    with pytest.raises(NotADirectoryError):
        diagnose_dist_dir(p)


def test_record_row_helper_is_sha256():
    assert record_row("a", b"").startswith("a,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0")


def test_dot_slash_prefixed_sdist(tmp_path):
    root = "demo-1.0.0"
    p = raw_sdist(tmp_path, "demo-1.0.0.tar.gz", [
        tinfo(".", type=tarfile.DIRTYPE),
        tinfo(f"./{root}/PKG-INFO", b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"),
        tinfo(f"./{root}/pyproject.toml", b""), tinfo(f"./{root}/LICENSE", b"MIT"),
    ])
    # PyPI rejects "./" members; structure checks still see the real layout
    assert [f.code for f in check_sdist(p) if f.severity != "info"] == ["path_not_normalized"]
