"""Regression tests for the synapse-1 panel review findings (1-8)."""
import json
import tarfile
import time
import zipfile

import pytest

from reldoctor import doctor
from reldoctor.cli import main
from reldoctor.doctor import check_sdist, check_wheel, content_type_problem
from reldoctor.reqs import parse_requirement
from reldoctor.safety import (
    broad_allow_pattern,
    redact,
    resolve_link_escapes,
    scan_secrets,
)
from tests.test_doctor import codes, make_sdist, make_wheel
from tests.test_hardening import FAKE_AWS, FAKE_GH, FAKE_KEY, raw_sdist, tinfo

DIST = "demo-1.0.0.dist-info"


def _rewrite(path, mutate):
    with zipfile.ZipFile(path) as z:
        members = {n: z.read(n) for n in z.namelist()}
    members = mutate(members)
    with zipfile.ZipFile(path, "w") as z:
        for n, b in members.items():
            z.writestr(n, b)


def _sdist(tmp, extra, name="demo-1.0.0.tar.gz", pkg_info=b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"):
    root = name[: -len(".tar.gz")]
    base = [tinfo(f"{root}/PKG-INFO", pkg_info), tinfo(f"{root}/pyproject.toml", b""),
            tinfo(f"{root}/LICENSE", b"MIT")]
    return raw_sdist(tmp, name, base + extra)


# 1. secrets in finding messages ------------------------------------------

def test_direct_url_token_is_redacted_everywhere(tmp_path, capsys):
    make_wheel(tmp_path, extra_meta=f"Requires-Dist: priv @ git+https://{FAKE_GH}@github.com/o/priv.git\n"
                                    "Project-URL: Source, https://user:hunter2@example.com/repo\n")
    make_sdist(tmp_path)
    for fmt in ("text", "json", "github"):
        main([str(tmp_path), "--format", fmt])
        out = capsys.readouterr().out
        assert "direct_url_dependency" in out
        assert FAKE_GH not in out and "hunter2" not in out


def test_redact_handles_userinfo_and_bare_tokens():
    assert redact("https://u:p@host/x") == "https://***@host/x"
    assert FAKE_AWS not in redact(f"key {FAKE_AWS} here")
    assert "user@example.com" in redact("mail user@example.com")  # not a URL


# 2. malformed RECORD ------------------------------------------------------

@pytest.mark.parametrize("payload", ["a,b,c\n\x00\n", "x" * 200_000 + ",,\n"])
def test_malformed_record_is_reported_not_crashed(tmp_path, capsys, payload):
    p = make_wheel(tmp_path)
    _rewrite(p, lambda m: {**m, f"{DIST}/RECORD": payload.encode()})
    assert "record_unparseable" in codes(check_wheel(p))
    assert main([p, "--json"]) == 1
    json.loads(capsys.readouterr().out)  # clean JSON, no traceback
    assert main([p, "--ignore", "record_unparseable"]) == 2  # locked


# 3. PyPI-rejection rules ---------------------------------------------------

@pytest.mark.parametrize("value,ok", [
    ("text/markdown", True), ("text/markdown; charset=UTF-8; variant=GFM", True),
    ("text/markdown; variant=CommonMark", True), ("text/x-rst", True), ("text/plain; charset=utf-8", True),
    ("text/html", False), ("text/plain; charset=latin-1", False), ("text/markdown; variant=foo", False),
    ("markdown", False),
])
def test_content_type_rules_match_packaging(value, ok):
    assert (content_type_problem(value) is None) is ok


def test_bad_content_type_is_an_error(tmp_path):
    for i, ct in enumerate(["text/html", "text/plain; charset=latin-1", "text/markdown; variant=foo"]):
        p = make_wheel(tmp_path, name=f"ct{i}", content_type=ct)
        found = [f for f in check_wheel(p) if f.code == "bad_content_type"]
        assert len(found) == 1 and found[0].severity == "error", ct


def test_member_cap_covers_metadata_readers(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "MAX_MEMBERS", 10)
    root = "demo-1.0.0"
    p = raw_sdist(tmp_path, "demo-1.0.0.tar.gz",
                  [tinfo(f"{root}/f{i}", b"") for i in range(50)]
                  + [tinfo(f"{root}/PKG-INFO", b"Metadata-Version: 2.2\nName: demo\nVersion: 1.0.0\n")])
    assert doctor.sdist_metadata(p) is None


@pytest.mark.parametrize("mv,code", [("3.0", "bad_metadata_version"), ("2.0", "bad_metadata_version"),
                                     ("2.5", None), ("1.2", "old_metadata_version")])
def test_metadata_version_allowlist(tmp_path, mv, code):
    p = make_wheel(tmp_path, metadata_version=mv)
    found = [c for c in codes(check_wheel(p)) if c in ("bad_metadata_version", "old_metadata_version")]
    assert found == ([code] if code else [])


@pytest.mark.parametrize("field", ["Requires-Dist", "Provides-Dist", "Obsoletes-Dist"])
def test_all_dist_fields_checked(tmp_path, field):
    p = make_wheel(tmp_path, extra_meta=f"{field}: x @ https://example.com/x.whl\n")
    assert "direct_url_dependency" in codes(check_wheel(p))
    p = make_wheel(tmp_path, name="bad", extra_meta=f"{field}: foo >>>> 1\n")
    assert "bad_requirement" in codes(check_wheel(p))


def test_sdist_pkg_info_dist_fields_and_version(tmp_path):
    p = _sdist(tmp_path, [], pkg_info=b"Metadata-Version: 3.0\nName: demo\nVersion: 1.0.0\n"
                                      b"Requires-Dist: foo >>>> 1\n")
    found = codes(check_sdist(p))
    assert "bad_requirement" in found and "bad_metadata_version" in found


@pytest.mark.parametrize("req", ["foo", "foo>=1,<2", "foo (>=1)", "foo[a,b]>=1; python_version<'3.9'",
                                 "foo==1.*", "foo~=1.0", "foo; extra == 'x' and os_name=='nt'",
                                 "foo==1.0+local"])
def test_valid_requirements_accepted(req):
    assert parse_requirement(req) == (None, False)


@pytest.mark.parametrize("req", ["foo >>>> 1", "foo~=1", "foo>=1.0+local", "foo; python_version",
                                 "foo,bar", "foo (>=1", "-foo", "foo>=1;"])
def test_invalid_requirements_rejected(req):
    assert parse_requirement(req)[0] is not None


def test_hostile_marker_nesting_is_bounded():
    err, _ = parse_requirement("foo; " + "(" * 5000 + "os_name=='nt'" + ")" * 5000)
    assert err is not None


@pytest.mark.parametrize("member", ["demo/./x.py", "demo//y.py", "./demo/z.py"])
def test_non_normalized_member_paths(tmp_path, member):
    p = make_wheel(tmp_path, extra_files={member: "x"})
    assert "path_not_normalized" in codes(check_wheel(p))


def test_sdist_dot_slash_not_hidden(tmp_path):
    p = _sdist(tmp_path, [tinfo("./demo-1.0.0/x.py", b"")])
    assert "path_not_normalized" in codes(check_sdist(p))


def test_sparse_member(tmp_path):
    info, data = tinfo("demo-1.0.0/sparse.bin", b"")
    info.type = tarfile.GNUTYPE_SPARSE
    p = _sdist(tmp_path, [(info, data)])
    assert "sparse_member" in codes(check_sdist(p))


def test_unsupported_compression(tmp_path):
    p = make_wheel(tmp_path)
    with zipfile.ZipFile(p, "a", compression=zipfile.ZIP_BZIP2) as z:
        z.writestr("demo/extra.txt", "x")
    assert "unsupported_compression" in codes(check_wheel(p))


def test_compression_ratio(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "COMPRESSION_RATIO_MIN_SIZE", 1000)
    p = make_wheel(tmp_path)
    with zipfile.ZipFile(p, "a", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("demo/zeros.bin", b"\0" * 2_000_000)
    assert "compression_ratio" in codes(check_wheel(p))


def test_length_limits_and_project_url_label(tmp_path):
    p = make_wheel(tmp_path, summary="s" * 513,
                   extra_meta="Project-URL: " + "L" * 33 + ", https://example.com\n")
    found = codes(check_wheel(p))
    assert "summary_too_long" in found and "project_url_rejected" in found


# 4. chained symlinks -------------------------------------------------------

def test_chained_symlink_escape(tmp_path):
    p = _sdist(tmp_path, [tinfo("demo-1.0.0/a", type=tarfile.SYMTYPE, linkname=".."),
                          tinfo("demo-1.0.0/b", type=tarfile.SYMTYPE, linkname="a/..")])
    msgs = [f.message for f in check_sdist(p) if f.code == "unsafe_link"]
    assert any("'demo-1.0.0/b'" in m for m in msgs)


def test_link_resolution_cases():
    links = {"r/a": "..", "r/loop1": "loop2", "r/loop2": "loop1", "r/d": "sub"}
    assert resolve_link_escapes(links, "r/b", "a/..")
    assert not resolve_link_escapes(links, "r/c", "a")              # lands on archive top, not outside
    assert resolve_link_escapes(links, "r/x", "loop1")              # cycle -> fail closed
    assert not resolve_link_escapes(links, "r/y", "d/../README")
    assert resolve_link_escapes({}, "r/z", "/etc/passwd")


# 5. member cap -------------------------------------------------------------

def test_member_cap_sdist_and_wheel(tmp_path, capsys):
    p = _sdist(tmp_path, [tinfo(f"demo-1.0.0/f{i}", b"") for i in range(30)])
    w = make_wheel(tmp_path, extra_files={f"demo/f{i}.py": "" for i in range(30)})
    assert main([p, w, "--max-members", "20", "--json"]) == 1
    found = [f["code"] for f in json.loads(capsys.readouterr().out)["findings"]]
    assert found.count("too_many_members") == 2
    assert main([p, w, "--ignore", "too_many_members"]) == 2       # locked
    assert main([p, "--max-members", "0"]) == 2
    assert doctor.MAX_MEMBERS == doctor.DEFAULT_MAX_MEMBERS          # restored after main()


def test_member_cap_is_fast(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "MAX_MEMBERS", 1000)
    p = _sdist(tmp_path, [tinfo(f"demo-1.0.0/f{i}", b"") for i in range(20_000)])
    t = time.time()
    assert codes(check_sdist(p)) == ["too_many_members"]
    assert time.time() - t < 2


# 6. --allow-path breadth -----------------------------------------------------

BROAD = ["*", "**", "**/*", "*/*", "?*", "*?", "*.*", "[!x]*", "*.py", "*e*", "*/.env", "*.pem",
         "*/*/*", "demo-1.0/*", "pkg/*", " "]
NARROW = ["tests/certs/*", "tests/fixtures/*.key", "*/tests/certs/*", "docs/examples/sample.env"]


@pytest.mark.parametrize("pattern", BROAD)
def test_broad_allow_patterns_refused(tmp_path, pattern):
    assert broad_allow_pattern(pattern) is not None
    make_wheel(tmp_path)
    assert main([str(tmp_path), "--allow-path", pattern]) == 2


@pytest.mark.parametrize("pattern", NARROW)
def test_narrow_allow_patterns_accepted(pattern):
    assert broad_allow_pattern(pattern) is None


# 7. hardlink aliasing ------------------------------------------------------

def test_hardlink_to_allowlisted_key_is_scanned(tmp_path, capsys):
    root = "demo-1.0.0"
    key = FAKE_KEY.encode()
    p = _sdist(tmp_path, [tinfo(f"{root}/tests/certs/k.pem", key),
                          tinfo(f"{root}/src/leak.txt", type=tarfile.LNKTYPE, linkname=f"{root}/tests/certs/k.pem")])
    main([p, "--allow-path", "tests/certs/*", "--json"])
    hits = [f["message"] for f in json.loads(capsys.readouterr().out)["findings"] if f["code"] == "secret_in_file"]
    assert len(hits) == 1 and "src/leak.txt" in hits[0]


def test_dangling_hardlink_flagged(tmp_path):
    p = _sdist(tmp_path, [tinfo("demo-1.0.0/x", type=tarfile.LNKTYPE, linkname="demo-1.0.0/missing")])
    assert "unsafe_link" in codes(check_sdist(p))


# 8. placeholders and large files ------------------------------------------

@pytest.mark.parametrize("text", [
    "AKIAIOSFODNN7EXAMPLE",                      # AWS's documented example key id
    "xoxb-your-token-here", "xoxb-" + "x" * 20,
    "gh" + "p_" + "x" * 36, "gh" + "p_" + "YOUR" + "a" * 32,
])
def test_placeholders_are_not_secrets(text):
    assert scan_secrets(text.encode()) == []


def test_real_looking_tokens_still_found():
    slack = "xox" + "b-123456789012-1234567890123-" + "Zq8RmT3vLp9XwY2nK"
    for tok, kind in [(FAKE_AWS, "AWS access key id"), (FAKE_GH, "GitHub token"), (slack, "Slack token")]:
        assert scan_secrets(tok.encode()) == [kind]


def test_large_files_are_scanned_not_skipped(tmp_path):
    big = "x = 1\n" * 600_000 + f"KEY = '{FAKE_AWS}'\n"     # ~3.6 MB, secret at the end
    p = make_wheel(tmp_path, extra_files={"demo/big.py": big})
    assert "secret_in_file" in codes(check_wheel(p))
    s = make_sdist(tmp_path, extra_files={"big.py": big})
    assert "secret_in_file" in codes(check_sdist(s))


def test_secret_across_chunk_boundary(tmp_path):
    pad = "#" * (doctor.CHUNK - 10)
    p = make_wheel(tmp_path, extra_files={"demo/edge.py": pad + FAKE_GH + "\n"})
    assert "secret_in_file" in codes(check_wheel(p))


def test_budget_skip_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "MAX_ARCHIVE_READ", 100)
    s = make_sdist(tmp_path, extra_files={"big.py": "y" * 1000})
    assert "archive_too_large" in codes(check_sdist(s))


def test_zip_symlink_mode_bits(tmp_path):
    p = make_wheel(tmp_path)
    with zipfile.ZipFile(p, "a") as z:
        info = zipfile.ZipInfo("demo/link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "../../etc/passwd")
    assert "zip_symlink" in codes(check_wheel(p))
