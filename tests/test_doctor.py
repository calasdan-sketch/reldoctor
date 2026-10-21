"""Artifact tests: build synthetic wheels/sdists and diagnose them."""
import io
import tarfile
import zipfile

import pytest

from reldoctor.doctor import (
    Finding,
    check_sdist,
    check_wheel,
    diagnose_dist_dir,
    normalize,
)


def make_wheel(tmp, name="demo", version="1.0.0", meta_name=None, meta_version=None,
               extra_meta="", entry_points=None, include_record=True, corrupt=False,
               license_field="License: MIT", summary="A demo package",
               requires_python=">=3.9"):
    dist = f"{name}-{version}.dist-info"
    path = tmp / f"{name}-{version}-py3-none-any.whl"
    if corrupt:
        path.write_bytes(b"not a zip at all")
        return str(path)
    meta = (
        f"Metadata-Version: 2.1\n"
        f"Name: {meta_name or name}\n"
        f"Version: {meta_version or version}\n"
        f"Summary: {summary}\n"
        f"Requires-Python: {requires_python}\n"
        f"{license_field + chr(10) if license_field else ''}"
        f"Description-Content-Type: text/markdown\n"
        f"{extra_meta}\n"
        f"# demo\n\nLong description body.\n"
    )
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{dist}/METADATA", meta)
        z.writestr(f"{dist}/WHEEL",
                   "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        z.writestr("demo/__init__.py", "__version__ = '1.0.0'\n")
        records = [f"{dist}/METADATA,,", f"{dist}/WHEEL,,", "demo/__init__.py,,"]
        if entry_points:
            z.writestr(f"{dist}/entry_points.txt", entry_points)
            records.append(f"{dist}/entry_points.txt,,")
        if include_record:
            records.append(f"{dist}/RECORD,,")
            z.writestr(f"{dist}/RECORD", "\n".join(records) + "\n")
    return str(path)


def make_sdist(tmp, name="demo", version="1.0.0", build_config="pyproject.toml",
               include_license=True, pkg_info=True):
    path = tmp / f"{name}-{version}.tar.gz"
    root = f"{name}-{version}"
    with tarfile.open(path, "w:gz") as tf:
        def add(member, data):
            info = tarfile.TarInfo(member)
            blob = data.encode()
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
        if pkg_info:
            add(f"{root}/PKG-INFO", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        if build_config:
            add(f"{root}/{build_config}", "[project]\nname = 'demo'\n")
        if include_license:
            add(f"{root}/LICENSE", "MIT license text\n")
        add(f"{root}/demo/__init__.py", "x = 1\n")
    return str(path)


def codes(findings):
    return [f.code for f in findings]


def test_normalize():
    assert normalize("Foo_Bar.baz") == "foo-bar-baz"


def test_healthy_release_is_clean(tmp_path):
    make_wheel(tmp_path)
    make_sdist(tmp_path)
    findings = diagnose_dist_dir(str(tmp_path))
    assert [f for f in findings if f.severity != "info"] == [], findings


def test_name_mismatch(tmp_path):
    make_wheel(tmp_path, meta_name="different")
    assert "name_mismatch" in codes(check_wheel(str(tmp_path / "demo-1.0.0-py3-none-any.whl")))


def test_version_mismatch_and_pep440(tmp_path):
    make_wheel(tmp_path, meta_version="1.0")
    found = codes(check_wheel(str(tmp_path / "demo-1.0.0-py3-none-any.whl")))
    assert "version_mismatch" in found


def test_bad_and_local_and_dev_versions(tmp_path):
    make_wheel(tmp_path, name="x", version="1.0", meta_version="1.0")
    assert "version_not_pep440" not in codes(check_wheel(str(tmp_path / "x-1.0-py3-none-any.whl")))

    make_wheel(tmp_path, name="y", version="1.0.0+local.1", meta_version="1.0.0+local.1")
    assert "local_version" in codes(check_wheel(str(tmp_path / "y-1.0.0+local.1-py3-none-any.whl")))

    make_wheel(tmp_path, name="z", version="2.0.0.dev3", meta_version="2.0.0.dev3")
    assert "dev_version" in codes(check_wheel(str(tmp_path / "z-2.0.0.dev3-py3-none-any.whl")))


def test_corrupt_wheel(tmp_path):
    p = make_wheel(tmp_path, corrupt=True)
    assert codes(check_wheel(p)) == ["wheel_corrupt"]


def test_missing_record(tmp_path):
    make_wheel(tmp_path, include_record=False)
    assert "no_record" in codes(check_wheel(str(tmp_path / "demo-1.0.0-py3-none-any.whl")))


def test_entry_point_validation(tmp_path):
    make_wheel(tmp_path, entry_points="[console_scripts]\ndemo = demo.cli:main\n")
    assert check_wheel(str(tmp_path / "demo-1.0.0-py3-none-any.whl")) == []

    make_wheel(tmp_path, name="bad", version="1.0.0",
               entry_points="[console_scripts]\nbad = not an entry point\n")
    assert "bad_entry_point" in codes(check_wheel(str(tmp_path / "bad-1.0.0-py3-none-any.whl")))


def test_summary_and_python_requires_warns(tmp_path):
    make_wheel(tmp_path, summary="", requires_python="")
    found = codes(check_wheel(str(tmp_path / "demo-1.0.0-py3-none-any.whl")))
    assert "no_summary" in found and "no_requires_python" in found


def test_license_found_in_license_expression_or_classifier(tmp_path):
    # SPDX License-Expression header (what modern setuptools emits)
    make_wheel(tmp_path, name="spdx", version="1.0.0",
               extra_meta="License-Expression: MIT\n", license_field="")
    assert "no_license_metadata" not in codes(
        check_wheel(str(tmp_path / "spdx-1.0.0-py3-none-any.whl")))

    # classifier-only metadata (the dict-vs-Message crash CI caught)
    make_wheel(tmp_path, name="cls", version="1.0.0",
               extra_meta="Classifier: OSI Approved :: MIT License\n", license_field="")
    assert "no_license_metadata" not in codes(
        check_wheel(str(tmp_path / "cls-1.0.0-py3-none-any.whl")))


def test_license_warns_when_truly_absent(tmp_path):
    make_wheel(tmp_path, name="nolicense", version="1.0.0", license_field="")
    assert "no_license_metadata" in codes(
        check_wheel(str(tmp_path / "nolicense-1.0.0-py3-none-any.whl")))


def test_real_world_metadata_parses_repeated_headers(tmp_path):
    # repeated Classifier headers must all survive parsing (Message, not dict)
    p = make_wheel(tmp_path, name="rep", version="1.0.0", license_field="",
                   extra_meta="Classifier: OSI Approved :: MIT License\n"
                              "Classifier: Topic :: Utilities\n")
    from reldoctor.doctor import check_wheel, parse_metadata
    import zipfile as zf
    with zf.ZipFile(p) as z:
        text = z.read("rep-1.0.0.dist-info/METADATA").decode()
    msg = parse_metadata(text)
    assert len(msg.get_all("Classifier", [])) == 2
    # license via classifier passes the strict check without crashing
    assert check_wheel(p) == [], check_wheel(p)


def test_sdist_missing_build_config(tmp_path):
    p = make_sdist(tmp_path, build_config=None)
    assert "sdist_no_build_config" in codes(check_sdist(p))


def test_sdist_missing_license_warns(tmp_path):
    p = make_sdist(tmp_path, include_license=False)
    assert "sdist_no_license_file" in codes(check_sdist(p))


def test_sdist_no_pkg_info(tmp_path):
    p = make_sdist(tmp_path, pkg_info=False)
    assert "sdist_no_pkg_info" in codes(check_sdist(p))


def test_version_drift_across_artifacts(tmp_path):
    make_wheel(tmp_path, version="1.0.0")
    make_sdist(tmp_path, version="1.0.1")
    assert "version_drift" in codes(diagnose_dist_dir(str(tmp_path)))


def test_empty_dir_and_missing_dir(tmp_path):
    assert codes(diagnose_dist_dir(str(tmp_path))) == ["no_artifacts"]
    with pytest.raises(FileNotFoundError):
        diagnose_dist_dir(str(tmp_path / "nope"))
