"""CLI tests."""
import json

from reldoctor.cli import main
from tests.test_doctor import make_sdist, make_wheel


def test_healthy_dir_passes(tmp_path, capsys):
    make_wheel(tmp_path)
    make_sdist(tmp_path)
    assert main([str(tmp_path)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_errors_fail_and_json_reports(tmp_path, capsys):
    make_wheel(tmp_path, version="1.0.0", meta_version="9.9.9")
    code = main([str(tmp_path), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and out["errors"] >= 1
    assert any(f["code"] == "version_mismatch" for f in out["findings"])


def test_strict_fails_on_warnings(tmp_path, capsys):
    make_wheel(tmp_path)
    # sdist-only dir: missing_wheel warning
    assert main([str(tmp_path)]) == 0
    capsys.readouterr()
    assert main([str(tmp_path), "--strict"]) == 1


def test_missing_dir_is_usage_error(tmp_path):
    assert main([str(tmp_path / "absent")]) == 2
