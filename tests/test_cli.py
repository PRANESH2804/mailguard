"""Unit tests for the Command Line Interface (CLI)."""

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from mailguard.cli import main


def test_cli_help(capsys):
    with patch("sys.argv", ["mailguard"]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        assert "MailGuard" in captured.out or "usage" in captured.out.lower()


def test_cli_analyze_single_file_offline(capsys):
    test_eml = Path("samples/legit/legit_01_standard_auth.eml")
    if not test_eml.is_file():
        pytest.skip("Sample file not generated")

    with patch("sys.argv", ["mailguard", "analyze", str(test_eml), "--offline"]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        assert "MAILGUARD" in captured.out or "LEGITIMATE" in captured.out


def test_cli_analyze_json_format(capsys):
    test_eml = Path("samples/legit/legit_01_standard_auth.eml")
    if not test_eml.is_file():
        pytest.skip("Sample file not generated")

    with patch("sys.argv", ["mailguard", "analyze", str(test_eml), "--offline", "--format", "json"]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "LEGITIMATE"
        assert "spf" in data


def test_cli_analyze_nonexistent_file(capsys):
    with patch("sys.argv", ["mailguard", "analyze", "nonexistent_file.eml"]):
        ret = main()
        assert ret == 1
        captured = capsys.readouterr()
        assert "failed" in captured.out.lower()


def test_cli_analyze_dir_offline(capsys):
    samples_dir = Path("samples/legit")
    if not samples_dir.is_dir():
        pytest.skip("Samples directory not present")

    with patch("sys.argv", ["mailguard", "analyze-dir", str(samples_dir), "--offline", "--format", "table"]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        assert "Batch Email Analysis Summary" in captured.out or "LEGITIMATE" in captured.out
