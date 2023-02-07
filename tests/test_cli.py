"""Test the functionality of the CLI module."""
import pytest

from eksupgrade.cli import entry


def test_entry_version_arg(capsys) -> None:
    """Test the entry method with version argument."""
    with pytest.raises(SystemExit):
        entry(["--version"])

    captured = capsys.readouterr()
    result = captured.out
    assert result.startswith("eksupgrade")


def test_entry_no_arg(capsys) -> None:
    """Test the entry method with no arguments."""
    with pytest.raises(SystemExit):
        entry()

    captured = capsys.readouterr()
    result = captured.out
    assert result.startswith("")
