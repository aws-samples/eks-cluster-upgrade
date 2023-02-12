"""Test the functionality of the CLI module."""
from unittest import mock

import pytest

from eksupgrade.cli import entry, get_eks_supported_regions


@pytest.fixture
def mock_regions():
    with mock.patch("eksupgrade.cli.get_eks_supported_regions"):
        mock_obj = mock.MagicMock()
        mock_obj.get_available_regions.return_value = ["TEST_REGION"]
        yield mock_obj


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


@mock.patch("boto3.session.Session")
def test_get_eks_supported_regions(boto_session) -> None:
    """Test the helper method which retrieves the active regions for eks"""
    mock_session = boto_session.return_value
    mock_session.get_available_regions.return_value = ["TEST_REGION"]

    assert get_eks_supported_regions() == ["TEST_REGION", "TEST_REGION"]
    assert mock_session.get_available_regions.call_count == 2
