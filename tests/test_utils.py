"""Test the util logic."""
from eksupgrade.utils import get_package_asset, get_package_dict


def test_get_package_asset() -> None:
    """Test the get package asset method."""
    data = get_package_asset("version_dict.json")
    assert data.startswith("{")
    assert data.endswith("\n")


def test_get_package_asset_nondefault() -> None:
    """Test the get package asset method."""
    data = get_package_asset("__init__.py", base_path="")
    assert "__version__" in data


def test_get_package_dict() -> None:
    """Test the get package dict method."""
    data = get_package_dict("version_dict.json")
    assert data["1.26"]["cluster-autoscaler"]
