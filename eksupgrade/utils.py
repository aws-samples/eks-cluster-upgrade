"""Define module level utilities to be used across the EKS Upgrade package."""

import json
import pkgutil

import yaml


def get_package_asset(filename: str, base_path: str = "src/S3Files/") -> str:
    """Get the specified package asset data."""
    return pkgutil.get_data(__package__, f"{base_path}/{filename}").decode("utf-8")


def get_package_dict(filename: str, base_path: str = "src/S3Files/"):
    """Get the specified package asset data dictionary."""
    _data = get_package_asset(filename, base_path)
    return json.loads(_data)


def get_package_yaml(filename: str, base_path: str = "src/S3Files/"):
    """Get the specified package asset data YAML."""
    _data = get_package_asset(filename, base_path)
    return yaml.safe_load(_data)
