"""Define module level utilities to be used across the EKS Upgrade package."""
import json
import logging
import pkgutil
import sys


def get_package_asset(filename: str, base_path: str = "src/S3Files/") -> str:
    """Get the specified package asset data."""
    return pkgutil.get_data(__package__, f"{base_path}/{filename}").decode("utf-8")


def get_package_dict(filename: str, base_path: str = "src/S3Files/"):
    """Get the specified package asset data dictionary."""
    _data = get_package_asset(filename, base_path)
    return json.loads(_data)


def get_logger(logger_name):
    """Get a logger object with handler to StreamHandler"""
    logger = logging.getLogger(logger_name)
    console_handler = logging.StreamHandler(sys.stdout)
    log_formatter = logging.Formatter(
        "[%(levelname)s] : %(asctime)s : %(name)s.%(lineno)d : %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)
    logger.propagate = False
    return logger
