"""Define the eksupgrade module exceptions."""


class BaseEksUpgradeException(Exception):
    """Define the base module exception for eksupgrade."""


class EksException(BaseEksUpgradeException):
    """Define the ELS module exception for eksupgrade."""


class ClusterException(EksException):
    """Define the cluster module exception for eksupgrade."""


class ClusterInactiveException(ClusterException):
    """Define the exception to raise when a cluster is considered inactive (or doesn't exist)."""


class EksUpgradeNotImplementedError(BaseEksUpgradeException, NotImplementedError):
    """Define the Not Implemented exception for eksupgrade."""


class InvalidUpgradeTargetVersion(BaseEksUpgradeException):
    """Define the exception to be raised when invalid target versions are provided."""
