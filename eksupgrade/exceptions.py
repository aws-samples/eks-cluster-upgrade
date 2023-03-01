"""Define the eksupgrade module exceptions."""


class BaseEksUpgradeException(Exception):
    """Define the base module exception for eksupgrade."""


class EksException(BaseEksUpgradeException):
    """Define the ELS module exception for eksupgrade."""


class ClusterException(EksException):
    """Define the cluster module exception for eksupgrade."""


class ClusterInactiveException(ClusterException):
    """Define the exception to raise when a cluster is considered inactive (or doesn't exist)."""
