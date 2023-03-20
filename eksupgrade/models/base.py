"""Define the base models to be used across the EKS upgrade tool."""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, Union

import boto3

from eksupgrade.utils import echo_info, echo_success, get_logger

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_autoscaling.client import AutoScalingClient
    from mypy_boto3_ec2.client import EC2Client
    from mypy_boto3_eks.client import EKSClient
    from mypy_boto3_sts.client import STSClient
else:
    AutoScalingClient = object
    EC2Client = object
    EKSClient = object
    STSClient = object

logger = get_logger(__name__)


@dataclass
class BaseResource(ABC):
    """Define the base resource for the EKS cluster upgrade tool."""

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of this object."""
        return self.__dict__

    def clear_cached_properties(self) -> None:
        """Clear all cached properties."""
        cls = type(self)

        def get_cached_properties(instance_type) -> List[str]:
            """Get the list of properties matching the instance type."""
            return [
                attribute
                for attribute, _ in self.to_dict().items()
                if (instance := getattr(cls, attribute, None))
                if isinstance(instance, instance_type)
            ]

        _cached_properties: List[str] = get_cached_properties(cached_property)

        for _cached_property in _cached_properties:
            echo_info(f"{self.__class__.__name__}: Clearing cached property: {_cached_property}")
            delattr(self, _cached_property)
        echo_success("Cached properties cleared!")


@dataclass
class AwsResource(BaseResource, ABC):
    """Define the abstract AWS base resource class."""

    arn: str
    resource_id: str = ""
    tags: Dict[str, Union[str, bool]] = field(default_factory=lambda: ({}))
    errors: List[Dict[str, Any]] = field(default_factory=lambda: ([]))

    def _get_boto_client(
        self, service: Literal["autoscaling", "ec2", "eks", "sts"], **kwargs
    ) -> AutoScalingClient | EC2Client | EKSClient | STSClient:
        """Get a boto client."""
        return boto3.client(service, **kwargs)

    @cached_property
    def sts_client(self) -> STSClient:
        """Get a boto STS client."""
        boto_kwargs: Dict[str, Any] = {}
        region: Optional[str] = getattr(self, "region", "")

        if region:
            boto_kwargs["region_name"] = region

        return self._get_boto_client(service="sts", **boto_kwargs)


@dataclass
class AwsRegionResource(AwsResource, ABC):
    """Define the abstract AWS region specific base resource class."""

    region: str = ""

    @cached_property
    def autoscaling_client(self) -> AutoScalingClient:
        """Get a boto autoscaling client."""
        return self._get_boto_client(service="autoscaling", region_name=self.region)
