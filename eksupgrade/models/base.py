"""Define the base models to be used across the EKS upgrade tool."""
from __future__ import annotations

import logging
from abc import ABC
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import boto3

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_autoscaling.client import AutoScalingClient
    from mypy_boto3_sts import STSClient
else:
    STSClient = object
    AutoScalingClient = object

logger = logging.getLogger(__name__)


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
            logger.info("%s: Clearing cached property: %s", self.__class__.__name__, _cached_property)
            delattr(self, _cached_property)


@dataclass
class AwsResource(BaseResource, ABC):
    """Define the abstract AWS base resource class."""

    arn: str
    resource_id: str = ""
    tags: Dict[str, str] = field(default_factory=lambda: ({}))
    errors: List[Dict[str, Any]] = field(default_factory=lambda: ([]))

    def _get_boto_client(self, service: str, **kwargs):
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
