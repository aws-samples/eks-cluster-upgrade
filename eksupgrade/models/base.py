"""Define the base models to be used across the EKS upgrade tool."""
from __future__ import annotations

import logging
from abc import ABC
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Dict, Optional

import boto3

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_sts import STSClient
else:
    STSClient = object

logger = logging.getLogger(__name__)


@dataclass
class BaseResource(ABC):
    """Define the base resource for the EKS cluster upgrade tool."""

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of this object."""
        return self.__dict__


@dataclass
class AwsResource(BaseResource, ABC):
    """Define the abstract AWS base resource class."""

    arn: str
    resource_id: str = ""
    tags: Dict[str, str] = field(default_factory=lambda: ({}))

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
