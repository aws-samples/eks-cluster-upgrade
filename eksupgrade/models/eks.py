"""Define the models to be used across the EKS upgrade tool."""
from __future__ import annotations

import base64
import datetime
import logging
from abc import ABC
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import boto3
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

from .base import AwsRegionResource

try:
    from functools import cache
except ImportError:  # pragma: no cover
    from functools import lru_cache as cache

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_eks.client import EKSClient
    from mypy_boto3_eks.type_defs import (
        AddonInfoTypeDef,
        AddonTypeDef,
        ClusterTypeDef,
        DescribeAddonResponseTypeDef,
        DescribeClusterResponseTypeDef,
        UpdateAddonResponseTypeDef,
    )
else:
    AddonInfoTypeDef = object
    AddonTypeDef = object
    ClusterTypeDef = object
    DescribeAddonResponseTypeDef = object
    DescribeClusterResponseTypeDef = object
    EKSClient = object
    UpdateAddonResponseTypeDef = object

logger = logging.getLogger(__name__)

TOKEN_PREFIX: str = "k8s-aws-v1"
TOKEN_HEADER_KEY: str = "x-k8s-aws-id"


def requires_cluster(function):
    """Decorate methods to require a cluster attribute."""

    def wrapper(self, *args, **kwargs):
        if not self.cluster.name:
            logger.error(
                "Unable to use method: %s without the cluster attribute! Pass a cluster to this child object!",
                function.__name__,
            )
            return None
        return function(self, *args, **kwargs)

    return wrapper


@dataclass
class EksResource(AwsRegionResource, ABC):
    """Define the abstract EKS base resource class."""

    name: str = ""
    status: str = ""
    version: str = ""

    @cached_property
    def eks_client(self) -> EKSClient:
        """Get a boto EKS client."""
        return self._get_boto_client(service="eks", region_name=self.region)

    @cached_property
    def core_api_client(self) -> Any:
        """Get a Kubernetes Core client."""
        return k8s_client.CoreV1Api()

    @cached_property
    def apps_api_client(self) -> Any:
        """Get a Kubernetes Apps client."""
        return k8s_client.AppsV1Api()


@dataclass
class ClusterAddon(EksResource):
    """Define the Kubernetes Cluster Addon model."""

    health: Dict[str, List[Any]] = field(default_factory=lambda: ({"issues": []}))
    created_at: datetime.datetime = datetime.datetime.now()
    modified_at: datetime.datetime = datetime.datetime.now()
    service_account_role_arn: str = ""
    publisher: str = ""
    owner: str = ""
    product_id: str = ""
    product_url: str = ""
    configuration_values: str = ""
    cluster: Cluster = field(default_factory=lambda: Cluster(arn=""))

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a Cluster Addon."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Version: {self.version} | Last Status: {self.status}>"

    @property
    def addon_name(self) -> str:
        """Return the addon name."""
        return self.name

    @classmethod
    def get_addon(cls, addon: str, cluster: Cluster, region: str):
        """Get the cluster addon details and build a ClusterAddon object."""
        logger.debug("Getting cluster addon details...")
        _temp_cluster = cls(arn="", region=region)
        response: DescribeAddonResponseTypeDef = _temp_cluster.eks_client.describe_addon(
            addonName=addon,
            clusterName=cluster.name,
        )
        addon_data: AddonTypeDef = response["addon"]
        addon_version: str = addon_data.get("addonVersion", "")
        markplace_data = addon_data.get("marketplaceInformation", {})
        logger.debug("Addon: %s - Current Version: %s - Cluster: %s", addon, addon_version, cluster.name)

        return cls(
            arn=addon_data.get("addonArn", ""),
            name=addon_data.get("addonName", ""),
            version=addon_version,
            status=addon_data.get("status", ""),
            health=addon_data.get("health", {}),
            created_at=addon_data.get("createdAt", datetime.datetime.now()),
            modified_at=addon_data.get("modifiedAt", datetime.datetime.now()),
            tags=addon_data.get("tags", {}),
            region=region,
            service_account_role_arn=addon_data.get("serviceAccountRoleArn", ""),
            publisher=addon_data.get("publisher", ""),
            owner=addon_data.get("owner", ""),
            product_id=markplace_data.get("productId", ""),
            product_url=markplace_data.get("productUrl", ""),
            cluster=cluster,
        )

    @cached_property
    def _addon_update_kwargs(self) -> Dict[str, Any]:
        """Get kwargs for subsequent update to addon."""
        kwargs: Dict[str, Any] = {}

        if self.service_account_role_arn:
            kwargs["serviceAccountRoleArn"] = self.service_account_role_arn
        if self.configuration_values:
            kwargs["configurationValues"] = self.configuration_values
        return kwargs

    @requires_cluster
    def update_addon(self, version: str) -> UpdateAddonResponseTypeDef:
        """Update the addon to the target version."""
        logger.info("Updating the EKS cluster's %s add-on version via the EKS API...", self.name)
        update_response: UpdateAddonResponseTypeDef = self.eks_client.update_addon(
            clusterName=self.cluster.name,
            addonName=self.name,
            addonVersion=version,
            resolveConflicts="OVERWRITE",
            **self._addon_update_kwargs,
        )
        return update_response


@dataclass
class Cluster(EksResource):
    """Define the Kubernetes Cluster model."""

    certificate_authority_data: str = ""
    identity_oidc_issuer: str = ""
    endpoint: str = ""
    role_arn: str = ""
    platform_version: str = ""
    secrets_key_arn: str = ""
    cluster_logging_enabled: bool = False

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a Cluster."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Version: {self.version} | Last Status: {self.status}>"

    def __post_init__(self) -> None:
        """Perform the post initialization steps."""
        self._register_k8s_aws_id_handlers()
        self.load_config()

    def _register_k8s_aws_id_handlers(self) -> None:
        """Register the kubernetes AWS ID header handlers."""
        self.sts_client.meta.events.register(
            "provide-client-params.sts.GetCallerIdentity",
            self._retrieve_k8s_aws_id,
        )
        self.sts_client.meta.events.register(
            "before-sign.sts.GetCallerIdentity",
            self._inject_k8s_aws_id_header,
        )

    def _retrieve_k8s_aws_id(self, params, context, **_) -> None:
        """Retrieve the kubernetes AWS ID header for use in boto3 request headers."""
        if TOKEN_HEADER_KEY in params:
            context[TOKEN_HEADER_KEY] = params.pop(TOKEN_HEADER_KEY)
            logger.debug("Retrieving cluster header %s: %s", TOKEN_HEADER_KEY, context[TOKEN_HEADER_KEY])

    def _inject_k8s_aws_id_header(self, request, **_) -> None:
        """Inject the kubernetes AWS ID header into boto3 request headers."""
        if TOKEN_HEADER_KEY in request.context:
            request.headers[TOKEN_HEADER_KEY] = request.context[TOKEN_HEADER_KEY]
            logger.debug("Patching boto3 STS calls with cluster headers: %s", request.headers)

    def _get_presigned_url(self, url_timeout: int = 60) -> str:
        """Get the presigned URL."""
        logger.debug("Generating the pre-signed url for get-caller-identity...")
        return self.sts_client.generate_presigned_url(
            "get_caller_identity",
            Params={TOKEN_HEADER_KEY: self.cluster_identifier},
            ExpiresIn=url_timeout,
            HttpMethod="GET",
        )

    @cached_property
    def _current_addons(self) -> List[str]:
        """Return a list of addon names currently installed in the cluster."""
        logger.debug("Getting the list of current cluster addons for cluster: %s...", self.name)
        return self.eks_client.list_addons(clusterName=self.name).get("addons", [])

    @property
    def cluster_name(self) -> str:
        """Return the cluster name."""
        return self.name

    @property
    def cluster_identifier(self) -> str:
        """Return the preferred identifier for the cluster.

        If the cluster is a local cluster deployed on AWS Outposts, the resource ID must be used.
        If not, use the cluster name.

        """
        return self.resource_id or self.name

    @cached_property
    def addons(self) -> List[ClusterAddon]:
        """Return a list of cluster addons currently setup in the cluster."""
        logger.debug("Fetching Cluster Addons...")
        return [ClusterAddon.get_addon(addon, self, self.region) for addon in self._current_addons]

    def get_token(self) -> str:
        """Generate a presigned url token to pass to client."""
        logger.debug("Getting the pre-signed STS token...")
        url = self._get_presigned_url()
        suffix: str = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
        token = f"{TOKEN_PREFIX}.{suffix}"
        return token

    @property
    def user_config(self) -> Dict[str, Union[str, List[Dict[str, Any]]]]:
        """Get a configuration for the Kubernetes client library.

        The credentials of the given portal user are used, access is restricted to the default namespace.

        """
        config_data: Dict[str, Union[str, List[Dict[str, Any]]]] = {
            "current-context": self.cluster_name,
            "contexts": [
                {
                    "name": self.cluster_name,
                    "context": {
                        "cluster": self.cluster_name,
                        "user": self.arn,
                    },
                }
            ],
            "clusters": [
                {
                    "name": self.cluster_name,
                    "cluster": {
                        "certificate-authority-data": self.certificate_authority_data,
                        "server": self.endpoint,
                    },
                }
            ],
            "users": [
                {
                    "name": self.arn,
                    "user": {
                        "token": self.get_token(),
                    },
                }
            ],
        }
        return config_data

    def load_config(self, user_config: Optional[Dict[str, Any]] = None) -> None:
        """Load the Kubernetes configuration."""
        logger.debug("Loading Kubernetes config from user config dictionary...")
        user_config = user_config or self.user_config
        k8s_config.load_kube_config_from_dict(user_config)
        logger.debug("Loaded kubernetes config from user config!")

    @classmethod
    def get_cluster(cls, cluster_name: str, region: str):
        """Get the cluster details and build a Cluster."""
        logger.debug("Getting cluster details...")
        eks_client = boto3.client("eks", region_name=region)

        response: DescribeClusterResponseTypeDef = eks_client.describe_cluster(
            name=cluster_name,
        )
        cluster_data: ClusterTypeDef = response["cluster"]

        # If encryption config is present, use it to populate secrets ARN.
        try:
            _secrets_key_arn: str = cluster_data["encryptionConfig"][0]["provider"]["keyArn"]
        except (KeyError, IndexError):
            logger.debug("No secrets key ARN found for cluster... defaulting to empty string.")
            _secrets_key_arn = ""

        return cls(
            arn=cluster_data.get("arn", ""),
            name=cluster_data.get("name", ""),
            resource_id=cluster_data.get("id", ""),
            certificate_authority_data=cluster_data.get("certificateAuthority", {}).get("data", ""),
            endpoint=cluster_data.get("endpoint", ""),
            version=cluster_data.get("version", ""),
            status=cluster_data.get("status", ""),
            platform_version=cluster_data.get("platformVersion", ""),
            role_arn=cluster_data.get("roleArn", ""),
            identity_oidc_issuer=cluster_data.get("identity", {}).get("oidc", {}).get("issuer", ""),
            secrets_key_arn=_secrets_key_arn,
            region=region,
        )

    @cache
    def get_available_addon_versions(self, kubernetes_version: str) -> List[AddonInfoTypeDef]:
        """Get the available addon versions for the associated Kubernetes version."""
        addon_versions: List[AddonInfoTypeDef] = self.eks_client.describe_addon_versions(
            kubernetesVersion=kubernetes_version
        ).get("addons", [])
        return addon_versions

    @cache
    def get_versions_by_addon(self, addon: str, kubernetes_version: str) -> AddonInfoTypeDef:
        """Get target addon versions."""
        addon_versions: List[AddonInfoTypeDef] = self.get_available_addon_versions(kubernetes_version)
        return next(item for item in addon_versions if item.get("addonName", "") == addon)

    @cache
    def get_default_version(self, addon: str, kubernetes_version: str) -> str:
        """Get the EKS default version of the addon."""
        addon_dict: AddonInfoTypeDef = self.get_versions_by_addon(addon, kubernetes_version)
        return next(
            item.get("addonVersion", "")
            for item in addon_dict.get("addonVersions", [])
            if item.get("compatibilities", [])[0].get("defaultVersion", False) is True
        )
