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
from packaging.version import parse as parse_version

from .base import AwsRegionResource

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_eks.client import EKSClient
    from mypy_boto3_eks.literals import ResolveConflictsType
    from mypy_boto3_eks.type_defs import (
        AddonInfoTypeDef,
        AddonTypeDef,
        AutoScalingGroupsTypeTypeDef,
        ClusterTypeDef,
        DescribeAddonResponseTypeDef,
        DescribeClusterResponseTypeDef,
        DescribeNodegroupResponseTypeDef,
        ListNodegroupsResponseTypeDef,
        NodegroupResourcesTypeDef,
        NodegroupTypeDef,
        UpdateAddonResponseTypeDef,
        UpdateClusterVersionResponseTypeDef,
        UpdateTypeDef,
        WaiterConfigTypeDef,
    )
else:
    AddonInfoTypeDef = object
    AddonTypeDef = object
    ClusterTypeDef = object
    DescribeAddonResponseTypeDef = object
    DescribeClusterResponseTypeDef = object
    EKSClient = object
    UpdateAddonResponseTypeDef = object
    ResolveConflictsType = object
    UpdateTypeDef = object
    UpdateClusterVersionResponseTypeDef = object
    DescribeNodegroupResponseTypeDef = object
    NodegroupTypeDef = object
    ListNodegroupsResponseTypeDef = object
    NodegroupResourcesTypeDef = object
    WaiterConfigTypeDef = object
    AutoScalingGroupsTypeTypeDef = object

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
class AutoscalingGroup(AwsRegionResource):
    """Define the Autoscaling Group model."""

    cluster: Cluster = field(default_factory=lambda: Cluster(arn="", version="1.24"))
    name: str = ""
    launch_configuration_name: str = ""
    launch_template: Dict[str, str] = field(default_factory=dict)
    mixed_instance_policy: List[Dict[str, Any]] = field(default_factory=list)
    min_size: int = 0
    max_size: int = 0
    desired_capacity: int = 0
    predicted_capacity: int = 0
    default_cooldown: int = 0
    availability_zones: List[str] = field(default_factory=list)
    load_balancer_names: List[str] = field(default_factory=list)
    target_group_arns: List[str] = field(default_factory=list)
    health_check_type: str = ""
    health_check_grace_period: int = 0
    instances: List[Dict[str, Any]] = field(default_factory=list)
    placement_group: str = ""
    created_at: datetime.datetime = datetime.datetime.now()
    suspended_processes: List[Dict[str, str]] = field(default_factory=list)
    vpc_zone_identifier: str = ""
    status: str = ""
    termination_policies: List[str] = field(default_factory=list)
    new_instances_protected_from_scale_in: bool = False
    service_linked_role_arn: str = ""
    max_instance_lifetime: int = 0
    capacity_rebalance: bool = False
    warm_pool_size: int = 0
    context: str = ""
    desired_capacity_type: str = ""
    default_instance_warmup: int = 0
    traffic_sources: List[Dict[str, str]] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a EKS Managed Node Group."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Launch Config: {self.launch_configuration_name} | Last Status: {self.status}>"

    @property
    def asg_name(self) -> str:
        """Return the autoscaling group name."""
        return self.name

    @classmethod
    def get_nodegroup(cls, autoscaling_group_name: str, cluster: Cluster, region: str):
        """Get the cluster's manage nodegroup details and build a ManagedNodeGroup object."""
        logger.info("Getting cluster autoscaling group details...")
        _temp_asg = cls(arn="", region=region)
        response: AutoScalingGroupsTypeTypeDef = _temp_asg.autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name],
        )
        nodegroup_data: NodegroupTypeDef = response["AutoScalingGroups"]
        version: str = nodegroup_data.get("version", "")
        release_version: str = nodegroup_data.get("releaseVersion", "")
        logger.info(
            "Managed Node Group: %s - Version: %s - Release Version: %s - Cluster: %s",
            node_group,
            version,
            release_version,
            cluster.name,
        )
        _resources: NodegroupResourcesTypeDef = nodegroup_data.get("resources", {})

        return cls(
            cluster=cluster,
            version=version,
            release_version=release_version,
            arn=nodegroup_data.get("nodegroupArn", ""),
            name=nodegroup_data.get("nodegroupName", ""),
            status=nodegroup_data.get("status", ""),
            created_at=nodegroup_data.get("createdAt", datetime.datetime.now()),
            modified_at=nodegroup_data.get("modifiedAt", datetime.datetime.now()),
            tags=nodegroup_data.get("tags", {}),
            region=region,
            node_role=nodegroup_data.get("nodeRole", ""),
            capacity_type=nodegroup_data.get("capacityType", ""),
            ami_type=nodegroup_data.get("amiType", ""),
            instance_types=nodegroup_data.get("instanceTypes", []),
            subnets=nodegroup_data.get("subnets", []),
            disk_size=nodegroup_data.get("diskSize", 0),
            labels=nodegroup_data.get("labels", {}),
            taints=nodegroup_data.get("taints", []),
            remote_access_sg=_resources.get("remoteAccessSecurityGroup", ""),
            update_config=nodegroup_data.get("updateConfig", {}),
            launch_template=nodegroup_data.get("launchTemplate", {}),
            autoscaling_groups=_resources.get("autoScalingGroups", []),
            scaling_config=nodegroup_data.get("scalingConfig", {}),
            remote_access=nodegroup_data.get("remoteAccess", {}),
            health=nodegroup_data.get("health", {}),
        )


@dataclass
class ManagedNodeGroup(EksResource):
    """Define the EKS Manage Node Group model."""

    cluster: Cluster = field(default_factory=lambda: Cluster(arn="", version="1.24"))
    remote_access: Dict[str, Any] = field(default_factory=dict)
    health: Dict[str, List[Any]] = field(default_factory=lambda: ({"issues": []}))
    labels: Dict[str, str] = field(default_factory=dict)
    update_config: Dict[str, int] = field(default_factory=dict)
    launch_template: Dict[str, Any] = field(default_factory=dict)
    scaling_config: Dict[str, int] = field(default_factory=dict)
    instance_types: List[str] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    autoscaling_groups: List[Dict[str, str]] = field(default_factory=list)
    taints: List[Dict[str, str]] = field(default_factory=list)
    created_at: datetime.datetime = datetime.datetime.now()
    modified_at: datetime.datetime = datetime.datetime.now()
    release_version: str = ""
    remote_access_sg: str = ""
    node_role: str = ""
    publisher: str = ""
    owner: str = ""
    product_id: str = ""
    disk_size: int = 0
    ami_type: str = ""
    capacity_type: str = ""

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a EKS Managed Node Group."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Version: {self.version} | Last Status: {self.status}>"

    def __post_init__(self) -> None:
        """Perform the post initialization steps."""
        self.active_waiter = self.eks_client.get_waiter("nodegroup_active")

    @property
    def nodegroup_name(self) -> str:
        """Return the nodegroup name."""
        return self.name

    @cached_property
    def autoscaling_group_names(self) -> List[str]:
        """Return the list of autoscaling group names."""
        return [asg["name"] for asg in self.autoscaling_groups]

    @classmethod
    def get_nodegroup(cls, node_group: str, cluster: Cluster, region: str):
        """Get the cluster's manage nodegroup details and build a ManagedNodeGroup object."""
        logger.info("Getting cluster managed nodegroup details...")
        _temp_nodegroup = cls(arn="", region=region)
        response: DescribeNodegroupResponseTypeDef = _temp_nodegroup.eks_client.describe_nodegroup(
            nodegroupName=node_group,
            clusterName=cluster.name,
        )
        nodegroup_data: NodegroupTypeDef = response["nodegroup"]
        version: str = nodegroup_data.get("version", "")
        release_version: str = nodegroup_data.get("releaseVersion", "")
        logger.info(
            "Managed Node Group: %s - Version: %s - Release Version: %s - Cluster: %s",
            node_group,
            version,
            release_version,
            cluster.name,
        )
        _resources: NodegroupResourcesTypeDef = nodegroup_data.get("resources", {})

        return cls(
            cluster=cluster,
            version=version,
            release_version=release_version,
            arn=nodegroup_data.get("nodegroupArn", ""),
            name=nodegroup_data.get("nodegroupName", ""),
            status=nodegroup_data.get("status", ""),
            created_at=nodegroup_data.get("createdAt", datetime.datetime.now()),
            modified_at=nodegroup_data.get("modifiedAt", datetime.datetime.now()),
            tags=nodegroup_data.get("tags", {}),
            region=region,
            node_role=nodegroup_data.get("nodeRole", ""),
            capacity_type=nodegroup_data.get("capacityType", ""),
            ami_type=nodegroup_data.get("amiType", ""),
            instance_types=nodegroup_data.get("instanceTypes", []),
            subnets=nodegroup_data.get("subnets", []),
            disk_size=nodegroup_data.get("diskSize", 0),
            labels=nodegroup_data.get("labels", {}),
            taints=nodegroup_data.get("taints", []),
            remote_access_sg=_resources.get("remoteAccessSecurityGroup", ""),
            update_config=nodegroup_data.get("updateConfig", {}),
            launch_template=nodegroup_data.get("launchTemplate", {}),
            autoscaling_groups=_resources.get("autoScalingGroups", []),
            scaling_config=nodegroup_data.get("scalingConfig", {}),
            remote_access=nodegroup_data.get("remoteAccess", {}),
            health=nodegroup_data.get("health", {}),
        )

    @property
    def needs_upgrade(self) -> bool:
        """Determine whether or not the managed nodegroup needs upgraded."""
        if self.status in ["ACTIVE", "UPDATING"] and not self.version == self.cluster.target_version:
            logger.info(
                "Managed Node Group: %s requires upgrade from version: %s to target version: %s",
                self.name,
                self.version,
                self.cluster.target_version,
            )
            return True
        return False

    @requires_cluster
    def update(
        self,
        version: str = "",
        release_version: str = "",
        force: bool = False,
        client_request_id: str = "",
        launch_template: Optional[Dict[str, Any]] = None,
        wait: bool = True,
    ) -> UpdateTypeDef:
        """Update the nodegroup to the target version."""
        update_kwargs: Dict[str, Any] = {}

        if not launch_template:
            update_kwargs["version"] = version or self.cluster.target_version
        elif launch_template and not version:
            update_kwargs["launchTemplate"] = launch_template
        elif launch_template and (self.ami_type != "CUSTOM" and version):
            update_kwargs["launchTemplate"] = launch_template
            update_kwargs["version"] = version
        elif launch_template and (self.ami_type == "CUSTOM" and version):
            logger.error("Version and launch template provided to managed nodegroug update with custom AMI!")

        if release_version:
            update_kwargs["releaseVersion"] = release_version

        if client_request_id:
            update_kwargs["clientRequestToken"] = client_request_id

        logger.info("Updating nodegroup: %s from version: %s to version: %s", self.name, self.version, version)
        update_response = self.eks_client.update_nodegroup_version(
            clusterName=self.cluster.name, nodegroupName=self.name, force=force, **update_kwargs
        )
        update_response_body: UpdateTypeDef = update_response["update"]
        _update_errors = update_response_body.get("errors", [])

        if _update_errors:
            logger.error(
                "Errors encountered while attempting to update addon: %s - Errors: %s", self.name, _update_errors
            )
            self.errors += _update_errors
        elif wait:
            self.wait_for_active()

        return update_response_body

    def wait_for_active(self, delay: int = 30, max_attempts: int = 80):
        """Wait for the nodegroup to become active."""
        waiter_config: WaiterConfigTypeDef = {"Delay": delay, "MaxAttempts": max_attempts}
        self.active_waiter.wait(clusterName=self.cluster.name, nodegroupName=self.name, WaiterConfig=waiter_config)


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
    cluster: Cluster = field(default_factory=lambda: Cluster(arn="", version="1.24"))

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a Cluster Addon."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Version: {self.version} | Last Status: {self.status}>"

    def __post_init__(self) -> None:
        """Perform the post initialization steps."""
        self.active_waiter = self.eks_client.get_waiter("addon_active")

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
    def update(
        self,
        version: str = "",
        resolve_conflicts: ResolveConflictsType = "OVERWRITE",
        latest: bool = False,
        wait: bool = False,
    ) -> UpdateTypeDef:
        """Update the addon to the target version."""
        logger.info("Updating addon: %s from version: %s to version: %s", self.name, self.version, self.default_version)
        version = version or self.latest_version if latest else self.default_version
        update_response: UpdateAddonResponseTypeDef = self.eks_client.update_addon(
            clusterName=self.cluster.name,
            addonName=self.name,
            addonVersion=version,
            resolveConflicts=resolve_conflicts,
            **self._addon_update_kwargs,
        )
        update_response_body: UpdateTypeDef = update_response["update"]
        _update_errors = update_response_body.get("errors", [])

        if _update_errors:
            logger.error(
                "Errors encountered while attempting to update addon: %s - Errors: %s", self.name, _update_errors
            )
            self.errors += _update_errors
        elif wait:
            self.wait_for_active()

        return update_response_body

    @cached_property
    def available_versions(self) -> AddonInfoTypeDef:
        """Get target addon versions."""
        return next(item for item in self.cluster.available_addon_versions if item.get("addonName", "") == self.name)

    @cached_property
    def default_version(self) -> str:
        """Get the EKS default version of the addon."""
        return next(
            item.get("addonVersion", "")
            for item in self.available_versions.get("addonVersions", [])
            if item.get("compatibilities", [])[0].get("defaultVersion", False) is True
        )

    @property
    def latest_version(self) -> str:
        """Return the latest version."""
        return sorted(self.available_versions, reverse=True, key=parse_version)[0]

    @property
    def needs_upgrade(self) -> bool:
        """Determine whether or not this addon should be upgraded."""
        return parse_version(self.version) < parse_version(self.default_version)

    def wait_for_active(self, delay: int = 30, max_attempts: int = 80):
        """Wait for the addon to become active."""
        waiter_config: WaiterConfigTypeDef = {"Delay": delay, "MaxAttempts": max_attempts}
        self.active_waiter.wait(clusterName=self.cluster.name, addonName=self.name, WaiterConfig=waiter_config)


@dataclass
class Cluster(EksResource):
    """Define the Kubernetes Cluster model.

    Attributes:
        certificate_authority_data: The certificate authority data.
        identity_oidc_issuer: The OIDC identity issuer.
        endpoint: The EKS endpoint.
        role_arn: The EKS cluster role ARN.
        platform_version: The EKS cluster platform version.
        secrets_key_arn: The EKS cluster's secrets key ARN.
        cluster_logging_enabled: Whether or not cluster logging is enabled.

    Properties:
        target_version: The target cluster version post upgrade.

    """

    certificate_authority_data: str = ""
    identity_oidc_issuer: str = ""
    endpoint: str = ""
    role_arn: str = ""
    platform_version: str = ""
    secrets_key_arn: str = ""
    cluster_logging_enabled: bool = False
    target_version: str = ""
    latest_addons: bool = False

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a Cluster."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Version: {self.version} | Last Status: {self.status}>"

    def __post_init__(self) -> None:
        """Perform the post initialization steps."""
        self._register_k8s_aws_id_handlers()
        self.load_config()
        self.target_version = self.target_version or str(float(self.version) + 0.01)
        self.active_waiter = self.eks_client.get_waiter("cluster_active")

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
        """Get the pre-signed URL.

        Arguments:
            url_timeout: The number of seconds to lease the pre-signed URL for.
                Defaults to: 60.

        Returns:
            The pre-signed URL.
        """
        logger.debug("Generating the pre-signed url for get-caller-identity...")
        return self.sts_client.generate_presigned_url(
            "get_caller_identity",
            Params={TOKEN_HEADER_KEY: self.cluster_identifier},
            ExpiresIn=url_timeout,
            HttpMethod="GET",
        )

    @cached_property
    def current_addons(self) -> List[str]:
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
        """Get the list of current cluster addons.

        Returns:
            The list of `ClusterAddon` objects.

        """
        logger.debug("Fetching Cluster Addons...")
        return [ClusterAddon.get_addon(addon, self, self.region) for addon in self.current_addons]

    @cached_property
    def needs_upgrade(self) -> bool:
        """Determine whether or not this addon should be upgraded."""
        return parse_version(self.version) < parse_version(self.target_version)

    @cached_property
    def upgradable_addons(self) -> List[ClusterAddon]:
        """Get a list of addons that require upgrade."""
        return [addon for addon in self.addons if addon.needs_upgrade]

    @cached_property
    def upgradable_managed_nodegroups(self) -> List[ManagedNodeGroup]:
        """Get a list of managed nodegroups that require upgrade."""
        return [nodegroup for nodegroup in self.nodegroups if nodegroup.needs_upgrade]

    def update_cluster(self, wait: bool = True) -> UpdateTypeDef:
        """Upgrade the cluster itself."""
        logger.info(
            "Upgrading cluster: %s from version: %s to version: %s", self.name, self.version, self.target_version
        )
        update_response: UpdateClusterVersionResponseTypeDef = self.eks_client.update_cluster_version(
            name=self.name, version=self.target_version
        )
        update_response_body: UpdateTypeDef = update_response["update"]
        _update_errors = update_response_body.get("errors", [])

        if _update_errors:
            logger.error(
                "Errors encountered while attempting to update cluster: %s - Errors: %s", self.name, _update_errors
            )
            self.errors += _update_errors
        elif wait:
            self.wait_for_active()
        return update_response_body

    def upgrade_addons(self, wait: bool = False) -> Dict[str, Any]:
        """Upgrade all cluster addons."""
        upgrade_details: Dict[str, Any] = {}
        for addon in self.upgradable_addons:
            _update_response: UpdateTypeDef = addon.update(wait=wait)
            _update_id: str = _update_response.get("id", "")
            _update_status: str = _update_response.get("status", "")
            logger.info("Updating addon: %s - ID: %s - Status: %s", addon.name, _update_id, _update_status)
            upgrade_details[addon.name] = _update_response
        return upgrade_details

    def upgrade_nodegroups(self, wait: bool = False) -> Dict[str, Any]:
        """Upgrade all EKS managed nodegroups."""
        upgrade_details: Dict[str, Any] = {}
        for nodegroup in self.upgradable_managed_nodegroups:
            _update_response: UpdateTypeDef = nodegroup.update(wait=wait)
            _update_id: str = _update_response.get("id", "")
            _update_status: str = _update_response.get("status", "")
            logger.info("Updating nodegroup: %s - ID: %s - Status: %s", nodegroup.name, _update_id, _update_status)
            upgrade_details[nodegroup.name] = _update_response
        return upgrade_details

    def get_token(self) -> str:
        """Generate a presigned url token to pass to client.

        Returns:
            The pre-signed STS token for use in the Kubernetes configuration.

        """
        logger.debug("Getting the pre-signed STS token...")
        url = self._get_presigned_url()
        suffix: str = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
        token = f"{TOKEN_PREFIX}.{suffix}"
        return token

    @property
    def user_config(self) -> Dict[str, Union[str, List[Dict[str, Any]]]]:
        """Get a configuration for the Kubernetes client library.

        The credentials of the given portal user are used, access is restricted to the default namespace.

        Returns:
            The dictionary representation of Kubernetes configuration for the current cluster.

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
        """Load the Kubernetes configuration.

        Arguments:
            user_config: The Kubernetes configuration to be used with the client.
                Defaults to: The current cluster's pre-populated configuration from `Cluster.user_config`.

        Returns:
            None.

        """
        logger.debug("Loading Kubernetes config from user config dictionary...")
        user_config = user_config or self.user_config
        k8s_config.load_kube_config_from_dict(user_config)
        logger.debug("Loaded kubernetes config from user config!")

    @property
    def available(self) -> bool:
        """Whether or not the cluster exists and is active."""
        return self.status in ["ACTIVE", "UPDATING"]

    @property
    def active(self) -> bool:
        """Whether or not the cluster exists and is active."""
        return self.status == "ACTIVE"

    @property
    def updating(self) -> bool:
        """Whether or not the cluster exists and is active."""
        return self.status == "UPDATING"

    def get_asgs(self) -> List[str]:
        """Get a list of ASGs by cluster and region.

        We get a list of ASGs (auto scaling groups) which will mach our format
        "kubernetes.io/cluster/{cluster_name}"
        and returns an empty list if none are found

        """
        cluster_tag = f"kubernetes.io/cluster/{self.name}"
        response = self.autoscaling_client.describe_auto_scaling_groups(
            Filters=[{"Name": "tag-key", "Values": [cluster_tag]}]
        ).get("AutoScalingGroups", [])
        return [asg["AutoScalingGroupName"] for asg in response]

    @cached_property
    def available_addon_versions(self) -> List[AddonInfoTypeDef]:
        """Get the available addon versions for the associated Kubernetes version."""
        addon_versions: List[AddonInfoTypeDef] = self.eks_client.describe_addon_versions(
            kubernetesVersion=self.target_version
        ).get("addons", [])
        return addon_versions

    @cached_property
    def nodegroup_names(self) -> List[str]:
        """Get the cluster's associated nodegroups."""
        response: ListNodegroupsResponseTypeDef = self.eks_client.list_nodegroups(clusterName=self.name, maxResults=100)
        return response["nodegroups"]

    @cached_property
    def nodegroups(self) -> List[ManagedNodeGroup]:
        """Get the cluster's associated nodegroups."""
        return [
            ManagedNodeGroup.get_nodegroup(node_group=nodegroup, cluster=self, region=self.region)
            for nodegroup in self.nodegroup_names
        ]

    @classmethod
    def get_cluster(cls, cluster_name: str, region: str, target_version: str = "", latest_addons: bool = False):
        """Get the cluster details and build a Cluster.

        Arguments:
            cluster_name: The name the of the cluster.
            region: The AWS region where the cluster resides.
            target_version: The target cluster version of this upgrade.
                Defaults to: The current cluster version + 1 minor (e.g. current cluster: `1.24` will target version: `1.25`)

        Returns:
            Cluster: The requested EKS cluster object.

        """
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
            target_version=target_version,
            latest_addons=latest_addons,
        )

    def wait_for_active(self, delay: int = 30, max_attempts: int = 80):
        """Wait for the cluster to become active."""
        waiter_config: WaiterConfigTypeDef = {"Delay": delay, "MaxAttempts": max_attempts}
        self.active_waiter.wait(name=self.name, WaiterConfig=waiter_config)
