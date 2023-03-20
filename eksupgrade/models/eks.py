"""Define the models to be used across the EKS upgrade tool."""
from __future__ import annotations

import base64
import datetime
import re
import time
from abc import ABC
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import boto3
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from packaging.version import Version
from packaging.version import parse as parse_version

from eksupgrade.utils import echo_error, echo_info, echo_success, echo_warning, get_logger

from ..exceptions import InvalidUpgradeTargetVersion
from .base import AwsRegionResource

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_autoscaling.type_defs import AutoScalingGroupsTypeTypeDef, AutoScalingGroupTypeDef
    from mypy_boto3_eks.client import EKSClient
    from mypy_boto3_eks.literals import ResolveConflictsType
    from mypy_boto3_eks.type_defs import (
        AddonInfoTypeDef,
        AddonTypeDef,
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
    AutoScalingGroupTypeDef = object

from eksupgrade.utils import get_logger

logger = get_logger(__name__)

TOKEN_PREFIX: str = "k8s-aws-v1"
TOKEN_HEADER_KEY: str = "x-k8s-aws-id"


def requires_cluster(function):
    """Decorate methods to require a cluster attribute."""

    def wrapper(self, *args, **kwargs):
        if not self.cluster.name:
            echo_error(
                f"Unable to use method: {function.__name__} without the cluster attribute! Pass a cluster to this child object!",
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
    mixed_instances_policy: Dict[str, Any] = field(default_factory=dict)
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
    created_time: datetime.datetime = datetime.datetime.now()
    suspended_processes: List[Dict[str, str]] = field(default_factory=list)
    vpc_zone_identifier: str = ""
    status: str = ""
    termination_policies: List[str] = field(default_factory=list)
    new_instances_protected_from_scale_in: bool = False
    service_linked_role_arn: str = ""
    max_instance_lifetime: int = 0
    capacity_rebalance: bool = False
    warm_pool_configuration: Dict[str, Any] = field(default_factory=dict)
    warm_pool_size: int = 0
    context: str = ""
    desired_capacity_type: str = ""
    default_instance_warmup: int = 0
    traffic_sources: List[Dict[str, str]] = field(default_factory=list)
    enabled_metrics: List[Dict[str, str]] = field(default_factory=list)
    asg_tags: List[Dict[str, str]] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover
        """Return the string representation of a EKS Managed Node Group."""
        return f"<{self.__class__.__name__} - Name: {self.name} | Launch Config: {self.launch_configuration_name} | Last Status: {self.status}>"

    @property
    def asg_name(self) -> str:
        """Return the autoscaling group name."""
        return self.name

    @classmethod
    def get(
        cls,
        cluster: Cluster,
        region: str,
        autoscaling_group_name: str = "",
        asg_data: Optional[AutoScalingGroupTypeDef] = None,
    ):
        """Get the cluster's manage nodegroup details and build a ManagedNodeGroup object."""
        echo_info("Getting cluster autoscaling group details...")

        if not asg_data:
            response: AutoScalingGroupsTypeTypeDef = cluster.autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[autoscaling_group_name],
            )
            asg_data = response["AutoScalingGroups"][0]

        asg_name: str = autoscaling_group_name or asg_data.get("AutoScalingGroupName", "")
        echo_info(
            f"Autoscaling Group: {asg_name} - Cluster: {cluster.name}",
        )
        instances = asg_data.get("Instances", [])
        unhealthy_instances = [
            instance["InstanceId"] for instance in instances if instance["HealthStatus"] == "Unhealthy"
        ]
        healthy_instances: List[str] = [
            instance["InstanceId"] for instance in instances if instance["HealthStatus"] == "Healthy"
        ]

        if unhealthy_instances:
            echo_warning("Unhealthy Instances:")
            for unhealthy_instance in unhealthy_instances:
                echo_warning(f"\t * {unhealthy_instance}")

        if healthy_instances:
            echo_info("Healthy Instances:")
            for healthy_instance in healthy_instances:
                echo_info(f"\t * {healthy_instance}")

        return cls(
            cluster=cluster,
            launch_configuration_name=asg_data.get("LaunchConfigurationName", ""),
            launch_template=asg_data.get("LaunchTemplate", {}),
            mixed_instances_policy=asg_data.get("MixedInstancesPolicy", {}),
            name=asg_data.get("AutoScalingGroupName", ""),
            status=asg_data.get("Status", ""),
            arn=asg_data.get("AutoScalingGroupARN", ""),
            min_size=asg_data.get("MinSize", 0),
            max_size=asg_data.get("MaxSize", 0),
            desired_capacity=asg_data.get("DesiredCapacity", 0),
            predicted_capacity=asg_data.get("PredictedCapacity", 0),
            default_cooldown=asg_data.get("DefaultCooldown", 0),
            created_time=asg_data.get("CreatedTime", datetime.datetime.now()),
            availability_zones=asg_data.get("AvailabilityZones", []),
            load_balancer_names=asg_data.get("LoadBalancerNames", []),
            target_group_arns=asg_data.get("TargetGroupARNs", []),
            health_check_type=asg_data.get("HealthCheckType", ""),
            instances=asg_data.get("Instances", []),
            health_check_grace_period=asg_data.get("HealthCheckGracePeriod", 0),
            suspended_processes=asg_data.get("SuspendedProcesses", []),
            placement_group=asg_data.get("PlacementGroup", ""),
            vpc_zone_identifier=asg_data.get("VPCZoneIdentifier", ""),
            enabled_metrics=asg_data.get("EnabledMetrics", []),
            termination_policies=asg_data.get("TerminationPolicies", []),
            asg_tags=asg_data.get("Tags", []),
            region=region,
            new_instances_protected_from_scale_in=asg_data.get("NewInstancesProtectedFromScaleIn", False),
            service_linked_role_arn=asg_data.get("ServiceLinkedRoleARN", ""),
            max_instance_lifetime=asg_data.get("MaxInstanceLifetime", ""),
            capacity_rebalance=asg_data.get("CapacityRebalance", ""),
            warm_pool_size=asg_data.get("WarmPoolSize", []),
            warm_pool_configuration=asg_data.get("WarmPoolConfiguration", []),
            context=asg_data.get("Context", ""),
            desired_capacity_type=asg_data.get("DesiredCapacityType", ""),
            default_instance_warmup=asg_data.get("DefaultInstanceWarmup", 0),
            traffic_sources=asg_data.get("TrafficSources", []),
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
    def get(cls, node_group: str, cluster: Cluster, region: str):
        """Get the cluster's manage nodegroup details and build a ManagedNodeGroup object."""
        echo_info("Getting cluster managed nodegroup details...")
        response: DescribeNodegroupResponseTypeDef = cluster.eks_client.describe_nodegroup(
            nodegroupName=node_group,
            clusterName=cluster.name,
        )
        nodegroup_data: NodegroupTypeDef = response["nodegroup"]
        version: str = nodegroup_data.get("version", "")
        release_version: str = nodegroup_data.get("releaseVersion", "")
        echo_info(
            f"Managed Node Group: {node_group} - Version: {version} - Release Version: {release_version} - Cluster: {cluster.name}",
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
            echo_info(
                f"Managed Node Group: {self.name} requires upgrade from version: {self.version} to target version: {self.cluster.target_version}",
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
            echo_error("Version and launch template provided to managed nodegroug update with custom AMI!")

        if release_version:
            update_kwargs["releaseVersion"] = release_version

        if client_request_id:
            update_kwargs["clientRequestToken"] = client_request_id

        version = version or self.cluster.target_version
        echo_info(f"Updating nodegroup: {self.name} from version: {self.version} to version: {version}")
        update_response = self.eks_client.update_nodegroup_version(
            clusterName=self.cluster.name, nodegroupName=self.name, force=force, **update_kwargs
        )
        update_response_body: UpdateTypeDef = update_response["update"]
        _update_errors = update_response_body.get("errors", [])

        if _update_errors:
            echo_error(
                f"Errors encountered while attempting to update addon: {self.name} - Errors: {_update_errors}",
            )
            self.errors += _update_errors
        if wait:
            self.wait_for_active()

        return update_response_body

    def wait_for_active(self, delay: int = 35, initial_delay: int = 30, max_attempts: int = 160) -> None:
        """Wait for the nodegroup to become active."""
        echo_info(f"Waiting for the Managed Node Group: {self.name} to become active...")
        time.sleep(initial_delay)
        waiter_config: WaiterConfigTypeDef = {"Delay": delay, "MaxAttempts": max_attempts}
        self.active_waiter.wait(clusterName=self.cluster.name, nodegroupName=self.name, WaiterConfig=waiter_config)
        echo_success(f"Managed Nodegroup: {self.name} now active!")


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
    def get(cls, addon: str, cluster: Cluster, region: str):
        """Get the cluster addon details and build a ClusterAddon object."""
        logger.debug("Getting cluster addon details...")
        response: DescribeAddonResponseTypeDef = cluster.eks_client.describe_addon(
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
    def _addon_update_kwargs(self) -> dict[str, Any]:
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
        wait: bool = False,
    ) -> list[UpdateTypeDef]:
        """Update the addon to the target version."""
        responses: list[UpdateTypeDef] = []
        if self.name == "vpc-cni":
            versions: list[str] = self.step_upgrade_versions
            wait = True
        else:
            versions = [version or self.target_version]

        for version in versions:
            echo_info(f"Updating addon: {self.name} from original version: {self.version} to version: {version}")
            update_response: UpdateAddonResponseTypeDef = self.eks_client.update_addon(
                clusterName=self.cluster.name,
                addonName=self.name,
                addonVersion=version,
                resolveConflicts=resolve_conflicts,
                **self._addon_update_kwargs,
            )
            update_response_body: UpdateTypeDef = update_response["update"]
            _update_errors = update_response_body.get("errors", [])

            _update_id: str = update_response_body.get("id", "")
            _update_status: str = update_response_body.get("status", "")
            echo_info(f"Updating addon: {self.name} - ID: {_update_id} - Status: {_update_status}")
            responses.append(update_response_body)

            if _update_errors:
                echo_error(
                    f"Errors encountered while attempting to update addon: {self.name} - Errors: {_update_errors}",
                )
                self.errors += _update_errors
            elif wait:
                self.wait_for_active()
        return responses

    @cached_property
    def available_versions_data(self) -> AddonInfoTypeDef:
        """Get target addon versions."""
        return next(item for item in self.cluster.available_addon_versions if item.get("addonName", "") == self.name)

    @cached_property
    def available_versions(self) -> list[str]:
        """Return the list of available versions."""
        return [item.get("addonVersion", "") for item in self.available_versions_data.get("addonVersions", [])]

    @cached_property
    def default_version(self) -> str:
        """Get the EKS default version of the addon."""
        return next(
            item.get("addonVersion", "")
            for item in self.available_versions_data.get("addonVersions", [])
            if item.get("compatibilities", [])[0].get("defaultVersion", False) is True
        )

    @property
    def minors_to_target(self) -> list[int]:
        """Return the list of minor revisions to upgrade target."""
        return list(range(self.semantic_version.minor, self._target_version_semver.minor + 1))

    @cached_property
    def sorted_versions(self) -> list[str]:
        """Return the latest version."""
        return sorted(self.available_versions, reverse=True, key=parse_version)

    @cached_property
    def semantic_version(self) -> Version:
        """Return the current version without eks platform details in the string."""
        return Version(re.sub(r"-eksbuild.*", "", self.version))

    @property
    def semantic_versions(self) -> list[Version]:
        """Return the list of semantic versions sorted with latest first."""
        return [Version(re.sub(r"-eksbuild.*", "", version)) for version in self.sorted_versions]

    @property
    def step_upgrade_versions(self) -> list[str]:
        """Return the list of semantic versions to target for step upgrade by minor."""
        versions: List[str] = []
        for minor in self.minors_to_target:
            version: Optional[Version] = self.get_version_by_minor(minor)
            full_version: str = self.get_full_version_str(version)
            if full_version:
                versions.append(full_version)
        return versions

    @property
    def _target_version(self) -> str:
        """Return the target version."""
        return self.latest_version if self.cluster.latest_addons else self.default_version

    @property
    def _target_version_semver(self) -> Version:
        """Return the target version."""
        return Version(re.sub(r"-eksbuild.*", "", self._target_version))

    @property
    def within_target_minor(self) -> bool:
        """Determine if the current version is within +1 of the minor target version."""
        if self._target_version_semver.minor in (self.semantic_version.minor, self.semantic_version.minor + 1):
            return True
        return False

    def get_version_by_minor(self, minor: int) -> Optional[Version]:
        """Return the semantic version based on the input version."""
        try:
            return [item for item in self.semantic_versions if item.minor == minor][0]
        except IndexError:
            return None

    def get_full_version_str(self, semantic_version: Optional[Version]) -> str:
        """Return the complete version string based on the semantic version."""
        if not semantic_version:
            return ""
        return next(item for item in self.sorted_versions if item.startswith(f"v{str(semantic_version)}"))

    @property
    def next_minor_semver(self) -> Optional[Version]:
        """Return the next minor version's semantic version."""
        return self.get_version_by_minor(minor=self.semantic_version.minor + 1)

    @property
    def next_minor(self) -> str:
        """Return the next minor's complete version string."""
        if self.next_minor_semver:
            return self.get_full_version_str(self.next_minor_semver)
        return ""

    @property
    def latest_version(self) -> str:
        """Return the latest version."""
        return self.sorted_versions[0]

    @property
    def target_version(self) -> str:
        """Return the target version."""
        # If VPC CNI Add-on, use graduated upgrade by single minor version.
        if (
            self.name == "vpc-cni"
            and not self.within_target_minor
            and parse_version(self.version) < parse_version(self.next_minor)
        ):
            echo_info(
                f"vpc-cni will target version: {self.next_minor} instead of {self._target_version} because it's not within +1 or current minor...",
            )
            return self.next_minor
        return self._target_version

    @property
    def needs_upgrade(self) -> bool:
        """Determine whether or not this addon should be upgraded."""
        return parse_version(self.version) < parse_version(self.target_version)

    def wait_for_active(self, delay: int = 35, initial_delay: int = 30, max_attempts: int = 160) -> None:
        """Wait for the addon to become active."""
        echo_info(f"Waiting for the add-on: {self.name} to become active...")
        time.sleep(initial_delay)
        waiter_config: WaiterConfigTypeDef = {"Delay": delay, "MaxAttempts": max_attempts}
        self.active_waiter.wait(clusterName=self.cluster.name, addonName=self.name, WaiterConfig=waiter_config)
        echo_success(f"Add-on: {self.name} upgraded!")


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
        echo_info(f"Getting the list of current cluster addons for cluster: {self.name}...")
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
        echo_info("Fetching Cluster Addons...")
        return [ClusterAddon.get(addon, self, self.region) for addon in self.current_addons]

    @cached_property
    def needs_upgrade(self) -> bool:
        """Determine whether or not this addon should be upgraded."""
        return self._version_object < self._target_version_object

    @cached_property
    def upgradable_addons(self) -> List[ClusterAddon]:
        """Get a list of addons that require upgrade."""
        return [addon for addon in self.addons if addon.needs_upgrade]

    @cached_property
    def upgradable_managed_nodegroups(self) -> List[ManagedNodeGroup]:
        """Get a list of managed nodegroups that require upgrade."""
        return [nodegroup for nodegroup in self.nodegroups if nodegroup.needs_upgrade]

    @cached_property
    def _version_object(self) -> Version:
        """Return the Cluster.version as a Version object."""
        return Version(self.version)

    @cached_property
    def _target_version_object(self) -> Version:
        """Return the Cluster.target_version as a Version object."""
        return Version(self.target_version)

    def update_cluster(self, wait: bool = True) -> Optional[UpdateTypeDef]:
        """Upgrade the cluster itself."""
        if self._version_object > self._target_version_object:
            echo_warning(
                f"Cluster: {self.name} version: {self.version} already greater than target version: {self.target_version}! Skipping cluster upgrade!",
            )
            return None

        if self._version_object == self._target_version_object:
            echo_warning(f"Cluster: {self.name} already on version: {self.version}! Skipping cluster upgrade!")
            return None

        if self._target_version_object.minor > self._version_object.minor + 1:
            echo_error(
                f"Cluster: {self.name} can't be upgraded more than one minor at a time! Please adjust the target cluster version and try again!",
            )
            raise InvalidUpgradeTargetVersion()

        echo_info(f"Upgrading cluster: {self.name} from version: {self.version} to version: {self.target_version}")
        update_response: UpdateClusterVersionResponseTypeDef = self.eks_client.update_cluster_version(
            name=self.name, version=self.target_version
        )
        update_response_body: UpdateTypeDef = update_response["update"]
        _update_errors = update_response_body.get("errors", [])

        if _update_errors:
            echo_error(
                f"Errors encountered while attempting to update cluster: {self.name} - Errors: {_update_errors}",
            )
            self.errors += _update_errors
        if wait:
            self.wait_for_active()
        return update_response_body

    def upgrade_addons(self, wait: bool = False) -> Dict[str, Any]:
        """Upgrade all cluster addons."""
        echo_info("The add-ons update has been initiated...")
        upgrade_details: Dict[str, Any] = {}
        for addon in self.upgradable_addons:
            _update_responses: list[UpdateTypeDef] = addon.update(wait=wait)
            upgrade_details[addon.name] = _update_responses
        return upgrade_details

    def upgrade_nodegroups(self, wait: bool = False) -> Dict[str, Any]:
        """Upgrade all EKS managed nodegroups."""
        upgrade_details: Dict[str, Any] = {}
        for nodegroup in self.upgradable_managed_nodegroups:
            _update_response: UpdateTypeDef = nodegroup.update(wait=wait)
            _update_id: str = _update_response.get("id", "")
            _update_status: str = _update_response.get("status", "")
            echo_info(f"Updating nodegroup: {nodegroup.name} - ID: {_update_id} - Status: {_update_status}")
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

    @cached_property
    def autoscaling_groups(self) -> List[AutoscalingGroup]:
        """Get the list of AutoScaling Groups (ASGs).

        We get a list of ASGs which will match the format
        "kubernetes.io/cluster/{cluster_name}"
        and returns an empty list if none are found

        """
        cluster_tag = f"kubernetes.io/cluster/{self.name}"
        response = self.autoscaling_client.describe_auto_scaling_groups(
            Filters=[{"Name": "tag-key", "Values": [cluster_tag]}]
        ).get("AutoScalingGroups", [])
        return [AutoscalingGroup.get(asg_data=asg, region=self.region, cluster=self) for asg in response]

    @cached_property
    def asg_names(self) -> List[str]:
        """Get the autoscaling group names."""
        return [asg.name for asg in self.autoscaling_groups]

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
            ManagedNodeGroup.get(node_group=nodegroup, cluster=self, region=self.region)
            for nodegroup in self.nodegroup_names
        ]

    @classmethod
    def get(cls, cluster_name: str, region: str, target_version: str = "", latest_addons: bool = False):
        """Get the cluster details and build a Cluster.

        Arguments:
            cluster_name: The name the of the cluster.
            region: The AWS region where the cluster resides.
            target_version: The target cluster version of this upgrade.
                Defaults to: The current cluster version + 1 minor
                    (e.g. current cluster: `1.24` will target version: `1.25`).
            latest_addons: Whether or not to target the latest versions of addons
                available versus the default versions.
                Defaults to: `False`.

        Returns:
            Cluster: The requested EKS cluster object.

        """
        logger.debug("Getting cluster details...")
        eks_client: EKSClient = boto3.client("eks", region_name=region)

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

    def wait_for_active(self, delay: int = 35, initial_delay: int = 30, max_attempts: int = 160) -> None:
        """Wait for the cluster to become active."""
        echo_info(f"Waiting for cluster: {self.name} to become active...")
        time.sleep(initial_delay)
        waiter_config: WaiterConfigTypeDef = {"Delay": delay, "MaxAttempts": max_attempts}
        self.active_waiter.wait(name=self.name, WaiterConfig=waiter_config)
        echo_success(f"Cluster: {self.name} now active, control plane upgrade should be completed!")
