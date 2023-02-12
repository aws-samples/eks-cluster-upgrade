"""Define the self-managed node logic."""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import boto3

from .latest_ami import get_latest_ami

logger = logging.getLogger(__name__)


def status_of_cluster(cluster_name: str, region: str) -> List[str]:
    """Get the self-managed Cluster Status."""
    client = boto3.client("eks", region_name=region)
    response = client.describe_cluster(name=cluster_name)
    status = response["cluster"]["status"]
    version = response["cluster"]["version"]
    logger.info("The Cluster Status = %s and Version = %s", status, version)
    return [status, version]


def get_node_groups(cluster_name: str, region: str) -> List[Any]:
    """Get the node group list."""
    client = boto3.client("eks", region_name=region)
    response = client.list_nodegroups(clusterName=cluster_name, maxResults=100)
    return response["nodegroups"]


def describe_node_groups(cluster_name: str, nodegroup: str, region: str) -> List[str]:
    """Get the description of the Node Group."""
    client = boto3.client("eks", region_name=region)
    response = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)
    status = response.get("nodegroup")["status"]
    version = response.get("nodegroup")["version"]
    logger.info("The NodeGroup = %s Status = %s and Version = %s", nodegroup, status, version)
    return [status, version]


def get_asg_node_groups(cluster_name: str, region: str) -> List[str]:
    """Get the ASG of the self-managed node groups."""
    client = boto3.client("eks", region_name=region)
    asg_groups = []
    node_groups = get_node_groups(cluster_name, region)

    if not node_groups:
        return []

    for nodegroup in node_groups:
        response = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)["nodegroup"][
            "resources"
        ]["autoScalingGroups"]
        for asg_name in response:
            asg_groups.append(asg_name["name"])

    logger.info("The cluster %s in region %s ASGs of the self-managed nodegroups: %s", cluster_name, region, asg_groups)
    return asg_groups


def filter_node_groups(cluster_name: str, node_list: List[str], latest_version: str, region: str) -> List[str]:
    """Filter the Node groups."""
    old_ng = []
    for node_group in node_list:
        logger.info("Filter node group: %s", node_group)
        status, version = describe_node_groups(cluster_name=cluster_name, nodegroup=node_group, region=region)

        if status in ["ACTIVE", "UPDATING"] and not version == latest_version:
            old_ng.append(node_group)

    logger.info("The Old Manged Node Groups Found Are %s", old_ng)
    return old_ng


def lt_id_func(cluster_name: str, nodegroup: str, version: str, region: str):
    """Get the launch template ID, AMI, and version information."""
    client = boto3.client("eks", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    res = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)
    latest_ami: str = ""
    launch_template_id: str = ""
    version_no: str = ""
    ami_type: str = res["nodegroup"]["amiType"]
    launch_template: Optional[Dict[str, Any]] = res["nodegroup"].get("launchTemplate")

    if launch_template:
        launch_template_id = launch_template["id"]
        version_no = launch_template["version"]

    if ami_type == "CUSTOM":
        os_lt = ec2.describe_launch_template_versions(LaunchTemplateId=launch_template_id, Versions=[version_no])
        current_ami = os_lt["LaunchTemplateVersions"][0]["LaunchTemplateData"]["ImageId"]
        os_type = ec2.describe_images(ImageIds=[current_ami])["Images"][0]["ImageLocation"]

        if isinstance(os_type, str) and "Windows_Server" in os_type:
            os_type = os_type[:46]

        latest_ami = get_latest_ami(
            cluster_version=version, instance_type=os_type, image_to_search=os_type, region=region
        )

    return ami_type, launch_template_id, version_no, latest_ami


def update_current_launch_template_ami(lt_id: str, latest_ami: str, region: str) -> None:
    """Update the current launch template's AMI."""
    ec2 = boto3.client("ec2", region_name=region)
    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        SourceVersion="$Latest",
        VersionDescription="Latest-AMI",
        LaunchTemplateData={"ImageId": latest_ami},
    )
    logger.info("New launch template created with AMI %s", latest_ami)


def update_nodegroup(cluster_name: str, nodegroup: str, version: str, region: str) -> bool:
    """Update the Node group."""
    client = boto3.client("eks", region_name=region)
    start = time.time()

    ami_type, lt_id, _, latest_ami = lt_id_func(cluster_name, nodegroup, version, region)
    if ami_type == "CUSTOM":
        update_current_launch_template_ami(lt_id, latest_ami, region)

    while True:
        try:
            if (
                status_of_cluster(cluster_name, region)[0] == "ACTIVE"
                and describe_node_groups(cluster_name, nodegroup, region)[0] == "ACTIVE"
                and describe_node_groups(cluster_name, nodegroup, region)[1] != version
            ):
                if ami_type == "CUSTOM":
                    client.update_nodegroup_version(
                        clusterName=cluster_name,
                        nodegroupName=nodegroup,
                        launchTemplate={"version": "$Latest", "id": lt_id},
                    )
                else:
                    client.update_nodegroup_version(
                        clusterName=cluster_name,
                        nodegroupName=nodegroup,
                        version=version,
                    )
                logger.info("Updating Node Group %s", nodegroup)
                time.sleep(20)
            if describe_node_groups(cluster_name, nodegroup, region)[0] == "UPDATING":
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                logger.info("The %s NodeGroup is Still Updating %s:%s:%s", nodegroup, int(hours), int(minutes), seconds)
                time.sleep(20)
            if describe_node_groups(cluster_name, nodegroup, region)[0] == "DEGRADED":
                raise Exception("NodeGroup has not started due to unavailability ")
            if (
                describe_node_groups(cluster_name, nodegroup, region)[0] == "ACTIVE"
                and describe_node_groups(cluster_name, nodegroup, region)[1] == version
            ):
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                logger.info(
                    "The Time Taken For the NodeGroup Upgrade %s %s:%s:%s", nodegroup, int(hours), int(minutes), seconds
                )
                return True

        except Exception as e:
            logger.error(
                "Exception encountered while attempting to update nodegroup: %s in cluster: %s - %s! Error: %s",
                nodegroup,
                cluster_name,
                region,
                e,
            )
            raise e
