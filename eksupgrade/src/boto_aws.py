"""Define the EKS upgrade boto specific logic."""
from __future__ import annotations

import datetime
import time
import uuid
from typing import Any, Dict, List

import boto3

from eksupgrade.utils import echo_error, echo_info, echo_success, echo_warning, get_logger

logger = get_logger(__name__)


def status_of_cluster(cluster_name: str, region: str) -> List[str]:
    """Check the satus of the cluster and version of the cluster."""
    eks_client = boto3.client("eks", region_name=region)
    try:
        response = eks_client.describe_cluster(name=cluster_name)
        return [response["cluster"]["status"], response["cluster"]["version"]]
    except Exception as e:
        echo_error(f"Exception encountered while attempting to get cluster status - Error: {e}")
        raise e


def is_cluster_exists(cluster_name: str, region: str) -> str:
    """Check whether the cluster exists or not."""
    try:
        response = status_of_cluster(cluster_name, region)
        return response[0]
    except Exception as e:
        echo_error(f"Exception encountered while checking if cluster exists. Error: {e}")
        raise e


def get_latest_instance(asg_name: str, add_time: datetime.datetime, region: str) -> str:
    """Retrieve the most recently launched/launching instance.

    Note that this is not necessarily the same one that was launched by `add_node()`,
    but it's the best I could think of.

    """
    asg_client = boto3.client("autoscaling", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)
    instances = []

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    time.sleep(20)
    instance_ids = [instance["InstanceId"] for instance in response["AutoScalingGroups"][0]["Instances"]]

    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(instance)

    instances_valid = []
    instances_valid = [
        instance
        for instance in instances
        if instance["State"]["Name"] in ["pending", "running"] and instance["LaunchTime"] > add_time
    ]

    latest_instance: Dict[str, Any] = {}
    try:
        time.sleep(10)
        latest_instance = sorted(instances_valid, key=lambda instance: instance["LaunchTime"])[-1]
        return latest_instance["InstanceId"]
    except Exception as e:
        echo_error(f"Exception encountered while sorting instances. Error: {e}")
        raise e


def wait_for_ready(instanceid: str, region: str) -> bool:
    """Wait for the cluster to pass the status checks."""
    ec2_client = boto3.client("ec2", region_name=region)
    echo_info(f"Instance {instanceid} waiting for the instance to pass the Health Checks")
    try:
        while (
            ec2_client.describe_instance_status(InstanceIds=[instanceid])["InstanceStatuses"][0]["InstanceStatus"][
                "Details"
            ][0]["Status"]
            != "passed"
        ):
            echo_info(f"Instance: {instanceid} waiting for the instance to pass the Health Checks")
            time.sleep(20)
    except Exception as e:
        echo_error(str(e))
        raise Exception(f"{e}: Please rerun the Script the instance will be created")
    return True


def check_asg_autoscaler(asg_name: str, region: str) -> bool:
    """Check whether the autoscaling is present or not."""
    asg_client = boto3.client("autoscaling", region_name=region)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    pat = "k8s.io/cluster-autoscaler/enabled"
    asg_list = []
    for asg in response["AutoScalingGroups"][0]["Tags"]:
        if asg["Key"] == pat:
            asg_list.append(asg)
    return bool(asg_list)


def enable_disable_autoscaler(asg_name: str, action: str, region: str) -> str:
    """Enable or disable the autoscaler depending on the provided action."""
    asg_client = boto3.client("autoscaling", region_name=region)
    try:
        if action == "pause":
            asg_client.delete_tags(
                Tags=[
                    {
                        "ResourceId": asg_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": "k8s.io/cluster-autoscaler/enabled",
                    },
                ]
            )
            return "done"
        if action == "start":
            asg_client.create_or_update_tags(
                Tags=[
                    {
                        "ResourceId": asg_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": "k8s.io/cluster-autoscaler/enabled",
                        "Value": "true",
                        "PropagateAtLaunch": False,
                    },
                ]
            )
            return "done"
        echo_warning("Invalid action provided to enable_disable_autoscaler!")
    except Exception as e:
        echo_error(
            f"Exception encountered while attempting to {action} the autoscaler associated with ASG: {asg_name} - Error: {e}",
        )
        raise Exception(e)
    finally:
        return "Something went Wrong auto scaling operation failed"


def worker_terminate(instance_id: str, region: str) -> None:
    """Terminate instance and decreasing the desired capacity whit asg terminate instance."""
    asg_client = boto3.client("autoscaling", region_name=region)

    try:
        asg_client.terminate_instance_in_auto_scaling_group(InstanceId=instance_id, ShouldDecrementDesiredCapacity=True)
    except Exception as e:
        echo_error(f"Exception encountered while attempting to terminate worker: {instance_id} - Error: {e}")
        raise e


def add_node(asg_name: str, region: str) -> None:
    """Add node to particular ASG."""
    asg_client = boto3.client("autoscaling", region_name=region)

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    try:
        old_capacity_mx = response["AutoScalingGroups"][0]["MaxSize"]
        old_capacity_des = response["AutoScalingGroups"][0]["DesiredCapacity"]
    except (KeyError, IndexError):
        echo_error(f"Exception encountered while getting old ASG capacity during add_node - ASG: {asg_name}")
        raise Exception("Error Index out of bound due to no max capacity field")

    if int(old_capacity_des) >= int(old_capacity_mx):
        asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name, MaxSize=(int(old_capacity_mx) + int(old_capacity_des))
        )

    old_capacity = response["AutoScalingGroups"][0]["DesiredCapacity"]
    new_capacity = old_capacity + 1

    try:
        asg_client.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=new_capacity)
        echo_info(f"New Node has been Added to {asg_name}")
    except Exception as e:
        echo_error(f"Exception encountered while attempting to add node to ASG: {asg_name} - Error: {e}")
        raise e


def get_num_of_instances(asg_name: str, exclude_ids: List[str], region: str) -> int:
    """Count the number of instances."""
    asg_client = boto3.client("autoscaling", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)
    instances = []

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instance_ids = [
        instance["InstanceId"]
        for instance in response["AutoScalingGroups"][0]["Instances"]
        if instance["InstanceId"] not in exclude_ids
    ]
    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(instance)
    # getting the instance in running or pending state
    instances = [instance for instance in instances if instance["State"]["Name"] in ["running", "pending"]]

    return len(instances)


def old_lt_scenarios(inst: Dict[str, Any], asg_lt_name: str, asg_lt_version: int) -> bool:
    """Get the old launch template based on launch template name and version 1!=2."""
    lt_name = inst["LaunchTemplate"]["LaunchTemplateName"]
    lt_version = int(inst["LaunchTemplate"]["Version"])
    return (lt_name != asg_lt_name) or (lt_version != int(asg_lt_version))


def get_old_lt(asg_name: str, region: str) -> List[str]:
    """Get the old launch template."""
    asg_client = boto3.client("autoscaling", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)

    old_lt_instance_ids = []
    instances = []

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    asg_lt_name = ""
    # finding the launch type
    if "LaunchTemplate" in response["AutoScalingGroups"][0]:
        response["AutoScalingGroups"][0]["LaunchTemplate"]["LaunchTemplateId"]
        asg_lt_name = response["AutoScalingGroups"][0]["LaunchTemplate"]["LaunchTemplateName"]
    elif "MixedInstancesPolicy" in response["AutoScalingGroups"][0]:
        response["AutoScalingGroups"][0]["MixedInstancesPolicy"]["LaunchTemplate"]["LaunchTemplateSpecification"][
            "LaunchTemplateId"
        ]
        asg_lt_name = response["AutoScalingGroups"][0]["MixedInstancesPolicy"]["LaunchTemplate"][
            "LaunchTemplateSpecification"
        ]["LaunchTemplateName"]
    else:
        echo_error(f"Old Launch Template not found! ASG: {asg_name} - Region: {region}")
        return []

    # checking whether there are instances with 1!=2 mismatch template version
    old_lt_instance_ids = [
        instance["InstanceId"]
        for instance in response["AutoScalingGroups"][0]["Instances"]
        if old_lt_scenarios(instance, asg_lt_name, int(instance["LaunchTemplate"]["Version"]))
    ]
    if not old_lt_instance_ids:
        return []
    response = ec2_client.describe_instances(InstanceIds=old_lt_instance_ids)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(instance)
    return instances


def old_launch_config_instances(asg_name: str, region: str) -> List[str]:
    """Get the old launch configuration instance IDs."""
    asg_client = boto3.client("autoscaling", region_name=region)
    old_lc_ids = []
    # describing the asg group
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instances = response["AutoScalingGroups"][0]["Instances"]
    for inst in instances:
        # checking the LaunchConfiguration is matching or not
        if inst.get("LaunchConfigurationName") != response["AutoScalingGroups"][0]["LaunchConfigurationName"]:
            old_lc_ids.append(inst["InstanceId"])
    return old_lc_ids


def outdated_lt(asgs, region: str) -> List[str]:
    """Get the outdated launch template."""
    asg_client = boto3.client("autoscaling", region_name=region)
    asg = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asgs])
    asg_name = asg["AutoScalingGroups"][0]["AutoScalingGroupName"]
    launch_type = ""
    if "LaunchConfigurationName" in asg["AutoScalingGroups"][0]:
        launch_type = "LaunchConfiguration"
    elif "LaunchTemplate" in asg["AutoScalingGroups"][0]:
        launch_type = "LaunchTemplate"
    elif "MixedInstancesPolicy" in asg["AutoScalingGroups"][0]:
        launch_type = "LaunchTemplate"
    else:
        return []
    old_instances = []

    if launch_type == "LaunchConfiguration":
        temp = old_launch_config_instances(asg_name, region)
        if temp:
            old_instances = temp
            return old_instances
        return []

    # checking with launch Template
    if launch_type == "LaunchTemplate":
        temp = get_old_lt(asg_name, region)
        if temp:
            old_instances = temp
            return old_instances
        return []
    return []


def add_autoscaling(asg_name: str, img_id: str, region: str) -> Dict[str, Any]:
    """Add the new Launch Configuration to the ASG."""
    asg_client = boto3.client("autoscaling", region_name=region)
    timestamp = time.time()
    timestamp_string = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d  %H-%M-%S")
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])

    source_instance_id = response.get("AutoScalingGroups")[0]["Instances"][0]["InstanceId"]
    new_launch_config_name = f"LC {img_id} {timestamp_string} {str(uuid.uuid4())}"

    try:
        asg_client.create_launch_configuration(
            InstanceId=source_instance_id, LaunchConfigurationName=new_launch_config_name, ImageId=img_id
        )
        response = asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name, LaunchConfigurationName=new_launch_config_name
        )
        echo_success("Updated to latest launch configuration")
    except Exception as e:
        echo_error(
            f"Exception encountered while executing add_autoscaling with ASG: {asg_name} - Image ID: {img_id} - Region: {region} - Error: {e}",
        )
        raise e
    return response


def get_outdated_asg(asg_name: str, latest_img: str, region: str) -> bool:
    """Get the outdated autoscaling group."""
    asg_client = boto3.client("autoscaling", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instance_ids = [instance["InstanceId"] for instance in response["AutoScalingGroups"][0]["Instances"]]
    old_ami_inst = []
    # filtering old instance where the logic is used to check whether we should add new launch configuration or not
    inst_response = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in inst_response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["ImageId"] != latest_img:
                old_ami_inst.append(instance["InstanceId"])
    instance_ids.sort()
    old_ami_inst.sort()
    if len(old_ami_inst) != len(instance_ids):
        return False

    for count, value in enumerate(old_ami_inst):
        if value != instance_ids[count]:
            return False
    return True
