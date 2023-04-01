"""Define the image type logic for EKS."""
from __future__ import annotations

from typing import Optional

import boto3

from eksupgrade.utils import echo_error, echo_warning, get_logger

from .k8s_client import find_node

logger = get_logger(__name__)


def image_type(node_type: str, image_id: str, region: str) -> Optional[str]:
    """Return the image location."""
    ec2_client = boto3.client("ec2", region_name=region)
    node_type = node_type.lower()
    filters = [
        {"Name": "is-public", "Values": ["true"]},
    ]

    if "amazon linux 2" in node_type:
        filters.append({"Name": "name", "Values": ["amazon-eks-node*"]})
    elif "bottlerocket" in node_type:
        filters.append({"Name": "name", "Values": ["bottlerocket-aws-k8s-*"]})
    elif "windows" in node_type:
        filters.append({"Name": "name", "Values": ["Windows_Server-*-English-*-EKS_Optimized*"]})
    else:
        echo_warning(f"Node type: {node_type} is unsupported  - Image ID: {image_id}")
        return None

    # describing image types
    images = ec2_client.describe_images(Filters=filters)
    images_list = [[item.get("ImageId"), item.get("Name")] for item in images.get("Images", [])]

    logger.debug("Images List: %s", images_list)

    for i in images_list:
        if image_id in i[0]:
            logger.debug("Found image ID: %s in list - returning image name: %s", image_id, i[1])
            return i[1]
    return None


def get_ami_name(cluster_name: str, asg_name: str, region: str):
    asg_client = boto3.client("autoscaling", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instance_ids = [instance["InstanceId"] for instance in response["AutoScalingGroups"][0]["Instances"]]
    if not instance_ids:
        echo_error(f"No instances found to determine AMI - cluster: {cluster_name} - ASG: {asg_name}")
        raise Exception("No Instances")

    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    ans = []
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            image_id = instance["ImageId"]
            # getting the instance type as amz2 or windows or ubuntu
            node_type = find_node(cluster_name, instance["InstanceId"], "os_type", region)
            _image_type = image_type(node_type=node_type, image_id=image_id, region=region)
            logger.debug("_image_type: %s", _image_type)
            ans.append(
                [
                    node_type,
                    _image_type,
                ]
            )
    # custom logic to check whether the os_type is same if same returning and if not returning the least repeated name
    result = False
    if ans:
        result = all(elem[0] == ans[0][0] for _, elem in enumerate(ans))
        if result:
            return ans[0]
        dd = {}
        ac = {}
        for d, ak in ans:
            dd[d] = dd.get(d, 0) + 1
            ac[d] = ac.get(d, ak)
        return min((ac.get(d, ""), d) for d in dd)
