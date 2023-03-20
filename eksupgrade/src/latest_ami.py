"""Define the AMI specific logic."""
from __future__ import annotations

import boto3

from eksupgrade.utils import echo_error, get_logger

logger = get_logger(__name__)


def get_latest_ami(cluster_version: str, instance_type: str, image_to_search: str, region: str) -> str:
    """Get the latest AMI."""
    ssm = boto3.client("ssm", region_name=region)
    client = boto3.client("ec2", region_name=region)

    if "Amazon Linux 2" in instance_type:
        names = [f"/aws/service/eks/optimized-ami/{cluster_version}/amazon-linux-2/recommended/image_id"]
    elif "Windows" in instance_type:
        names = [f"/aws/service/ami-windows-latest/{image_to_search}-{cluster_version}/image_id"]
    elif "bottlerocket" in instance_type.lower():
        names = [f"/aws/service/bottlerocket/aws-k8s-{cluster_version}/x86_64/latest/image_id"]
    elif "Ubuntu" in instance_type:
        filters = [
            {"Name": "owner-id", "Values": ["099720109477"]},
            {"Name": "name", "Values": [f"ubuntu-eks/k8s_{cluster_version}*"]},
            {"Name": "is-public", "Values": ["true"]},
        ]
        response = client.describe_images(Filters=filters)
        sorted_images = sorted(response["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if sorted_images:
            return sorted_images[0].get("ImageId")
        raise Exception("Couldn't Find Latest Image Retry The Script")
    else:
        return "NAN"
    response = ssm.get_parameters(Names=names)
    if response.get("Parameters"):
        return response.get("Parameters")[0]["Value"]
    echo_error("Couldn't find the latest image - please retry the script!")
    raise Exception("Couldn't Find Latest Image Retry The Script")
