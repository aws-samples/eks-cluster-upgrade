"""Test EKS Upgrade get image type specific logic."""

from typing import Optional

import pytest

from eksupgrade.src.eks_get_image_type import image_type


@pytest.mark.parametrize(
    "node_type,image_id",
    [
        ("windows server 2019 datacenter ", "ami-ekswin"),
        ("windows server 2022", "ami-ekswin"),
        ("amazon linux 2", "ami-ekslinux"),
    ],
)
def test_image_type(ec2_client, region, node_type, image_id) -> None:
    """Test the image_type method."""
    ami_id: Optional[str] = image_type(node_type=node_type, image_id=image_id, region=region)
    assert ami_id
