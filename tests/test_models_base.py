"""Test the base model logic."""
from eksupgrade.models.base import AwsRegionResource, AwsResource, BaseResource


def test_base_resource() -> None:
    """Test the base resource."""
    base_resource = BaseResource()
    base_dict = base_resource.to_dict()
    assert not base_dict
    assert isinstance(base_dict, dict)
    assert len(base_dict.keys()) == 0


def test_aws_resource_no_optional() -> None:
    """Test the AWS resource without optional arguments."""
    aws_resource = AwsResource(arn="abc")
    aws_dict = aws_resource.to_dict()
    assert isinstance(aws_dict, dict)
    assert aws_dict["arn"] == "abc"
    assert not aws_dict["resource_id"]
    assert not aws_dict["tags"]
    assert len(aws_dict.keys()) == 3


def test_aws_resource_optional() -> None:
    """Test the AWS resource with optional arguments."""
    aws_resource = AwsResource(arn="abc", resource_id="123", tags={"Name": "123"})
    aws_dict = aws_resource.to_dict()
    assert isinstance(aws_dict, dict)
    assert aws_dict["arn"] == "abc"
    assert aws_dict["resource_id"] == "123"
    assert aws_dict["tags"]["Name"] == "123"
    assert len(aws_dict.keys()) == 3


def test_aws_region_resource_no_optional() -> None:
    """Test the AWS region resource without optional arguments."""
    aws_region_resource = AwsRegionResource(arn="abc")
    aws_dict = aws_region_resource.to_dict()
    assert isinstance(aws_dict, dict)
    assert aws_dict["arn"] == "abc"
    assert not aws_dict["resource_id"]
    assert not aws_dict["tags"]
    assert not aws_dict["region"]
    assert len(aws_dict.keys()) == 4


def test_aws_region_resource_optional() -> None:
    """Test the AWS region resource with optional arguments."""
    aws_region_resource = AwsRegionResource(arn="abc", resource_id="123", tags={"Name": "123"}, region="us-east-1")
    aws_dict = aws_region_resource.to_dict()
    assert isinstance(aws_dict, dict)
    assert aws_dict["arn"] == "abc"
    assert aws_dict["resource_id"] == "123"
    assert aws_dict["tags"]["Name"] == "123"
    assert aws_dict["region"] == "us-east-1"
    assert len(aws_dict.keys()) == 4


def test_sts_client_region(sts_client) -> None:
    """Test the STS client on AwsResource."""
    aws_resource = AwsRegionResource(arn="abc", resource_id="123", tags={"Name": "123"}, region="us-east-1")
    assert aws_resource.sts_client.meta.region_name == "us-east-1"
