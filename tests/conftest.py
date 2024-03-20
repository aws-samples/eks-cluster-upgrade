"""Define the pytest configuration for fixture reuse."""

import os
from typing import Any, Generator

import boto3
import pytest
import typer
from moto import mock_ec2, mock_eks, mock_sts


@pytest.fixture
def aws_creds() -> None:
    """Mock the AWS credentials to use for testing."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testaccesskeyid"  # nosec
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testsecretaccesskey"  # nosec
    os.environ["AWS_SECURITY_TOKEN"] = "testsecuritytoken"  # nosec
    os.environ["AWS_SESSION_TOKEN"] = "testsessiontoken"  # nosec


@pytest.fixture
def region() -> str:
    """Define the region fixture for reuse."""
    return "us-east-1"


@pytest.fixture
def sts_client(aws_creds, region) -> Generator[Any, None, None]:
    """Mock the STS boto client."""
    with mock_sts():
        client = boto3.client("sts", region_name=region)
        yield client


@pytest.fixture
def ec2_client(aws_creds, region) -> Generator[Any, None, None]:
    """Mock the EKS boto client."""
    with mock_ec2():
        client = boto3.client("ec2", region_name=region)
        yield client


@pytest.fixture
def eks_client(aws_creds, region) -> Generator[Any, None, None]:
    """Mock the EKS boto client."""
    with mock_eks():
        client = boto3.client("eks", region_name=region)
        yield client


@pytest.fixture
def cluster_name() -> str:
    """Define the EKS cluster name to be used across test mocks."""
    return "eks-test"


@pytest.fixture
def eks_cluster(eks_client, cluster_name):
    """Define the EKS cluster to be reused for mocked calls."""
    eks_client.create_cluster(
        name=cluster_name,
        version="1.23",
        roleArn=f"arn:aws:iam::123456789012:role/{cluster_name}",
        resourcesVpcConfig={},
    )
    yield


@pytest.fixture
def app():
    """Define the typer cli fixture."""
    return typer.Typer()
