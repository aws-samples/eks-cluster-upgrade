"""Test EKS Upgrade k8s client specific logic."""
import pytest

from eksupgrade.src.k8s_client import get_bearer_token, loading_config


def test_get_bearer_token(sts_client, eks_cluster, cluster_name, region) -> None:
    """Test the get_bearer_token method."""
    token = get_bearer_token(cluster_id=cluster_name, region=region)
    assert token.startswith("k8s-aws-v1.")


def test_loading_config(eks_client, eks_cluster, cluster_name, region) -> None:
    """Test the loading_config method."""
    result = loading_config(cluster_name, region=region)
    assert result == "Initialized"
