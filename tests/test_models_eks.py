"""Test the EKS model logic."""
from eksupgrade.models.eks import Cluster, ClusterAddon


def test_cluster_resource(eks_client, eks_cluster, cluster_name, region) -> None:
    """Test the cluster resource."""
    cluster_resource = Cluster.get_cluster(cluster_name, region)
    cluster_dict = cluster_resource.to_dict()
    assert cluster_dict
    assert isinstance(cluster_dict, dict)
    assert cluster_dict["version"] == "1.21"
    assert len(cluster_dict.keys()) == 15


def test_cluster_addon_resource(eks_client, eks_cluster, cluster_name, region) -> None:
    """Test the cluster addon resource."""
    cluster_resource = Cluster.get_cluster(cluster_name, region)
    addon_resource = ClusterAddon(
        arn="abc", name="coredns", cluster=cluster_resource, region=region, owner="amazon", publisher="amazon"
    )
    addon_dict = addon_resource.to_dict()
    assert isinstance(addon_dict, dict)
    assert addon_dict["arn"] == "abc"
    assert addon_resource.name == "coredns"
    assert not addon_dict["resource_id"]
    assert not addon_dict["tags"]
    assert len(addon_dict.keys()) == 17
