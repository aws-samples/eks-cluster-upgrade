"""The EKS Upgrade kubernetes client module.

Attributes:
    queue (queue.Queue): The queue used for executing jobs (status checks, etc).

"""
from __future__ import annotations

import base64
import queue
import re
import threading
import time
from typing import Any, Dict, List, Optional, Union

try:
    from functools import cache
except ImportError:
    from functools import lru_cache as cache

try:
    from kubernetes.client.models.v1beta1_eviction import V1beta1Eviction as V1Eviction
except ImportError:
    from kubernetes.client.models.v1_eviction import V1Eviction

import boto3
from botocore.signers import RequestSigner
from kubernetes import client, watch
from kubernetes.client.rest import ApiException

from eksupgrade.utils import echo_error, echo_info, get_logger

logger = get_logger(__name__)

queue = queue.Queue()


class StatsWorker(threading.Thread):
    def __init__(self, queue, id):
        threading.Thread.__init__(self)
        self.queue = queue
        self.id = id

    def run(self):
        while self.queue.not_empty:
            cluster_name, namespace, new_pod_name, _, region = self.queue.get()
            status = addon_status(
                cluster_name=cluster_name,
                new_pod_name=new_pod_name,
                region=region,
                namespace=namespace,
            )
            # signals to queue job is done
            if not status:
                echo_error(
                    f"Pod not started! Cluster: {cluster_name} - Namespace: {namespace} - New Pod: {new_pod_name}"
                )
                raise Exception("Pod Not Started", new_pod_name)

            self.queue.task_done()


def get_bearer_token(cluster_id: str, region: str) -> str:
    """Authenticate the session with sts token."""
    sts_token_expiration_ttl: int = 60
    session = boto3.session.Session()

    sts_client = session.client("sts", region_name=region)
    service_id = sts_client.meta.service_model.service_id
    signer = RequestSigner(service_id, region, "sts", "v4", session.get_credentials(), session.events)

    params = {
        "method": "GET",
        "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_id},
        "context": {},
    }

    # Getting a presigned Url
    signed_url = signer.generate_presigned_url(
        params, region_name=region, expires_in=sts_token_expiration_ttl, operation_name=""
    )
    base64_url = base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8")

    # remove any base64 encoding padding and returning the kubernetes token
    return "k8s-aws-v1." + re.sub(r"=*", "", base64_url)


def loading_config(cluster_name: str, region: str) -> str:
    """loading kubeconfig with sts"""
    eks = boto3.client("eks", region_name=region)
    resp = eks.describe_cluster(name=cluster_name)
    configs = client.Configuration()
    configs.host = resp["cluster"]["endpoint"]
    configs.verify_ssl = False
    configs.debug = False
    configs.api_key = {"authorization": "Bearer " + get_bearer_token(cluster_name, region)}
    client.Configuration.set_default(configs)
    return "Initialized"


def unschedule_old_nodes(cluster_name: str, node_name: str, region: str) -> None:
    """Unschedule the nodes to avoid new nodes being launched."""
    loading_config(cluster_name, region)
    try:
        core_v1_api = client.CoreV1Api()
        # unscheduling the nodes
        body = {"spec": {"unschedulable": True}}
        core_v1_api.patch_node(node_name, body)
    except Exception as e:
        echo_error(
            f"Exception encountered while attempting to unschedule old nodes - cluster: {cluster_name} - node: {node_name}",
        )
        raise e
    return


def watcher(cluster_name: str, name: str, region: str) -> bool:
    """Watch whether the pod is deleted or not."""
    loading_config(cluster_name, region)
    core_v1_api = client.CoreV1Api()
    _watcher = watch.Watch()

    try:
        for event in _watcher.stream(core_v1_api.list_pod_for_all_namespaces, timeout_seconds=30):
            echo_info(f"{event['type']} {event['object'].metadata.name}")

            if event["type"] == "DELETED" and event["object"].metadata.name == name:
                _watcher.stop()
                return True
        return False
    except Exception as e:
        echo_error(
            f"Exception encountered in watcher method against cluster: {cluster_name} name: {name} Error: {e}",
        )
        raise e


def drain_nodes(cluster_name, node_name, forced, region) -> Optional[str]:
    """Pod eviction using the eviction API."""
    loading_config(cluster_name, region)
    core_v1_api = client.CoreV1Api()
    api_response = core_v1_api.list_pod_for_all_namespaces(watch=False, field_selector=f"spec.nodeName={node_name}")
    retry = 0

    if not api_response.items:
        return f"Empty Nothing to Drain {node_name}"

    for i in api_response.items:
        if i.spec.node_name == node_name:
            try:
                if forced:
                    core_v1_api.delete_namespaced_pod(
                        i.metadata.name, i.metadata.namespace, grace_period_seconds=0, body=client.V1DeleteOptions()
                    )
                else:
                    eviction_body = V1Eviction(
                        metadata=client.V1ObjectMeta(name=i.metadata.name, namespace=i.metadata.namespace)
                    )
                    core_v1_api.create_namespaced_pod_eviction(
                        name=i.metadata.name, namespace=i.metadata.namespace, body=eviction_body
                    )
                    # retry to if pod is not deleted with eviction api
                    if not watcher(cluster_name, i.metadata.name, region) and retry < 2:
                        drain_nodes(cluster_name, i.metadata.name, forced=forced, region=region)
                        retry += 1
                    if retry == 2:
                        echo_error(
                            f"Exception encountered - unable to delete the node: {i.metadata.name} in cluster: {cluster_name}",
                        )
                        raise Exception("Error Not able to delete the Node" + i.metadata.name)
                    return None
            except Exception as e:
                echo_error(
                    f"Exception encountered while attempting to drain nodes! Node: {node_name} Cluster: {cluster_name} - Error: {e}",
                )
                raise Exception("Unable to Delete the Node")


def delete_node(cluster_name: str, node_name: str, region: str) -> None:
    """Delete the node from compute list this doesn't terminate the instance."""
    try:
        loading_config(cluster_name, region)
        core_v1_api = client.CoreV1Api()
        core_v1_api.delete_node(node_name)
        return
    except ApiException as e:
        echo_error(
            f"Exception encountered attempting to delete a node! Cluster: {cluster_name} - Node: {node_name} - Error: {e}",
        )
        raise e


def find_node(cluster_name: str, instance_id: str, operation: str, region: str) -> str:
    """Find the node by instance id."""
    loading_config(cluster_name, region)
    core_v1_api = client.CoreV1Api()
    nodes: List[List[str]] = []
    response = core_v1_api.list_node()

    if not response.items:
        return "NAN"

    for node in response.items:
        nodes.append(
            [
                node.spec.provider_id.split("/")[-1],
                node.metadata.name,
                node.status.node_info.kube_proxy_version.split("-")[0],
                node.status.node_info.kubelet_version.split("-")[0],
                node.status.node_info.os_image,
            ]
        )

    if operation == "find":
        for i in nodes:
            if i[0] == instance_id:
                return i[1]
        return "NAN"

    if operation == "os_type":
        for i in nodes:
            if i[0] == instance_id:
                echo_info(i[0])
                return i[-1]
        return "NAN"
    return "NAN"


def addon_status(cluster_name: str, new_pod_name: str, region: str, namespace: str) -> bool:
    """Get the status of an addon pod."""
    loading_config(cluster_name, region)
    core_v1_api = client.CoreV1Api()
    tts = 100
    now = time.time()

    while time.time() < now + tts:
        response = core_v1_api.read_namespaced_pod_status(name=new_pod_name, namespace=namespace)
        if response.status.container_statuses[0].ready and response.status.container_statuses[0].started:
            return True
    return False


def sort_pods(
    cluster_name: str,
    region: str,
    original_name: str,
    pod_name: str,
    old_pods_names: List[str],
    namespace: str,
    count: int = 90,
) -> str:
    """Sort the pod results."""
    if not count:
        echo_error(
            f"Pod has no associated new pod! Cluster: {cluster_name} - Namespace: {namespace} - Pod Name: {pod_name}",
        )
        raise Exception("Pod has No associated New Launch")

    pods_nodes = []
    loading_config(cluster_name, region)
    core_v1_api = client.CoreV1Api()
    try:
        if pod_name == "cluster-autoscaler":
            pod_list = core_v1_api.list_namespaced_pod(namespace=namespace, label_selector=f"app={pod_name}")
        else:
            pod_list = core_v1_api.list_namespaced_pod(namespace=namespace, label_selector=f"k8s-app={pod_name}")
    except Exception as e:
        echo_error(
            f"Exception encountered while attempting to get the pod list and sort_pods - cluster: {cluster_name}, error: {e}",
        )
        return "Not Found"

    echo_info(f"Total Pods With {pod_name} = {len(pod_list.items)}")
    for i in pod_list.items:
        pods_nodes.append([i.metadata.name, i.metadata.creation_timestamp])

    if pods_nodes:
        new_pod_name = sorted(pods_nodes, key=lambda x: x[1])[-1][0]
    else:
        count -= 1
        sort_pods(cluster_name, region, original_name, pod_name, old_pods_names, namespace, count)
        # TODO: Remove this.  Adding to resolve possible use before assignment below.
        new_pod_name = ""

    if original_name != new_pod_name and new_pod_name in old_pods_names:
        count -= 1
        sort_pods(cluster_name, region, original_name, pod_name, old_pods_names, namespace, count)
    return new_pod_name


@cache
def get_addon_details(cluster_name: str, addon: str, region: str) -> Dict[str, Any]:
    """Get addon details which includes its current version."""
    eks_client = boto3.client("eks", region_name=region)
    addon_details: Dict[str, Any] = eks_client.describe_addon(clusterName=cluster_name, addonName=addon).get(
        "addon", {}
    )
    return addon_details


@cache
def get_addon_update_kwargs(cluster_name: str, addon: str, region: str) -> Dict[str, Any]:
    """Get kwargs for subsequent update to addon."""
    addon_details: Dict[str, Any] = get_addon_details(cluster_name, addon, region)
    kwargs: Dict[str, Any] = {}
    iam_role_arn: Optional[str] = addon_details.get("serviceAccountRoleArn")
    config_values: Optional[str] = addon_details.get("configurationValues")

    if iam_role_arn:
        kwargs["serviceAccountRoleArn"] = iam_role_arn
    if config_values:
        kwargs["configurationValues"] = config_values
    return kwargs


@cache
def get_addon_versions(version: str, region: str) -> List[Dict[str, Any]]:
    """Get addon versions for the associated Kubernetes `version`."""
    eks_client = boto3.client("eks", region_name=region)
    addon_versions: List[Dict[str, Any]] = eks_client.describe_addon_versions(kubernetesVersion=version).get(
        "addons", []
    )
    return addon_versions


@cache
def get_versions_by_addon(addon: str, version: str, region: str) -> Dict[str, Any]:
    """Get target addon versions."""
    addon_versions: List[Dict[str, Any]] = get_addon_versions(version, region)
    return next(item for item in addon_versions if item["addonName"] == addon)


@cache
def get_default_version(addon: str, version: str, region: str) -> str:
    """Get the EKS default version of the `addon`."""
    addon_dict: Dict[str, Any] = get_versions_by_addon(addon, version, region)
    return next(
        item["addonVersion"]
        for item in addon_dict["addonVersions"]
        if item["compatibilities"][0]["defaultVersion"] is True
    )


def is_cluster_auto_scaler_present(cluster_name: str, region: str) -> List[Union[bool, int]]:
    """Determine whether or not cluster autoscaler is present."""
    loading_config(cluster_name, region)
    apps_v1_api = client.AppsV1Api()
    res = apps_v1_api.list_deployment_for_all_namespaces()
    for res_i in res.items:
        if res_i.metadata.name == "cluster-autoscaler":
            return [True, res_i.spec.replicas]
    return [False, 0]


def cluster_auto_enable_disable(cluster_name: str, operation: str, mx_val: int, region: str) -> None:
    """Enable or disable deployment in cluster."""
    loading_config(cluster_name, region)
    api = client.AppsV1Api()
    if operation == "pause":
        body = {"spec": {"replicas": 0}}
    elif operation == "start":
        body = {"spec": {"replicas": mx_val}}
    else:
        echo_error("Operation must be either pause or start to auto_enable_disable!")
        raise NotImplementedError("Operation must be either pause or start!")

    try:
        api.patch_namespaced_deployment(name="cluster-autoscaler", namespace="kube-system", body=body)
    except Exception as e:
        echo_error(f"Exception encountered while running auto enable disable - Error: {e}")
        raise e
