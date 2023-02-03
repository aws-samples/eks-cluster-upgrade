"""The EKS Upgrade kubernetes client module.

Attributes:
    queue (queue.Queue): The queue used for executing jobs (status checks, etc).

"""
from __future__ import annotations

import base64
import json
import queue
import re
import threading
import time
from typing import Optional

import boto3
import yaml
from botocore.signers import RequestSigner
from kubernetes import client, watch
from kubernetes.client.rest import ApiException

from .ekslogs import logs_pusher

queue = queue.Queue()


class StatsWorker(threading.Thread):
    def __init__(self, queue, id):
        threading.Thread.__init__(self)
        self.queue = queue
        self.id = id

    def run(self):
        while self.queue.not_empty:
            cluster_name, nameSpace, new_pod_name, _, regionName = self.queue.get()
            status = addon_status(
                cluster_name=cluster_name,
                new_pod_name=new_pod_name,
                region_name=regionName,
                namespace=nameSpace,
            )
            # signals to queue job is done
            if not status:
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

    # remove any base64 encoding padding and returing the kubernetes token
    return "k8s-aws-v1." + re.sub(r"=*", "", base64_url)


def loading_config(cluster_name, regionName) -> str:
    """loading kubeconfig with sts"""
    eks = boto3.client("eks", region_name=regionName)
    resp = eks.describe_cluster(name=cluster_name)
    configs = client.Configuration()
    configs.host = resp["cluster"]["endpoint"]
    configs.verify_ssl = False
    configs.debug = False
    configs.api_key = {"authorization": "Bearer " + get_bearer_token(cluster_name, regionName)}
    client.Configuration.set_default(configs)
    return "Initialiazed"


def unschedule_old_nodes(ClusterName, Nodename, regionName) -> None:
    """Unschedule the nodes to avoid new nodes being launched."""
    loading_config(ClusterName, regionName)
    try:
        core_v1_api = client.CoreV1Api()
        # unscheduling the nodes
        body = {"spec": {"unschedulable": True}}
        core_v1_api.patch_node(Nodename, body)
    except Exception as e:
        raise Exception(str(e))
    return


def watcher(cluster_name: str, name: str, region: str) -> bool:
    """Watch whether the pod is deleted or not."""
    loading_config(cluster_name=cluster_name, regionName=region)
    core_v1_api = client.CoreV1Api()
    _watcher = watch.Watch()

    try:
        for event in _watcher.stream(core_v1_api.list_pod_for_all_namespaces, timeout_seconds=30):
            print(event["type"], event["object"].metadata.name)

            if event["type"] == "DELETED" and event["object"].metadata.name == name:
                _watcher.stop()
                return True
        return False
    except Exception as e:
        print(e)
        raise e


def drain_nodes(cluster_name, Nodename, forced, regionName) -> Optional[str]:
    """pod eviction using eviction api"""
    loading_config(cluster_name, regionName)
    v1 = client.CoreV1Api()
    api_response = v1.list_pod_for_all_namespaces(watch=False, field_selector=f"spec.nodeName={Nodename}")
    retry = 0

    if not api_response.items:
        return f"Empty Nothing to Drain {Nodename}"

    for i in api_response.items:
        if i.spec.node_name == Nodename:
            try:
                if forced:
                    v1.delete_namespaced_pod(
                        i.metadata.name, i.metadata.namespace, grace_period_seconds=0, body=client.V1DeleteOptions()
                    )
                else:
                    eviction_body = client.models.v1beta1_eviction.V1beta1Eviction(
                        metadata=client.V1ObjectMeta(name=i.metadata.name, namespace=i.metadata.namespace)
                    )
                    v1.create_namespaced_pod_eviction(
                        name=i.metadata.name, namespace=i.metadata.namespace, body=eviction_body
                    )
                    # retry to if pod is not deleted with eviction api
                    if not watcher(cluster_name, i.metadata.name, regionName) and retry < 2:
                        drain_nodes(cluster_name, i.metadata.name, forced=forced, regionName=regionName)
                        retry += 1
                    if retry == 2:
                        raise Exception("Error Not able to delete the Node" + i.metadata.name)
                    return None
            except Exception as e:
                print(e)
                raise Exception("Unable to Delete the Node")


def delete_node(cluster_name, NodeName, regionName) -> None:
    """Delete the node from compute list this doesnt terminate the instance."""
    try:
        loading_config(cluster_name, regionName)
        v1 = client.CoreV1Api()
        v1.delete_node(NodeName)
        return
    except ApiException as e:
        print(e)
        raise e


def find_node(cluster_name, instance_id, operation, region_name):
    """Find the node by instance id."""
    loading_config(cluster_name, region_name)
    core_v1_api = client.CoreV1Api()
    nodes = []
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
                print(i[0])
                return i[-1]
        return "NAN"


def addon_status(cluster_name, new_pod_name, region_name, namespace):
    loading_config(cluster_name, region_name)
    core_v1_api = client.CoreV1Api()
    tts = 100
    now = time.time()

    while time.time() < now + tts:
        response = core_v1_api.read_namespaced_pod_status(name=new_pod_name, namespace=namespace)
        if response.status.container_statuses[0].ready and response.status.container_statuses[0].started:
            return True

    return False


def sort_pods(cluster_name, regionName, original_name, pod_name, old_pods_name, nameSpace, c=90):
    if not c:
        raise Exception("Pod has No assosicated New Launch")

    pods_nodes = []
    loading_config(cluster_name, regionName)
    core_v1_api = client.CoreV1Api()
    try:
        if pod_name == "cluster-autoscaler":
            pod_list = core_v1_api.list_namespaced_pod(namespace=nameSpace, label_selector=f"app={pod_name}")
        else:
            pod_list = core_v1_api.list_namespaced_pod(namespace=nameSpace, label_selector=f"k8s-app={pod_name}")

    except Exception as e:
        logs_pusher(regionName, cluster_name, e)
        return "Not Found"

    print(f"Total Pods With {pod_name} = {len(pod_list.items)}")
    for i in pod_list.items:
        pods_nodes.append([i.metadata.name, i.metadata.creation_timestamp])

    if pods_nodes:
        new_pod_name = sorted(pods_nodes, key=lambda x: x[1])[-1][0]
    else:
        c -= 1
        sort_pods(cluster_name, regionName, original_name, pod_name, old_pods_name, nameSpace, c)
        # TODO: Remove this.  Adding to resolve possible use before assignment below.
        new_pod_name = ""

    if original_name != new_pod_name and new_pod_name in old_pods_name:
        c -= 1
        sort_pods(cluster_name, regionName, original_name, pod_name, old_pods_name, nameSpace, c)
    return new_pod_name


def update_addons(cluster_name, version, vpc_pass, region_name) -> None:
    loading_config(cluster_name, region_name)
    for x in range(20):
        worker = StatsWorker(queue, x)
        worker.setDaemon(True)
        worker.start()

    core_v1_api = client.CoreV1Api()
    apps_v1_api = client.AppsV1Api()
    rep = core_v1_api.list_namespaced_pod("kube-system")

    with open("eksupgrade/src/S3Files/version_dict.json", "r", encoding="utf-8") as add_on_dict:
        add_on_dict = json.load(add_on_dict)

    old_pods_name = []

    for pod in rep.items:
        old_pods_name.append(pod.metadata.name)

    print("The Addons Found = ", *old_pods_name)

    flag_vpc, flag_core, flag_proxy, flag_scaler = True, True, True, True

    try:
        for pod in rep.items:
            images = [c.image for c in pod.spec.containers]
            image = "".join(images)
            coredns_new = add_on_dict[version].get("coredns")
            kubeproxy_new = add_on_dict[version].get("kube-proxy")
            autoscaler_new = add_on_dict[version].get("cluster-autoscaler")
            cni_new = add_on_dict[version].get("vpc-cni")
            _current_image = image.rsplit(":", maxsplit=1)[-1]
            vv = int("".join(_current_image.replace("v", "").replace("-", ".").split(".")[:3]))
            new_version_int = int(version.replace(".", ""))
            image_base_uri: str = image.split(":")[0]

            if "coredns" in pod.metadata.name and _current_image != "v" + coredns_new + "-eksbuild.1":
                print(f"{pod.metadata.name} Current Version = {_current_image} Updating to = v{coredns_new}-eksbuild.1")
                body = {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "coredns",
                                        "image": image_base_uri + ":v" + coredns_new + "-eksbuild.1",
                                    }
                                ]
                            }
                        }
                    }
                }
                if flag_core:
                    apps_v1_api.patch_namespaced_deployment(
                        name="coredns", namespace="kube-system", body=body, pretty=True
                    )
                    if vv <= 170:
                        with open("eksupgrade/src/S3Files/core-dns.yaml", "r", encoding="utf-8") as coredns_yaml:
                            body = yaml.safe_load(coredns_yaml)
                        core_v1_api.patch_namespaced_config_map(name="coredns", namespace="kube-system", body=body)
                    flag_core = False
                time.sleep(20)

                new_pod_name = sort_pods(
                    cluster_name=cluster_name,
                    regionName=region_name,
                    original_name=pod.metadata.name,
                    old_pods_name=old_pods_name,
                    pod_name="kube-dns",
                    nameSpace="kube-system",
                )
                print(f"Old CoreDNS Pod: {pod.metadata.name} \t New CoreDNS Pod: {new_pod_name}")
                queue.put([cluster_name, "kube-system", new_pod_name, "coredns", region_name])
            elif "kube-proxy" in pod.metadata.name:
                if new_version_int <= 118:
                    final_ender = "eksbuild.1"
                else:
                    final_ender = "eksbuild.2"

                # TODO: Handle versions better and rework this logic so we don't have to do this.
                kubeproxy_new = re.sub(r"-eksbuild.*", "", kubeproxy_new)
                _new_kubeproxy_version: str = f"v{kubeproxy_new}-{final_ender}"

                if _current_image != _new_kubeproxy_version:
                    print(
                        f"{pod.metadata.name} Current version: {_current_image} Updating to: {_new_kubeproxy_version}"
                    )
                    body = {
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "kube-proxy",
                                            "image": image_base_uri + _new_kubeproxy_version,
                                        }
                                    ]
                                }
                            }
                        }
                    }
                    if flag_proxy:
                        apps_v1_api.patch_namespaced_daemon_set(
                            name="kube-proxy", namespace="kube-system", body=body, pretty=True
                        )
                        flag_proxy = False
                    time.sleep(20)
                    new_pod_name = sort_pods(
                        cluster_name=cluster_name,
                        regionName=region_name,
                        original_name=pod.metadata.name,
                        old_pods_name=old_pods_name,
                        pod_name="kube-proxy",
                        nameSpace="kube-system",
                    )

                    print(f"Old kube-proxy pod: {pod.metadata.name} \t New kube-proxy pod: {new_pod_name}")
                    queue.put([cluster_name, "kube-system", new_pod_name, "kube-proxy", region_name])
            elif "cluster-autoscaler" in pod.metadata.name and _current_image != "v" + autoscaler_new:
                print(
                    pod.metadata.name,
                    "Current Version = ",
                    _current_image,
                    "Updating To = ",
                    "v" + autoscaler_new,
                )
                body = {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": "cluster-autoscaler", "image": image_base_uri + ":v" + autoscaler_new}
                                ]
                            }
                        }
                    }
                }
                if flag_scaler:
                    apps_v1_api.patch_namespaced_deployment(
                        name="cluster-autoscaler", namespace="kube-system", body=body, pretty=True
                    )
                    flag_scaler = False
                time.sleep(20)
                new_pod_name = sort_pods(
                    cluster_name=cluster_name,
                    regionName=region_name,
                    original_name=pod.metadata.name,
                    old_pods_name=old_pods_name,
                    pod_name="cluster-autoscaler",
                    nameSpace="kube-system",
                )
                print(
                    "old Cluster AutoScaler Pod {oldp} \t new AutoScaler pod {newp}".format(
                        oldp=pod.metadata.name, newp=new_pod_name
                    )
                )
                queue.put([cluster_name, "kube-system", new_pod_name, "cluster-autoscaler", region_name])
            elif "aws-node" in pod.metadata.name and _current_image != "v" + cni_new and not vpc_pass:
                print(pod.metadata.name, "Current Version = ", _current_image, "Updating To = ", "v" + cni_new)
                if flag_vpc:
                    with open("eksupgrade/src/S3Files/vpc-cni.yaml", "r", encoding="utf-8") as vpc_cni_yaml:
                        body = yaml.safe_load(vpc_cni_yaml)

                    body["spec"]["template"]["spec"]["containers"][0]["image"] = image_base_uri + ":v" + cni_new
                    old = body["spec"]["template"]["spec"]["initContainers"][0]["image"]
                    body["spec"]["template"]["spec"]["initContainers"][0]["image"] = old.split(":")[0] + ":v" + cni_new
                    apps_v1_api.patch_namespaced_daemon_set(
                        namespace="kube-system", name="aws-node", body=body, pretty=True
                    )
                    flag_vpc = False
                time.sleep(20)
                new_pod_name = sort_pods(
                    cluster_name=cluster_name,
                    regionName=region_name,
                    original_name=pod.metadata.name,
                    old_pods_name=old_pods_name,
                    pod_name="aws-node",
                    nameSpace="kube-system",
                )
                print(f"Old VPC CNI pod: {pod.metadata.name} \t New VPC CNI pod: {new_pod_name}")
                queue.put([cluster_name, "kube-system", new_pod_name, "aws-node", region_name])
        queue.join()
    except Exception as e:
        print(e)
        raise Exception(e)


def delete_pd_policy(pd_name):
    api_cli = client.PolicyV1beta1Api()
    try:
        api_response = api_cli.delete_namespaced_pod_disruption_budget(name=pd_name, namespace="default")
        print(api_response)
    except ApiException as e:
        print("Exception when calling PolicyV1beta1Api->delete_namespaced_pod_disruption_budget: %s\n" % e)


def is_cluster_auto_scaler_present(ClusterName, regionName):
    loading_config(cluster_name=ClusterName, regionName=regionName)
    v1 = client.AppsV1Api()
    res = v1.list_deployment_for_all_namespaces()
    for res_i in res.items:
        if res_i.metadata.name == "cluster-autoscaler":
            return [True, res_i.spec.replicas]
    return [False, "NAN"]


def clus_auto_enable_disable(ClusterName, type, mx_val, regionName):
    loading_config(cluster_name=ClusterName, regionName=regionName)
    api = client.AppsV1Api()
    if type == "pause":
        body = {"spec": {"replicas": 0}}
    elif type == "start":
        body = {"spec": {"replicas": mx_val}}
    else:
        return "error"
    try:
        api.patch_namespaced_deployment(name="cluster-autoscaler", namespace="kube-system", body=body)
    except Exception as e:
        print(e)
        raise Exception(e)
