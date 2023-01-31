import base64
import json
import queue
import re
import threading
import time

import boto3
import kubernetes.client
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

            cluster_name, nameSpace, new_pod_name, podName, regionName = self.queue.get()
            x = addon_status(
                cluster_name=cluster_name,
                new_pod_name=new_pod_name,
                podName=podName,
                regionName=regionName,
                nameSpace=nameSpace,
            )
            # signals to queue job is done
            if not x:
                raise Exception("Pod Not Started", new_pod_name)

            self.queue.task_done()


def get_bearer_token(cluster_id, region):
    """' AUthenticating the session with sts token"""
    STS_TOKEN_EXPIRES_IN = 60
    session = boto3.session.Session()

    client = session.client("sts", region_name=region)
    service_id = client.meta.service_model.service_id

    signer = RequestSigner(service_id, region, "sts", "v4", session.get_credentials(), session.events)

    params = {
        "method": "GET",
        "url": "https://sts.{}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15".format(region),
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_id},
        "context": {},
    }
    """Getting a presigned Url"""

    signed_url = signer.generate_presigned_url(
        params, region_name=region, expires_in=STS_TOKEN_EXPIRES_IN, operation_name=""
    )

    base64_url = base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8")

    # remove any base64 encoding padding and returing the kubernets token
    return "k8s-aws-v1." + re.sub(r"=*", "", base64_url)


def loading_config(cluster_name, regionName):
    """loading kubeconfig with sts"""
    eks = boto3.client("eks", region_name=regionName)
    resp = eks.describe_cluster(name=cluster_name)
    endPoint = resp["cluster"]["endpoint"]
    configs = client.Configuration()
    configs.host = endPoint
    configs.verify_ssl = False
    configs.debug = False
    configs.api_key = {"authorization": "Bearer " + get_bearer_token(cluster_name, regionName)}
    client.Configuration.set_default(configs)
    return "Initialiazed"


def unschedule_old_nodes(ClusterName, Nodename, regionName):
    loading_config(ClusterName, regionName)
    """ unsheduling the nodes to avaoid new nodes to be launched """
    try:
        v1 = client.CoreV1Api()
        """ unscheduling the nodes"""
        body = {"spec": {"unschedulable": True}}
        v1.patch_node(Nodename, body)
        return
    except Exception as e:
        raise Exception(str(e))


def watcher(cluster_name, name, regionName):
    """watcher to check wether the pod is deleted or not"""
    loading_config(cluster_name=cluster_name, regionName=regionName)
    v1 = client.CoreV1Api()
    w = watch.Watch()
    try:
        for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=30):
            print(event["type"], event["object"].metadata.name)
            if event["type"] == "DELETED" and event["object"].metadata.name == name:
                w.stop()
                return True
        else:
            return False
    except Exception as e:
        print(e)
        raise Exception(e)


def drain_nodes(cluster_name, Nodename, forced, regionName):
    """pod eviction using eviction api"""
    loading_config(cluster_name, regionName)
    v1 = client.CoreV1Api()
    api_response = v1.list_pod_for_all_namespaces(watch=False, field_selector="spec.nodeName=" + Nodename)
    retry = 0
    # print(api_response.items)
    if len(api_response.items) == 0:
        return "Empty Nothing to Drain" + Nodename
    for i in api_response.items:
        if i.spec.node_name == Nodename:
            try:
                if forced:
                    v1.delete_namespaced_pod(
                        i.metadata.name, i.metadata.namespace, grace_period_seconds=0, body=client.V1DeleteOptions()
                    )
                else:
                    eviction_body = kubernetes.client.models.v1beta1_eviction.V1beta1Eviction(
                        metadata=kubernetes.client.V1ObjectMeta(name=i.metadata.name, namespace=i.metadata.namespace)
                    )
                    v1.create_namespaced_pod_eviction(
                        name=i.metadata.name, namespace=i.metadata.namespace, body=eviction_body
                    )
                    """retry to if pod is not deleted with eviction api"""
                    if watcher(cluster_name, i.metadata.name) == False and retry < 2:
                        drain_nodes(cluster_name, i.metadata.name)
                        retry += 1
                    if retry == 2:
                        raise Exception("Error Not able to delete the Node" + i.metadata.name)
                    return

            except Exception as e:
                print(e)
                # logs_pusher(e, "error")
                raise Exception("Unable to Delete the Node")


def delete_node(cluster_name, NodeName, regionName):
    try:
        loading_config(cluster_name, regionName)
        v1 = client.CoreV1Api()
        """ delete the node from compute list this doesnt terminate the instance"""
        v1.delete_node(NodeName)
        return
    except ApiException as e:
        # logs_pusher(e, "error")
        print(e)
        raise Exception(e)


def find_node(cluster_name, instance_id, op, regionName):
    """finding the node with instance id"""
    loading_config(cluster_name, regionName)
    v1 = client.CoreV1Api()
    nodes = []
    response = v1.list_node()
    if len(response.items) == 0:
        return "NAN"
    for node in response.items:
        # print(node.spec.provider_id, node.metadata.name,
        #       node.status.node_info.kube_proxy_version, node.status.node_info.kubelet_version)
        # print(node.status.node_info.os_image)
        nodes.append(
            [
                node.spec.provider_id.split("/")[-1],
                node.metadata.name,
                node.status.node_info.kube_proxy_version.split("-")[0],
                node.status.node_info.kubelet_version.split("-")[0],
                node.status.node_info.os_image,
            ]
        )
    if op == "find":
        for i in nodes:
            if i[0] == instance_id:
                return i[1]
        return "NAN"
    if op == "os_type":
        for i in nodes:
            if i[0] == instance_id:
                print(i[0])
                return i[-1]
        return "NAN"
    # for node in nodes:
    #     try:
    #         drain_nodes(node[1])
    #     except Exception as x:
    #         return x


def addon_status(cluster_name, new_pod_name, podName, regionName, nameSpace):
    loading_config(cluster_name, regionName)
    v1 = client.CoreV1Api()
    tts = 100
    now = time.time()
    v1 = client.CoreV1Api()

    while time.time() < now + tts:
        response = v1.read_namespaced_pod_status(name=new_pod_name, namespace=nameSpace)
        if response.status.container_statuses[0].ready and response.status.container_statuses[0].started:
            return True

    return False


def sort_pods(cluster_name, regionName, original_name, pod_name, old_pods_name, nameSpace, c=90):
    if c == 0:
        raise Exception("Pod has No assosicated New Launch")
    pods_nodes = []
    loading_config(cluster_name, regionName)
    v1 = client.CoreV1Api()
    try:
        if pod_name == "cluster-autoscaler":
            pod_list = v1.list_namespaced_pod(namespace=nameSpace, label_selector="app={name}".format(name=pod_name))
        else:
            pod_list = v1.list_namespaced_pod(
                namespace=nameSpace, label_selector="k8s-app={name}".format(name=pod_name)
            )

    except Exception as e:
        logs_pusher(regionName, cluster_name, e)
        return "Not Found"
    print("Total Pods With {p} = {c}".format(p=pod_name, c=len(pod_list.items)))
    for i in pod_list.items:
        pods_nodes.append([i.metadata.name, i.metadata.creation_timestamp])
    if len(pods_nodes) > 0:
        new_pod_name = sorted(pods_nodes, key=lambda x: x[1])[-1][0]
    else:
        c -= 1
        sort_pods(cluster_name, regionName, original_name, pod_name, old_pods_name, nameSpace, c)
    """ aws-node not in aws-node-hshsh  """
    if original_name != new_pod_name and new_pod_name in old_pods_name:
        c -= 1
        sort_pods(cluster_name, regionName, original_name, pod_name, old_pods_name, nameSpace, c)
    return new_pod_name


def update_addons(cluster_name, version, vpcPass, regionName):
    loading_config(cluster_name, regionName)
    for x in range(20):
        worker = StatsWorker(queue, x)
        worker.setDaemon(True)
        worker.start()
    v1 = client.CoreV1Api()
    api_instance = client.AppsV1Api()
    rep = v1.list_namespaced_pod("kube-system")
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    add_on_dict = open("eksupgrade/src/S3Files/version_dict.json", "r")
    add_on_dict = json.load(add_on_dict)
    old_pods_name = []

    for pod in rep.items:
        old_pods_name.append(pod.metadata.name)
    print("The Addons Found = ", *old_pods_name)
    logs_pusher(
        regionName=regionName, cluster_name=cluster_name, msg="The Addons Found = {instan}".format(instan=old_pods_name)
    )

    flag_vpc, flag_core, flag_proxy, flag_scaler = True, True, True, True

    try:
        for pod in rep.items:
            images = [c.image for c in pod.spec.containers]
            # logs_pusher(images, "info")
            image = "".join(images)
            coredns_new = add_on_dict[version].get("coredns")
            kubeproxy_new = add_on_dict[version].get("kube-proxy")
            autosclaer_new = add_on_dict[version].get("cluster-autoscaler")
            cni_new = add_on_dict[version].get("vpc-cni")
            vv = int("".join(image.split(":")[-1].replace("v", "").replace("-", ".").split(".")[:3]))
            newv = version.replace(".", "")
            newv = int(newv)

            if "coredns" in pod.metadata.name and image.split(":")[-1] != "v" + coredns_new + "-eksbuild.1":
                print(
                    pod.metadata.name,
                    "Current Version = ",
                    image.split(":")[-1],
                    "Updating To = ",
                    "v" + coredns_new + "-eksbuild.1",
                )
                body = {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "coredns",
                                        "image": image.split(":")[0] + ":v" + coredns_new + "-eksbuild.1",
                                    }
                                ]
                            }
                        }
                    }
                }
                if flag_core:
                    api_response = api_instance.patch_namespaced_deployment(
                        name="coredns", namespace="kube-system", body=body, pretty=True
                    )
                    if vv <= 170:
                        # TODO: Make this load safe.  This file is never closed. Use context manager instead.
                        coredns_yaml = open("eksupgrade/src/S3Files/core-dns.yaml", "r")
                        body = yaml.safe_load(coredns_yaml)
                        v1.patch_namespaced_config_map(name="coredns", namespace="kube-system", body=body)
                    flag_core = False
                time.sleep(20)

                new_pod_name = sort_pods(
                    cluster_name=cluster_name,
                    regionName=regionName,
                    original_name=pod.metadata.name,
                    old_pods_name=old_pods_name,
                    pod_name="kube-dns",
                    nameSpace="kube-system",
                )
                print(
                    "old CoreDNs Pod {oldp} \t new CoreDnsPod {newp}".format(oldp=pod.metadata.name, newp=new_pod_name)
                )
                queue.put([cluster_name, "kube-system", new_pod_name, "coredns", regionName])
                # if addon_status(cluster_name=cluster_name,nameSpace="kube-system",new_pod_name=new_pod_name,podName=pod.metadata.name,regionName=regionName) != True:
                #     raise Exception("Pod Is not Started"+pod.metadata.name)
            elif "kube-proxy" in pod.metadata.name:
                if newv <= 118:
                    final_ender = "-eksbuild.1"
                else:
                    final_ender = "-eksbuild.2"

                if image.split(":")[-1] != "v" + kubeproxy_new + final_ender:
                    print(
                        pod.metadata.name,
                        "Current Version = ",
                        image.split(":")[-1],
                        "Updating To = ",
                        "v" + kubeproxy_new + final_ender,
                    )
                    body = {
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "kube-proxy",
                                            "image": image.split(":")[0] + ":v" + kubeproxy_new + final_ender,
                                        }
                                    ]
                                }
                            }
                        }
                    }
                    if flag_proxy:
                        api_response = api_instance.patch_namespaced_daemon_set(
                            name="kube-proxy", namespace="kube-system", body=body, pretty=True
                        )
                        flag_proxy = False
                    time.sleep(20)
                    new_pod_name = sort_pods(
                        cluster_name=cluster_name,
                        regionName=regionName,
                        original_name=pod.metadata.name,
                        old_pods_name=old_pods_name,
                        pod_name="kube-proxy",
                        nameSpace="kube-system",
                    )

                    print(
                        "old KubProxy Pod {oldp} \t new KubeProxyPod {newp}".format(
                            oldp=pod.metadata.name, newp=new_pod_name
                        )
                    )
                    queue.put([cluster_name, "kube-system", new_pod_name, "kube-proxy", regionName])
                # if addon_status(cluster_name=cluster_name,nameSpace='kube-system',new_pod_name=new_pod_name, podName=pod.metadata.name,regionName=regionName) != True:
                #     raise Exception("Pod is Not Started"+pod.metadata.name)
            elif "cluster-autoscaler" in pod.metadata.name and image.split(":")[-1] != "v" + autosclaer_new:
                print(
                    pod.metadata.name,
                    "Current Version = ",
                    image.split(":")[-1],
                    "Updating To = ",
                    "v" + autosclaer_new + "-eksbuild.1",
                )
                body = {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": "cluster-autoscaler", "image": image.split(":")[0] + ":v" + autosclaer_new}
                                ]
                            }
                        }
                    }
                }
                if flag_scaler:
                    api_response = api_instance.patch_namespaced_deployment(
                        name="cluster-autoscaler", namespace="kube-system", body=body, pretty=True
                    )
                    flag_scaler = False
                time.sleep(20)
                new_pod_name = sort_pods(
                    cluster_name=cluster_name,
                    regionName=regionName,
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
                queue.put([cluster_name, "kube-system", new_pod_name, "cluster-autoscaler", regionName])
                # if addon_status(cluster_name=cluster_name,nameSpace='kube-system',new_pod_name=new_pod_name, podName=pod.metadata.name,regionName=regionName) != True:
                #     raise Exception("Pod is Not Started"+pod.metadata.name)
            elif "aws-node" in pod.metadata.name and image.split(":")[-1] != "v" + cni_new and not vpcPass:
                print(pod.metadata.name, "Current Version = ", image.split(":")[-1], "Updating To = ", "v" + cni_new)
                if flag_vpc:
                    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
                    vpc_cni_yaml = open("eksupgrade/src/S3Files/vpc-cni.yaml", "r")
                    body = yaml.safe_load(vpc_cni_yaml)
                    body["spec"]["template"]["spec"]["containers"][0]["image"] = image.split(":")[0] + ":v" + cni_new
                    old = body["spec"]["template"]["spec"]["initContainers"][0]["image"]
                    body["spec"]["template"]["spec"]["initContainers"][0]["image"] = old.split(":")[0] + ":v" + cni_new
                    api_response = api_instance.patch_namespaced_daemon_set(
                        namespace="kube-system", name="aws-node", body=body, pretty=True
                    )
                    flag_vpc = False
                time.sleep(20)
                new_pod_name = sort_pods(
                    cluster_name=cluster_name,
                    regionName=regionName,
                    original_name=pod.metadata.name,
                    old_pods_name=old_pods_name,
                    pod_name="aws-node",
                    nameSpace="kube-system",
                )
                print("old vpc cni Pod {oldp} \t new vpc cni {newp}".format(oldp=pod.metadata.name, newp=new_pod_name))
                queue.put([cluster_name, "kube-system", new_pod_name, "aws-node", regionName])
        queue.join()
        # if addon_status(cluster_name=cluster_name,nameSpace='kube-system',new_pod_name=new_pod_name, podName="aws-node",regionName=regionName) != True:
        #     raise Exception("Pod is Not Started"+pod.metadata.name)

    except Exception as e:
        print(e)
        raise Exception(e)


# print(list_nodes())
# print(update_addons())
def list_pods(ClusterName):
    loading_config(cluster_name=ClusterName)
    v1 = client.CoreV1Api()
    print("Listing pods with their IPs:")
    ret = v1.list_namespaced_pod("default")
    for i in ret.items:
        print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))


# def pd_bd():
#     new_cli = client.PolicyV1beta1Api()
#     namespace = "default"
#     body = client.V1beta1PodDisruptionBudget(
#         api_version="policy/v1beta1",
#         kind="PodDisruptionBudget",
#         metadata={
#             "name": "nginxpdb_new"
#         },
#         spec={
#             "minAvailable": 2,
#             "selector": {
#                 "matchLabels": {
#                     "app": "nginx"

#                 }
#             }
#         }
#     )
#     try:
#         res = new_cli.create_namespaced_pod_disruption_budget(
#             namespace, body, pretty="true")
#         print(res)
#     except Exception as e:
#         print(e)


def delete_pd_policy(pd_name):
    api_cli = client.PolicyV1beta1Api()
    try:
        api_response = api_cli.delete_namespaced_pod_disruption_budget(name=pd_name, namespace="default")
        print(api_response)
    except ApiException as e:
        print("Exception when calling PolicyV1beta1Api->delete_namespaced_pod_disruption_budget: %s\n" % e)


# addon_status(cluster_name="Prod",podName="coredns-6b4cdc67b4-4cfjs")


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
    v1 = client.CoreV1Api()
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
