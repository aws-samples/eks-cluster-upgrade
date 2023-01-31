import base64
import json
import re
import subprocess
import time

import boto3
from botocore.signers import RequestSigner
from kubernetes import client

from .ekslogs import logs_pusher

# will be updated soon in future releases right now still in alpha
vpc_version = "v1.7.5-eksbuild.1"


def botoclient(region):
    bclient = boto3.client("eks", region)
    return bclient


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


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def upgrade_cluster(region, clust_name, d, bclient, version):
    start_time = time.ctime()
    start = time.time()
    logs_pusher(regionName=region, cluster_name=clust_name, msg="The cluster Upgrade Started At " + str(start_time))

    response = bclient.describe_cluster(name=clust_name)  # to describe the cluster using boto3
    print("cluster verion before upgrade " + response["cluster"]["version"])  # to print present version
    d["cluster_prev_version"] = response["cluster"]["version"]
    args = (
        "~/eksctl upgrade cluster --name=" + clust_name + " --version " + version + " --approve"
    )  # upgrades cluster to one version above
    output = subprocess.call(args, shell=True)
    response = bclient.describe_cluster(name=clust_name)
    print("cluster verion after upgrade " + response["cluster"]["version"])  # to print updated/new version
    d["cluster_updated_version:"] = response["cluster"]["version"]

    end = time.time()
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    print("The time Taken For the cluster Upgrade ", "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds))
    logs_pusher(
        regionName=region,
        cluster_name=clust_name,
        msg="The time Taken For the cluster Upgrade "
        + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )

    return d


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# upgrades addon availble in given cluster
def add_on_upgrade(region, clust_name, d, v1):
    print("addon upgrade started")
    start_time = time.ctime()
    start = time.time()
    logs_pusher(regionName=region, cluster_name=clust_name, msg="The Addons Upgrade Started At " + str(start_time))

    loading_config(clust_name, region)

    v1 = client.CoreV1Api()

    rep = v1.list_namespaced_pod("kube-system")

    d["addonsbeforeupdate"] = {}
    for pod in rep.items:
        print(pod.metadata.name, "Current Version = ", pod.spec.containers[0].image.split(":")[-1])
        d["addonsbeforeupdate"][pod.metadata.name] = pod.spec.containers[0].image.split(":")[-1]

    args = "~/eksctl utils update-kube-proxy --cluster=" + clust_name + " --approve"  # to update kube-proxy
    output = subprocess.call(args, shell=True)
    args = "~/eksctl utils update-coredns --cluster=" + clust_name + " --approve"  # to update coredns
    output = subprocess.call(args, shell=True)

    output = botoclient("us-west-2").list_addons(clusterName=clust_name)

    if "vpc-cni" in output["addons"]:
        try:
            response = botoclient("us-west-2").describe_cluster(name=clust_name)
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                print("Success response recieved for describing cluster " + clust_name)
                oidc = response["cluster"]["identity"]["oidc"]["issuer"]
                print("OIDC output recieved " + oidc + " for Cluster Name " + clust_name)
                response = botoclient("us-west-2").describe_addon(clusterName=clust_name, addonName="vpc-cni")
                # print(response['addon']['addonVersion'])
                if response["addon"]["addonVersion"] != vpc_version:
                    args = (
                        "~/eksctl update addon --name vpc-cni  --version " + vpc_version + " --cluster " + clust_name
                    )  # to update aws-node
                    output = subprocess.call(args, shell=True)
        except Exception as e:
            print("Failed to fetch Cluster OIDC value for cluster name " + clust_name, e)
    else:
        args = "~/eksctl utils update-aws-node --cluster=" + clust_name + " --approve"
        output = subprocess.call(args, shell=True)

    print("addons  update completed")
    end = time.time()
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    print("The time Taken For the Addons Upgrade ", "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds))

    logs_pusher(
        regionName=region,
        cluster_name=clust_name,
        msg="The time Taken For the addons Upgrade "
        + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )

    return d


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# retrives the self managed nodegroup name
def get_old_smg_node_groups(region, clust_name, bclient):

    args = "~/eksctl get nodegroup --cluster=" + clust_name + " -o json"
    output = subprocess.check_output(args, shell=True)
    output = json.loads((output))  # to extract all nodegroups present in the cluster
    old_smg = []
    response = bclient.list_nodegroups(
        clusterName=clust_name,
    )
    ls = response["nodegroups"]  # to extract MANAGED NODE GROUPS
    for i in output:
        if i["Name"] not in ls:
            old_smg.append(i["Name"])  # to extract SELF MANAGED NODEGROUPS
    return old_smg


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# updates the unmanaged nodegroup  by migrating to new nodegroup
def update_unmanaged_nodegroup(region, clust_name, d, bclient):
    start_time = time.ctime()
    start = time.time()
    logs_pusher(
        regionName=region, cluster_name=clust_name, msg=" update managed nodegroups Started At " + str(start_time)
    )

    old_smg = get_old_smg_node_groups(region, clust_name, bclient)  # extract SELF MANAGED NODEGROUPS
    args = "~/eksctl get nodegroup --cluster=" + clust_name + " -o json"
    output = subprocess.check_output(args, shell=True)
    output = json.loads((output))
    response = bclient.list_nodegroups(
        clusterName=clust_name,
    )
    d["un_managed_ndgrp_before_update"] = {}
    ls = response["nodegroups"]
    for i in output:
        if i["Name"] not in ls:
            print(
                i["Name"] + " image-id befrore update " + i["ImageID"]
            )  # to print PRESENT - SELF MANAGED NODEGROUP IMAGE and ID
            d["un_managed_ndgrp_before_update"][i["Name"]] = i["ImageID"]

    if old_smg != []:
        try:  # to verify "if SELF MANAGED GROUP exists"
            for i in old_smg:
                args = (
                    "~/eksctl create nodegroup --cluster=" + clust_name
                )  # creates a node group with CONTROL PLANE version
                output = subprocess.call(args, shell=True)
                ls = get_old_smg_node_groups(region, clust_name, bclient)
                time.sleep(60)
                args = "~/eksctl drain nodegroup --cluster=" + clust_name + " --name=" + i  # DRAINS the old node groups
                output = subprocess.call(args, shell=True)
                time.sleep(60)
                args = (
                    "~/eksctl delete nodegroup --cluster=" + clust_name + " --name=" + i
                )  # DELETES the old node groups
                output = subprocess.call(args, shell=True)
        except Exception as e:
            print("pdb set cant delete pods" + e)
    else:
        print("no unmanaged nodegroups")
        return d

    print("**printing unmanaged nodegroups....waiting for nodegroup to be active")
    time.sleep(240)
    args = "~/eksctl get nodegroup --cluster=" + clust_name + " -o json"
    output = subprocess.check_output(args, shell=True)
    output = json.loads((output))
    response = bclient.list_nodegroups(
        clusterName=clust_name,
    )
    ls = response["nodegroups"]

    d["un_managed_ndgrp_after_update"] = {}
    for i in output:
        if i["Name"] not in ls:
            print(
                i["Name"] + " image-id after update " + i["ImageID"]
            )  # to print UPDATED - SELF MANAGED NODEGROUP IMAGE and ID
            d["un_managed_ndgrp_after_update"][i["Name"]] = i["ImageID"]

    end = time.time()
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    print(
        "The time Taken For update managed nodegroups ",
        "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )
    logs_pusher(
        regionName=region,
        cluster_name=clust_name,
        msg="The time Taken For update managed nodegroups "
        + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )

    return d


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# creates a managed nodegroup
def create_managed_nodegroup(region, clust_name, client):
    start_time = time.ctime()
    start = time.time()
    logs_pusher(
        regionName=region, cluster_name=clust_name, msg="creation of managed nodegroups Started At " + str(start_time)
    )

    start_time = time.ctime()
    start = time.time()
    logs_pusher(regionName=region, cluster_name=clust_name, msg="The Addons Upgrade Started At " + str(start_time))

    args = "~/eksctl create nodegroup --managed --cluster=" + clust_name
    output = subprocess.call(args, shell=True)

    end = time.time()
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    print(
        "The time Taken For the creation of managed nodegroups ",
        "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )
    logs_pusher(
        regionName=region,
        cluster_name=clust_name,
        msg="The time Taken For the creation of managed nodegroups  "
        + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )

    print(output)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# creates unmanaged nodegroup
def create_unmanaged_nodegroup(region, clust_name, client):
    start_time = time.ctime()
    start = time.time()
    logs_pusher(
        regionName=region, cluster_name=clust_name, msg="creation of Unmanaged nodegroups Started At " + str(start_time)
    )

    args = "~/eksctl create nodegroup --cluster=" + clust_name
    output = subprocess.call(args, shell=True)

    end = time.time()
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    print(
        "The time Taken For the creation of Unmanaged nodegroups ",
        "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )
    logs_pusher(
        regionName=region,
        cluster_name=clust_name,
        msg="The time Taken For the creation of Unmanaged nodegroups  "
        + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )

    print(output)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# updates managed existing managed node group
def update_managed_nodegroup(region, clust_name, version, d, bclient):
    print("managed node group upgrade started")
    start_time = time.ctime()
    start = time.time()
    logs_pusher(
        regionName=region, cluster_name=clust_name, msg="Updation of managed nodegroups Started At " + str(start_time)
    )

    response = bclient.list_nodegroups(
        clusterName=clust_name,
    )
    d["managed_nodegroup_after_update"] = {}
    if response["nodegroups"] != []:  # to verify if MANAGED NODEGROUP exists
        for i in response["nodegroups"]:
            response = bclient.describe_nodegroup(clusterName=clust_name, nodegroupName=i)
            print("nodegroup " + i + "version before upgrade is " + response["nodegroup"]["version"])
            args = (
                "~/eksctl upgrade nodegroup --name="
                + i
                + " --cluster="
                + clust_name
                + " --kubernetes-version="
                + version
            )  # UPDATES MANAGED NODEGROUP
            output = subprocess.call(args, shell=True)
            response = bclient.describe_nodegroup(clusterName=clust_name, nodegroupName=i)
            print("nodegroup " + i + "version after upgrade is " + response["nodegroup"]["version"])
            d["managed_nodegroup_after_update"][i] = response["nodegroup"]["version"]

    else:
        print("no managed nodegroups found")
        return d

    end = time.time()
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    print(
        "The time Taken For the Updation of managed nodegroups ",
        "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )
    logs_pusher(
        regionName=region,
        cluster_name=clust_name,
        msg="The time Taken For the Updation of managed nodegroups  "
        + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
    )

    return d


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def eksctl_execute(args):
    # ~~~~~~~~~~~~~~~~~~~~~~~~~INPUT
    clust_name = args.name
    version = args.version
    region = args.region

    bclient = botoclient(region)
    loading_config(clust_name, region)

    v1 = client.CoreV1Api()

    rep = v1.list_namespaced_pod("kube-system")
    d = {}
    # ~~~~~~~~~~~~~~~~~~~~~~~~~UPGRADE
    # call to upgrade cluster to latest version
    d = upgrade_cluster(region, clust_name, d, bclient, version)
    # #call to upgrade addons to latest version
    d = add_on_upgrade(region, clust_name, d, v1)
    # call to update managed nodegroup
    d = update_managed_nodegroup(region, clust_name, str(version), d, bclient)
    # call to update unmanaged nodegroup b
    d = update_unmanaged_nodegroup(region, clust_name, d, bclient)
    loading_config(clust_name, region)

    v1 = client.CoreV1Api()

    rep = v1.list_namespaced_pod("kube-system")
    d["addonsafterupdate"] = {}
    for pod in rep.items:
        print(pod.metadata.name, "Current Version = ", pod.spec.containers[0].image.split(":")[-1])
        d["addonsafterupdate"][pod.metadata.name] = pod.spec.containers[0].image.split(":")[-1]

    print(json.dumps(d, indent=4))
