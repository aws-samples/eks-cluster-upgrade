import time

import boto3

from .ekslogs import logs_pusher
from .latest_ami import get_latestami


def status_of_cluster(Clustname, regionName):
    client = boto3.client("eks", region_name=regionName)
    """ Getting Self Managed Cluster Status"""
    response = client.describe_cluster(name=Clustname)
    logs_pusher(
        regionName=regionName,
        cluster_name=Clustname,
        msg="The Cluster Status = {stat} and Version = {ver}".format(
            stat=response["cluster"]["status"], ver=response["cluster"]["version"]
        ),
    )
    return [response["cluster"]["status"], response["cluster"]["version"]]


def get_node_groups(Clustername, regionName):
    client = boto3.client("eks", region_name=regionName)
    """ Getting Node Group list"""
    response = client.list_nodegroups(clusterName=Clustername, maxResults=100)

    return response["nodegroups"]


def Desc_node_groups(Clustername, Nodegroup, regionName):
    client = boto3.client("eks", region_name=regionName)
    """ Getting Descrption of Node Gorup """
    response = client.describe_nodegroup(clusterName=Clustername, nodegroupName=Nodegroup)
    logs_pusher(
        regionName=regionName,
        cluster_name=Clustername,
        msg="The NodeGroup = {ng} Status = {stat} and Version = {ver}".format(
            ng=Nodegroup, stat=response.get("nodegroup")["status"], ver=response.get("nodegroup")["version"]
        ),
    )
    return [response.get("nodegroup")["status"], response.get("nodegroup")["version"]]


def get_asg_node_groups(Clustername, regionName):
    client = boto3.client("eks", region_name=regionName)
    """ Getting asg of self managed node groups """
    asg_groups = []
    node_groups = get_node_groups(Clustername, regionName)
    if len(node_groups) == 0:
        return []

    for ng in node_groups:
        response = client.describe_nodegroup(clusterName=Clustername, nodegroupName=ng).get("nodegroup")["resources"][
            "autoScalingGroups"
        ]
        for asg_name in response:
            asg_groups.append(asg_name["name"])
    logs_pusher(
        regionName=regionName, cluster_name=Clustername, msg="The Asg's Of Node Groups ".format(inst=asg_groups)
    )

    return asg_groups


def filter_node_groups(cluster_name, node_list, latest_version, regionName):
    """filtering Node groups"""
    old_ng = []
    for ng in node_list:
        print("filter node group ", ng)
        status, version = Desc_node_groups(Clustername=cluster_name, Nodegroup=ng, regionName=regionName)
        if (status == "ACTIVE" or status == "UPDATING") and not version == latest_version:
            old_ng.append(ng)
    logs_pusher(
        regionName=regionName,
        cluster_name=cluster_name,
        msg="The Old Manged Node Groups Found Are {inst} ".format(inst=old_ng),
    )

    return old_ng


def lt_id_func(Clustername, Nodegroup, Version, regionName):
    client = boto3.client("eks", region_name=regionName)
    ec2 = boto3.client("ec2", region_name=regionName)
    res = client.describe_nodegroup(clusterName=Clustername, nodegroupName=Nodegroup)
    Lt_id = ""
    version_no = ""
    AmiType = res["nodegroup"]["amiType"]
    if res["nodegroup"].get("launchTemplate"):
        Lt_id, version_no = res["nodegroup"]["launchTemplate"]["id"], res["nodegroup"]["launchTemplate"]["version"]
        os_lt = ec2.describe_launch_template_versions(LaunchTemplateId=Lt_id, Versions=[version_no])
    latest_ami = ""
    if AmiType == "CUSTOM":
        current_ami = os_lt["LaunchTemplateVersions"][0]["LaunchTemplateData"]["ImageId"]
        os_type = ec2.describe_images(ImageIds=[current_ami])["Images"][0]["ImageLocation"]

        if isinstance(os_type, str) and "Windows_Server" in os_type:
            os_type = os_type[:46]

        latest_ami = get_latestami(
            clustVersion=Version, instancetype=os_type, image_to_search=os_type, region_Name=regionName
        )

    return AmiType, Lt_id, version_no, latest_ami


def update_current_launch_template_ami(lt_id, latest_ami, regionName):
    ec2 = boto3.client("ec2", region_name=regionName)
    response = ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        SourceVersion="$Latest",
        VersionDescription="Latest-AMI",
        LaunchTemplateData={"ImageId": latest_ami},
    )
    print(f"New launch template created with AMI {latest_ami}")


def Update_nodeGroup(Clustername, Nodegroup, Version, regionName):
    client = boto3.client("eks", region_name=regionName)
    start = time.time()
    """ updating Node group """

    ami_type, lt_id, _, latest_ami = lt_id_func(Clustername, Nodegroup, Version, regionName)
    if ami_type == "CUSTOM":
        update_current_launch_template_ami(lt_id, latest_ami, regionName)

    while True:
        try:
            if (
                status_of_cluster(Clustername, regionName)[0] == "ACTIVE"
                and Desc_node_groups(Clustername, Nodegroup, regionName)[0] == "ACTIVE"
                and Desc_node_groups(Clustername, Nodegroup, regionName)[1] != Version
            ):
                if ami_type == "CUSTOM":
                    client.update_nodegroup_version(
                        clusterName=Clustername,
                        nodegroupName=Nodegroup,
                        launchTemplate={"version": "$Latest", "id": lt_id},
                    )
                else:
                    client.update_nodegroup_version(
                        clusterName=Clustername,
                        nodegroupName=Nodegroup,
                        version=Version,
                    )
                print("Updating Node Group ", Nodegroup)
                time.sleep(20)
            if Desc_node_groups(Clustername, Nodegroup, regionName)[0] == "UPDATING":
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                print(
                    "The {Ng}".format(Ng=Nodegroup) + " NodeGroup is Still Updating ",
                    "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
                )
                time.sleep(20)
            if Desc_node_groups(Clustername, Nodegroup, regionName)[0] == "DEGRADED":
                raise Exception("NodeGroup has not started due to unavailability ")
            if (
                Desc_node_groups(Clustername, Nodegroup, regionName)[0] == "ACTIVE"
                and Desc_node_groups(Clustername, Nodegroup, regionName)[1] == Version
            ):
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                print(
                    "The  Time Taken For the NodeGroup Upgrade " + str(Nodegroup),
                    "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
                )

                logs_pusher(
                    regionName=regionName,
                    cluster_name=Clustername,
                    msg="The Taken For the  NodeGroup Upgrade "
                    + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
                )
                return True

        except Exception as e:
            print(e)
            raise Exception(e)
