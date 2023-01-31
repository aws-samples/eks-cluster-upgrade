import datetime
import time
import uuid

import boto3

from .ekslogs import logs_pusher


def status_of_cluster(Clustname, regionName):
    eks_client = boto3.client("eks", region_name=regionName)
    """checking the satus of the cluster and version of the cluster """
    try:
        response = eks_client.describe_cluster(name=Clustname)
        return [response["cluster"]["status"], response["cluster"]["version"]]

    except Exception as e:
        # logs_pusher(e,"error")
        print(e)
        raise Exception(str(e))


def is_cluster_exists(Clustname, regionName):
    """checking wether the cluster exists or not"""
    try:
        response = status_of_cluster(Clustname, regionName)
        return response[0]
    except Exception as e:
        # logs_pusher(e,"error")
        raise Exception(e)


def get_latest_instance(asg_name, add_time, regionName):
    """Retrieve the most recently launched/launching instance. Note that this is not necessarily the same one that was launched by `add_node()`, but it's the best I could think of"""
    asg_client = boto3.client("autoscaling", region_name=regionName)
    ec2_client = boto3.client("ec2", region_name=regionName)
    instances = []

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    time.sleep(20)
    instance_ids = [instance["InstanceId"] for instance in response["AutoScalingGroups"][0]["Instances"]]

    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(instance)
    # print(instances)
    instance_launch_times = [{x["PrivateDnsName"]: x["LaunchTime"]} for x in instances]

    instances_valid = []
    instances_valid = [
        instance
        for instance in instances
        if instance["State"]["Name"] in ["pending", "running"] and instance["LaunchTime"] > add_time
    ]

    latest_instance = ""
    try:
        time.sleep(10)
        latest_instance = sorted(instances_valid, key=lambda instance: instance["LaunchTime"])[-1]
    except Exception as e:
        # logs_pusher(e,"error")
        raise Exception(e)

    return latest_instance.get("InstanceId")


def wait_for_ready(instanceid, regionName):

    ec2_client = boto3.client("ec2", region_name=regionName)
    st = time.time()

    """ waiting for the cluster to pass the status checks """
    print(instanceid + " waiting for the instance to pass the Health Checks ")
    try:
        while (
            ec2_client.describe_instance_status(InstanceIds=[instanceid])["InstanceStatuses"][0]["InstanceStatus"][
                "Details"
            ][0]["Status"]
            != "passed"
        ):
            end = time.time()
            hours, rem = divmod(end - st, 3600)
            minutes, seconds = divmod(rem, 60)
            print(
                instanceid,
                " waiting for the instance to pass the Health Checks ",
                "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
            )

            time.sleep(20)
    except Exception as e:
        print(e)
        raise Exception(str(e) + " Please rerun the Script the instance will be created")
    return True


def check_asg_autoscaler(asg_name, regionName):
    """Checking wether the autoscaling is present or not"""
    asg_client = boto3.client("autoscaling", region_name=regionName)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    pat = "k8s.io/cluster-autoscaler/enabled"
    asg_list = []
    for asg in response["AutoScalingGroups"][0]["Tags"]:
        if asg["Key"] == pat:
            asg_list.append(asg)
    """ checking wether asg is present """
    return len(asg_list) > 0


def enable_disable_autoscaler(asg_name, action, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)
    try:
        if action == "pause":
            asg_client.delete_tags(
                Tags=[
                    {
                        "ResourceId": asg_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": "k8s.io/cluster-autoscaler/enabled",
                    },
                ]
            )
            return "done"
        elif action == "start":
            asg_client.create_or_update_tags(
                Tags=[
                    {
                        "ResourceId": asg_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": "k8s.io/cluster-autoscaler/enabled",
                        "Value": "true",
                        "PropagateAtLaunch": False,
                    },
                ]
            )
            return "done"
        else:
            print("Invalid Method")
    except Exception as e:
        print(e)
        raise Exception(e)
    finally:
        return "Something went Wrong auto scaling operation failed"


def update_cluster(Clustname, Version, regionName):
    eks_client = boto3.client("eks", region_name=regionName)
    """ checking for cluster update """
    logs_pusher(
        regionName=regionName,
        cluster_name=Clustname,
        msg="The Cluster status = {Status} and version = {Version}".format(
            Status=status_of_cluster(Clustname, regionName)[0], Version=status_of_cluster(Clustname, regionName)[1]
        ),
    )
    try:
        if status_of_cluster(Clustname, regionName)[1] == Version:
            print(
                "The {clustname} cluster is already Updated to {version}".format(clustname=Clustname, version=Version)
            )
            logs_pusher(
                regionName=regionName,
                cluster_name=Clustname,
                msg="The {clustname} cluster is already Updated to {version}".format(
                    clustname=Clustname, version=Version
                ),
            )
            return True
        start = time.time()
        while True:
            if (
                is_cluster_exists(Clustname, regionName) == "ACTIVE"
                and status_of_cluster(Clustname, regionName)[1] != Version
            ):
                resp = eks_client.update_cluster_version(name=Clustname, version=Version)
                print(
                    "The {clustname} Cluster upgrade is initiated and getting updated to  {version} ".format(
                        clustname=Clustname, version=Version
                    )
                )
                time.sleep(40)
                print(
                    "The {clustname} is still in the upgrade process this usually takes longer time..... ".format(
                        clustname=Clustname
                    )
                )
                time.sleep(20)

            if is_cluster_exists(Clustname, regionName) == "UPDATING":
                # logs_pusher("Still Updating","info")
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                print(
                    "The Cluster {Clustname} is Still Updating to {version} .....".format(
                        Clustname=Clustname, version=Version
                    ),
                    "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
                )
                time.sleep(20)

            if (
                is_cluster_exists(Clustname, regionName) == "ACTIVE"
                and status_of_cluster(Clustname, regionName)[1] == Version
            ):
                print("The {clustname} Updated to {version}".format(clustname=Clustname, version=Version))
                logs_pusher(
                    regionName=regionName,
                    cluster_name=Clustname,
                    msg="The {clustname} cluster is already Updated to {version}".format(
                        clustname=Clustname, version=Version
                    ),
                )

                break

        return True
    except Exception as e:
        # logs_pusher(e,"error")
        raise Exception(e)


def worker_terminate(instance_id, regionName):
    """terminating instance and decreasing the desired capacity whit asg terminate instance"""
    asg_client = boto3.client("autoscaling", region_name=regionName)

    try:
        asg_client.terminate_instance_in_auto_scaling_group(InstanceId=instance_id, ShouldDecrementDesiredCapacity=True)
    except Exception as e:
        # logs_pusher(e,"error")
        raise Exception(e)


def add_node(asg_name, regionName):
    """add node to particular asg"""
    asg_client = boto3.client("autoscaling", region_name=regionName)

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    try:
        old_capacity_mx = response["AutoScalingGroups"][0]["MaxSize"]
        old_capacity_des = response["AutoScalingGroups"][0]["DesiredCapacity"]
    except Exception as e:
        raise Exception("Error Index out of bound due to no max capacity field")
    if int(old_capacity_des) >= int(old_capacity_mx):
        asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name, MaxSize=(int(old_capacity_mx) + int(old_capacity_des))
        )

    old_capacity = response["AutoScalingGroups"][0]["DesiredCapacity"]
    new_capacity = old_capacity + 1
    try:
        asg_client.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=new_capacity)
        # logs_pusher("New Node Added to"+asg_name+"with capacity"+str(new_capacity),"info")
        print("New Node has been Added to " + asg_name)
    except Exception as e:
        # logs_pusher(e,"error")
        raise Exception(e)


def get_num_of_instances(asg_name, exclude_ids, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)

    ec2_client = boto3.client("ec2", region_name=regionName)

    """counting the number of instances """
    instances = []

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instance_ids = [
        instance["InstanceId"]
        for instance in response["AutoScalingGroups"][0]["Instances"]
        if instance["InstanceId"] not in exclude_ids
    ]
    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(instance)
    """ getting the instance in running or pending state"""
    instances = [instance for instance in instances if instance["State"]["Name"] in ["running", "pending"]]

    return len(instances)


def get_Asgs(cluster_name, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)

    """
     We get a list of Asg's (auto scaling groups) Which will mach our format 
     "kubernetes.io/cluster/{cluster_name}"
     and returns an empty list if none are found

    """
    pat = "kubernetes.io/cluster/{clusterName}"
    response = asg_client.describe_auto_scaling_groups()
    matching = []
    for asg in response["AutoScalingGroups"]:
        # print(asg)
        # logs_pusher(asg,"info")

        for tg in asg["Tags"]:
            # print(tag)

            if tg["Key"] == pat.format(clusterName=cluster_name):
                matching.append(asg)
    matching_names = [x["AutoScalingGroupName"] for x in matching]
    logs_pusher(regionName=regionName, cluster_name=cluster_name, msg="ASG Matched = " + " ,".join(matching_names))
    return matching_names


def get_latest_lt_version(lt_id, regionName):
    ec2_client = boto3.client("ec2", region_name=regionName)

    """ getting the latest launch template version """
    response = ec2_client.describe_launch_templates(LaunchTemplateIds=[lt_id])
    latest_version = response["LaunchTemplates"][0]["LatestVersionNumber"]
    # logs_pusher(latest_version,"info")
    return latest_version


def old_lt_secanarios(inst, asg_lt_name, asg_lt_version):
    """Getting old launch template based on launch template name and version 1!=2"""
    lt_name = inst["LaunchTemplate"]["LaunchTemplateName"]
    lt_version = int(inst["LaunchTemplate"]["Version"])
    if lt_name != asg_lt_name:
        return True
    elif lt_version != int(asg_lt_version):
        return True
    else:
        return False


def get_old_lt(asg_name, regionName):
    """Get old launc template"""
    asg_client = boto3.client("autoscaling", region_name=regionName)
    ec2_client = boto3.client("ec2", region_name=regionName)

    old_lt_instance_ids = []
    instances = []

    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    asg_lt_name = ""
    # print(response)
    """ finding the launch type"""
    if "LaunchTemplate" in response["AutoScalingGroups"][0]:
        lt_id = response["AutoScalingGroups"][0]["LaunchTemplate"]["LaunchTemplateId"]
        asg_lt_name = response["AutoScalingGroups"][0]["LaunchTemplate"]["LaunchTemplateName"]
    elif "MixedInstancesPolicy" in response["AutoScalingGroups"][0]:
        lt_id = response["AutoScalingGroups"][0]["MixedInstancesPolicy"]["LaunchTemplate"][
            "LaunchTemplateSpecification"
        ]["LaunchTemplateId"]
        asg_lt_name = response["AutoScalingGroups"][0]["MixedInstancesPolicy"]["LaunchTemplate"][
            "LaunchTemplateSpecification"
        ]["LaunchTemplateName"]

    else:
        # logs_pusher("None found","error")
        return "error"

    # print(latest_lt)
    """ checking wethether there are instances with 1!=2 mismatch template version """
    old_lt_instance_ids = [
        instance["InstanceId"]
        for instance in response["AutoScalingGroups"][0]["Instances"]
        if old_lt_secanarios(instance, asg_lt_name, int(instance["LaunchTemplate"]["Version"]))
    ]
    if len(old_lt_instance_ids) == 0:
        return []
    response = ec2_client.describe_instances(InstanceIds=old_lt_instance_ids)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            # logs_pusher(instance,"info")
            instances.append(instance)

    return instances


def old_launchConfiguation_instances(asg_name, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)

    old_lc_ids = []
    """ describing the asg group """
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    # print(response)
    instances = response["AutoScalingGroups"][0]["Instances"]
    # print(instances)
    for inst in instances:
        # print(inst)
        # logs_pusher(inst)
        """checking the LaunchConfiguration is matching or not"""
        if inst.get("LaunchConfigurationName") != response["AutoScalingGroups"][0]["LaunchConfigurationName"]:
            old_lc_ids.append(inst["InstanceId"])
    return old_lc_ids


def outdated_lt(asgs, regionName):
    """Getting outdated launch template"""
    asg_client = boto3.client("autoscaling", region_name=regionName)
    asg = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asgs])
    # print(asg)
    # # print(asg)
    asg_name = asg["AutoScalingGroups"][0]["AutoScalingGroupName"]
    # print(asg_name)
    # logs_pusher(asg_name)
    launch_type = ""
    if "LaunchConfigurationName" in asg["AutoScalingGroups"][0]:
        launch_type = "LaunchConfiguration"
    elif "LaunchTemplate" in asg["AutoScalingGroups"][0]:
        launch_type = "LaunchTemplate"
    elif "MixedInstancesPolicy" in asg["AutoScalingGroups"][0]:
        launch_type = "LaunchTemplate"
    else:
        return []
    old_instances = []

    # logs_pusher(launch_type)
    if launch_type == "LaunchConfiguration":
        temp = old_launchConfiguation_instances(asg_name, regionName)
        if len(temp) > 0:
            old_instances = temp
            return old_instances
        else:
            return []
            """ checking with launch Template"""
    if launch_type == "LaunchTemplate":
        temp = get_old_lt(asg_name, regionName)
        if len(temp) > 0:
            old_instances = temp
            return old_instances
        else:
            return []

    return []


def addAutoScaling(asg_name, img_id, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)

    """ Adding new Launch Configuration to the Asg"""
    timeStamp = time.time()
    timeStampString = datetime.datetime.fromtimestamp(timeStamp).strftime("%Y-%m-%d  %H-%M-%S")
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])

    # print(response)
    sourceInstanceId = response.get("AutoScalingGroups")[0]["Instances"][0]["InstanceId"]
    # print(sourceInstanceId)
    k = str(uuid.uuid4())
    newLaunchConfigName = "LC " + img_id + " " + timeStampString + " " + k

    try:
        asg_client.create_launch_configuration(
            InstanceId=sourceInstanceId, LaunchConfigurationName=newLaunchConfigName, ImageId=img_id
        )
        response = asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name, LaunchConfigurationName=newLaunchConfigName
        )
        print("updated to latest launch configuration")
    except Exception as e:
        print(e)
        # logs_pusher(e)
    return response


def get_outdated_Asg(asg_name, latest_img, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)
    ec2_client = boto3.client("ec2", region_name=regionName)

    """Getting outdate asuto scaling group """
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instance_ids = [instance["InstanceId"] for instance in response["AutoScalingGroups"][0]["Instances"]]
    old_ami_inst = []
    """ filetering old instance where the logic is used to check wether we should add new launch configuration or not """
    inst_response = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in inst_response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["ImageId"] != latest_img:
                old_ami_inst.append(instance["InstanceId"])
    instance_ids.sort()
    old_ami_inst.sort()
    if len(old_ami_inst) != len(instance_ids):
        return False
    else:
        for i in range(len(old_ami_inst)):
            if old_ami_inst[i] != instance_ids[i]:
                return False
        return True
