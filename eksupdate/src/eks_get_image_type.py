import boto3

from .k8s_client import find_node


def image_type(node_type, Presentversion, inst, regionName):
    """returning image location"""
    ec2_client = boto3.client("ec2", region_name=regionName)
    if node_type == "Amazon Linux 2":
        filters = [
            {"Name": "owner-id", "Values": ["602401143452"]},
            {"Name": "name", "Values": ["amazon-eks-node-*"]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    elif "ubuntu" in node_type.lower():
        filters = [
            {"Name": "owner-id", "Values": ["099720109477"]},
            {"Name": "name", "Values": ["ubuntu-eks/k8s_*"]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    elif "bottlerocket" in node_type.lower():
        filters = [
            {"Name": "owner-id", "Values": ["092701018921"]},
            {"Name": "name", "Values": ["bottlerocket-aws-k8s-*"]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    elif "Windows" in node_type:
        filters = [
            {"Name": "owner-id", "Values": ["801119661308"]},
            {"Name": "name", "Values": ["Windows_Server-*-English-*-EKS_Optimized-*"]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    else:
        return True
    """ decribing image types"""
    images = ec2_client.describe_images(Filters=filters)
    instances_list = []
    for i in images.get("Images"):
        instances_list.append([i.get("ImageId"), i.get("Name")])
    for i in instances_list:
        if inst in i[0]:
            return i[1]
    return inst in instances_list


def get_ami_name(cluster_name, asg_name, PresentVersion, regionName):
    asg_client = boto3.client("autoscaling", region_name=regionName)
    ec2_client = boto3.client("ec2", region_name=regionName)
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    instance_ids = [instance["InstanceId"] for instance in response["AutoScalingGroups"][0]["Instances"]]
    if len(instance_ids) == 0:
        raise Exception("No Instances")

    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    ans = []
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["ImageId"]
            """ getting the instance type as amz2 or windows or ubuntu """
            node_type = find_node(cluster_name, instance["InstanceId"], "os_type", regionName)
            ans.append(
                [
                    node_type,
                    image_type(
                        node_type=node_type, Presentversion=PresentVersion, inst=instance_id, regionName=regionName
                    ),
                ]
            )
    """ custom logic to check wether the os_type is same if same returning and if not returing the least repeated  name"""
    result = False
    if len(ans) > 0:
        result = all(elem[0] == ans[0][0] for i, elem in enumerate(ans))
        if result:
            return ans[0]
        else:
            dd = {}
            ac = {}
            for (d, ak) in ans:
                dd[d] = dd.get(d, 0) + 1
                ac[d] = ac.get(d, ak)
            return min((ac.get(d, ""), d) for d in dd)
