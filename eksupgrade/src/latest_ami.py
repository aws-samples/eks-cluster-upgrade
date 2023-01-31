import boto3


def get_latestami(clustVersion, instancetype, image_to_search, region_Name):
    ssm = boto3.client("ssm", region_name=region_Name)
    client = boto3.client("ec2", region_name=region_Name)
    if "Amazon Linux 2" in instancetype:
        names = [
            "/aws/service/eks/optimized-ami/{version}/amazon-linux-2/recommended/image_id".format(version=clustVersion),
        ]
    elif "Windows" in instancetype:
        names = [
            "/aws/service/ami-windows-latest/{image_to_search}-{version}/image_id".format(
                image_to_search=image_to_search, version=clustVersion
            )
        ]
    elif "bottlerocket" in instancetype.lower():
        names = ["/aws/service/bottlerocket/aws-k8s-{version}/x86_64/latest/image_id".format(version=clustVersion)]
    elif "Ubuntu" in instancetype:
        filters = [
            {"Name": "owner-id", "Values": ["099720109477"]},
            {"Name": "name", "Values": ["ubuntu-eks/k8s_{version}*".format(version=clustVersion)]},
            {"Name": "is-public", "Values": ["true"]},
        ]
        response = client.describe_images(Filters=filters)
        x = sorted(response["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if len(x) > 0:
            return x[0].get("ImageId")
        else:
            raise Exception("Couldn't Find Latest Image Retry The Script")
    else:
        return "NAN"
    response = ssm.get_parameters(Names=names)
    if len(response.get("Parameters")) > 0:
        return response.get("Parameters")[0]["Value"]
    else:
        raise Exception("Couldn't Find Latest Image Retry The Script")
