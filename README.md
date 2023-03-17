# Amazon EKS Upgrade Utility

<p align="center">
<a href="https://github.com/aws-samples/eks-cluster-upgrade/actions/workflows/validate.yaml"><img alt="Validation Status" src="https://github.com/aws-samples/eks-cluster-upgrade/actions/workflows/validate.yaml/badge.svg?branch=main&event=push"></a>
<a href="https://codecov.io/github/aws-samples/eks-cluster-upgrade?branch=main"><img alt="Coverage Status" src="https://codecov.io/github/aws-samples/eks-cluster-upgrade/coverage.svg?branch=main"></a>
<a href="https://pypi.org/project/eksupgrade/"><img alt="PyPI" src="https://img.shields.io/pypi/v/eksupgrade"></a>
<a href="https://pepy.tech/project/eksupgrade"><img alt="Downloads" src="https://pepy.tech/badge/eksupgrade"></a>
</p>

Amazon EKS cluster upgrade is a utility that automates the upgrade process for Amazon EKS clusters.

## Process

The process for upgrading an Amazon EKS cluster using `eksupgrade` consists of primarily of three parts:

1. Perform pre-flight checks prior to upgrading the cluster
2. Upgrade the cluster
3. Evaluate the cluster after upgrade

### Pre-Flight Checks

There are a number of version compatibility constraints, health checks, etc., before a cluster can successfully be upgraded. `eksupgrade` performs the following pre-flight checks:

1. Target Version Compatibility Check - Since any cluster in EKS is always allowed to upgrade to one version above and not beyond, a check for the target version is done as with each upgrade there are a lot of configuration changes and upgrading directly to a higher version can lead to breakdown of the services being provided by it.
2. Customer Management Key - A cluster might have a CMK Key associated with it, so it is essential to verify if the same exists in user's account before carrying out the upgrade.
3. Security Group - Every cluster has a security group associated with it to restrict and allow the flow of traffic across it, and therefore it has to be verified whether it exists in the user's VPC or not.
4. Node group and worker node detail - EKS cluster supports multiple types of node groups. So for the purpose of upgrade, their kubelet version compatibility has to be checked to proceed with the upgrade step.
5. Subnets - A minimum of 4-5 free IPs are required when doing a cluster upgrade to launch new nodes and node groups with the old ones to keep the services of the cluster running while the upgrade is going on. So check on the existence of the free IPs is performed.
6. Cluster Roles - There are a lot of important cluster roles required during the upgrade related to addons, nodes, and other components of the cluster without which the cluster upgrade cannot be executed successfully.
7. Pod Security Policy - EKS privileged role has to be checked to be present with the current pod security policy. (deprecated in Kubernetes v1.21, and removed from Kubernetes in v1.25)
8. Cluster addons - The cluster addons like kube-proxy, VPC CNI and CoreDNS are essential for running various services across the cluster. The parameters available on these addons which are customized by the users on the target cluster have to be captured while upgrading so that they are to added back to maintain service availability. 
9. Pod Disruption Budget - The existence of PDB has to be checked in the cluster, and minimum and maximum available with it has to be taken into account while upgrading.
10. Horizontal Pod and Cluster Autoscaler - As the other components are upgraded to the compatible image version, a check is performed to see if Cluster or Horizontal Pod Autoscaler are present. They are reviewed to upgrade to a compatible version with respect to the control plane.

### Cluster Upgrade

1. Control plane upgrade - This is handled entirely by AWS once the version upgrade has been requested.
2. Identification of Managed and Self-managed node - The worker nodes are identified as EKS managed and Self-managed to perform upgrade.
3. Managed Node group update - Updates managed node group to the specified version.
4. Self-managed Node group update
   - Launch new nodes with upgraded version and wait until they require ready status for next step.
   - Mark existing nodes as unschedulable.
   - If pod disruption budget (PDB) is present then check for force eviction flag (--force) which is given by user, only then evict the pods or continue with the flow.

## Pre-Requisites

Before running `eksupgrade`, you will need to have permission for both AWS and the Kubernetes cluster itself.

1. Install `eksupgrade` locally:

```sh
pip install eksupgrade
```

2. Ensure you have the necessary AWS permissions; an example policy of required permissions is listed below:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "iam",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "sts:GetAccessKeyInfo",
        "sts:GetCallerIdentity",
        "sts:GetSessionToken"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ec2",
      "Effect": "Allow",
      "Action": [
        "autoscaling:CreateLaunchConfiguration",
        "autoscaling:Describe*",
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
        "autoscaling:UpdateAutoScalingGroup",
        "ec2:Describe*",
        "ssm:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "eks",
      "Effect": "Allow",
      "Action": [
        "eks:Describe*",
        "eks:List*",
        "eks:UpdateAddon",
        "eks:UpdateClusterVersion",
        "eks:UpdateNodegroupVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

3. Update your local kubeconfig to authenticate to the cluster:

```sh
aws eks update-kubeconfig --name <CLUSTER-NAME> --region <REGION>
```

## Usage

To view the arguments and options, run:

```sh
eksupgrade --help
```

```sh
usage: eksupgrade [-h] [--pass_vpc] [--max_retry MAX_RETRY] [--force]
                  [--preflight] [--disable-checks] [--parallel]
                  [--latest-addons] [--log-level LOG_LEVEL] [--version]
                  name version region

Amazon EKS cluster upgrade

positional arguments:
  name                  Cluster Name
  version               new version which you want to update
  region                The AWS region where the cluster resides

optional arguments:
  -h, --help            show this help message and exit
  --pass_vpc            this --pass-vpc will skip the vpc cni upgrade
  --max_retry MAX_RETRY
                        you can specify max retry or else by default it is 2
  --force               force pod eviction when you have pdb
  --preflight           Run pre-flight check without upgrade
  --disable-checks      Totally disable the pre-flight and post-flight
                        checks during upgrade scenarios
  --parallel            Upgrade all nodegroups in parallel
  --latest-addons       Upgrade addons to the latest eligible version
                        instead of default
  --log-level LOG_LEVEL
                        The log level to be displayed in the console.
                        Default to: INFO
  --version             show program's version number and exit

example:

  eksupgrade <name> <version> <region>

Force pod eviction when you have PDB (Pod Disruption Budget):

  eksupgrade <name> <version> <region>n --force

Skip VPC CNI upgrade:

  eksupgrade <name> <version> <region> --pass_vpc

Skip upgrade workflow:

  eksupgrade <name> <version> <region> --preflight

Set log level to console (default to INFO):

  eksupgrade <name> <version> <region> --log-level debug

Display the eksupgrade version:

  eksupgrade --version
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
