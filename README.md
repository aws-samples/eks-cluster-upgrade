# Amazon EKS Upgrade Utility

<p align="center">
<a href="https://github.com/aws-samples/eks-cluster-upgrade/actions/workflows/validate.yaml"><img alt="Validation Status" src="https://github.com/aws-samples/eks-cluster-upgrade/actions/workflows/validate.yaml/badge.svg?branch=main&event=push"></a>
<a href="https://github.com/aws-samples/eks-cluster-upgrade/actions/workflows/e2e-test.yaml"><img alt="E2E Cluster Upgrade" src="https://github.com/aws-samples/eks-cluster-upgrade/actions/workflows/e2e-test.yaml/badge.svg?branch=main"></a>
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
 Usage: eksupgrade [OPTIONS] CLUSTER_NAME CLUSTER_VERSION REGION

 Run eksupgrade against a target cluster.

╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    cluster_name         TEXT  The name of the cluster to be upgraded [default: None] [required]                                                                                                                   │
│ *    cluster_version      TEXT  The target Kubernetes version to upgrade the cluster to [default: None] [required]                                                                                                  │
│ *    region               TEXT  The AWS region where the target cluster resides [default: None] [required]                                                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --max-retry                                    INTEGER  The most number of times to retry an upgrade [default: 2]                                                                                                   │
│ --force                 --no-force                      Force the upgrade (e.g. pod eviction with PDB) [default: no-force]                                                                                          │
│ --preflight             --no-preflight                  Run pre-flight check without upgrade [default: no-preflight]                                                                                                │
│ --parallel              --no-parallel                   Upgrade all nodegroups in parallel [default: no-parallel]                                                                                                   │
│ --latest-addons         --no-latest-addons              Upgrade addons to the latest eligible version instead of default [default: no-latest-addons]                                                                │
│ --disable-checks        --no-disable-checks             Disable the pre-flight and post-flight checks during upgrade scenarios [default: no-disable-checks]                                                         │
│ --interactive           --no-interactive                If enabled, prompt the user for confirmations [default: interactive]                                                                                        │
│ --version                                               Display the current eksupgrade version                                                                                                                      │
│ --install-completion                                    Install completion for the current shell.                                                                                                                   │
│ --show-completion                                       Show completion for the current shell, to copy it or customize the installation.                                                                            │
│ --help                                                  Show this message and exit.                                                                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
## Support & Feedback

This project is maintained by AWS Solution Architects and Consultants. It is not part of an AWS service and support is provided best-effort by the maintainers. To post feedback, submit feature ideas, or report bugs, please use the [Issues section](https://github.com/aws-samples/eks-cluster-upgrade/issues) of this repo. If you are interested in contributing, please see the [Contribution guide](https://github.com/aws-samples/eks-cluster-upgrade/blob/main/CONTRIBUTING.md).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
