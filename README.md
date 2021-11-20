[![Open Source Love svg1](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)]()


## EKS one click upgrade 

TODO: Fill this README out!

Amazon Elastic Kubernetes Service (Amazon EKS) is a managed service that you can use to run Kubernetes on AWS without needing to install, operate, and maintain your own Kubernetes control plane or nodes. Kubernetes is an open-source system for automating the deployment, scaling, and management of containerized applications.
Working with EKS starts with creating a cluster and an Amazon EKS cluster consists of two primary components:

1. Amazon EKS control plane
2. Amazon EKS nodes that are registered with the control plane

The current process of EKS cluster upgrade includes
1. Check the k8s object compatibility with regards to API specific Changes
2. Check the version of Core Kubernetes Components and do changes as per the changes required in the newer
version which is compatible with the targeted version.
3. Check worker node version and control plane version and ensure that they are in same version
4. Check Enough IPs are there in the Subnet and the Customer account has not reached the ENI limit
5. Do Control Plane Upgrade
6. Do Node Upgrade and graceful shift of workloads to newer instances
7. Check for stability of Core K8s Components after Cluster Upgrade.

Be sure to:

* Change the title in this README
* Edit your repository description on GitHub

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.


### 🤝 Contributing

[![ForTheBadge built-with-love](http://ForTheBadge.com/images/badges/made-with-python.svg)]() 
[![ForTheBadge built-with-love](http://ForTheBadge.com/images/badges/built-with-love.svg)]()

