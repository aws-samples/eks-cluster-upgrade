"""Define the preflight module."""
from __future__ import annotations

from typing import Any, Dict, List

import boto3
import urllib3
import yaml
from kubernetes import client

from eksupgrade.utils import echo_deprecation, echo_error, echo_info, echo_success, echo_warning, get_package_dict

from .k8s_client import get_default_version, loading_config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from eksupgrade.utils import get_logger

logger = get_logger(__name__)


# Function declaration for pre flight checks
# Verify IAM role for the Input
def pre_flight_checks(
    preflight,
    cluster_name: str,
    region: str,
    update_version: str = "",
    force_upgrade: bool = False,
) -> bool:
    """Handle the pre-flight checks."""
    echo_deprecation(
        f"The {'pre' if preflight else 'post'}-flight checks will be deprecated in the next minor release in favor of cluster summaries: #103"
    )
    echo_info(f"Running validation checks against cluster: {cluster_name}...")
    loading_config(cluster_name, region)
    report: Dict[str, Any] = {"preflight_status": True}
    customer_report: Dict[str, Any] = {}

    errors: List[str] = []
    try:
        core_v1_api = client.CoreV1Api()
        echo_info("Verifying User IAM Role...")
        core_v1_api.list_namespaced_service("default")
        echo_info("IAM role for user verified!")
        customer_report["IAM role"] = "IAM role for user verified"
        get_cluster_version(
            errors,
            cluster_name,
            region,
            update_version,
            report,
            customer_report,
            force_upgrade,
        )

        if errors:
            echo_error(
                f"{'Pre' if preflight else 'Post'} flight unsuccessful because of the following errors: {errors}",
            )
    except Exception as error:
        echo_error(f"IAM role verification failed - Error: {error}")
        report["preflight_status"] = False
        customer_report["IAM role"] = "IAM role verification failed"
    return report["preflight_status"]


# Control Plane version listing
def get_cluster_version(
    errors,
    cluster_name,
    region,
    update_version,
    report,
    customer_report,
    force_upgrade,
) -> None:
    """Determine the cluster version."""
    loading_config(cluster_name, region)
    echo_info("Fetching cluster details...")
    eks = boto3.client("eks", region_name=region)
    try:
        cluster_details = eks.describe_cluster(name=cluster_name)
        report["cluster"] = {
            "version": cluster_details["cluster"]["version"],
            "region": cluster_details["cluster"]["arn"].split(":")[3],
        }
        echo_info(f"Cluster control plane version {report['cluster']['version']}")
        customer_report["cluster version"] = "Cluster control plane version " + report["cluster"]["version"]
        if update_version:
            if cluster_details["cluster"]["version"] == update_version:
                echo_warning(f"Cluster already upgraded to version {cluster_details['cluster']['version']}")
                customer_report["cluster upgradation"] = (
                    "Cluster already upgraded to version " + cluster_details["cluster"]["version"]
                )
            elif (round(float(update_version) - float(cluster_details["cluster"]["version"]), 2)) == 0.01:
                echo_info(
                    f"Cluster with version {cluster_details['cluster']['version']} can be updated to target version {update_version}",
                )
                customer_report[
                    "cluster upgradation"
                ] = f"Cluster with version {cluster_details['cluster']['version']} can be updated to target version {update_version}"
            else:
                customer_report[
                    "cluster upgradation"
                ] = f"Cluster with version {cluster_details['cluster']['version']} cannot be updated to target version {update_version}"
                echo_error(
                    f"Cluster with version {cluster_details['cluster']['version']} cannot be updated to target version {update_version}",
                )
                report["preflight_status"] = False
                errors.append(
                    f"Cluster with version {cluster_details['cluster']['version']} cannot be updated to target version {update_version}"
                )
                return
        cmk_key_check(errors, cluster_name, region, cluster_details, report, customer_report)
        security_group_check(errors, cluster_name, region, cluster_details, report, customer_report)
        if float(cluster_details["cluster"]["version"]) < 1.25:
            pod_security_policies(errors, cluster_name, region, report, customer_report)
        node_group_details = nodegroup_customami(errors, cluster_name, region, report, customer_report, update_version)
        report["nodegroup_details"] = node_group_details
        customer_report["nodegroup_details"] = node_group_details
        subnet_details(errors, cluster_name, region, report, customer_report)
        cluster_roles(errors, cluster_name, region, report, customer_report)
        addon_version(errors, cluster_name, region, cluster_details, report, customer_report)
        pod_disruption_budget(errors, cluster_name, region, report, customer_report, force_upgrade)
        horizontal_auto_scaler(errors, cluster_name, region, report, customer_report)
        cluster_auto_scaler(errors, cluster_name, region, report, customer_report)
        # TODO: Revisit deprecation checks. Disabled due to confusing or misleading results per GH Issue #37.
    except Exception as error:
        errors.append(f"Some error occurred during preflight check process {error}")
        customer_report["cluster version"] = "Some error occured during preflight check process"
        echo_error(f"Some error occurred during preflight check process - Error: {error}")
        report["preflight_status"] = False


# Gather Subnet Utilization from the current cluster
def subnet_details(
    errors: List[str], cluster_name: str, region: str, report: Dict[str, Any], customer_report: Dict[str, Any]
) -> None:
    """Get subnet details."""
    loading_config(cluster_name, region)
    try:
        echo_info("Checking Available IP for subnets associated with cluster...")
        eks = boto3.client("eks", region_name=region)
        cluster_details = eks.describe_cluster(name=cluster_name)
        subnets: List[Dict[str, Any]] = []
        customer_report["subnet"] = []
        encountered_errors: List[str] = []

        for subnet_id in cluster_details["cluster"]["resourcesVpcConfig"]["subnetIds"]:
            ec2 = boto3.resource("ec2", region_name=region)
            subnet = ec2.Subnet(subnet_id)

            if subnet.available_ip_address_count < 5:
                encountered_errors.append(f"Subnet ID {subnet_id} doesnt have a minimum of 5 available IP")

            customer_report["subnet"].append(
                f"Subnet ID {subnet_id} has {subnet.available_ip_address_count} available IP addresses"
            )
            echo_info(f"Subnet ID {subnet_id} has {subnet.available_ip_address_count} available IP addresses")
            subnets.append({subnet_id: subnet.available_ip_address_count})

        if encountered_errors:
            report["preflight_status"] = False
            errors.append("Available IPs for Subnet verification failed")
            echo_error("Available IPs for Subnet verification failed")
            customer_report["subnet"].append("Available IP for Subnet verification failed")
            for _error in encountered_errors:
                customer_report["subnet"].append(_error)
                echo_error(_error)
        else:
            customer_report["subnet"].append("Available IP for Subnet verified")
            echo_success("Available IPs for Subnet verified")
    except Exception as error:
        errors.append(f"Some error occurred while fetching subnet details {error}")
        echo_error(f"Some error occurred while fetching subnet details {error}")
        report["preflight_status"] = False


# Verification for required cluster roles
def cluster_roles(
    errors: List[str],
    cluster_name: str,
    region: str,
    report: Dict[str, Any],
    customer_report: Dict[str, Any],
) -> None:
    """Get cluster roles."""
    loading_config(cluster_name, region)

    try:
        echo_info("Checking important cluster role are present or not...")
        available: List[str] = []
        not_available: List[str] = []
        customer_report["cluster role"] = []

        if not_available:
            customer_report["cluster role"].append("Cluster role verification failed")
            echo_error("Cluster role verification failed")
            report["preflight_status"] = False
            errors.append("Cluster role verification failed")
            for _item in not_available:
                customer_report["cluster role"].append(f"{_item} role is not present in the cluster")
                echo_warning(f"{_item} role is not present in the cluster")
        else:
            customer_report["cluster role"].append("All cluster role needed successfully verified")
            for _item in available:
                customer_report["cluster role"].append(f"{_item} role is present in cluster")
                echo_info("{_item} role is present in the cluster")
            echo_success("All cluster role needed successfully verified")
    except Exception as error:
        errors.append(f"Some error occurred while checking the cluster roles available {error}")
        customer_report["cluster role"].append(
            f"Some error occurred while checking the cluster roles available {error}"
        )
        echo_error(f"Some error occurred while checking the cluster roles available - Error: {error}")
        report["preflight_status"] = False


def pod_security_policies(
    errors: List[str], cluster_name: str, region: str, report: Dict[str, Any], customer_report: Dict[str, Any]
) -> None:
    """Check for pod security policies."""
    loading_config(cluster_name, region)
    try:
        try:
            policy_v1_api = client.PolicyV1beta1Api()
            echo_info("Pod Security Policies...")
            ret = policy_v1_api.list_pod_security_policy(field_selector="metadata.name=eks.privileged")
        except AttributeError:
            echo_warning("Current kubernetes python client version doesn't support PSP - continuing...")
            return

        if not ret.items:
            customer_report["pod security policy"] = "Pod Security Policy with eks.privileged role doesnt exists."
            report["preflight_status"] = False
            errors.append("Pod Security Policy with eks.privileged role doesnt exists.")
            echo_warning("Pod Security Policy with eks.privileged role doesnt exists.")

        for item in ret.items:
            if item.metadata.name == "eks.privileged":
                customer_report["pod security policy"] = "Pod Security Policy with eks.privileged role exists."
                echo_success("Pod Security Policy with eks.privileged role exists.")
            else:
                customer_report["pod security policy"] = "Pod Security Policy with eks.privileged role doesnt exists."
                report["preflight_status"] = False
                errors.append("Pod Security Policy with eks.privileged role doesnt exists.")
                echo_warning("Pod Security Policy with eks.privileged role doesnt exists.")
    except Exception as error:
        errors.append(f"Some error occurred while checking for the policy security policies {error}")
        customer_report["pod security policy"] = "Some error occurred while checking for the policy security policies"
        echo_error(f"Some error occurred while checking for the policy security policies {error}")
        report["preflight_status"] = False


def addon_version(
    errors: List[str],
    cluster_name: str,
    region: str,
    cluster_details: Dict[str, Any],
    report: Dict[str, Any],
    customer_report: Dict[str, Any],
) -> None:
    """Check for compatibility between addon and control plane versions."""
    loading_config(cluster_name, region)

    yaml_data: Dict[str, Any] = {}
    config_map: Dict[str, Any] = {}

    default_version_kwargs: Dict[str, Any] = {
        "version": report["cluster"]["version"],
        "region": region,
    }

    coredns_target_version: str = get_default_version("coredns", **default_version_kwargs).split("-")[0].lstrip("v")
    proxy_target_version: str = get_default_version("kube-proxy", **default_version_kwargs).split("-")[0].lstrip("v")
    cni_target_version: str = get_default_version("vpc-cni", **default_version_kwargs).split("-")[0].lstrip("v")

    # Kube Proxy config
    kube_proxy_config = get_package_dict("kube-proxy.json")
    kube_proxy_container = kube_proxy_config["spec"]["template"]["spec"]["containers"][0]
    yaml_data["kube-proxy"] = {
        "image": kube_proxy_container["image"],
        "volumeMount": kube_proxy_container["volumeMounts"],
        "env": None,
    }

    # Core DNS config
    core_dns_config = get_package_dict("coredns.json")
    coredns_container = core_dns_config["spec"]["template"]["spec"]["containers"][0]
    yaml_data["coredns"] = {
        "image": coredns_container["image"],
        "volumeMount": coredns_container["volumeMounts"],
        "env": None,
    }

    # VPC CNI config
    vpc_cni_config = get_package_dict("vpc-cni.json")
    vpc_cni_container = vpc_cni_config["spec"]["template"]["spec"]["containers"][0]
    yaml_data["vpc-cni"] = {
        "image": vpc_cni_container["image"],
        "volumeMount": vpc_cni_container["volumeMounts"],
        "env": vpc_cni_container["env"],
    }

    # Kube Proxy config map
    kube_proxy_config_map = get_package_dict("kube-proxy-configmap.json")
    config_map["certificate-authority"] = yaml.safe_load(kube_proxy_config_map["data"]["kubeconfig"])["clusters"][0][
        "cluster"
    ]["certificate-authority"]

    try:
        echo_info("Check addon version compatibility...")
        addons: List[Dict[str, Any]] = []
        report["addon_params"] = {}
        customer_report["addons"] = {"vpc-cni": {}, "kube-proxy": {}, "coredns": {}}
        apps_v1_api = client.AppsV1Api()
        daemon_set = apps_v1_api.list_namespaced_daemon_set("kube-system")
        deployment = apps_v1_api.list_namespaced_deployment("kube-system")
        calico = apps_v1_api.list_namespaced_daemon_set("calico-system")

        if calico.items:
            echo_info("Calico addon is present in cluster")
            check_pods_running("calico", report, errors, "calico-system")

        for daemon_set_item in daemon_set.items:
            if daemon_set_item.metadata.name == "aws-node":
                version_str = (
                    daemon_set_item.spec.template.spec.containers[0].image.split("amazon-k8s-cni:v")[1].split("-")[0]
                )
                config = {
                    "image": daemon_set_item.spec.template.spec.containers[0].image,
                    "volumeMount": daemon_set_item.spec.template.spec.containers[0].volume_mounts,
                    "env": daemon_set_item.spec.template.spec.containers[0].env,
                }
                version = version_str.split(".")
                echo_info(f"Likely desired vpc-cni version: {cni_target_version}")
                check_pods_running("aws-node", report, errors)
                if int("".join(version)) >= 170:
                    addons.append({"name": "vpc-cni", "version": version_str, "update": False})
                    customer_report["addons"]["vpc-cni"]["version"] = "Up to date"
                    echo_info(f"vpc-cni version up to date")
                    check_addons_params(
                        config,
                        "vpc-cni",
                        cluster_details,
                        config_map,
                        yaml_data,
                        report,
                        customer_report,
                    )
                else:
                    addons.append({"name": "vpc-cni", "version": version_str, "update": True})
                    echo_warning("vpc-cni version is not compatible")
                    customer_report["addons"]["vpc-cni"][
                        "version"
                    ] = f"Version: {cni_target_version} not compatible with current cluster version: {version_str}"
            elif daemon_set_item.metadata.name == "kube-proxy":
                version = (
                    daemon_set_item.spec.template.spec.containers[0]
                    .image.split(daemon_set_item.metadata.name + ":v")[1]
                    .split("-")[0]
                )
                config = {
                    "image": daemon_set_item.spec.template.spec.containers[0].image,
                    "volumeMount": daemon_set_item.spec.template.spec.containers[0].volume_mounts,
                    "env": daemon_set_item.spec.template.spec.containers[0].env,
                }
                check_pods_running("kube-proxy", report, errors)
                echo_info(
                    f"Checking if kube-proxy target version: {proxy_target_version} is equal to the current version: {version}",
                )
                if proxy_target_version == version:
                    addons.append({"name": daemon_set_item.metadata.name, "version": version, "update": False})
                    echo_info("kube-proxy version up to date")
                    customer_report["addons"][daemon_set_item.metadata.name]["version"] = "Up to date"
                    check_addons_params(
                        config,
                        daemon_set_item.metadata.name,
                        cluster_details,
                        config_map,
                        yaml_data,
                        report,
                        customer_report,
                    )
                else:
                    addons.append({"name": daemon_set_item.metadata.name, "version": version, "update": True})
                    echo_warning("kube-proxy version not compatible")
                    customer_report["addons"][daemon_set_item.metadata.name][
                        "version"
                    ] = f"Version: {proxy_target_version} not compatible with current cluster version: {version}"
        for deployment_item in deployment.items:
            if deployment_item.metadata.name == "coredns":
                version = (
                    deployment_item.spec.template.spec.containers[0]
                    .image.split(deployment_item.metadata.name + ":v")[1]
                    .split("-")[0]
                )
                config = {
                    "image": deployment_item.spec.template.spec.containers[0].image,
                    "volumeMount": deployment_item.spec.template.spec.containers[0].volume_mounts,
                    "env": deployment_item.spec.template.spec.containers[0].env,
                }
                check_pods_running("coredns", report, errors)
                echo_info(
                    f"Checking if coredns target version: {coredns_target_version} is equal to the current version: {version}",
                )
                if coredns_target_version == version:
                    addons.append({"name": deployment_item.metadata.name, "version": version, "update": False})
                    customer_report["addons"][deployment_item.metadata.name]["version"] = "Up to date"
                    echo_info("core-dns version up to date")
                    check_addons_params(
                        config,
                        deployment_item.metadata.name,
                        cluster_details,
                        config_map,
                        yaml_data,
                        report,
                        customer_report,
                    )
                else:
                    addons.append({"name": deployment_item.metadata.name, "version": version, "update": True})
                    echo_warning("core-dns version up not compatible")
                    customer_report["addons"][deployment_item.metadata.name][
                        "version"
                    ] = f"Version: {coredns_target_version} not compatible with current cluster version: {version}"
        report["addons"] = addons
        customer_report["addons_version"] = addons
    except Exception as error:
        errors.append(f"Some error occurred while checking the addon version {error}")
        echo_error(f"Some error occurred while checking the addon version - Error: {error}")
        report["preflight_status"] = False


def check_pods_running(addon: str, report: Dict[str, Any], errors: List[str], namespace: str = "kube-system") -> None:
    """Check whether the addon pod is in a running state."""
    try:
        core_v1_api = client.CoreV1Api()
        count = 0
        rep = core_v1_api.list_namespaced_pod(namespace)

        for pod in rep.items:
            if addon in pod.metadata.name:
                count = count + 1
                if pod.status.phase == "Running":
                    echo_info(f"{addon} pod is running")
                else:
                    echo_info(f"{addon} Pod is not running, it is in {pod.status.phase}")
                    errors.append(f"{addon} Pod is not running, it is in {pod.status.phase}")
                    report["preflight_status"] = False

        if not count:
            echo_error(f"{addon} pod is not present in the cluster")
            report["preflight_status"] = False
            errors.append(f"{addon} pod is not present in the cluster")
    except Exception as error:
        errors.append(f"Some error occurred while checking for addon pods to be running {error}")
        echo_error(f"Some error occurred while checking for addon pods to be running - Error: {error}")
        report["preflight_status"] = False


def check_addons_params(
    config: Dict[str, Any],
    name: str,
    cluster_details: Dict[str, Any],
    config_map: Dict[str, Any],
    yaml_data: Dict[str, Any],
    report: Dict[str, Any],
    customer_report: Dict[str, Any],
) -> None:
    """Check the volume mount and environment in cluster and original YAML for addons."""
    s3_config = yaml_data[name]
    echo_info(f"************* Parameter check for {name} *************")
    # Compare image name
    image_part_1 = config["image"].split(".ecr.")[0] == s3_config["image"].split(".ecr.")[0]
    image_part_2 = (
        config["image"].split("amazonaws.com/")[1].split(":v")[0]
        == s3_config["image"].split("amazonaws.com/")[1].split(":v")[0]
    )
    if image_part_1 and image_part_2:
        report["addon_params"][name] = {"image": config["image"]}
        customer_report["addons"][name]["image"] = "Image Verified"
        echo_success("Image verified")
    else:
        customer_report["addons"][name]["image"] = "Image Verification Failed"
        echo_error("Image verification failed")

    # Compare Volume Mounts
    mount_paths = []
    customer_report["addons"][name]["mount_paths"] = {}
    report["addon_params"][name]["mount_paths"] = {}
    remaining = []

    for i in range(len(s3_config["volumeMount"])):
        mount_paths.append(s3_config["volumeMount"][i]["mountPath"])

    for i in range(len(config["volumeMount"])):
        if config["volumeMount"][i].mount_path in mount_paths:
            mount_paths.remove(config["volumeMount"][i].mount_path)
        else:
            remaining.append(config["volumeMount"][i].mount_path)

    if mount_paths:
        customer_report["addons"][name]["mount_paths"]["message"] = "Default mount paths are missing"
        report["addon_params"][name]["mount_paths"]["custom"] = True
        report["addon_params"][name]["mount_paths"]["default"] = " ".join(map(str, mount_paths))
        customer_report["addons"][name]["mount_paths"]["default-mountpaths"] = " ".join(map(str, mount_paths))
        echo_warning(f"These mount paths are not present {' '.join(map(str, mount_paths))}")

    if remaining:
        customer_report["addons"][name]["mount_paths"]["message"] = "There are additional mount paths present"
        report["addon_params"][name]["mount_paths"]["custom"] = True
        report["addon_params"][name]["mount_paths"]["user-defined"] = " ".join(map(str, mount_paths))
        customer_report["addons"][name]["mount_paths"]["userdefined-mountpaths"] = " ".join(map(str, mount_paths))
        echo_warning(f"These user defined mount paths are present {' '.join(map(str, mount_paths))}")

    if not mount_paths and not remaining:
        report["addon_params"][name]["mount_paths"]["custom"] = False
        customer_report["addons"][name]["mount_paths"]["message"] = "Mount paths verified successfully"
        echo_success("Mount path verification successful")

    # Compare env
    if name == "vpc-cni":
        customer_report["addons"][name]["env"] = {}
        report["addon_params"][name]["envs"] = {}
        envs = []
        extra_envs = []

        for i in range(len(s3_config["env"])):
            envs.append(s3_config["env"][i]["name"])

        for i in range(len(config["env"])):
            if config["env"][i].name in envs:
                envs.remove(config["env"][i].name)
            else:
                extra_envs.append(config["env"][i].name)

        if envs:
            customer_report["addons"][name]["env"]["message"] = "Default envs are missing"
            report["addon_params"][name]["envs"]["custom"] = True
            report["addon_params"][name]["envs"]["default"] = " ".join(map(str, envs))
            customer_report["addons"][name]["env"]["default-envs"] = " ".join(map(str, envs))
            echo_warning(f"These envs are not present: {' '.join(map(str, envs))}")

        if extra_envs:
            report["addon_params"][name]["envs"]["custom"] = True
            report["addon_params"][name]["envs"]["user-defined"] = " ".join(map(str, extra_envs))
            customer_report["addons"][name]["env"]["message"] = "There are additional envs present"
            echo_warning(f"These user defined envs are present {' '.join(map(str, extra_envs))}")
            customer_report["addons"][name]["env"]["userdefined-envs"] = " ".join(map(str, extra_envs))

        if not envs and not extra_envs:
            report["addon_params"][name]["envs"]["custom"] = False
            customer_report["addons"][name]["env"]["message"] = "Envs verified successfully"
            echo_success("Envs verification successful")

    if name == "coredns":
        customer_report["addons"][name]["corefile"] = {}
        report["addon_params"][name]["corefile"] = {}
        arr = [
            "errors",
            "health",
            "kubernetes cluster.local in-addr.arpa ip6.arpa { pods insecure fallthrough in-addr.arpa ip6.arpa }",
            "prometheus :9153",
            "forward . /etc/resolv.conf",
            "cache 30",
            "loop",
            "reload",
            "loadbalance",
            "{",
            "}",
        ]
        core_v1_api = client.CoreV1Api()
        default = []
        ret = core_v1_api.list_config_map_for_all_namespaces(field_selector="metadata.name=coredns")
        corefile = yaml.safe_load(ret.items[0].data["Corefile"]).split(".:53")[1]
        for i in arr:
            if corefile.find(i) == -1:
                default.append(i)
                echo_info(f"{i} doesn't exist in corefile")
            else:
                corefile = corefile.replace(i, "")
        corefile = corefile.replace(" ", "")

        if default:
            customer_report["addons"][name]["corefile"]["message"] = "Default corefile fields are not present"
            report["addon_params"][name]["corefile"]["custom"] = True
            report["addon_params"][name]["corefile"]["default"] = " ".join(map(str, default))
            customer_report["addons"][name]["corefile"]["default-corefile-fields"] = " ".join(map(str, default))
            echo_warning(f"Default corefile fields are not present {' '.join(map(str, default))}")

        if corefile:
            customer_report["addons"][name]["corefile"]["message"] = "There are additional fields present in corefile"
            report["addon_params"][name]["corefile"]["custom"] = True
            report["addon_params"][name]["corefile"]["userdefined"] = " ".join(map(str, corefile))
            customer_report["addons"][name]["corefile"]["userdefined-corefile-fields"] = " ".join(map(str, corefile))
            echo_warning(f"Additional fields in corefile {' '.join(map(str, corefile))}")

        if not corefile and not default:
            report["addon_params"][name]["corefile"]["custom"] = False
            customer_report["addons"][name]["corefile"]["message"] = "Corefile fields verified successfully"
            echo_success("Corefile verified successfully")

    if name == "kube-proxy":
        report["addon_params"][name]["certificate-authority"] = {}
        report["addon_params"][name]["server-endpoint"] = {}
        customer_report["addons"][name]["certificate-authority"] = {}
        customer_report["addons"][name]["server-endpoint"] = {}
        core_v1_api = client.CoreV1Api()
        ret = core_v1_api.list_config_map_for_all_namespaces(field_selector="metadata.name=kube-proxy")

        if (
            yaml.safe_load(ret.items[0].data["kubeconfig"])["clusters"][0]["cluster"]["certificate-authority"]
            == config_map["certificate-authority"]
        ):
            report["addon_params"][name]["certificate-authority"]["verified"] = True
            customer_report["addons"][name]["certificate-authority"][
                "message"
            ] = "Certificate Authority Verified in kube config"
            report["addon_params"][name]["certificate-authority"]["certificate"] = config_map["certificate-authority"]
            echo_success("Certificate Authority Verified in kube config")
        else:
            customer_report["addons"][name]["certificate-authority"][
                "message"
            ] = "Certificate Verification failed in kube config"
            report["addon_params"][name]["certificate-authority"]["verified"] = False
            report["addon_params"][name]["certificate-authority"]["certificate"] = yaml.safe_load(
                ret.items[0].data["kubeconfig"]
            )["clusters"][0]["cluster"]["certificate-authority"]
            echo_error("Certificate Verification failed in kube config")

        if (
            yaml.safe_load(ret.items[0].data["kubeconfig"])["clusters"][0]["cluster"]["server"]
            == cluster_details["cluster"]["endpoint"].lower()
        ):
            customer_report["addons"][name]["server-endpoint"]["message"] = "Server end point verified"
            report["addon_params"][name]["server-endpoint"]["verified"] = True
            report["addon_params"][name]["server-endpoint"]["server-endpoint"] = cluster_details["cluster"][
                "endpoint"
            ].lower()
            echo_success("Server end point verified")
        else:
            customer_report["addons"][name]["server-endpoint"]["message"] = "Server end point verification failed"
            report["addon_params"][name]["certificate-authority"]["verified"] = False
            report["addon_params"][name]["certificate-authority"]["server-endpoint"] = yaml.safe_load(
                ret.items[0].data["kubeconfig"]
            )["clusters"][0]["cluster"]["server"]
            echo_error("Server end point verification failed")


def pod_disruption_budget(
    errors: List[str],
    cluster_name: str,
    region: str,
    report: Dict[str, Any],
    customer_report: Dict[str, Any],
    force_upgrade: bool,
) -> None:
    """Get pod disruption budgets."""
    loading_config(cluster_name, region)
    echo_info("Fetching Pod Disruption Budget Details...")
    try:
        policy_v1_api = client.PolicyV1Api()
        ret = policy_v1_api.list_pod_disruption_budget_for_all_namespaces()
        if not ret.items:
            customer_report["pod disruption budget"] = "No Pod Disruption Budget exists in cluster"
            echo_success("No Pod Disruption Budget exists in cluster")
        else:
            echo_warning(
                "Pod Disruption Budget exists in cluster therefore force upgrade is required to upgrade the cluster"
            )
            if not force_upgrade:
                echo_warning(
                    "Pod Disruption Budget exists in cluster therefore force upgrade is required to upgrade the cluster, To upgrade please run the code with --force flag "
                )
                errors.append("To upgrade please run the code with --force flag ")
                report["preflight_status"] = False
            for pdb in ret.items:
                max_available = pdb.spec.max_unavailable
                min_available = pdb.spec.min_available
                report["pdb"] = {"max_unavailable": max_available, "min_available": min_available}
                customer_report["pod disruption budget"] = "Pod disruption budget exists in the cluster"
                echo_warning(
                    f"Pod disruption budget exists with max unavailable as {max_available} and min available as {min_available}",
                )
            core_v1_api = client.CoreV1Api()
            pods_and_nodes = []
            ret = core_v1_api.list_pod_for_all_namespaces(watch=False)

            for i in ret.items:
                pods_and_nodes.append(
                    {"name": i.metadata.name, "namespace": i.metadata.namespace, "nodename": i.spec.node_name}
                )
            report["pdb"]["pods"] = pods_and_nodes
            logger.debug(pods_and_nodes)
    except Exception as error:
        errors.append(f"Error occurred while checking for pod disruption budget {error}")
        customer_report["pod disruption budget"] = "Error occurred while checking for pod disruption budget"
        echo_error(f"Error occurred while checking for pod disruption budget - Error: {error}")
        report["preflight_status"] = False


def cluster_auto_scaler(
    errors: List[str], cluster_name: str, region: str, report: Dict[str, Any], customer_report: Dict[str, Any]
) -> None:
    """Get cluster autoscaler details."""
    loading_config(cluster_name, region)
    echo_info("Fetching Cluster Auto Scaler Details...")
    try:
        eks = boto3.client("eks", region_name=region)
        cluster_details = eks.describe_cluster(name=cluster_name)
        val: str = cluster_details["cluster"]["version"]
        l = val.split(".")
        v1 = client.AppsV1Api()
        res = v1.list_deployment_for_all_namespaces()
        for i in res.items:
            x = i.metadata.name
            if x == "cluster-autoscaler":
                echo_info("Cluster Autoscaler exists")
                check_pods_running("cluster-autoscaler", report, errors)
                version = (
                    i.spec.template.spec.containers[0]
                    .image.split("k8s.gcr.io/autoscaling/cluster-autoscaler:v")[1]
                    .split("-")[0]
                )
                l1 = version.split(".")
                if l[0] == l1[0] and l[1] == l1[1]:
                    report["cluster_auto_scaler"] = {"image": i.spec.template.spec.containers[0].image}
                    customer_report["cluster autoscaler"] = "Auto scaler version is compatible with cluster version!"
                    echo_success("Auto scaler version is compatible with cluster version!")
                else:
                    echo_warning("Auto scaler version is not compatible with cluster version")
                    customer_report["cluster autoscaler"] = "Auto scaler version is not compatible with cluster version"
                return
            else:
                continue
        customer_report["cluster autoscaler"] = "Cluster Autoscaler doesn't exist"
        echo_info("Cluster Autoscaler doesn't exist")
    except Exception as error:
        errors.append(f"Error occurred while checking for the cluster autoscaler {error}")
        customer_report["cluster autoscaler"] = f"Error occurred while checking for the cluster autoscaler {error}"
        echo_error(f"Error occurred while checking for the cluster autoscaler - Error: {error}")
        report["preflight_status"] = False


def horizontal_auto_scaler(errors, cluster_name, region, report, customer_report):
    loading_config(cluster_name, region)
    echo_info("Fetching Horizontal Autoscaler Details...")
    try:
        v1 = client.AutoscalingV1Api()
        ret = v1.list_horizontal_pod_autoscaler_for_all_namespaces()
        if not ret.items:
            customer_report["horizontal auto scaler"] = "No Horizontal Auto Scaler exists in cluster"
            echo_info("No Horizontal Auto Scaler exists in cluster")
        else:
            customer_report["horizontal auto scaler"] = "Horizontal Pod Auto scaler exists in cluster"
            echo_info("Horizontal Pod Auto scaler exists in cluster")
            report["horizontal_autoscaler"] = ret.items[0]
    except Exception as e:
        errors.append(f"Error occurred while checking for horizontal autoscaler {e}")
        echo_error(f"Error occurred while checking for horizontal autoscaler - Error: {e}")
        customer_report["horizontal auto scaler"] = "Error occurred while checking for horizontal autoscaler"
        report["preflight_status"] = False


def cmk_key_check(errors, cluster_name, region, cluster, report, customer_report):
    loading_config(cluster_name, region)
    cmk = boto3.client("kms", region_name=region)
    echo_info("Checking if customer management key exists...")
    try:
        if "encryptionConfig" in cluster["cluster"].keys():
            cmk_key = cluster["cluster"]["encryptionConfig"][0]["provider"]["keyArn"]
            customer_report["CMK Key"] = f"CMK Key with id {cmk_key} is present"
            echo_info(f"CMK Key with id {cmk_key} is present")
            response = cmk.describe_key(KeyId=cmk_key)
            try:
                response = cmk.describe_key(
                    KeyId=cmk_key,
                )
                if "KeyId" in response["KeyMetadata"].keys():
                    customer_report["CMK Key"] = f"Key with id {cmk_key} exist in user account"
                    echo_success(f"Key with id {cmk_key} exist in user account")
                else:
                    report["preflight_status"] = False
                    errors.append(f"Key with id {cmk_key} doesnt exist in user account")
                    customer_report["CMK Key"] = f"Key with id {cmk_key} doesnt exist in user account"
                    echo_error(f"Key with id {cmk_key} doesnt exist in user account")
            except Exception:
                report["preflight_status"] = False
                errors.append(f"Key with id {cmk_key} doesnt exist in user account")
                customer_report["CMK Key"] = f"Key with id {cmk_key} doesnt exist in user account"
                echo_error(f"Key with id {cmk_key} doesnt exist in user account")
        else:
            customer_report["CMK Key"] = "No CMK Key associated with the cluster"
            echo_warning("No CMK Key associated with the cluster")
    except Exception as e:
        errors.append(f"Error while checking for cluster CMK key {e}")
        customer_report["CMK Key"] = "Error while checking for cluster CMK key"
        echo_error(f"Error while checking for cluster CMK key - Error: {e}")
        report["preflight_status"] = False


def security_group_check(errors, cluster_name, region, cluster, report, customer_report):
    loading_config(cluster_name, region)
    echo_info("Fetching security group details...")
    try:
        security_groups = cluster["cluster"]["resourcesVpcConfig"]["securityGroupIds"]
        if not security_groups:
            customer_report["security group"] = "No security groups available with cluster"
            echo_warning("No security groups available with cluster")
        else:
            for s in security_groups:
                try:
                    ec2 = boto3.resource("ec2", region_name=region)
                    security_group = ec2.SecurityGroup(s)
                    customer_report[
                        "security group"
                    ] = f"Security Group {security_group.id} is present in VPC with ID {security_group.vpc_id}"
                    echo_success(
                        f"Security Group {security_group.id} is present in VPC with ID {security_group.vpc_id}"
                    )
                except Exception:
                    customer_report["security group"] = f"The security group with id {s} is not present"
                    report["preflight_status"] = False
                    errors.append(f"The security group with id {s} is not present")
                    echo_error(f"The security group with id {s} is not present")
    except Exception as e:
        errors.append(f"Error retrieving security group of cluster {e}")
        customer_report["security group"] = f"Error retrieving security group of cluster {e}"
        echo_error(f"Error retrieving security group of cluster - Error: {e}")
        report["preflight_status"] = False


# Check if the AMI is custom
def iscustomami(node_type, Presentversion, image_id, region):
    filters = [{"Name": "is-public", "Values": ["true"]}]

    if node_type == "Amazon Linux 2":
        filters.append({"Name": "name", "Values": [f"amazon-eks-node-{Presentversion}*"]})
    elif "bottlerocket" in node_type.lower():
        filters.append({"Name": "name", "Values": [f"bottlerocket-aws-k8s-{Presentversion}*"]})
    elif "windows" in node_type.lower():
        filters.append({"Name": "name", "Values": [f"Windows_Server-*-English-*-EKS_Optimized-{Presentversion}*"]})
    else:
        return True

    ec2Client = boto3.client("ec2", region_name=region)
    images = ec2Client.describe_images(Filters=filters)
    instances_list = []
    for i in images.get("Images"):
        instances_list.append([i.get("ImageId"), i.get("ImageLocation")])

    for i in instances_list:
        if image_id in i[0]:
            return False
    return True


# Print nodegroup details
def nodegroup_customami(errors, cluster_name, region, report, customer_report, update_version):
    loading_config(cluster_name, region)
    final_dict = {"self-managed": {}, "managed": {}, "fargate": {}}
    echo_info("Fetching node group details...")
    try:
        v1 = client.CoreV1Api()
        ret = v1.list_node()
        if not ret.items:
            echo_error("No running nodes present in the cluster!")
            raise Exception("No running nodes present in the cluster")

        for i in ret.items:
            x = i.metadata.labels
            ver = i.status.node_info.kubelet_version.split("-")[0][1:5]
            if "eks.amazonaws.com/compute-type" in x:
                final_dict["fargate"][i.metadata.name] = {
                    "version": ver,
                    "node_type": "fargate",
                    "version_compatibility": ver == report["cluster"]["version"],
                }
            else:
                instance_id = i.spec.provider_id.split("/")[-1]
                node_type = i.status.node_info.os_image
                if "windows" in node_type.lower():
                    node_type = "windows"
                ec2Client = boto3.client("ec2", region_name=region)
                res = ec2Client.describe_instances(InstanceIds=[instance_id])

                ami = res.get("Reservations")[0]["Instances"][0]["ImageId"]
                hd = res["Reservations"][0]["Instances"][0]["Tags"]

                for m in hd:
                    if m["Key"] == "aws:autoscaling:groupName":
                        autoscale_group_name = m["Value"]

                custom_ami = iscustomami(node_type, ver, ami, region)
                if ver == report["cluster"]["version"]:
                    version_compatibility = True
                elif update_version and round(float(report["cluster"]["version"]) - float(ver), 2) == 0.01:
                    version_compatibility = True
                else:
                    version_compatibility = False
                if custom_ami:
                    echo_error(f"{instance_id} cannot be upgraded as it uses a custom AMI!")
                if not version_compatibility:
                    report["preflight_status"] = False
                    echo_error(
                        f"{instance_id} cannot be upgraded because the cluster version is not compatible with the node version",
                    )
                if "alpha.eksctl.io/instance-id" in x or "eks.amazonaws.com/nodegroup" not in x:
                    if autoscale_group_name not in final_dict["self-managed"].keys():
                        final_dict["self-managed"][autoscale_group_name] = {
                            "instances": [
                                {
                                    "version": ver,
                                    "ami": ami,
                                    "node_type": node_type,
                                    "version_compatibility": version_compatibility,
                                    "custom_ami": custom_ami,
                                }
                            ]
                        }
                    else:
                        instances = final_dict["self-managed"][autoscale_group_name]["instances"]
                        instances.append(
                            {
                                "version": ver,
                                "ami": ami,
                                "node_type": node_type,
                                "version_compatibility": version_compatibility,
                                "custom_ami": custom_ami,
                            }
                        )
                        final_dict["self-managed"][autoscale_group_name]["instances"] = instances

                else:
                    if autoscale_group_name not in final_dict["managed"].keys():
                        node_group_name = ""
                        if "alpha.eksctl.io/nodegroup-name" in x:
                            node_group_name = x["alpha.eksctl.io/nodegroup-name"]
                        else:
                            node_group_name = x["eks.amazonaws.com/nodegroup"]
                        eks = boto3.client("eks", region_name=region)
                        response = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=node_group_name)
                        if response["nodegroup"]["amiType"] == "CUSTOM":
                            echo_error("Nodegroup cannot be upgraded as it has custom launch template")
                        final_dict["managed"][autoscale_group_name] = {
                            "nodegroup_name": node_group_name,
                            "custom_launch_template": response["nodegroup"]["amiType"] == "CUSTOM",
                            "instances": [
                                {
                                    "version": ver,
                                    "ami": ami,
                                    "node_type": node_type,
                                    "version_compatibility": version_compatibility,
                                    "custom_ami": custom_ami,
                                }
                            ],
                        }
                    else:
                        instances = final_dict["managed"][autoscale_group_name]["instances"]
                        instances.append(
                            {
                                "version": ver,
                                "ami": ami,
                                "node_type": node_type,
                                "version_compatibility": version_compatibility,
                                "custom_ami": custom_ami,
                            }
                        )
                        final_dict["managed"][autoscale_group_name]["instances"] = instances
        return final_dict
    except Exception as e:
        errors.append(f"Error occurred while checking node group details {e}")
        echo_error(f"Error occurred while checking node group details - Error: {e}")
        customer_report["node group details"] = "Error occurred while checking node group details"
        report["preflight_status"] = False
