import json
import time
from pprint import pprint

import boto3
import urllib3
import yaml
from kubernetes import client
from kubernetes.client import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from .k8s_client import loading_config

# Function to upload logs onto cloud watch


def log_pusher(log_details, cluster_name, region, msg):
    timestamp = int(round(time.time() * 1000))
    logs = boto3.client("logs", region_name=region)
    log_group = log_details["group"]
    log_stream = log_details["stream"]
    timestamp = int(round(time.time() * 1000))
    response = logs.describe_log_streams(logGroupName=log_group, logStreamNamePrefix=log_stream)
    response = logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": timestamp, "message": msg}],
        sequenceToken=response["logStreams"][0]["uploadSequenceToken"],
    )


def create_log_group_stream(cluster_name, region):
    timestamp = int(round(time.time() * 1000))
    logs = boto3.client("logs", region_name=region)
    log_group = "cluster-" + cluster_name + "-" + region

    log_stream = "preflight-checks-" + str(timestamp)
    if len(logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]) > 0:
        print("Log group exists")
    else:
        logs.create_log_group(logGroupName=log_group)
    if len(logs.describe_log_streams(logGroupName=log_group, logStreamNamePrefix=log_stream)["logStreams"]) > 0:
        print("Stream exists")
    else:
        logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
        timestamp = int(round(time.time() * 1000))
        response = logs.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[{"timestamp": timestamp, "message": "Log stream create at " + str(timestamp)}],
        )
    print("Check logs in cloud watch group " + log_group + " for more information" + "in stream " + log_stream)
    return {"group": log_group, "stream": log_stream}


# Function declaration for pre flight checks

# Verify IAM role for the Input


def pre_flight_checks(
    preflight, cluster_name, region, pass_vpc, update_version=False, email=False, force_upgrade=False
):
    loading_config(cluster_name, region)
    report = {"preflight_status": True}
    customer_report = {}
    log_details = create_log_group_stream(cluster_name, region)

    errors = []
    try:
        if email:
            ses_client = boto3.client("ses", region_name="ap-south-1")
            identities = ses_client.list_identities()
            if email not in identities["Identities"]:
                response = ses_client.verify_email_identity(EmailAddress=email)
                print("Please check your inbox to verify your email")
        v1 = client.CoreV1Api()
        ret = v1.list_namespaced_service("default")
        print("\n")
        log_pusher(log_details, cluster_name, region, "Verifying User IAM Role....")
        print("Verifying User IAM Role....")
        log_pusher(log_details, cluster_name, region, "IAM role for user verified")
        print("IAM role for user verified")
        customer_report["IAM role"] = "IAM role for user verified"
        get_cluster_version(
            preflight,
            log_details,
            errors,
            cluster_name,
            region,
            pass_vpc,
            update_version,
            report,
            customer_report,
            email,
            force_upgrade,
        )
        print("\n")
        log_pusher(log_details, cluster_name, region, "Customer report.....")
        log_pusher(log_details, cluster_name, region, str(report))
        if (len(errors)) > 0:
            if preflight:
                print("Preflight unsuccessful because of following errors")
            else:
                print("Postflight unsuccessful because of following errors")
            for e in errors:
                print(e)
            print("\n")
        # print('Customer report.....')
        # pprint(customer_report)
        return report["preflight_status"]
    except Exception as e:
        log_pusher(log_details, cluster_name, region, "IAM role verification failed {err}".format(err=e))
        print("IAM role verification failed {err}".format(err=e))
        report["preflight_status"] = False
        customer_report["IAM role"] = "IAM role verification failed"


# Control Plane version listing


def get_cluster_version(
    preflight,
    log_details,
    errors,
    cluster_name,
    region,
    pass_vpc,
    update_version,
    report,
    customer_report,
    email,
    force_upgrade,
):
    loading_config(cluster_name, region)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Fetching cluster details .....")
    print("Fetching cluster details .....")
    eks = boto3.client("eks", region_name=region)
    try:
        cluster_details = eks.describe_cluster(name=cluster_name)
        report["cluster"] = {
            "version": cluster_details["cluster"]["version"],
            "region": cluster_details["cluster"]["arn"].split(":")[3],
        }
        log_pusher(log_details, cluster_name, region, "Cluster control plane version " + report["cluster"]["version"])
        print("Cluster control plane version " + report["cluster"]["version"])
        customer_report["cluster version"] = "Cluster control plane version " + report["cluster"]["version"]
        if update_version:
            if cluster_details["cluster"]["version"] == update_version:
                log_pusher(
                    log_details,
                    cluster_name,
                    region,
                    "Cluster already upgraded to version" + cluster_details["cluster"]["version"],
                )
                print("Cluster already upgraded to version " + cluster_details["cluster"]["version"])
                customer_report["cluster upgradation"] = (
                    "Cluster already upgraded to version " + cluster_details["cluster"]["version"]
                )
            elif (round(float(update_version) - float(cluster_details["cluster"]["version"]), 2)) == 0.01 and float(
                update_version
            ) < 1.25:
                log_pusher(
                    log_details,
                    cluster_name,
                    region,
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " can be updated to target version "
                    + update_version,
                )
                print(
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " can be updated to target version "
                    + update_version
                )
                customer_report["cluster upgradation"] = (
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " can be updated to target version "
                    + update_version
                )
            else:
                customer_report["cluster upgradation"] = (
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " cannot be updated to target version "
                    + update_version
                )
                log_pusher(
                    log_details,
                    cluster_name,
                    region,
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " cannot be updated to target version "
                    + update_version,
                )
                print(
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " cannot be updated to target version "
                    + update_version
                )
                report["preflight_status"] = False
                errors.append(
                    "Cluster with verison "
                    + cluster_details["cluster"]["version"]
                    + " cannot be updated to target version "
                    + update_version
                )
                return
        cmk_key_check(log_details, errors, cluster_name, region, cluster_details, report, customer_report)
        security_group_check(log_details, errors, cluster_name, region, cluster_details, report, customer_report)
        pod_security_policies(log_details, errors, cluster_name, region, report, customer_report)
        node_group_details = nodegroup_customami(
            log_details, errors, cluster_name, region, report, customer_report, update_version
        )
        report["nodegroup_details"] = node_group_details
        customer_report["nodegroup_details"] = node_group_details
        subnet_details(log_details, errors, cluster_name, region, report, customer_report)
        cluster_roles(preflight, log_details, errors, cluster_name, region, report, customer_report)
        addon_version(log_details, errors, cluster_name, region, cluster_details, report, customer_report, pass_vpc)
        pod_disruption_budget(log_details, errors, cluster_name, region, report, customer_report, force_upgrade)
        horizontal_auto_scaler(log_details, errors, cluster_name, region, report, customer_report)
        cluster_auto_scaler(log_details, errors, cluster_name, region, report, customer_report)
        if report["cluster"]["version"] != "1.21" and update_version:
            depricated_api_check(log_details, errors, cluster_name, region, report, customer_report, update_version)
        if email:
            print("\n")
            log_pusher(log_details, cluster_name, region, "Delivering report via Email...")
            print("Delivering report via Email...")
            send_email(preflight, log_details, errors, cluster_name, region, report, customer_report, email)
    except Exception as e:
        errors.append("Some error occured during preflight check process {err}".format(err=e))
        customer_report["cluster version"] = "Some error occured during preflight check process"
        log_pusher(
            log_details, cluster_name, region, "Some error occured during preflight check process {err}".format(err=e)
        )
        print("Some error occured during preflight check process {err}".format(err=e))
        report["preflight_status"] = False


# Gather Subnet Utilization fro the current cluster


def subnet_details(log_details, errors, cluster_name, region, report, customer_report):
    loading_config(cluster_name, region)
    try:
        print("\n")
        log_pusher(log_details, cluster_name, region, "Checking Available IP for subnets associated with cluster.....")
        print("Checking Available IP for subnets associated with cluster.....")
        eks = boto3.client("eks", region_name=region)
        cluster_details = eks.describe_cluster(name=cluster_name)
        subnets = []
        customer_report["subnet"] = []
        error = []
        for subnet_id in cluster_details["cluster"]["resourcesVpcConfig"]["subnetIds"]:
            ec2 = boto3.resource("ec2", region_name=region)
            subnet = ec2.Subnet(subnet_id)
            if subnet.available_ip_address_count < 5:
                error.append("Subnet ID " + str(subnet_id) + " doesnt have a minimum of 5 available IP")
            log_pusher(
                log_details,
                cluster_name,
                region,
                "Subnet ID "
                + str(subnet_id)
                + " have a "
                + str(subnet.available_ip_address_count)
                + " available IP address",
            )
            customer_report["subnet"].append(
                "Subnet ID "
                + str(subnet_id)
                + " have a "
                + str(subnet.available_ip_address_count)
                + " available IP address"
            )
            print(
                "Subnet ID "
                + str(subnet_id)
                + " have a "
                + str(subnet.available_ip_address_count)
                + " available IP address"
            )
            subnets.append({subnet_id: subnet.available_ip_address_count})
        # report['subnets'] = subnets
        if len(error) > 0:
            report["preflight_status"] = False
            errors.append("Available IPs for Subnet verification failed")
            log_pusher(log_details, cluster_name, region, "Available IPs for Subnet verification failed")
            print("Available IPs for Subnet verification failed")
            customer_report["subnet"].append("Available IP for Subnet verification failed")
            for e in error:
                customer_report["subnet"].append(e)
                print(e)
        else:
            customer_report["subnet"].append("Available IP for Subnet verified")
            log_pusher(log_details, cluster_name, region, "Available IPs for Subnet verified")
            print("Available IPs for Subnet verified")
    except Exception as e:

        errors.append("Some error occured while fetching subnet details {err}".format(err=e))
        log_pusher(
            log_details, cluster_name, region, "Some error occured while fetching subnet details {err}".format(err=e)
        )
        print("Some error occured while fetching subnet details {err}".format(err=e))
        report["preflight_status"] = False


# Verification for required cluster roles


def cluster_roles(preflight, log_details, errors, cluster_name, region, report, customer_report):
    loading_config(cluster_name, region)
    s3 = boto3.resource("s3")
    # Cluster Roles for proper functioning
    # cluster_roles_list = s3.Object('eks-one-click-upgrade', 'cluster_roles.json')
    # cluster_roles_list = cluster_roles_list.get()['Body'].read().decode('utf-8')
    # cluster_roles_list = json.loads(cluster_roles_list)
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/cluster_roles.json",
    )
    cluster_roles_list = json.load(f)
    # print(cluster_roles_list)
    if preflight:
        cluster_roles_list = cluster_roles_list["preflight"]
    else:
        cluster_roles_list = cluster_roles_list["postflight"]
    # print(cluster_roles_list)
    try:
        print("\n")
        log_pusher(log_details, cluster_name, region, "Checking important cluster role are present or not .....")
        print("Checking important cluster role are present or not .....")
        available = []
        not_available = []
        customer_report["cluster role"] = []
        for role in cluster_roles_list["roles"]:
            try:
                v1 = client.RbacAuthorizationV1Api()
                fs = "metadata.name=" + role
                res = v1.list_cluster_role(field_selector=fs)
                if len(res.items) > 0:
                    available.append(role)
                    # print(available)
                    # print(res)
                else:
                    not_available.append(role)
                    # print(not_available)
                    # print('Unable to find ' + role)
            except:
                customer_report["cluster role"].append("Some error occured while checking role for " + role)
                log_pusher(log_details, cluster_name, region, "Some error occured while checking role for " + role)
                print("Some error occured while checking role for " + role)
        # report['cluster-roles'] = {'available' : available,'not-available':not_available}
        if report["cluster"]["version"] in cluster_roles_list.keys():

            # print(cluster_roles_list[report['cluster']['version']])
            for role in cluster_roles_list[report["cluster"]["version"]].keys():
                v1 = client.RbacAuthorizationV1Api()
                res = eval(cluster_roles_list[report["cluster"]["version"]][role])

                if len(res.items) == 0:
                    log_pusher(log_details, cluster_name, region, role + " is not present in the cluster")
                    customer_report["cluster role"].append(role + " is not present in the cluster")
                    print(role + " is not present in the cluster")
                    not_available.append(role)
                else:
                    available.append(role)
        if len(not_available) > 0:
            customer_report["cluster role"].append("Cluster role verification failed")
            log_pusher(log_details, cluster_name, region, "Cluster role verification failed")
            print("Cluster role verification failed")
            report["preflight_status"] = False
            errors.append("Cluster role verification failed")
            for n in not_available:
                customer_report["cluster role"].append(n + " role is not present in the cluster")
                print(n + " role is not present in the cluster")
                log_pusher(log_details, cluster_name, region, n + " role is not present in the cluster")

        else:
            customer_report["cluster role"].append("All cluster role needed sucessfully verified")
            for n in available:
                customer_report["cluster role"].append(n + " role is present in cluster")
                log_pusher(log_details, cluster_name, region, n + " role is present in cluster")
                print(n + " role is present in the cluster")
            log_pusher(log_details, cluster_name, region, "All cluster role needed sucessfully verified")
            print("All cluster role needed sucessfully verified")
        # print(report['cluster-roles'])
    except Exception as e:

        errors.append("Some error occured while checking the cluster roles available {err}".format(err=e))
        customer_report["cluster role"].append(
            "Some error occured while checking the cluster roles available {err}".format(err=e)
        )
        print("Some error occured while checking the cluster roles available {err}".format(err=e))
        report["preflight_status"] = False


# Check for Pod Security Policies


def pod_security_policies(log_details, errors, cluster_name, region, report, customer_report):
    loading_config(cluster_name, region)
    try:
        v1 = client.PolicyV1beta1Api()
        print("\n")
        log_pusher(log_details, cluster_name, region, "Pod Security Policies .....")
        print("Pod Security Policies .....")
        ret = v1.list_pod_security_policy(field_selector="metadata.name=eks.privileged")
        # pprint(ret)
        # report['pod-security-policy'] = ret
        if len(ret.items) == 0:
            customer_report["pod security policy"] = "Pod Security Policy with eks.privileged role doesnt exists."
            report["preflight_status"] = False
            errors.append("Pod Security Policy with eks.privileged role doesnt exists.")
            log_pusher(log_details, cluster_name, region, "Pod Security Policy with eks.privileged role doesnt exists.")
            print("Pod Security Policy with eks.privileged role doesnt exists.")
        for i in ret.items:
            # print(i.metadata)
            if i.metadata.name == "eks.privileged":
                customer_report["pod security policy"] = "Pod Security Policy with eks.privileged role exists."
                log_pusher(log_details, cluster_name, region, "Pod Security Policy with eks.privileged role exists.")
                print("Pod Security Policy with eks.privileged role exists.")
            else:
                customer_report["pod security policy"] = "Pod Security Policy with eks.privileged role doesnt exists."
                report["preflight_status"] = False
                errors.append("Pod Security Policy with eks.privileged role doesnt exists.")
                log_pusher(
                    log_details, cluster_name, region, "Pod Security Policy with eks.privileged role doesnt exists."
                )
                print("Pod Security Policy with eks.privileged role doesnt exists.")
        # print(report['pod-security-policy'])
    except Exception as e:
        errors.append("Some error occured while checking for the policy security policies {err}".format(err=e))
        customer_report["pod security policy"] = "Some error occured while checking for the policy security policies"
        log_pusher(
            log_details,
            cluster_name,
            region,
            "Some error occured while checking for the policy security policies {err}".format(err=e),
        )
        print("Some error occured while checking for the policy security policies {err}".format(err=e))
        report["preflight_status"] = False


# Check for compatibility between addon and control plane versions


def addon_version(log_details, errors, cluster_name, region, cluster_details, report, customer_report, pass_vpc):
    loading_config(cluster_name, region)

    # Fetch data from S3 Bucket
    s3 = boto3.resource("s3")
    yaml_data = {}
    config_map = {}

    # Version Dictionary

    # version_dict = s3.Object('eks-one-click-upgrade', 'version_dict.json')
    # version_dict = version_dict.get()['Body'].read().decode('utf-8')
    # version_dict = json.loads(version_dict)
    # print(version_dict)

    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/version_dict.json",
    )
    version_dict = json.load(f)

    # Kube Proxy config YAML
    # kube_proxy_config = s3.Object('eks-one-click-upgrade', 'addons/kube-proxy.json')
    # kube_proxy_config = kube_proxy_config.get()['Body'].read().decode('utf-8')
    # kube_proxy_config = json.loads(kube_proxy_config)
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/kube-proxy.json",
    )
    kube_proxy_config = json.load(f)
    kube_proxy_container = kube_proxy_config["spec"]["template"]["spec"]["containers"][0]
    yaml_data["kube-proxy"] = {
        "image": kube_proxy_container["image"],
        "volumeMount": kube_proxy_container["volumeMounts"],
        "env": None,
    }
    # print(kube_proxy_config)

    # Core DNS config YAML
    # core_dns_config = s3.Object('eks-one-click-upgrade', 'addons/coredns.json')
    # core_dns_config = core_dns_config.get()['Body'].read().decode('utf-8')
    # core_dns_config = json.loads(core_dns_config)
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/coredns.json",
    )
    core_dns_config = json.load(f)
    coredns_container = core_dns_config["spec"]["template"]["spec"]["containers"][0]
    yaml_data["coredns"] = {
        "image": coredns_container["image"],
        "volumeMount": coredns_container["volumeMounts"],
        "env": None,
    }
    # print(core_dns_config)

    # VPC CNI config YAML
    # vpc_cni_config = s3.Object('eks-one-click-upgrade', 'addons/vpc-cni.json')
    # vpc_cni_config = vpc_cni_config.get()['Body'].read().decode('utf-8')
    # vpc_cni_config = json.loads(vpc_cni_config)
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/vpc-cni.json",
    )
    vpc_cni_config = json.load(f)
    vpc_cni_container = vpc_cni_config["spec"]["template"]["spec"]["containers"][0]
    yaml_data["vpc-cni"] = {
        "image": vpc_cni_container["image"],
        "volumeMount": vpc_cni_container["volumeMounts"],
        "env": vpc_cni_container["env"],
    }
    # print(vpc_cni_config)

    # Kube Proxy config map YAML
    # kube_proxy_config_map = s3.Object('eks-one-click-upgrade', 'configMap/kube-proxy.json')
    # kube_proxy_config_map = kube_proxy_config_map.get()['Body'].read().decode('utf-8')
    # kube_proxy_config_map = json.loads(kube_proxy_config_map)
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/kube-proxy-configmap.json",
    )
    kube_proxy_config_map = json.load(f)
    config_map["certificate-authority"] = yaml.safe_load(kube_proxy_config_map["data"]["kubeconfig"])["clusters"][0][
        "cluster"
    ]["certificate-authority"]

    # Core DNS config map YAML
    # core_dns_config_map = s3.Object('eks-one-click-upgrade', 'configMap/coredns.json')
    # core_dns_config_map = core_dns_config_map.get()['Body'].read().decode('utf-8')
    # core_dns_config_map = json.loads(core_dns_config_map)
    # config_map['coredns'] = core_dns_config_map['data']
    # pprint(yaml.load(core_dns_config_map['data']['Corefile']).split('.:53')[1].split(' '))

    try:

        print("\n")
        log_pusher(log_details, cluster_name, region, "Check addon version compatibility .....")
        print("Check addon version compatibility .....")

        addons = []
        report["addon_params"] = {}
        customer_report["addons"] = {"vpc-cni": {}, "kube-proxy": {}, "coredns": {}}
        v1 = client.AppsV1Api()
        daemon_set = v1.list_namespaced_daemon_set("kube-system")
        deployment = v1.list_namespaced_deployment("kube-system")
        calico = v1.list_namespaced_daemon_set("calico-system")
        if len(calico.items) != 0:
            for cal in calico.items:
                print("Calico addon is present in cluster")
                check_pods_running("calico", log_details, cluster_name, region, report, errors, "calico-system")
        for ds in daemon_set.items:
            # print(ds.metadata.name)
            if ds.metadata.name == "aws-node" and not pass_vpc:
                version_str = ds.spec.template.spec.containers[0].image.split("amazon-k8s-cni:v")[1].split("-")[0]
                config = {
                    "image": ds.spec.template.spec.containers[0].image,
                    "volumeMount": ds.spec.template.spec.containers[0].volume_mounts,
                    "env": ds.spec.template.spec.containers[0].env,
                }
                target_version = version_dict[report["cluster"]["version"]]["vpc-cni"].split(".")
                version = version_str.split(".")
                check_pods_running("aws-node", log_details, cluster_name, region, report, errors)
                if int("".join(version)) >= int("170"):
                    addons.append({"name": "vpc-cni", "version": version_str, "update": False})
                    customer_report["addons"]["vpc-cni"]["version"] = "Up to date"
                    log_pusher(log_details, cluster_name, region, "vpc-cni version up to date")
                    print("vpc-cni version up to date")
                    check_addons_params(
                        log_details,
                        config,
                        "vpc-cni",
                        cluster_details,
                        config_map,
                        yaml_data,
                        report,
                        customer_report,
                        cluster_name,
                        region,
                        errors,
                    )
                else:
                    addons.append({"name": "vpc-cni", "version": version_str, "update": True})
                    log_pusher(log_details, cluster_name, region, "vpc-cni version is not compatible")
                    print("vpc-cni version is not compatible")
                    customer_report["addons"]["vpc-cni"][
                        "version"
                    ] = "Version Not Compatible with current cluster version"
                # print(ds.metadata.name + ':' + version)
            elif ds.metadata.name == "kube-proxy":
                version = ds.spec.template.spec.containers[0].image.split(ds.metadata.name + ":v")[1].split("-")[0]
                config = {
                    "image": ds.spec.template.spec.containers[0].image,
                    "volumeMount": ds.spec.template.spec.containers[0].volume_mounts,
                    "env": ds.spec.template.spec.containers[0].env,
                }
                check_pods_running("kube-proxy", log_details, cluster_name, region, report, errors)
                print(version_dict[report["cluster"]["version"]][ds.metadata.name], version)
                if version_dict[report["cluster"]["version"]][ds.metadata.name] == version:
                    addons.append({"name": ds.metadata.name, "version": version, "update": False})
                    log_pusher(log_details, cluster_name, region, "kube-proxy version up to date")
                    print("kube-proxy version up to date")
                    customer_report["addons"][ds.metadata.name]["version"] = "Up to date"
                    check_addons_params(
                        log_details,
                        config,
                        ds.metadata.name,
                        cluster_details,
                        config_map,
                        yaml_data,
                        report,
                        customer_report,
                        cluster_name,
                        region,
                        errors,
                    )
                else:
                    addons.append({"name": ds.metadata.name, "version": version, "update": True})
                    print("kube-proxy version not compatible")
                    log_pusher(log_details, cluster_name, region, "kube-proxy version not compatible")
                    customer_report["addons"][ds.metadata.name][
                        "version"
                    ] = "Version Not Compatible with current cluster version"
                # print(ds.metadata.name + ':' + version)
                # print(addons)
        for dp in deployment.items:
            # print(dp.metadata.name)
            if dp.metadata.name == "coredns":
                version = dp.spec.template.spec.containers[0].image.split(dp.metadata.name + ":v")[1].split("-")[0]
                config = {
                    "image": dp.spec.template.spec.containers[0].image,
                    "volumeMount": dp.spec.template.spec.containers[0].volume_mounts,
                    "env": dp.spec.template.spec.containers[0].env,
                }
                check_pods_running("coredns", log_details, cluster_name, region, report, errors)
                if version_dict[report["cluster"]["version"]][dp.metadata.name] == version:
                    addons.append({"name": dp.metadata.name, "version": version, "update": False})
                    log_pusher(log_details, cluster_name, region, "core-dns version up to date")
                    customer_report["addons"][dp.metadata.name]["version"] = "Up to date"
                    # print(config)
                    print("core-dns version up to date")
                    check_addons_params(
                        log_details,
                        config,
                        dp.metadata.name,
                        cluster_details,
                        config_map,
                        yaml_data,
                        report,
                        customer_report,
                        cluster_name,
                        region,
                        errors,
                    )
                else:
                    addons.append({"name": dp.metadata.name, "version": version, "update": True})
                    print("core-dns version up not compatible")
                    log_pusher(log_details, cluster_name, region, "core-dns version up not compatible")
                    customer_report["addons"][dp.metadata.name][
                        "version"
                    ] = "Version Not Compatible with current cluster version"
        # print(addons)
        report["addons"] = addons
        customer_report["addons_version"] = addons
    except Exception as e:
        errors.append("Some error occured while checking the addon version {err}".format(err=e))
        log_pusher(
            log_details, cluster_name, region, "Some error occured while checking the addon version {err}".format(err=e)
        )
        print("Some error occured while checking the addon version {err}".format(err=e))
        report["preflight_status"] = False


# Function to check for addons pod to be in running state


def check_pods_running(addon, log_details, cluster_name, region, report, errors, namespace="kube-system"):
    try:
        v1 = client.CoreV1Api()
        count = 0
        rep = v1.list_namespaced_pod(namespace)
        for pod in rep.items:
            if addon in pod.metadata.name:
                count = count + 1
                if pod.status.phase == "Running":
                    print(addon + " pod is running")
                    log_pusher(log_details, cluster_name, region, addon + " pod is running")
                else:
                    print(addon + " Pod is not running, it is in " + pod.status.phase)
                    log_pusher(
                        log_details, cluster_name, region, addon + " Pod is not running, it is in " + pod.status.phase
                    )
                    errors.append(addon + " Pod is not running, it is in " + pod.status.phase)
                    report["preflight_status"] = False

        if count == 0:
            print(addon + " pod is not present in the cluster")
            log_pusher(log_details, cluster_name, region, addon + " pod is not present in the cluster")
            report["preflight_status"] = False
            errors.append(addon + " pod is not present in the cluster")
    except Exception as e:
        errors.append("Some error occured while checking for addon pods to be running {err}".format(err=e))
        log_pusher(
            log_details,
            cluster_name,
            region,
            "Some error occured while checking for addon pods to be running {err}".format(err=e),
        )
        print("Some error occured while checking for addon pods to be running {err}".format(err=e))
        report["preflight_status"] = False


# Function to check the volume mount and env in cluster and original YAML files for addons


def check_addons_params(
    log_details,
    config,
    name,
    cluster_details,
    config_map,
    yaml_data,
    report,
    customer_report,
    cluster_name,
    region,
    errors,
):
    # loading_config(cluster_name,region)
    s3_config = yaml_data[name]
    log_pusher(log_details, cluster_name, region, "************* Parameter check for " + name + " *************")
    print("************* Parameter check for " + name + " *************")
    # Compare image name
    image_part_1 = config["image"].split(".ecr.")[0] == s3_config["image"].split(".ecr.")[0]
    image_part_2 = (
        config["image"].split("amazonaws.com/")[1].split(":v")[0]
        == s3_config["image"].split("amazonaws.com/")[1].split(":v")[0]
    )
    if image_part_1 and image_part_2:
        report["addon_params"][name] = {"image": config["image"]}
        customer_report["addons"][name]["image"] = "Image Verified"
        log_pusher(log_details, cluster_name, region, "Image verified")
        print("Image verified")
    else:
        customer_report["addons"][name]["image"] = "Image Verification Failed"
        log_pusher(log_details, cluster_name, region, "Image verification failed")
        print("Image verification failed")

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
    if len(mount_paths) > 0:
        customer_report["addons"][name]["mount_paths"]["message"] = "Default mount paths are missing"
        report["addon_params"][name]["mount_paths"]["custom"] = True
        report["addon_params"][name]["mount_paths"]["default"] = " ".join(map(str, mount_paths))
        customer_report["addons"][name]["mount_paths"]["default-mountpaths"] = " ".join(map(str, mount_paths))
        log_pusher(
            log_details, cluster_name, region, "These mount paths are not present " + " ".join(map(str, mount_paths))
        )
        print("These mount paths are not present", " ".join(map(str, mount_paths)))
    if len(remaining) > 0:
        customer_report["addons"][name]["mount_paths"]["message"] = "There are additional mount paths present"
        report["addon_params"][name]["mount_paths"]["custom"] = True
        report["addon_params"][name]["mount_paths"]["user-defined"] = " ".join(map(str, mount_paths))
        customer_report["addons"][name]["mount_paths"]["userdefined-mountpaths"] = " ".join(map(str, mount_paths))
        log_pusher(
            log_details,
            cluster_name,
            region,
            "These user defined mount paths are present" + " ".join(map(str, mount_paths)),
        )
        print("These user defined mount paths are present", " ".join(map(str, mount_paths)))
    if len(mount_paths) == 0 and len(remaining) == 0:
        report["addon_params"][name]["mount_paths"]["custom"] = False
        customer_report["addons"][name]["mount_paths"]["message"] = "Mount paths verified successfully"
        log_pusher(log_details, cluster_name, region, "Mount path verification successful")
        print("Mount path verification successful")

    # Compare env
    if name == "vpc-cni":
        customer_report["addons"][name]["env"] = {}
        report["addon_params"][name]["envs"] = {}
        envs = []
        extra_envs = []
        for i in range(len(s3_config["env"])):
            # print(s3_config['env'][i]['name'])
            envs.append(s3_config["env"][i]["name"])
        for i in range(len(config["env"])):
            if config["env"][i].name in envs:
                envs.remove(config["env"][i].name)
            else:
                extra_envs.append(config["env"][i].name)
        if len(envs) > 0:
            # customer_report['addons'][name]["mount_paths"].append('These mount paths are not present',mount_paths)
            customer_report["addons"][name]["env"]["message"] = "Default envs are missing"
            report["addon_params"][name]["envs"]["custom"] = True
            report["addon_params"][name]["envs"]["default"] = " ".join(map(str, envs))
            customer_report["addons"][name]["env"]["default-envs"] = " ".join(map(str, envs))
            log_pusher(log_details, cluster_name, region, "These envs are not present" + " ".join(map(str, envs)))

            print("These envs are not present" + " ".join(map(str, envs)))

        if len(extra_envs) > 0:
            # customer_report['addons'][name]["mount_paths"].append('these user defined mount paths are not present',remaining)
            report["addon_params"][name]["envs"]["custom"] = True
            report["addon_params"][name]["envs"]["user-defined"] = " ".join(map(str, extra_envs))
            customer_report["addons"][name]["env"]["message"] = "There are additional envs present"
            log_pusher(
                log_details,
                cluster_name,
                region,
                "These user defined envs are present" + " ".join(map(str, extra_envs)),
            )
            print("These user defined envs are present", " ".join(map(str, extra_envs)))

            customer_report["addons"][name]["env"]["userdefined-envs"] = " ".join(map(str, extra_envs))
        if len(envs) == 0 and len(extra_envs) == 0:
            report["addon_params"][name]["envs"]["custom"] = False
            customer_report["addons"][name]["env"]["message"] = "Envs verified successfully"
            log_pusher(log_details, cluster_name, region, "Envs verification successful")
            print("Envs verification successful")
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
        v1 = client.CoreV1Api()
        default = []
        ret = v1.list_config_map_for_all_namespaces(field_selector="metadata.name=coredns")
        corefile = yaml.safe_load(ret.items[0].data["Corefile"]).split(".:53")[1]
        for i in arr:
            if corefile.find(i) == -1:
                default.append(i)
                log_pusher(log_details, cluster_name, region, i + "doesnt exist in corefile")
                print(i + "doesnt exist in corefile")

            else:
                corefile = corefile.replace(i, "")
        corefile = corefile.replace(" ", "")
        if len(default) > 0:
            customer_report["addons"][name]["corefile"]["message"] = "Default corefile fields are not present"
            report["addon_params"][name]["corefile"]["custom"] = True
            report["addon_params"][name]["corefile"]["default"] = " ".join(map(str, default))
            customer_report["addons"][name]["corefile"]["default-corefile-fields"] = " ".join(map(str, default))
            print("Default corefile fields are not present", " ".join(map(str, default)))
        if len(corefile) > 0:
            customer_report["addons"][name]["corefile"]["message"] = "There are additional fields present in corefile"
            report["addon_params"][name]["corefile"]["custom"] = True
            report["addon_params"][name]["corefile"]["userdefined"] = " ".join(map(str, corefile))
            customer_report["addons"][name]["corefile"]["userdefined-corefile-fields"] = " ".join(map(str, corefile))
            log_pusher(
                log_details, cluster_name, region, "Additional fields in corefile " + " ".join(map(str, corefile))
            )
            print("Additional fields in corefile ", " ".join(map(str, corefile)))
        if len(corefile) == 0 and len(default) == 0:
            report["addon_params"][name]["corefile"]["custom"] = False
            customer_report["addons"][name]["corefile"]["message"] = "Corefile fields verified successfully"
            log_pusher(log_details, cluster_name, region, "Corefile verified successfully")
            print("Corefile verified successfully")
    if name == "kube-proxy":
        report["addon_params"][name]["certificate-authority"] = {}
        report["addon_params"][name]["server-endpoint"] = {}
        customer_report["addons"][name]["certificate-authority"] = {}
        customer_report["addons"][name]["server-endpoint"] = {}
        v1 = client.CoreV1Api()
        ret = v1.list_config_map_for_all_namespaces(field_selector="metadata.name=kube-proxy")
        if (
            yaml.safe_load(ret.items[0].data["kubeconfig"])["clusters"][0]["cluster"]["certificate-authority"]
            == config_map["certificate-authority"]
        ):
            report["addon_params"][name]["certificate-authority"]["verified"] = True
            customer_report["addons"][name]["certificate-authority"][
                "message"
            ] = "Certificate Authority Verified in kube config"
            report["addon_params"][name]["certificate-authority"]["certificate"] = config_map["certificate-authority"]
            log_pusher(log_details, cluster_name, region, "Certificate Authority Verified in kube config")
            print("Certificate Authority Verified in kube config")
        else:
            customer_report["addons"][name]["certificate-authority"][
                "message"
            ] = "Certificate Verification failed in kube config"
            report["addon_params"][name]["certificate-authority"]["verified"] = False
            report["addon_params"][name]["certificate-authority"]["certificate"] = yaml.safe_load(
                ret.items[0].data["kubeconfig"]
            )["clusters"][0]["cluster"]["certificate-authority"]
            log_pusher(log_details, cluster_name, region, "Certificate Verification failed in kube config")
            print("Certificate Verification failed in kube config")
        # pprint(yaml.load(ret.items[0].data['kubeconfig'])['clusters'][0]['cluster']['server'])
        # pprint(yaml.load(ret.items[0].data['kubeconfig'])['clusters'][0]['cluster']['certificate-authority'])
        # pprint(config_map['certificate-authority'])
        server_endpoint = cluster_details["cluster"]["endpoint"]
        if (
            yaml.safe_load(ret.items[0].data["kubeconfig"])["clusters"][0]["cluster"]["server"]
            == cluster_details["cluster"]["endpoint"].lower()
        ):
            customer_report["addons"][name]["server-endpoint"]["message"] = "Server end point verified"
            report["addon_params"][name]["server-endpoint"]["verified"] = True
            report["addon_params"][name]["server-endpoint"]["server-endpoint"] = cluster_details["cluster"][
                "endpoint"
            ].lower()
            log_pusher(log_details, cluster_name, region, "Server end point verified")
            print("Server end point verified")
        else:
            customer_report["addons"][name]["server-endpoint"]["message"] = "Server end point verification failed"
            report["addon_params"][name]["certificate-authority"]["verified"] = False
            report["addon_params"][name]["certificate-authority"]["server-endpoint"] = yaml.safe_load(
                ret.items[0].data["kubeconfig"]
            )["clusters"][0]["cluster"]["server"]
            log_pusher(log_details, cluster_name, region, " Server end point verification failed")
            print(" Server end point verification failed")


def pod_disruption_budget(log_details, errors, cluster_name, region, report, customer_report, force_upgrade):
    loading_config(cluster_name, region)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Fetching Pod Disruption Budget Details....")
    print("Fetching Pod Disruption Budget Details....")
    try:
        v1 = client.PolicyV1beta1Api()
        ret = v1.list_pod_disruption_budget_for_all_namespaces()
        if len(ret.items) == 0:
            customer_report["pod disruption budget"] = "No Pod Disruption Budget exists in cluster"
            log_pusher(log_details, cluster_name, region, "No Pod Disruption Budget exists in cluster")
            print("No Pod Disruption Budget exists in cluster")
        else:
            print("Pod Disruption Budget exists in cluster therefore force upgrade is required to upgrade the cluster")
            if not force_upgrade:
                print(
                    "Pod Disruption Budget exists in cluster therefore force upgrade is required to upgrade the cluster, To upgrade please run the code with --force flag "
                )
                errors.append("To upgrade please run the code with --force flag ")
                report["preflight_status"] = False
            for pdb in ret.items:
                max_available = pdb.spec.max_unavailable
                min_available = pdb.spec.min_available
                # print(max_available,min_available)
                report["pdb"] = {"max_unavailable": max_available, "min_available": min_available}
                customer_report["pod disruption budget"] = "Pod disruption budget exists in the cluster"
                log_pusher(
                    log_details,
                    cluster_name,
                    region,
                    "Pod disruption budget exists with max unavailable as "
                    + str(max_available)
                    + " and min available as "
                    + str(min_available),
                )
                print(
                    "Pod disruption budget exists with max unavailable as "
                    + str(max_available)
                    + " and min available as "
                    + str(min_available)
                )
            v1 = client.CoreV1Api()
            pods_and_nodes = []
            ret = v1.list_pod_for_all_namespaces(watch=False)
            # pprint(ret.items[0].spec.node_name)
            for i in ret.items:
                pods_and_nodes.append(
                    {"name": i.metadata.name, "namespace": i.metadata.namespace, "nodename": i.spec.node_name}
                )
            report["pdb"]["pods"] = pods_and_nodes
            pprint(pods_and_nodes)
            # pprint(pods_and_nodes)
    except Exception as e:
        errors.append("Error ocurred while checking for pod disruption budget {err}".format(err=e))
        customer_report["pod disruption budget"] = "Error ocurred while checking for pod disruption budget"
        log_pusher(
            log_details,
            cluster_name,
            region,
            "Error ocurred while checking for pod disruption budget {err}".format(err=e),
        )
        print("Error ocurred while checking for pod disruption budget {err}".format(err=e))
        report["preflight_status"] = False


def cluster_auto_scaler(log_details, errors, cluster_name, region, report, customer_report):
    loading_config(cluster_name, region)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Fetching Cluster Auto Scaler Details....")
    print("Fetching Cluster Auto Scaler Details....")
    try:
        eks = boto3.client("eks", region_name=region)
        cluster_details = eks.describe_cluster(name=cluster_name)
        val = cluster_details["cluster"]["version"]
        l = val.split(".")
        v1 = client.AppsV1Api()
        res = v1.list_deployment_for_all_namespaces()
        for i in res.items:
            x = i.metadata.name
            if x == "cluster-autoscaler":
                log_pusher(log_details, cluster_name, region, "Cluster Autoscaler exists")
                print("Cluster Autoscaler exists")
                check_pods_running("cluster-autoscaler", log_details, cluster_name, region, report, errors)
                version = (
                    i.spec.template.spec.containers[0]
                    .image.split("k8s.gcr.io/autoscaling/cluster-autoscaler:v")[1]
                    .split("-")[0]
                )
                l1 = version.split(".")
                if l[0] == l1[0] and l[1] == l1[1]:
                    report["cluster_auto_scaler"] = {"image": i.spec.template.spec.containers[0].image}
                    customer_report["cluster autoscaler"] = "Auto scaler version is compatible with cluster version!"
                    log_pusher(
                        log_details, cluster_name, region, "Auto scaler version is compatible with cluster version!"
                    )
                    print("Auto scaler version is compatible with cluster version!")
                else:
                    print("Auto scaler version is not compatible with cluster version")
                    customer_report["cluster autoscaler"] = "Auto scaler version is not compatible with cluster version"
                    log_pusher(
                        log_details, cluster_name, region, "Auto scaler version is not compatible with cluster version!"
                    )
                return

            else:
                continue
        customer_report["cluster autoscaler"] = "Cluster Autoscaler doesn't exists"
        log_pusher(log_details, cluster_name, region, "Cluster Autoscaler doesn't exists")
        print("Cluster Autoscaler doesn't exists")
    except Exception as e:
        errors.append("Error occured while checking for the cluster autoscaler {err}".format(err=e))
        customer_report["cluster autoscaler"] = "Error occured while checking for the cluster autoscaler" + e
        log_pusher(
            log_details,
            cluster_name,
            region,
            "Error occured while checking for the cluster autoscaler {err}".format(err=e),
        )
        print("Error occured while checking for the cluster autoscaler {err}".format(err=e))
        report["preflight_status"] = False


def horizontal_auto_scaler(log_details, errors, cluster_name, region, report, customer_report):
    loading_config(cluster_name, region)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Fetching Horizontal Autoscaler Details....")
    print("Fetching Horizontal Autoscaler Details....")
    try:
        v1 = client.AutoscalingV1Api()
        ret = v1.list_horizontal_pod_autoscaler_for_all_namespaces()
        if len(ret.items) == 0:
            customer_report["horizontal auto scaler"] = "No Horizontal Auto Scaler exists in cluster"
            log_pusher(log_details, cluster_name, region, "No Horizontal Auto Scaler exists in cluster")
            print("No Horizontal Auto Scaler exists in cluster")
        else:
            customer_report["horizontal auto scaler"] = "Horizontal Pod Auto scaler exists in cluster"
            log_pusher(log_details, cluster_name, region, "Horizontal Pod Auto scaler exists in cluster")
            print("Horizontal Pod Auto scaler exists in cluster")
            report["horizontal_autoscaler"] = ret.items[0]
            # pprint(ret.items[0])
    except Exception as e:
        errors.append("Error occured while checking for horizontal autoscaler {err}".format(err=e))
        log_pusher(
            log_details,
            cluster_name,
            region,
            "Error occured while checking for horizontal autoscaler {err}".format(err=e),
        )
        print("Error occured while checking for horizontal autoscaler {err}".format(err=e))
        customer_report["horizontal auto scaler"] = "Error occured while checking for horizontal autoscaler"
        report["preflight_status"] = False


def depricated_api_check(log_details, errors, cluster_name, region, report, customer_report, update_version):
    loading_config(cluster_name, region)
    s3 = boto3.resource("s3")
    # Depricated API dictionary
    # depricated_api = s3.Object('eks-one-click-upgrade', 'depricatedApi')
    # depricated_api = depricated_api.get()['Body'].read().decode('utf-8')
    # depricated_api = json.loads(depricated_api)
    # TODO: Make this load safe.  This file is never closed. Use context manager instead.
    f = open(
        "eksupgrade/src/S3Files/depricatedApi",
    )
    depricated_api = json.load(f)
    # print(depricated_api)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Checking for any depricated API being used....")
    print("Checking for any depricated API being used....")
    customer_report["depricated Api"] = []
    try:
        dict = depricated_api[update_version]
        # print(dict)

        for key in dict.keys():
            # print(key)
            if key == "all-resources":
                for k in dict[key].keys():
                    if dict[key][k] == "permanent":
                        customer_report["depricated Api"].append(k + " API has been depricated permanently ")
                        log_pusher(log_details, cluster_name, region, k + " API has been depricated permanently ")
                        print(k + " API has been depricated permanently ")
                    else:
                        customer_report["depricated Api"].append(
                            k + " API has been depricated use " + dict[key][k] + " instead"
                        )
                        log_pusher(
                            log_details,
                            cluster_name,
                            region,
                            k + " API has been depricated use " + dict[key][k] + " instead",
                        )
                        print(k + " API has been depricated use " + dict[key][k] + " instead")
            else:
                depricated_resource = []
                new_resource = []
                v1 = eval(key)
                res = v1.get_api_resources()
                for resource in res.resources:
                    depricated_resource.append(resource.name)
                for k in dict[key].keys():
                    v2 = eval(k)
                    ret = v2.get_api_resources()
                    for resource in ret.resources:
                        new_resource.append(resource.name)
                    if dict[key][k] in depricated_resource and dict[key][k] not in new_resource:
                        customer_report["depricated Api"].append(
                            "Resource "
                            + dict[key][k]
                            + " is present in depricated API "
                            + key
                            + " to be shifted to "
                            + k
                        )
                        errors.append(
                            "Resource "
                            + dict[key][k]
                            + " is present in depricated API "
                            + key
                            + " to be shifted to "
                            + k
                        )
                        log_pusher(
                            log_details,
                            cluster_name,
                            region,
                            "Resource "
                            + dict[key][k]
                            + " is present in depricated API "
                            + key
                            + " to be shifted to "
                            + k,
                        )
                        print(
                            "Resource "
                            + dict[key][k]
                            + " is present in depricated API "
                            + key
                            + " to be shifted to "
                            + k
                        )
        log_pusher(log_details, cluster_name, region, "Depricated Api check completed")
        print("Depricated Api check completed")
    except Exception as e:
        errors.append("Depricated API check failed {err}".format(err=e))
        customer_report["depricated Api"].append("Depricated API check failed")
        log_pusher(log_details, cluster_name, region, "Depricated API check failed {err}".format(err=e))
        print("Depricated API check failed {err}".format(err=e))
        report["preflight_status"] = False


def cmk_key_check(log_details, errors, cluster_name, region, cluster, report, customer_report):
    loading_config(cluster_name, region)
    cmk = boto3.client("kms", region_name=region)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Checking if customer management key exists....")
    print("Checking if customer management key exists....")
    try:
        if "encryptionConfig" in cluster["cluster"].keys():
            cmk_key = cluster["cluster"]["encryptionConfig"][0]["provider"]["keyArn"]
            customer_report["CMK Key"] = "CMK Key with id " + cmk_key + " is present"
            log_pusher(log_details, cluster_name, region, "CMK Key with id " + cmk_key + " is present")
            print("CMK Key with id " + cmk_key + " is present")
            response = cmk.describe_key(
                KeyId=cmk_key,
            )
            try:
                response = cmk.describe_key(
                    KeyId=cmk_key,
                )
                if "KeyId" in response["KeyMetadata"].keys():
                    log_pusher(log_details, cluster_name, region, "Key with id " + cmk_key + " exist in user account")
                    customer_report["CMK Key"] = "Key with id " + cmk_key + " exist in user account"
                    print("Key with id " + cmk_key + " exist in user account")
                else:
                    report["preflight_status"] = False
                    errors.append("Key with id " + cmk_key + " doesnt exist in user account")
                    log_pusher(
                        log_details, cluster_name, region, "Key with id " + cmk_key + " doesnt exist in user account"
                    )
                    customer_report["CMK Key"] = "Key with id " + cmk_key + " doesnt exist in user account"
                    print("Key with id " + cmk_key + " doesnt exist in user account")
            except:
                report["preflight_status"] = False
                errors.append("Key with id " + cmk_key + " doesnt exist in user account")
                log_pusher(
                    log_details, cluster_name, region, "Key with id " + cmk_key + " doesnt exist in user account"
                )
                customer_report["CMK Key"] = "Key with id " + cmk_key + " doesnt exist in user account"
                print("Key with id " + cmk_key + " doesnt exist in user account")
        else:
            customer_report["CMK Key"] = "No CMK Key associated with the cluster"
            log_pusher(log_details, cluster_name, region, "No CMK Key associated with the cluster")
            print("No CMK Key associated with the cluster")
    except Exception as e:

        errors.append("Error while checking for cluster CMK key {err}".format(err=e))
        customer_report["CMK Key"] = "Error while checking for cluster CMK key"
        log_pusher(log_details, cluster_name, region, "Error while checking for cluster CMK key {err}".format(err=e))
        print("Error while checking for cluster CMK key {err}".format(err=e))
        report["preflight_status"] = False


def security_group_check(log_details, errors, cluster_name, region, cluster, report, customer_report):
    loading_config(cluster_name, region)
    print("\n")
    log_pusher(log_details, cluster_name, region, "Fetching security group details .....")
    print("Fetching security group details .....")
    try:
        security_groups = cluster["cluster"]["resourcesVpcConfig"]["securityGroupIds"]
        if len(security_groups) == 0:
            log_pusher(log_details, cluster_name, region, "No security groups available with cluster")
            customer_report["security group"] = "No security groups available with cluster"
            print("No security groups available with cluster")
        else:
            for s in security_groups:
                try:
                    ec2 = boto3.resource("ec2", region_name=region)
                    security_group = ec2.SecurityGroup(s)
                    y = security_group.description
                    customer_report["security group"] = (
                        "Security Group " + security_group.id + " is present in VPC with ID" + security_group.vpc_id
                    )
                    log_pusher(
                        log_details,
                        cluster_name,
                        region,
                        "Security Group " + security_group.id + " is present in VPC with ID " + security_group.vpc_id,
                    )
                    print("Security Group " + security_group.id + " is present in VPC with ID " + security_group.vpc_id)
                except:
                    customer_report["security group"] = "The security group with id " + s + " is not present"
                    report["preflight_status"] = False
                    errors.append("The security group with id " + s + " is not present")
                    log_pusher(log_details, cluster_name, region, "The security group with id " + s + " is not present")
                    print("The security group with id " + s + " is not present")
    except Exception as e:

        errors.append(" Error retireving security  group of cluster {err}".format(err=e))
        customer_report["security group"] = " Error retireving security  group of cluster {err}".format(err=e)
        log_pusher(
            log_details, cluster_name, region, " Error retireving security  group of cluster {err}".format(err=e)
        )
        print(" Error retireving security  group of cluster {err}".format(err=e))
        report["preflight_status"] = False


# Check if the AMI is custom


def iscustomami(node_type, Presentversion, image_id, region):
    # print(node_type)
    all_images = []
    if node_type == "Amazon Linux 2":
        filters = [
            {"Name": "owner-id", "Values": ["602401143452"]},
            {"Name": "name", "Values": ["amazon-eks-node-{version}*".format(version=Presentversion)]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    elif "ubuntu" in node_type.lower():
        filters = [
            {"Name": "owner-id", "Values": ["099720109477"]},
            {"Name": "name", "Values": ["ubuntu-eks/k8s_{version}*".format(version=Presentversion)]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    elif "bottlerocket" in node_type.lower():
        filters = [
            {"Name": "owner-id", "Values": ["092701018921"]},
            {"Name": "name", "Values": ["bottlerocket-aws-k8s-{version}*".format(version=Presentversion)]},
            {"Name": "is-public", "Values": ["true"]},
        ]
    elif "windows" in node_type.lower():
        filters = [
            {"Name": "owner-id", "Values": ["801119661308"]},
            {
                "Name": "name",
                "Values": ["Windows_Server-*-English-*-EKS_Optimized-{version}*".format(version=Presentversion)],
            },
            {"Name": "is-public", "Values": ["true"]},
        ]
    else:
        return True

    ec2Client = boto3.client("ec2", region_name=region)
    images = ec2Client.describe_images(Filters=filters)
    instances_list = []
    for i in images.get("Images"):
        instances_list.append([i.get("ImageId"), i.get("ImageLocation")])
    # print(instances_list)
    for i in instances_list:
        if image_id in i[0]:
            return False
    else:
        return True
    # for i in images.get('Images'):
    #     all_images.append(i.get('ImageId'))
    # if image_id in all_images:
    #     return False
    # else:
    #     return True


# Print nodegroup details


def nodegroup_customami(log_details, errors, cluster_name, region, report, customer_report, update_version):
    loading_config(cluster_name, region)
    final_dict = {"self-managed": {}, "managed": {}, "fargate": {}}
    print("\n")
    log_pusher(log_details, cluster_name, region, "Fetching node group details ......")
    print("Fetching node group details ......")
    try:
        v1 = client.CoreV1Api()
        ret = v1.list_node()
        # pprint(ret.items)
        if len(ret.items) == 0:
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
                # print(instance_id)
                node_type = i.status.node_info.os_image
                # print(node_type)
                if "windows" in (node_type).lower():
                    node_type = "windows"
                ec2Client = boto3.client("ec2", region_name=region)
                res = ec2Client.describe_instances(InstanceIds=[instance_id])

                ami = res.get("Reservations")[0]["Instances"][0]["ImageId"]
                # print(ami)

                hd = res["Reservations"][0]["Instances"][0]["Tags"]

                for m in hd:

                    if m["Key"] == "aws:autoscaling:groupName":
                        autoscale_group_name = m["Value"]
                        # print(autoscale_group_name)

                custom_ami = iscustomami(node_type, ver, ami, region)
                # print(custom_ami)
                if ver == report["cluster"]["version"]:
                    version_compatibility = True
                elif update_version and round(float(report["cluster"]["version"]) - float(ver), 2) == 0.01:
                    version_compatibility = True
                else:
                    version_compatibility = False
                if custom_ami:
                    # errors.append(instance_id + ' cannot be upgraded as it has custom ami')
                    log_pusher(
                        log_details, cluster_name, region, instance_id + " cannot be upgraded as it has custom ami"
                    )
                    print(instance_id + " cannot be upgraded as it has custom ami")
                if not version_compatibility:
                    report["preflight_status"] = False
                    # errors.append(instance_id  + ' cannot be upgraded as cluster version is not compatible with node version')
                    log_pusher(
                        log_details,
                        cluster_name,
                        region,
                        instance_id + " cannot be upgraded as cluster version is not compatible with node version",
                    )
                    print(instance_id + " cannot be upgraded as cluster version is not compatible with node version")
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
                            print("Nodegroup cannot be upgraded as it has custom launch template")
                            # errors.append('Nodegroup cannot be upgraded as it has custom launch template')
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

        errors.append("Error ocurred while checking node group details {err}".format(err=e))
        log_pusher(
            log_details, cluster_name, region, "Error ocurred while checking node group details {err}".format(err=e)
        )
        print("Error ocurred while checking node group details {err}".format(err=e))
        customer_report["node group details"] = "Error ocurred while checking node group details"
        report["preflight_status"] = False


# Publish a preflight report via SES


def send_email(preflight, log_details, errors, cluster_name, region, report, customer_report, email):
    try:
        ses_client = boto3.client("ses", region_name="ap-south-1")
        # response = ses_client.list_identities()
        htmlStart = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Document</title><style>table,th,td {border: 1px solid black;border-collapse: collapse;}th,td {padding: 10px;}th {text-align: left;}</style></head><body>'
        htmlend = ""
        if preflight:
            htmlStart = (
                htmlStart
                + "<h2>Preflight check for cluster "
                + cluster_name
                + " in region "
                + region
                + " : "
                + str(report["preflight_status"])
                + "</h2>"
            )
        else:
            htmlStart = (
                htmlStart
                + "<h2>Postflight check for cluster "
                + cluster_name
                + " in region "
                + region
                + " : "
                + str(report["preflight_status"])
                + "</h2>"
            )
        if report["preflight_status"]:
            if preflight:
                htmlStart = htmlStart + "<h3>The preflight check for your cluster completed successfully</h3>"
            else:
                htmlStart = htmlStart + "<h3>The postflight check for your cluster completed successfully</h3>"
                htmlStart = htmlStart + "All things upgraded successfully"

        else:
            if preflight:
                htmlStart = (
                    htmlStart
                    + "<h3>The preflight check for your cluster failed, please check the below report for more details</h3>"
                )
            else:
                htmlStart = (
                    htmlStart
                    + "<h3>The postflight check for your cluster failed, please check the below report for more details</h3>"
                )
                htmlStart = htmlStart + "Certain things couldn’t be upgraded during the upgrade"

        htmlStart = (
            htmlStart
            + "<h3>General Check details</h3><table><thead><tr><th>Name</th><th>Status</th></tr></thead><tbody>"
        )

        htmlStart = htmlStart + "<tr><td>CMK Key</td><td>" + customer_report["CMK Key"] + "</td></tr>"
        htmlStart = htmlStart + "<tr><td>IAM role</td><td>" + customer_report["IAM role"] + "</td></tr>"
        htmlStart = (
            htmlStart + "<tr><td>cluster autoscaler</td><td>" + customer_report["cluster autoscaler"] + "</td></tr>"
        )
        if "cluster upgradation" in customer_report.keys():
            htmlStart = (
                htmlStart
                + "<tr><td>cluster upgradation</td><td>"
                + customer_report["cluster upgradation"]
                + "</td></tr>"
            )
        htmlStart = htmlStart + "<tr><td>Cluster Roles</td><td><ul>"
        for s in customer_report["cluster role"]:
            htmlStart = htmlStart + "<li>" + str(s) + "</li>"
        htmlStart = htmlStart + "</ul></td></tr>"
        htmlStart = htmlStart + "<tr><td>cluster version</td><td>" + customer_report["cluster version"] + "</td></tr>"
        if "depricated Api" in customer_report.keys():
            htmlStart = (
                htmlStart + "<tr><td>depricated Api</td><td>" + str(customer_report["depricated Api"]) + "</td></tr>"
            )
        htmlStart = (
            htmlStart
            + "<tr><td>horizontal auto scaler</td><td>"
            + customer_report["horizontal auto scaler"]
            + "</td></tr>"
        )
        htmlStart = (
            htmlStart
            + "<tr><td>pod disruption budget</td><td>"
            + str(customer_report["pod disruption budget"])
            + "</td></tr>"
        )
        htmlStart = (
            htmlStart + "<tr><td>pod security policy</td><td>" + customer_report["pod security policy"] + "</td></tr>"
        )
        htmlStart = htmlStart + "<tr><td>security group</td><td>" + customer_report["security group"] + "</td></tr>"
        htmlStart = htmlStart + "<tr><td>subnet</td><td><ul>"
        for s in customer_report["subnet"]:
            htmlStart = htmlStart + "<li>" + str(s) + "</li>"
        htmlStart = htmlStart + "</ul></td></tr>"
        htmlStart = htmlStart + "</tbody></table>"

        htmlStart = htmlStart + "<h3>Addons details</h3>"
        if "coredns" in customer_report["addons"].keys() and len(customer_report["addons"]["coredns"].keys()) != 0:
            if "image" in customer_report["addons"]["coredns"].keys():
                htmlStart = (
                    htmlStart
                    + "<p>Core DNS </p>"
                    + "<table><thead><td>Corefile</td><td>Image</td><td>Mount Path</td><td>Version</td></thead><tbody><tr>"
                )
                htmlStart = htmlStart + "<td>" + customer_report["addons"]["coredns"]["corefile"]["message"] + "<ul>"
                if "default-corefile-fields" in customer_report["addons"]["coredns"]["corefile"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>default-corefile-fields "
                        + str(customer_report["addons"]["coredns"]["corefile"]["default-corefile-fields"])
                        + "</li>"
                    )
                if "userdefined-corefile-fields" in customer_report["addons"]["coredns"]["corefile"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>userdefined-corefile-fields "
                        + str(customer_report["addons"]["coredns"]["corefile"]["userdefined-corefile-fields"])
                        + "</li>"
                    )
                htmlStart = htmlStart + "</ul></td><td>" + customer_report["addons"]["coredns"]["image"] + "</td>"
                htmlStart = htmlStart + "<td>" + customer_report["addons"]["coredns"]["mount_paths"]["message"] + "<ul>"
                if "default-mountpaths" in customer_report["addons"]["coredns"]["mount_paths"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>default-mountpaths "
                        + str(customer_report["addons"]["coredns"]["mount_paths"]["default-mountpaths"])
                        + "</li>"
                    )
                if "userdefined-mountpaths" in customer_report["addons"]["coredns"]["mount_paths"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>userdefined-mountpaths "
                        + str(customer_report["addons"]["coredns"]["mount_paths"]["userdefined-mountpaths"])
                        + "</li>"
                    )
                htmlStart = htmlStart + "</ul></td><td>" + customer_report["addons"]["coredns"]["version"] + "</td>"
                htmlStart = htmlStart + "</tr></tbody></table>"
            else:
                htmlStart = htmlStart + "<p>Core DNS </p>"
                htmlStart = htmlStart + "<p>" + customer_report["addons"]["coredns"]["version"] + "</p>"

        if (
            "kube-proxy" in customer_report["addons"].keys()
            and len(customer_report["addons"]["kube-proxy"].keys()) != 0
        ):
            if "image" in customer_report["addons"]["kube-proxy"].keys():
                htmlStart = (
                    htmlStart
                    + "<p>Kube Proxy </p>"
                    + "<table><thead><td>Certificate Authority</td><td>Image</td><td>Mount Path</td><td>Version</td><td>Server Endpoint</td></thead><tbody><tr>"
                )
                htmlStart = (
                    htmlStart
                    + "<td>"
                    + customer_report["addons"]["kube-proxy"]["certificate-authority"]["message"]
                    + "</td>"
                )
                htmlStart = htmlStart + "<td>" + customer_report["addons"]["kube-proxy"]["image"] + "</td>"
                htmlStart = (
                    htmlStart + "<td>" + customer_report["addons"]["kube-proxy"]["mount_paths"]["message"] + "<ul>"
                )
                if "default-mountpaths" in customer_report["addons"]["kube-proxy"]["mount_paths"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>default-mountpaths "
                        + str(customer_report["addons"]["kube-proxy"]["mount_paths"]["default-mountpaths"])
                        + "</li>"
                    )
                if "userdefined-mountpaths" in customer_report["addons"]["kube-proxy"]["mount_paths"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>userdefined-mountpaths "
                        + str(customer_report["addons"]["kube-proxy"]["mount_paths"]["userdefined-mountpaths"])
                        + "</li>"
                    )
                htmlStart = htmlStart + "</ul></td><td>" + customer_report["addons"]["kube-proxy"]["version"] + "</td>"
                htmlStart = (
                    htmlStart + "<td>" + customer_report["addons"]["kube-proxy"]["server-endpoint"]["message"] + "</td>"
                )
                htmlStart = htmlStart + "</tr></tbody></table>"
            else:
                htmlStart = htmlStart + "<p>Kube Proxy </p>"
                htmlStart = htmlStart + "<p>" + customer_report["addons"]["kube-proxy"]["version"] + "</p>"

        if "vpc-cni" in customer_report["addons"].keys() and len(customer_report["addons"]["vpc-cni"].keys()) != 0:
            if "image" in customer_report["addons"]["vpc-cni"]:
                htmlStart = (
                    htmlStart
                    + "<p>VPC Cni </p>"
                    + "<table><thead><td>Image</td><td>Mount Path</td><td>Version</td><td>Env</td></thead><tbody><tr>"
                )
                htmlStart = htmlStart + "<td>" + customer_report["addons"]["vpc-cni"]["image"] + "</td>"
                htmlStart = htmlStart + "<td>" + customer_report["addons"]["vpc-cni"]["mount_paths"]["message"] + "<ul>"
                if "default-mountpaths" in customer_report["addons"]["vpc-cni"]["mount_paths"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>default-mountpaths "
                        + str(customer_report["addons"]["vpc-cni"]["mount_paths"]["default-mountpaths"])
                        + "</li>"
                    )
                if "userdefined-mountpaths" in customer_report["addons"]["vpc-cni"]["mount_paths"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>userdefined-mountpaths "
                        + str(customer_report["addons"]["vpc-cni"]["mount_paths"]["userdefined-mountpaths"])
                        + "</li>"
                    )
                htmlStart = htmlStart + "</ul></td><td>" + customer_report["addons"]["vpc-cni"]["version"] + "</td>"
                htmlStart = htmlStart + "<td>" + customer_report["addons"]["vpc-cni"]["env"]["message"] + "<ul>"
                if "default-envs" in customer_report["addons"]["vpc-cni"]["env"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>default-envs "
                        + str(customer_report["addons"]["vpc-cni"]["env"]["default-envs"])
                        + "</li>"
                    )
                if "userdefined-envs" in customer_report["addons"]["vpc-cni"]["env"].keys():
                    htmlStart = (
                        htmlStart
                        + "<li>userdefined-envs "
                        + str(customer_report["addons"]["vpc-cni"]["env"]["userdefined-envs"])
                        + "</li>"
                    )
                htmlStart = htmlStart + "</ul></td></tr></tbody></table>"
            else:
                htmlStart = htmlStart + "<p>VPC Cni </p>"
                htmlStart = htmlStart + "<p>" + customer_report["addons"]["vpc-cni"]["version"] + "</p>"
        if customer_report["nodegroup_details"]:
            node_groups = customer_report["nodegroup_details"]
            htmlStart = htmlStart + "<h3>Node groups</h3>"
            htmlStart = (
                htmlStart
                + "<table><thead><tr><th>Node group type</th><th>Autoscaling group</th><th>Custom launch template</th><th>AMI image</th><th>Custom AMI</th><th>Node type</th><th>Version</th><th>Version Compatibility</th></tr></thead><tbody>"
            )
            for k in node_groups.keys():
                if k == "fargate" and len(node_groups[k].keys()) > 0:
                    for id in node_groups[k].keys():
                        htmlStart = (
                            htmlStart
                            + "<tr><td>Fargate</td><td>--</td><td>--</td><td>--</td><td>--</td><td>"
                            + id
                            + "</td>"
                            + "<td>"
                            + node_groups[k][id]["version"]
                            + "</td><td>"
                            + str(node_groups[k][id]["version_compatibility"])
                            + "</td></tr>"
                        )
                if k == "managed" and len(node_groups[k].keys()) > 0:
                    for autoscaling in node_groups[k].keys():
                        for n in node_groups[k][autoscaling]:
                            if n == "instances":
                                for inst in node_groups[k][autoscaling][n]:
                                    htmlStart = htmlStart + "<tr><td>Managed</td>"
                                    htmlStart = htmlStart + "<td>" + autoscaling + "</td>"
                                    htmlStart = (
                                        htmlStart
                                        + "<td>"
                                        + str(node_groups[k][autoscaling]["custom_launch_template"])
                                        + "</td>"
                                    )
                                    htmlStart = htmlStart + "<td>" + str(inst["ami"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["custom_ami"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["node_type"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["version"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["version_compatibility"]) + "</td>"
                                    htmlend = htmlend + "</tr>"
                if k == "self-managed" and len(node_groups[k].keys()) > 0:
                    for autoscaling in node_groups[k].keys():
                        for n in node_groups[k][autoscaling]:
                            if n == "instances":
                                for inst in node_groups[k][autoscaling][n]:
                                    htmlStart = htmlStart + "<tr><td>Self Managed</td>"
                                    htmlStart = htmlStart + "<td>" + autoscaling + "</td>"
                                    htmlStart = htmlStart + "<td>" + "--" + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["ami"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["custom_ami"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["node_type"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["version"]) + "</td>"
                                    htmlStart = htmlStart + "<td>" + str(inst["version_compatibility"]) + "</td>"
                                    htmlend = htmlend + "</tr>"

        htmlend = htmlend + "</tbody></table></body></html>"
        CHARSET = "UTF-8"
        HTML_EMAIL_CONTENT = htmlStart + htmlend
        if preflight:
            subject = "Preflight check report for cluster " + cluster_name + " in region " + region
        else:
            subject = "Postflight check report for cluster " + cluster_name + " in region " + region
        try:
            response = ses_client.send_email(
                Destination={
                    "ToAddresses": [
                        email,
                    ],
                },
                Message={
                    "Body": {
                        "Html": {
                            "Charset": CHARSET,
                            "Data": HTML_EMAIL_CONTENT,
                        }
                    },
                    "Subject": {
                        "Charset": CHARSET,
                        "Data": subject,
                    },
                },
                Source=email,
            )
            print("It may take sometime for the user to get email delivered if verified")
        except:
            print("The email given is not verified by user to share the report over it")
    except Exception as e:
        print("Error occurred while sharing email {err}".format(err=e))
