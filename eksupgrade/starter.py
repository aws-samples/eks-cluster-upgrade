"""Define the starter module."""
from __future__ import annotations

import datetime
import logging
import queue
import sys
import threading
import time

from .src.boto_aws import (
    add_autoscaling,
    add_node,
    get_asgs,
    get_latest_instance,
    get_num_of_instances,
    get_outdated_asg,
    is_cluster_exists,
    outdated_lt,
    status_of_cluster,
    update_cluster,
    wait_for_ready,
    worker_terminate,
)
from .src.eks_get_image_type import get_ami_name
from .src.k8s_client import (
    cluster_auto_enable_disable,
    delete_node,
    drain_nodes,
    find_node,
    is_cluster_auto_scaler_present,
    unschedule_old_nodes,
    update_addons,
)
from .src.latest_ami import get_latest_ami
from .src.preflight_module import pre_flight_checks
from .src.self_managed import filter_node_groups, get_asg_node_groups, get_node_groups, update_nodegroup

logger = logging.getLogger(__name__)

queue = queue.Queue()


class StatsWorker(threading.Thread):
    """Define the Stats worker for process and queue handling."""

    def __init__(self, queue, id) -> None:
        """Initialize the stats worker."""
        threading.Thread.__init__(self)
        self.queue = queue
        self.id = id

    def run(self) -> None:
        """Run the thread routine."""
        while self.queue.not_empty:
            cluster_name, ng_name, to_update, region, max_retry, forced, typse = self.queue.get()
            if typse == "managed":
                logger.info("Updating node group: %s to version: %s", ng_name, to_update)
                update_nodegroup(cluster_name, ng_name, to_update, region)
                logger.info("Updated node group: %s to version: %s", ng_name, to_update)
                self.queue.task_done()
            elif typse == "selfmanaged":
                logger.info("Updating node group: %s to version: %s", ng_name, to_update)
                actual_update(
                    cluster_name=cluster_name,
                    asg_iter=ng_name,
                    to_update=to_update,
                    region=region,
                    max_retry=max_retry,
                    forced=forced,
                )
                logger.info("Updated node group: %s to version: %s", ng_name, to_update)
                self.queue.task_done()


def actual_update(cluster_name, asg_iter, to_update, region, max_retry, forced):
    """Perform the update."""
    instance_type, image_to_search = get_ami_name(cluster_name, asg_iter, region)
    logger.info("The Image Type Detected = %s", instance_type)

    if instance_type == "NAN":
        return False
    if isinstance(image_to_search, str) and "Windows_Server" in image_to_search:
        image_to_search = image_to_search[:46]
    latest_ami = get_latest_ami(to_update, instance_type, image_to_search, region)
    logger.info("The Latest AMI Recommended = %s", latest_ami)

    if get_outdated_asg(asg_iter, latest_ami, region):
        add_autoscaling(asg_iter, latest_ami, region)
        logger.info("New Launch Configuration Added to = %s With EKS AMI = %s", asg_iter, latest_ami)

    outdated_instances = outdated_lt(asg_iter, region)
    if not outdated_instances:
        return True

    try:
        terminated_ids = []
        logger.info("The Outdate Instance Found Are = %s", outdated_instances)
        for instance in outdated_instances:
            before_count = get_num_of_instances(asg_iter, terminated_ids, region)
            logger.info("Total Instance count = %s", before_count)
            add_time = datetime.datetime.now(datetime.timezone.utc)

            if abs(before_count - len(outdated_instances)) != len(outdated_instances):
                add_node(asg_iter, region)
                time.sleep(45)
                latest_instance = get_latest_instance(asg_name=asg_iter, add_time=add_time, region=region)
                logger.info("The Instance Created = %s and waiting for it to be ready", latest_instance)
                time.sleep(30)
                wait_for_ready(latest_instance, region)

            old_pod_id = find_node(cluster_name=cluster_name, instance_id=instance, operation="find", region=region)
            if old_pod_id != "NAN":
                retry = 0
                flag = 0
                while retry <= max_retry:
                    if (
                        not find_node(cluster_name=cluster_name, instance_id=instance, operation="find", region=region)
                        == "NAN"
                    ):
                        flag = 1
                        retry += 1
                        time.sleep(10)
                if flag == 0:
                    worker_terminate(instance, region=region)
                    raise Exception("404 instance is not corresponded to particular node group")

            logger.info("Unscheduling the worker node = %s", old_pod_id)

            unschedule_old_nodes(cluster_name=cluster_name, node_name=old_pod_id, region=region)
            logger.info("The node: %s has been unscheduled! Worker Node Draining...", old_pod_id)
            drain_nodes(cluster_name=cluster_name, node_name=old_pod_id, forced=forced, region=region)
            logger.info("The worker node has been drained! Deleting worker Node Started = %s", old_pod_id)
            delete_node(cluster_name=cluster_name, node_name=old_pod_id, region=region)
            logger.info("The worker node: %s has been deleted. Terminating Worker Node: %s...", old_pod_id, instance)
            worker_terminate(instance, region=region)
            terminated_ids.append(instance)
            logger.info("The worker node instance: %s has been terminated!", instance)
        return True
    except Exception as e:
        logger.error("Error encountered during actual update! Exception: %s", e)
        raise e


def main(args) -> None:
    """Handle the main workflow for eks update."""
    try:
        cluster_name = args.name
        to_update = args.version
        pass_vpc = args.pass_vpc
        max_retry = args.max_retry
        region = args.region
        present_version = "NAN"
        is_present = False
        forced = args.force
        paralleled = args.parallel
        preflight = args.preflight

        # Preflight Logic
        if not (pre_flight_checks(True, cluster_name, region, args.pass_vpc, args.version, args.force)):
            logger.error("Pre-flight check for cluster %s failed!", cluster_name)
            sys.exit()
        else:
            logger.info("Pre-flight check for the cluster %s succeeded!", cluster_name)
        if preflight:
            sys.exit()

        # upgrade Logic
        logger.info("The cluster upgrade process has started")
        if (
            is_cluster_exists(cluster_name=cluster_name, region=region) == "ACTIVE"
            or is_cluster_exists(cluster_name=cluster_name, region=region) == "UPDATING"
        ):
            present_version = status_of_cluster(cluster_name, region)[1]
            logger.info("The current version of the cluster was detected as: %s", present_version)
        else:
            raise Exception("The cluster is not active")

        # Checking Cluster is Active or Not Before Making an Update
        start = time.time()
        if is_cluster_exists(cluster_name=cluster_name, region=region) == "ACTIVE":
            update_cluster(cluster_name=cluster_name, version=to_update, region=region)
        time.sleep(5)

        # Making Sure the Cluster is Updated
        if (
            status_of_cluster(cluster_name, region)[1] != to_update
            or status_of_cluster(cluster_name, region)[0] != "ACTIVE"
        ):
            update_cluster(cluster_name, to_update, region)

        # finding the managed autoscaling groups

        end = time.time()
        hours, rem = divmod(end - start, 3600)
        minutes, seconds = divmod(rem, 60)
        logger.info("The Time Taken For the Cluster to Upgrade %s:%s:%s", int(hours), int(minutes), seconds)
        finding_manged = get_asg_node_groups(cluster_name, region)
        logger.info("The Manged Node Groups Found are %s", ",".join(finding_manged))
        asg_list = get_asgs(cluster_name, region)
        logger.info("The ASGs Found Are %s", ",".join(asg_list))

        # removing self-managed from managed so that we don't update them again
        asg_list_self_managed = list(set(asg_list) - set(finding_manged))

        # addons update
        finding_manged_nodes_names = get_node_groups(cluster_name=cluster_name, region=region)

        logger.info("The add-ons Update has been initiated...")
        start_time = time.time()
        start = time.time()
        logger.info("The Addons Upgrade Started At %s", str(start_time))
        update_addons(cluster_name=cluster_name, version=to_update, vpc_pass=pass_vpc, region_name=region)
        end = time.time()
        hours, rem = divmod(end - start, 3600)
        minutes, seconds = divmod(rem, 60)

        logger.info("The Taken For the Addons Upgrade %s:%s:%s", int(hours), int(minutes), seconds)
        # finding managed node groups with filter
        finding_manged_nodes = filter_node_groups(
            cluster_name=cluster_name,
            node_list=finding_manged_nodes_names,
            latest_version=to_update,
            region=region,
        )
        if finding_manged:
            logger.info("The OutDated Managed Node Groups = %s", finding_manged)
        else:
            logger.info("No OutDated Managed Node Groups Found")

        replicas_value = 0

        # checking auto scaler present and the value associated from it

        is_present, replicas_value = is_cluster_auto_scaler_present(cluster_name=cluster_name, region=region)

        if is_present:
            cluster_auto_enable_disable(
                cluster_name=cluster_name, operation="pause", mx_val=replicas_value, region=region
            )
            logger.info("Paused the Cluster AutoScaler")
        else:
            logger.info("No Cluster AutoScaler is Found")
        if paralleled:
            for x in range(20):
                worker = StatsWorker(queue, x)
                worker.setDaemon(True)
                worker.start()

        for ng_name in finding_manged_nodes:
            start = time.time()
            logger.info("Updating the Node Group = %s To version = %s", ng_name, to_update)
            if paralleled:
                queue.put([cluster_name, ng_name, to_update, region, max_retry, forced, "managed"])
            else:
                update_nodegroup(cluster_name, ng_name, to_update, region)

        for asg_iter in asg_list_self_managed:
            if paralleled:
                queue.put([cluster_name, asg_iter, to_update, region, max_retry, forced, "selfmanaged"])
            else:
                actual_update(cluster_name, asg_iter, to_update, region, max_retry, forced)

        if paralleled:
            queue.join()

        if is_present:
            cluster_auto_enable_disable(
                cluster_name=cluster_name, operation="start", mx_val=replicas_value, region=region
            )
            logger.info("Cluster Autoscaler is Enabled Again")
        logger.info("EKS Cluster %s UPDATED TO %s", cluster_name, to_update)
        logger.info("Post flight check for the upgraded cluster")

        if not (pre_flight_checks(False, cluster_name, region, args.pass_vpc)):
            logger.info("Post flight check for cluster %s failed after it upgraded", cluster_name)
        else:
            logger.info("After update check for cluster completed successfully")
    except Exception as e:
        if is_present:
            try:
                cluster_auto_enable_disable(
                    cluster_name=cluster_name, operation="start", mx_val=replicas_value, region=region
                )
                logger.info("Cluster Autoscaler is Enabled Again")
            except Exception as e:
                logger.error("Autoenable failed and must be done manually! Error: %s", e)
        logger.error("Exception encountered in main method - Error: %s", e)
