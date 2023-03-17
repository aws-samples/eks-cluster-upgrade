"""Define the starter module."""
from __future__ import annotations

import datetime
import logging
import queue
import sys
import threading
import time

from .exceptions import ClusterInactiveException
from .models.eks import Cluster
from .src.boto_aws import (
    add_autoscaling,
    add_node,
    get_latest_instance,
    get_num_of_instances,
    get_outdated_asg,
    outdated_lt,
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
)
from .src.latest_ami import get_latest_ami
from .src.preflight_module import pre_flight_checks
from .src.self_managed import update_nodegroup

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
    is_present = False
    cluster_name = args.name
    to_update = args.version
    pass_vpc = args.pass_vpc
    max_retry = args.max_retry
    region = args.region
    forced = args.force
    paralleled = args.parallel
    preflight = args.preflight
    use_latest_addons = args.latest_addons
    disable_checks = args.disable_checks
    replicas_value = 0

    try:
        # Preflight Logic
        if not disable_checks:
            if not pre_flight_checks(True, cluster_name, region, pass_vpc, args.version, args.force):
                logger.error("Pre-flight check for cluster %s failed!", cluster_name)
                sys.exit()
            else:
                logger.info("Pre-flight check for the cluster %s succeeded!", cluster_name)
            if preflight:
                sys.exit()
        else:
            logger.info("Pre-flight check was disabled and didn't run.")

        # upgrade Logic
        logger.info("The cluster upgrade process has started")

        target_cluster: Cluster = Cluster.get(
            cluster_name=cluster_name, region=region, target_version=to_update, latest_addons=use_latest_addons
        )

        if not target_cluster.available:
            raise ClusterInactiveException("The cluster is not active")

        logger.info("The current version of the cluster was detected as: %s", target_cluster.version)

        # Checking Cluster is Active or Not Before Making an Update
        if target_cluster.active:
            target_cluster.update_cluster(wait=True)
        else:
            logger.warning(
                "The target EKS cluster: %s isn't currently active - status: %s",
                target_cluster.name,
                target_cluster.status,
            )
            target_cluster.wait_for_active()

        # Managed Node Groups
        logger.info("The Manged Node Groups Found are %s", ",".join(target_cluster.nodegroup_names))
        managed_nodegroup_asgs: list[str] = []
        for nodegroup in target_cluster.nodegroups:
            managed_nodegroup_asgs += nodegroup.autoscaling_group_names

        # removing self-managed from managed so that we don't update them again
        asg_list_self_managed = list(set(target_cluster.asg_names) - set(managed_nodegroup_asgs))

        # addons update
        target_cluster.upgrade_addons(wait=True)

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

        if target_cluster.upgradable_managed_nodegroups:
            logger.info("The outdated managed nodegroups = %s", target_cluster.upgradable_managed_nodegroups)
        else:
            logger.info("No outdated managed nodegroups found!")

        target_cluster.upgrade_nodegroups(wait=not paralleled)

        # TODO: Use custom_ami to update launch templates and re-roll self-managed nodes under ASGs.
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

        if not disable_checks:
            if not pre_flight_checks(
                preflight=False, cluster_name=cluster_name, region=region, pass_vpc=pass_vpc, force_upgrade=forced
            ):
                logger.info("Post flight check for cluster %s failed after it upgraded", cluster_name)
            else:
                logger.info("After update check for cluster completed successfully")
        else:
            logger.info("Post-flight check was disabled and didn't run.")
    except Exception as error:
        if is_present:
            try:
                cluster_auto_enable_disable(
                    cluster_name=cluster_name, operation="start", mx_val=replicas_value, region=region
                )
                logger.info("Cluster Autoscaler is Enabled Again")
            except Exception as error2:
                logger.error("Autoenable failed and must be done manually! Error: %s", error2)
        logger.error("Exception encountered in main method - Error: %s", error)
