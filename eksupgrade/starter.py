"""Define the starter module."""
from __future__ import annotations

import datetime
import queue
import threading
import time

from eksupgrade.utils import echo_error, echo_info, echo_success, get_logger

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
from .src.k8s_client import delete_node, drain_nodes, find_node, unschedule_old_nodes
from .src.latest_ami import get_latest_ami
from .src.self_managed import update_nodegroup

logger = get_logger(__name__)

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
                echo_info(f"Updating node group: {ng_name} to version: {to_update}")
                update_nodegroup(cluster_name, ng_name, to_update, region)
                echo_success(f"Updated node group: {ng_name} to version: {to_update}")
                self.queue.task_done()
            elif typse == "selfmanaged":
                echo_info(f"Updating node group: {ng_name} to version: {to_update}")
                actual_update(
                    cluster_name=cluster_name,
                    asg_iter=ng_name,
                    to_update=to_update,
                    region=region,
                    max_retry=max_retry,
                    forced=forced,
                )
                echo_success(f"Updated node group: {ng_name} to version: {to_update}")
                self.queue.task_done()


def actual_update(cluster_name, asg_iter, to_update, region, max_retry, forced):
    """Perform the update."""
    instance_type, image_to_search = get_ami_name(cluster_name, asg_iter, region)
    echo_info(f"The Image Type Detected = {instance_type}")

    if instance_type == "NAN":
        return False
    if isinstance(image_to_search, str) and "Windows_Server" in image_to_search:
        image_to_search = image_to_search[:46]
    latest_ami = get_latest_ami(to_update, instance_type, image_to_search, region)
    echo_info(f"The Latest AMI Recommended = {latest_ami}")

    if get_outdated_asg(asg_iter, latest_ami, region):
        add_autoscaling(asg_iter, latest_ami, region)
        echo_info(f"New Launch Configuration Added to = {asg_iter} With EKS AMI = {latest_ami}")

    outdated_instances = outdated_lt(asg_iter, region)
    if not outdated_instances:
        return True

    try:
        terminated_ids = []
        echo_info(f"The Outdate Instance Found Are = {outdated_instances}")
        for instance in outdated_instances:
            before_count = get_num_of_instances(asg_iter, terminated_ids, region)
            echo_info(f"Total Instance count = {before_count}")
            add_time = datetime.datetime.now(datetime.timezone.utc)

            if abs(before_count - len(outdated_instances)) != len(outdated_instances):
                add_node(asg_iter, region)
                time.sleep(45)
                latest_instance = get_latest_instance(asg_name=asg_iter, add_time=add_time, region=region)
                echo_info(f"The Instance Created = {latest_instance} and waiting for it to be ready")
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
                    echo_error("404 instance is not corresponded to particular node group")
                    raise Exception("404 instance is not corresponded to particular node group")

            echo_info(f"Unscheduling the worker node = {old_pod_id}")

            unschedule_old_nodes(cluster_name=cluster_name, node_name=old_pod_id, region=region)
            echo_info(f"The node: {old_pod_id} has been unscheduled! Worker Node Draining...")
            drain_nodes(cluster_name=cluster_name, node_name=old_pod_id, forced=forced, region=region)
            echo_info(f"The worker node has been drained! Deleting worker Node Started = {old_pod_id}")
            delete_node(cluster_name=cluster_name, node_name=old_pod_id, region=region)
            echo_info(f"The worker node: {old_pod_id} has been deleted. Terminating Worker Node: {instance}...")
            worker_terminate(instance, region=region)
            terminated_ids.append(instance)
            echo_success(f"The worker node instance: {instance} has been terminated!")
        return True
    except Exception as e:
        echo_error(f"Error encountered during actual update! Exception: {e}")
        raise e
