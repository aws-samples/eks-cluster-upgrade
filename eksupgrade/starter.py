import datetime
import queue
import threading
import time

from .src.boto_aws import (
    add_node,
    addAutoScaling,
    get_Asgs,
    get_latest_instance,
    get_num_of_instances,
    get_outdated_Asg,
    is_cluster_exists,
    outdated_lt,
    status_of_cluster,
    update_cluster,
    wait_for_ready,
    worker_terminate,
)
from .src.eks_get_image_type import get_ami_name
from .src.eksctlfinal import eksctl_execute
from .src.ekslogs import logs_pusher
from .src.k8s_client import (
    clus_auto_enable_disable,
    delete_node,
    drain_nodes,
    find_node,
    is_cluster_auto_scaler_present,
    unschedule_old_nodes,
    update_addons,
)
from .src.latest_ami import get_latestami
from .src.preflight_module import pre_flight_checks
from .src.self_managed import Update_nodeGroup, filter_node_groups, get_asg_node_groups, get_node_groups

queue = queue.Queue()


class StatsWorker(threading.Thread):
    def __init__(self, queue, id):
        threading.Thread.__init__(self)
        self.queue = queue
        self.id = id

    def run(self):
        while self.queue.not_empty:
            cluster_name, ng_name, to_update, regionName, max_retry, forced, typse = self.queue.get()
            if typse == "managed":
                start = time.time()
                logs_pusher(
                    regionName=regionName,
                    cluster_name=cluster_name,
                    msg="Updating Node Group {ng} To version {versi}".format(ng=ng_name, versi=to_update),
                )
                Update_nodeGroup(cluster_name, ng_name, to_update, regionName)
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                print(
                    "Updated Node Group {ng} To version {versi} ".format(ng=ng_name, versi=to_update),
                    "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
                )
                logs_pusher(
                    regionName=regionName,
                    cluster_name=cluster_name,
                    msg="Updated Node Group {ng} To version {versi}".format(ng=ng_name, versi=to_update),
                )

                self.queue.task_done()
            elif typse == "selfmanaged":
                start = time.time()
                logs_pusher(
                    regionName=regionName,
                    cluster_name=cluster_name,
                    msg="Updating Node Group {ng} To version {versi}".format(ng=ng_name, versi=to_update),
                )
                actual_update(
                    cluster_name=cluster_name,
                    asg_iter=ng_name,
                    to_update=to_update,
                    regionName=regionName,
                    max_retry=max_retry,
                    forced=forced,
                )
                end = time.time()
                hours, rem = divmod(end - start, 3600)
                minutes, seconds = divmod(rem, 60)
                print(
                    "Updated Node Group {ng} To version {versi} ".format(ng=ng_name, versi=to_update),
                    "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
                )
                logs_pusher(
                    regionName=regionName,
                    cluster_name=cluster_name,
                    msg="Updated Node Group {ng} To version {versi}".format(ng=ng_name, versi=to_update),
                )

                self.queue.task_done()


def actual_update(cluster_name, asg_iter, to_update, regionName, max_retry, forced):
    presentversion = "1.1 eks update"
    instance_type, image_to_search = get_ami_name(cluster_name, asg_iter, presentversion, regionName)
    print("The Image Type Detected = ", instance_type)
    if instance_type == "NAN":
        return False
    if isinstance(image_to_search, str) and "Windows_Server" in image_to_search:
        image_to_search = image_to_search[:46]
    latest_ami = get_latestami(to_update, instance_type, image_to_search, regionName)
    print("The Latest AMI Recommended = {image}".format(image=latest_ami))
    logs_pusher(
        regionName=regionName, cluster_name=cluster_name, msg="The Latest AMI Image = {image}".format(image=latest_ami)
    )
    if get_outdated_Asg(asg_iter, latest_ami, regionName):
        addAutoScaling(asg_iter, latest_ami, regionName)
        print("New Launch Configuration Added to = {ast} With EKS AMI = {ami}".format(ast=asg_iter, ami=latest_ami))

    outdated_instances = outdated_lt(asg_iter, regionName)
    if len(outdated_instances) == 0:
        return True
    try:
        terminated_ids = []
        logs_pusher(
            regionName=regionName,
            cluster_name=cluster_name,
            msg="The Outdate Instance Found Are = {instan}".format(instan=outdated_instances),
        )
        for instance in outdated_instances:
            befor_count = get_num_of_instances(asg_iter, terminated_ids, regionName)
            logs_pusher(
                regionName=regionName,
                cluster_name=cluster_name,
                msg="Total Instance count = {count}".format(count=befor_count),
            )
            add_time = datetime.datetime.now(datetime.timezone.utc)
            if abs(befor_count - len(outdated_instances)) != len(outdated_instances):
                add_node(asg_iter, regionName)
                time.sleep(45)
                latest_instance = get_latest_instance(asg_name=asg_iter, add_time=add_time, regionName=regionName)
                logs_pusher(
                    regionName=regionName,
                    cluster_name=cluster_name,
                    msg="The Instance Created = {instan}".format(instan=latest_instance),
                )
                print(latest_instance, "is Created and waiting for it to be ready")
                time.sleep(30)
                wait_for_ready(latest_instance, regionName)

            old_pod_id = find_node(
                cluster_name=cluster_name, instance_id=instance, operation="find", region_name=regionName
            )
            if old_pod_id != "NAN":
                retry = 0
                flag = 0
                while retry <= max_retry:
                    if (
                        not find_node(
                            cluster_name=cluster_name, instance_id=instance, operation="find", region_name=regionName
                        )
                        == "NAN"
                    ):
                        flag = 1
                        retry += 1
                        time.sleep(10)
                if flag == 0:
                    worker_terminate(instance, regionName=regionName)
                    raise Exception("404 instance is not corresponded to particular node group")

            print("Unshceduling The worker Node ={wn} ".format(wn=old_pod_id))

            unschedule_old_nodes(ClusterName=cluster_name, Nodename=old_pod_id, regionName=regionName)
            logs_pusher(
                regionName=regionName,
                cluster_name=cluster_name,
                msg="The Node is Unscheduled = {instan}".format(instan=old_pod_id),
            )
            print("Worker Node Drained = {instan}".format(instan=old_pod_id))
            drain_nodes(cluster_name=cluster_name, Nodename=old_pod_id, forced=forced, regionName=regionName)
            logs_pusher(
                regionName=regionName,
                cluster_name=cluster_name,
                msg="The Worker Node is Drained = {instan}".format(instan=old_pod_id),
            )

            print("Deleting worker Node Started ={op} ".format(op=old_pod_id))
            delete_node(cluster_name=cluster_name, NodeName=old_pod_id, regionName=regionName)
            logs_pusher(
                regionName=regionName,
                cluster_name=cluster_name,
                msg="The Worker Node is Deleted = {instan}".format(instan=old_pod_id),
            )
            print("Terminating Worker Node {wn}".format(wn=instance))
            worker_terminate(instance, regionName=regionName)
            terminated_ids.append(instance)
            logs_pusher(
                regionName=regionName,
                cluster_name=cluster_name,
                msg="The Worker Node instance is Terminated = {instan}".format(instan=instance),
            )
        return True
    except Exception as e:
        raise (e)


def main(args):
    try:
        cluster_name = args.name
        to_update = args.version
        pass_vpc = args.pass_vpc
        max_retry = args.max_retry
        regionName = args.region
        presentversion = "NAN"
        isPresent = False
        forced = args.force
        paralleled = args.parallel
        preflight = args.preflight

        if args.eksctl:
            quit("updating using EKSCTL is still under testing will be launched soon")

        """ Preflight Logic """
        if not (pre_flight_checks(True, cluster_name, regionName, args.pass_vpc, args.version, args.email, args.force)):
            print("Pre flight check for cluster " + cluster_name + " failed")
            quit()
        else:
            print("Pre flight check for the cluster " + cluster_name + " succeded")
        if preflight:
            quit()

        # upgrade Logic
        logs_pusher(regionName=regionName, cluster_name=cluster_name, msg="The Cluster Upgrade Process has Started")
        if (
            is_cluster_exists(Clustname=cluster_name, regionName=regionName) == "ACTIVE"
            or is_cluster_exists(Clustname=cluster_name, regionName=regionName) == "UPDATING"
        ):
            presentversion = status_of_cluster(cluster_name, regionName)[1]
            logs_pusher(
                regionName=regionName,
                cluster_name=cluster_name,
                msg="The Current Version of the Cluster is Detected = {version} ".format(version=presentversion),
            )
        else:
            raise Exception("Cluster is Not Active")

        # Checking Cluster is Active or Not Befor Making an Update
        start = time.time()
        if is_cluster_exists(Clustname=cluster_name, regionName=regionName) == "ACTIVE":
            # if eksctl flag is enabled.
            if args.eksctl != False:
                print("updating using EKSCTL")
                eksctl_execute(args)
                print("Pre flight check for the upgraded cluster")
                if not (pre_flight_checks(preflight, cluster_name, regionName, pass_vpc=pass_vpc)):
                    print("Pre flight check for cluster " + cluster_name + " failed after it upgraded")
                else:
                    print("After update check for cluster completed successfully")
                quit()
            update_cluster(Clustname=cluster_name, Version=to_update, regionName=regionName)
        time.sleep(5)

        """ Making Sure the Cluster is Updated"""
        if (
            status_of_cluster(cluster_name, regionName)[1] != to_update
            or status_of_cluster(cluster_name, regionName)[0] != "ACTIVE"
        ):
            update_cluster(cluster_name, to_update, regionName)

        """ finding the managed autoscaling groups """

        end = time.time()
        hours, rem = divmod(end - start, 3600)
        minutes, seconds = divmod(rem, 60)
        print(
            "The Time Taken For the Cluster to Upgrade ",
            "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
        )
        logs_pusher(
            regionName=regionName,
            cluster_name=cluster_name,
            msg="Time Taken For the Cluster to Upgrade "
            + " {:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
        )

        finding_manged = get_asg_node_groups(cluster_name, regionName)

        logs_pusher(
            regionName=regionName,
            cluster_name=cluster_name,
            msg="The Manged Node Groups Found are " + ",".join(finding_manged),
        )

        asg_list = get_Asgs(cluster_name, regionName)

        logs_pusher(regionName=regionName, cluster_name=cluster_name, msg="The Asg's Found Are " + ",".join(asg_list))

        """ removing selfmanged from manged so that we dont update them again"""

        asg_list_self_managed = list(set(asg_list) - set(finding_manged))

        """ addons update """

        finding_manged_nodes_names = get_node_groups(Clustername=cluster_name, regionName=regionName)

        print(" The add-ons Update has been initiated.... ")
        start_time = time.time()
        start = time.time()
        logs_pusher(
            regionName=regionName, cluster_name=cluster_name, msg="The Addons Upgrade Started At " + str(start_time)
        )

        update_addons(cluster_name=cluster_name, version=to_update, vpc_pass=pass_vpc, region_name=regionName)
        end = time.time()
        hours, rem = divmod(end - start, 3600)
        minutes, seconds = divmod(rem, 60)

        print("The Taken For the Addons Upgrade ", "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds))
        logs_pusher(
            regionName=regionName,
            cluster_name=cluster_name,
            msg="The Taken For the Addons Upgrade "
            + "{:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), seconds),
        )

        """ finding managed node groups with filter"""
        finding_manged_nodes = filter_node_groups(
            cluster_name=cluster_name,
            node_list=finding_manged_nodes_names,
            latest_version=to_update,
            regionName=regionName,
        )
        if len(finding_manged) > 0:
            print("The OutDated Managed Node Groups = ", finding_manged)
        else:
            print("No OutDated Managed Node Groups Found ")

        replicas_value = 0

        """ checking auto scaler present and the value associated from it """

        isPresent, replicas_value = is_cluster_auto_scaler_present(ClusterName=cluster_name, regionName=regionName)

        if isPresent:
            clus_auto_enable_disable(
                ClusterName=cluster_name, type="pause", mx_val=replicas_value, regionName=regionName
            )
            logs_pusher(regionName=regionName, cluster_name=cluster_name, msg="Paused Cluster AutoScaler")

            print("Paused the Cluster AutoScaler")
        else:
            print("No Cluster AutoScaler is Found")
        if paralleled:
            for x in range(20):
                worker = StatsWorker(queue, x)
                worker.setDaemon(True)
                worker.start()

        if len(finding_manged_nodes) != 0:
            for ng_name in finding_manged_nodes:
                start = time.time()
                print("Updating the Node Group = {ng} To version = {versi}".format(ng=ng_name, versi=to_update))
                if paralleled:
                    queue.put([cluster_name, ng_name, to_update, regionName, max_retry, forced, "managed"])
                else:
                    Update_nodeGroup(cluster_name, ng_name, to_update, regionName)
        if len(asg_list_self_managed) != 0:
            for asg_iter in asg_list_self_managed:
                if paralleled:
                    queue.put([cluster_name, asg_iter, to_update, regionName, max_retry, forced, "selfmanaged"])
                else:
                    actual_update(cluster_name, asg_iter, to_update, regionName, max_retry, forced)
        if paralleled:
            queue.join()
        if isPresent:
            clus_auto_enable_disable(
                ClusterName=cluster_name, type="start", mx_val=replicas_value, regionName=regionName
            )
            print("Cluster Autoscaler is Enabled Again")
            logs_pusher(regionName=regionName, cluster_name=cluster_name, msg="Cluster Autoscaler is Enabled Again")
        print(" EKS Cluster {Clustname} UPDATED TO {ver}".format(Clustname=cluster_name, ver=to_update))
        logs_pusher(
            regionName=regionName,
            cluster_name=cluster_name,
            msg=" EKS Cluster {Clustname} UPDATED TO {ver}".format(Clustname=cluster_name, ver=to_update),
        )
        print("Post flight check for the upgraded cluster")
        if not (pre_flight_checks(False, cluster_name, regionName, args.pass_vpc, email=args.email)):
            print("Post flight check for cluster " + cluster_name + " failed after it upgraded")
        else:
            print("After update check for cluster completed successfully")

    except Exception as e:
        if isPresent:
            try:
                clus_auto_enable_disable(
                    ClusterName=cluster_name, type="start", mx_val=replicas_value, regionName=regionName
                )
                print("Cluster Autoscaler is Enabled Again")
                logs_pusher(regionName=regionName, cluster_name=cluster_name, msg="Cluster Autoscaler is Enabled Again")
            except Exception as e:
                print("Enter AutoScaler Manullay")
        logs_pusher(
            regionName=regionName,
            cluster_name=cluster_name,
            msg="The Cluster Upgrade Failed Due To = {err}".format(err=e),
        )
        print(e)
