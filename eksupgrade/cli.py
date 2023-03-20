"""Handle CLI specific logic and module definitions."""
from __future__ import annotations

import sys
from queue import Queue
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from eksupgrade import __version__
from eksupgrade.utils import confirm, echo_error, echo_info, echo_success, echo_warning, get_logger

from .exceptions import ClusterInactiveException
from .models.eks import Cluster
from .src.k8s_client import cluster_auto_enable_disable, is_cluster_auto_scaler_present
from .src.preflight_module import pre_flight_checks
from .starter import StatsWorker, actual_update

logger = get_logger(__name__)
app = typer.Typer(help="Automated Amazon EKS cluster upgrade CLI utility")
console = Console()


def version_callback(value: bool) -> None:
    """Handle the version callback."""
    if value:
        typer.secho(f"eksupgrade version: {__version__}", fg=typer.colors.BRIGHT_BLUE, bold=True)
        raise typer.Exit()


@app.command()
def main(
    cluster_name: str = typer.Argument(..., help="The name of the cluster to be upgraded"),
    cluster_version: str = typer.Argument(..., help="The target Kubernetes version to upgrade the cluster to"),
    region: str = typer.Argument(..., help="The AWS region where the target cluster resides"),
    max_retry: int = typer.Option(default=2, help="The most number of times to retry an upgrade"),
    force: bool = typer.Option(default=False, help="Force the upgrade (e.g. pod eviction with PDB)"),
    preflight: bool = typer.Option(default=False, help="Run pre-flight check without upgrade"),
    parallel: bool = typer.Option(default=False, help="Upgrade all nodegroups in parallel"),
    latest_addons: bool = typer.Option(
        default=False, help="Upgrade addons to the latest eligible version instead of default"
    ),
    disable_checks: bool = typer.Option(
        default=False, help="Disable the pre-flight and post-flight checks during upgrade scenarios"
    ),
    interactive: bool = typer.Option(default=True, help="If enabled, prompt the user for confirmations"),
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Display the current eksupgrade version"
    ),
) -> None:
    """Run eksupgrade against a target cluster."""
    queue = Queue()
    is_present: bool = False
    replicas_value: int = 0

    try:
        # Preflight Logic
        if not disable_checks:
            if not pre_flight_checks(
                preflight=True,
                cluster_name=cluster_name,
                region=region,
                update_version=cluster_version,
                force_upgrade=force,
            ):
                echo_error(
                    f"Pre-flight check for cluster {cluster_name} targeting version: {cluster_version} failed!",
                )
                sys.exit()
            else:
                echo_success(
                    f"Pre-flight check for the cluster {cluster_name} succeeded!",
                )
            if preflight:
                sys.exit()
        else:
            echo_warning("Checks disabled! Pre/post-flight checks not executing!")

        # Pull cluster details, populating the object for subsequent use throughout the upgrade.
        target_cluster: Cluster = Cluster.get(
            cluster_name=cluster_name, region=region, target_version=cluster_version, latest_addons=latest_addons
        )
        echo_info(
            f"Upgrading cluster: {cluster_name} from version: {target_cluster.version} to {target_cluster.target_version}...",
        )

        # Confirm whether or not to proceed following pre-flight checks.
        if interactive:
            confirm(
                f"Are you sure you want to proceed with the upgrade process against: {cluster_name}?",
            )

        if not target_cluster.available:
            echo_error("The cluster is not active!")
            raise ClusterInactiveException("The cluster is not active")

        echo_info(
            f"The current version of the cluster was detected as: {target_cluster.version}",
        )

        # Checking Cluster is Active or Not Before Making an Update
        if target_cluster.active:
            target_cluster.update_cluster(wait=True)
        else:
            echo_warning(
                f"The target EKS cluster: {target_cluster.name} isn't currently active - status: {target_cluster.status}",
            )
            target_cluster.wait_for_active()

        echo_info("Found the following Managed Nodegroups")
        for _mng_nodegroup_name in target_cluster.nodegroup_names:
            echo_info(f"\t* {_mng_nodegroup_name}")

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
            echo_info("Paused the Cluster AutoScaler")
        else:
            echo_info("No Cluster AutoScaler is Found")

        if parallel:
            for x in range(20):
                worker = StatsWorker(queue, x)
                worker.setDaemon(True)
                worker.start()

        if target_cluster.upgradable_managed_nodegroups:
            _mng_nodegroup_table = Table("Name", "Version")
            for item in target_cluster.upgradable_managed_nodegroups:
                _mng_nodegroup_table.add_row(item.name, item.version)
            echo_info("Outdated managed nodegroups:")
            console.print(_mng_nodegroup_table)
        else:
            echo_warning("No outdated managed nodegroups found!")

        target_cluster.upgrade_nodegroups(wait=not parallel)

        # TODO: Use custom_ami to update launch templates and re-roll self-managed nodes under ASGs.
        echo_info("Found the following Self-managed Nodegroups:")
        for asg_iter in asg_list_self_managed:
            echo_info(f"\t* {asg_iter}")
            if parallel:
                queue.put([cluster_name, asg_iter, cluster_version, region, max_retry, force, "selfmanaged"])
            else:
                actual_update(cluster_name, asg_iter, cluster_version, region, max_retry, force)

        if parallel:
            queue.join()

        if is_present:
            cluster_auto_enable_disable(
                cluster_name=cluster_name, operation="start", mx_val=replicas_value, region=region
            )
            echo_info("Cluster Autoscaler is Enabled Again")
        echo_info(f"EKS Cluster {cluster_name} UPDATED TO {cluster_version}")

        if not disable_checks:
            if not pre_flight_checks(preflight=False, cluster_name=cluster_name, region=region, force_upgrade=force):
                echo_error(
                    f"Post flight check for cluster {cluster_name} failed after it upgraded",
                )
            else:
                echo_success("After update check for cluster completed successfully")
        else:
            echo_warning("Post-flight check was disabled and didn't run.")
    except typer.Abort:
        echo_warning("Cluster upgrade aborted!")
    except Exception as error:
        if is_present:
            try:
                cluster_auto_enable_disable(
                    cluster_name=cluster_name, operation="start", mx_val=replicas_value, region=region
                )
                echo_info("Cluster Autoscaler is Enabled Again")
            except Exception as error2:
                echo_error(
                    f"Autoenable failed and must be done manually! Error: {error2}",
                )
        echo_error(f"Exception encountered! Error: {error}")


if __name__ == "__main__":  # pragma: no cover
    app(prog_name="eksupgrade")
