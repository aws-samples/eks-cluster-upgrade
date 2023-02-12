"""Handle CLI specific logic and module definitions."""
from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

import boto3

from eksupgrade import __version__
from eksupgrade.starter import main

logger = logging.getLogger(__name__)


def entry(args: Optional[List[str]] = None) -> None:
    """Handle the CLI entrypoint argument parsing."""
    # If no arguments are provided directly to the function, default to input.
    if not args:
        args = sys.argv[1:]

    example_text = """
example:

            eksupgrade name_of_cluster new_version region


Force pod eviction when you have PDB (Pod Disruption Budget):

    -> eksupgrade cluster_name new_version aws_region --force

Skip VPC CNI upgrade:

    -> eksupgrade cluster_name new_version aws_region --pass_vpc

Skip upgrade workflow:

    -> eksupgrade cluster_name new_version aws_region --preflight

Set log level to console (default to INFO):

    -> eksupgrade cluster_name new_version aws_region --log-level debug

Display the eksupgrade version:

    -> eksupgrade --version

"""

    regions_list: List[str] = get_eks_supported_regions()

    parser = argparse.ArgumentParser(
        description="Eks Cluster OneClick Upgrade",
        epilog=example_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("name", help="Cluster Name")
    parser.add_argument("version", help="new version which you want to update")
    parser.add_argument("region", help=f"Give the region name {', '.join(regions_list)}")
    parser.add_argument(
        "--pass_vpc", action="store_true", default=False, help="this --pass-vpc will skip the vpc cni upgrade"
    )
    parser.add_argument("--max_retry", default=2, type=int, help="you can specify max retry or else by default it is 2")
    parser.add_argument("--force", action="store_true", default=False, help="force pod eviction when you have pdb")
    # Eksctl will be added in future version
    parser.add_argument("--eksctl", action="store_true", default=False, help="eksctl upgrade process")
    parser.add_argument("--preflight", action="store_true", default=False, help="Run preflight check without upgrade")
    parser.add_argument("--email", default=False, help="Email for sharing the preflight report")
    parser.add_argument(
        "--parallel", action="store_true", default=False, help="Parllel Upgrade all node groups together "
    )
    parser.add_argument(
        "--log-level", default="INFO", help="The log level to be displayed in the console. Default to: INFO"
    )
    parser.add_argument("--version", action="version", version=f"eksupgrade {__version__}")
    parsed_arguments = parser.parse_args(args)
    logging.basicConfig(level=parsed_arguments.log_level.upper())
    main(parsed_arguments)


def get_eks_supported_regions() -> List[str]:
    """Retrieve the active regions supporting EKS across aws, aws-cn and aws-us-gov partitions"""
    session = boto3.session.Session()
    partition_list: List[str] = ["aws", "aws-cn", "aws-us-gov"]
    regions_list: List[str] = []
    for partition in partition_list:
        regions_list.extend(session.get_available_regions("eks", partition))
    return regions_list


if __name__ == "__main__":  # pragma: no cover
    entry()
