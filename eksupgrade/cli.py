"""Handle CLI specific logic and module definitions."""
from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

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

    regions_list: List[str] = [
        "af-south-1",
        "eu-north-1",
        "ap-south-1",
        "eu-west-3",
        "eu-west-2",
        "eu-south-1",
        "eu-west-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "me-central-1",
        "me-south-1",
        "ap-northeast-1",
        "sa-east-1",
        "ca-central-1",
        "ap-east-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "eu-central-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "us-gov-east-1",
        "us-gov-west-1",
    ]

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


if __name__ == "__main__":  # pragma: no cover
    entry()
