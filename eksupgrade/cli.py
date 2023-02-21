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

  eksupgrade <name> <version> <region>

Force pod eviction when you have PDB (Pod Disruption Budget):

  eksupgrade <name> <version> <region>n --force

Skip VPC CNI upgrade:

  eksupgrade <name> <version> <region> --pass_vpc

Skip upgrade workflow:

  eksupgrade <name> <version> <region> --preflight

Set log level to console (default to INFO):

  eksupgrade <name> <version> <region> --log-level debug

Display the eksupgrade version:

  eksupgrade --version
"""

    parser = argparse.ArgumentParser(
        description="Amazon EKS cluster upgrade",
        epilog=example_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("name", help="Cluster Name")
    parser.add_argument("version", help="new version which you want to update")
    parser.add_argument("region", help="The AWS region where the cluster resides")
    parser.add_argument(
        "--pass_vpc", action="store_true", default=False, help="this --pass-vpc will skip the vpc cni upgrade"
    )
    parser.add_argument("--max_retry", default=2, type=int, help="you can specify max retry or else by default it is 2")
    parser.add_argument("--force", action="store_true", default=False, help="force pod eviction when you have pdb")
    parser.add_argument("--preflight", action="store_true", default=False, help="Run pre-flight check without upgrade")
    parser.add_argument("--parallel", action="store_true", default=False, help="Upgrade all nodegroups in parallel")
    parser.add_argument(
        "--log-level", default="INFO", help="The log level to be displayed in the console. Default to: INFO"
    )
    parser.add_argument("--version", action="version", version=f"eksupgrade {__version__}")
    parsed_arguments = parser.parse_args(args)
    logging.basicConfig(level=parsed_arguments.log_level.upper())
    main(parsed_arguments)


if __name__ == "__main__":  # pragma: no cover
    entry()
