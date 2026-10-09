"""Command-line entry point: arguments in, one JSON document out.

Every run that gets past argument parsing prints exactly one JSON document,
even when something unexpected goes wrong.
"""

import argparse
import ipaddress
import logging
import os
import re
import sys
from typing import Any

from wall_scan import __version__, networks, nmap
from wall_scan.envelope import Run, emit

TOOL_NAME = "wall-scan"
DEFAULT_PORTS = "21,22,23,53,80,135,139,443,445,515,631,3389,5900,8080,9100"
LARGEST_PREFIX = 16  # refuse ranges bigger than a /16 (65,536 addresses)
PORT_LIST = re.compile(r"[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*")
log = logging.getLogger(TOOL_NAME)


def target(value: str) -> ipaddress.IPv4Network:
    """argparse type: an IPv4 address or CIDR range of at most a /16."""
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IPv4 address or CIDR range: {value!r}") from None
    if network.prefixlen < LARGEST_PREFIX:
        raise argparse.ArgumentTypeError(
            f"{value} is larger than a /{LARGEST_PREFIX}; scan smaller ranges"
        )
    return network


def port_list(value: str) -> str:
    """argparse type: ports and ranges for nmap -p, e.g. 22,80,8000-8100."""
    if not PORT_LIST.fullmatch(value):
        raise argparse.ArgumentTypeError(f"not a port list like 22,80,8000-8100: {value!r}")
    for part in value.split(","):
        low, _, high = part.partition("-")
        if not 1 <= int(low) <= int(high or low) <= 65535:
            raise argparse.ArgumentTypeError(f"invalid port or range: {part}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Discover devices on IPv4 networks with nmap and print them as JSON.",
        epilog="Only scan networks you own or have written permission to scan.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        type=target,
        metavar="TARGET",
        help="IPv4 address or CIDR range, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="also scan every private network this machine is directly attached to "
        "(Linux; Docker and VPN interfaces are skipped)",
    )
    parser.add_argument(
        "--exclude-interface",
        action="append",
        default=[],
        metavar="IFACE",
        help="with --local: do not scan the network on this interface (repeatable)",
    )
    ports = parser.add_mutually_exclusive_group()
    ports.add_argument(
        "--ports",
        type=port_list,
        default=DEFAULT_PORTS,
        metavar="LIST",
        help="TCP ports to check on each device (default: %(default)s)",
    )
    ports.add_argument(
        "--no-ports", action="store_true", help="only discover devices, do not scan ports"
    )
    parser.add_argument(
        "--privileged",
        action="store_true",
        help="nmap has raw-socket privileges (root or capabilities): enables ARP "
        "discovery, MAC addresses and vendors",
    )
    parser.add_argument(
        "--timeout-s",
        type=int,
        default=600,
        metavar="N",
        help="stop nmap after N seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="allow targets outside private address ranges",
    )
    parser.add_argument(
        "--nmap", default="nmap", metavar="PATH", help="nmap executable (default: %(default)s)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout_s < 1:
        parser.error("--timeout-s must be at least 1")
    if args.exclude_interface and not args.local:
        parser.error("--exclude-interface only applies to --local")
    if not args.targets and not args.local:
        parser.error("give at least one TARGET, or --local")
    public = [as_text(t) for t in args.targets if not t.is_private]
    if public and not args.allow_public:
        parser.error(
            f"not a private address range: {', '.join(public)} "
            "(use --allow-public only for networks you are allowed to scan)"
        )
    args.skipped_routes = []
    if args.local:
        add_local_networks(parser, args)
    return args


def add_local_networks(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Append the detected networks to args.targets, skipping ones already given."""
    try:
        found, args.skipped_routes = networks.local_networks(set(args.exclude_interface))
    except networks.DetectionError as exc:
        parser.error(f"--local: {exc} (it needs Linux)")
    if not found:
        skipped = "; ".join(
            f"{r.interface} {r.network}: {reason}" for r, reason in args.skipped_routes
        )
        parser.error(f"--local found no network to scan (skipped: {skipped or 'none'})")
    args.targets += [network for network in found if network not in args.targets]


def as_text(network: ipaddress.IPv4Network) -> str:
    """A single address without /32, a range in CIDR form."""
    return str(network.network_address) if network.prefixlen == 32 else str(network)


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def collect(args: argparse.Namespace, run: Run) -> dict[str, Any] | None:
    """Run nmap and return the result object, or record an error and return None."""
    params = run.params
    command = nmap.build_command(
        args.nmap, params["targets"], params["ports"], params["privileged"]
    )
    try:
        xml = nmap.run(command, params["timeout_s"])
        return nmap.parse(xml, ports_scanned=params["ports"] is not None)
    except nmap.ScanError as exc:
        run.error(exc.code, exc.message)
        return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(name)s: %(message)s",
    )
    for route, reason in args.skipped_routes:
        log.info("--local: not scanning %s on %s: %s", route.network, route.interface, reason)
    params = {
        "targets": [as_text(t) for t in args.targets],
        "ports": None if args.no_ports else args.ports,
        "privileged": args.privileged or running_as_root(),
        "timeout_s": args.timeout_s,
    }
    run = Run(TOOL_NAME, __version__, params)
    try:
        result = collect(args, run)
    except Exception as exc:
        log.exception("unexpected error")
        run.error("internal_error", f"{type(exc).__name__}: {exc}")
        result = None
    return emit(run.finish(result))
