"""The IPv4 networks this machine is directly attached to, for wall-scan --local.

Reads the kernel's routing table, /proc/net/route (Linux; no extra packages).
A route that is up and has no gateway is a network this machine sits on. In
Docker, the scanner must use the host's network (network_mode: host) to see the
host's routes.

Some attached networks are never scanned automatically:
- Docker, VPN and other virtual interfaces (docker0, br-*, veth*, tun*, wg*, ...):
  scanning through a VPN would scan someone else's network;
- single-host routes (/32), link-local and public networks;
- networks larger than a /16, the same limit as for typed targets.
"""

import ipaddress
import socket
import struct
from dataclasses import dataclass

ROUTE_FILE = "/proc/net/route"
LARGEST_PREFIX = 16
VIRTUAL_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vnet",
    "tun",
    "tap",
    "wg",
    "zt",
    "tailscale",
    "cni",
    "flannel",
    "cali",
    "vxlan",
)
RTF_UP = 0x1
RTF_GATEWAY = 0x2


@dataclass(frozen=True)
class Route:
    interface: str
    network: ipaddress.IPv4Network
    flags: int


class DetectionError(Exception):
    """The routing table could not be read."""


def _address(hex_le: str) -> str:
    # /proc/net/route prints addresses as hex in the kernel's (little-endian) byte order.
    return socket.inet_ntoa(struct.pack("<L", int(hex_le, 16)))


def parse_routes(text: str) -> list[Route]:
    routes = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        interface, destination, _gateway, flags, *_, mask = fields[:8]
        network = ipaddress.IPv4Network((_address(destination), _address(mask)), strict=False)
        routes.append(Route(interface, network, int(flags, 16)))
    return routes


def skip_reason(route: Route, exclude: set[str]) -> str | None:
    """Why this route is not a network to scan, or None if it is one."""
    network = route.network
    if not route.flags & RTF_UP:
        return "route is down"
    if route.flags & RTF_GATEWAY:
        return "reached through a router"
    if route.interface in exclude:
        return "interface excluded"
    if route.interface.startswith(VIRTUAL_PREFIXES):
        return "virtual interface (Docker, VPN, ...)"
    if network.prefixlen == 32:
        return "single host"
    if network.is_link_local:
        return "link-local"
    if not network.is_private:
        return "not a private network"
    if network.prefixlen < LARGEST_PREFIX:
        return f"larger than a /{LARGEST_PREFIX}"
    return None


def local_networks(
    exclude: set[str] = frozenset(), route_file: str | None = None
) -> tuple[list[ipaddress.IPv4Network], list[tuple[Route, str]]]:
    """(networks to scan, sorted) and (skipped routes with the reason for each)."""
    try:
        with open(route_file or ROUTE_FILE, encoding="ascii") as file:
            routes = parse_routes(file.read())
    except OSError as exc:
        raise DetectionError(f"cannot read the routing table: {exc}") from None
    found, skipped = set(), []
    for route in routes:
        reason = skip_reason(route, exclude)
        if reason is None:
            found.add(route.network)
        else:
            skipped.append((route, reason))
    return sorted(found), skipped
