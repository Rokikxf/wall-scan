"""The routing table: networks to scan with --local, and how each scanned network is reached.

Reads the kernel's routing table, /proc/net/route (Linux; no extra packages).
A route that is up and has no gateway is a network this machine sits on. In
Docker, the scanner must use the host's network (network_mode: host) to see the
host's routes.

Some attached networks are never scanned automatically:
- Docker, VPN and other virtual interfaces (docker0, br-*, veth*, tun*, wg*, ...):
  scanning through a VPN would scan someone else's network;
- single-host routes (/32), link-local and public networks;
- networks larger than a /16, the same limit as for typed targets.

describe() reports, for every scanned network, whether it is attached, the
interface, this machine's own address on it and its gateway (result.networks).
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
    gateway: ipaddress.IPv4Address | None = None
    metric: int = 0


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
        interface, destination, gateway, flags, _refcnt, _use, metric, mask = fields[:8]
        network = ipaddress.IPv4Network((_address(destination), _address(mask)), strict=False)
        via = ipaddress.IPv4Address(_address(gateway))
        routes.append(
            Route(interface, network, int(flags, 16), via if int(via) else None, int(metric))
        )
    return routes


def read_routes(route_file: str | None = None) -> list[Route]:
    try:
        with open(route_file or ROUTE_FILE, encoding="ascii") as file:
            return parse_routes(file.read())
    except OSError as exc:
        raise DetectionError(f"cannot read the routing table: {exc}") from None


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
    found, skipped = set(), []
    for route in read_routes(route_file):
        reason = skip_reason(route, exclude)
        if reason is None:
            found.add(route.network)
        else:
            skipped.append((route, reason))
    return sorted(found), skipped


def source_address(network: ipaddress.IPv4Network) -> str | None:
    """This machine's own address in the network, or None if it has none there.

    Connecting a UDP socket sends nothing: it only makes the operating system pick
    the outgoing interface and source address for that destination.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((str(network.network_address + 1), 9))
        address = ipaddress.IPv4Address(probe.getsockname()[0])
    except OSError:
        return None
    finally:
        probe.close()
    return str(address) if address in network else None


def best_route(network: ipaddress.IPv4Network, routes: list[Route]) -> Route | None:
    """The route the kernel would use for the network: longest prefix, then lowest metric."""
    covering = [r for r in routes if r.flags & RTF_UP and network.subnet_of(r.network)]
    return max(covering, key=lambda r: (r.network.prefixlen, -r.metric), default=None)


def describe(network: ipaddress.IPv4Network, routes: list[Route] | None) -> dict:
    """The result.networks entry for one scanned network (see schema.json).

    routes is None when the routing table could not be read: then only the own
    address is known.
    """
    entry = {
        "network": str(network),
        "attached": None,
        "interface": None,
        "address": source_address(network),
        "gateway": None,
    }
    if routes is None:
        return entry
    route = best_route(network, routes)
    # A default route leads everywhere else, even without a gateway ("default dev
    # ppp0"): it never makes a network attached.
    entry["attached"] = (
        route is not None and not route.flags & RTF_GATEWAY and route.network.prefixlen > 0
    )
    if route is None:  # no route at all, not even a default one
        return entry
    entry["interface"] = route.interface
    if entry["attached"]:
        # The network's own router: a default route out of this interface, through
        # an address inside the network.
        defaults = [
            r
            for r in routes
            if r.network.prefixlen == 0
            and r.flags & RTF_UP
            and r.interface == route.interface
            and r.gateway is not None  # "default dev ppp0" has none
            and r.gateway in network
        ]
        if defaults:
            entry["gateway"] = str(min(defaults, key=lambda r: r.metric).gateway)
    elif route.gateway is not None:
        entry["gateway"] = str(route.gateway)
    return entry
