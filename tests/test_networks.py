"""wall-scan --local: finding the directly attached networks in /proc/net/route.

The detection tests read saved routing tables only. Nothing here scans a real
network: on a CI runner, --local would scan the cloud provider's network.
"""

import ipaddress
import json
import sys
from pathlib import Path

import pytest

from wall_scan import cli, networks

VM_ROUTES = str(Path(__file__).parent / "fixtures" / "proc-net-route-vm.txt")
HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"


def route_line(interface, network, gateway="0.0.0.0", flags=0x1):
    """One line of /proc/net/route, addresses in the kernel's little-endian hex."""
    net = ipaddress.IPv4Network(network)

    def hex_le(address):
        return int.from_bytes(ipaddress.IPv4Address(address).packed, "little")

    return (
        f"{interface}\t{hex_le(net.network_address):08X}\t{hex_le(gateway):08X}\t{flags:04X}"
        f"\t0\t0\t0\t{hex_le(net.netmask):08X}\t0\t0\t0\n"
    )


def nets(*cidrs):
    return [ipaddress.IPv4Network(c) for c in cidrs]


# --- detection ---


def test_the_lab_vm():
    """The real routing table of the lab VM: NAT, host-only, Docker networks."""
    found, skipped = networks.local_networks(route_file=VM_ROUTES)

    assert found == nets("10.0.2.0/24", "192.168.56.0/24")
    reasons = {(str(route.network), reason) for route, reason in skipped}
    assert ("0.0.0.0/0", "reached through a router") in reasons  # default route
    assert ("10.0.2.2/32", "single host") in reasons
    assert ("172.17.0.0/16", "virtual interface (Docker, VPN, ...)") in reasons  # docker0
    assert ("172.18.0.0/16", "virtual interface (Docker, VPN, ...)") in reasons  # br-...


def test_excluding_an_interface():
    found, skipped = networks.local_networks({"enp0s3"}, route_file=VM_ROUTES)

    assert found == nets("192.168.56.0/24")
    assert ("enp0s3", "interface excluded") in {(r.interface, why) for r, why in skipped}


@pytest.mark.parametrize(
    "line, reason",
    [
        (route_line("tun0", "10.8.0.0/24"), "virtual interface (Docker, VPN, ...)"),
        (route_line("wg0", "10.10.0.0/24"), "virtual interface (Docker, VPN, ...)"),
        (route_line("eth0", "8.8.8.0/24"), "not a private network"),
        (route_line("eth0", "10.0.0.0/8"), "larger than a /16"),
        (route_line("eth0", "169.254.0.0/16"), "link-local"),
        (route_line("eth0", "192.168.9.0/24", flags=0x0), "route is down"),
        (
            route_line("eth0", "192.168.9.0/24", gateway="192.168.1.1", flags=0x3),
            "reached through a router",
        ),
    ],
    ids=["vpn-tun", "wireguard", "public", "too-large", "link-local", "down", "via-router"],
)
def test_networks_that_are_never_scanned(tmp_path, line, reason):
    routes = tmp_path / "route"
    routes.write_text(HEADER + line + route_line("eth0", "192.168.1.0/24"))

    found, skipped = networks.local_networks(route_file=str(routes))

    assert found == nets("192.168.1.0/24")
    assert [why for _, why in skipped] == [reason]


def test_same_network_on_two_interfaces_is_scanned_once(tmp_path):
    routes = tmp_path / "route"
    routes.write_text(
        HEADER + route_line("eth0", "192.168.1.0/24") + route_line("eth1", "192.168.1.0/24")
    )

    assert networks.local_networks(route_file=str(routes))[0] == nets("192.168.1.0/24")


def test_missing_routing_table(tmp_path):
    with pytest.raises(networks.DetectionError, match="cannot read the routing table"):
        networks.local_networks(route_file=str(tmp_path / "missing"))


@pytest.mark.skipif(sys.platform != "linux", reason="/proc/net/route exists on Linux only")
def test_real_routing_table_can_be_read():
    # Reading only: whatever the runner's network is, it is not scanned.
    found, skipped = networks.local_networks()
    assert all(network.is_private for network in found)


# --- command line ---


@pytest.fixture
def vm_routes(monkeypatch):
    monkeypatch.setattr(networks, "ROUTE_FILE", VM_ROUTES)


@pytest.fixture
def fake_nmap(monkeypatch, nmap_xml):
    """Answer every nmap call with an empty scan; collect the commands."""
    calls = []

    def fake_run(command, timeout_s):
        calls.append(command)
        return nmap_xml("real-localhost-down.xml")

    monkeypatch.setattr(cli.nmap, "run", fake_run)
    return calls


def invoke(capsys, *argv):
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_local_scans_the_detected_networks(capsys, vm_routes, fake_nmap, validator):
    code, doc = invoke(capsys, "--local", "--no-ports", "--privileged")

    validator.validate(doc)
    assert code == 0
    assert doc["params"]["targets"] == ["10.0.2.0/24", "192.168.56.0/24"]
    assert fake_nmap[0][-2:] == ["10.0.2.0/24", "192.168.56.0/24"]


def test_local_with_typed_targets_and_an_excluded_interface(capsys, vm_routes, fake_nmap):
    code, doc = invoke(
        capsys, "192.168.56.0/24", "10.20.0.5", "--local", "--exclude-interface", "enp0s3"
    )

    assert code == 0
    # Typed targets first, then detected networks not already given.
    assert doc["params"]["targets"] == ["192.168.56.0/24", "10.20.0.5"]


def test_skipped_networks_are_logged_with_verbose(capsys, vm_routes, fake_nmap, caplog):
    caplog.set_level("INFO", logger="wall-scan")

    invoke(capsys, "--local", "-v")

    assert "not scanning 172.17.0.0/16 on docker0: virtual interface" in caplog.text


@pytest.mark.parametrize(
    "argv, message",
    [
        ([], "give at least one TARGET, or --local"),
        (["192.168.1.0/24", "--exclude-interface", "eth0"], "only applies to --local"),
        (
            ["--local", "--exclude-interface", "enp0s3", "--exclude-interface", "enp0s8"],
            "found no network to scan",
        ),
    ],
    ids=["nothing-to-scan", "exclude-without-local", "everything-excluded"],
)
def test_local_argument_errors(capsys, vm_routes, fake_nmap, argv, message):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err
    assert fake_nmap == []


def test_local_without_a_routing_table(capsys, monkeypatch, tmp_path, fake_nmap):
    monkeypatch.setattr(networks, "ROUTE_FILE", str(tmp_path / "missing"))

    with pytest.raises(SystemExit) as exc:
        cli.main(["--local"])

    assert exc.value.code == 2
    assert "it needs Linux" in capsys.readouterr().err


# --- how each scanned network is reached (result.networks) ---

# The lab VM after a bridged adapter was added: NAT on enp0s3 (default route,
# metric 100), the LAN on enp0s9 (a second default route via the LAN's router,
# metric 200) and host-only on enp0s8.
VM_BRIDGED = str(Path(__file__).parent / "fixtures" / "proc-net-route-vm-bridged.txt")
VM_ADDRESSES = {"10.180.103.0/24": "10.180.103.124", "192.168.56.0/24": "192.168.56.10"}


@pytest.fixture
def vm_addresses(monkeypatch):
    monkeypatch.setattr(networks, "source_address", lambda net: VM_ADDRESSES.get(str(net)))


@pytest.mark.parametrize(
    "network, attached, interface, gateway",
    [
        ("10.180.103.0/24", True, "enp0s9", "10.180.103.140"),
        ("192.168.56.0/24", True, "enp0s8", None),
        ("10.0.2.0/24", True, "enp0s3", "10.0.2.2"),
        ("10.20.0.0/24", False, "enp0s3", "10.0.2.2"),
    ],
    ids=["lan-router-on-second-default", "host-only-no-router", "nat", "remote-lowest-metric"],
)
def test_how_the_lab_vm_reaches_each_network(vm_addresses, network, attached, interface, gateway):
    entry = networks.describe(ipaddress.IPv4Network(network), networks.read_routes(VM_BRIDGED))

    assert entry == {
        "network": network,
        "attached": attached,
        "interface": interface,
        "address": VM_ADDRESSES.get(network),
        "gateway": gateway,
    }


def test_a_default_route_without_a_gateway_attaches_nothing(tmp_path, vm_addresses):
    routes = tmp_path / "route"
    routes.write_text(HEADER + route_line("ppp0", "0.0.0.0/0") + route_line("eth0", "10.1.0.0/24"))

    entry = networks.describe(ipaddress.IPv4Network("10.20.0.0/24"), networks.read_routes(routes))

    assert (entry["attached"], entry["interface"], entry["gateway"]) == (False, "ppp0", None)


def test_no_route_at_all(vm_addresses):
    entry = networks.describe(ipaddress.IPv4Network("10.20.0.0/24"), [])

    assert (entry["attached"], entry["interface"], entry["gateway"]) == (False, None, None)


def test_without_a_routing_table_only_the_address_is_known(vm_addresses):
    entry = networks.describe(ipaddress.IPv4Network("10.180.103.0/24"), None)

    assert entry == {"network": "10.180.103.0/24", "attached": None, "interface": None,
                     "address": "10.180.103.124", "gateway": None}  # fmt: skip


def test_source_address_sends_nothing_and_needs_an_address_inside():
    # Connecting a UDP socket only asks the routing table; these work offline too.
    assert networks.source_address(ipaddress.IPv4Network("127.0.0.0/8")) == "127.0.0.1"
    assert networks.source_address(ipaddress.IPv4Network("192.0.2.0/24")) is None  # TEST-NET-1


def test_networks_in_the_result(capsys, monkeypatch, fake_nmap, vm_addresses, validator):
    monkeypatch.setattr(networks, "ROUTE_FILE", VM_BRIDGED)

    code, doc = invoke(capsys, "--local", "--exclude-interface", "enp0s3", "10.180.103.5")

    validator.validate(doc)
    assert code == 0
    assert doc["params"]["targets"] == ["10.180.103.5", "10.180.103.0/24", "192.168.56.0/24"]
    assert doc["result"]["networks"] == [  # the single address has no entry
        {"network": "10.180.103.0/24", "attached": True, "interface": "enp0s9",
         "address": "10.180.103.124", "gateway": "10.180.103.140"},
        {"network": "192.168.56.0/24", "attached": True, "interface": "enp0s8",
         "address": "192.168.56.10", "gateway": None},
    ]  # fmt: skip


def test_networks_without_a_routing_table(capsys, monkeypatch, tmp_path, fake_nmap, validator):
    monkeypatch.setattr(networks, "ROUTE_FILE", str(tmp_path / "missing"))  # e.g. Windows
    monkeypatch.setattr(networks, "source_address", lambda net: None)

    code, doc = invoke(capsys, "192.168.1.0/24")

    validator.validate(doc)
    assert code == 0  # the scan itself is not affected
    assert doc["result"]["networks"][0]["attached"] is None
