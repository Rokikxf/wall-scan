"""Building the nmap command and parsing nmap's XML output."""

import pytest

from wall_scan.nmap import ScanError, build_command, parse


def nmaprun(hosts: str, total: int = 256) -> bytes:
    """Minimal nmap XML around the given <host> elements."""
    return (
        f'<nmaprun scanner="nmap" version="7.94SVN">{hosts}'
        f'<runstats><finished exit="success"/><hosts total="{total}"/></runstats></nmaprun>'
    ).encode()


def host(ip: str, state: str = "up", extra: str = "") -> str:
    return (
        f'<host><status state="{state}" reason="arp-response"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>{extra}</host>'
    )


# --- command ---


def test_command_for_privileged_port_scan():
    assert build_command("nmap", ["192.168.1.0/24"], "22,80", privileged=True) == [
        "nmap", "-oX", "-", "-T4", "--privileged", "-p", "22,80", "192.168.1.0/24",
    ]  # fmt: skip


def test_command_for_unprivileged_discovery_only():
    assert build_command("/usr/bin/nmap", ["10.0.0.1", "10.0.1.0/24"], None, privileged=False) == [
        "/usr/bin/nmap", "-oX", "-", "-T4", "-sn", "10.0.0.1", "10.0.1.0/24",
    ]  # fmt: skip


# --- fixtures: hand-written LAN scans must produce the schema examples exactly ---


def nmap_part(document):
    """The result without networks, which comes from the routing table (see test_networks)."""
    return {key: value for key, value in document["result"].items() if key != "networks"}


def test_lan_port_scan_gives_the_ok_example(nmap_xml, example):
    assert parse(nmap_xml("lan-ports.xml"), ports_scanned=True) == nmap_part(example("ok.json"))


def test_lan_discovery_gives_the_discovery_only_example(nmap_xml, example):
    result = parse(nmap_xml("lan-discovery.xml"), ports_scanned=False)
    assert result == nmap_part(example("discovery-only.json"))


# --- fixtures: real nmap 7.92 output ---


def test_real_localhost_scan(nmap_xml):
    result = parse(nmap_xml("real-localhost-ports.xml"), ports_scanned=True)

    assert result["engine"] == {"name": "nmap", "version": "7.92"}
    assert result["hosts_scanned"] == 1
    assert result["devices"] == [
        {
            "ip": "127.0.0.1",
            "mac": None,
            "vendor": None,
            "hostname": "localhost",
            "discovery_reason": "user-set",
            "open_ports": [
                {"port": 135, "protocol": "tcp", "service": "msrpc"},
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds"},
            ],
        }
    ]


def test_real_scan_where_no_host_answered(nmap_xml):
    result = parse(nmap_xml("real-localhost-down.xml"), ports_scanned=True)
    assert result["hosts_scanned"] == 1
    assert result["devices"] == []


def test_real_fatal_error(nmap_xml):
    with pytest.raises(ScanError) as exc:
        parse(nmap_xml("real-fatal-error.xml"), ports_scanned=True)
    assert exc.value.code == "nmap_failed"
    assert exc.value.message == "Ports specified must be between 0 and 65535 inclusive"


# --- edge cases ---


def test_down_and_ipv6_only_hosts_are_left_out_and_devices_sorted_numerically():
    ipv6_only = '<host><status state="up"/><address addr="fe80::1" addrtype="ipv6"/></host>'
    xml = nmaprun(host("10.0.0.10") + host("10.0.0.9") + host("10.0.0.5", state="down") + ipv6_only)

    devices = parse(xml, ports_scanned=False)["devices"]

    assert [d["ip"] for d in devices] == ["10.0.0.9", "10.0.0.10"]


def test_only_open_ports_are_kept_and_unknown_service_is_null():
    ports = (
        "<ports>"
        '<port protocol="tcp" portid="8443"><state state="open"/>'
        '<service name="unknown"/></port>'
        '<port protocol="udp" portid="161"><state state="open|filtered"/></port>'
        '<port protocol="tcp" portid="25"><state state="closed"/></port>'
        '<port protocol="tcp" portid="22"><state state="open"/></port>'
        "</ports>"
    )
    device = parse(nmaprun(host("10.0.0.1", extra=ports)), ports_scanned=True)["devices"][0]

    assert device["open_ports"] == [
        {"port": 22, "protocol": "tcp", "service": None},
        {"port": 8443, "protocol": "tcp", "service": None},
    ]


def test_ptr_hostname_preferred_and_mac_lowercased():
    extra = (
        '<address addr="AA:BB:CC:00:11:22" addrtype="mac"/>'
        '<hostnames><hostname name="given.example" type="user"/>'
        '<hostname name="printer.lan" type="PTR"/></hostnames>'
    )
    device = parse(nmaprun(host("10.0.0.1", extra=extra)), ports_scanned=False)["devices"][0]

    assert device["hostname"] == "printer.lan"
    assert device["mac"] == "aa:bb:cc:00:11:22"
    assert device["vendor"] is None


@pytest.mark.parametrize(
    "xml",
    [b"Starting Nmap 7.94", b"<html></html>", b'<nmaprun version="7.94"><host/>'],
    ids=["not-xml", "wrong-root", "cut-off"],
)
def test_unusable_output(xml):
    with pytest.raises(ScanError) as exc:
        parse(xml, ports_scanned=True)
    assert exc.value.code == "nmap_output_invalid"


def test_output_without_run_statistics_is_rejected():
    with pytest.raises(ScanError) as exc:
        parse(b'<nmaprun version="7.94">' + host("10.0.0.1").encode() + b"</nmaprun>", True)
    assert exc.value.code == "nmap_output_invalid"
