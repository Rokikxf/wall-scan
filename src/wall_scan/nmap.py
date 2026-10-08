"""Running nmap and turning its XML output into wall-scan's result object.

nmap writes XML to stdout (-oX -). The parts used here are stable across nmap
versions: host/status, host/address, host/hostnames, host/ports and runstats.
"""

import ipaddress
import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

log = logging.getLogger("wall-scan")


class ScanError(Exception):
    """A failure that leaves no result. code becomes errors[].code in the output."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def build_command(nmap: str, targets: list[str], ports: str | None, privileged: bool) -> list[str]:
    command = [nmap, "-oX", "-", "-T4"]
    if privileged:
        command.append("--privileged")
    command += ["-sn"] if ports is None else ["-p", ports]
    return command + targets


def run(command: list[str], timeout_s: int) -> bytes:
    """Run nmap and return its XML output, or raise ScanError."""
    log.info("running: %s", " ".join(command))
    try:
        proc = subprocess.run(command, capture_output=True, timeout=timeout_s, check=False)
    except FileNotFoundError:
        raise ScanError("nmap_not_found", f"nmap executable not found: {command[0]}") from None
    except subprocess.TimeoutExpired:
        raise ScanError("scan_timeout", f"nmap did not finish within {timeout_s} s") from None
    except OSError as exc:
        raise ScanError("nmap_failed", f"Could not start nmap: {exc}") from None

    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    for line in stderr.splitlines():
        log.warning("nmap: %s", line)
    if proc.returncode != 0:
        message = _fatal_error_message(_parse_or_none(proc.stdout)) or _last_line(stderr)
        raise ScanError("nmap_failed", message or f"nmap exited with code {proc.returncode}")
    return proc.stdout


def parse(xml: bytes, ports_scanned: bool) -> dict[str, Any]:
    """Turn nmap's XML output into the result object described in schema.json."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ScanError("nmap_output_invalid", f"Could not parse nmap XML output: {exc}") from None
    if root.tag != "nmaprun":
        raise ScanError("nmap_output_invalid", f"Expected <nmaprun>, found <{root.tag}>")

    message = _fatal_error_message(root)
    if message:
        raise ScanError("nmap_failed", message)
    hosts = root.find("runstats/hosts")
    if hosts is None:
        raise ScanError("nmap_output_invalid", "nmap output ends early: no run statistics")

    devices = [
        _device(host, ports_scanned)
        for host in root.findall("host")
        if _status(host) == "up" and _address(host, "ipv4") is not None
    ]
    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return {
        "engine": {"name": "nmap", "version": root.get("version")},
        "hosts_scanned": int(hosts.get("total", "0")),
        "devices": devices,
    }


def _device(host: ET.Element, ports_scanned: bool) -> dict[str, Any]:
    mac = _address(host, "mac")
    status = host.find("status")
    return {
        "ip": _address(host, "ipv4").get("addr"),
        "mac": mac.get("addr").lower() if mac is not None else None,
        "vendor": (mac.get("vendor") or None) if mac is not None else None,
        "hostname": _hostname(host),
        "discovery_reason": (status.get("reason") if status is not None else None) or "unknown",
        "open_ports": _open_ports(host) if ports_scanned else None,
    }


def _status(host: ET.Element) -> str | None:
    status = host.find("status")
    return status.get("state") if status is not None else None


def _address(host: ET.Element, addrtype: str) -> ET.Element | None:
    for address in host.findall("address"):
        if address.get("addrtype") == addrtype:
            return address
    return None


def _hostname(host: ET.Element) -> str | None:
    """The reverse-DNS (PTR) name if there is one, otherwise any name nmap reports."""
    names = host.findall("hostnames/hostname")
    names.sort(key=lambda n: n.get("type") != "PTR")
    for name in names:
        if name.get("name"):
            return name.get("name")
    return None


def _open_ports(host: ET.Element) -> list[dict[str, Any]]:
    ports = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        name = service.get("name") if service is not None else None
        ports.append(
            {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": None if name in (None, "", "unknown") else name,
            }
        )
    ports.sort(key=lambda p: (p["protocol"], p["port"]))
    return ports


def _parse_or_none(xml: bytes) -> ET.Element | None:
    try:
        return ET.fromstring(xml)
    except ET.ParseError:
        return None


def _fatal_error_message(root: ET.Element | None) -> str | None:
    """nmap reports fatal errors as <finished exit="error" errormsg="...">."""
    finished = root.find("runstats/finished") if root is not None else None
    if finished is not None and finished.get("exit") == "error":
        return finished.get("errormsg") or "nmap reported an error"
    return None


def _last_line(text: str) -> str | None:
    lines = [line for line in text.splitlines() if line.strip() and line.strip() != "QUITTING!"]
    return lines[-1].strip() if lines else None
