"""The command line: argument checks, the nmap call, and one valid document every time.

nmap itself is replaced by a fake that returns saved XML (see fake_nmap), so these
tests need neither nmap nor network access. test_integration.py runs the real thing.
"""

import ipaddress
import json
import shutil
import subprocess
import sysconfig
from pathlib import Path

import pytest

from wall_scan import cli, networks

LAN_PORTS = "22,80,443,445,3389,9100"
LAN_ROUTES = str(Path(__file__).parent / "fixtures" / "proc-net-route-lan.txt")
OWN_ADDRESS = ipaddress.IPv4Address("192.168.1.10")


@pytest.fixture(autouse=True)
def office_pc(monkeypatch):
    """Scan from an office PC: 192.168.1.10 on eth0, router 192.168.1.1. The routing
    table and addresses of the machine running the tests never reach the output."""
    monkeypatch.setattr(networks, "ROUTE_FILE", LAN_ROUTES)
    monkeypatch.setattr(
        networks, "source_address", lambda net: str(OWN_ADDRESS) if OWN_ADDRESS in net else None
    )


@pytest.fixture
def fake_nmap(monkeypatch, nmap_xml):
    """Replace subprocess.run in wall_scan.nmap. Returns a function that sets what the
    fake does; the commands it receives are collected in its .calls list."""

    def configure(xml_file=None, returncode=0, stderr=b"", raises=None):
        def fake_run(command, **kwargs):
            configure.calls.append(command)
            if raises:
                raise raises
            stdout = nmap_xml(xml_file) if xml_file else b""
            return subprocess.CompletedProcess(command, returncode, stdout, stderr)

        monkeypatch.setattr("wall_scan.nmap.subprocess.run", fake_run)
        return configure

    configure.calls = []
    return configure


def invoke(capsys, *argv):
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


# --- successful scans ---


def test_port_scan(capsys, fake_nmap, validator, example):
    fake_nmap("lan-ports.xml")
    code, doc = invoke(capsys, "192.168.1.0/24", "--ports", LAN_PORTS, "--privileged")

    validator.validate(doc)
    assert code == 0
    assert doc["status"] == "ok"
    assert doc["params"] == example("ok.json")["params"]
    assert doc["result"] == example("ok.json")["result"]
    assert fake_nmap.calls == [
        ["nmap", "-oX", "-", "-T4", "--privileged", "-p", LAN_PORTS, "192.168.1.0/24"]
    ]


def test_discovery_only(capsys, fake_nmap, validator, example):
    fake_nmap("lan-discovery.xml")
    code, doc = invoke(capsys, "192.168.1.0/24", "--no-ports", "--privileged")

    validator.validate(doc)
    assert code == 0
    assert doc["params"] == example("discovery-only.json")["params"]
    assert doc["result"] == example("discovery-only.json")["result"]
    assert "-sn" in fake_nmap.calls[0]


def test_defaults_and_target_normalisation(capsys, fake_nmap, validator, monkeypatch):
    monkeypatch.setattr(cli, "running_as_root", lambda: False)
    fake_nmap("real-localhost-down.xml")
    code, doc = invoke(capsys, "192.168.1.77/24", "10.0.0.5")

    validator.validate(doc)
    assert code == 0
    assert doc["params"] == {
        "targets": ["192.168.1.0/24", "10.0.0.5"],
        "ports": cli.DEFAULT_PORTS,
        "privileged": False,
        "timeout_s": 600,
    }
    assert fake_nmap.calls[0][-4:] == ["-p", cli.DEFAULT_PORTS, "192.168.1.0/24", "10.0.0.5"]


def test_public_target_allowed_with_flag(capsys, fake_nmap):
    fake_nmap("real-localhost-down.xml")
    code, doc = invoke(capsys, "203.0.113.7", "--allow-public")
    assert code == 0
    assert doc["params"]["targets"] == ["203.0.113.7"]


# --- failures still produce a valid document ---


def test_nmap_not_installed(capsys, fake_nmap, validator, example):
    fake_nmap(raises=FileNotFoundError())
    code, doc = invoke(capsys, "192.168.1.0/24", "--ports", LAN_PORTS, "--privileged")

    validator.validate(doc)
    assert code == 1
    assert doc["errors"] == example("error.json")["errors"]
    assert doc["result"] is None


def test_nmap_fatal_error_uses_message_from_xml(capsys, fake_nmap, validator):
    stderr = b"Ports specified must be between 0 and 65535 inclusive\nQUITTING!\n"
    fake_nmap("real-fatal-error.xml", returncode=1, stderr=stderr)
    code, doc = invoke(capsys, "192.168.1.0/24")

    validator.validate(doc)
    assert code == 1
    assert doc["errors"] == [
        {
            "code": "nmap_failed",
            "message": "Ports specified must be between 0 and 65535 inclusive",
            "target": None,
        }
    ]


def test_nmap_failure_without_xml_uses_stderr(capsys, fake_nmap, validator):
    stderr = b"Couldn't open a raw socket. Error: Operation not permitted (1)\n"
    fake_nmap(returncode=1, stderr=stderr)
    code, doc = invoke(capsys, "192.168.1.0/24", "--privileged")

    validator.validate(doc)
    assert code == 1
    assert doc["errors"][0]["code"] == "nmap_failed"
    assert doc["errors"][0]["message"] == stderr.decode().strip()


def test_timeout(capsys, fake_nmap, validator):
    fake_nmap(raises=subprocess.TimeoutExpired("nmap", 5))
    code, doc = invoke(capsys, "192.168.1.0/24", "--timeout-s", "5")

    validator.validate(doc)
    assert code == 1
    assert doc["errors"][0]["code"] == "scan_timeout"


def test_unexpected_exception_still_prints_valid_json(capsys, monkeypatch, validator):
    def fail(args, run):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(cli, "collect", fail)
    code, doc = invoke(capsys, "192.168.1.1")

    validator.validate(doc)
    assert code == 1
    assert doc["errors"][0]["code"] == "internal_error"


# --- bad arguments: exit code 2, nothing on stdout ---


@pytest.mark.parametrize(
    "argv",
    [
        ["not-an-ip"],
        ["192.168.0.0/15"],
        ["8.8.8.8"],
        ["192.168.1.0/24", "--ports", "0"],
        ["192.168.1.0/24", "--ports", "80-22"],
        ["192.168.1.0/24", "--ports", "http"],
        ["192.168.1.0/24", "--ports", "22", "--no-ports"],
        ["192.168.1.0/24", "--timeout-s", "0"],
    ],
    ids=[
        "not-an-address",
        "larger-than-slash-16",
        "public-address",
        "port-zero",
        "reversed-range",
        "port-name",
        "ports-and-no-ports",
        "zero-timeout",
    ],
)
def test_bad_arguments(capsys, fake_nmap, argv):
    fake_nmap("real-localhost-down.xml")
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)

    assert exc.value.code == 2
    assert capsys.readouterr().out == ""
    assert fake_nmap.calls == []


# --- the installed command ---


def test_installed_command(tmp_path, validator):
    exe = shutil.which(cli.TOOL_NAME, path=sysconfig.get_path("scripts"))
    assert exe, 'console script not found: run pip install -e ".[dev]"'
    missing_nmap = str(tmp_path / "no-such-nmap")

    proc = subprocess.run(
        [exe, "192.168.1.1", "--nmap", missing_nmap], capture_output=True, text=True, check=False
    )

    assert proc.returncode == 1, proc.stderr
    doc = json.loads(proc.stdout)
    validator.validate(doc)
    assert doc["errors"][0]["code"] == "nmap_not_found"
