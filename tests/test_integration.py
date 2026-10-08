"""Real nmap against 127.0.0.1, so no other machine is touched.

Skipped when nmap is not installed. CI installs it. To run locally with an
nmap that is not on PATH, set WALL_SCAN_NMAP to its path.
"""

import json
import os
import shutil
import sys

import pytest

from wall_scan import cli

NMAP = os.environ.get("WALL_SCAN_NMAP") or shutil.which("nmap")
pytestmark = pytest.mark.skipif(NMAP is None, reason="nmap is not installed")


def test_scan_localhost(capsys, validator):
    code = cli.main(["127.0.0.1", "--ports", "1-1024", "--nmap", NMAP, "--timeout-s", "120"])
    doc = json.loads(capsys.readouterr().out)

    validator.validate(doc)
    assert code == 0, doc["errors"]
    assert doc["result"]["hosts_scanned"] == 1
    assert doc["result"]["engine"]["version"]
    if sys.platform == "linux":
        # nmap on Linux always finds the local host. On Windows without Npcap, host
        # discovery for 127.0.0.1 fails, so the host is not listed there.
        assert [d["ip"] for d in doc["result"]["devices"]] == ["127.0.0.1"]
