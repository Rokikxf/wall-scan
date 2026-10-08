"""The command line always prints one document that follows schema.json."""

import json
import shutil
import subprocess
import sysconfig

import pytest

from wall_template import cli


def invoke(capsys, *argv):
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_ok_run(capsys, validator):
    code, doc = invoke(capsys, "192.168.1.20", "8.8.8.8", "192.168.1.3")

    validator.validate(doc)
    assert code == 0
    assert doc["status"] == "ok"
    assert doc["tool"]["name"] == cli.TOOL_NAME
    assert doc["params"]["addresses"] == ["192.168.1.20", "8.8.8.8", "192.168.1.3"]
    sorted_ips = [a["ip"] for a in doc["result"]["addresses"]]
    assert sorted_ips == ["8.8.8.8", "192.168.1.3", "192.168.1.20"]


def test_unexpected_exception_still_prints_valid_json(capsys, monkeypatch, validator):
    def fail(args, run):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(cli, "collect", fail)
    code, doc = invoke(capsys, "192.168.1.1")

    validator.validate(doc)
    assert code == 1
    assert doc["status"] == "error"
    assert doc["errors"][0]["code"] == "internal_error"


def test_bad_arguments_exit_2_with_nothing_on_stdout(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["not-an-ip"])

    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


def test_installed_command(validator):
    exe = shutil.which(cli.TOOL_NAME, path=sysconfig.get_path("scripts"))
    assert exe, 'console script not found: run pip install -e ".[dev]"'

    proc = subprocess.run([exe, "10.0.0.1"], capture_output=True, text=True, check=False)

    assert proc.returncode == 0, proc.stderr
    validator.validate(json.loads(proc.stdout))
