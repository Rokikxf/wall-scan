"""scripts/new_tool.py turns a copy of the template into a working tool.

Template-only: new_tool.py deletes this file along with itself.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "*.egg-info", "build", "dist"
)


def test_new_tool_produces_a_renamed_working_tool(tmp_path):
    copy = tmp_path / "wall-demo"
    shutil.copytree(ROOT, copy, ignore=IGNORE)

    subprocess.run(
        [sys.executable, "scripts/new_tool.py", "wall-demo", "Demo tool."], cwd=copy, check=True
    )

    assert not (copy / "scripts").exists()
    assert not (copy / "tests" / "test_new_tool.py").exists()
    assert (copy / "src" / "wall_demo" / "cli.py").is_file()
    assert not (copy / "src" / "wall_template").exists()
    assert "template-only" not in (copy / "README.md").read_text(encoding="utf-8")
    assert 'description = "Demo tool."' in (copy / "pyproject.toml").read_text(encoding="utf-8")
    old_names = (b"wall-template", b"wall_template")
    leftovers = [
        str(p.relative_to(copy))
        for p in copy.rglob("*")
        if p.is_file() and any(old in p.read_bytes() for old in old_names)
    ]
    assert leftovers == []

    env = {**os.environ, "PYTHONPATH": str(copy / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "wall_demo", "192.168.1.1"],
        cwd=copy,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["tool"]["name"] == "wall-demo"
    schema = json.loads((copy / "schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(doc)
