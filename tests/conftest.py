import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def schema():
    return json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def validator(schema):
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


@pytest.fixture(scope="session")
def example():
    """Load an output example from tests/fixtures by file name, e.g. example("ok.json")."""
    return lambda name: json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def nmap_xml():
    """Load nmap XML from tests/fixtures/nmap by file name."""
    return lambda name: (FIXTURES / "nmap" / name).read_bytes()
