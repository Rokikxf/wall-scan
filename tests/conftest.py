import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def schema():
    return json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def validator(schema):
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
