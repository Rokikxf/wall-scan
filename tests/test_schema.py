"""schema.json is a valid JSON Schema and the fixtures follow it."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))


def test_schema_is_valid_json_schema(schema):
    Draft202012Validator.check_schema(schema)


def test_date_time_format_is_checked():
    # Without rfc3339-validator installed, jsonschema silently skips date-time checks.
    assert "date-time" in Draft202012Validator.FORMAT_CHECKER.checkers


def test_there_are_fixtures():
    assert FIXTURES


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_fixture_follows_schema(validator, path):
    validator.validate(json.loads(path.read_text(encoding="utf-8")))
