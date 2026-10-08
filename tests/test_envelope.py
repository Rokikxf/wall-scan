"""envelope.py derives status from result and errors, so it cannot break the contract."""

import io
import json

from wall_template.envelope import SCHEMA_VERSION, Run, emit


def new_run():
    return Run("wall-test", "0.1.0", params={})


def test_ok_when_result_and_no_errors():
    assert new_run().finish({})["status"] == "ok"


def test_partial_when_result_and_errors():
    run = new_run()
    run.error("some_code", "Something was skipped", target="192.168.1.1")
    doc = run.finish({})
    assert doc["status"] == "partial"
    assert doc["errors"] == [
        {"code": "some_code", "message": "Something was skipped", "target": "192.168.1.1"}
    ]


def test_error_when_no_result():
    run = new_run()
    run.error("some_code", "Nothing could be collected")
    doc = run.finish(None)
    assert doc["status"] == "error"
    assert doc["result"] is None


def test_no_result_and_no_error_is_reported_as_internal_error():
    doc = new_run().finish(None)
    assert doc["status"] == "error"
    assert doc["errors"][0]["code"] == "internal_error"


def test_envelope_fields():
    doc = new_run().finish({})
    assert list(doc) == [
        "schema_version",
        "tool",
        "started_at",
        "duration_ms",
        "status",
        "errors",
        "params",
        "result",
    ]
    assert doc["schema_version"] == SCHEMA_VERSION
    assert doc["started_at"].endswith("Z")
    assert isinstance(doc["duration_ms"], int)


def test_emit_prints_json_and_returns_exit_code():
    out = io.StringIO()
    assert emit(new_run().finish({}), out) == 0
    assert json.loads(out.getvalue())["status"] == "ok"
    assert emit(new_run().finish(None), io.StringIO()) == 1
