"""The output envelope shared by every wall-* tool (see CONTRACT.md).

This file is identical in every tool repo, because there is no shared library.
Change it in the template repo first, then copy it into each tool.
"""

import json
import sys
import time
from datetime import UTC, datetime
from typing import Any, TextIO

SCHEMA_VERSION = "1.0"


class Run:
    """Collects timing and errors for one run, then builds the output document."""

    def __init__(self, tool: str, version: str, params: dict[str, Any]) -> None:
        self.tool = tool
        self.version = version
        self.params = params
        self.errors: list[dict[str, Any]] = []
        self.started_at = datetime.now(UTC)
        self._start = time.perf_counter()

    def error(self, code: str, message: str, target: str | None = None) -> None:
        """Record an error. code is snake_case; target is the input it concerns, if any."""
        self.errors.append({"code": code, "message": message, "target": target})

    def finish(self, result: dict[str, Any] | None) -> dict[str, Any]:
        """Build the output document.

        status is derived from result and errors, so the combinations the schema
        forbids (ok with errors, error with a result) cannot be produced.
        """
        if result is None and not self.errors:
            self.error("internal_error", "No result and no error recorded (bug in the tool)")
        if result is None:
            status = "error"
        elif self.errors:
            status = "partial"
        else:
            status = "ok"
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": self.tool, "version": self.version},
            "started_at": self.started_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "duration_ms": round((time.perf_counter() - self._start) * 1000),
            "status": status,
            "errors": self.errors,
            "params": self.params,
            "result": result,
        }


def emit(document: dict[str, Any], stream: TextIO | None = None) -> int:
    """Print the document as JSON and return the matching exit code."""
    stream = stream or sys.stdout
    json.dump(document, stream, indent=2)
    stream.write("\n")
    return 1 if document["status"] == "error" else 0
