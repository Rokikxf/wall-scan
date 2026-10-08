# wall-* output contract

Rules shared by every wall-\* tool. Each tool's `schema.json` is the authority
for its own fields; this file covers what all of them have in common.

This file is identical in every tool repo. Change it in the template repo
first, then copy it into each tool.

## Running a tool

- **Input** comes only from command-line arguments. Secrets come from
  environment variables (for example `WALL_SNMP_COMMUNITY`), because other
  users can read command lines with `ps`.
- **Output** is exactly one JSON document on stdout, UTF-8, followed by a
  newline. Logs and progress go to stderr.
- **Exit codes**

  | Code  | Meaning                               | stdout                       |
  |-------|---------------------------------------|------------------------------|
  | 0     | `status` is `ok` or `partial`         | JSON document                |
  | 1     | `status` is `error`                   | JSON document                |
  | 2     | bad arguments (argparse's own code)   | empty; usage text on stderr  |
  | other | crash                                 | anything; treat as a failure |

- **The hub** parses stdout first, whatever the exit code. If stdout does not
  parse or does not validate, the run failed: the hub stores stderr with it.

In code, `main()` in `cli.py` and `envelope.py` implement all of this. An
unexpected exception becomes an `internal_error`, so a crash with no JSON
means something outside Python itself failed.

## Envelope

Every document has these top-level fields, in this order:

| Field            | Type            | Notes                                                         |
|------------------|-----------------|---------------------------------------------------------------|
| `schema_version` | string          | `"1.0"`, `"1.1"`, ... See Versioning.                         |
| `tool`           | object          | `{"name": "wall-scan", "version": "0.1.0"}`                   |
| `started_at`     | string          | RFC 3339, UTC, `Z` suffix                                     |
| `duration_ms`    | integer         | Wall-clock run time                                           |
| `status`         | string          | `ok`, `partial` or `error`                                    |
| `errors`         | array           | `{"code", "message", "target"}`                               |
| `params`         | object          | The inputs, echoed back. Never contains secrets.              |
| `result`         | object or null  | Tool-specific                                                 |

The schema enforces these combinations:

| `status`  | `errors`     | `result`                                       |
|-----------|--------------|------------------------------------------------|
| `ok`      | empty        | present                                        |
| `partial` | at least one | present; fields the errors affected are `null` |
| `error`   | at least one | `null`                                         |

`envelope.py` derives `status` from the result and the errors, so a tool
cannot produce a combination the schema forbids.

A host that is down, or a device that is not a printer, is data, not an error.
Errors are for things that stopped the tool doing its job: nmap missing, no
permission to open a socket, an SNMP timeout.

## Value conventions

- Keys are `snake_case`.
- Every field defined in 1.0 is always present. An unknown value is `null`,
  never an omitted key, so hub code can write `device["mac"]` safely.
- `null` and `[]` mean different things. `null` means not collected or not
  applicable. `[]` means the tool looked and found nothing. Examples:
  `open_ports` and `supplies`.
- Empty strings become `null`.
- Units go in the name: `duration_ms`, `rtt_ms`, `uptime_s`.
- IPv4 addresses are dotted decimal. IPv6 is out of scope for 1.x.
- MAC addresses are lowercase and colon-separated: `aa:bb:cc:dd:ee:ff`.
- Lists have a defined order (each schema says which), so output can be
  diffed and compared to fixtures in tests.
- A field is an `enum` only when its set of values is closed, either because
  the tool's inputs fix it (`method`) or because a standard does
  (`level_state`, from RFC 3805). Open sets (error `code`, `down_reason`,
  supply `type`) are `snake_case` strings, and consumers must accept values
  they have not seen.

## Versioning

`schema_version` is `MAJOR.MINOR` and is independent of the tool's own
version. Tool v0.4.2 might still emit schema 1.1.

**Minor (1.0 → 1.1).** Changes that a 1.0 validator still accepts:
- Add a field. It stays out of `required` for the rest of major version 1,
  even if the tool always emits it, so that 1.0 output still validates against
  the 1.1 schema.
- Add a new value to an open set.

**Major (1.x → 2.0).** Everything else, including:
- renaming or removing a field, or changing its type or meaning;
- adding a value to an `enum`, since old validators reject it;
- tightening or loosening a constraint (for example, allowing IPv6 in an
  `ipv4` field).

The schemas leave `additionalProperties` open on purpose: this is what lets a
1.0 validator accept 1.1 output.

Record every schema change in `CHANGELOG.md` with the new `schema_version`,
and change `SCHEMA_VERSION` in `envelope.py` to match.

**In the hub**, keep a copy of each schema for every major version the hub
understands, for example `contracts/wall-scan.v1.json`. Pick the copy using the
major number in `schema_version`, and reject unknown majors with a clear
message. Do not load the schema from the installed tool package: the hub's copy
records what the *hub's code* expects. The same copy can also validate a
future Rust scanner, which will not be pip-installed.

## Validating in Python

```python
import json
from pathlib import Path
from jsonschema import Draft202012Validator

schema = json.loads(Path("schema.json").read_text(encoding="utf-8"))
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
```

Two gotchas, both silent:

1. `format` keywords (`date-time`, `ipv4`) are skipped unless you pass
   `format_checker`.
2. `date-time` is also skipped if the `rfc3339-validator` package is not
   installed. It is in this repo's dev dependencies, and must also be in the
   hub's dependencies. `tests/test_schema.py` fails if it is missing.

## Where the contract is checked

- **In each tool**, `tests/test_schema.py` checks that `schema.json` is a valid
  schema and that every fixture follows it. `tests/test_cli.py` validates the
  tool's real output.
- **Across tools**, the envelope must be identical in every `schema.json`,
  because there is no shared library to enforce it. `check_schemas.py` compares
  the envelopes and tests each schema against deliberately broken documents.
  It lives in `wall-contracts/` until the hub exists, and then moves into the
  hub next to its `contracts/` copies, so the hub's CI runs it.
