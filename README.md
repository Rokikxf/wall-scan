# wall-template

<!-- template-only -->
> **This is the template repository for the wall-\* tools.** Every tool repo
> (wall-scan, wall-healthcheck, wall-snmpinfo, wall-wol) starts as a copy of it.
> The section below explains how. `scripts/new_tool.py` deletes this section,
> so a new tool's README starts at the description.

## Creating a tool from this template

1. On GitHub: **Use this template → Create a new repository**, named after the
   tool, e.g. `wall-scan`. Then clone it.
2. Rename the placeholder and install:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate            # Linux: . .venv/bin/activate
   python scripts/new_tool.py wall-scan "Discovers devices on IPv4 networks using nmap."
   pip install -e ".[dev]"
   pytest
   ```

3. Replace the placeholder parts: the arguments and `collect()` in `cli.py`,
   `params` and `result` in `schema.json`, the fixtures in `tests/fixtures/`, and
   the description and usage below.
4. Commit and push. CI runs on the first push.

The shared parts are `envelope.py`, the envelope in `schema.json`,
`CONTRACT.md` and the CI workflow. Change them here first, then copy the change
into each tool.
<!-- /template-only -->

Placeholder tool: reports whether each IPv4 address is private. It exists to
show the structure every wall-\* tool follows.

## Usage

```
wall-template IP [IP ...] [-v] [--version]
```

```console
$ wall-template 192.168.1.20 8.8.8.8
{
  "schema_version": "1.0",
  "tool": {"name": "wall-template", "version": "0.1.0"},
  "started_at": "2026-10-08T09:30:00.125Z",
  "duration_ms": 0,
  "status": "ok",
  "errors": [],
  "params": {"addresses": ["192.168.1.20", "8.8.8.8"]},
  "result": {
    "addresses": [
      {"ip": "8.8.8.8", "private": false},
      {"ip": "192.168.1.20", "private": true}
    ]
  }
}
```

## Output

Every run that gets past argument parsing prints exactly one JSON document to
stdout, described by [schema.json](schema.json) (schema version 1.0). Logs go to
stderr; `-v` turns on progress messages.

| Exit code | Meaning                                                   |
|-----------|-----------------------------------------------------------|
| 0         | `status` is `ok` or `partial`                             |
| 1         | `status` is `error` (details in `errors`)                 |
| 2         | invalid arguments: nothing on stdout, usage on stderr     |

The rules shared by all wall-\* tools (the envelope, value formats,
versioning) are in [CONTRACT.md](CONTRACT.md).

## Development

Needs Python 3.13.

```bash
python -m venv .venv
.venv\Scripts\activate            # Linux: . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

CI runs the same checks on every push and pull request.

## Releasing

1. Set `__version__` in `src/wall_template/__init__.py`, and move the
   `Unreleased` entries in `CHANGELOG.md` under the new version.
2. Commit, then tag and push the tag:

   ```bash
   git tag v0.1.0
   git push origin main v0.1.0
   ```

CI fails a tag that does not match `__version__`. The hub installs an exact
release:

```bash
pip install "wall-template @ git+https://github.com/rokikxf/wall-template@v0.1.0"
```
