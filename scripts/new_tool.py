"""Turn a fresh copy of the template into a new wall-* tool. Run it once, before anything else.

    python scripts/new_tool.py wall-scan "Discovers devices on IPv4 networks using nmap."

This renames the package and every mention of the placeholder name, sets the
description in pyproject.toml, and removes the template-only parts: the README
section between the template-only markers, this script, and its test.

What is left to write by hand: the arguments and collect() in cli.py, the params
and result definitions in schema.json, the fixtures, and the README usage section.
"""

import argparse
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD_NAME = "wall-template"
OLD_MODULE = "wall_template"
OLD_DESCRIPTION = "Template for wall-* command-line tools."
TEMPLATE_ONLY = ["scripts", "tests/test_new_tool.py"]
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
TEXT_SUFFIXES = {".py", ".toml", ".md", ".json", ".yml", ".yaml", ".txt"}
README_BLOCK = re.compile(r"<!-- template-only -->.*?<!-- /template-only -->\n+", re.DOTALL)


def text_files():
    for path in ROOT.rglob("*"):
        skipped = SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
        if path.is_file() and path.suffix in TEXT_SUFFIXES and not skipped:
            yield path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("name", help="tool name, e.g. wall-scan")
    parser.add_argument("description", help="one-line description for pyproject.toml")
    args = parser.parse_args()

    if not re.fullmatch(r"wall-[a-z][a-z0-9]*(-[a-z0-9]+)*", args.name):
        parser.error("name must look like wall-scan: lowercase, starting with wall-")
    if any(c in args.description for c in '"\\\n'):
        parser.error("description must not contain quotes, backslashes or newlines")
    if not (ROOT / "src" / OLD_MODULE).is_dir():
        parser.error(f"src/{OLD_MODULE} not found; has this copy already been renamed?")
    module = args.name.replace("-", "_")

    for rel in TEMPLATE_ONLY:
        path = ROOT / rel
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    (ROOT / "src" / OLD_MODULE).rename(ROOT / "src" / module)

    # Bytes in, bytes out, so line endings stay as they are.
    for path in text_files():
        text = path.read_bytes().decode("utf-8")
        new = text.replace(OLD_DESCRIPTION, args.description)
        new = new.replace(OLD_MODULE, module).replace(OLD_NAME, args.name)
        if path.name == "README.md":
            new = README_BLOCK.sub("", new)
        if new != text:
            path.write_bytes(new.encode("utf-8"))

    print(f"Renamed to {args.name} (package src/{module}). Next:")
    print('  pip install -e ".[dev]" && pytest')
    print(f"  then replace the placeholder parts of src/{module}/cli.py, schema.json,")
    print("  tests/fixtures/ and README.md, and commit.")


if __name__ == "__main__":
    main()
