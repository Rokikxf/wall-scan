"""Command-line entry point.

To build a real tool, replace the arguments in build_parser() and the body of
collect(). Keep the shape of main(): every run that gets past argument parsing
prints exactly one JSON document, even when something unexpected goes wrong.
"""

import argparse
import ipaddress
import logging
import sys
from typing import Any

from wall_template import __version__
from wall_template.envelope import Run, emit

TOOL_NAME = "wall-template"
log = logging.getLogger(TOOL_NAME)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Placeholder: reports whether each IPv4 address is private.",
    )
    parser.add_argument(
        "addresses",
        nargs="+",
        type=ipaddress.IPv4Address,
        metavar="IP",
        help="IPv4 address to classify",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def collect(args: argparse.Namespace, run: Run) -> dict[str, Any] | None:
    """Do the tool's work and return the result object.

    For problems that affect only part of the result, call run.error() and still
    return a result (status becomes partial). If nothing could be collected, call
    run.error() and return None (status becomes error).
    """
    addresses = sorted(set(args.addresses))
    log.info("classifying %d address(es)", len(addresses))
    return {"addresses": [{"ip": str(ip), "private": ip.is_private} for ip in addresses]}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(name)s: %(message)s",
    )
    run = Run(TOOL_NAME, __version__, params={"addresses": [str(ip) for ip in args.addresses]})
    try:
        result = collect(args, run)
    except Exception as exc:
        log.exception("unexpected error")
        run.error("internal_error", f"{type(exc).__name__}: {exc}")
        result = None
    return emit(run.finish(result))
