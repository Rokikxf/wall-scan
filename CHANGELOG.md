# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Changes to the output format also
state the new `schema_version` (see [CONTRACT.md](CONTRACT.md)).

## [Unreleased]

## [0.1.0] - 2026-10-08

First release. Output schema version 1.0.

### Added

- Discover devices on IPv4 addresses and CIDR ranges with nmap: IP, MAC
  address, vendor, reverse-DNS hostname and the reason nmap considered the
  host up.
- Check open TCP ports (`--ports`, with a default list of common office
  services), or skip port scanning (`--no-ports`).
- `--privileged` for nmap with raw-socket capabilities, which enables ARP
  discovery and MAC addresses without running as root.
- Safety limits: only private address ranges unless `--allow-public` is
  given, ranges of at most a /16, and a time limit (`--timeout-s`).
- One JSON document per run following `schema.json`, including for nmap
  failures (`nmap_not_found`, `nmap_failed`, `nmap_output_invalid`,
  `scan_timeout`).
