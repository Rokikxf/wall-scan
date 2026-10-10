# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Changes to the output format also
state the new `schema_version` (see [CONTRACT.md](CONTRACT.md)).

## [Unreleased]

## [0.3.0] - 2026-10-10

Output schema version 1.1: `result.networks` is new. 1.0 consumers ignore it.

### Added

- `result.networks`: for every scanned range, whether this machine is
  attached to it, the interface, its own address in it and the network's
  gateway, read from the routing table. Single addresses have no entry. On
  systems without `/proc/net/route` only the address is known.

## [0.2.0] - 2026-10-09

Output schema version unchanged (1.0): `params.targets` lists the networks
`--local` found.

### Added

- `--local`: scan every private network this machine is directly attached
  to, found in the kernel's routing table (Linux). Docker, VPN and other
  virtual interfaces, single-host and link-local routes, public networks and
  networks larger than a /16 are skipped; `-v` logs each skipped route and why.
- `--exclude-interface IFACE` (repeatable) to leave an attached network out.

### Changed

- `TARGET` is optional when `--local` is given; typed targets and detected
  networks can be combined.

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
