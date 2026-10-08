# wall-scan

Discovers devices on IPv4 networks with [nmap](https://nmap.org) and prints
them as JSON: IP address, MAC address, vendor, hostname and open ports. It is
the discovery tool of the wall IT asset management system. The hub runs it on a
schedule and stores the results, but it works on its own from the command line.

Only scan networks you own or have written permission to scan.

## Requirements

- Python 3.13
- nmap (`sudo apt install nmap` on Ubuntu)

## Usage

```
wall-scan TARGET [TARGET ...] [--ports LIST | --no-ports] [--privileged]
          [--timeout-s N] [--allow-public] [--nmap PATH] [-v] [--version]
```

| Option            | Meaning                                                                    |
|-------------------|----------------------------------------------------------------------------|
| `TARGET`          | IPv4 address or CIDR range, e.g. `192.168.1.0/24`. At most a /16.          |
| `--ports LIST`    | TCP ports to check, e.g. `22,80,8000-8100`. The default covers common office services: `21,22,23,53,80,135,139,443,445,515,631,3389,5900,8080,9100`. |
| `--no-ports`      | Only discover devices (`nmap -sn`). `open_ports` is then `null`.          |
| `--privileged`    | nmap has raw-socket privileges (see below). Enables ARP discovery, MAC addresses and vendors. |
| `--timeout-s N`   | Stop nmap after N seconds (default 600). The run then fails with `scan_timeout`. |
| `--allow-public`  | Allow targets outside private address ranges.                             |
| `--nmap PATH`     | nmap executable to use (default: `nmap` on PATH).                         |
| `-v`              | Log progress, including the nmap command line, to stderr.                 |

One device from a scan of `192.168.1.0/24`:

```json
{
  "ip": "192.168.1.50",
  "mac": "3c:52:82:ab:cd:ef",
  "vendor": "Hewlett Packard",
  "hostname": "npi1a2b3c.lan",
  "discovery_reason": "arp-response",
  "open_ports": [
    {"port": 80, "protocol": "tcp", "service": "http"},
    {"port": 443, "protocol": "tcp", "service": "https"},
    {"port": 9100, "protocol": "tcp", "service": "jetdirect"}
  ]
}
```

Complete documents are in [tests/fixtures/](tests/fixtures/): `ok.json`,
`discovery-only.json` and `error.json`.

## Privileges

Without raw-socket privileges nmap falls back to TCP connect scans. Devices
are still found, but nmap cannot use ARP, so `mac` and `vendor` are always
`null`, and devices that answer no TCP probe are missed.

The web app never runs as root. To give nmap the raw sockets it needs, grant
capabilities to the nmap binary and pass `--privileged`:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
wall-scan 192.168.1.0/24 --privileged
```

Capabilities apply to every user who can run that nmap binary, so grant them
only on a dedicated scanner machine or container. When running as root,
`--privileged` is implied.

MAC addresses are only visible for devices on the same network segment as the
scanner. They do not cross routers. In Docker, this means the scanner
container needs `network_mode: host` (and the `NET_RAW` and `NET_ADMIN`
capabilities); on the default bridge network nmap sees no MAC addresses.

## Output

Every run that gets past argument parsing prints exactly one JSON document to
stdout, described by [schema.json](schema.json) (schema version 1.0). Logs and
nmap's own warnings go to stderr.

| Exit code | Meaning                                                   |
|-----------|-----------------------------------------------------------|
| 0         | `status` is `ok`                                          |
| 1         | `status` is `error` (details in `errors`)                 |
| 2         | invalid arguments: nothing on stdout, usage on stderr     |

| Error code            | Cause                                                          |
|-----------------------|----------------------------------------------------------------|
| `nmap_not_found`      | No nmap executable at `--nmap` (default: on PATH).             |
| `nmap_failed`         | nmap exited with an error, e.g. `--privileged` without capabilities. The message is nmap's own. |
| `nmap_output_invalid` | nmap's XML output could not be parsed or was cut off.          |
| `scan_timeout`        | The scan took longer than `--timeout-s`.                       |
| `internal_error`      | A bug in wall-scan. The traceback is on stderr.                |

The rules shared by all wall-\* tools (the envelope, value formats,
versioning) are in [CONTRACT.md](CONTRACT.md).

## Development

```bash
python -m venv .venv
.venv\Scripts\activate            # Linux: . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

Most tests replace nmap with saved XML output ([tests/fixtures/nmap/](tests/fixtures/nmap/)),
so they need neither nmap nor a network. `tests/test_integration.py` runs the
real nmap against 127.0.0.1. It is skipped when nmap is not installed; set
`WALL_SCAN_NMAP` to use an nmap that is not on PATH. CI installs nmap, so it
always runs there.

## Releasing

1. Set `__version__` in `src/wall_scan/__init__.py`, and move the
   `Unreleased` entries in `CHANGELOG.md` under the new version.
2. Commit, then tag and push the tag:

   ```bash
   git tag v0.1.0
   git push origin main v0.1.0
   ```

CI fails a tag that does not match `__version__`. The hub installs an exact
release:

```bash
pip install "wall-scan @ git+https://github.com/Rokikxf/wall-scan@v0.1.0"
```
