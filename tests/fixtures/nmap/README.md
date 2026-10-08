# nmap XML fixtures

| File                       | Source                                                                 |
|----------------------------|------------------------------------------------------------------------|
| `real-localhost-ports.xml` | Real nmap 7.92 output: `-Pn` port scan of 127.0.0.1 on Windows (connect mode, no Npcap). Filtered ports are included. |
| `real-localhost-down.xml`  | Real nmap 7.92 output: the same scan without `-Pn`. Host discovery failed, so no hosts are listed. |
| `real-fatal-error.xml`     | Real nmap 7.92 output for a fatal error (`-p 70000`): bare XML with `exit="error"` and `errormsg`. |
| `lan-ports.xml`            | Hand-written in nmap 7.94 format to model a privileged LAN scan. Parses to the `result` in `../ok.json`. |
| `lan-discovery.xml`        | Hand-written, `-sn` (no port scan). Parses to the `result` in `../discovery-only.json`. |

In the real files, the path to `nmap.exe` was replaced with `nmap`.

Replace the hand-written files with real captures from the lab VM once it is
running. Then update `../ok.json` and `../discovery-only.json` to match.
