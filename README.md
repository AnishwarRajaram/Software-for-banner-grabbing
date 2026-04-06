# NetProbe

A layered active network fingerprinting tool written in Python.  
Given a subnet or a single IP, NetProbe discovers live hosts, probes them across multiple protocol layers, and produces a best-guess identification of the **OS**, **web server**, and **FTP server** running on each target — without installing anything on the target machine.

> **Requires root** — raw socket operations (Scapy) need `CAP_NET_RAW`.  
> Tested on Linux (Debian / Ubuntu). Python 3.9+.

---

## Features

- Subnet discovery via parallel ping sweep + ARP cache, with MAC vendor lookup
- Interactive host selection before any deep probing begins
- TCP stack fingerprinting (TTL, window, options string, DF bit, ECN) from a single SYN — no redundant handshakes
- ICMP fingerprinting (echo reply, large echo, unreachable quoting) as a corroborating signal
- HTTP fingerprinting across four probes (normal GET, deliberate 404, malformed version, OPTIONS) on a single persistent connection
- FTP fingerprinting (banner, SYST, FEAT, anonymous login, CSID) on a single persistent connection
- OS matching against the **nmap-os-db** (~5500 entries) with CPE-based label normalisation
- Web / FTP server identification via a regex pattern table
- Hierarchical confidence scoring — each level outputs a result even if a later level fails

---

## Pipeline overview

```
discover.py          ping sweep + ARP cache → numbered host table → user selects targets
     │
port_check.py        one SYN per port → open / closed / filtered  +  raw SYN-ACK packet
     │
layer34_probe.py     extracts TCP fingerprint from the SYN-ACK (zero extra packets)
                     + fires 3 ICMP probes (echo, large echo, UDP unreachable)
     │
layer5_probe.py      HTTPProber  — 4 HTTP probes on one persistent connection
                     FTPProber   — 5 FTP commands on one persistent connection
     │
fingerprint_db.py    matches accumulated fingerprint dict against nmap-os-db + web_servers.json
     │
analyser.py          hierarchical scoring → OS + server + confidence + notes
```

Every layer writes into a **single shared fingerprint dict** that is passed forward through the pipeline. The analyser reads the complete dict once at the end.

---

## Requirements

### Python packages

```bash
pip install scapy
```

### External data files

Two files are not bundled and must be downloaded before first run.

**nmap OS database** (~3 MB) — the fingerprint database used for OS matching:

```bash
curl -o nmap-os-db https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db
```

**IEEE OUI vendor table** (~2 MB) — maps MAC prefixes to manufacturer names:

```bash
curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt
```

Place both files in the same directory as the scripts.  
The tool runs without `oui.txt` (vendor column shows "unknown") but requires `nmap-os-db` for OS matching.

---

## Standalone script checks

Each module can be run directly to verify it works before using `main.py`.

**Verify the databases loaded correctly:**
```bash
python3 fingerprint_db.py
# nmap-os-db   : 5500+ entries loaded
# web_servers  : 14 entries
# ftp_servers  : 7 entries
```

**Check if a single port is open:**
```bash
sudo python3 port_check.py 192.168.1.10 80
```

**Layer 3/4 probe only (TCP stack + ICMP fingerprint):**
```bash
sudo python3 layer34_probe.py 192.168.1.10 80
```

**Layer 5 probe — HTTP:**
```bash
sudo python3 layer5_probe.py 192.168.1.10 80 HTTP
```

**Layer 5 probe — HTTPS:**
```bash
sudo python3 layer5_probe.py 192.168.1.10 443 HTTPS
```

**Layer 5 probe — FTP:**
```bash
sudo python3 layer5_probe.py 192.168.1.10 21 FTP
```

**Run the analyser against a built-in test fingerprint:**
```bash
python3 analyser.py
```

**Run discovery only (no deep probing):**
```bash
sudo python3 discover.py 192.168.1.0/24
```

---

## Main usage

```bash
sudo python3 main.py [target] [options]
```

### Arguments

| Argument | Description |
|---|---|
| *(none)* | Auto-detect local `/24` subnet and run discovery |
| `192.168.1.0/24` | Explicit subnet |
| `192.168.1.10` | Single IP — skips discovery, probes immediately |

### Options

| Flag | Description |
|---|---|
| `--ports 80,443,21` | Override the default port set |
| `--no-http` | Skip ports 80 and 8080 |
| `--no-https` | Skip ports 443 and 8443 |
| `--no-ftp` | Skip port 21 |
| `--no-resolve` | Skip reverse-DNS hostname lookups during discovery |
| `--no-detail` | Print summary table only, skip per-host detailed reports |

### Default ports scanned

| Port | Protocol |
|---|---|
| 80 | HTTP |
| 443 | HTTPS |
| 8080 | HTTP |
| 8443 | HTTPS |
| 21 | FTP |

### Examples

```bash
# Auto-detect subnet, discover hosts, let user select, probe all default ports
sudo python3 main.py

# Probe a specific subnet
sudo python3 main.py 192.168.1.0/24

# Single target, all default ports
sudo python3 main.py 192.168.1.10

# Single target, specific ports only
sudo python3 main.py 192.168.1.10 --ports 80,8080,21

# Skip FTP and HTTPS, summary table only
sudo python3 main.py 192.168.1.0/24 --no-ftp --no-https --no-detail
```

### Example output

```
════════════════════════════════════════════════════════════════════════
  IP                 Port    State      Server                 OS
────────────────────────────────────────────────────────────────────────
  192.168.1.10       80      open       Nginx                  Linux (kernel 6.x)
  192.168.1.10       443     filtered   ─                      Linux / macOS / FreeBSD
  192.168.1.10       8080    open       Apache httpd 2.4.66    Linux (kernel 6.x)
  192.168.1.10       21      open       vsftpd 3.0.3           Linux (kernel 6.x)
════════════════════════════════════════════════════════════════════════
```

---

## Project structure

```
.
├── main.py              Entry point — orchestrates the full pipeline
├── discover.py          Host discovery: ping sweep, ARP cache, vendor lookup, host selection
├── port_check.py        Single-SYN port state check, returns raw SYN-ACK for reuse
├── layer34_probe.py     TCP stack + ICMP fingerprinting (layers 3 and 4)
├── layer5_probe.py      HTTP and FTP application-layer probing (layer 5)
├── fingerprint_db.py    nmap-os-db parser + web server regex matcher
├── analyser.py          Hierarchical fingerprint analysis and confidence scoring
├── web_servers.json     Handwritten regex patterns for web and FTP server identification
├── scanner.py           (utility)
├── nmap-os-db           ← download with curl (not bundled)
└── oui.txt              ← download with curl (not bundled)
```

---

## Notes

- **Firewalled hosts** — filtered ports produce no layer-4 data. The OS column falls back to a coarse TTL-origin guess (`Linux / macOS / FreeBSD`, `Windows`, or `Cisco`) rather than a precise match.
- **Linux window randomisation** — Linux randomises its initial TCP window size per connection. Window size is excluded from OS scoring for TTL-64 hosts to avoid false positives from embedded device entries in the nmap-os-db that happen to share the same options string.
- **Same OS on all ports** — expected. OS fingerprinting is per-host (the TCP stack is shared), not per-port. Different ports on the same host will always produce the same OS result and may differ only in their layer-5 server identification.
- **Root requirement** — Scapy needs `CAP_NET_RAW` to send raw IP/ICMP packets. The ping sweep in `discover.py` uses the system `ping` binary and does not require root.

---

## Disclaimer

This tool is intended for use on networks you own or have explicit permission to test.