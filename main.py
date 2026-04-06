"""
main.py
-------
Entry point for the network fingerprinting tool.

Flow
----
    1. discover  — ping sweep + ARP cache → numbered host table
    2. select    — user picks targets interactively
    3. probe     — for each target × each port:
                       port_check → layer34 → layer5 (HTTP/HTTPS/FTP)
    4. analyse   — hierarchical fingerprint → OS + server + confidence
    5. report    — print per-host summary table + detailed notes

Usage
-----
    sudo python main.py                      # auto-detect subnet
    sudo python main.py 192.168.1.0/24       # explicit subnet
    sudo python main.py 192.168.1.10         # single IP (skip discovery)
    sudo python main.py 192.168.1.10 --ports 80,443,21
    sudo python main.py 192.168.0.0/24 --no-ftp --no-https
    sudo python main.py 192.168.1.10 --no-detail
"""

import sys
import os
import argparse
import traceback
from typing import List, Dict, Any, Optional

# ── project imports ───────────────────────────────────────────────────────────
from discover      import discover, print_hosts, select_hosts, HostRecord
from port_check    import check_port, PORT_OPEN, PortCheckError
from layer34_probe import Layer34Prober
from layer5_probe  import HTTPProber, FTPProber
from analyser import analyse, print_report


# ──────────────────────────────────────────────
#  Default ports and their protocols
# ──────────────────────────────────────────────

DEFAULT_PORTS: Dict[int, str] = {
    80:   "HTTP",
    443:  "HTTPS",
    8080: "HTTP",
    8443: "HTTPS",
    21:   "FTP",
}


# ──────────────────────────────────────────────
#  Single-port probe pipeline
# ──────────────────────────────────────────────

def probe_port(ip: str,
               port: int,
               protocol: str) -> Dict[str, Any]:
    """
    Run the full probe pipeline for one IP:port and return the
    enriched fingerprint dict.

    port_check → layer34 (TCP fingerprint + ICMP) → layer5 (HTTP or FTP)
    """
    fp: Dict[str, Any] = {"ip": ip, "port": port, "protocol": protocol}

    # ── 1. Port check ─────────────────────────────────────────────────
    try:
        state, syn_ack = check_port(ip, port, timeout=2.0)
    except PortCheckError as e:
        fp["port_state"]  = "error"
        fp["port_error"]  = str(e)
        return fp

    fp["port_state"] = state
    print(f"      port {port}/{protocol}: {state.upper()}")

    # ── 2. Layer 3/4 ─────────────────────────────────────────────────
    # complete_handshake only if HTTP/HTTPS will follow
    http_follows = state == PORT_OPEN and protocol in ("HTTP", "HTTPS")
    try:
        prober34 = Layer34Prober(ip, port,
                                 syn_ack if state == PORT_OPEN else None)
        fp = prober34.probe(fingerprint=fp,
                            complete_handshake=http_follows)
    except Exception as e:
        fp["layer34_error"] = str(e)

    # ── 3. Layer 5 ───────────────────────────────────────────────────
    try:
        if protocol == "FTP":
            fp = FTPProber(ip, port).probe(fingerprint=fp,
                                           port_state=state)
        else:
            fp = HTTPProber(ip, port, protocol).probe(fingerprint=fp,
                                                      port_state=state)
    except Exception as e:
        fp["layer5_error"] = str(e)

    return fp


# ──────────────────────────────────────────────
#  Per-host probe  (all configured ports)
# ──────────────────────────────────────────────

def probe_host(host: HostRecord,
               ports: Dict[int, str]) -> List[Dict[str, Any]]:
    """
    Probe all configured ports on one host.
    Returns a list of fingerprint dicts (one per port).
    """
    results = []
    for port, protocol in ports.items():
        fp = probe_port(host.ip, port, protocol)
        results.append(fp)
    return results


# ──────────────────────────────────────────────
#  Summary table
# ──────────────────────────────────────────────

def print_summary(all_results: List[Dict[str, Any]]) -> None:
    """
    Print a compact one-line-per-port summary of all probe results
    before the detailed per-host reports.
    """
    print(f"\n{'═'*72}")
    print(f"  {'IP':<18} {'Port':<7} {'State':<10} {'Server':<22} {'OS'}")
    print(f"{'─'*72}")

    for entry in all_results:
        ip        = entry.get("ip", "?")
        port      = entry.get("port", "?")
        state     = entry.get("port_state", "?")
        analysis  = entry.get("_analysis")

        server_str = "─"
        os_str     = "─"

        if analysis:
            ws = analysis.get("web_server")
            fs = analysis.get("ftp_server")
            op = analysis.get("os_precise")
            of = analysis.get("os_family")

            if ws:
                server_str = ws["name"][:21]
            elif fs:
                server_str = fs["name"][:21]

            if op:
                # Shorten long OS names for the table
                os_str = op["name"][:28]
            elif of:
                os_str = of["name"][:28]

        print(f"  {ip:<18} {str(port):<7} {state:<10} "
              f"{server_str:<22} {os_str}")

    print(f"{'═'*72}\n")


# ──────────────────────────────────────────────
#  Argument parsing
# ──────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Network fingerprinting tool — OS + web/FTP server detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py                        auto-detect subnet
  sudo python main.py 192.168.1.0/24         explicit subnet
  sudo python main.py 192.168.1.10           single IP, skip discovery
  sudo python main.py 192.168.1.10 --ports 80,8080,21
  sudo python main.py 192.168.0.0/24 --no-ftp --no-https
        """,
    )
    p.add_argument(
        "target", nargs="?", default=None,
        help="CIDR subnet or single IP (omit to auto-detect subnet)"
    )
    p.add_argument(
        "--ports", default=None,
        help="Comma-separated port list, e.g. 80,443,21 "
             "(overrides default port set)"
    )
    p.add_argument(
        "--no-http",  action="store_true", help="Skip port 80"
    )
    p.add_argument(
        "--no-https", action="store_true", help="Skip port 443 and 8443"
    )
    p.add_argument(
        "--no-ftp",   action="store_true", help="Skip port 21"
    )
    p.add_argument(
        "--no-resolve", action="store_true",
        help="Skip reverse-DNS hostname resolution during discovery"
    )
    p.add_argument(
        "--no-detail", action="store_true",
        help="Print summary table only, skip per-host detailed reports"
    )
    return p.parse_args()


def _build_port_map(args: argparse.Namespace) -> Dict[int, str]:
    """Build the {port: protocol} dict from args."""
    if args.ports:
        # User supplied explicit port list — infer protocol from known map
        port_map = {}
        for tok in args.ports.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                p = int(tok)
            except ValueError:
                print(f"[!] Ignoring invalid port: '{tok}'")
                continue
            proto = DEFAULT_PORTS.get(p, "HTTP")   # default to HTTP if unknown
            port_map[p] = proto
        return port_map

    port_map = dict(DEFAULT_PORTS)

    if args.no_http:
        port_map.pop(80,   None)
        port_map.pop(8080, None)
    if args.no_https:
        port_map.pop(443,  None)
        port_map.pop(8443, None)
    if args.no_ftp:
        port_map.pop(21,   None)

    return port_map


# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────

def main() -> None:
    args     = _parse_args()
    port_map = _build_port_map(args)

    if not port_map:
        print("[!] No ports to scan after applying flags. Exiting.")
        sys.exit(1)

    print(f"\n{'═'*60}")
    print(f"  Network Fingerprinting Tool")
    print(f"  Ports: { {p: v for p, v in port_map.items()} }")
    print(f"{'═'*60}\n")

    # ── Step 1: Host selection ────────────────────────────────────────
    target = args.target

    # Single IP — skip discovery entirely
    if target and "/" not in target and _is_ip(target):
        print(f"[*] Single target mode: {target}")
        hosts = [HostRecord(target)]
    else:
        # Subnet discovery
        cidr = target  # may be None → auto-detect
        try:
            hosts = discover(
                cidr=cidr,
                resolve_hostnames=not args.no_resolve,
            )
        except RuntimeError as e:
            print(f"[!] Discovery failed: {e}")
            sys.exit(1)

        if not hosts:
            print("[!] No hosts found. Check your subnet or try passing a CIDR.")
            sys.exit(0)

        print_hosts(hosts)
        hosts = select_hosts(hosts)

        if not hosts:
            print("[*] No hosts selected. Exiting.")
            sys.exit(0)

    # ── Step 2: Probe + analyse ───────────────────────────────────────
    all_results: List[Dict[str, Any]] = []

    for host in hosts:
        print(f"\n[»] Probing {host.ip}"
              + (f"  ({host.hostname})" if host.hostname else "")
              + (f"  [{host.vendor}]"   if host.vendor != "unknown" else ""))

        port_results = probe_host(host, port_map)

        for fp in port_results:
            # Only analyse ports that had some response
            if fp.get("port_state") in (PORT_OPEN, "filtered", "closed"):
                try:
                    fp["_analysis"] = analyse(fp)
                except Exception as e:
                    fp["_analysis"] = None
                    fp["_analysis_error"] = str(e)
            all_results.append(fp)

    # ── Step 3: Output ────────────────────────────────────────────────
    print_summary(all_results)

    if not args.no_detail:
        for entry in all_results:
            analysis = entry.get("_analysis")
            if analysis:
                print_report(entry, analysis)
            elif entry.get("port_state") == "error":
                print(f"\n  [{entry['ip']}:{entry['port']}]  "
                      f"probe error: {entry.get('port_error')}")


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    """Return True if s looks like a dotted-quad IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        sys.exit(0)
    except Exception:
        traceback.print_exc()
        sys.exit(1)