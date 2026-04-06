"""
discover.py
-----------
Host discovery for the local subnet:

    1. Ping sweep  — ICMP echo to every host in the subnet (parallel)
    2. ARP cache   — read /proc/net/arp (or `arp -a`) for hosts that
                     didn't respond to ping but are in the cache
    3. OUI lookup  — first 3 bytes of MAC → vendor name (oui.txt)
    4. Display     — print a numbered table so the user can choose targets
    5. Selection   — user types numbers / ranges / "all"; returns list of IPs

Download oui.txt once:
    curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt
"""

import re
import os
import sys
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple



_HERE    = os.path.dirname(os.path.abspath(__file__))
OUI_FILE = os.path.join(_HERE, "oui.txt")



_oui_db: Optional[Dict[str, str]] = None


def _load_oui(path: str = OUI_FILE) -> Dict[str, str]:
    """
    Parse the IEEE oui.txt into a dict  { 'AA:BB:CC': 'Vendor Name' }.

    The file has lines like:
        00-00-0C   (hex)        Cisco Systems, Inc
    We normalise to upper-case colon-separated hex.
    """
    db: Dict[str, str] = {}
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                # Match lines with the (hex) marker
                m = re.match(
                    r'^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})'
                    r'\s+\(hex\)\s+(.+)', line)
                if m:
                    oui    = f"{m.group(1).upper()}:{m.group(2).upper()}:{m.group(3).upper()}"
                    vendor = m.group(4).strip()
                    db[oui] = vendor
    except FileNotFoundError:
        pass   # oui.txt is optional — vendor column will show "unknown"
    return db


def _vendor(mac: Optional[str]) -> str:
    """Return vendor name for a MAC address, or 'unknown'."""
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui()
    if not mac:
        return "unknown"
    # Normalise separators to colons, upper-case, take first 3 octets
    normalised = mac.upper().replace("-", ":").replace(".", ":")
    parts = normalised.split(":")
    if len(parts) < 3:
        return "unknown"
    oui = ":".join(parts[:3])
    return _oui_db.get(oui, "unknown")




def _ping_one(ip: str, timeout: int = 1) -> bool:
    """
    Send one ICMP echo using the system ping binary (no root needed).
    Returns True if the host responds.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False



def _subnet_hosts(cidr: str) -> List[str]:
    """
    Expand a CIDR like '192.168.1.0/24' into a list of host IPs
    (excludes network address and broadcast).
    Uses only stdlib — no ipaddress module quirks.
    """
    try:
        import ipaddress
        net = ipaddress.IPv4Network(cidr, strict=False)
        # Skip network and broadcast for /24 and smaller
        hosts = list(net.hosts())
        return [str(h) for h in hosts]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR '{cidr}': {e}")


def _local_subnet() -> Optional[str]:
    """
    Best-effort guess at the local /24 subnet by looking at the default
    route's source address.  Returns e.g. '192.168.1.0/24' or None.
    """
    try:
        # Connect a UDP socket to an external address — doesn't send anything
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        # Assume /24
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return None



def _read_arp_cache() -> Dict[str, str]:
    """
    Return { ip: mac } for all entries in the ARP cache.

    Tries /proc/net/arp first (Linux); falls back to parsing `arp -a`
    output (works on macOS and other Unix).
    """
    entries: Dict[str, str] = {}

    # ── /proc/net/arp (Linux) ──────────────────────────────────────
    try:
        with open("/proc/net/arp", "r") as fh:
            next(fh)   # skip header line
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    ip  = parts[0]
                    mac = parts[3]
                    # Skip incomplete entries (00:00:00:00:00:00)
                    if mac and mac != "00:00:00:00:00:00":
                        entries[ip] = mac.upper()
        return entries
    except FileNotFoundError:
        pass

    # ── arp -a fallback ────────────────────────────────────────────
    try:
        out = subprocess.check_output(["arp", "-a"],
                                      stderr=subprocess.DEVNULL,
                                      text=True)
        # Lines look like:
        #   router.local (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        for line in out.splitlines():
            m = re.search(
                r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})', line)
            if m:
                entries[m.group(1)] = m.group(2).upper()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return entries



def _resolve_hostname(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Reverse-DNS lookup with a short timeout. Returns None on failure."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)



class HostRecord:
    """One discovered host — all fields optional except ip."""
    def __init__(self, ip: str):
        self.ip:       str            = ip
        self.ping:     bool           = False
        self.mac:      Optional[str]  = None
        self.vendor:   str            = "unknown"
        self.hostname: Optional[str]  = None
        self.source:   str            = "arp"   # "ping" | "arp" | "both"

    def __repr__(self) -> str:
        return (f"HostRecord(ip={self.ip}, ping={self.ping}, "
                f"mac={self.mac}, vendor={self.vendor})")


def discover(cidr: Optional[str]      = None,
             ping_workers: int        = 64,
             resolve_hostnames: bool  = True) -> List[HostRecord]:
    """
    Discover live hosts on the local subnet.

    Parameters
    ----------
    cidr              : CIDR string e.g. '192.168.1.0/24'.  If None,
                        auto-detected from the default route.
    ping_workers      : number of parallel ping threads
    resolve_hostnames : attempt reverse-DNS for each host

    Returns
    -------
    List[HostRecord] sorted by IP address
    """
    if cidr is None:
        cidr = _local_subnet()
        if cidr is None:
            raise RuntimeError(
                "Could not determine local subnet. "
                "Pass cidr= explicitly, e.g. '192.168.1.0/24'."
            )
        print(f"[*] Auto-detected subnet: {cidr}")

    all_hosts_ips = _subnet_hosts(cidr)
    print(f"[*] Pinging {len(all_hosts_ips)} hosts ({ping_workers} threads)...")

    # ── Ping sweep ────────────────────────────────────────────────────
    ping_alive: set = set()
    with ThreadPoolExecutor(max_workers=ping_workers) as pool:
        future_to_ip = {pool.submit(_ping_one, ip): ip for ip in all_hosts_ips}
        done = 0
        for future in as_completed(future_to_ip):
            done += 1
            ip = future_to_ip[future]
            if future.result():
                ping_alive.add(ip)
            
            if done % 32 == 0 or done == len(all_hosts_ips):
                print(f"\r    {done}/{len(all_hosts_ips)} probed, "
                      f"{len(ping_alive)} alive   ", end="", flush=True)
    print()  

    # ── ARP cache ─────────────────────────────────────────────────────
    print("[*] Reading ARP cache...")
    arp_cache = _read_arp_cache()

    # ── Merge ─────────────────────────────────────────────────────────
    merged: Dict[str, HostRecord] = {}

    for ip in ping_alive:
        rec       = HostRecord(ip)
        rec.ping  = True
        rec.source = "ping"
        merged[ip] = rec

    for ip, mac in arp_cache.items():
        if ip not in merged:
            rec = HostRecord(ip)
            merged[ip] = rec
        merged[ip].mac    = mac
        merged[ip].vendor = _vendor(mac)
        if merged[ip].source == "ping":
            merged[ip].source = "both"

    # Fill MAC from ARP for ping-only entries that happen to be in cache
    for ip, rec in merged.items():
        if rec.mac is None and ip in arp_cache:
            rec.mac    = arp_cache[ip]
            rec.vendor = _vendor(rec.mac)

    # ── Hostname resolution ───────────────────────────────────────────
    if resolve_hostnames and merged:
        print(f"[*] Resolving hostnames for {len(merged)} hosts...")
        with ThreadPoolExecutor(max_workers=32) as pool:
            future_to_ip = {
                pool.submit(_resolve_hostname, ip): ip
                for ip in merged
            }
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                merged[ip].hostname = future.result()

    # Sort by IP numerically
    def _ip_sort_key(rec: HostRecord) -> Tuple:
        try:
            return tuple(int(p) for p in rec.ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)

    return sorted(merged.values(), key=_ip_sort_key)



def print_hosts(hosts: List[HostRecord]) -> None:
    """Print a numbered table of discovered hosts."""
    if not hosts:
        print("  No hosts found.")
        return

    # Column widths
    w_ip  = max(len(h.ip) for h in hosts) + 2
    w_mac = 19
    w_ven = min(max((len(h.vendor) for h in hosts), default=10), 30) + 2
    w_hst = min(max((len(h.hostname or "") for h in hosts), default=0), 35) + 2

    header = (f"  {'#':<4} {'IP':<{w_ip}} {'MAC':<{w_mac}} "
              f"{'Vendor':<{w_ven}} {'Src':<6} {'Hostname':<{w_hst}}")
    sep    = "  " + "─" * (len(header) - 2)

    print(f"\n{sep}")
    print(header)
    print(sep)

    for i, h in enumerate(hosts, 1):
        mac      = h.mac      or "──:──:──:──:──:──"
        vendor   = h.vendor   or "unknown"
        hostname = h.hostname or ""
        src_icon = {"ping": "●", "arp": "○", "both": "◉"}.get(h.source, "?")
        print(f"  {i:<4} {h.ip:<{w_ip}} {mac:<{w_mac}} "
              f"{vendor[:w_ven-2]:<{w_ven}} {src_icon:<6} {hostname[:w_hst-2]}")

    print(sep)
    print(f"  ● ping alive   ○ ARP only   ◉ both")
    print(f"  {len(hosts)} host(s) found\n")


def select_hosts(hosts: List[HostRecord]) -> List[HostRecord]:
    """
    Prompt the user to select hosts from the numbered table.

    Accepts:
        all          → every host
        1            → host #1
        1,3,5        → hosts 1, 3, 5
        1-5          → hosts 1 through 5
        2,4-7,9      → mixed

    Returns the selected HostRecord list.
    """
    if not hosts:
        return []

    while True:
        try:
            raw = input("Select targets (e.g. all / 1 / 1,3 / 2-5): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []

        if not raw:
            continue

        if raw.lower() == "all":
            return list(hosts)

        selected_indices: set = set()
        valid = True

        for token in raw.split(","):
            token = token.strip()
            if "-" in token:
                parts = token.split("-", 1)
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    if lo < 1 or hi > len(hosts) or lo > hi:
                        print(f"  [!] Range {token} out of bounds "
                              f"(1–{len(hosts)})")
                        valid = False
                        break
                    selected_indices.update(range(lo, hi + 1))
                except ValueError:
                    print(f"  [!] Invalid range: '{token}'")
                    valid = False
                    break
            else:
                try:
                    n = int(token)
                    if n < 1 or n > len(hosts):
                        print(f"  [!] Index {n} out of bounds (1–{len(hosts)})")
                        valid = False
                        break
                    selected_indices.add(n)
                except ValueError:
                    print(f"  [!] Unrecognised input: '{token}'")
                    valid = False
                    break

        if valid and selected_indices:
            chosen = [hosts[i - 1] for i in sorted(selected_indices)]
            print(f"  [✓] Selected {len(chosen)} host(s): "
                  + ", ".join(h.ip for h in chosen))
            return chosen

if __name__ == "__main__":
    cidr_arg = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        found = discover(cidr=cidr_arg)
    except RuntimeError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print_hosts(found)
    chosen = select_hosts(found)
    if chosen:
        print("\nYou selected:")
        for h in chosen:
            print(f"  {h.ip}  ({h.vendor})")