"""
fingerprint_db.py
-----------------
Loads two databases at startup and exposes clean lookup functions
for the analyser layer.

  nmap-os-db     → OS fingerprints (TCP/IP stack signals)
  web_servers.json → web server + FTP server regex patterns

Neither database is bundled — they live in the same directory:

    nmap-os-db      from https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db
    web_servers.json  written by hand (ships with this project)
"""

import re
import os
import json
from typing import Optional, List, Dict, Any



_HERE          = os.path.dirname(os.path.abspath(__file__))
NMAP_OS_DB     = os.path.join(_HERE, "nmap-os-db")
WEB_SERVER_DB  = os.path.join(_HERE, "web_servers.json")



def _parse_nmap_os_db(path: str) -> List[Dict[str, Any]]:
    """
    Parse the flat-text nmap-os-db into a list of entry dicts.

    We only extract the fields our analyser actually uses:
        name        → the Fingerprint line (OS label)
        ttl         → T= value from T1 block (decimal)
        window      → W1= from WIN block (hex → int)
        options     → O1= from OPS block (raw option string)
        df          → DF= from T1 block  ('Y'→1, 'N'→0)
        icmp_df     → DFI= from IE block ('Y'/'S'→1, 'N'→0)
        cpe         → CPE line if present (e.g. cpe:/o:linux:linux_kernel:5)

    Everything else in the file is silently ignored.
    """
    entries: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}

    def _commit():
        if current.get("name"):
            entries.append(dict(current))

    def _hex_or_none(val: str) -> Optional[int]:
        try:
            return int(val, 16)
        except (ValueError, TypeError):
            return None

    def _int_or_none(val: str) -> Optional[int]:
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    def _extract(block: str, key: str) -> Optional[str]:
        """Pull a value from a block like 'T=40%W=FE88%...' given key 'W'."""
        m = re.search(r'(?:^|%)' + re.escape(key) + r'=([^%]+)', block)
        return m.group(1) if m else None

    try:
        with open(path, "r", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("Fingerprint "):
                    _commit()
                    current = {"name": line[len("Fingerprint "):].strip()}

                elif line.startswith("CPE "):
                    current.setdefault("cpe", line[4:].split()[0].strip())

                elif line.startswith("T1("):
                    block = line[3:].rstrip(")")
                    ttl_raw = _extract(block, "T")
                    df_raw  = _extract(block, "DF")
                    current["ttl"] = _int_or_none(ttl_raw) if ttl_raw else None
                    current["df"]  = (1 if df_raw == "Y" else 0) if df_raw else None

                elif line.startswith("WIN("):
                    block = line[4:].rstrip(")")
                    # W1 is the window from the first probe — matches our syn_rich
                    w1 = _extract(block, "W1")
                    current["window"] = _hex_or_none(w1) if w1 else None

                elif line.startswith("OPS("):
                    block = line[4:].rstrip(")")
                    # O1 = options string from first probe
                    o1 = _extract(block, "O1")
                    current["options_raw"] = o1   # keep raw; we normalise later

                elif line.startswith("IE("):
                    block = line[3:].rstrip(")")
                    dfi = _extract(block, "DFI")
                    # DFI=N → 0,  DFI=Y or DFI=S (same) → 1
                    current["icmp_df"] = (0 if dfi == "N" else 1) if dfi else None

        _commit()   # last entry

    except FileNotFoundError:
        raise FileNotFoundError(
            f"nmap-os-db not found at '{path}'.\n"
            "Download it with:\n"
            "  curl -o nmap-os-db "
            "https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db"
        )

    return entries


def _normalise_nmap_options(raw: Optional[str]) -> Optional[str]:
    """
    Convert an nmap OPS option string like 'M5B4ST11NW7' into the compact
    comma-separated token format our probes produce, e.g. 'M,S,T,N,W'.

    Nmap encodes options as letter+value pairs concatenated with no separator:
        M = MSS  (followed by hex MSS value, e.g. M5B4 = MSS 1460)
        S = SAckOK
        T = Timestamp (followed by digits)
        N = NOP
        W = WScale (followed by hex value)
        L = ?  (rare)
    We only care about the letter tokens, not the values.
    """
    if not raw:
        return None
    tokens = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch in ("M", "W", "T"):
            tokens.append(ch)
            # skip the following hex/decimal digits
            i += 1
            while i < len(raw) and raw[i] not in ("M", "S", "T", "N", "W", "L"):
                i += 1
        elif ch in ("S", "N", "L"):
            tokens.append(ch)
            i += 1
        else:
            i += 1   # unknown — skip
    return ",".join(tokens) if tokens else None



def _load_web_server_db(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        raise FileNotFoundError(f"web_servers.json not found at '{path}'.")

    # Pre-compile all regex patterns for speed
    for category in ("web_servers", "ftp_servers"):
        for entry in raw.get(category, []):
            entry["compiled"] = [
                re.compile(p, re.IGNORECASE) for p in entry["patterns"]
            ]
    return raw


_os_db: Optional[List[Dict[str, Any]]]  = None
_web_db: Optional[Dict[str, Any]]       = None


def _ensure_loaded() -> None:
    global _os_db, _web_db
    if _os_db is None:
        raw_entries = _parse_nmap_os_db(NMAP_OS_DB)
        # Normalise option strings into our token format
        for e in raw_entries:
            e["options"] = _normalise_nmap_options(e.get("options_raw"))
        _os_db = raw_entries

    if _web_db is None:
        _web_db = _load_web_server_db(WEB_SERVER_DB)



def _normalise_os_name(name: str, cpe: Optional[str]) -> str:
    """
    Normalise the nmap OS label into something clean and honest.

    nmap entries carry distro-specific names like
    'Linux 4.15 - 5.6' or 'Ubuntu 18.04 Linux 5.4'.
    We can't distinguish Debian from Ubuntu from Fedora via TCP signals,
    so we collapse everything with a linux CPE to 'Linux (kernel X.x)'
    using the kernel version from the CPE string.

    Windows and Cisco labels are left as-is — those are meaningful.
    """
    if cpe and "linux_kernel" in cpe:
        # CPE looks like cpe:/o:linux:linux_kernel:5  or  :5.4
        m = re.search(r'linux_kernel:([\d.]+)', cpe)
        if m:
            return f"Linux (kernel {m.group(1)}.x)"
        return "Linux"
    return name


# Linux randomises its initial TCP window per-connection (net.ipv4.tcp_rmem).
# Matching against a hardcoded window value from nmap-os-db will almost
# never hit, and when it does it's coincidence.  Only use window as a
# signal for OSes with fixed window sizes (Windows: 64240/65535,
# Cisco IOS: 4128).
_FIXED_WINDOW_TTL_ORIGINS = {128, 255}   # Windows, Cisco


def match_os(ttl:     Optional[int],
             window:  Optional[int],
             options: Optional[str],
             df:      Optional[int]) -> List[Dict[str, Any]]:
    """
    Return a ranked list of OS matches from nmap-os-db.

    Scoring (additive):
        options match   +2  (strongest signal — order is OS-specific)
        ttl_origin      +1  (coarse: 64 / 128 / 255)
        df bit          +1
        window          +1  (only for non-Linux TTL buckets — Linux
                             randomises window size per connection)

    Each result dict:
        name        normalised OS label
        score       int
        cpe         CPE string or None
        matched_on  list of contributing field names
    """
    _ensure_loaded()

    ttl_origin = None
    if ttl is not None:
        ttl_origin = 64 if ttl <= 64 else 128 if ttl <= 128 else 255

    # Only score window when we're in a fixed-window TTL bucket
    use_window = (ttl_origin in _FIXED_WINDOW_TTL_ORIGINS)

    results = []

    for entry in _os_db:
        score   = 0
        matched = []

        # TTL origin
        if ttl_origin is not None and entry.get("ttl") is not None:
            entry_origin = (64  if entry["ttl"] <= 64  else
                            128 if entry["ttl"] <= 128 else 255)
            if ttl_origin == entry_origin:
                score += 1
                matched.append("ttl_origin")

        # TCP options order (strongest signal)
        if options and entry.get("options"):
            if options == entry["options"]:
                score += 2
                matched.append("options")
            elif options.replace(",", "") == entry["options"].replace(",", ""):
                score += 2
                matched.append("options")

        # DF bit
        if df is not None and entry.get("df") is not None:
            if df == entry["df"]:
                score += 1
                matched.append("df")

        # Window — only for Windows / Cisco buckets
        if use_window and window is not None and entry.get("window") is not None:
            if window == entry["window"]:
                score += 1
                matched.append("window")

        if score > 0:
            # Give a tiebreaker bonus to entries whose CPE confirms the
            # TTL-origin family.  This prevents e.g. a 2Wire ADSL modem
            # (options=M,S,T,N,W, ttl=64, no linux CPE) from outranking
            # actual Linux kernel entries at the same raw score.
            cpe_bonus = 0
            cpe = entry.get("cpe", "") or ""
            if ttl_origin == 64  and "linux_kernel" in cpe: cpe_bonus = 1
            if ttl_origin == 128 and "windows"      in cpe: cpe_bonus = 1
            if ttl_origin == 255 and "cisco"        in cpe: cpe_bonus = 1

            results.append({
                "name":       _normalise_os_name(entry["name"], entry.get("cpe")),
                "score":      score + cpe_bonus,
                "raw_score":  score,
                "cpe":        entry.get("cpe"),
                "matched_on": matched,
            })

    # Sort by score desc, then name for stable output
    results.sort(key=lambda x: (-x["score"], x["name"]))
    return results


def match_web_server(fingerprint: dict) -> Optional[Dict[str, Any]]:
    """
    Match the fingerprint against web server patterns.

    Checks fields in strict priority order:
        1. server_header  — definitive; if this matches anything, return it
        2. powered_by     — reliable secondary header
        3. http_body_normal_get  — fallback body match
        4. http_body_404_get     — fallback error page match

    The outer loop is over FIELDS (high→low priority), not over server
    entries.  This means we fully exhaust the server_header against every
    known server pattern before we ever look at body text — preventing a
    body-level Apache match from overriding a header-level Nginx match.

    Returns the first match as:
        { name, version (or None), matched_field, pattern }
    Returns None if no pattern matches.
    """
    _ensure_loaded()

    # Build candidates in strict priority order
    candidates = []
    for field in ("server_header", "powered_by"):
        val = fingerprint.get(field)
        if val:
            candidates.append((field, val))

    # Body fallbacks — only used if no header matched
    probes = fingerprint.get("http_probes", {})
    for probe_name in ("normal_get", "404_get"):
        raw = probes.get(probe_name)
        if raw and isinstance(raw, str) and "PROBE_ERROR" not in raw:
            # Extract only the response headers, not the full body —
            # body text is too noisy (e.g. Apache error pages mention
            # "Apache" even when Nginx is the actual server)
            headers_only = raw.split("\r\n\r\n", 1)[0]
            if not headers_only:
                headers_only = raw.split("\n\n", 1)[0]
            candidates.append((f"http_body_{probe_name}", headers_only))

    # Outer loop: field priority.  We try every server entry against this
    # field before moving to the next field.
    for field, text in candidates:
        for entry in _web_db.get("web_servers", []):
            if field not in entry["fields"]:
                continue
            for pattern in entry["compiled"]:
                m = pattern.search(text)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    return {
                        "name":          entry["name"],
                        "version":       version,
                        "matched_field": field,
                        "pattern":       pattern.pattern,
                    }
    return None


def match_ftp_server(fingerprint: dict) -> Optional[Dict[str, Any]]:
    """
    Match the fingerprint against FTP server patterns.

    Checks ftp_banner and ftp_software fields.
    Returns { name, version, matched_field, pattern } or None.
    """
    _ensure_loaded()

    candidates = []
    for field in ("ftp_banner", "ftp_software"):
        val = fingerprint.get(field)
        if val:
            candidates.append((field, val))

    for entry in _web_db.get("ftp_servers", []):
        for field, text in candidates:
            if field not in entry["fields"]:
                continue
            for pattern in entry["compiled"]:
                m = pattern.search(text)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    return {
                        "name":          entry["name"],
                        "version":       version,
                        "matched_field": field,
                        "pattern":       pattern.pattern,
                    }
    return None


def db_stats() -> Dict[str, int]:
    """Return entry counts for both databases — useful for sanity-checking."""
    _ensure_loaded()
    return {
        "os_entries":         len(_os_db),
        "web_server_entries": len(_web_db.get("web_servers", [])),
        "ftp_server_entries": len(_web_db.get("ftp_servers", [])),
    }



if __name__ == "__main__":
    stats = db_stats()
    print(f"nmap-os-db   : {stats['os_entries']} entries loaded")
    print(f"web_servers  : {stats['web_server_entries']} entries")
    print(f"ftp_servers  : {stats['ftp_server_entries']} entries")

    # Quick match test with known Linux values
    print("\n--- OS match test (Linux TTL=64, window=29200, opts=M,S,T,N,W, df=1) ---")
    matches = match_os(ttl=64, window=29200, options="M,S,T,N,W", df=1)
    for m in matches[:5]:
        print(f"  score={m['score']}  matched_on={m['matched_on']}  {m['name']}")

    print("\n--- OS match test (Windows TTL=128, window=64240, opts=M,N,W,N,N,S, df=1) ---")
    matches = match_os(ttl=128, window=64240, options="M,N,W,N,N,S", df=1)
    for m in matches[:5]:
        print(f"  score={m['score']}  matched_on={m['matched_on']}  {m['name']}")