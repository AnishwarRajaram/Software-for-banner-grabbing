"""
analyser.py
-----------
Takes a completed fingerprint dict (as produced by the probe pipeline)
and runs the hierarchical matching logic:

    Level 1 — Application server  (web or FTP)
        Source: Server: header, banner text, error page body
        Confidence: high if Server: header present, medium if body-only

    Level 2 — OS family  (coarse)
        Source: TTL origin (64 / 128 / 255)
        Confidence: low — many hops can shift TTL into the wrong bucket

    Level 3 — OS precise  (nmap-os-db match)
        Source: TCP options string + window + DF bit + TTL
        Confidence: scales with how many signals matched and how many
                    candidates scored the same

    Level 4 — Cross-signal consistency check
        Compares TCP TTL vs ICMP TTL, and ICMP quote_len vs expected OS
        Adjusts confidence up or down accordingly

Final output dict:

    {
        "web_server":  { "name", "version", "confidence", "evidence" }  | None,
        "ftp_server":  { "name", "version", "confidence", "evidence" }  | None,
        "os_family":   { "name", "confidence", "evidence" },
        "os_precise":  { "name", "cpe", "score", "confidence",
                         "matched_on", "candidates" }  | None,
        "confidence":  "high" | "medium" | "low",    #overall
        "notes":       [ "..." ]                      
    }
"""

from typing import Optional, Dict, Any, List
import fingerprint_db as db



_LEVELS = {"high": 3, "medium": 2, "low": 1, "none": 0}
_LABELS = {3: "high", 2: "medium", 1: "low", 0: "none"}

def _min_conf(*labels: str) -> str:
    return _LABELS[min(_LEVELS[l] for l in labels)]

def _max_conf(*labels: str) -> str:
    return _LABELS[max(_LEVELS[l] for l in labels)]

_TTL_MAP = {64: "Linux / macOS / FreeBSD", 128: "Windows", 255: "Cisco / network device"}

def _ttl_origin(ttl: Optional[int]) -> Optional[int]:
    if ttl is None:
        return None
    if ttl <= 64:  return 64
    if ttl <= 128: return 128
    return 255


''' 
──────────────────────────────────────────────
ICMP quote_len heuristic

    RFC 792 mandates original IP header + 8 bytes.
    Linux is strict: ~28 bytes total (20 IP + 8 UDP).
    Windows returns more: typically 48-576 bytes.
    Cisco returns the minimum: exactly 28.
──────────────────────────────────────────────
'''

def _quote_len_os_hint(quote_len: Optional[int]) -> Optional[str]:
    if quote_len is None:
        return None
    if quote_len <= 28:
        return "Linux or Cisco (strict RFC quoting)"
    if quote_len > 28:
        return "Windows (extended quoting)"
    return None


# ──────────────────────────────────────────────
#  Main analysis function
# ──────────────────────────────────────────────

def analyse(fingerprint: dict) -> Dict[str, Any]:
    """
    Run all matching levels and return the analysis result dict.

    Parameters:
   
    fingerprint : dict
        The accumulated dict from port_check → layer34 → layer5.

    Returns:
    dict  see module docstring for schema
    """
    notes: List[str] = []
    result: Dict[str, Any] = {
        "web_server": None,
        "ftp_server": None,
        "os_family":  None,
        "os_precise": None,
        "confidence": "none",
        "notes":      notes,
    }
    #---level 1a: HTTP Server --------
    ws = db.match_web_server(fingerprint)
    if ws:
        field = ws["matched_field"]
        if field == "server_header":
            conf = "high"
        elif field == "powered_by":
            conf = "medium"
        else:
            conf = "low"   

        ver_str = f" {ws['version']}" if ws["version"] else ""
        result["web_server"] = {
            "name":       ws["name"] + ver_str,
            "version":    ws["version"],
            "confidence": conf,
            "evidence":   f"{field} matched /{ws['pattern']}/",
        }
        notes.append(
            f"Web server identified as '{ws['name']}{ver_str}' "
            f"({conf} confidence, via {field})"
        )
    else:
        
        probes = fingerprint.get("http_probes", {})
        all_skipped = all(
            v is None or "SKIPPED" in str(v) or "PROBE_ERROR" in str(v)
            for v in probes.values()
        )
        if all_skipped:
            notes.append("HTTP probes were skipped or all failed — no web server data")
        else:
            notes.append("No web server signature matched in HTTP responses")

    # ── Level 1b: FTP server ────────────────────────────────────────
    fs = db.match_ftp_server(fingerprint)
    if fs:
        ver_str = f" {fs['version']}" if fs["version"] else ""
        result["ftp_server"] = {
            "name":       fs["name"] + ver_str,
            "version":    fs["version"],
            "confidence": "high",   # FTP banners are almost never spoofed on LANs
            "evidence":   f"{fs['matched_field']} matched /{fs['pattern']}/",
        }
        notes.append(
            f"FTP server identified as '{fs['name']}{ver_str}' (high confidence)"
        )
    elif fingerprint.get("ftp_banner"):
        notes.append(
            f"FTP banner present but unrecognised: "
            f"{fingerprint['ftp_banner'][:80]!r}"
        )

    # ── Level 2: OS family (coarse TTL bucket) ───────────────────────
    tcp_ttl  = fingerprint.get("ttl")
    icmp_ttl = fingerprint.get("icmp_ttl")

    # Prefer TCP TTL (SYN-ACK); fall back to ICMP echo TTL
    primary_ttl = tcp_ttl if tcp_ttl is not None else icmp_ttl
    origin      = _ttl_origin(primary_ttl)

    if origin:
        family_name = _TTL_MAP[origin]
        # Confidence is low for TTL-only: a single routing hop shifts it
        family_conf = "low"

        # If BOTH TCP and ICMP TTLs agree on the same origin → bump to medium
        if tcp_ttl is not None and icmp_ttl is not None:
            if _ttl_origin(tcp_ttl) == _ttl_origin(icmp_ttl):
                family_conf = "medium"
                notes.append(
                    f"TCP TTL ({tcp_ttl}) and ICMP TTL ({icmp_ttl}) "
                    f"both point to origin ~{origin} → {family_name}"
                )
            else:
                notes.append(
                    f"TCP TTL ({tcp_ttl}) and ICMP TTL ({icmp_ttl}) "
                    f"disagree on origin — unusual, possible asymmetric routing"
                )
        else:
            src = "TCP SYN-ACK" if tcp_ttl is not None else "ICMP echo"
            notes.append(
                f"OS family from {src} TTL={primary_ttl} → origin ~{origin} "
                f"→ {family_name} (low confidence, single signal)"
            )

        result["os_family"] = {
            "name":       family_name,
            "ttl_origin": origin,
            "confidence": family_conf,
            "evidence":   f"ttl={primary_ttl} → origin ~{origin}",
        }
    else:
        notes.append("No TTL data available — OS family unknown")

    # ── Level 3: OS precise (nmap-os-db) ────────────────────────────
    tcp_opts   = fingerprint.get("tcp_options")
    tcp_window = fingerprint.get("tcp_window")
    df_bit     = fingerprint.get("df_bit")

    os_matches = db.match_os(
        ttl     = primary_ttl,
        window  = tcp_window,
        options = tcp_opts,
        df      = df_bit,
    )

    if os_matches:
        best        = os_matches[0]
        best_score  = best["score"]

        # Count how many candidates share the top score
        top_tier = [m for m in os_matches if m["score"] == best_score]

        # Derive confidence from score and ambiguity
        if best_score >= 4 and len(top_tier) == 1:
            precise_conf = "high"
        elif best_score >= 3 and len(top_tier) <= 2:
            precise_conf = "medium"
        elif best_score >= 2:
            precise_conf = "low"
        else:
            precise_conf = "low"

        result["os_precise"] = {
            "name":       best["name"],
            "cpe":        best.get("cpe"),
            "score":      best_score,
            "confidence": precise_conf,
            "matched_on": best["matched_on"],
            "candidates": [m["name"] for m in top_tier[:5]],
        }

        if len(top_tier) == 1:
            notes.append(
                f"OS precise match: '{best['name']}' "
                f"(score={best_score}, matched on {best['matched_on']})"
            )
        else:
            notes.append(
                f"OS precise — top {len(top_tier)} candidates tied at "
                f"score={best_score}: "
                + ", ".join(f"'{m['name']}'" for m in top_tier[:3])
                + (" ..." if len(top_tier) > 3 else "")
            )
    else:
        notes.append("No nmap-os-db entry matched the observed TCP signals")

    # ── Level 4: cross-signal consistency ───────────────────────────
    quote_hint = _quote_len_os_hint(fingerprint.get("icmp_quote_len"))
    if quote_hint:
        notes.append(f"ICMP quote_len={fingerprint['icmp_quote_len']} → {quote_hint}")

        # If quote_len hint contradicts the precise OS match, note it
        precise = result.get("os_precise")
        if precise:
            os_name_lower = precise["name"].lower()
            if "windows" in quote_hint.lower() and "windows" not in os_name_lower:
                notes.append(
                    "ICMP quoting suggests Windows but TCP stack matched "
                    f"'{precise['name']}' — possible NAT or load balancer"
                )
            elif "linux" in quote_hint.lower() and "windows" in os_name_lower:
                notes.append(
                    "ICMP quoting suggests Linux but TCP stack matched "
                    f"'{precise['name']}' — possible NAT or load balancer"
                )

    # ── Overall confidence ───────────────────────────────────────────
    conf_votes = []
    if result["web_server"]:
        conf_votes.append(result["web_server"]["confidence"])
    if result["ftp_server"]:
        conf_votes.append(result["ftp_server"]["confidence"])
    if result["os_precise"]:
        conf_votes.append(result["os_precise"]["confidence"])
    elif result["os_family"]:
        conf_votes.append(result["os_family"]["confidence"])

    if conf_votes:
        result["confidence"] = _max_conf(*conf_votes)
    else:
        result["confidence"] = "none"

    return result


def print_report(fingerprint: dict, analysis: dict) -> None:
    ip   = fingerprint.get("ip", "?")
    port = fingerprint.get("port", "?")

    print(f"\n{'═'*60}")
    print(f"  Analysis report  {ip}:{port}")
    print(f"{'═'*60}")

    ws = analysis["web_server"]
    fs = analysis["ftp_server"]
    op = analysis["os_precise"]
    of = analysis["os_family"]

    if ws:
        print(f"  Web server  : {ws['name']}")
        print(f"               confidence={ws['confidence']}  via {ws['evidence']}")
    else:
        print("  Web server  : unknown")

    if fs:
        print(f"  FTP server  : {fs['name']}")
        print(f"               confidence={fs['confidence']}  via {fs['evidence']}")

    if op:
        print(f"  OS precise  : {op['name']}")
        print(f"               confidence={op['confidence']}  "
              f"score={op['score']}  matched_on={op['matched_on']}")
        if op.get("cpe"):
            print(f"               CPE: {op['cpe']}")
        if len(op["candidates"]) > 1:
            print(f"               other candidates: "
                  + ", ".join(f"'{c}'" for c in op["candidates"][1:]))
    elif of:
        print(f"  OS family   : {of['name']}")
        print(f"               confidence={of['confidence']}  via {of['evidence']}")
    else:
        print("  OS          : unknown")

    print(f"\n  Overall confidence : {analysis['confidence'].upper()}")

    print(f"\n  Notes:")
    for note in analysis["notes"]:
        print(f"    • {note}")

    print(f"{'═'*60}\n")



if __name__ == "__main__":
    import sys

    # Simulate a fingerprint as if produced by the full pipeline
    # against a Linux + Apache + vsftpd host
    test_fp = {
        "ip":            "192.168.1.10",
        "port":          80,
        "protocol":      "HTTP",
        # layer-5 HTTP
        "server_header": "Apache/2.4.54 (Ubuntu)",
        "powered_by":    None,
        "allow_header":  "GET, POST, OPTIONS, HEAD",
        "status_codes":  {"normal_get": 200, "404_get": 404},
        "http_probes": {
            "normal_get":      "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n",
            "404_get":         "HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.54\r\n",
            "bad_version_get": "HTTP/1.0 400 Bad Request\r\n",
            "options":         "HTTP/1.1 200 OK\r\nAllow: GET,POST\r\n",
        },
        # layer-5 FTP (not probed on port 80, all skipped)
        "ftp_banner":       None,
        "ftp_software":     None,
        "ftp_anon_allowed": None,
        "ftp_features":     [],
        # layer-3/4
        "ttl":              63,
        "ttl_origin":       64,
        "tcp_window":       29200,
        "tcp_options":      "M,S,T,N,W",
        "df_bit":           1,
        "icmp_ttl":         63,
        "icmp_df":          1,
        "icmp_quote_len":   28,
        "icmp_unreach_ttl": 63,
    }

    analysis = analyse(test_fp)
    print_report(test_fp, analysis)

    if len(sys.argv) > 1 and sys.argv[1] == "--db-stats":
        stats = db.db_stats()
        print(f"DB stats: {stats}")